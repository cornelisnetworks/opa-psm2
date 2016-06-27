/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation, www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/* Copyright (c) 2003-2014 Intel Corporation. All rights reserved. */

#ifndef _IPS_PROTO_HELP_H
#define _IPS_PROTO_HELP_H

#include "ips_recvhdrq.h"
#include "ips_proto.h"
#include "ipserror.h"
#include "psm_mq_internal.h"	/* psmi_mq_handle_tiny_envelope */
#include "ptl_ips.h"

/* hfi_opcode is not the ips-level opcode. */
PSMI_ALWAYS_INLINE(
uint8_t
_get_proto_hfi_opcode(const struct ips_message_header *p_hdr))
{
	return ((__be32_to_cpu(p_hdr->bth[0]) >>
		 HFI_BTH_OPCODE_SHIFT) & HFI_BTH_OPCODE_MASK);
}

PSMI_ALWAYS_INLINE(
uint8_t
ips_flow_gen_ackflags(ips_scb_t *scb, struct ips_flow *flow))
{
	/*
	 * Setup ACK request if more than ack_interval packets
	 * have not been requested an ACK
	 */
	if (scb->flags & IPS_SEND_FLAG_ACKREQ || scb->nfrag > 1) {
		flow->ack_counter = 0;
	} else {
		flow->ack_counter++;
		if (flow->ack_counter > flow->ack_interval) {
			flow->ack_counter = 0;
			scb->flags |= IPS_SEND_FLAG_ACKREQ;
		}
	}

	/* Bottom 6 bits wind up in protocol header fields, other bits
	 * control other aspects of packet composition */
	return (uint8_t) (scb->flags & IPS_SEND_FLAG_PROTO_OPTS);
}

PSMI_ALWAYS_INLINE(
ips_epaddr_flow_t
ips_proto_flowid(struct ips_message_header *p_hdr))
{
	return (ips_epaddr_flow_t) ((__be32_to_cpu(p_hdr->bth[1]) >>
				     HFI_BTH_FLOWID_SHIFT) &
				    HFI_BTH_FLOWID_MASK);
}

PSMI_ALWAYS_INLINE(
int
ips_do_cksum(struct ips_proto *proto, struct ips_message_header *p_hdr,
	     void *payload, uint32_t paylen, uint32_t *cksum))
{
	uint16_t paywords;

	/* Update the payload words in header */
	paywords = (sizeof(struct ips_message_header) + paylen +
		    PSM_CRC_SIZE_IN_BYTES + HFI_CRC_SIZE_IN_BYTES) >>
	    BYTE2DWORD_SHIFT;
	p_hdr->lrh[2] = __cpu_to_be16(paywords & HFI_LRH_PKTLEN_MASK);

	/* Need to regenerate KDETH checksum after updating payload length */
	/* ips_kdeth_cksum(p_hdr); */

	*cksum = 0xffffffff;

	/* Checksum header */
	*cksum = ips_crc_calculate(sizeof(struct ips_message_header),
				   (uint8_t *) p_hdr, *cksum);

	/* Checksum payload (if any) */
	if (paylen) {
		psmi_assert_always(payload);
		*cksum = ips_crc_calculate(paylen, (uint8_t *) payload, *cksum);
	}

	return 0;
}

/* Get pbc static rate value for flow for a given message length */
PSMI_ALWAYS_INLINE(
uint16_t
ips_proto_pbc_static_rate(struct ips_proto *proto, struct ips_flow *flow,
			  uint32_t msgLen))
{
	uint32_t rate = 0;

	/* The PBC rate is based on which HFI type as different media have different
	 * mechanism for static rate control.
	 */

	switch (proto->epinfo.ep_hfi_type) {
	case PSMI_HFI_TYPE_OPA1:
		{
		/*
		 * time_to_send is:
		 *
		 *  (packet_length) [bits] / (pkt_egress_rate) [bits/sec]
		 *  -----------------------------------------------------
		 *     fabric_clock_period == (1 / 805 * 10^6) [1/sec]
		 *
		 *   (where pkt_egress_rate is assumed to be 100 Gbit/s.)
		 */
		uint32_t time_to_send = (8 * msgLen * 805) / (100000);
		rate = (time_to_send >> flow->path->pr_cca_divisor) *
				(flow->path->pr_active_ipd);

		if (rate > 65535)
			rate = 65535;

		}
		break;

	default:
		rate = 0;
	}

	return (uint16_t) rate;
}

/* This is only used for SDMA cases; pbc is really a pointer to
 * struct ips_pbc_header * or the equivalent un-named structure
 * in ips_scb */
PSMI_ALWAYS_INLINE(
void
ips_proto_pbc_update(struct ips_proto *proto, struct ips_flow *flow,
		     uint32_t isCtrlMsg, struct hfi_pbc *pbc, uint32_t hdrlen,
		     uint32_t paylen))
{
	int dw = (sizeof(struct hfi_pbc) + hdrlen + paylen) >> BYTE2DWORD_SHIFT;
	int sc = proto->sl2sc[flow->path->pr_sl];
	int vl = proto->sc2vl[sc];
	uint16_t static_rate = 0;

	if_pf(!isCtrlMsg && flow->path->pr_active_ipd)
	    static_rate =
	    ips_proto_pbc_static_rate(proto, flow, hdrlen + paylen);

	pbc->pbc0 = (dw & HFI_PBC_LENGTHDWS_MASK) |
	    ((vl & HFI_PBC_VL_MASK) << HFI_PBC_VL_SHIFT) |
	    (((sc >> HFI_PBC_SC4_SHIFT) &
	      HFI_PBC_SC4_MASK) << HFI_PBC_DCINFO_SHIFT);

	pbc->PbcStaticRateControlCnt = static_rate & HFI_PBC_STATICRCC_MASK;

	return;
}

PSMI_ALWAYS_INLINE(
uint32_t
ips_proto_dest_context_from_header(struct ips_proto *proto,
				   struct ips_message_header *p_hdr))
{
	return (__be32_to_cpu(p_hdr->bth[1]) & 0xFF);
}

PSMI_ALWAYS_INLINE(
void
ips_proto_hdr(struct ips_proto *proto, struct ips_epaddr *ipsaddr,
	      struct ips_flow *flow, ips_scb_t *scb, uint8_t flags))
{
	uint32_t paywords = (sizeof(struct ips_message_header) +
			     scb->payload_size + HFI_CRC_SIZE_IN_BYTES) >>
	    BYTE2DWORD_SHIFT;
	struct ips_message_header *p_hdr = &scb->ips_lrh;

#if 0
	/*
	 * This scb has been used by this connection last time,
	 * so some of the header fields are already set.
	 */
	if (scb->flow == flow) {
		p_hdr->lrh[2] = __cpu_to_be16(paywords & HFI_LRH_PKTLEN_MASK);

		p_hdr->bth[0] = __cpu_to_be32(flow->path->pr_pkey |
					      (scb->
					       opcode << BTH_OPCODE_SHIFT) |
					      (extra_bytes <<
					       BTH_EXTRA_BYTE_SHIFT));
		p_hdr->bth[2] =
		    __cpu_to_be32(flow->xmit_seq_num.
				  psn | (scb->flags & IPS_SEND_FLAG_ACKREQ));

		p_hdr->khdr.kdeth0 = __cpu_to_le32(scb->offset |
						   (scb->
						    offset_mode <<
						    HFI_KHDR_OM_SHIFT) | (scb->
									  tid <<
									  HFI_KHDR_TID_SHIFT)
						   | (scb->
						      tidctrl <<
						      HFI_KHDR_TIDCTRL_SHIFT) |
						   (scb->
						    flags & IPS_SEND_FLAG_INTR)
						   | (scb->
						      flags &
						      IPS_SEND_FLAG_HDR_SUPPRESS)
						   | (IPS_PROTO_VERSION <<
						      HFI_KHDR_KVER_SHIFT));

		/* ips_kdeth_cksum(p_hdr); // Generate KDETH checksum */

		p_hdr->ack_seq_num = flow->recv_seq_num.psn;
		p_hdr->flags = flags;

		return;
	}
#endif

	/* Setup LRH fields */
	p_hdr->lrh[0] = __cpu_to_be16(HFI_LRH_BTH |
				      ((flow->path->pr_sl & HFI_LRH_SL_MASK) <<
				       HFI_LRH_SL_SHIFT) |
				      ((proto->sl2sc[flow->path->pr_sl] &
					HFI_LRH_SC_MASK) << HFI_LRH_SC_SHIFT));
	p_hdr->lrh[1] = flow->path->pr_dlid;
	p_hdr->lrh[2] = __cpu_to_be16(paywords & HFI_LRH_PKTLEN_MASK);
	p_hdr->lrh[3] = flow->path->pr_slid;

	/* Setup BTH fields */
	p_hdr->bth[0] = __cpu_to_be32(flow->path->pr_pkey |
			      (scb->opcode << HFI_BTH_OPCODE_SHIFT));
	p_hdr->bth[2] = __cpu_to_be32(flow->xmit_seq_num.psn_num |
				      (scb->flags & IPS_SEND_FLAG_ACKREQ));

	if (scb->tidctrl) {	/* expected receive packet */
		p_hdr->bth[1] = __cpu_to_be32(ipsaddr->context |
					      (ipsaddr->
					       subcontext <<
					       HFI_BTH_SUBCTXT_SHIFT) |
						(scb->tidsendc->
						rdescid._desc_idx
						 << HFI_BTH_FLOWID_SHIFT)
					      | (proto->epinfo.
						 ep_baseqp <<
						 HFI_BTH_QP_SHIFT));

		/* Setup KHDR fields */
		p_hdr->khdr.kdeth0 = __cpu_to_le32(p_hdr->khdr.kdeth0 |
						   (scb->
						    tidctrl <<
						    HFI_KHDR_TIDCTRL_SHIFT) |
						   (scb->
						    flags & IPS_SEND_FLAG_INTR)
						   | (scb->
						      flags &
						      IPS_SEND_FLAG_HDRSUPP) |
						   (IPS_PROTO_VERSION <<
						    HFI_KHDR_KVER_SHIFT));
	} else {		/* eager receive packet */
		p_hdr->bth[1] = __cpu_to_be32(ipsaddr->context |
					      (ipsaddr->
					       subcontext <<
					       HFI_BTH_SUBCTXT_SHIFT) |
						(flow->flowid
						 << HFI_BTH_FLOWID_SHIFT)
					      | (proto->epinfo.
						 ep_baseqp <<
						 HFI_BTH_QP_SHIFT));

		/* Setup KHDR fields */
		p_hdr->khdr.kdeth0 = __cpu_to_le32(p_hdr->khdr.kdeth0 |
						   (scb->
						    flags & IPS_SEND_FLAG_INTR)
						   | (IPS_PROTO_VERSION <<
						      HFI_KHDR_KVER_SHIFT));

		p_hdr->ack_seq_num = flow->recv_seq_num.psn_num;
	}

	p_hdr->khdr.job_key = __cpu_to_le32(proto->epinfo.ep_jkey);
	p_hdr->connidx = ipsaddr->connidx_to;
	p_hdr->flags = flags;

	scb->flow = flow;

	return;
}

/*
 * Assumes that the following fields are already set in scb:
 * payload
 * payload_size
 * flags
 */
PSMI_INLINE(
void
ips_scb_prepare_flow_inner(struct ips_proto *proto, struct ips_epaddr *ipsaddr,
			   struct ips_flow *flow, ips_scb_t *scb))
{
	psmi_assert((scb->payload_size & 3) == 0);
	ips_proto_hdr(proto, ipsaddr, flow, scb,
		      ips_flow_gen_ackflags(scb, flow));

	scb->ack_timeout = proto->epinfo.ep_timeout_ack;
	scb->abs_timeout = TIMEOUT_INFINITE;
	scb->flags |= IPS_SEND_FLAG_PENDING;

	if (flow->protocol == PSM_PROTOCOL_TIDFLOW) {
		flow->xmit_seq_num.psn_seq += scb->nfrag;
		scb->seq_num = flow->xmit_seq_num;
		scb->seq_num.psn_seq--;
	} else {
		flow->xmit_seq_num.psn_num =
		    (flow->xmit_seq_num.psn_num + scb->nfrag) & proto->psn_mask;
		scb->seq_num.psn_num =
		    (flow->xmit_seq_num.psn_num - 1) & proto->psn_mask;
	}

	return;
}

PSMI_ALWAYS_INLINE(
void
ips_proto_epaddr_stats_set(struct ips_proto *proto, uint8_t msgtype))
{
	switch (msgtype) {
	case OPCODE_ACK:
		break;
	case OPCODE_ERR_CHK:
	case OPCODE_ERR_CHK_GEN:
		proto->epaddr_stats.err_chk_send++;
		break;
	case OPCODE_NAK:
		proto->epaddr_stats.nak_send++;
		break;
	case OPCODE_CONNECT_REQUEST:
		proto->epaddr_stats.connect_req++;
		break;
	case OPCODE_DISCONNECT_REQUEST:
		proto->epaddr_stats.disconnect_req++;
		break;
	default:
		break;
	}
	return;
}

/*
 * Exported there solely for inlining is_expected_or_nak and mq_tiny handling
 */
extern
psm2_error_t ips_proto_send_ctrl_message(struct ips_flow *flow,
		uint8_t message_type, uint16_t *msg_queue_mask,
		ips_scb_t *ctrlscb, void *payload, uint32_t paylen);

PSMI_ALWAYS_INLINE(
void
ips_proto_send_ack(struct ips_recvhdrq *recvq, struct ips_flow *flow))
{
	if_pt(recvq->proto->flags & IPS_PROTO_FLAG_COALESCE_ACKS) {
		if (flow->flags & IPS_FLOW_FLAG_PENDING_NAK) {
			flow->flags &= ~IPS_FLOW_FLAG_PENDING_NAK;	/* ACK clears NAK */
		} else if (!(flow->flags & IPS_FLOW_FLAG_PENDING_ACK)) {
			SLIST_INSERT_HEAD(&recvq->pending_acks, flow, next);
		}

		flow->flags |= IPS_FLOW_FLAG_PENDING_ACK;
	}
	else {
		ips_scb_t ctrlscb;

		ctrlscb.flags = 0;
		ctrlscb.ips_lrh.ack_seq_num = flow->recv_seq_num.psn_num;
		/* Coalesced ACKs disabled. Send ACK immediately */
		ips_proto_send_ctrl_message(flow, OPCODE_ACK,
					    &flow->ipsaddr->ctrl_msg_queued,
					    &ctrlscb, ctrlscb.cksum, 0);
	}
}

PSMI_ALWAYS_INLINE(
void
ips_proto_send_nak(struct ips_recvhdrq *recvq, struct ips_flow *flow))
{
	if_pt(recvq->proto->flags & IPS_PROTO_FLAG_COALESCE_ACKS) {
		if (flow->flags & IPS_FLOW_FLAG_PENDING_ACK) {
			flow->flags &= ~IPS_FLOW_FLAG_PENDING_ACK;	/* NAK clears ACK */
		} else if (!(flow->flags & IPS_FLOW_FLAG_PENDING_NAK)) {
			SLIST_INSERT_HEAD(&recvq->pending_acks, flow, next);
		}

		flow->flags |= IPS_FLOW_FLAG_PENDING_NAK;
	}
	else {
		ips_scb_t ctrlscb;

		ctrlscb.flags = 0;
		ctrlscb.ips_lrh.ack_seq_num = flow->recv_seq_num.psn_num;
		/* Coalesced ACKs disabled. Send NAK immediately */
		ips_proto_send_ctrl_message(flow, OPCODE_NAK,
					    &flow->ipsaddr->ctrl_msg_queued,
					    &ctrlscb, ctrlscb.cksum, 0);
	}
}

/* return 1 if packet is next expected in flow
 * return 0 if packet is not next expected in flow (and nak packet).
 */
PSMI_ALWAYS_INLINE(
int
ips_proto_is_expected_or_nak(struct ips_recvhdrq_event *rcv_ev))
{
	struct ips_proto *proto = rcv_ev->proto;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
	struct ips_flow *flow;
	psmi_seqnum_t sequence_num;

	psmi_assert((flowid == EP_FLOW_GO_BACK_N_PIO) ||
		           (flowid == EP_FLOW_GO_BACK_N_DMA)
	    );
	flow = &ipsaddr->flows[flowid];
	/* If packet faced congestion generate BECN in NAK. */
	if_pf((rcv_ev->is_congested & IPS_RECV_EVENT_FECN) &&
	      ((flow->cca_ooo_pkts & 0xf) == 0)) {
		/* Generate a BECN for every 16th OOO packet marked with a FECN. */
		flow->flags |= IPS_FLOW_FLAG_GEN_BECN;
		flow->cca_ooo_pkts++;
		rcv_ev->proto->epaddr_stats.congestion_pkts++;
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;	/* Clear FECN event */
	}

	sequence_num.psn_val = __be32_to_cpu(p_hdr->bth[2]);
	if_pf(flow->recv_seq_num.psn_num == sequence_num.psn_num) {
		flow->flags &= ~IPS_FLOW_FLAG_NAK_SEND;

		flow->recv_seq_num.psn_num =
		    (flow->recv_seq_num.psn_num + 1) & proto->psn_mask;
		flow->cca_ooo_pkts = 0;

		/* don't process ack, caller will do it. */
		return 1;

	}

	int16_t diff = (int16_t) (sequence_num.psn_num -
			       flow->recv_seq_num.psn_num);
	if (diff > 0) {
		if (!(flow->flags & IPS_FLOW_FLAG_NAK_SEND)) {
			/* Queue/Send NAK to peer  */
			ips_proto_send_nak((struct ips_recvhdrq *)
					   rcv_ev->recvq, flow);
			flow->flags |= IPS_FLOW_FLAG_NAK_SEND;
			flow->cca_ooo_pkts = 0;
		} else if (proto->flags & IPS_PROTO_FLAG_CCA) {
			flow->cca_ooo_pkts = diff;
			if (flow->cca_ooo_pkts > flow->ack_interval) {
				ips_scb_t ctrlscb;

				rcv_ev->proto->epaddr_stats.congestion_pkts++;
				flow->flags |= IPS_FLOW_FLAG_GEN_BECN;
				_HFI_CCADBG
				    ("BECN Generation. Expected: %d, Got: %d.\n",
				     flow->recv_seq_num.psn_num,
				     sequence_num.psn_num);

				ctrlscb.flags = 0;
				ctrlscb.ips_lrh.data[0].u32w0 =
						flow->cca_ooo_pkts;
				/* Send Control message to throttle flow. Will clear flow flag and
				 * reset cca_ooo_pkts.
				 */
				ips_proto_send_ctrl_message(flow,
					    OPCODE_BECN,
					    &flow->ipsaddr->
					    ctrl_msg_queued,
					    &ctrlscb, ctrlscb.cksum, 0);
			}
		}
	}

	/* process ack if packet is not in sequence. */
	ips_proto_process_ack(rcv_ev);

	return 0;
}

/*
 * Note, some code depends on the literal values specified in this enum.
 */
enum ips_msg_order {
	IPS_MSG_ORDER_PAST  = 3,	/* Old message, recv & drop */
	IPS_MSG_ORDER_EXPECTED_MATCH = 2, /* Expected message, recv on match */
	IPS_MSG_ORDER_EXPECTED = 1,	/* Expected message, always recv */
	IPS_MSG_ORDER_FUTURE_RECV = 0,	/* Future message, buffer in OOO Q */
	IPS_MSG_ORDER_FUTURE = -1,	/* Future message, leave on RHQ */
};

PSMI_ALWAYS_INLINE(
enum ips_msg_order
ips_proto_check_msg_order(ips_epaddr_t *ipsaddr,
			 struct ips_flow *flow,
			 uint16_t send_seqnum,
			 uint16_t *recv_seqnum))

{
	int16_t diff = (int16_t) (*recv_seqnum - send_seqnum);

	if (likely(diff == 0)) {
		*recv_seqnum += 1;

		ipsaddr->msg_toggle ^= IPS_FLOW_MSG_TOGGLE_UNEXP_MASK;
		if (ipsaddr->msg_toggle & IPS_FLOW_MSG_TOGGLE_UNEXP_MASK)
			return IPS_MSG_ORDER_EXPECTED_MATCH;

		return IPS_MSG_ORDER_EXPECTED;
	} else if (diff > 0) {
		return IPS_MSG_ORDER_PAST;
	}

	ipsaddr->msg_toggle ^= IPS_FLOW_MSG_TOGGLE_OOO_MASK;
	if (!(ipsaddr->msg_toggle & IPS_FLOW_MSG_TOGGLE_OOO_MASK)) {
		/*
		 * Second time to see the same ooo message, receive and put
		 * into OOO queue.
		 */
		return IPS_MSG_ORDER_FUTURE_RECV;
	}

	/* The first time to see an OOO message, leave it there and try
	 * next time. But we need to revert back the receiving flow PSN. */
	uint32_t psn_mask = ((psm2_epaddr_t)ipsaddr)->proto->psn_mask;
	flow->recv_seq_num.psn_num =
		(flow->recv_seq_num.psn_num - 1) & psn_mask;
	return IPS_MSG_ORDER_FUTURE;
}

PSMI_INLINE(
int
ips_proto_process_packet(const struct ips_recvhdrq_event *rcv_ev))
{
	uint32_t index;

	/* NOTE: Fault injection will currently not work with hardware
	 * suppression. See note below for reason why as we currently
	 * do not update the hardware tidflow table if FI is dropping
	 * the packet.
	 *
	 * We need to look into the packet before dropping it and
	 * if it's an expected packet AND we have hardware suppression
	 * then we need to update the hardware tidflow table and the
	 * associated tidrecvc state to fake having received a packet
	 * until some point in the window defined by the loss rate.
	 * This way the subsequent err chk will be NAKd and we can resync
	 * the flow with the sender.
	 *
	 * Note: For real errors the hardware generates seq/gen errors
	 * which are handled appropriately by the protocol.
	 */

	if_pf(PSMI_FAULTINJ_ENABLED()) {
		PSMI_FAULTINJ_STATIC_DECL(fi_recv, "recvlost", 1,
					  IPS_FAULTINJ_RECVLOST);
		if (psmi_faultinj_is_fault(fi_recv))
			return IPS_RECVHDRQ_CONTINUE;
	}

	/* see file ips_proto_header.h for details */
	index = _get_proto_hfi_opcode(rcv_ev->p_hdr) - OPCODE_RESERVED;
	if (index >= (OPCODE_FUTURE_FROM - OPCODE_RESERVED))
		index = 0;

	return ips_packet_service_routine[index]
			((struct ips_recvhdrq_event *)rcv_ev);
}

/*
 * Breaks header encapsulation but needed in mq sends so we can pay
 * "near-equal" attention to putting sends on the wire and servicing the
 * receive queue.
 */

PSMI_ALWAYS_INLINE(
psm2_error_t
ips_recv_progress_if_busy(ptl_t *ptl, psm2_error_t err))
{
	if (err == PSM2_EP_NO_RESOURCES) {
		ptl->ctl->ep_poll(ptl, 0);
		return PSM2_OK;
	} else
		return err;
}

/* Find next lowest power of a two for a 32 bit number*/
PSMI_ALWAYS_INLINE(
unsigned int
ips_next_low_pow2(unsigned int v))
{

	const unsigned int b[] = { 0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000 };
	const unsigned int S[] = { 1, 2, 4, 8, 16 };
	register unsigned int r = 1;
	int i;

	for (i = 4; i >= 0; i--) {
		if (v & b[i]) {
			v >>= S[i];
			r <<= S[i];
		}
	}

	return r;
}

PSMI_ALWAYS_INLINE(
ips_path_rec_t *
ips_select_path(struct ips_proto *proto, ips_path_type_t path_type,
		ips_epaddr_t *ipsaddr, ips_path_grp_t *pathgrp))
{
	uint32_t path_idx;

	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE) {
		/* If dispersive routes are configured then select the routes in round
		 * robin order. We may want to use congestion information to select the
		 * least lightly loaded path.
		 */
		path_idx = pathgrp->pg_next_path[path_type];
		if (++pathgrp->pg_next_path[path_type] >=
		    pathgrp->pg_num_paths[path_type])
			pathgrp->pg_next_path[path_type] = 0;
	} else if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_DST)
		path_idx =	/* Key on destination context */
		    ipsaddr->context % pathgrp->pg_num_paths[path_type];
	else if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_SRC)
		path_idx =	/* Key off src context */
		    proto->epinfo.ep_context % pathgrp->pg_num_paths[path_type];
	else			/* Base LID routed - Default in Infinhfi 2.5 (Oct 09). */
		path_idx = 0;

	return pathgrp->pg_path[path_idx][path_type];
}

#endif /* _IPS_PROTO_HELP_H */
