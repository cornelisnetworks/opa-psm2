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

/* Copyright (c) 2003-2015 Intel Corporation. All rights reserved. */

#include "psm_user.h"
#include "psm2_hal.h"

#include "ips_epstate.h"
#include "ips_proto.h"
#include "ips_expected_proto.h"
#include "ips_proto_help.h"
#include "ips_proto_internal.h"

/*
 * Receive header queue initialization.
 */
psm2_error_t
ips_recvhdrq_init(const psmi_context_t *context,
		  const struct ips_epstate *epstate,
		  const struct ips_proto *proto,
		  const struct ips_recvhdrq_callbacks *callbacks,
		  uint32_t subcontext,
		  struct ips_recvhdrq *recvq,
		  struct ips_recvhdrq_state *recvq_state,
		  psmi_hal_cl_q psm_hal_cl_hdrq)
{
	psm2_error_t err = PSM2_OK;

	memset(recvq, 0, sizeof(*recvq));
	recvq->proto = (struct ips_proto *)proto;
	recvq->state = recvq_state;
	recvq->context = context;
	recvq->subcontext = subcontext;
	recvq->psm_hal_cl_hdrq = psm_hal_cl_hdrq;
	pthread_spin_init(&recvq->hdrq_lock, PTHREAD_PROCESS_SHARED);
	recvq->hdrq_elemlast = ((psmi_hal_get_rx_hdr_q_cnt(context->psm_hw_ctxt) - 1) *
				(psmi_hal_get_rx_hdr_q_ent_size(context->psm_hw_ctxt) >> BYTE2DWORD_SHIFT));

	recvq->epstate = epstate;
	recvq->recvq_callbacks = *callbacks;	/* deep copy */
	SLIST_INIT(&recvq->pending_acks);

	recvq->state->hdrq_head = 0;
	recvq->state->rcv_egr_index_head = NO_EAGER_UPDATE;
	recvq->state->num_hdrq_done = 0;
	recvq->state->num_egrq_done = 0;
	recvq->state->hdr_countdown = 0;
	recvq->state->hdrq_cachedlastscan = 0;

	{
		union psmi_envvar_val env_hdr_update;
		psmi_getenv("PSM2_HEAD_UPDATE",
			    "header queue update interval (0 to update after all entries are processed). Default is 64",
			    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
			    (union psmi_envvar_val) 64, &env_hdr_update);

		/* Cap max header update interval to size of header/eager queue */
		recvq->state->head_update_interval =
			min(env_hdr_update.e_uint, psmi_hal_get_rx_hdr_q_cnt(context->psm_hw_ctxt) - 1);
		recvq->state->egrq_update_interval = 1;
	}
	return err;
}


/* flush the eager buffers, by setting the eager index head to eager index tail
   if eager buffer queue is full.

   Called when we had eager buffer overflows (ERR_TID/HFI_RHF_H_TIDERR
   was set in RHF errors), and no good eager packets were received, so
   that eager head wasn't advanced.
*/
#if 0
static void ips_flush_egrq_if_required(struct ips_recvhdrq *recvq)
{
	const uint32_t tail = ips_recvq_tail_get(&recvq->egrq);
	const uint32_t head = ips_recvq_head_get(&recvq->egrq);
	uint32_t egr_cnt = recvq->egrq.elemcnt;

	if ((head % egr_cnt) == ((tail + 1) % egr_cnt)) {
		_HFI_DBG("eager array full after overflow, flushing "
			 "(head %llx, tail %llx)\n",
			 (long long)head, (long long)tail);
		recvq->proto->stats.egr_overflow++;
	}
	return;
}
#endif

/*
 * Helpers for ips_recvhdrq_progress.
 */

static __inline__ int
_get_proto_subcontext(const struct ips_message_header *p_hdr)
{
	return ((__be32_to_cpu(p_hdr->bth[1]) >>
		 HFI_BTH_SUBCTXT_SHIFT) & HFI_BTH_SUBCTXT_MASK);
}

static __inline__ void _dump_invalid_pkt(struct ips_recvhdrq_event *rcv_ev)
{
	char *payload = ips_recvhdrq_event_payload(rcv_ev);
	uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
	    ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);

#ifdef PSM_DEBUG
	ips_proto_show_header((struct ips_message_header *)
			      rcv_ev->p_hdr, "received invalid pkt");
#endif
	if (hfi_debug & __HFI_PKTDBG) {
		ips_proto_dump_frame(rcv_ev->p_hdr, HFI_MESSAGE_HDR_SIZE,
				     "header");
		if (!payload) {
			_HFI_DBG("Cannot dump frame; payload is NULL\n");
		} else if (paylen) {
			ips_proto_dump_frame(payload, paylen, "data");
		}
	}

}

static __inline__ void
_update_error_stats(struct ips_proto *proto, uint32_t err)
{
	if (err & PSMI_HAL_RHF_ERR_ICRC)
		proto->error_stats.num_icrc_err++;
	if (err & PSMI_HAL_RHF_ERR_ECC)
		proto->error_stats.num_ecc_err++;
	if (err & PSMI_HAL_RHF_ERR_LEN)
		proto->error_stats.num_len_err++;
	if (err & PSMI_HAL_RHF_ERR_TID)
		proto->error_stats.num_tid_err++;
	if (err & PSMI_HAL_RHF_ERR_DC)
		proto->error_stats.num_dc_err++;
	if (err & PSMI_HAL_RHF_ERR_DCUN)
		proto->error_stats.num_dcunc_err++;
	if (err & PSMI_HAL_RHF_ERR_KHDRLEN)
		proto->error_stats.num_khdrlen_err++;
}

#ifdef PSM_DEBUG

static int _check_headers(struct ips_recvhdrq_event *rcv_ev, psmi_hal_cl_q cl_q)
{
	struct ips_recvhdrq *recvq = (struct ips_recvhdrq *)rcv_ev->recvq;
	struct ips_proto *proto = rcv_ev->proto;
	uint32_t *lrh = (uint32_t *) rcv_ev->p_hdr;
	uint32_t dest_context;
	const uint16_t pkt_dlid = __be16_to_cpu(rcv_ev->p_hdr->lrh[1]);
	const uint16_t base_dlid =
	    __be16_to_cpu(recvq->proto->epinfo.ep_base_lid);

	/* Check that the receive header queue entry has a sane sequence number */
	if (psmi_hal_check_rhf_sequence_number(psmi_hal_rhf_get_seq(rcv_ev->psm_hal_rhf))
	    != PSM_HAL_ERROR_OK) {
		unsigned int seqno=0;

		psmi_hal_get_rhf_expected_sequence_number(&seqno, cl_q, recvq->context->psm_hw_ctxt);
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
				  "ErrPkt: Invalid header queue entry! RHF Sequence in Hdrq Seq: %d, Recvq State Seq: %d. LRH[0]: 0x%08x, LRH[1] (PktCount): 0x%08x\n",
				  psmi_hal_rhf_get_seq(rcv_ev->psm_hal_rhf),
				  seqno, lrh[0], lrh[1]);
		return -1;
	}

	/* Verify that the packet was destined for our context */
	dest_context = ips_proto_dest_context_from_header(proto, rcv_ev->p_hdr);
	if_pf(dest_context != recvq->proto->epinfo.ep_context) {

		struct ips_recvhdrq_state *state = recvq->state;

		/* Packet not targeted at us. Drop packet and continue */
		ips_proto_dump_err_stats(proto);
		_dump_invalid_pkt(rcv_ev);

		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
				  "ErrPkt: Received packet for context %d on context %d. Receive Header Queue offset: 0x%x. Exiting.\n",
				  dest_context, recvq->proto->epinfo.ep_context,
				  state->hdrq_head);

		return -1;
	}

	/* Verify that rhf packet length matches the length in LRH */
	if_pf(psmi_hal_rhf_get_packet_length(rcv_ev->psm_hal_rhf) !=
	      (__be16_to_cpu(rcv_ev->p_hdr->lrh[2]) << BYTE2DWORD_SHIFT)) {
		_HFI_EPDBG
		    ("ErrPkt: RHF Packet Len (0x%x) does not match LRH (0x%x).\n",
		     psmi_hal_rhf_get_packet_length(rcv_ev->psm_hal_rhf) >> 2,
		     __be16_to_cpu(rcv_ev->p_hdr->lrh[2]));

		ips_proto_dump_err_stats(proto);
		_dump_invalid_pkt(rcv_ev);
		return -1;
	}

	/* Verify that the DLID matches our local LID. */
	if_pf(!((base_dlid <= pkt_dlid) &&
		(pkt_dlid <=
		 (base_dlid + (1 << recvq->proto->epinfo.ep_lmc))))) {
		_HFI_EPDBG
		    ("ErrPkt: DLID in LRH (0x%04x) does not match local LID (0x%04x) Skipping packet!\n",
		     rcv_ev->p_hdr->lrh[1], recvq->proto->epinfo.ep_base_lid);
		ips_proto_dump_err_stats(proto);
		_dump_invalid_pkt(rcv_ev);
		return -1;
	}

	return 0;
}
#endif

static __inline__ int do_pkt_cksum(struct ips_recvhdrq_event *rcv_ev)
{
	char *payload = ips_recvhdrq_event_payload(rcv_ev);
	uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
	    ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);
	uint32_t *ckptr;
	uint32_t recv_cksum, cksum, dest_subcontext;
	/* With checksum every packet has a payload */
	psmi_assert_always(payload);

	ckptr = (uint32_t *) (payload + paylen);
	recv_cksum = ckptr[0];

	/* Calculate checksum hdr + payload (includes any padding words) */
	cksum = 0xffffffff;
	cksum = ips_crc_calculate(HFI_MESSAGE_HDR_SIZE,
				  (uint8_t *) rcv_ev->p_hdr, cksum);
	if (paylen)
		cksum = ips_crc_calculate(paylen, (uint8_t *) payload, cksum);

	if ((cksum != recv_cksum) || (ckptr[0] != ckptr[1])) {
		struct ips_epstate_entry *epstaddr;
		uint32_t lcontext;
		psmi_hal_cl_idx hd, tl;

		epstaddr =
		    ips_epstate_lookup(rcv_ev->recvq->epstate,
				       rcv_ev->p_hdr->connidx);
		epstaddr = (epstaddr && epstaddr->ipsaddr) ? epstaddr : NULL;
		lcontext = epstaddr ? rcv_ev->proto->epinfo.ep_context : -1;

		hd = psmi_hal_get_cl_q_head_index(PSM_HAL_CL_Q_RX_HDR_Q,
					rcv_ev->recvq->context->psm_hw_ctxt);
		tl = psmi_hal_get_cl_q_tail_index(PSM_HAL_CL_Q_RX_HDR_Q,
					rcv_ev->recvq->context->psm_hw_ctxt);

		dest_subcontext = _get_proto_subcontext(rcv_ev->p_hdr);

		_HFI_ERROR
		    ("ErrPkt: SharedContext: %s. Local Context: %i, Checksum mismatch from LID %d! Received Checksum: 0x%08x, Expected: 0x%08x & 0x%08x. Opcode: 0x%08x, Error Flag: 0x%08x. hdrq hd 0x%x tl 0x%x rhf 0x%"
		     PRIx64 ", rhfseq 0x%x\n",
		     (dest_subcontext !=
		      rcv_ev->recvq->subcontext) ? "Yes" : "No", lcontext,
		     epstaddr ? __be16_to_cpu(epstaddr->ipsaddr->pathgrp->
					      pg_base_dlid) : -1, cksum,
		     ckptr[0], ckptr[1], _get_proto_hfi_opcode(rcv_ev->p_hdr),
		     psmi_hal_rhf_get_all_err_flags(rcv_ev->psm_hal_rhf), hd, tl, rcv_ev->psm_hal_rhf.raw_rhf,
		     psmi_hal_rhf_get_seq(rcv_ev->psm_hal_rhf));
		/* Dump packet */
		_dump_invalid_pkt(rcv_ev);
		return 0;	/* Packet checksum error */
	}

	return 1;
}

PSMI_ALWAYS_INLINE(
void
process_pending_acks(struct ips_recvhdrq *recvq))
{
	ips_scb_t ctrlscb;
	struct ips_message_header *msg_hdr = NULL;

	/* If any pending acks, dispatch them now */
	while (!SLIST_EMPTY(&recvq->pending_acks)) {
		struct ips_flow *flow = SLIST_FIRST(&recvq->pending_acks);

		SLIST_REMOVE_HEAD(&recvq->pending_acks, next);
		SLIST_NEXT(flow, next) = NULL;

		ctrlscb.scb_flags = 0;
		msg_hdr = &ctrlscb.ips_lrh;
		msg_hdr->ack_seq_num = flow->recv_seq_num.psn_num;

		if (flow->flags & IPS_FLOW_FLAG_PENDING_ACK) {
			psmi_assert_always((flow->
					    flags & IPS_FLOW_FLAG_PENDING_NAK)
					   == 0);

			flow->flags &= ~IPS_FLOW_FLAG_PENDING_ACK;
			ips_proto_send_ctrl_message(flow, OPCODE_ACK,
						    &flow->ipsaddr->
						    ctrl_msg_queued,
						    &ctrlscb, ctrlscb.cksum, 0);
		} else {
			psmi_assert_always(flow->
					   flags & IPS_FLOW_FLAG_PENDING_NAK);

			flow->flags &= ~IPS_FLOW_FLAG_PENDING_NAK;
			ips_proto_send_ctrl_message(flow, OPCODE_NAK,
						    &flow->ipsaddr->
						    ctrl_msg_queued,
						    &ctrlscb, ctrlscb.cksum, 0);
		}
	}
}

/*
 * Core receive progress function
 *
 * recvhdrq_progress is the core function that services the receive header
 * queue and optionally, the eager queue.  At the lowest level, it identifies
 * packets marked with errors by the chip and also detects and corrects when
 * eager overflow conditions occur.  At the highest level, it queries the
 * 'epstate' interface to classify packets from "known" and "unknown"
 * endpoints.  In order to support shared contexts, it can also handle packets
 * destined for other contexts (or "subcontexts").
 */
psm2_error_t ips_recvhdrq_progress(struct ips_recvhdrq *recvq)
{
	/* When PSM_PERF is enabled, the following line causes the
	   PMU to start a stop watch to measure instruction cycles of the
	   RX speedpath of PSM.  The stop watch is stopped below. */
	GENERIC_PERF_BEGIN(PSM_RX_SPEEDPATH_CTR);
	struct ips_recvhdrq_state *state = recvq->state;
	PSMI_CACHEALIGN struct ips_recvhdrq_event rcv_ev = {.proto =
		    recvq->proto,
		.recvq = recvq
	};
	struct ips_epstate_entry *epstaddr;
	uint32_t num_hdrq_done = 0;
	const uint32_t num_hdrq_todo = psmi_hal_get_rx_hdr_q_cnt(recvq->context->psm_hw_ctxt);
	uint32_t dest_subcontext;
	const uint32_t hdrq_elemsz = psmi_hal_get_rx_hdr_q_ent_size(recvq->context->psm_hw_ctxt) >> BYTE2DWORD_SHIFT;
	int ret = IPS_RECVHDRQ_CONTINUE;
	int done = 0, empty = 0;
	int do_hdr_update = 0;
	const psmi_hal_cl_q psm_hal_hdr_q = recvq->psm_hal_cl_hdrq;
	const psmi_hal_cl_q psm_hal_egr_q = psm_hal_hdr_q + 1;

	/* Returns whether the currently set 'rcv_hdr'/head is a readable entry */
#define next_hdrq_is_ready()  (! empty )

	if (psmi_hal_cl_q_empty(state->hdrq_head, psm_hal_hdr_q, recvq->context->psm_hw_ctxt))
	    return PSM2_OK;

	PSM2_LOG_MSG("entering");

	done = !next_hdrq_is_ready();

	rcv_ev.psm_hal_hdr_q = psm_hal_hdr_q;

	while (!done) {
		psmi_hal_get_receive_event(state->hdrq_head, recvq->context->psm_hw_ctxt,
					   &rcv_ev);
		rcv_ev.has_cksum =
		    ((recvq->proto->flags & IPS_PROTO_FLAG_CKSUM) &&
		     (rcv_ev.p_hdr->flags & IPS_SEND_FLAG_PKTCKSUM));
		_HFI_VDBG
		    ("new packet: rcv_hdr %p, rhf %" PRIx64 "\n",
		     rcv_ev.p_hdr, rcv_ev.psm_hal_rhf.raw_rhf);

#ifdef PSM_DEBUG
		if_pf(_check_headers(&rcv_ev, psm_hal_hdr_q))
			goto skip_packet;
#endif
		dest_subcontext = _get_proto_subcontext(rcv_ev.p_hdr);

		/* If the destination is not our subcontext, process
		 * message as subcontext message (shared contexts) */
		if (dest_subcontext != recvq->subcontext) {
			rcv_ev.ipsaddr = NULL;

			ret = recvq->recvq_callbacks.callback_subcontext
						(&rcv_ev, dest_subcontext);
			if (ret == IPS_RECVHDRQ_REVISIT)
			{
				PSM2_LOG_MSG("leaving");
				/* When PSM_PERF is enabled, the following line causes the
				   PMU to stop a stop watch to measure instruction cycles of
				   the RX speedpath of PSM.  The stop watch was started
				   above. */
				GENERIC_PERF_END(PSM_RX_SPEEDPATH_CTR);
				return PSM2_OK_NO_PROGRESS;
			}

			goto skip_packet;
		}

		if_pf(psmi_hal_rhf_get_all_err_flags(rcv_ev.psm_hal_rhf)) {

			_update_error_stats(recvq->proto, psmi_hal_rhf_get_all_err_flags(rcv_ev.psm_hal_rhf));

			recvq->recvq_callbacks.callback_error(&rcv_ev);

			if ((psmi_hal_rhf_get_rx_type(rcv_ev.psm_hal_rhf) != PSM_HAL_RHF_RX_TYPE_EAGER) ||
			    (!(psmi_hal_rhf_get_all_err_flags(rcv_ev.psm_hal_rhf) & PSMI_HAL_RHF_ERR_TID)))
				goto skip_packet;

			/* no pending eager update, header
			 * is not currently under tracing. */
			if (state->hdr_countdown == 0 &&
			    state->rcv_egr_index_head == NO_EAGER_UPDATE) {
				uint32_t egr_cnt = psmi_hal_get_rx_egr_tid_cnt(recvq->context->psm_hw_ctxt);
				psmi_hal_cl_idx etail=0, ehead=0;

				ehead = psmi_hal_get_cl_q_head_index(
					psm_hal_egr_q,
					rcv_ev.recvq->context->psm_hw_ctxt);
				etail = psmi_hal_get_cl_q_tail_index(
					psm_hal_egr_q,
					rcv_ev.recvq->context->psm_hw_ctxt);
				if (ehead == ((etail + 1) % egr_cnt)) {
					/* eager is full,
					 * trace existing header entries */
					uint32_t hdr_size =
						recvq->hdrq_elemlast +
						hdrq_elemsz;
					psmi_hal_cl_idx htail=0;

					htail = psmi_hal_get_cl_q_tail_index(
					   psm_hal_hdr_q,
					   rcv_ev.recvq->context->psm_hw_ctxt);
					const uint32_t hhead = state->hdrq_head;

					state->hdr_countdown =
						(htail > hhead) ?
						(htail - hhead) :
						(htail + hdr_size - hhead);
				}
			}

			/* Eager packet and tiderr.
			 * Don't consider updating egr head, unless we're in
			 * the congested state.  If we're congested, we should
			 * try to keep the eager buffers free. */

			if (!rcv_ev.is_congested)
				goto skip_packet_no_egr_update;
			else
				goto skip_packet;
		}

		/* If checksum is enabled, verify that it is valid */
		if_pf(rcv_ev.has_cksum && !do_pkt_cksum(&rcv_ev))
			goto skip_packet;

		if (_HFI_VDBG_ON)
		{
			psmi_hal_cl_idx egr_buff_q_head, egr_buff_q_tail;

			egr_buff_q_head = psmi_hal_get_cl_q_head_index(
					    psm_hal_egr_q,
					    rcv_ev.recvq->context->psm_hw_ctxt);
			egr_buff_q_tail = psmi_hal_get_cl_q_tail_index(
					    psm_hal_egr_q,
					    rcv_ev.recvq->context->psm_hw_ctxt);

			_HFI_VDBG_ALWAYS(
				"hdrq_head %d, p_hdr: %p, opcode %x, payload %p paylen %d; "
				"egrhead %x egrtail %x; "
				"useegrbit %x egrindex %x, egroffset %x, egrindexhead %x\n",
				state->hdrq_head,
				rcv_ev.p_hdr,
				_get_proto_hfi_opcode(rcv_ev.p_hdr),
				ips_recvhdrq_event_payload(&rcv_ev),
				ips_recvhdrq_event_paylen(&rcv_ev),
				egr_buff_q_head,egr_buff_q_tail,
				psmi_hal_rhf_get_use_egr_buff(rcv_ev.psm_hal_rhf),
				psmi_hal_rhf_get_egr_buff_index(rcv_ev.psm_hal_rhf),
				psmi_hal_rhf_get_egr_buff_offset(rcv_ev.psm_hal_rhf),
				state->rcv_egr_index_head);
		}

                PSM2_LOG_PKT_STRM(PSM2_LOG_RX,rcv_ev.p_hdr,&rcv_ev.psm_hal_rhf.raw_rhf,
				  "PKT_STRM:");

		/* Classify packet from a known or unknown endpoint */
		epstaddr = ips_epstate_lookup(recvq->epstate,
					       rcv_ev.p_hdr->connidx);
		if_pf((epstaddr == NULL) || (epstaddr->ipsaddr == NULL)) {
			rcv_ev.ipsaddr = NULL;
			recvq->recvq_callbacks.
			    callback_packet_unknown(&rcv_ev);
		} else {
			rcv_ev.ipsaddr = epstaddr->ipsaddr;
			ret = ips_proto_process_packet(&rcv_ev);
			if (ret == IPS_RECVHDRQ_REVISIT)
			{
				PSM2_LOG_MSG("leaving");
				/* When PSM_PERF is enabled, the following line causes the
				   PMU to stop a stop watch to measure instruction cycles of
				   the RX speedpath of PSM.  The stop watch was started
				   above. */
				GENERIC_PERF_END(PSM_RX_SPEEDPATH_CTR);
				return PSM2_OK_NO_PROGRESS;
			}
		}

skip_packet:
		/*
		 * if eager buffer is used, record the index.
		 */
		if (psmi_hal_rhf_get_use_egr_buff(rcv_ev.psm_hal_rhf)) {
			/* set only when a new entry is used */
			if (psmi_hal_rhf_get_egr_buff_offset(rcv_ev.psm_hal_rhf) == 0) {
				state->rcv_egr_index_head =
					psmi_hal_rhf_get_egr_buff_index(rcv_ev.psm_hal_rhf);
				state->num_egrq_done++;
			}
			/* a header entry is using an eager entry, stop tracing. */
			state->hdr_countdown = 0;
		}

skip_packet_no_egr_update:
		/* Note that state->hdrq_head is sampled speculatively by the code
		 * in ips_ptl_shared_poll() when context sharing, so it is not safe
		 * for this shared variable to temporarily exceed the last element. */
		_HFI_VDBG
		    ("head %d, elemsz %d elemlast %d\n",
		     state->hdrq_head, hdrq_elemsz,
		     recvq->hdrq_elemlast);
		psmi_hal_retire_hdr_q_entry(&state->hdrq_head, psm_hal_hdr_q,
					    recvq->context->psm_hw_ctxt,
					    hdrq_elemsz, recvq->hdrq_elemlast, &empty);
		state->num_hdrq_done++;
		num_hdrq_done++;
		done = (!next_hdrq_is_ready() || (ret == IPS_RECVHDRQ_BREAK)
			|| (num_hdrq_done == num_hdrq_todo));

		do_hdr_update = (state->head_update_interval ?
				 (state->num_hdrq_done ==
				  state->head_update_interval) : done);
		if (do_hdr_update) {

			psmi_hal_set_cl_q_head_index(
					state->hdrq_head,
					psm_hal_hdr_q,
				 	rcv_ev.recvq->context->psm_hw_ctxt);
			/* Reset header queue entries processed */
			state->num_hdrq_done = 0;
		}
		if (state->num_egrq_done >= state->egrq_update_interval) {
			/* Lazy update of egrq */
			if (state->rcv_egr_index_head != NO_EAGER_UPDATE) {
				psmi_hal_set_cl_q_head_index(
					state->rcv_egr_index_head,
				     	psm_hal_egr_q,
				        recvq->context->psm_hw_ctxt);
				state->rcv_egr_index_head = NO_EAGER_UPDATE;
				state->num_egrq_done = 0;
			}
		}
		if (state->hdr_countdown > 0) {
			/* a header entry is consumed. */
			state->hdr_countdown -= hdrq_elemsz;
			if (state->hdr_countdown == 0) {
				/* header entry count reaches zero. */
				psmi_hal_cl_idx tail=0;

				tail = psmi_hal_get_cl_q_tail_index(
					   psm_hal_egr_q,
					   recvq->context->psm_hw_ctxt);

				psmi_hal_cl_idx head=0;

				head = psmi_hal_get_cl_q_head_index(
					   psm_hal_egr_q,
					   recvq->context->psm_hw_ctxt);

				uint32_t egr_cnt = psmi_hal_get_rx_egr_tid_cnt(recvq->context->psm_hw_ctxt);
				/* Checks eager-full again. This is a real false-egr-full */
				if (head == ((tail + 1) % egr_cnt)) {

					psmi_hal_set_cl_q_tail_index(
						tail,
					        psm_hal_egr_q,
						recvq->context->psm_hw_ctxt);

					_HFI_DBG
					    ("eager array full after overflow, flushing "
					     "(head %llx, tail %llx)\n",
					     (long long)head, (long long)tail);
					recvq->proto->stats.egr_overflow++;
				} else
					_HFI_ERROR
					    ("PSM BUG: EgrOverflow: eager queue is not full\n");
			}
		}
	}
	/* while (hdrq_entries_to_read) */

	/* Process any pending acks before exiting */
	process_pending_acks(recvq);

	PSM2_LOG_MSG("leaving");
	/* When PSM_PERF is enabled, the following line causes the
	   PMU to stop a stop watch to measure instruction cycles of
	   the RX speedpath of PSM.  The stop watch was started
	   above. */
	GENERIC_PERF_END(PSM_RX_SPEEDPATH_CTR);
	return num_hdrq_done ? PSM2_OK : PSM2_OK_NO_PROGRESS;
}

/*	This function is designed to implement RAPID CCA. It iterates
	through the recvq, checking each element for set FECN or BECN bits.
	In the case of finding one, the proper response is executed, and the bits
	are cleared.
*/
psm2_error_t ips_recvhdrq_scan_cca (struct ips_recvhdrq *recvq)
{

/* Looks at hdr and determines if it is the last item in the queue */

#define is_last_hdr(idx)				\
	psmi_hal_cl_q_empty(idx, psm_hal_hdr_q, recvq->context->psm_hw_ctxt)

	struct ips_recvhdrq_state *state = recvq->state;
	PSMI_CACHEALIGN struct ips_recvhdrq_event rcv_ev = {.proto = recvq->proto,
							    .recvq = recvq
	};

	uint32_t num_hdrq_done = state->hdrq_cachedlastscan /
		psmi_hal_get_rx_hdr_q_ent_size(recvq->context->psm_hw_ctxt) >> BYTE2DWORD_SHIFT;
	const int num_hdrq_todo = psmi_hal_get_rx_hdr_q_cnt(recvq->context->psm_hw_ctxt);
	const uint32_t hdrq_elemsz = psmi_hal_get_rx_hdr_q_ent_size(recvq->context->psm_hw_ctxt) >> BYTE2DWORD_SHIFT;

	int done;
	uint32_t scan_head = state->hdrq_head + state->hdrq_cachedlastscan;
	const psmi_hal_cl_q psm_hal_hdr_q = recvq->psm_hal_cl_hdrq;

	/* Skip the first element, since we're going to process it soon anyway */
	if ( state->hdrq_cachedlastscan == 0 )
	{
		scan_head += hdrq_elemsz;
		num_hdrq_done++;
	}

	PSM2_LOG_MSG("entering");
	done = !is_last_hdr(scan_head);
	rcv_ev.psm_hal_hdr_q = psm_hal_hdr_q;
	while (!done) {
		psmi_hal_get_receive_event(scan_head, recvq->context->psm_hw_ctxt,
					   &rcv_ev);
		rcv_ev.has_cksum =
		    ((recvq->proto->flags & IPS_PROTO_FLAG_CKSUM) &&
		     (rcv_ev.p_hdr->flags & IPS_SEND_FLAG_PKTCKSUM));

		_HFI_VDBG
			("scanning new packet for CCA: rcv_hdr %p, rhf %" PRIx64 "\n",
			 rcv_ev.p_hdr, rcv_ev.psm_hal_rhf.raw_rhf);

		if_pt ( _is_cca_fecn_set(rcv_ev.p_hdr) & IPS_RECV_EVENT_FECN ) {
			struct ips_epstate_entry *epstaddr = ips_epstate_lookup(recvq->epstate,
										rcv_ev.p_hdr->connidx);

			if (epstaddr != NULL && epstaddr->ipsaddr != NULL)
			{
				rcv_ev.ipsaddr = epstaddr->ipsaddr;

				/* Send BECN back */
				ips_epaddr_t *ipsaddr = rcv_ev.ipsaddr;
				struct ips_message_header *p_hdr = rcv_ev.p_hdr;
				ips_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
				struct ips_flow *flow;
				ips_scb_t ctrlscb;

				psmi_assert(flowid < EP_FLOW_LAST);
				flow = &ipsaddr->flows[flowid];
				ctrlscb.scb_flags = 0;
				ctrlscb.ips_lrh.data[0].u32w0 =
					flow->cca_ooo_pkts;

				rcv_ev.proto->epaddr_stats.congestion_pkts++;
				/* Clear FECN event */
				rcv_ev.is_congested &= ~IPS_RECV_EVENT_FECN;

				ips_proto_send_ctrl_message(flow,
							    OPCODE_BECN,
							    &flow->ipsaddr->
							    ctrl_msg_queued,
							    &ctrlscb, ctrlscb.cksum, 0);
			}
		}
		else if_pt (0 != (_is_cca_becn_set(rcv_ev.p_hdr) << (IPS_RECV_EVENT_BECN - 1))) {
			struct ips_epstate_entry *epstaddr = ips_epstate_lookup(recvq->epstate,
										rcv_ev.p_hdr->connidx);

			if (epstaddr != NULL && epstaddr->ipsaddr != NULL)
			{
				rcv_ev.ipsaddr = epstaddr->ipsaddr;

				/* Adjust flow */
				struct ips_proto *proto = rcv_ev.proto;
				struct ips_message_header *p_hdr = rcv_ev.p_hdr;
				ips_epaddr_t *ipsaddr = rcv_ev.ipsaddr;
				struct ips_flow *flow;
				ips_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);

				psmi_assert(flowid < EP_FLOW_LAST);
				flow = &ipsaddr->flows[flowid];
				if ((flow->path->pr_ccti +
				     proto->cace[flow->path->pr_sl].ccti_increase) <= proto->ccti_limit) {
					ips_cca_adjust_rate(flow->path,
							    proto->cace[flow->path->pr_sl].ccti_increase);
					/* Clear congestion event */
					rcv_ev.is_congested &= ~IPS_RECV_EVENT_BECN;
				}
			}
		}

		num_hdrq_done++;
		scan_head += hdrq_elemsz;
		state->hdrq_cachedlastscan += hdrq_elemsz;

		done = (num_hdrq_done == num_hdrq_todo && !is_last_hdr(scan_head) );

	}
	/* while (hdrq_entries_to_read) */


	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}
