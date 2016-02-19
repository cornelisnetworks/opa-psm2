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

#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_recvhdrq.h"

/*
 * Receive header queue initialization.
 */
psm2_error_t
ips_recvhdrq_init(const psmi_context_t *context,
		  const struct ips_epstate *epstate,
		  const struct ips_proto *proto,
		  const struct ips_recvq_params *hdrq_params,
		  const struct ips_recvq_params *egrq_params,
		  const struct ips_recvhdrq_callbacks *callbacks,
		  uint32_t runtime_flags,
		  uint32_t subcontext,
		  struct ips_recvhdrq *recvq,
		  struct ips_recvhdrq_state *recvq_state)
{
	const struct hfi1_ctxt_info *ctxt_info = &context->ctrl->ctxt_info;
	psm2_error_t err = PSM2_OK;

	memset(recvq, 0, sizeof(*recvq));
	recvq->proto = (struct ips_proto *)proto;
	recvq->state = recvq_state;
	recvq->context = context;
	recvq->subcontext = subcontext;
	/* This runtime flags may be different from the context's runtime flags since
	 * a receive queue may be initialised to represent a "software" receive
	 * queue (shared contexts) or a hardware receive queue */
	recvq->runtime_flags = runtime_flags;
	recvq->hdrq = *hdrq_params;	/* deep copy */
	pthread_spin_init(&recvq->hdrq_lock, PTHREAD_PROCESS_SHARED);
	recvq->hdrq_rhf_off =
	    (ctxt_info->rcvhdrq_entsize - 8) >> BYTE2DWORD_SHIFT;

	if (recvq->runtime_flags & HFI1_CAP_DMA_RTAIL) {
		recvq->hdrq_rhf_notail = 0;
		recvq->state->hdrq_rhf_seq = 0;	/* _seq is ignored */
	} else {
		recvq->hdrq_rhf_notail = 1;
		recvq->state->hdrq_rhf_seq = 1;
	}
	recvq->hdrq_elemlast = ((recvq->hdrq.elemcnt - 1) * recvq->hdrq.elemsz);

	recvq->egrq = *egrq_params;	/* deep copy */
	recvq->egrq_buftable =
	    ips_recvq_egrbuf_table_alloc(context->ep, recvq->egrq.base_addr,
					 recvq->egrq.elemcnt,
					 recvq->egrq.elemsz);
	if (recvq->egrq_buftable == NULL) {
		err = psmi_handle_error(proto->ep, PSM2_NO_MEMORY,
					"Couldn't allocate memory for eager buffer index table");
		goto fail;
	}

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
			min(env_hdr_update.e_uint, recvq->hdrq.elemcnt - 1);
		recvq->state->egrq_update_interval = 1;
	}

fail:
	return err;
}

psm2_error_t ips_recvhdrq_fini(struct ips_recvhdrq *recvq)
{
	ips_recvq_egrbuf_table_free(recvq->egrq_buftable);
	return PSM2_OK;
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

/* Detrmine if FECN bit is set IBTA 1.2.1 CCA Annex A*/
static __inline__ uint8_t
_is_cca_fecn_set(const struct ips_message_header *p_hdr)
{
	return (__be32_to_cpu(p_hdr->bth[1]) >> HFI_BTH_FECN_SHIFT) & 0x1;
}

/* Detrmine if BECN bit is set IBTA 1.2.1 CCA Annex A*/
static __inline__ uint8_t
_is_cca_becn_set(const struct ips_message_header *p_hdr)
{
	return (__be32_to_cpu(p_hdr->bth[1]) >> HFI_BTH_BECN_SHIFT) & 0x1;
}

static __inline__ struct ips_message_header *_get_proto_hdr_from_rhf(const
								     uint32_t *
								     rcv_hdr,
								     const
								     __le32 *
								     rhf)
{
	return (struct ips_message_header *)(rcv_hdr +
					     hfi_hdrget_hdrq_offset(rhf));
}

static __inline__ struct ips_message_header *_get_proto_hdr(const uint32_t *
							    rcv_hdr)
{
	return (struct ips_message_header *)&rcv_hdr[2];
}

static __inline__ uint32_t
_get_rhf_seq(struct ips_recvhdrq *recvq, const __u32 *rcv_hdr)
{
	return hfi_hdrget_seq((const __le32 *)rcv_hdr + recvq->hdrq_rhf_off);
}

static __inline__ uint32_t
_get_rhf_len_in_bytes(struct ips_recvhdrq *recvq, const __u32 *rcv_hdr)
{
	return hfi_hdrget_length_in_bytes((const __le32 *)rcv_hdr +
					  recvq->hdrq_rhf_off);
}

static __inline__ void _dump_invalid_pkt(struct ips_recvhdrq_event *rcv_ev)
{
	char *payload = ips_recvhdrq_event_payload(rcv_ev);
	uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
	    ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);

#ifdef PSM_DEBUG
	ips_proto_show_header((struct ips_message_header *)
			      rcv_ev->rcv_hdr, "received invalid pkt");
#endif
	if (hfi_debug & __HFI_PKTDBG) {
		ips_proto_dump_frame(rcv_ev->p_hdr, HFI_MESSAGE_HDR_SIZE,
				     "header");
		if (paylen)
			ips_proto_dump_frame(payload, paylen, "data");
	}

}

static __inline__ void
_update_error_stats(struct ips_proto *proto, uint32_t err)
{
	if (err & HFI_RHF_ICRCERR)
		proto->error_stats.num_icrc_err++;
	if (err & HFI_RHF_ECCERR)
		proto->error_stats.num_ecc_err++;
	if (err & HFI_RHF_LENERR)
		proto->error_stats.num_len_err++;
	if (err & HFI_RHF_TIDERR)
		proto->error_stats.num_tid_err++;
	if (err & HFI_RHF_DCERR)
		proto->error_stats.num_dc_err++;
	if (err & HFI_RHF_DCUNCERR)
		proto->error_stats.num_dcunc_err++;
	if (err & HFI_RHF_KHDRLENERR)
		proto->error_stats.num_khdrlen_err++;
}

#ifdef PSM_DEBUG
static int _check_headers(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_recvhdrq *recvq = (struct ips_recvhdrq *)rcv_ev->recvq;
	struct ips_proto *proto = rcv_ev->proto;
	uint32_t *lrh = (uint32_t *) rcv_ev->p_hdr;
	const uint32_t *rcv_hdr = rcv_ev->rcv_hdr;
	uint32_t dest_context;
	const uint16_t pkt_dlid = __be16_to_cpu(rcv_ev->p_hdr->lrh[1]);
	const uint16_t base_dlid =
	    __be16_to_cpu(recvq->proto->epinfo.ep_base_lid);

	/* Check that the receive header queue entry has a sane sequence number */
	if (_get_rhf_seq(recvq, rcv_hdr) > LAST_RHF_SEQNO) {
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
				  "ErrPkt: Invalid header queue entry! RHF Sequence in Hdrq Seq: %d, Recvq State Seq: %d. LRH[0]: 0x%08x, LRH[1] (PktCount): 0x%08x\n",
				  _get_rhf_seq(recvq, rcv_hdr),
				  recvq->state->hdrq_rhf_seq, lrh[0], lrh[1]);
		return -1;
	}

	/* Verify that the packet was destined for our context */
	dest_context = ips_proto_dest_context_from_header(proto, rcv_ev->p_hdr);
	if_pf(dest_context != recvq->proto->epinfo.ep_context) {

		struct ips_recvhdrq_state *state = recvq->state;

		/* Packet not targetted at us. Drop packet and continue */
		ips_proto_dump_err_stats(proto);
		_dump_invalid_pkt(rcv_ev);

		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
				  "ErrPkt: Received packet for context %d on context %d. Receive Header Queue offset: 0x%x. Exiting.\n",
				  dest_context, recvq->proto->epinfo.ep_context,
				  state->hdrq_head);

		return -1;
	}

	/* Verify that rhf packet length matches the length in LRH */
	if_pf(_get_rhf_len_in_bytes(recvq, rcv_hdr) !=
	      (__be16_to_cpu(rcv_ev->p_hdr->lrh[2]) << BYTE2DWORD_SHIFT)) {
		_HFI_EPDBG
		    ("ErrPkt: RHF Packet Len (0x%x) does not match LRH (0x%x).\n",
		     _get_rhf_len_in_bytes(recvq, rcv_hdr) >> 2,
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
		uint32_t hd, tl;

		epstaddr =
		    ips_epstate_lookup(rcv_ev->recvq->epstate,
				       rcv_ev->p_hdr->connidx);
		epstaddr = (epstaddr && epstaddr->ipsaddr) ? epstaddr : NULL;

		lcontext = epstaddr ? rcv_ev->proto->epinfo.ep_context : -1;

		hd = rcv_ev->recvq->context->ctrl->__hfi_rcvhdrhead[0];
		tl = rcv_ev->recvq->context->ctrl->__hfi_rcvhdrhead[-2];

		dest_subcontext = _get_proto_subcontext(rcv_ev->p_hdr);

		_HFI_ERROR
		    ("ErrPkt: SharedContext: %s. Local Context: %i, Checksum mismatch from LID %d! Received Checksum: 0x%08x, Expected: 0x%08x & 0x%08x. Opcode: 0x%08x, Error Flag: 0x%08x. hdrq hd 0x%x tl 0x%x rhf 0x%x,%x, rhfseq 0x%x\n",
		     (dest_subcontext !=
		      rcv_ev->recvq->subcontext) ? "Yes" : "No", lcontext,
		     epstaddr ? __be16_to_cpu(epstaddr->ipsaddr->pathgrp->
					      pg_base_lid) : -1, cksum,
		     ckptr[0], ckptr[1], _get_proto_hfi_opcode(rcv_ev->p_hdr),
		     rcv_ev->error_flags, hd, tl, rcv_ev->rhf[0],
		     rcv_ev->rhf[1],
		     _get_rhf_seq((struct ips_recvhdrq *)rcv_ev->recvq,
				  rcv_ev->rcv_hdr));

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

	/* If any pending acks, dispatch them now */
	while (!SLIST_EMPTY(&recvq->pending_acks)) {
		struct ips_flow *flow = SLIST_FIRST(&recvq->pending_acks);

		SLIST_REMOVE_HEAD(&recvq->pending_acks, next);
		SLIST_NEXT(flow, next) = NULL;

		ctrlscb.flags = 0;
		ctrlscb.ips_lrh.ack_seq_num = flow->recv_seq_num.psn_num;

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
	struct ips_recvhdrq_state *state = recvq->state;
	const __le32 *rhf;
	PSMI_CACHEALIGN struct ips_recvhdrq_event rcv_ev = {.proto =
		    recvq->proto,
		.recvq = recvq
	};
	struct ips_epstate_entry *epstaddr;

	uint32_t num_hdrq_done = 0;
	const int num_hdrq_todo = recvq->hdrq.elemcnt;
	const uint32_t hdrq_elemsz = recvq->hdrq.elemsz;
	uint32_t dest_subcontext;

	int ret = IPS_RECVHDRQ_CONTINUE;
	int done = 0;
	int do_hdr_update = 0;

	/* Chip features */
	const int has_rtail = recvq->runtime_flags & HFI1_CAP_DMA_RTAIL;

	/* Returns whether the currently set 'rcv_hdr'/head is a readable entry */
#define next_hdrq_is_ready()						     \
	(has_rtail ? \
	 state->hdrq_head != ips_recvq_tail_get(&recvq->hdrq) : \
	 recvq->state->hdrq_rhf_seq == _get_rhf_seq(recvq, rcv_hdr))

	const uint32_t *rcv_hdr =
	    (const uint32_t *)recvq->hdrq.base_addr + state->hdrq_head;
	uint32_t tmp_hdrq_head;

	PSM2_LOG_MSG("entering");
	done = !next_hdrq_is_ready();

	while (!done) {

		rhf = (const __le32 *)rcv_hdr + recvq->hdrq_rhf_off;
		rcv_ev.error_flags = hfi_hdrget_err_flags(rhf);
		rcv_ev.ptype = hfi_hdrget_rcv_type(rhf);
		rcv_ev.rhf = rhf;
		rcv_ev.rcv_hdr = rcv_hdr;
		rcv_ev.p_hdr =
		    recvq->hdrq_rhf_off ? _get_proto_hdr_from_rhf(rcv_hdr, rhf)
		    : _get_proto_hdr(rcv_hdr);
		rcv_ev.has_cksum =
		    ((recvq->proto->flags & IPS_PROTO_FLAG_CKSUM) &&
		     (rcv_ev.p_hdr->flags & IPS_SEND_FLAG_PKTCKSUM));

		_HFI_VDBG
		    ("new packet: rcv_hdr %p, rhf_off %d, rhf %p (%x,%x), p_hdr %p\n",
		     rcv_hdr, recvq->hdrq_rhf_off, rhf, rhf[0], rhf[1],
		     rcv_ev.p_hdr);

		/* If the hdrq_head is before cachedlastscan, that means that we have
		 * already prescanned this for BECNs and FECNs, so we should not check
		 * again
		 */
		if_pt((recvq->proto->flags & IPS_PROTO_FLAG_CCA) &&
				(state->hdrq_head >= state->hdrq_cachedlastscan)) {
			/* IBTA CCA handling:
			 * If FECN bit set handle IBTA CCA protocol. For the
			 * flow that suffered congestion we flag it to generate
			 * a control packet with the BECN bit set - This is
			 * currently an unsolicited ACK.
			 *
			 * For all MQ packets the FECN processing/BECN
			 * generation is done in the is_expected_or_nak
			 * function as each eager packet is inspected there.
			 *
			 * For TIDFLOW/Expected data transfers the FECN
			 * bit/BECN generation is done in protoexp_data. Since
			 * header suppression can result in even FECN packets
			 * being suppressed the expected protocol generated
			 * addiional BECN packets if a "large" number of
			 * generations are swapped without progress being made
			 * for receive. "Large" is set empirically to 4.
			 *
			 * FECN packets are ignored for all control messages
			 * (except ACKs and NAKs) since they indicate
			 * congestion on the control path which is not rate
			 * controlled. The CCA specification allows FECN on
			 * ACKs to be disregarded as well.
			 */
			rcv_ev.is_congested =
			    _is_cca_fecn_set(rcv_ev.
					     p_hdr) & IPS_RECV_EVENT_FECN;
			rcv_ev.is_congested |=
			    (_is_cca_becn_set(rcv_ev.p_hdr) <<
			     (IPS_RECV_EVENT_BECN - 1));
		} else
			rcv_ev.is_congested = 0;

#ifdef PSM_DEBUG
		if_pf(_check_headers(&rcv_ev))
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
				return PSM2_OK_NO_PROGRESS;
			}

			goto skip_packet;
		}

		if_pf(rcv_ev.error_flags) {

			_update_error_stats(recvq->proto, rcv_ev.error_flags);

			recvq->recvq_callbacks.callback_error(&rcv_ev);

			if ((rcv_ev.ptype != RCVHQ_RCV_TYPE_EAGER) ||
			    (!(rcv_ev.error_flags & HFI_RHF_TIDERR)))
				goto skip_packet;

			/* no pending eager update, header
			 * is not currently under tracing. */
			if (state->hdr_countdown == 0 &&
			    state->rcv_egr_index_head == NO_EAGER_UPDATE) {
				uint32_t egr_cnt = recvq->egrq.elemcnt;
				const uint32_t etail =
					ips_recvq_tail_get(&recvq->egrq);
				const uint32_t ehead =
					ips_recvq_head_get(&recvq->egrq);

				if (ehead == ((etail + 1) % egr_cnt)) {
					/* eager is full,
					 * trace existing header entries */
					uint32_t hdr_size =
						recvq->hdrq_elemlast +
						hdrq_elemsz;
					const uint32_t htail =
						ips_recvq_tail_get
						(&recvq->hdrq);
					const uint32_t hhead =
						state->hdrq_head;

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

		_HFI_VDBG("opcode %x, payload %p paylen %d; "
			  "egrhead %lx egrtail %lx; "
			  "useegrbit %x egrindex %x, egroffset %x, egrindexhead %x\n",
			  _get_proto_hfi_opcode(rcv_ev.p_hdr),
			  ips_recvhdrq_event_payload(&rcv_ev),
			  ips_recvhdrq_event_paylen(&rcv_ev),
			  ips_recvq_head_get(&recvq->egrq),
			  ips_recvq_tail_get(&recvq->egrq),
			  hfi_hdrget_use_egrbfr(rhf),
			  hfi_hdrget_egrbfr_index(rhf),
			  hfi_hdrget_egrbfr_offset(rhf),
			  state->rcv_egr_index_head);

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
				return PSM2_OK_NO_PROGRESS;
			}
		}

skip_packet:
		/*
		 * if eager buffer is used, record the index.
		 */
		if (hfi_hdrget_use_egrbfr(rhf)) {
			/* set only when a new entry is used */
			if (hfi_hdrget_egrbfr_offset(rhf) == 0){
				state->rcv_egr_index_head =
				    hfi_hdrget_egrbfr_index(rhf);
				state->num_egrq_done++;
			}
			/* a header entry is using an eager entry, stop tracing. */
			state->hdr_countdown = 0;
		}

skip_packet_no_egr_update:
		/* Note that state->hdrq_head is sampled speculatively by the code
		 * in ips_ptl_shared_poll() when context sharing, so it is not safe
		 * for this shared variable to temporarily exceed the last element. */
		tmp_hdrq_head = state->hdrq_head + hdrq_elemsz;
		_HFI_VDBG
		    ("dma_rtail %d head %d, elemsz %d elemlast %d tmp %d\n",
		     has_rtail, state->hdrq_head, hdrq_elemsz,
		     recvq->hdrq_elemlast, tmp_hdrq_head);

		if_pt(tmp_hdrq_head <= recvq->hdrq_elemlast)
		    state->hdrq_head = tmp_hdrq_head;
		else
		state->hdrq_head = 0;

		if_pf(has_rtail == 0
		      && ++recvq->state->hdrq_rhf_seq > LAST_RHF_SEQNO)
		    recvq->state->hdrq_rhf_seq = 1;

		state->num_hdrq_done++;
		num_hdrq_done++;
		rcv_hdr =
		    (const uint32_t *)recvq->hdrq.base_addr + state->hdrq_head;
		done = (!next_hdrq_is_ready() || (ret == IPS_RECVHDRQ_BREAK)
			|| (num_hdrq_done == num_hdrq_todo));

		do_hdr_update = (state->head_update_interval ?
				 (state->num_hdrq_done ==
				  state->head_update_interval) : done);
		if (do_hdr_update) {
			ips_recvq_head_update(&recvq->hdrq, state->hdrq_head);
			/* Reset header queue entries processed */
			state->num_hdrq_done = 0;
		}
		if (state->num_egrq_done >= state->egrq_update_interval) {
			/* Lazy update of egrq */
			if (state->rcv_egr_index_head != NO_EAGER_UPDATE) {
				ips_recvq_head_update(&recvq->egrq,
						      state->
						      rcv_egr_index_head);
				state->rcv_egr_index_head = NO_EAGER_UPDATE;
				state->num_egrq_done = 0;
			}
		}
		if (state->hdr_countdown > 0) {
			/* a header entry is consumed. */
			state->hdr_countdown -= hdrq_elemsz;
			if (state->hdr_countdown == 0) {
				/* header entry count reaches zero. */
				const uint32_t tail =
				    ips_recvq_tail_get(&recvq->egrq);
				const uint32_t head =
				    ips_recvq_head_get(&recvq->egrq);
				uint32_t egr_cnt = recvq->egrq.elemcnt;

				/* Checks eager-full again. This is a real false-egr-full */
				if (head == ((tail + 1) % egr_cnt)) {
					ips_recvq_head_update(&recvq->egrq,
							      tail);
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

#define is_last_hdr(hdr)						\
	(has_rtail ? 							\
	(hdr != ips_recvq_tail_get(&recvq->hdrq)) :			\
	(recvq->state->hdrq_rhf_seq == _get_rhf_seq(recvq, curr_hdr)))

	struct ips_recvhdrq_state *state = recvq->state;
	const __le32 *rhf;
	PSMI_CACHEALIGN struct ips_recvhdrq_event rcv_ev = {.proto = recvq->proto,
							    .recvq = recvq
	};

	uint32_t num_hdrq_done = state->hdrq_cachedlastscan / recvq->hdrq.elemsz;
	const int num_hdrq_todo = recvq->hdrq.elemcnt;
	const uint32_t hdrq_elemsz = recvq->hdrq.elemsz;

	int done;

	/* Chip features */
	const int has_rtail = recvq->runtime_flags & HFI1_CAP_DMA_RTAIL;

	uint32_t *rcv_hdr =
	    (uint32_t *)recvq->hdrq.base_addr + state->hdrq_cachedlastscan;
	uint32_t *curr_hdr = rcv_hdr;
	uint32_t scan_head = state->hdrq_head + state->hdrq_cachedlastscan;

	/* Skip the first element, since we're going to process it soon anyway */
	if ( state->hdrq_cachedlastscan == 0 )
	{
		curr_hdr = curr_hdr + hdrq_elemsz;
		scan_head += hdrq_elemsz;
		num_hdrq_done++;
	}

	PSM2_LOG_MSG("entering");
	done = !is_last_hdr(scan_head);

	while (!done) {
		rhf = (const __le32 *)curr_hdr + recvq->hdrq_rhf_off;
		rcv_ev.error_flags = hfi_hdrget_err_flags(rhf);
		rcv_ev.ptype = hfi_hdrget_rcv_type(rhf);
		rcv_ev.rhf = rhf;
		rcv_ev.rcv_hdr = curr_hdr;
		rcv_ev.p_hdr =
		    recvq->hdrq_rhf_off ? _get_proto_hdr_from_rhf(curr_hdr, rhf)
		    : _get_proto_hdr(curr_hdr);
		rcv_ev.has_cksum =
		    ((recvq->proto->flags & IPS_PROTO_FLAG_CKSUM) &&
		     (rcv_ev.p_hdr->flags & IPS_SEND_FLAG_PKTCKSUM));

		_HFI_VDBG
		    ("scanning packet for CCA: curr_hdr %p, rhf_off %d, rhf %p (%x,%x), p_hdr %p\n",
		     curr_hdr, recvq->hdrq_rhf_off, rhf, rhf[0], rhf[1],
		     rcv_ev.p_hdr);

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
				ctrlscb.flags = 0;
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
		else if_pt (_is_cca_becn_set(rcv_ev.p_hdr) << (IPS_RECV_EVENT_BECN - 1) ) {
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

		curr_hdr = curr_hdr + hdrq_elemsz;

		num_hdrq_done++;
		scan_head += hdrq_elemsz;
		state->hdrq_cachedlastscan += hdrq_elemsz;

		done = (num_hdrq_done == num_hdrq_todo && !is_last_hdr(scan_head) );

	}
	/* while (hdrq_entries_to_read) */


	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}
