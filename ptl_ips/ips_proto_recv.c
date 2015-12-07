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

#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

/* receive service routine for each packet opcode */
ips_packet_service_fn_t
ips_packet_service_routine[OPCODE_FUTURE_FROM-OPCODE_RESERVED] = {
ips_proto_process_unknown_opcode,	/* 0xC0 */
ips_proto_mq_handle_tiny,		/* OPCODE_TINY */
ips_proto_mq_handle_short,
ips_proto_mq_handle_eager,
ips_proto_mq_handle_rts,                /* RTS */
ips_proto_mq_handle_cts,                /* CTS */
ips_proto_mq_handle_data,               /* DATA */
ips_protoexp_data,                      /* EXPTID */
ips_protoexp_recv_tid_completion,       /* EXPTID_COMPLETION */
ips_proto_process_ack,
ips_proto_process_nak,
ips_proto_process_becn,
ips_proto_process_err_chk,
ips_proto_process_err_chk_gen,
ips_proto_connect_disconnect,
ips_proto_connect_disconnect,
ips_proto_connect_disconnect,
ips_proto_connect_disconnect,
ips_proto_am,
ips_proto_am,
ips_proto_am				/* OPCODE_AM_REPLY */
};

#define PSM_STRAY_WARN_INTERVAL_DEFAULT_SECS	30
static void ips_report_strays(struct ips_proto *proto);

#define INC_TIME_SPEND(timer)

psm2_error_t ips_proto_recv_init(struct ips_proto *proto)
{
	uint32_t interval_secs;
	union psmi_envvar_val env_stray;

	psmi_getenv("PSM2_STRAY_WARNINTERVAL",
		    "min secs between stray process warnings",
		    PSMI_ENVVAR_LEVEL_HIDDEN,
		    PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)PSM_STRAY_WARN_INTERVAL_DEFAULT_SECS,
		    &env_stray);
	interval_secs = env_stray.e_uint;
	if (interval_secs > 0)
		proto->stray_warn_interval = sec_2_cycles(interval_secs);
	else
		proto->stray_warn_interval = 0;

	return PSM2_OK;
}

psm2_error_t ips_proto_recv_fini(struct ips_proto *proto)
{
	ips_report_strays(proto);
	return PSM2_OK;
}

#define cycles_to_sec_f(cycles)		    \
	(((double)cycles_to_nanosecs(cycles)) / 1000000000.0)

struct ips_stray_epid {
	psm2_epid_t epid;
	uint32_t err_check_bad_sent;
	uint32_t ipv4_addr;
	uint32_t pid;
	uint32_t num_messages;
	uint64_t t_warn_next;
	uint64_t t_first;
	uint64_t t_last;
};

static
void ips_report_strays(struct ips_proto *proto)
{
	struct ips_stray_epid *sepid;
	struct psmi_eptab_iterator itor;
	psmi_epid_itor_init(&itor, PSMI_EP_CROSSTALK);
	double t_runtime = cycles_to_sec_f(proto->t_fini - proto->t_init);

	while ((sepid = psmi_epid_itor_next(&itor))) {
		char ipbuf[INET_ADDRSTRLEN], *ip = NULL;
		char bufpid[32];
		uint32_t lid = psm2_epid_nid(sepid->epid);
		double t_first =
		    cycles_to_sec_f(sepid->t_first - proto->t_init);
		double t_last = cycles_to_sec_f(sepid->t_last - proto->t_init);
		if (sepid->ipv4_addr)
			ip = (char *)
			    inet_ntop(AF_INET, &sepid->ipv4_addr, ipbuf,
				      sizeof(ipbuf));
		if (!ip)
			snprintf(ipbuf, sizeof(ipbuf), "%d (%x)", lid, lid);

		if (sepid->pid)
			snprintf(bufpid, sizeof(bufpid), "PID=%d", sepid->pid);
		else
			snprintf(bufpid, sizeof(bufpid), "PID unknown");

		_HFI_INFO
		    ("Process %s on host %s=%s sent %d stray message(s) and "
		     "was told so %d time(s) (first stray message at %.1fs "
		     "(%d%%), last at %.1fs (%d%%) into application run)\n",
		     bufpid, ip ? "IP" : "LID", ipbuf, sepid->num_messages,
		     sepid->err_check_bad_sent, t_first,
		     (int)(t_first * 100.0 / t_runtime), t_last,
		     (int)(t_last * 100.0 / t_runtime));

		psmi_epid_remove(PSMI_EP_CROSSTALK, sepid->epid);
		psmi_free(sepid);
	}
	psmi_epid_itor_fini(&itor);
	return;
}

/* New scbs now available.  If we have pending sends because we were out of
 * scbs, put the pendq on the timerq so it can be processed. */
void ips_proto_rv_scbavail_callback(struct ips_scbctrl *scbc, void *context)
{
	struct ips_proto *proto = (struct ips_proto *)context;
	struct ips_pend_sreq *sreq = STAILQ_FIRST(&proto->pend_sends.pendq);
	if (sreq != NULL)
		psmi_timer_request(proto->timerq,
				   &proto->pend_sends.timer, PSMI_TIMER_PRIO_1);
	return;
}

psm2_error_t
ips_proto_timer_pendq_callback(struct psmi_timer *timer, uint64_t current)
{
	psm2_error_t err = PSM2_OK;
	struct ips_pend_sends *pend_sends =
	    (struct ips_pend_sends *)timer->context;
	struct ips_pendsendq *phead = &pend_sends->pendq;
	struct ips_proto *proto = (struct ips_proto *)pend_sends->proto;
	struct ips_pend_sreq *sreq;

	while (!STAILQ_EMPTY(phead)) {
		sreq = STAILQ_FIRST(phead);
		switch (sreq->type) {
		case IPS_PENDSEND_EAGER_REQ:
			err = ips_proto_mq_push_cts_req(proto, sreq->req);
			break;
		case IPS_PENDSEND_EAGER_DATA:
			err = ips_proto_mq_push_rts_data(proto, sreq->req);
			break;

		default:
			psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
					  "Unknown pendq state %d\n",
					  sreq->type);
		}

		if (err == PSM2_OK) {
			STAILQ_REMOVE_HEAD(phead, next);
			psmi_mpool_put(sreq);
		} else {	/* out of scbs. wait for the next scb_avail callback */
			/* printf("!!!!! breaking out of pendq progress\n"); */
			break;
		}
	}

	return err;
}

PSMI_INLINE(
int
between(int first_seq, int last_seq, int seq))
{
	if (last_seq >= first_seq) {
		if (seq < first_seq || seq > last_seq) {
			return 0;
		}
	} else {
		if (seq > last_seq && seq < first_seq) {
			return 0;
		}
	}
	return 1;
}

PSMI_INLINE(
int
pio_dma_ack_valid(struct ips_proto *proto, struct ips_flow *flow,
		  psmi_seqnum_t ack_seq_num))
{
	uint32_t last_num;
	struct ips_scb_unackedq *unackedq = &flow->scb_unacked;

	if (STAILQ_EMPTY(unackedq))
		return 0;

	/* scb_pend will be moved back when an nak is received, but
	 * the packet may actually be received and acked after the nak,
	 * so we use the tail of unacked queue, which may include packets
	 * not being sent out yet, this is over do, but it should be OK. */
	last_num = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num.psn_num;

	return between(flow->xmit_ack_num.psn_num,
				last_num, ack_seq_num.psn_num);
}

PSMI_INLINE(
struct ips_flow *
get_tidflow(struct ips_proto *proto, ips_epaddr_t *ipsaddr,
	    struct ips_message_header *p_hdr, psmi_seqnum_t ack_seq_num))
{
	struct ips_protoexp *protoexp = proto->protoexp;
	ptl_arg_t desc_id = p_hdr->data[0];
	struct ips_tid_send_desc *tidsendc;
	ptl_arg_t desc_tidsendc;
	struct ips_flow *flow;
	uint32_t last_seq;
	struct ips_scb_unackedq *unackedq;

	tidsendc = (struct ips_tid_send_desc *)
	    psmi_mpool_find_obj_by_index(protoexp->tid_desc_send_pool,
					 desc_id._desc_idx);
	if (tidsendc == NULL) {
		_HFI_ERROR
		    ("OPCODE_ACK: Index %d is out of range in tidflow ack\n",
		     desc_id._desc_idx);
		return NULL;
	}

	/* Ensure generation matches */
	psmi_mpool_get_obj_index_gen_count(tidsendc,
					   &desc_tidsendc._desc_idx,
					   &desc_tidsendc._desc_genc);
	if (desc_tidsendc.u64 != desc_id.u64)
		return NULL;

	/* Ensure ack is within window */
	flow = &tidsendc->tidflow;
	unackedq = &flow->scb_unacked;

	/* No unacked scbs */
	if (STAILQ_EMPTY(unackedq))
		return NULL;

	/* Generation for ack should match */
	if (STAILQ_FIRST(unackedq)->seq_num.psn_gen != ack_seq_num.psn_gen)
		return NULL;

	/* scb_pend will be moved back when an nak is received, but
	 * the packet may actually be received and acked after the nak,
	 * so we use the tail of unacked queue, which may include packets
	 * not being sent out yet, this is over do, but it should be OK. */
	last_seq = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num.psn_seq;

	if (between(flow->xmit_ack_num.psn_seq,
				last_seq, ack_seq_num.psn_seq) == 0)
		return NULL;

	return flow;
}

/* NAK post process for tid flow */
void ips_tidflow_nak_post_process(struct ips_proto *proto,
				  struct ips_flow *flow)
{
	ips_scb_t *scb;
	uint32_t first_seq, ack_seq;

	scb = STAILQ_FIRST(&flow->scb_unacked);
	first_seq = __be32_to_cpu(scb->ips_lrh.bth[2]) & HFI_BTH_SEQ_MASK;
	ack_seq = (flow->xmit_ack_num.psn_seq - 1) & HFI_BTH_SEQ_MASK;

	/* If the ack SEQ falls into a multi-packets scb,
	 * don't re-send the packets already acked. */
	if (scb->nfrag > 1 &&
	between(first_seq, scb->seq_num.psn_seq, ack_seq)) {
		uint32_t om, offset_in_tid, remaining_bytes_in_tid;
		uint32_t npkt, pktlen, nbytes;
		uint32_t idx, loop;

		/* how many packets acked in this scb */
		npkt = ((ack_seq - first_seq) & HFI_BTH_SEQ_MASK) + 1;

		/* Get offset/om from current packet header */
		offset_in_tid = __le32_to_cpu(scb->ips_lrh.khdr.kdeth0) &
				HFI_KHDR_OFFSET_MASK;
		om = (__le32_to_cpu(scb->ips_lrh.khdr.kdeth0) >>
				HFI_KHDR_OM_SHIFT) & 0x1;
		if (om)
			offset_in_tid *= 64;
		else
			offset_in_tid *= 4;
		/* bytes remaining in current tid */
		remaining_bytes_in_tid =
			(IPS_TIDINFO_GET_LENGTH(scb->tsess[0]) << 12) -
			offset_in_tid;

		/* packet length in current header */
		pktlen = scb->payload_size;
		psmi_assert(min(remaining_bytes_in_tid,
			scb->frag_size) >= pktlen);
		psmi_assert((((__be16_to_cpu(scb->ips_lrh.lrh[2]) &
			HFI_LRH_PKTLEN_MASK) << BYTE2DWORD_SHIFT) -
			sizeof(struct ips_message_header) -
			HFI_CRC_SIZE_IN_BYTES) == pktlen);

		/* Loop to find the position to start */
		idx = 0;
		nbytes = 0;
		loop = npkt;
		while (loop) {
			remaining_bytes_in_tid -= pktlen;
			offset_in_tid += pktlen;
			nbytes += pktlen;
			first_seq++;
			loop--;

			if (remaining_bytes_in_tid == 0) {
				idx++;
				remaining_bytes_in_tid =
					IPS_TIDINFO_GET_LENGTH(scb->
					tsess[idx]) << 12;
				offset_in_tid = 0;
			}

			pktlen = min(remaining_bytes_in_tid, scb->frag_size);
		}
		psmi_assert((first_seq & HFI_BTH_SEQ_MASK) ==
				((ack_seq + 1) & HFI_BTH_SEQ_MASK));

		/* 0. update scb info */
		psmi_assert(scb->nfrag_remaining > npkt);
		scb->nfrag_remaining -= npkt;
		psmi_assert(scb->chunk_size_remaining > nbytes);
		scb->chunk_size_remaining -= nbytes;
		scb->payload = (void *)((char *)scb->payload + nbytes);

		/* 1. if last packet in sequence, set ACK, clear SH */
		if (scb->chunk_size_remaining <= scb->frag_size) {
			psmi_assert(scb->nfrag_remaining == 1);
			scb->flags |= IPS_SEND_FLAG_ACKREQ;
			scb->flags &= ~IPS_SEND_FLAG_HDRSUPP;

			/* last packet is what remaining */
			pktlen = scb->chunk_size_remaining;
		}

		/* 2. set new packet sequence number */
		scb->ips_lrh.bth[2] = __cpu_to_be32(
			((first_seq & HFI_BTH_SEQ_MASK) << HFI_BTH_SEQ_SHIFT) |
			((scb->seq_num.psn_gen &
			HFI_BTH_GEN_MASK) << HFI_BTH_GEN_SHIFT) |
			(scb->flags & IPS_SEND_FLAG_ACKREQ));

		/* 3. set new packet offset */
		scb->ips_lrh.exp_offset += nbytes;

		/* 4. if packet length is changed, set new length */
		if (scb->payload_size != pktlen) {
			scb->payload_size = pktlen;
			scb->ips_lrh.lrh[2] = __cpu_to_be16((
				(scb->payload_size +
				sizeof(struct ips_message_header) +
				HFI_CRC_SIZE_IN_BYTES) >>
				BYTE2DWORD_SHIFT) & HFI_LRH_PKTLEN_MASK);
		}

		/* 5. set new tidctrl and tidinfo array */
		scb->tsess = &scb->tsess[idx];
		scb->tsess_length -= idx * sizeof(uint32_t);
		scb->tidctrl = IPS_TIDINFO_GET_TIDCTRL(scb->tsess[0]);

		/* 6. calculate new offset mode */
		if (offset_in_tid < 131072) { /* 2^15 * 4 */
			offset_in_tid /= 4;
			om = 0;
		} else {
			offset_in_tid /= 64;
			om = 1;
		}

		/* 7. set new tidinfo */
		scb->ips_lrh.khdr.kdeth0 = __cpu_to_le32(
			(offset_in_tid & HFI_KHDR_OFFSET_MASK) |
			(om << HFI_KHDR_OM_SHIFT) |
			(IPS_TIDINFO_GET_TID(scb->tsess[0])
					<< HFI_KHDR_TID_SHIFT) |
			(scb->tidctrl << HFI_KHDR_TIDCTRL_SHIFT) |
			(scb->flags & IPS_SEND_FLAG_INTR) |
			(scb->flags & IPS_SEND_FLAG_HDRSUPP) |
			(IPS_PROTO_VERSION << HFI_KHDR_KVER_SHIFT));
	}

	/* Update unacked scb's to use the new generation */
	while (scb) {
		/* update with new generation */
		scb->ips_lrh.bth[2] = __cpu_to_be32(
			(__be32_to_cpu(scb->ips_lrh.bth[2]) &
			(~(HFI_BTH_GEN_MASK << HFI_BTH_GEN_SHIFT))) |
			((flow->xmit_seq_num.psn_gen &
			HFI_BTH_GEN_MASK) << HFI_BTH_GEN_SHIFT));
		scb->seq_num.psn_gen = flow->xmit_seq_num.psn_gen;
		scb = SLIST_NEXT(scb, next);
	}
}

/* NAK post process for dma flow */
void ips_dmaflow_nak_post_process(struct ips_proto *proto,
				  struct ips_flow *flow)
{
	ips_scb_t *scb;
	uint32_t first_num, ack_num;

	scb = STAILQ_FIRST(&flow->scb_unacked);
	first_num = __be32_to_cpu(scb->ips_lrh.bth[2]) & proto->psn_mask;
	ack_num = (flow->xmit_ack_num.psn_num - 1) & proto->psn_mask;

	/* If the ack PSN falls into a multi-packets scb,
	 * don't re-send the packets already acked. */
	psmi_assert(scb->nfrag > 1);
	if (between(first_num, scb->seq_num.psn_num, ack_num)) {
		uint32_t npkt, pktlen, nbytes;

		/* how many packets acked in this scb */
		npkt = ((ack_num - first_num) & proto->psn_mask) + 1;

		/* how many bytes acked in this scb, for eager receive
		 * packets, all payload size is frag_size except the
		 * last packet which is not acked yet */
		pktlen = scb->frag_size;
		nbytes = (((ack_num - first_num) &
			proto->psn_mask) + 1) * pktlen;

		/* 0. update scb info */
		psmi_assert(scb->nfrag_remaining > npkt);
		scb->nfrag_remaining -= npkt;
		psmi_assert(scb->chunk_size_remaining > nbytes);
		scb->chunk_size_remaining -= nbytes;
		scb->payload = (void *)((char *)scb->payload + nbytes);

		/* 1. if last packet in sequence, set ACK */
		if (scb->chunk_size_remaining <= scb->frag_size) {
			psmi_assert(scb->nfrag_remaining == 1);
			scb->flags |= IPS_SEND_FLAG_ACKREQ;

			/* last packet is what remaining */
			pktlen = scb->chunk_size_remaining;
		}

		/* 2. set new packet sequence number */
		scb->ips_lrh.bth[2] = __cpu_to_be32(
			((ack_num + 1) & proto->psn_mask) |
			(scb->flags & IPS_SEND_FLAG_ACKREQ));

		/* 3. set new packet offset */
		ips_scb_hdrdata(scb).u32w0 += nbytes;

		/* 4. if packet length is changed, set new length */
		if (scb->payload_size != pktlen) {
			scb->payload_size = pktlen;
			scb->ips_lrh.lrh[2] = __cpu_to_be16((
				(scb->payload_size +
				sizeof(struct ips_message_header) +
				HFI_CRC_SIZE_IN_BYTES) >>
				BYTE2DWORD_SHIFT) & HFI_LRH_PKTLEN_MASK);
		}
	}
}

/* process an incoming ack message.  Separate function to allow */
/* for better optimization by compiler */
int
ips_proto_process_ack(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_proto *proto = rcv_ev->proto;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_flow *flow = NULL;
	struct ips_scb_unackedq *unackedq;
	struct ips_scb_pendlist *scb_pend;
	psmi_seqnum_t ack_seq_num, last_seq_num;
	ips_epaddr_flow_t flowid;
	ips_scb_t *scb;
	uint32_t tidctrl;

	ack_seq_num.psn_num = p_hdr->ack_seq_num;
	tidctrl = GET_HFI_KHDR_TIDCTRL(__le32_to_cpu(p_hdr->khdr.kdeth0));
	if (!tidctrl && ((flowid = ips_proto_flowid(p_hdr)) < EP_FLOW_TIDFLOW)) {
		ack_seq_num.psn_num =
		    (ack_seq_num.psn_num - 1) & proto->psn_mask;
		psmi_assert(flowid < EP_FLOW_LAST);
		flow = &ipsaddr->flows[flowid];
		if (!pio_dma_ack_valid(proto, flow, ack_seq_num))
			goto ret;
	} else {
		ack_seq_num.psn_seq -= 1;
		flow = get_tidflow(proto, ipsaddr, p_hdr, ack_seq_num);
		if (!flow)	/* Invalid ack for flow */
			goto ret;
	}
	flow->xmit_ack_num.psn_num = p_hdr->ack_seq_num;

	unackedq = &flow->scb_unacked;
	scb_pend = &flow->scb_pend;

	if (STAILQ_EMPTY(unackedq))
		goto ret;

	last_seq_num = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num;

	INC_TIME_SPEND(TIME_SPEND_USER2);

	/* For tidflow, psn_gen matches. So for all flows, tid/pio/dma,
	 * we can used general psn_num to compare the PSN. */
	while (between((scb = STAILQ_FIRST(unackedq))->seq_num.psn_num,
		       last_seq_num.psn_num, ack_seq_num.psn_num)
	    ) {

		/* take it out of the xmit queue and ..  */
		if (scb == SLIST_FIRST(scb_pend)) {
#ifdef PSM_DEBUG
			flow->scb_num_pending--;
#endif
			SLIST_REMOVE_HEAD(scb_pend, next);
		}

		STAILQ_REMOVE_HEAD(unackedq, nextq);
#ifdef PSM_DEBUG
		flow->scb_num_unacked--;
		psmi_assert(flow->scb_num_unacked >= flow->scb_num_pending);
#endif
		flow->credits += scb->nfrag;

		if (flow->transfer == PSM_TRANSFER_DMA &&
				scb->dma_complete == 0)
			ips_proto_dma_wait_until(proto, scb);

		if (scb->callback)
			(*scb->callback) (scb->cb_param, scb->nfrag > 1 ?
					  scb->chunk_size : scb->payload_size);

		if (!(scb->flags & IPS_SEND_FLAG_PERSISTENT))
			ips_scbctrl_free(scb);

		/* set all index pointer to NULL if all frames have been
		 * acked */
		if (STAILQ_EMPTY(unackedq)) {
			psmi_timer_cancel(proto->timerq, flow->timer_ack);
			psmi_mpool_put(flow->timer_ack);
			flow->timer_ack = NULL;
			psmi_timer_cancel(proto->timerq, flow->timer_send);
			psmi_mpool_put(flow->timer_send);
			flow->timer_send = NULL;
			SLIST_FIRST(scb_pend) = NULL;
			psmi_assert(flow->scb_num_pending == 0);
			/* Reset congestion window - all packets ACK'd */
			flow->credits = flow->cwin = proto->flow_credits;
			flow->ack_interval = max((flow->credits >> 2) - 1, 1);
			flow->flags &= ~IPS_FLOW_FLAG_CONGESTED;
			goto ret;
		}
	}

	/* CCA: If flow is congested adjust rate */
	if_pf(rcv_ev->is_congested & IPS_RECV_EVENT_BECN) {
		if ((flow->path->pr_ccti +
		     proto->cace[flow->path->pr_sl].ccti_increase) <=
		    proto->ccti_limit) {
			ips_cca_adjust_rate(flow->path,
					    proto->cace[flow->path->pr_sl].
					    ccti_increase);
			/* Clear congestion event */
			rcv_ev->is_congested &= ~IPS_RECV_EVENT_BECN;
		}
	}
	else {
		/* Increase congestion window if flow is not congested */
		if_pf(flow->cwin < proto->flow_credits) {
			flow->credits +=
			    min(flow->cwin << 1,
				proto->flow_credits) - flow->cwin;
			flow->cwin = min(flow->cwin << 1, proto->flow_credits);
			flow->ack_interval = max((flow->credits >> 2) - 1, 1);
		}
	}

	/* Reclaimed some credits - attempt to flush flow */
	flow->flush(flow, NULL);

	/*
	 * If the next packet has not even been put on the wire, cancel the
	 * retransmission timer since we're still presumably waiting on free
	 * pio bufs
	 */
	if (STAILQ_FIRST(unackedq)->abs_timeout == TIMEOUT_INFINITE)
		psmi_timer_cancel(proto->timerq, flow->timer_ack);

ret:
	return IPS_RECVHDRQ_CONTINUE;
}

/* process an incoming nack message.  Separate function to allow */
/* for better optimization by compiler */
int ips_proto_process_nak(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_proto *proto = rcv_ev->proto;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_flow *flow = NULL;
	struct ips_scb_unackedq *unackedq;
	struct ips_scb_pendlist *scb_pend;
	psmi_seqnum_t ack_seq_num, last_seq_num;
	psm_protocol_type_t protocol;
	ips_epaddr_flow_t flowid;
	ips_scb_t *scb;
	uint32_t tidctrl;

	INC_TIME_SPEND(TIME_SPEND_USER3);

	ack_seq_num.psn_num = p_hdr->ack_seq_num;
	tidctrl = GET_HFI_KHDR_TIDCTRL(__le32_to_cpu(p_hdr->khdr.kdeth0));
	if (!tidctrl && ((flowid = ips_proto_flowid(p_hdr)) < EP_FLOW_TIDFLOW)) {
		protocol = PSM_PROTOCOL_GO_BACK_N;
		psmi_assert(flowid < EP_FLOW_LAST);
		flow = &ipsaddr->flows[flowid];
		if (!pio_dma_ack_valid(proto, flow, ack_seq_num))
			goto ret;
		ack_seq_num.psn_num =
		    (ack_seq_num.psn_num - 1) & proto->psn_mask;
		flow->xmit_ack_num.psn_num = p_hdr->ack_seq_num;
	} else {
		protocol = PSM_PROTOCOL_TIDFLOW;
		flow = get_tidflow(proto, ipsaddr, p_hdr, ack_seq_num);
		if (!flow)
			goto ret;	/* Invalid ack for flow */
		ack_seq_num.psn_seq--;

		psmi_assert(flow->xmit_seq_num.psn_gen == ack_seq_num.psn_gen);
		psmi_assert(flow->xmit_ack_num.psn_gen == ack_seq_num.psn_gen);
		/* Update xmit_ack_num with both new generation and new
		 * acked sequence; update xmit_seq_num with the new flow
		 * generation, don't change the sequence number. */
		flow->xmit_ack_num = (psmi_seqnum_t) p_hdr->data[1].u32w0;
		flow->xmit_seq_num.psn_gen = flow->xmit_ack_num.psn_gen;
		psmi_assert(flow->xmit_seq_num.psn_gen != ack_seq_num.psn_gen);
	}

	unackedq = &flow->scb_unacked;
	scb_pend = &flow->scb_pend;

	if (STAILQ_EMPTY(unackedq))
		goto ret;

	last_seq_num = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num;

	proto->epaddr_stats.nak_recv++;

	_HFI_VDBG("got a nack %d on flow %d, "
		  "first is %d, last is %d\n", ack_seq_num.psn_num,
		  flow->flowid,
		  STAILQ_EMPTY(unackedq) ? -1 : STAILQ_FIRST(unackedq)->seq_num.
		  psn_num, STAILQ_EMPTY(unackedq) ? -1 : STAILQ_LAST(unackedq,
								     ips_scb,
								     nextq)->
		  seq_num.psn_num);

	/* For tidflow, psn_gen matches. So for all flows, tid/pio/dma,
	 * we can used general psn_num to compare the PSN. */
	while (between((scb = STAILQ_FIRST(unackedq))->seq_num.psn_num,
		       last_seq_num.psn_num, ack_seq_num.psn_num)
	    ) {
		/* take it out of the xmit queue and ..  */
		if (scb == SLIST_FIRST(scb_pend)) {
#ifdef PSM_DEBUG
			flow->scb_num_pending--;
#endif
			SLIST_REMOVE_HEAD(scb_pend, next);
		}

		STAILQ_REMOVE_HEAD(unackedq, nextq);
#ifdef PSM_DEBUG
		flow->scb_num_unacked--;
		psmi_assert(flow->scb_num_unacked >= flow->scb_num_pending);
#endif

		if (flow->transfer == PSM_TRANSFER_DMA &&
				scb->dma_complete == 0)
			ips_proto_dma_wait_until(proto, scb);

		if (scb->callback)
			(*scb->callback) (scb->cb_param, scb->nfrag > 1 ?
					  scb->chunk_size : scb->payload_size);

		if (!(scb->flags & IPS_SEND_FLAG_PERSISTENT))
			ips_scbctrl_free(scb);

		/* set all index pointer to NULL if all frames has been acked */
		if (STAILQ_EMPTY(unackedq)) {
			psmi_timer_cancel(proto->timerq, flow->timer_ack);
			psmi_mpool_put(flow->timer_ack);
			flow->timer_ack = NULL;
			psmi_timer_cancel(proto->timerq, flow->timer_send);
			psmi_mpool_put(flow->timer_send);
			flow->timer_send = NULL;
			SLIST_FIRST(scb_pend) = NULL;
			psmi_assert(flow->scb_num_pending == 0);
			/* Reset congestion window if all packets acknowledged */
			flow->credits = flow->cwin = proto->flow_credits;
			flow->ack_interval = max((flow->credits >> 2) - 1, 1);
			flow->flags &= ~IPS_FLOW_FLAG_CONGESTED;
			goto ret;
		}
	}

	psmi_assert(!STAILQ_EMPTY(unackedq));	/* sanity for above loop */

	if (protocol == PSM_PROTOCOL_TIDFLOW)
		ips_tidflow_nak_post_process(proto, flow);
	else if (scb->nfrag > 1)
		ips_dmaflow_nak_post_process(proto, flow);

	/* Always cancel ACK timer as we are going to restart the flow */
	psmi_timer_cancel(proto->timerq, flow->timer_ack);

	/* What's now pending is all that was unacked */
	SLIST_FIRST(scb_pend) = scb;
#ifdef PSM_DEBUG
	flow->scb_num_pending = flow->scb_num_unacked;
#endif
	while (scb && !(scb->flags & IPS_SEND_FLAG_PENDING)) {
		/* Wait for the previous dma completion */
		if (flow->transfer == PSM_TRANSFER_DMA &&
				scb->dma_complete == 0)
			ips_proto_dma_wait_until(proto, scb);

		scb->flags |= IPS_SEND_FLAG_PENDING;
		scb = SLIST_NEXT(scb, next);
	}

	/* If NAK with congestion bit set - delay re-transmitting and THEN adjust
	 * CCA rate.
	 */
	if_pf(rcv_ev->is_congested & IPS_RECV_EVENT_BECN) {
		uint64_t offset;

		/* Clear congestion event and mark flow as congested */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_BECN;
		flow->flags |= IPS_FLOW_FLAG_CONGESTED;

		/* For congested flow use slow start i.e. reduce congestion window.
		 * For TIDFLOW we cannot reduce congestion window as peer expects
		 * header packets at regular intervals (protoexp->hdr_pkt_interval).
		 */
		if (flow->protocol != PSM_PROTOCOL_TIDFLOW)
			flow->credits = flow->cwin = 1;
		else
			flow->credits = flow->cwin;

		flow->ack_interval = max((flow->credits >> 2) - 1, 1);

		/* During congestion cancel send timer and delay retransmission by
		 * random interval
		 */
		psmi_timer_cancel(proto->timerq, flow->timer_send);
		if (SLIST_FIRST(scb_pend)->ack_timeout != TIMEOUT_INFINITE)
			offset = (SLIST_FIRST(scb_pend)->ack_timeout >> 1);
		else
			offset = 0;
		psmi_timer_request(proto->timerq, flow->timer_send,
				   (get_cycles() +
				    (uint64_t) (offset *
						(rand() / RAND_MAX + 1.0))));
	}
	else {
		int num_resent = 0;

		/* Reclaim all credits upto congestion window only */
		flow->credits = flow->cwin;
		flow->ack_interval = max((flow->credits >> 2) - 1, 1);

		/* Flush pending scb's */
		flow->flush(flow, &num_resent);

		proto->epaddr_stats.send_rexmit += num_resent;
	}

ret:
	return IPS_RECVHDRQ_CONTINUE;
}

int
ips_proto_process_err_chk(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_recvhdrq *recvq = (struct ips_recvhdrq *)rcv_ev->recvq;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	ips_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
	struct ips_flow *flow;
	psmi_seqnum_t seq_num;
	int16_t seq_off;

	INC_TIME_SPEND(TIME_SPEND_USER4);
	PSM2_LOG_MSG("entering");
	psmi_assert(flowid < EP_FLOW_LAST);
	flow = &ipsaddr->flows[flowid];
	recvq->proto->epaddr_stats.err_chk_recv++;
	/* Ignore FECN bit since this is the control path */
	rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;

	seq_num.psn_val = __be32_to_cpu(p_hdr->bth[2]);
	seq_off = (int16_t) (flow->recv_seq_num.psn_num - seq_num.psn_num);

	if_pf(seq_off <= 0) {
		_HFI_VDBG("naking for seq=%d, off=%d on flowid  %d\n",
			  seq_num.psn_num, seq_off, flowid);

		if (seq_off < -flow->ack_interval)
			flow->flags |= IPS_FLOW_FLAG_GEN_BECN;

		ips_proto_send_nak(recvq, flow);
		flow->flags |= IPS_FLOW_FLAG_NAK_SEND;
	}
	else {
		ips_scb_t ctrlscb;

		ctrlscb.flags = 0;
		ctrlscb.ips_lrh.ack_seq_num = flow->recv_seq_num.psn_num;

		ips_proto_send_ctrl_message(flow, OPCODE_ACK,
					    &ipsaddr->ctrl_msg_queued,
					    &ctrlscb, ctrlscb.cksum, 0);
	}

	PSM2_LOG_MSG("leaving");
	return IPS_RECVHDRQ_CONTINUE;
}

int
ips_proto_process_err_chk_gen(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_recvhdrq *recvq = (struct ips_recvhdrq *)rcv_ev->recvq;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_protoexp *protoexp = recvq->proto->protoexp;
	struct ips_tid_recv_desc *tidrecvc;
	ips_scb_t ctrlscb;
	psmi_seqnum_t err_seqnum, recvseq;
	ptl_arg_t desc_id = p_hdr->data[0];
	ptl_arg_t send_desc_id = p_hdr->data[1];
	int16_t seq_off;
	uint8_t ack_type;

	INC_TIME_SPEND(TIME_SPEND_USER4);
	PSM2_LOG_MSG("entering");
	recvq->proto->epaddr_stats.err_chk_recv++;

	/* Ignore FECN bit since this is the control path */
	rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;

	/* Get the flowgenseq for err chk gen */
	err_seqnum.psn_val = __be32_to_cpu(p_hdr->bth[2]);

	/* Get receive descriptor */
	psmi_assert(desc_id._desc_idx < HFI_TF_NFLOWS);
	tidrecvc = &protoexp->tfc.tidrecvc[desc_id._desc_idx];

	if (tidrecvc->rdescid._desc_genc != desc_id._desc_genc) {
		/* Receive descriptor mismatch in time and space.
		 * Stale err chk gen, drop packet
		 */
		_HFI_DBG
		    ("ERR_CHK_GEN: gen mismatch Pkt: 0x%x, Current: 0x%x\n",
		     desc_id._desc_genc, tidrecvc->rdescid._desc_genc);
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_CONTINUE;
	}
	psmi_assert(tidrecvc->state == TIDRECVC_STATE_BUSY);

	/*
	 * We change tidrecvc->tidflow_genseq here only when a new generation
	 * is allocated and programmed into hardware. Otherwise we use local
	 * variable recvseq to create the reply.
	 */
	recvseq = tidrecvc->tidflow_genseq;

	/* Get the latest seq from hardware tidflow table. But
	 * only do this when context sharing is not used, because
	 * context sharing might drop packet even though hardware
	 * has received it successfully.
	 */
	if (!tidrecvc->context->tf_ctrl)
		recvseq.psn_seq = hfi_tidflow_get_seqnum(
			hfi_tidflow_get(tidrecvc->context->ctrl,
			tidrecvc->rdescid._desc_idx));

	if (err_seqnum.psn_gen != recvseq.psn_gen) {
		ack_type = OPCODE_NAK;
		/* NAK without allocating a new generation */

		/* My current generation and last received seq */
		ctrlscb.ips_lrh.data[1].u32w0 = recvseq.psn_val;
	 } else {
		/* Either lost packets or lost ack, we need to deal
		 * with wrap around of the seq value from 2047 to 0
		 * because seq is only 11 bits */
		seq_off = (int16_t)(err_seqnum.psn_seq - recvseq.psn_seq);
		if (seq_off < 0)
			seq_off += 2048; /* seq is 11 bits */

		if (seq_off < 1024) {
			ack_type = OPCODE_NAK;
			/* NAK with allocating a new generation */

			/* set latest seq */
			tidrecvc->tidflow_genseq.psn_seq = recvseq.psn_seq;
			/* allocate and set a new generation */
			ips_protoexp_flow_newgen(tidrecvc);
			/* get the new generation */
			recvseq.psn_gen = tidrecvc->tidflow_genseq.psn_gen;

			/* My new generation and last received seq */
			ctrlscb.ips_lrh.data[1].u32w0 = recvseq.psn_val;
		} else
			/* ACK with last received seq,
			 * no need to set ips_lrh.data[1].u32w0 */
			ack_type = OPCODE_ACK;
	}

	ctrlscb.flags = 0;
	ctrlscb.ips_lrh.data[0].u64 = send_desc_id.u64;
	/* Keep peer generation but use my last received sequence */
	err_seqnum.psn_seq = recvseq.psn_seq;
	ctrlscb.ips_lrh.ack_seq_num = err_seqnum.psn_val;

	/* May want to generate a BECN if a lot of swapped generations */
	if_pf((tidrecvc->tidflow_nswap_gen > 4) &&
	      (protoexp->proto->flags & IPS_PROTO_FLAG_CCA)) {
		_HFI_CCADBG
		    ("ERR_CHK_GEN: Generating BECN. Number of swapped generations: %d.\n",
		     tidrecvc->tidflow_nswap_gen);
		/* Mark flow to generate BECN in control packet */
		tidrecvc->tidflow.flags |= IPS_FLOW_FLAG_GEN_BECN;

		/* Update stats for congestion encountered */
		recvq->proto->epaddr_stats.congestion_pkts++;
	}

	ips_proto_send_ctrl_message(&tidrecvc->tidflow,
				    ack_type, &tidrecvc->ctrl_msg_queued,
				    &ctrlscb, ctrlscb.cksum, 0);

	/* Update stats for expected window */
	tidrecvc->stats.nErrChkReceived++;
	if (ack_type == OPCODE_NAK)
		tidrecvc->stats.nReXmit++;	/* Update stats for retransmit (Sent a NAK) */

	PSM2_LOG_MSG("leaving");
	return IPS_RECVHDRQ_CONTINUE;
}

int
ips_proto_process_becn(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_proto *proto = rcv_ev->proto;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	int flowid = ips_proto_flowid(p_hdr);
	struct ips_flow *flow;

	psmi_assert(flowid < EP_FLOW_LAST);
	flow = &ipsaddr->flows[flowid];
	if ((flow->path->pr_ccti +
	proto->cace[flow->path->pr_sl].ccti_increase) <= proto->ccti_limit) {
		ips_cca_adjust_rate(flow->path,
			    proto->cace[flow->path->pr_sl].ccti_increase);
		/* Clear congestion event */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_BECN;
	}

	return IPS_RECVHDRQ_CONTINUE;
}

static void ips_bad_opcode(uint8_t op_code, struct ips_message_header *proto)
{
	_HFI_DBG("Discarding message with bad opcode 0x%x\n", op_code);

	if (hfi_debug & __HFI_DBG) {
		ips_proto_show_header(proto, "received bad opcode");
		ips_proto_dump_frame(proto, sizeof(struct ips_message_header),
				     "Opcode error protocol header dump");
	}
}

int
ips_proto_process_unknown_opcode(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_message_header *protocol_header = rcv_ev->p_hdr;
	struct ips_proto *proto = rcv_ev->proto;

	proto->stats.unknown_packets++;
	ips_bad_opcode(_get_proto_hfi_opcode(protocol_header), protocol_header);

	return IPS_RECVHDRQ_CONTINUE;
}

int
ips_proto_connect_disconnect(struct ips_recvhdrq_event *rcv_ev)
{
	psm2_error_t err = PSM2_OK;
	char *payload = ips_recvhdrq_event_payload(rcv_ev);
	uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev);

	psmi_assert(payload);
	err = ips_proto_process_connect(rcv_ev->proto,
					_get_proto_hfi_opcode(rcv_ev->p_hdr),
					rcv_ev->p_hdr,
					payload,
					paylen);
	if (err != PSM2_OK)
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
			"Process connect/disconnect error: %d, opcode %d\n",
			err, _get_proto_hfi_opcode(rcv_ev->p_hdr));

	return IPS_RECVHDRQ_CONTINUE;
}

/* Return 1 if packet is ok. */
/* Return 0 if packet should be skipped */
int ips_proto_process_unknown(const struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	uint8_t ptype = rcv_ev->ptype;
	struct ips_proto *proto = rcv_ev->proto;
	psm2_ep_t ep_err;
	char *pkt_type;
	int opcode = (int)_get_proto_hfi_opcode(p_hdr);

	/*
	 * If the protocol is disabled or not yet enabled, no processing happens
	 * We set it t_init to 0 when disabling the protocol
	 */
	if (proto->t_init == 0)
		return IPS_RECVHDRQ_CONTINUE;

	/* Connect messages don't have to be from a known epaddr */
	switch (opcode) {
	case OPCODE_CONNECT_REQUEST:
	case OPCODE_CONNECT_REPLY:
	case OPCODE_DISCONNECT_REQUEST:
	case OPCODE_DISCONNECT_REPLY:
		ips_proto_connect_disconnect(
				(struct ips_recvhdrq_event *)rcv_ev);
		return IPS_RECVHDRQ_CONTINUE;
	default:
		break;
	}

	/* Packet from "unknown" peer. Log the packet and payload if at appropriate
	 * verbose level.
	 */
	{
		char *payload = ips_recvhdrq_event_payload(rcv_ev);
		uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
		    ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);

		ips_proto_dump_err_stats(proto);

		if (hfi_debug & __HFI_PKTDBG) {
			ips_proto_dump_frame(rcv_ev->p_hdr,
					     HFI_MESSAGE_HDR_SIZE, "header");
			if (paylen)
				ips_proto_dump_frame(payload, paylen, "data");
		}
	}

	/* Other messages are definitely crosstalk. */
	/* out-of-context expected messages are always fatal */
	if (ptype == RCVHQ_RCV_TYPE_EXPECTED) {
		ep_err = PSMI_EP_NORETURN;
		pkt_type = "expected";
	} else if (ptype == RCVHQ_RCV_TYPE_EAGER) {
		ep_err = PSMI_EP_LOGEVENT;
		pkt_type = "eager";
	} else {
		ep_err = PSMI_EP_NORETURN;
		pkt_type = "unknown";
	}

	proto->stats.stray_packets++;

	/* If we have debug mode, print the complete packet every time */
	if (hfi_debug & __HFI_PKTDBG)
		ips_proto_show_header(p_hdr, "invalid connidx");

	/* At this point we are out of luck. */
	psmi_handle_error(ep_err, PSM2_EPID_NETWORK_ERROR,
			  "Received %s message(s) ptype=0x%x opcode=0x%x"
			  " from an unknown process", pkt_type, ptype, opcode);

	return 0;		/* Always skip this packet unless the above call was a noreturn
				 * call */
}

/* get the error string as a number and a string */
static void rhf_errnum_string(char *msg, size_t msglen, long err)
{
	int len;
	char *errmsg;

	len = snprintf(msg, msglen, "RHFerror %lx: ", err);
	if (len > 0 && len < msglen) {
		errmsg = msg + len;
		msglen -= len;
	} else
		errmsg = msg;
	*errmsg = 0;
	ips_proto_get_rhf_errstring(err, errmsg, msglen);
}

/*
 * Error handling
 */
int ips_proto_process_packet_error(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_proto *proto = rcv_ev->proto;
	int pkt_verbose_err = hfi_debug & __HFI_PKTDBG;
	int tiderr = rcv_ev->error_flags & HFI_RHF_TIDERR;
	int tf_seqerr = rcv_ev->error_flags & HFI_RHF_TFSEQERR;
	int tf_generr = rcv_ev->error_flags & HFI_RHF_TFGENERR;
	int data_err = rcv_ev->error_flags &
	    (HFI_RHF_ICRCERR | HFI_RHF_ECCERR | HFI_RHF_LENERR |
	     HFI_RHF_DCERR | HFI_RHF_DCUNCERR | HFI_RHF_KHDRLENERR);
	char pktmsg[128];

	*pktmsg = 0;
	/*
	 * Tid errors on eager pkts mean we get a headerq overflow, perfectly
	 * safe.  Tid errors on expected or other packets means trouble.
	 */
	if (tiderr && rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER) {
		struct ips_message_header *p_hdr = rcv_ev->p_hdr;

		/* Payload dropped - Determine flow for this header and see if
		 * we need to generate a NAK.
		 *
		 * ALL PACKET DROPS IN THIS CATEGORY CAN BE FLAGGED AS DROPPED DUE TO
		 * CONGESTION AS THE EAGER BUFFER IS FULL.
		 *
		 * Possible eager packet type:
		 *
		 * Ctrl Message - ignore
		 * MQ message - Can get flow and see if we need to NAK.
		 * AM message - Can get flow and see if we need to NAK.
		 */

		proto->stats.hdr_overflow++;
		if (data_err)
			return 0;

		switch (_get_proto_hfi_opcode(p_hdr)) {
		case OPCODE_TINY:
		case OPCODE_SHORT:
		case OPCODE_EAGER:
		case OPCODE_LONG_RTS:
		case OPCODE_LONG_CTS:
		case OPCODE_LONG_DATA:
		case OPCODE_AM_REQUEST:
		case OPCODE_AM_REQUEST_NOREPLY:
		case OPCODE_AM_REPLY:
			{
				ips_epaddr_flow_t flowid =
				    ips_proto_flowid(p_hdr);
				struct ips_epstate_entry *epstaddr;
				struct ips_flow *flow;
				psmi_seqnum_t sequence_num;
				int16_t diff;

				/* Obtain ipsaddr for packet */
				epstaddr =
				    ips_epstate_lookup(rcv_ev->recvq->epstate,
						       rcv_ev->p_hdr->connidx);
				if_pf(epstaddr == NULL
				      || epstaddr->ipsaddr == NULL)
				    return 0;	/* Unknown packet - drop */

				rcv_ev->ipsaddr = epstaddr->ipsaddr;

				psmi_assert(flowid < EP_FLOW_LAST);
				flow = &rcv_ev->ipsaddr->flows[flowid];
				sequence_num.psn_val =
				    __be32_to_cpu(p_hdr->bth[2]);
				diff =
				    (int16_t) (sequence_num.psn_num -
					       flow->recv_seq_num.psn_num);

				if (diff >= 0
				    && !(flow->
					 flags & IPS_FLOW_FLAG_NAK_SEND)) {
					/* Mark flow as congested and attempt to generate NAK */
					flow->flags |= IPS_FLOW_FLAG_GEN_BECN;
					proto->epaddr_stats.congestion_pkts++;

					flow->flags |= IPS_FLOW_FLAG_NAK_SEND;
					flow->cca_ooo_pkts = 0;
					ips_proto_send_nak((struct ips_recvhdrq
							    *)rcv_ev->recvq,
							   flow);
				}

				/* Safe to process ACKs from header */
				ips_proto_process_ack(rcv_ev);
			}
			break;
		default:
			break;
		}
	} else if (tf_generr) /* handle generr, ignore tiderr if any */
		ips_protoexp_handle_tf_generr(rcv_ev);
	else if (tf_seqerr)
		ips_protoexp_handle_tf_seqerr(rcv_ev);
	else if (tiderr) {	/* tid error, but not on an eager pkt */
		psm2_ep_t ep_err = PSMI_EP_LOGEVENT;
		uint16_t tid, offset;
		uint64_t t_now = get_cycles();

		proto->tiderr_cnt++;

		/* Whether and how we will be logging this event */
		if (proto->tiderr_max > 0
		    && proto->tiderr_cnt >= proto->tiderr_max)
			ep_err = PSMI_EP_NORETURN;
		else if (proto->tiderr_warn_interval != UINT64_MAX &&
			 proto->tiderr_tnext <= t_now)
			proto->tiderr_tnext =
			    get_cycles() + proto->tiderr_warn_interval;
		else
			ep_err = NULL;

		if (ep_err != NULL) {
			rhf_errnum_string(pktmsg, sizeof(pktmsg),
					  rcv_ev->error_flags);

			tid = (__le32_to_cpu(rcv_ev->p_hdr->khdr.kdeth0) >>
			       HFI_KHDR_TID_SHIFT) & HFI_KHDR_TID_MASK;
			offset = __le32_to_cpu(rcv_ev->p_hdr->khdr.kdeth0) &
			    HFI_KHDR_OFFSET_MASK;

			psmi_handle_error(ep_err, PSM2_EP_DEVICE_FAILURE,
					  "%s with tid=%d,offset=%d,count=%d: %s %s",
					  "TID Error",
					  tid, offset, proto->tiderr_cnt,
					  pktmsg, ep_err == PSMI_EP_NORETURN ?
					  "(Terminating...)" : "");
		}

		ips_protoexp_handle_tiderr(rcv_ev);
	} else if (data_err) {
		uint8_t op_code = _get_proto_hfi_opcode(rcv_ev->p_hdr);

		if (!pkt_verbose_err) {
			rhf_errnum_string(pktmsg, sizeof(pktmsg),
					  rcv_ev->error_flags);
			_HFI_DBG
			    ("Error %s pkt type opcode 0x%x at hd=0x%x %s\n",
			     (rcv_ev->ptype ==
			      RCVHQ_RCV_TYPE_EAGER) ? "eager" : (rcv_ev->
								 ptype ==
								 RCVHQ_RCV_TYPE_EXPECTED)
			     ? "expected" : (rcv_ev->ptype ==
					     RCVHQ_RCV_TYPE_NON_KD) ? "non-kd" :
			     "<error>", op_code,
			     rcv_ev->recvq->state->hdrq_head, pktmsg);
		}

		if (rcv_ev->ptype == RCVHQ_RCV_TYPE_EXPECTED)
			ips_protoexp_handle_data_err(rcv_ev);
	} else {		/* not a tid or data error -- some other error */
		uint8_t op_code =
		    __be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 24 & 0xFF;

		if (!pkt_verbose_err)
			rhf_errnum_string(pktmsg, sizeof(pktmsg),
					  rcv_ev->error_flags);

		/* else RHFerr decode printed below */
		_HFI_DBG("Error pkt type 0x%x opcode 0x%x at hd=0x%x %s\n",
			 rcv_ev->ptype, op_code,
			 rcv_ev->recvq->state->hdrq_head, pktmsg);
	}
	if (pkt_verbose_err) {
		if (!*pktmsg)
			rhf_errnum_string(pktmsg, sizeof(pktmsg),
					  rcv_ev->error_flags);
		ips_proto_show_header(rcv_ev->p_hdr, pktmsg);
	}

	return 0;
}
