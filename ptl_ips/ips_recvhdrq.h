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
#include "ips_proto_params.h"
#include "ips_proto_header.h"

#ifndef _IPS_RECVHDRQ_H
#define _IPS_RECVHDRQ_H

struct ips_recvhdrq;
struct ips_recvhdrq_state;
struct ips_epstate;

/* process current packet, continue on next packet */
#define IPS_RECVHDRQ_CONTINUE   0
/* process current packet, break and return to caller */
#define IPS_RECVHDRQ_BREAK      1
/* keep current packet, revisit the same packet next time */
#define IPS_RECVHDRQ_REVISIT	2

/* CCA related receive events */
#define IPS_RECV_EVENT_FECN 0x1
#define IPS_RECV_EVENT_BECN 0x2

struct ips_recvhdrq_event {
	struct ips_proto *proto;
	const struct ips_recvhdrq *recvq;	/* where message received */
	psmi_hal_rhf_t psm_hal_rhf;
	struct ips_message_header *p_hdr;	/* protocol header in rcv_hdr */
	struct ips_epaddr *ipsaddr;	/* peer ipsaddr, if available */
	uint8_t has_cksum;	/* payload has cksum */
	uint8_t is_congested;	/* Packet faced congestion */
	psmi_hal_cl_q psm_hal_hdr_q;
};

struct ips_recvhdrq_callbacks {
	int (*callback_packet_unknown) (const struct ips_recvhdrq_event *);
	int (*callback_subcontext) (struct ips_recvhdrq_event *,
				    uint32_t subcontext);
	int (*callback_error) (struct ips_recvhdrq_event *);
};

psm2_error_t
ips_recvhdrq_init(const psmi_context_t *context,
		  const struct ips_epstate *epstate,
		  const struct ips_proto *proto,
		  const struct ips_recvhdrq_callbacks *callbacks,
		  uint32_t subcontext,
		  struct ips_recvhdrq *recvq,
		  struct ips_recvhdrq_state *recvq_state,
		  psmi_hal_cl_q cl_q);

psm2_error_t ips_recvhdrq_progress(struct ips_recvhdrq *recvq);

 /* This function is designed to implement RAPID CCA. It iterates
 * through the recvq, checking each element for set FECN or BECN bits.
 * In the case of finding one, the proper response is executed, and the bits
 * are cleared.
 */
psm2_error_t ips_recvhdrq_scan_cca(struct ips_recvhdrq *recvq);

/*
 * Structure containing state for recvhdrq reading. This is logically
 * part of ips_recvhdrq but needs to be separated out for context
 * sharing so that it can be put in a shared memory page and hence
 * be available to all processes sharing the context. Generally, do not
 * put pointers in here since the address map of each process can be
 * different.
 */
#define NO_EAGER_UPDATE ~0U
struct ips_recvhdrq_state {
	psmi_hal_cl_idx hdrq_head; /* software copy of head */
	psmi_hal_cl_idx rcv_egr_index_head; /* software copy of eager index head */
	uint32_t head_update_interval;	/* Header update interval */
	uint32_t num_hdrq_done;	/* Num header queue done */
	uint32_t egrq_update_interval; /* Eager buffer update interval */
	uint32_t num_egrq_done; /* num eager buffer done */
	uint32_t hdr_countdown;	/* for false-egr-full tracing */
	uint32_t hdrq_cachedlastscan;	/* last element to be prescanned */
};

/*
 * Structure to read from recvhdrq
 */
struct ips_recvhdrq {
	struct ips_proto *proto;
	const psmi_context_t *context;	/* error handling, epid id, etc. */
	struct ips_recvhdrq_state *state;
	uint32_t subcontext;	/* messages that don't match subcontext call
				 * recv_callback_subcontext */
	psmi_hal_cl_q psm_hal_cl_hdrq;
	/* Header queue handling */
	pthread_spinlock_t hdrq_lock;	/* Lock for thread-safe polling */
	uint32_t hdrq_elemlast;	/* last element precomputed */
	/* Lookup endpoints epid -> ptladdr (rank)) */
	const struct ips_epstate *epstate;

	/* Callbacks to handle recvq events */
	struct ips_recvhdrq_callbacks recvq_callbacks;

	/* List of flows with pending acks for receive queue */
	SLIST_HEAD(pending_flows, ips_flow) pending_acks;

	volatile __u64 *spi_status;
};

PSMI_INLINE(int ips_recvhdrq_isempty(const struct ips_recvhdrq *recvq))
{
	return psmi_hal_cl_q_empty(recvq->state->hdrq_head,
				   recvq->psm_hal_cl_hdrq,
		recvq->context->psm_hw_ctxt);
}

PSMI_INLINE(
void *
ips_recvhdrq_event_payload(const struct ips_recvhdrq_event *rcv_ev))
{
	if (psmi_hal_rhf_get_use_egr_buff(rcv_ev->psm_hal_rhf))
		return psmi_hal_get_egr_buff(
			psmi_hal_rhf_get_egr_buff_index(rcv_ev->psm_hal_rhf),
			rcv_ev->psm_hal_hdr_q + 1 /* The circular list q (cl_q) for the
						     egr buff for any rx hdrq event is
						     always one more than the hdrq cl q */,
			rcv_ev->recvq->context->psm_hw_ctxt)+
			(psmi_hal_rhf_get_egr_buff_offset(rcv_ev->psm_hal_rhf)*64);
	else
		return NULL;
}

PSMI_INLINE(
uint32_t
ips_recvhdrq_event_paylen(const struct ips_recvhdrq_event *rcv_ev))
{
	uint32_t cksum_len = rcv_ev->has_cksum ? PSM_CRC_SIZE_IN_BYTES : 0;

	return psmi_hal_rhf_get_packet_length(rcv_ev->psm_hal_rhf) -
	    (sizeof(struct ips_message_header) +
	     HFI_CRC_SIZE_IN_BYTES + cksum_len);
	/* PSM does not use bth0].PadCnt, it figures out real datalen other way */
}

PSMI_INLINE(int ips_recvhdrq_trylock(struct ips_recvhdrq *recvq))
{
	int ret = pthread_spin_trylock(&recvq->hdrq_lock);
	return !ret;
}

PSMI_INLINE(int ips_recvhdrq_lock(struct ips_recvhdrq *recvq))
{
	int ret = pthread_spin_lock(&recvq->hdrq_lock);
	return !ret;
}

PSMI_INLINE(int ips_recvhdrq_unlock(struct ips_recvhdrq *recvq))
{
	int ret = pthread_spin_unlock(&recvq->hdrq_lock);
	return !ret;
}

#endif /* _IPS_RECVHDRQ_H */
