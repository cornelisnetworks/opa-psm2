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

#ifndef _IPS_WRITEHDRQ_H
#define _IPS_WRITEHDRQ_H

#include "psm_user.h"
#include "ips_recvhdrq.h"
#include "ips_recvq.h"
#include "psm_mq_internal.h"

/*
 * Structure containing state for writehdrq writing. This is logically
 * part of ips_writehdrq but needs to be separated out for context
 * sharing so that it can be put in a shared memory page and hence
 * be available to all processes sharing the port. Generally, do not
 * put pointers in here since the address map of each process can be
 * different.
 */
struct ips_writehdrq_state {
	uint32_t hdrq_rhf_seq;	/* last seq */
	uint32_t egrq_offset;	/* in bytes unit, not 64B */
	uint32_t enabled;	/* enables writing */
};

struct ips_writehdrq {
	const psmi_context_t *context;
	struct ips_writehdrq_state *state;
	struct ips_recvq_params hdrq;
	uint32_t hdrq_elemlast;
	uint32_t hdrq_rhf_off;	/* rhf offset */
	uint32_t hdrq_hdr_copysz;
	struct ips_recvq_params egrq;
	void **egrq_buftable;	/* table of eager idx-to-ptr */
	uint32_t runtime_flags;
};

psm2_error_t
ips_writehdrq_init(const psmi_context_t *context,
		   const struct ips_recvq_params *hdrq_params,
		   const struct ips_recvq_params *egrq_params,
		   struct ips_writehdrq *writeq,
		   struct ips_writehdrq_state *state, uint32_t runtime_flags);

psm2_error_t ips_writehdrq_fini(struct ips_writehdrq *writeq);

PSMI_ALWAYS_INLINE(
void
ips_writehdrq_write_rhf_atomic(uint32_t *rhf_dest, uint32_t *rhf_src))
{
	/*
	 * In 64-bit mode, we check in init that the rhf will always be 8-byte
	 * aligned
	 */
	*((uint64_t *) rhf_dest) = *((uint64_t *) rhf_src);
	return;
}

PSMI_ALWAYS_INLINE(
int
ips_write_eager_packet(struct ips_writehdrq *writeq, uint32_t *write_hdr,
		       uint32_t *write_rhf,
		       const struct ips_recvhdrq_event *rcv_ev))
{
	uint32_t write_egr_tail = ips_recvq_tail_get(&writeq->egrq);
	uint32_t next_write_egr_tail = write_egr_tail;
	/* checksum is trimmed from paylen, we need to add back */
	uint32_t rcv_paylen = ips_recvhdrq_event_paylen(rcv_ev) +
	    (rcv_ev->has_cksum ? PSM_CRC_SIZE_IN_BYTES : 0);
	psmi_assert(rcv_paylen > 0);

	/* Loop as long as the write eager queue is NOT full */
	while (1) {
		next_write_egr_tail++;
		if (next_write_egr_tail >= writeq->egrq.elemcnt)
			next_write_egr_tail = 0;
		if (next_write_egr_tail == ips_recvq_head_get(&writeq->egrq)) {
			break;
		}

		/* Move to next eager entry if leftover is not enough */
		if ((writeq->state->egrq_offset + rcv_paylen) >
		    writeq->egrq.elemsz) {
			writeq->state->egrq_offset = 0;
			write_egr_tail = next_write_egr_tail;

			/* Update the eager buffer tail pointer */
			ips_recvq_tail_update(&writeq->egrq, write_egr_tail);
		} else {
			/* There is enough space in this entry! */
			/* Use pre-calculated address from look-up table */
			char *write_payload =
			    ips_recvq_egr_index_2_ptr(writeq->egrq_buftable,
						      write_egr_tail,
						      writeq->state->
						      egrq_offset);
			const char *rcv_payload =
			    ips_recvhdrq_event_payload(rcv_ev);

			psmi_assert(write_payload != NULL);
			psmi_assert(rcv_payload != NULL);
			psmi_mq_mtucpy(write_payload, rcv_payload, rcv_paylen);

			/* Copy the header to the subcontext's header queue */
			psmi_mq_mtucpy(write_hdr, rcv_ev->rcv_hdr,
				       writeq->hdrq_hdr_copysz);

			/* Fix up the header with the subcontext's eager index/offset */
			hfi_hdrset_egrbfr_index((uint32_t *) write_rhf,
						write_egr_tail);
			hfi_hdrset_egrbfr_offset((uint32_t *) write_rhf,
						 (writeq->state->
						  egrq_offset >> 6));

			/* Update offset to next 64B boundary */
			writeq->state->egrq_offset =
			    (writeq->state->egrq_offset + rcv_paylen +
			     63) & (~63);
			return IPS_RECVHDRQ_CONTINUE;
		}
	}

	/* At this point, the eager queue is full -- drop the packet. */
	/* Copy the header to the subcontext's header queue */
	psmi_mq_mtucpy(write_hdr, rcv_ev->rcv_hdr, writeq->hdrq_hdr_copysz);

	/* Mark header with ETIDERR (eager overflow) */
	hfi_hdrset_err_flags(write_rhf, HFI_RHF_TIDERR);

	/* Clear UseEgrBfr bit because payload is dropped */
	hfi_hdrset_use_egrbfr(write_rhf, 0);
	return IPS_RECVHDRQ_BREAK;
}

PSMI_INLINE(
int
ips_writehdrq_append(struct ips_writehdrq *writeq,
		     const struct ips_recvhdrq_event *rcv_ev))
{
	uint32_t write_hdr_head;
	uint32_t write_hdr_tail;
	uint32_t *write_hdr;
	uint32_t *write_rhf;
	uint32_t next_write_hdr_tail;
	union {
		uint32_t u32[2];
		uint64_t u64;
	} rhf;
	int result = IPS_RECVHDRQ_CONTINUE;

	/* Drop packet if write header queue is disabled */
	if (!writeq->state->enabled) {
		return IPS_RECVHDRQ_BREAK;
	}

	write_hdr_head = ips_recvq_head_get(&writeq->hdrq);
	write_hdr_tail = ips_recvq_tail_get(&writeq->hdrq);
	write_hdr = writeq->hdrq.base_addr + write_hdr_tail;
	write_rhf = write_hdr + writeq->hdrq_rhf_off;

	/* Drop packet if write header queue is full */
	next_write_hdr_tail = write_hdr_tail + writeq->hdrq.elemsz;
	if (next_write_hdr_tail > writeq->hdrq_elemlast) {
		next_write_hdr_tail = 0;
	}
	if (next_write_hdr_tail == write_hdr_head) {
		return IPS_RECVHDRQ_BREAK;
	}

	/*
	 * If not DMA_RTAIL, don't let consumer see RHF until it's ready.
	 * We copy the source rhf and operate on it until we are ready
	 * to atomically update it for the reader.
	 */
	if (!(writeq->runtime_flags & HFI1_CAP_DMA_RTAIL)) {
		write_rhf = &rhf.u32[0];
		rhf.u64 = *((uint64_t *) rcv_ev->rhf);
	}

	if (hfi_hdrget_use_egrbfr(rcv_ev->rhf)) {
		result = ips_write_eager_packet(writeq,
						write_hdr, write_rhf, rcv_ev);
	} else {
		/* Copy the header to the subcontext's header queue */
		psmi_mq_mtucpy(write_hdr, rcv_ev->rcv_hdr,
			       writeq->hdrq_hdr_copysz);
	}

	/* Ensure previous writes are visible before writing rhf seq or tail */
	ips_wmb();

	if (!(writeq->runtime_flags & HFI1_CAP_DMA_RTAIL)) {
		/* We accumulated a few changes to the RHF and now want to make it
		 * atomically visible for the reader.
		 */
		uint32_t rhf_seq = writeq->state->hdrq_rhf_seq;
		hfi_hdrset_seq((uint32_t *) write_rhf, rhf_seq);
		if (rhf_seq >= LAST_RHF_SEQNO)
			writeq->state->hdrq_rhf_seq = 1;
		else
			writeq->state->hdrq_rhf_seq = rhf_seq + 1;

		/* Now write the new rhf */
		ips_writehdrq_write_rhf_atomic(write_hdr + writeq->hdrq_rhf_off,
					       write_rhf);
	}

	/* The tail must be updated regardless of HFI1_CAP_DMA_RTAIL
	 * since this tail is also used to keep track of where
	 * ips_writehdrq_append will write to next. For subcontexts there is
	 * no separate shadow copy of the tail. */
	ips_recvq_tail_update(&writeq->hdrq, next_write_hdr_tail);

	return result;
}

#endif /* _IPS_WRITEHDRQ_H */
