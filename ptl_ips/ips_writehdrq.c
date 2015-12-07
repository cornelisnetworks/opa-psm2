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

#include "ips_writehdrq.h"

psm2_error_t
ips_writehdrq_init(const psmi_context_t *context,
		   const struct ips_recvq_params *hdrq_params,
		   const struct ips_recvq_params *egrq_params,
		   struct ips_writehdrq *writeq,
		   struct ips_writehdrq_state *state, uint32_t runtime_flags)
{
	const struct hfi1_ctxt_info *ctxt_info = &context->ctrl->ctxt_info;

	memset(writeq, 0, sizeof(*writeq));
	writeq->context = context;
	writeq->state = state;
	writeq->hdrq = *hdrq_params;	/* deep copy */
	writeq->hdrq_elemlast =
	    ((writeq->hdrq.elemcnt - 1) * writeq->hdrq.elemsz);
	writeq->egrq = *egrq_params;	/* deep copy */
	writeq->egrq_buftable =
	    ips_recvq_egrbuf_table_alloc(context->ep, writeq->egrq.base_addr,
					 writeq->egrq.elemcnt,
					 writeq->egrq.elemsz);
	writeq->runtime_flags = runtime_flags;
	writeq->hdrq_rhf_off =
	    (ctxt_info->rcvhdrq_entsize - 8) >> BYTE2DWORD_SHIFT;

	if (writeq->runtime_flags & HFI1_CAP_DMA_RTAIL) {
		writeq->hdrq_hdr_copysz =
		    writeq->hdrq.elemsz * sizeof(uint32_t);
		writeq->state->hdrq_rhf_seq = 0;	/* _seq is ignored */
	} else {
		writeq->state->hdrq_rhf_seq = 1;
		/*
		 * We don't allow readers to see the RHF until the writer can
		 * atomically write an updated RHF.
		 */
		writeq->hdrq_hdr_copysz =
		    (writeq->hdrq.elemsz - 2) * sizeof(uint32_t);
		/*
		 * Ensure 8-byte alignment of the RHF by looking at RHF of the second
		 * header, which is required for atomic RHF updates.
		 */
		psmi_assert_always(!((uintptr_t) (writeq->hdrq.base_addr +
						  writeq->hdrq.elemsz +
						  writeq->hdrq_rhf_off) & 0x7));
	}
	writeq->state->enabled = 1;
	return PSM2_OK;
}

psm2_error_t ips_writehdrq_fini(struct ips_writehdrq *writeq)
{
	ips_recvq_egrbuf_table_free(writeq->egrq_buftable);
	return PSM2_OK;
}
