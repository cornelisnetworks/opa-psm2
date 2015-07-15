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
#include "ips_proto.h"
#include "ips_scb.h"

psm_error_t
ips_scbctrl_init(const psmi_context_t *context,
		 uint32_t numscb, uint32_t numbufs,
		 uint32_t imm_size, uint32_t bufsize,
		 ips_scbctrl_avail_callback_fn_t scb_avail_callback,
		 void *scb_avail_context, struct ips_scbctrl *scbc)
{
	int i;
	struct ips_scb *scb;
	size_t scb_size;
	size_t alloc_sz;
	uintptr_t base, imm_base;
	psm_ep_t ep = context->ep;
	/* scbc->context = context; */
	psm_error_t err = PSM_OK;

	psmi_assert_always(numscb > 0);
	scbc->sbuf_num = scbc->sbuf_num_cur = numbufs;
	SLIST_INIT(&scbc->sbuf_free);
	scbc->sbuf_buf_size = bufsize;
	scbc->sbuf_buf_base = NULL;
	scbc->sbuf_buf_alloc = NULL;
	scbc->sbuf_buf_last = NULL;

	/* send buffers are not mandatory but when allocating them, make sure they
	 * are on a page boundary */
	if (numbufs > 0) {
		struct ips_scbbuf *sbuf;
		int redzone = PSM_VALGRIND_REDZONE_SZ;

		/* If the allocation requested is a page and we have redzones we have
		 * to allocate 2 pages so we end up using a redzone of 2048 bytes.
		 *
		 * if the allocation is not 4096, we relax that requirement and keep
		 * the redzones PSM_VALGRIND_REDZONE_SZ
		 */
		if (redzone > 0 && bufsize % PSMI_PAGESIZE == 0)
			redzone = PSMI_PAGESIZE / 2;
		bufsize += 2 * redzone;
		bufsize = PSMI_ALIGNUP(bufsize, 64);

		alloc_sz = numbufs * bufsize + redzone + PSMI_PAGESIZE;
		scbc->sbuf_buf_alloc =
		    psmi_calloc(ep, NETWORK_BUFFERS, 1, alloc_sz);
		if (scbc->sbuf_buf_alloc == NULL) {
			err = PSM_NO_MEMORY;
			goto fail;
		}
		base = (uintptr_t) scbc->sbuf_buf_alloc;
		base = PSMI_ALIGNUP(base + redzone, PSMI_PAGESIZE);
		scbc->sbuf_buf_base = (void *)base;
		scbc->sbuf_buf_last = (void *)(base + bufsize * (numbufs - 1));
		_HFI_VDBG
		    ("sendbufs=%d, (redzone=%d|size=%d|redzone=%d),base=[%p..%p)\n",
		     numbufs, redzone, bufsize - 2 * redzone, redzone,
		     (void *)scbc->sbuf_buf_base, (void *)scbc->sbuf_buf_last);

		for (i = 0; i < numbufs; i++) {
			sbuf = (struct ips_scbbuf *)(base + bufsize * i);
			SLIST_NEXT(sbuf, next) = NULL;
			SLIST_INSERT_HEAD(&scbc->sbuf_free, sbuf, next);
		}

		VALGRIND_CREATE_MEMPOOL(scbc->sbuf_buf_alloc, 0,
					/* Should be undefined but we stuff a next
					 * pointer in the buffer */
					PSM_VALGRIND_MEM_DEFINED);
	}

	imm_base = 0;
	scbc->scb_imm_size = imm_size;
	if (scbc->scb_imm_size) {
		scbc->scb_imm_size = PSMI_ALIGNUP(imm_size, 64);
		alloc_sz = numscb * scbc->scb_imm_size + 64;
		scbc->scb_imm_buf =
		    psmi_calloc(ep, NETWORK_BUFFERS, 1, alloc_sz);
		if (scbc->scb_imm_buf == NULL) {
			err = PSM_NO_MEMORY;
			goto fail;
		}
		imm_base = PSMI_ALIGNUP(scbc->scb_imm_buf, 64);
	} else
		scbc->scb_imm_buf = NULL;

	scbc->scb_num = scbc->scb_num_cur = numscb;
	SLIST_INIT(&scbc->scb_free);
	scb_size = sizeof(struct ips_scb) + 2 * PSM_VALGRIND_REDZONE_SZ;
	scb_size = PSMI_ALIGNUP(scb_size, 64);
	alloc_sz = numscb * scb_size + PSM_VALGRIND_REDZONE_SZ + 64;
	scbc->scb_base = (void *)
	    psmi_calloc(ep, NETWORK_BUFFERS, 1, alloc_sz);
	if (scbc->scb_base == NULL) {
		err = PSM_NO_MEMORY;
		goto fail;
	}
	base = (uintptr_t) scbc->scb_base;
	base = PSMI_ALIGNUP(base + PSM_VALGRIND_REDZONE_SZ, 64);
	for (i = 0; i < numscb; i++) {
		scb = (struct ips_scb *)(base + i * scb_size);
		scb->scbc = scbc;
		if (scbc->scb_imm_buf)
			scb->imm_payload =
			    (void *)(imm_base + (i * scbc->scb_imm_size));
		else
			scb->imm_payload = NULL;

		SLIST_INSERT_HEAD(&scbc->scb_free, scb, next);
	}
	scbc->scb_avail_callback = scb_avail_callback;
	scbc->scb_avail_context = scb_avail_context;

	/* It would be nice to mark the scb as undefined but we pre-initialize the
	 * "next" pointer and valgrind would see this as a violation.
	 */
	VALGRIND_CREATE_MEMPOOL(scbc, PSM_VALGRIND_REDZONE_SZ,
				PSM_VALGRIND_MEM_DEFINED);

fail:
	return err;
}

psm_error_t ips_scbctrl_fini(struct ips_scbctrl *scbc)
{
	if (scbc->scb_base != NULL) {
		psmi_free(scbc->scb_base);
		VALGRIND_DESTROY_MEMPOOL(scbc);
	}
	if (scbc->sbuf_buf_alloc) {
		VALGRIND_DESTROY_MEMPOOL(scbc->sbuf_buf_alloc);
		psmi_free(scbc->sbuf_buf_alloc);
	}
	return PSM_OK;
}

int ips_scbctrl_bufalloc(ips_scb_t *scb)
{
	struct ips_scbctrl *scbc = scb->scbc;

	psmi_assert_always(scbc->sbuf_num > 0);
	psmi_assert_always(!((scb->payload >= scbc->sbuf_buf_base) &&
			     (scb->payload <= scbc->sbuf_buf_last)));
	if (SLIST_EMPTY(&scbc->sbuf_free))
		return 0;
	else {
		psmi_assert(scbc->sbuf_num_cur);
		scb->payload = SLIST_FIRST(&scbc->sbuf_free);
		scb->payload_size = scbc->sbuf_buf_size;
		scbc->sbuf_num_cur--;

		/* If under memory pressure request ACK for packet to reclaim
		 * credits.
		 */
		if (scbc->sbuf_num_cur < (scbc->sbuf_num >> 1))
			scb->flags |= IPS_SEND_FLAG_ACKREQ;

		VALGRIND_MEMPOOL_ALLOC(scbc->sbuf_buf_alloc, scb->payload,
				       scb->payload_size);
		SLIST_REMOVE_HEAD(&scbc->sbuf_free, next);
		return 1;
	}
}

int ips_scbctrl_avail(struct ips_scbctrl *scbc)
{
	return (!SLIST_EMPTY(&scbc->scb_free) && scbc->sbuf_num_cur > 0);
}

ips_scb_t *ips_scbctrl_alloc(struct ips_scbctrl *scbc, int scbnum, int len,
			     uint32_t flags)
{
	ips_scb_t *scb, *scb_head = NULL;

	psmi_assert(flags & IPS_SCB_FLAG_ADD_BUFFER ? (scbc->sbuf_num > 0) : 1);

	while (scbnum--) {
		if (SLIST_EMPTY(&scbc->scb_free))
			break;
		scb = SLIST_FIRST(&scbc->scb_free);
		scb->flags = 0;	/* Need to set this here as bufalloc may request
				 * an ACK under memory pressure
				 */
		VALGRIND_MEMPOOL_ALLOC(scbc, scb, sizeof(struct ips_scb));

		if (flags & IPS_SCB_FLAG_ADD_BUFFER) {
			if (len > scbc->scb_imm_size) {
				if (!ips_scbctrl_bufalloc(scb))
					break;
			} else {	/* Attach immediate buffer */
				scb->payload = scb->imm_payload;
				scb->payload_size = scbc->scb_imm_size;
				psmi_assert(scb->payload);
			}
		} else {
			scb->payload = NULL;
			scb->payload_size = 0;
		}

		scb->tidsendc = NULL;
		scb->callback = NULL;
		scb->tidctrl = 0;
		scb->nfrag = 1;
		scb->frag_size = 0;
		scb->padcnt = 0;

		scbc->scb_num_cur--;
		if (scbc->scb_num_cur < (scbc->scb_num >> 1))
			scb->flags |= IPS_SEND_FLAG_ACKREQ;

		SLIST_REMOVE_HEAD(&scbc->scb_free, next);
		SLIST_NEXT(scb, next) = scb_head;
		scb_head = scb;
	}
	return scb_head;
}

void ips_scbctrl_free(ips_scb_t *scb)
{
	struct ips_scbctrl *scbc = scb->scbc;
	if (scbc->sbuf_num && (scb->payload >= scbc->sbuf_buf_base) &&
	    (scb->payload <= scbc->sbuf_buf_last)) {
		scbc->sbuf_num_cur++;
		SLIST_INSERT_HEAD(&scbc->sbuf_free, scb->sbuf, next);
		VALGRIND_MEMPOOL_FREE(scbc->sbuf_buf_alloc, scb->payload);
	}

	scb->payload = NULL;
	scb->tidsendc = NULL;
	scb->payload_size = 0;
	scbc->scb_num_cur++;
	if (SLIST_EMPTY(&scbc->scb_free)) {
		SLIST_INSERT_HEAD(&scbc->scb_free, scb, next);
		if (scbc->scb_avail_callback != NULL)
			scbc->scb_avail_callback(scbc, scbc->scb_avail_context);
	} else
		SLIST_INSERT_HEAD(&scbc->scb_free, scb, next);

	VALGRIND_MEMPOOL_FREE(scbc, scb);
	return;
}

ips_scb_t *ips_scbctrl_alloc_tiny(struct ips_scbctrl *scbc)
{
	ips_scb_t *scb;
	if (SLIST_EMPTY(&scbc->scb_free))
		return NULL;
	scb = SLIST_FIRST(&scbc->scb_free);

	VALGRIND_MEMPOOL_ALLOC(scbc, scb, sizeof(struct ips_scb));
	SLIST_REMOVE_HEAD(&scbc->scb_free, next);
	SLIST_NEXT(scb, next) = NULL;

	scb->payload = NULL;
	scb->payload_size = 0;
	scb->flags = 0;
	scb->tidsendc = NULL;
	scb->callback = NULL;
	scb->tidctrl = 0;
	scb->nfrag = 1;
	scb->frag_size = 0;
	scb->padcnt = 0;

	scbc->scb_num_cur--;
	if (scbc->scb_num_cur < (scbc->scb_num >> 1))
		scb->flags |= IPS_SEND_FLAG_ACKREQ;
	return scb;
}
