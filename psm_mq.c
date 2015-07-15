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

#include <sched.h>

#include "psm_user.h"
#include "psm_mq_internal.h"

/*
 * Functions to manipulate the expected queue in mq_ep.
 */

/*
 * ! @brief PSM exposed version to allow PTLs to match
 */

/*! @brief Try to match against an mqsq using a tag and tagsel
 *
 * @param[in] q Match Queue
 * @param[in] src Source (sender) epaddr, may be PSM_MQ_ANY_ADDR.
 * @param[in] tag Input Tag
 * @param[in] tagsel Input Tag Selector
 * @param[in] remove Non-zero to remove the req from the queue
 *
 * @returns NULL if no match or an mq request if there is a match
 */
static
psm_mq_req_t
mq_req_match_with_tagsel(psm_mq_t mq, struct mqsq *q, psm_epaddr_t src,
			 psm_mq_tag_t *tag, psm_mq_tag_t *tagsel, int remove)
{
	psm_mq_req_t *curp;
	psm_mq_req_t cur;

	for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
		psmi_assert(cur->peer != PSM_MQ_ANY_ADDR);
		if ((src == PSM_MQ_ANY_ADDR || src == cur->peer) &&
		    !((tag->tag[0] ^ cur->tag.tag[0]) & tagsel->tag[0]) &&
		    !((tag->tag[1] ^ cur->tag.tag[1]) & tagsel->tag[1]) &&
		    !((tag->tag[2] ^ cur->tag.tag[2]) & tagsel->tag[2])) {
			/* match! */
			if (remove) {
				if ((*curp = cur->next) == NULL)	/* fix tail */
					q->lastp = curp;
				cur->next = NULL;
			}
			return cur;
		}
	}
	return NULL;
}

#if 0
/* Only for psm_mq_irecv. Currently not enabled. */
PSMI_ALWAYS_INLINE(
psm_mq_req_t
mq_req_match_with_tagsel_inline(struct mqsq *q,
				uint64_t tag,
				uint64_t tagsel))
{
	psm_mq_req_t cur = q->first;
	if (cur == NULL)
		return NULL;
	else if (!((cur->tag ^ tag) & tagsel)) {
		if ((q->first = cur->next) == NULL)
			q->lastp = &q->first;
		cur->next = NULL;
		return cur;
	} else
		return mq_req_match_with_tagsel(q, tag, tagsel, 1);
}
#endif

/*! @brief Try to remove the req in an mqsq
 *
 * @param[in] q Match Queue
 * @param[in] req MQ request
 *
 * @returns 1 if successfully removed, or 0 if req cannot be found.
 */
static
int mq_req_remove_single(psm_mq_t mq, struct mqsq *q, psm_mq_req_t req)
{
	psm_mq_req_t *curp;
	psm_mq_req_t cur;

	for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
		if (cur == req) {
			if ((*curp = cur->next) == NULL)
				q->lastp = curp;
			cur->next = NULL;
			return 1;
		}
	}
	return 0;
}

#if 0
 /*XXX only used with cancel, for now */
/*! @brief Remove a req that matches a send_req in an mqsq
 *
 * Rendez-vous requests keep track of the sender's send_req within a req in a
 * match Queue.  Upon cancels, it is required to search the queue and remove
 * the send_req that matches the request to be cancelled.
 *
 * @param[in] q Match Queue
 * @param[in] req MQ send request to match
 * @param[in] remove Non-zero value to remove the req from the MQ
 */
static
psm_mq_req_t
mq_req_match_req(struct mqsq *q, psm_mq_req_t req, int remove)
{
	psm_mq_req_t *curp;
	psm_mq_req_t cur;

	for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
		if (cur->send_req == req) {
			if (remove) {
				if ((*curp = cur->next) == NULL)	/* fix tail */
					q->lastp = curp;
				cur->next = NULL;
			}
			return cur;
		}
	}
	return NULL;		/* no match */
}
#endif

void psmi_mq_mtucpy(void *vdest, const void *vsrc, uint32_t nchars)
{
	unsigned char *dest = (unsigned char *)vdest;
	const unsigned char *src = (const unsigned char *)vsrc;
	if (nchars >> 2)
		hfi_dwordcpy((uint32_t *) dest, (uint32_t *) src, nchars >> 2);
	dest += (nchars >> 2) << 2;
	src += (nchars >> 2) << 2;
	switch (nchars & 0x03) {
	case 3:
		*dest++ = *src++;
	case 2:
		*dest++ = *src++;
	case 1:
		*dest++ = *src++;
	}
}

#if 0				/* defined(__x86_64__) No consumers of mtucpy safe */
void psmi_mq_mtucpy_safe(void *vdest, const void *vsrc, uint32_t nchars)
{
	unsigned char *dest = (unsigned char *)vdest;
	const unsigned char *src = (const unsigned char *)vsrc;
	if (nchars >> 2)
		hfi_dwordcpy_safe((uint32_t *) dest, (uint32_t *) src,
				  nchars >> 2);
	dest += (nchars >> 2) << 2;
	src += (nchars >> 2) << 2;
	switch (nchars & 0x03) {
	case 3:
		*dest++ = *src++;
	case 2:
		*dest++ = *src++;
	case 1:
		*dest++ = *src++;
	}
}
#endif

PSMI_ALWAYS_INLINE(
psm_mq_req_t
psmi_mq_iprobe_inner(psm_mq_t mq, psm_epaddr_t src,
		     psm_mq_tag_t *tag,
		     psm_mq_tag_t *tagsel, int remove_req))
{
	psm_mq_req_t req;

	PSMI_PLOCK();
	req = mq_req_match_with_tagsel(mq, &mq->unexpected_q,
				       src, tag, tagsel, remove_req);

	if (req != NULL) {
		PSMI_PUNLOCK();
		return req;
	}

	psmi_poll_internal(mq->ep, 1);
	/* try again */
	req = mq_req_match_with_tagsel(mq, &mq->unexpected_q,
				       src, tag, tagsel, remove_req);

	PSMI_PUNLOCK();
	return req;
}

psm_error_t
__psm_mq_iprobe2(psm_mq_t mq, psm_epaddr_t src,
		 psm_mq_tag_t *tag, psm_mq_tag_t *tagsel,
		 psm_mq_status2_t *status)
{
	psm_mq_req_t req;

	PSMI_ASSERT_INITIALIZED();

	req = psmi_mq_iprobe_inner(mq, src, tag, tagsel, 0);
	if (req != NULL) {
		if (status != NULL) {
			mq_status2_copy(req, status);
		}
		return PSM_OK;
	}

	return PSM_MQ_NO_COMPLETIONS;
}
PSMI_API_DECL(psm_mq_iprobe2)

psm_error_t
__psm_mq_iprobe(psm_mq_t mq, uint64_t tag, uint64_t tagsel,
		psm_mq_status_t *status)
{
	psm_mq_tag_t rtag;
	psm_mq_tag_t rtagsel;
	psm_mq_req_t req;

	PSMI_ASSERT_INITIALIZED();

	*(uint64_t *) rtag.tag = tag;
#ifdef PSM_DEBUG
	rtag.tag[2] = 0;
#endif
	*(uint64_t *) rtagsel.tag = tagsel;
	rtagsel.tag[2] = 0;

	req = psmi_mq_iprobe_inner(mq, PSM_MQ_ANY_ADDR, &rtag, &rtagsel, 0);
	if (req != NULL) {
		if (status != NULL) {
			mq_status_copy(req, status);
		}
		return PSM_OK;
	}

	return PSM_MQ_NO_COMPLETIONS;
}
PSMI_API_DECL(psm_mq_iprobe)

psm_error_t
__psm_mq_improbe2(psm_mq_t mq, psm_epaddr_t src,
		  psm_mq_tag_t *tag, psm_mq_tag_t *tagsel,
		  psm_mq_req_t *reqo, psm_mq_status2_t *status)
{
	psm_mq_req_t req;

	PSMI_ASSERT_INITIALIZED();

	req = psmi_mq_iprobe_inner(mq, src, tag, tagsel, 1);
	if (req != NULL) {
		if (status != NULL) {
			mq_status2_copy(req, status);
		}
		*reqo = req;
		return PSM_OK;
	}

	*reqo = NULL;
	return PSM_MQ_NO_COMPLETIONS;
}
PSMI_API_DECL(psm_mq_improbe2)

psm_error_t
__psm_mq_improbe(psm_mq_t mq, uint64_t tag, uint64_t tagsel,
		 psm_mq_req_t *reqo, psm_mq_status_t *status)
{
	psm_mq_tag_t rtag;
	psm_mq_tag_t rtagsel;
	psm_mq_req_t req;

	PSMI_ASSERT_INITIALIZED();

	*(uint64_t *) rtag.tag = tag;
#ifdef PSM_DEBUG
	rtag.tag[2] = 0;
#endif
	*(uint64_t *) rtagsel.tag = tagsel;
	rtagsel.tag[2] = 0;

	req = psmi_mq_iprobe_inner(mq, PSM_MQ_ANY_ADDR, &rtag, &rtagsel, 1);
	if (req != NULL) {
		if (status != NULL) {
			mq_status_copy(req, status);
		}
		*reqo = req;
		return PSM_OK;
	}

	*reqo = NULL;
	return PSM_MQ_NO_COMPLETIONS;
}
PSMI_API_DECL(psm_mq_improbe)

psm_error_t __psm_mq_cancel(psm_mq_req_t *ireq)
{
	psm_mq_req_t req = *ireq;
	psm_mq_t mq;
	psm_error_t err = PSM_OK;

	PSMI_ASSERT_INITIALIZED();

	if (req == NULL)
		return PSM_MQ_NO_COMPLETIONS;

	/* Cancelling a send is a blocking operation, and expensive.
	 * We only allow cancellation of rendezvous sends, consider the eager sends
	 * as always unsuccessfully cancelled.
	 */
	PSMI_PLOCK();

	mq = req->mq;
	if (MQE_TYPE_IS_RECV(req->type)) {
		if (req->state == MQ_STATE_POSTED) {
			int rc;

			rc = mq_req_remove_single(mq, &mq->expected_q, req);
			psmi_assert_always(rc);
			req->state = MQ_STATE_COMPLETE;
			mq_qq_append(&mq->completed_q, req);
			err = PSM_OK;
		} else
			err = PSM_MQ_NO_COMPLETIONS;
	} else {
		err = psmi_handle_error(mq->ep, PSM_PARAM_ERR,
					"Cannot cancel send requests (req=%p)",
					req);
	}

	PSMI_PUNLOCK();

	return err;
}
PSMI_API_DECL(psm_mq_cancel)

/* This is the only PSM function that blocks.
 * We handle it in a special manner since we don't know what the user's
 * execution environment is (threads, oversubscribing processes, etc).
 *
 * The status argument can be an instance of either type psm_mq_status_t or
 * psm_mq_status2_t.  Depending on the type, a corresponding status copy
 * routine should be passed in.
 */
PSMI_ALWAYS_INLINE(
psm_error_t
psmi_mq_wait_inner(psm_mq_req_t *ireq, void *status,
		   psmi_mq_status_copy_t status_copy,
		   int do_lock))
{
	psm_error_t err = PSM_OK;

	psm_mq_req_t req = *ireq;
	if (req == PSM_MQ_REQINVALID) {
		return PSM_OK;
	}

	if (do_lock)
		PSMI_PLOCK();

	if (req->state != MQ_STATE_COMPLETE) {
		psm_mq_t mq = req->mq;

		/* We'll be waiting on this req, mark it as so */
		req->type |= MQE_TYPE_WAITING;

		_HFI_VDBG("req=%p, buf=%p, len=%d, waiting\n",
			  req, req->buf, req->buf_len);

		if (req->testwait_callback) {
			err = req->testwait_callback(ireq);
			if (do_lock)
				PSMI_PUNLOCK();
			if (status != NULL) {
				status_copy(req, status);
			}
			return err;
		}

		PSMI_BLOCKUNTIL(mq->ep, err, req->state == MQ_STATE_COMPLETE);

		if (err > PSM_OK_NO_PROGRESS)
			goto fail_with_lock;
		else
			err = PSM_OK;
	}

	mq_qq_remove(&req->mq->completed_q, req);

	if (status != NULL) {
		status_copy(req, status);
	}

	_HFI_VDBG("req=%p complete, buf=%p, len=%d, err=%d\n",
		  req, req->buf, req->buf_len, req->error_code);

	psmi_mq_req_free(req);
	*ireq = PSM_MQ_REQINVALID;

fail_with_lock:
	if (do_lock)
		PSMI_PUNLOCK();
	return err;
}

psm_error_t
__psm_mq_wait2(psm_mq_req_t *ireq, psm_mq_status2_t *status)
{
	PSMI_ASSERT_INITIALIZED();
	return psmi_mq_wait_inner(ireq, status,
				  (psmi_mq_status_copy_t) mq_status2_copy, 1);
}
PSMI_API_DECL(psm_mq_wait2)

psm_error_t
__psm_mq_wait(psm_mq_req_t *ireq, psm_mq_status_t *status)
{
	PSMI_ASSERT_INITIALIZED();
	return psmi_mq_wait_inner(ireq, status,
				  (psmi_mq_status_copy_t) mq_status_copy, 1);
}
PSMI_API_DECL(psm_mq_wait)

psm_error_t psmi_mq_wait_internal(psm_mq_req_t *ireq)
{
	return psmi_mq_wait_inner(ireq, NULL, NULL, 0);
}

/* The status argument can be an instance of either type psm_mq_status_t or
 * psm_mq_status2_t.  Depending on the type, a corresponding status copy
 * routine should be passed in.
 */
PSMI_ALWAYS_INLINE(
psm_error_t
psmi_mq_test_inner(psm_mq_req_t *ireq, void *status,
		   psmi_mq_status_copy_t status_copy))
{
	psm_mq_req_t req = *ireq;
	psm_error_t err = PSM_OK;

	PSMI_ASSERT_INITIALIZED();

	if (req == PSM_MQ_REQINVALID) {
		return PSM_OK;
	}

	if (req->state != MQ_STATE_COMPLETE) {
		if (req->testwait_callback) {
			PSMI_PLOCK();
			err = req->testwait_callback(ireq);
			if (status != NULL) {
				status_copy(req, status);
			}
			PSMI_PUNLOCK();
			return err;
		} else
			return PSM_MQ_NO_COMPLETIONS;
	}

	if (status != NULL)
		status_copy(req, status);

	_HFI_VDBG
	    ("req=%p complete, tag=%08x.%08x.%08x buf=%p, len=%d, err=%d\n",
	     req, req->tag.tag[0], req->tag.tag[1], req->tag.tag[2], req->buf,
	     req->buf_len, req->error_code);

	PSMI_PLOCK();
	mq_qq_remove(&req->mq->completed_q, req);
	psmi_mq_req_free(req);
	PSMI_PUNLOCK();

	*ireq = PSM_MQ_REQINVALID;

	return err;
}

psm_error_t
__psm_mq_test2(psm_mq_req_t *ireq, psm_mq_status2_t *status)
{
	return psmi_mq_test_inner(ireq, status,
				  (psmi_mq_status_copy_t) mq_status2_copy);
}
PSMI_API_DECL(psm_mq_test2)

psm_error_t
__psm_mq_test(psm_mq_req_t *ireq, psm_mq_status_t *status)
{
	return psmi_mq_test_inner(ireq, status,
				  (psmi_mq_status_copy_t) mq_status_copy);
}
PSMI_API_DECL(psm_mq_test)

psm_error_t
__psm_mq_isend2(psm_mq_t mq, psm_epaddr_t dest, uint32_t flags,
		psm_mq_tag_t *stag, const void *buf, uint32_t len,
		void *context, psm_mq_req_t *req)
{
	psm_error_t err;

	PSMI_ASSERT_INITIALIZED();
	psmi_assert(stag != NULL);

	PSMI_PLOCK();
	err =
	    dest->ptlctl->mq_isend(mq, dest, flags, stag, buf, len, context,
				   req);
	PSMI_PUNLOCK();

#if 0
#ifdef PSM_VALGRIND
	/* If the send isn't completed yet, make sure that we mark the memory as
	 * unaccessible
	 */
	if (*req != PSM_MQ_REQINVALID && (*req)->state != MQ_STATE_COMPLETE)
		VALGRIND_MAKE_MEM_NOACCESS(buf, len);
#endif
#endif
	psmi_assert(*req != NULL);

	(*req)->peer = dest;

	return err;
}
PSMI_API_DECL(psm_mq_isend2)

psm_error_t
__psm_mq_isend(psm_mq_t mq, psm_epaddr_t dest, uint32_t flags, uint64_t stag,
	       const void *buf, uint32_t len, void *context, psm_mq_req_t *req)
{
	psm_error_t err;
	psm_mq_tag_t tag;

	*((uint64_t *) tag.tag) = stag;
	tag.tag[2] = 0;

	PSMI_ASSERT_INITIALIZED();

	PSMI_PLOCK();
	err =
	    dest->ptlctl->mq_isend(mq, dest, flags, &tag, buf, len, context,
				   req);
	PSMI_PUNLOCK();

#if 0
#ifdef PSM_VALGRIND
	/* If the send isn't completed yet, make sure that we mark the memory as
	 * unaccessible
	 */
	if (*req != PSM_MQ_REQINVALID && (*req)->state != MQ_STATE_COMPLETE)
		VALGRIND_MAKE_MEM_NOACCESS(buf, len);
#endif
#endif
	psmi_assert(*req != NULL);

	(*req)->peer = dest;

	return err;
}
PSMI_API_DECL(psm_mq_isend)

psm_error_t
__psm_mq_send2(psm_mq_t mq, psm_epaddr_t dest, uint32_t flags,
	       psm_mq_tag_t *stag, const void *buf, uint32_t len)
{
	psm_error_t err;

	PSMI_ASSERT_INITIALIZED();
	psmi_assert(stag != NULL);

	PSMI_PLOCK();
	err = dest->ptlctl->mq_send(mq, dest, flags, stag, buf, len);
	PSMI_PUNLOCK();
	return err;
}
PSMI_API_DECL(psm_mq_send2)

psm_error_t
__psm_mq_send(psm_mq_t mq, psm_epaddr_t dest, uint32_t flags, uint64_t stag,
	      const void *buf, uint32_t len)
{
	psm_error_t err;
	psm_mq_tag_t tag;

	*((uint64_t *) tag.tag) = stag;
	tag.tag[2] = 0;

	PSMI_ASSERT_INITIALIZED();

	PSMI_PLOCK();
	err = dest->ptlctl->mq_send(mq, dest, flags, &tag, buf, len);
	PSMI_PUNLOCK();
	return err;
}
PSMI_API_DECL(psm_mq_send)

/*
 * Common subroutine to psm_mq_irecv2 and psm_mq_imrecv.  This code assumes
 * that the provided request has been matched, and begins copying message data
 * that has already arrived to the user's buffer.  Any remaining data is copied
 * by PSM polling until the message is complete.
 */
static psm_error_t
psm_mq_irecv_inner(psm_mq_t mq, psm_mq_req_t req, void *buf, uint32_t len)
{
	uint32_t copysz;

	psmi_assert(MQE_TYPE_IS_RECV(req->type));

	switch (req->state) {
	case MQ_STATE_COMPLETE:
		if (req->buf != NULL) {	/* 0-byte messages don't alloc a sysbuf */
			copysz = mq_set_msglen(req, len, req->send_msglen);
			psmi_mq_mtucpy(buf, (const void *)req->buf, copysz);
			psmi_sysbuf_free(req->buf);
		}
		req->buf = buf;
		req->buf_len = len;
		mq_qq_append(&mq->completed_q, req);
		break;

	case MQ_STATE_UNEXP:	/* not done yet */
		copysz = mq_set_msglen(req, len, req->send_msglen);
		/* Copy What's been received so far and make sure we don't receive
		 * any more than copysz.  After that, swap system with user buffer
		 */
		req->recv_msgoff = min(req->recv_msgoff, copysz);
		if (req->recv_msgoff) {
			psmi_mq_mtucpy(buf, (const void *)req->buf,
				       req->recv_msgoff);
		}
		/* What's "left" is no access */
		VALGRIND_MAKE_MEM_NOACCESS((void *)((uintptr_t) buf +
						    req->recv_msgoff),
					   len - req->recv_msgoff);
		psmi_sysbuf_free(req->buf);

		req->state = MQ_STATE_MATCHED;
		req->buf = buf;
		req->buf_len = len;
		break;

	case MQ_STATE_UNEXP_RV:	/* rendez-vous ... */
		copysz = mq_set_msglen(req, len, req->send_msglen);
		/* Copy What's been received so far and make sure we don't receive
		 * any more than copysz.  After that, swap system with user buffer
		 */
		req->recv_msgoff = min(req->recv_msgoff, copysz);
		if (req->recv_msgoff) {
			psmi_mq_mtucpy(buf, (const void *)req->buf,
				       req->recv_msgoff);
		}
		/* What's "left" is no access */
		VALGRIND_MAKE_MEM_NOACCESS((void *)((uintptr_t) buf +
						    req->recv_msgoff),
					   len - req->recv_msgoff);
		if (req->send_msgoff) {
			psmi_sysbuf_free(req->buf);
		}

		req->state = MQ_STATE_MATCHED;
		req->buf = buf;
		req->buf_len = len;
		req->rts_callback(req, 0);
		break;

	default:
		fprintf(stderr, "Unexpected state %d in req %p\n", req->state,
			req);
		fprintf(stderr, "type=%d, mq=%p, tag=%08x.%08x.%08x\n",
			req->type, req->mq, req->tag.tag[0], req->tag.tag[1],
			req->tag.tag[2]);
		abort();
	}

	return PSM_OK;
}

psm_error_t
__psm_mq_irecv2(psm_mq_t mq, psm_epaddr_t src,
		psm_mq_tag_t *tag, psm_mq_tag_t *tagsel,
		uint32_t flags, void *buf, uint32_t len, void *context,
		psm_mq_req_t *reqo)
{
	psm_error_t err = PSM_OK;
	psm_mq_req_t req;

	PSMI_ASSERT_INITIALIZED();

	PSMI_PLOCK();

	/* First check unexpected Queue and remove req if found */
	req =
	    mq_req_match_with_tagsel(mq, &mq->unexpected_q, src, tag, tagsel,
				     1);

	if (req == NULL) {
		/* prepost before arrival, add to expected q */
		req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
		if_pf(req == NULL) {
			err = PSM_NO_MEMORY;
			goto ret;
		}

		req->peer = src;
		req->tag = *tag;
		req->tagsel = *tagsel;
		req->state = MQ_STATE_POSTED;
		req->buf = buf;
		req->buf_len = len;
		req->recv_msglen = len;
		req->recv_msgoff = 0;

		/* Nobody should touch the buffer after it's posted */
		VALGRIND_MAKE_MEM_NOACCESS(buf, len);

		mq_sq_append(&mq->expected_q, req);
		_HFI_VDBG("buf=%p,len=%d,tag=%08x.%08x.%08x "
			  " tagsel=%08x.%08x.%08x req=%p\n",
			  buf, len, tag->tag[0], tag->tag[1], tag->tag[2],
			  tagsel->tag[0], tagsel->tag[1], tagsel->tag[2], req);
	} else {
		_HFI_VDBG("unexpected buf=%p,len=%d,tag=%08x.%08x.%08x"
			  " tagsel=%08x.%08x.%08x req=%p\n", buf, len,
			  tag->tag[0], tag->tag[1], tag->tag[2],
			  tagsel->tag[0], tagsel->tag[1], tagsel->tag[2], req);

		psm_mq_irecv_inner(mq, req, buf, len);
	}

	req->context = context;

ret:
	PSMI_PUNLOCK();
	*reqo = req;
	return err;
}
PSMI_API_DECL(psm_mq_irecv2)

psm_error_t
__psm_mq_irecv(psm_mq_t mq, uint64_t tag, uint64_t tagsel, uint32_t flags,
	       void *buf, uint32_t len, void *context, psm_mq_req_t *reqo)
{
	psm_mq_tag_t rtag;
	psm_mq_tag_t rtagsel;

	*(uint64_t *) rtag.tag = tag;
#ifdef PSM_DEBUG
	rtag.tag[2] = 0;
#endif
	*(uint64_t *) rtagsel.tag = tagsel;
	rtagsel.tag[2] = 0;
	return __psm_mq_irecv2(mq, PSM_MQ_ANY_ADDR, &rtag, &rtagsel,
			       flags, buf, len, context, reqo);
}
PSMI_API_DECL(psm_mq_irecv)

psm_error_t
__psm_mq_imrecv(psm_mq_t mq, uint32_t flags, void *buf, uint32_t len,
		void *context, psm_mq_req_t *reqo)
{
	psm_error_t err = PSM_OK;
	psm_mq_req_t req = *reqo;

	PSMI_ASSERT_INITIALIZED();

	if (req == PSM_MQ_REQINVALID) {
		err = psmi_handle_error(mq->ep, PSM_PARAM_ERR,
					"Invalid request (req=%p)", req);
	} else {
		/* Message is already matched -- begin delivering message data to the
		   user's buffer. */
		req->context = context;

		PSMI_PLOCK();
		psm_mq_irecv_inner(mq, req, buf, len);
		PSMI_PUNLOCK();
	}

	return err;
}
PSMI_API_DECL(psm_mq_imrecv)

/* The status argument can be an instance of either type psm_mq_status_t or
 * psm_mq_status2_t.  Depending on the type, a corresponding status copy
 * routine should be passed in.
 */
PSMI_ALWAYS_INLINE(
psm_error_t
psmi_mq_ipeek_inner(psm_mq_t mq, psm_mq_req_t *oreq,
		    void *status,
		    psmi_mq_status_copy_t status_copy))
{
	psm_mq_req_t req;

	PSMI_ASSERT_INITIALIZED();

	if ((req = mq->completed_q.first) == NULL) {
		PSMI_PLOCK();
		psmi_poll_internal(mq->ep, 1);
		if ((req = mq->completed_q.first) == NULL) {
			PSMI_PUNLOCK();
			return PSM_MQ_NO_COMPLETIONS;
		}
		PSMI_PUNLOCK();
	}
	/* something in the queue */
	*oreq = req;
	if (status != NULL)
		status_copy(req, status);

	return PSM_OK;
}

psm_error_t
__psm_mq_ipeek2(psm_mq_t mq, psm_mq_req_t *oreq, psm_mq_status2_t *status)
{
	return psmi_mq_ipeek_inner(mq, oreq, status,
				   (psmi_mq_status_copy_t) mq_status2_copy);
}
PSMI_API_DECL(psm_mq_ipeek2)

psm_error_t
__psm_mq_ipeek(psm_mq_t mq, psm_mq_req_t *oreq, psm_mq_status_t *status)
{
	return psmi_mq_ipeek_inner(mq, oreq, status,
				   (psmi_mq_status_copy_t) mq_status_copy);
}
PSMI_API_DECL(psm_mq_ipeek)

static
psm_error_t psmi_mqopt_ctl(psm_mq_t mq, uint32_t key, void *value, int get)
{
	psm_error_t err = PSM_OK;
	uint32_t val32;

	switch (key) {
	case PSM_MQ_RNDV_HFI_SZ:
		if (get)
			*((uint32_t *) value) = mq->hfi_thresh_rv;
		else {
			val32 = *((uint32_t *) value);
			mq->hfi_thresh_rv = val32;
		}
		_HFI_VDBG("RNDV_HFI_SZ = %d (%s)\n",
			  mq->hfi_thresh_rv, get ? "GET" : "SET");
		break;

	case PSM_MQ_RNDV_SHM_SZ:
		if (get)
			*((uint32_t *) value) = mq->shm_thresh_rv;
		else {
			val32 = *((uint32_t *) value);
			mq->shm_thresh_rv = val32;
		}
		_HFI_VDBG("RNDV_SHM_SZ = %d (%s)\n",
			  mq->shm_thresh_rv, get ? "GET" : "SET");
		break;
	case PSM_MQ_MAX_SYSBUF_MBYTES:
		/* Deprecated: this option no longer does anything. */
		break;

	default:
		err =
		    psmi_handle_error(NULL, PSM_PARAM_ERR,
				      "Unknown option key=%u", key);
		break;
	}
	return err;
}

psm_error_t __psm_mq_getopt(psm_mq_t mq, int key, void *value)
{
	PSMI_ERR_UNLESS_INITIALIZED(mq->ep);
	return psmi_mqopt_ctl(mq, key, value, 1);
}
PSMI_API_DECL(psm_mq_getopt)

psm_error_t __psm_mq_setopt(psm_mq_t mq, int key, const void *value)
{
	PSMI_ERR_UNLESS_INITIALIZED(mq->ep);
	return psmi_mqopt_ctl(mq, key, (void *)value, 0);
}
PSMI_API_DECL(psm_mq_setopt)

/*
 * This is the API for the user.  We actually allocate the MQ much earlier, but
 * the user can set options after obtaining an endpoint
 */
psm_error_t
__psm_mq_init(psm_ep_t ep, uint64_t tag_order_mask,
	      const struct psm_optkey *opts, int numopts, psm_mq_t *mqo)
{
	psm_error_t err = PSM_OK;
	psm_mq_t mq = ep->mq;
	int i;

	PSMI_ERR_UNLESS_INITIALIZED(ep);

	psmi_assert(mq != NULL);
	psmi_assert(mq->ep != NULL);

	/* Process options */
	for (i = 0; err == PSM_OK && i < numopts; i++)
		err = psmi_mqopt_ctl(mq, opts[i].key, opts[i].value, 0);
	if (err != PSM_OK)	/* error already handled */
		goto fail;

	*mqo = mq;

fail:
	return err;
}
PSMI_API_DECL(psm_mq_init)

static
void
psmi_mq_print_stats(psm_mq_t mq)
{
	psm_mq_stats_t stats;

	psm_mq_get_stats(mq, &stats);
	_HFI_INFO("rx_user_bytes %lu\n", stats.rx_user_bytes);
	_HFI_INFO("rx_user_num %lu\n", stats.rx_user_num);
	_HFI_INFO("rx_sys_bytes %lu\n", stats.rx_sys_bytes);
	_HFI_INFO("rx_sys_num %lu\n", stats.rx_sys_num);

	_HFI_INFO("tx_num %lu\n", stats.tx_num);
	_HFI_INFO("tx_eager_num %lu\n", stats.tx_eager_num);
	_HFI_INFO("tx_eager_bytes %lu\n", stats.tx_eager_bytes);
	_HFI_INFO("tx_rndv_num %lu\n", stats.tx_rndv_num);
	_HFI_INFO("tx_rndv_bytes %lu\n", stats.tx_rndv_bytes);

	_HFI_INFO("tx_shm_num %lu\n", stats.tx_shm_num);
	_HFI_INFO("rx_shm_num %lu\n", stats.rx_shm_num);

	_HFI_INFO("rx_sysbuf_num %lu\n", stats.rx_sysbuf_num);
	_HFI_INFO("rx_sysbuf_bytes %lu\n", stats.rx_sysbuf_bytes);
}

psm_error_t __psm_mq_finalize(psm_mq_t mq)
{
	psm_ep_t ep;
	PSMI_ERR_UNLESS_INITIALIZED(mq->ep);

	if (mq->print_stats != 0)
		psmi_mq_print_stats(mq);

	ep = mq->ep;
	do {
		ep->mq = NULL;
		ep = ep->mctxt_next;
	} while (ep != mq->ep);

	return psmi_mq_free(mq);
}
PSMI_API_DECL(psm_mq_finalize)

void __psm_mq_get_stats(psm_mq_t mq, psm_mq_stats_t *stats)
{
	memcpy(stats, &mq->stats, sizeof(psm_mq_stats_t));
}
PSMI_API_DECL(psm_mq_get_stats)

psm_error_t psmi_mq_malloc(psm_mq_t *mqo)
{
	psm_error_t err = PSM_OK;

	psm_mq_t mq =
	    (psm_mq_t) psmi_calloc(NULL, UNDEFINED, 1, sizeof(struct psm_mq));
	if (mq == NULL) {
		err = psmi_handle_error(NULL, PSM_NO_MEMORY,
					"Couldn't allocate memory for mq endpoint");
		goto fail;
	}

	mq->ep = NULL;
	/*mq->unexpected_callback = NULL; */
	mq->memmode = psmi_parse_memmode();
	mq->expected_q.first = NULL;
	mq->expected_q.lastp = &mq->expected_q.first;
	mq->unexpected_q.first = NULL;
	mq->unexpected_q.lastp = &mq->unexpected_q.first;
	mq->completed_q.first = NULL;
	mq->completed_q.lastp = &mq->completed_q.first;

	mq->outoforder_q.first = NULL;
	mq->outoforder_q.lastp = &mq->outoforder_q.first;
	STAILQ_INIT(&mq->eager_q);


	/* The values are overwritten in initialize_defaults, they're just set to
	 * sensible defaults until then */
	mq->hfi_thresh_rv = 64000;
	mq->hfi_window_rv = 131072;
	mq->shm_thresh_rv = 16000;

	memset(&mq->stats, 0, sizeof(psm_mq_stats_t));
	err = psmi_mq_req_init(mq);
	if (err)
		goto fail;

	*mqo = mq;

	return PSM_OK;
fail:
	if (mq != NULL)
		psmi_free(mq);
	return err;
}

psm_error_t psmi_mq_initialize_defaults(psm_mq_t mq)
{
	union psmi_envvar_val env_rvwin, env_hfirv, env_shmrv, env_stats;

	psmi_getenv("PSM_MQ_RNDV_HFI_THRESH",
		    "hfi eager-to-rendezvous switchover",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)mq->hfi_thresh_rv, &env_hfirv);
	mq->hfi_thresh_rv = env_hfirv.e_uint;

	psmi_getenv("PSM_MQ_RNDV_HFI_WINDOW",
		    "hfi rendezvous window size, max 4M",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)mq->hfi_window_rv, &env_rvwin);
	mq->hfi_window_rv = min(4 * 1024 * 1024, env_rvwin.e_uint);

	/* Re-evaluate this since it may have changed after initializing the shm
	 * device */
	mq->shm_thresh_rv = psmi_shm_mq_rv_thresh;
	psmi_getenv("PSM_MQ_RNDV_SHM_THRESH",
		    "shm eager-to-rendezvous switchover",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)mq->shm_thresh_rv, &env_shmrv);
	mq->shm_thresh_rv = env_shmrv.e_uint;

	psmi_getenv("PSM_MQ_PRINT_STATS",
		    "Print MQ stats during finalization",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val) 0, &env_stats);
	mq->print_stats = env_stats.e_uint;

	return PSM_OK;
}

psm_error_t psmi_mq_free(psm_mq_t mq)
{
	psmi_mq_req_fini(mq);
	psmi_free(mq);
	return PSM_OK;
}
