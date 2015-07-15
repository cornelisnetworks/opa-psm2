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
#include "psm_mq_internal.h"

#if 0
/* Not exposed in public psm, but may extend parts of PSM 2.1 to support
 * this feature before 2.3 */
psm_mq_unexpected_callback_fn_t
psmi_mq_register_unexpected_callback(psm_mq_t mq,
				     psm_mq_unexpected_callback_fn_t fn)
{
	psm_mq_unexpected_callback_fn_t old_fn = mq->unexpected_callback;
	mq->unexpected_callback = fn;
	return old_fn;
}
#endif

void psmi_mq_handle_rts_complete(psm_mq_req_t req)
{
	psm_mq_t mq = req->mq;

	/* Stats on rendez-vous messages */
	psmi_mq_stats_rts_account(req);
	req->state = MQ_STATE_COMPLETE;
	mq_qq_append(&mq->completed_q, req);
#ifdef PSM_VALGRIND
	if (MQE_TYPE_IS_RECV(req->type))
		PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len,
					    req->recv_msglen);
	else
		VALGRIND_MAKE_MEM_DEFINED(req->buf, req->buf_len);
#endif
	_HFI_VDBG("RTS complete, req=%p, recv_msglen = %d\n",
		  req, req->recv_msglen);
	return;
}

static void
psmi_mq_req_copy(psm_mq_req_t req,
		 uint32_t offset, const void *buf, uint32_t nbytes)
{
	/* recv_msglen may be changed by unexpected receive buf. */
	uint32_t msglen_this, end;
	uint8_t *msgptr = (uint8_t *) req->buf + offset;

	/* out of receiving range. */
	if (offset >= req->recv_msglen) {
		req->send_msgoff += nbytes;
		return;
	}

	end = offset + nbytes;
	if (end > req->recv_msglen) {
		msglen_this = req->recv_msglen - offset;
		end = req->recv_msglen;
	} else {
		msglen_this = nbytes;
	}

	VALGRIND_MAKE_MEM_DEFINED(msgptr, msglen_this);
	psmi_mq_mtucpy(msgptr, buf, msglen_this);

	if (req->recv_msgoff < end) {
		req->recv_msgoff = end;
	}

	req->send_msgoff += nbytes;
	return;
}

int
psmi_mq_handle_data(psm_mq_t mq, psm_mq_req_t req,
		    uint32_t offset, const void *buf, uint32_t nbytes)
{
	psmi_assert(req != NULL);
	int rc;

	if (req->state == MQ_STATE_MATCHED)
		rc = MQ_RET_MATCH_OK;
	else {
		psmi_assert(req->state == MQ_STATE_UNEXP);
		rc = MQ_RET_UNEXP_OK;
	}

	psmi_mq_req_copy(req, offset, buf, nbytes);

	/*
	 * the reason to use >= is because send_msgoff
	 * may be DW pad included.
	 */
	if (req->send_msgoff >= req->send_msglen) {
		if (req->type & MQE_TYPE_EAGER_QUEUE) {
			STAILQ_REMOVE(&mq->eager_q, req, psm_mq_req, nextq);
		}

		if (req->state == MQ_STATE_MATCHED) {
			req->state = MQ_STATE_COMPLETE;
			mq_qq_append(&mq->completed_q, req);
		} else {	/* MQ_STATE_UNEXP */
			req->state = MQ_STATE_COMPLETE;
		}
	}

	return rc;
}

/*
 * This handles the rendezvous MPI envelopes, the packet might have the whole
 * message payload, or zero payload.
 */
int
psmi_mq_handle_rts(psm_mq_t mq, psm_epaddr_t src, psm_mq_tag_t *tag,
		   uint32_t send_msglen, const void *payload, uint32_t paylen,
		   int msgorder, mq_rts_callback_fn_t cb, psm_mq_req_t *req_o)
{
	psm_mq_req_t req;
	uint32_t msglen;
	int rc;

	PSMI_PLOCK_ASSERT();

	if (msgorder && (req = mq_req_match(&(mq->expected_q), src, tag, 1))) {
		/* we have a match, no need to callback */
		msglen = mq_set_msglen(req, req->buf_len, send_msglen);
		/* reset send_msglen because sender only sends this many */
		req->send_msglen = msglen;
		req->state = MQ_STATE_MATCHED;
		req->peer = src;
		req->tag = *tag;

		paylen = (paylen < msglen) ? paylen : msglen;
		if (paylen) {
			psmi_mq_mtucpy(req->buf, payload, paylen);
		}
		req->recv_msgoff = req->send_msgoff = paylen;
		*req_o = req;	/* yes match */
		rc = MQ_RET_MATCH_OK;
	} else if (msgorder > 1) {
		/* There is NO request match, and this is the first time
		 * to try to process this packet, we leave the packet in
		 * hardware queue for retry in hope there is a request
		 * match nex time, this is for performance
		 * consideration.
		 */
		rc = MQ_RET_UNEXP_NO_RESOURCES;
	} else {		/* No match, keep track of callback */
		req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
		psmi_assert(req != NULL);
		/* We don't know recv_msglen yet but we set it here for
		 * mq_iprobe */
		req->send_msglen = req->recv_msglen = send_msglen;
		req->state = MQ_STATE_UNEXP_RV;
		req->peer = src;
		req->tag = *tag;

		req->rts_callback = cb;
		if (paylen) {
			req->buf = psmi_sysbuf_alloc(paylen);
			mq->stats.rx_sysbuf_num++;
			mq->stats.rx_sysbuf_bytes += paylen;
			psmi_mq_mtucpy(req->buf, payload, paylen);
		}
		req->recv_msgoff = req->send_msgoff = paylen;

		if (msgorder) {
			mq_sq_append(&mq->unexpected_q, req);
		}
		/* caller will handle out of order case */
		*req_o = req;	/* no match, will callback */
		rc = MQ_RET_UNEXP_OK;
	}

#ifdef PSM_DEBUG
	if (req)
		_HFI_VDBG("match=%s (req=%p) src=%s mqtag=%08x.%08x.%08x recvlen=%d "
			  "sendlen=%d errcode=%d\n",
			  rc == MQ_RET_MATCH_OK ? "YES" : "NO", req,
			  psmi_epaddr_get_name(src->epid),
			  req->tag.tag[0], req->tag.tag[1], req->tag.tag[2],
			  req->recv_msglen, req->send_msglen, req->error_code);
	else
		_HFI_VDBG("match=%s (req=%p) src=%s\n",
			  rc == MQ_RET_MATCH_OK ? "YES" : "NO", req,
			  psmi_epaddr_get_name(src->epid));
#endif /* #ifdef PSM_DEBUG */
	return rc;
}

/*
 * This handles the regular (i.e. non-rendezvous MPI envelopes)
 */
int
psmi_mq_handle_envelope(psm_mq_t mq, psm_epaddr_t src, psm_mq_tag_t *tag,
			uint32_t send_msglen, uint32_t offset,
			const void *payload, uint32_t paylen, int msgorder,
			uint32_t opcode, psm_mq_req_t *req_o)
{
	psm_mq_req_t req;
	uint32_t msglen;

	if (msgorder && (req = mq_req_match(&(mq->expected_q), src, tag, 1))) {
		/* we have a match */
		psmi_assert(MQE_TYPE_IS_RECV(req->type));
		req->peer = src;
		req->tag = *tag;
		msglen = mq_set_msglen(req, req->buf_len, send_msglen);

		_HFI_VDBG("match=YES (req=%p) opcode=%x src=%s mqtag=%x.%x.%x"
			  " msglen=%d paylen=%d\n", req, opcode,
			  psmi_epaddr_get_name(src->epid),
			  tag->tag[0], tag->tag[1], tag->tag[2], msglen,
			  paylen);

		switch (opcode) {
		case MQ_MSG_TINY:
			PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len,
						    msglen);
			mq_copy_tiny((uint32_t *) req->buf,
				     (uint32_t *) payload, msglen);
			req->state = MQ_STATE_COMPLETE;
			mq_qq_append(&mq->completed_q, req);
			break;

		case MQ_MSG_SHORT:	/* message fits in 1 payload */
			PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len,
						    msglen);
			psmi_mq_mtucpy(req->buf, payload, msglen);
			req->state = MQ_STATE_COMPLETE;
			mq_qq_append(&mq->completed_q, req);
			break;

		case MQ_MSG_EAGER:
			req->state = MQ_STATE_MATCHED;
			req->type |= MQE_TYPE_EAGER_QUEUE;
			req->send_msgoff = req->recv_msgoff = 0;
			STAILQ_INSERT_TAIL(&mq->eager_q, req, nextq);
			_HFI_VDBG("exp MSG_EAGER of length %d bytes pay=%d\n",
				  msglen, paylen);
			if (paylen > 0)
				psmi_mq_handle_data(mq, req, offset, payload,
						    paylen);
			break;

		default:
			psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
					  "Internal error, unknown packet 0x%x",
					  opcode);
		}

		mq->stats.rx_user_bytes += msglen;
		mq->stats.rx_user_num++;

		*req_o = req;	/* yes match */
		return MQ_RET_MATCH_OK;
	}

	/* unexpected message or out of order message. */

#if 0
	/*
	 * Keep a callback here in case we want to fit some other high-level
	 * protocols over MQ (i.e. shmem).  These protocols would bypass the
	 * normal mesage handling and go to higher-level message handlers.
	 */
	if (msgorder && mq->unexpected_callback) {
		mq->unexpected_callback(mq, opcode, epaddr, tag, send_msglen,
					payload, paylen);
		*req_o = NULL;
		return MQ_RET_UNEXP_OK;
	}
#endif

	if (msgorder > 1) {
		/* There is NO request match, and this is the first time
		 * to try to process this packet, we leave the packet in
		 * hardware queue for retry in hope there is a request
		 * match nex time, this is for performance
		 * consideration.
		 */
		return MQ_RET_UNEXP_NO_RESOURCES;
	}

	req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
	psmi_assert(req != NULL);

	req->peer = src;
	req->tag = *tag;
	req->recv_msgoff = 0;
	req->recv_msglen = req->send_msglen = req->buf_len = msglen =
	    send_msglen;

	_HFI_VDBG("match=NO (req=%p) opcode=%x src=%s mqtag=%08x.%08x.%08x"
		  " send_msglen=%d\n", req, opcode,
		  psmi_epaddr_get_name(src->epid),
		  tag->tag[0], tag->tag[1], tag->tag[2], send_msglen);

	switch (opcode) {
	case MQ_MSG_TINY:
		if (msglen > 0) {
			req->buf = psmi_sysbuf_alloc(msglen);
			mq->stats.rx_sysbuf_num++;
			mq->stats.rx_sysbuf_bytes += paylen;
			mq_copy_tiny((uint32_t *) req->buf,
				     (uint32_t *) payload, msglen);
		} else
			req->buf = NULL;
		req->state = MQ_STATE_COMPLETE;
		break;

	case MQ_MSG_SHORT:
		req->buf = psmi_sysbuf_alloc(msglen);
		mq->stats.rx_sysbuf_num++;
		mq->stats.rx_sysbuf_bytes += paylen;
		psmi_mq_mtucpy(req->buf, payload, msglen);
		req->state = MQ_STATE_COMPLETE;
		break;

	case MQ_MSG_EAGER:
		req->send_msgoff = 0;
		req->buf = psmi_sysbuf_alloc(msglen);
		mq->stats.rx_sysbuf_num++;
		mq->stats.rx_sysbuf_bytes += paylen;
		req->state = MQ_STATE_UNEXP;
		req->type |= MQE_TYPE_EAGER_QUEUE;
		STAILQ_INSERT_TAIL(&mq->eager_q, req, nextq);
		_HFI_VDBG("unexp MSG_EAGER of length %d bytes pay=%d\n",
			  msglen, paylen);
		if (paylen > 0)
			psmi_mq_handle_data(mq, req, offset, payload, paylen);
		break;

	default:
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
				  "Internal error, unknown packet 0x%x",
				  opcode);
	}

	mq->stats.rx_sys_bytes += msglen;
	mq->stats.rx_sys_num++;

	if (msgorder) {
		mq_sq_append(&mq->unexpected_q, req);
	}
	/* caller will handle out of order case */
	*req_o = req;		/* no match, will callback */
	return MQ_RET_UNEXP_OK;
}

int psmi_mq_handle_outoforder(psm_mq_t mq, psm_mq_req_t ureq)
{
	psm_mq_req_t ereq;
	uint32_t msglen;

	ereq = mq_req_match(&(mq->expected_q), ureq->peer, &ureq->tag, 1);
	if (ereq == NULL) {
		mq_sq_append(&mq->unexpected_q, ureq);
		return 0;
	}

	psmi_assert(MQE_TYPE_IS_RECV(ereq->type));
	ereq->peer = ureq->peer;
	ereq->tag = ureq->tag;
	msglen = mq_set_msglen(ereq, ereq->buf_len, ureq->send_msglen);

	switch (ureq->state) {
	case MQ_STATE_COMPLETE:
		if (ureq->buf != NULL) {	/* 0-byte don't alloc a sysbuf */
			psmi_mq_mtucpy(ereq->buf, (const void *)ureq->buf,
				       msglen);
			psmi_sysbuf_free(ureq->buf);
		}
		ereq->state = MQ_STATE_COMPLETE;
		mq_qq_append(&mq->completed_q, ereq);
		break;
	case MQ_STATE_UNEXP:	/* not done yet */
		ereq->state = MQ_STATE_MATCHED;
		ereq->msg_seqnum = ureq->msg_seqnum;
		ereq->ptl_req_ptr = ureq->ptl_req_ptr;
		ereq->send_msgoff = ureq->send_msgoff;
		ereq->recv_msgoff = min(ureq->recv_msgoff, msglen);
		if (ereq->recv_msgoff) {
			psmi_mq_mtucpy(ereq->buf,
				       (const void *)ureq->buf,
				       ereq->recv_msgoff);
		}
		psmi_sysbuf_free(ureq->buf);
		ereq->type = ureq->type;
		STAILQ_INSERT_AFTER(&mq->eager_q, ureq, ereq, nextq);
		STAILQ_REMOVE(&mq->eager_q, ureq, psm_mq_req, nextq);
		break;
	case MQ_STATE_UNEXP_RV:	/* rendez-vous ... */
		ereq->state = MQ_STATE_MATCHED;
		ereq->rts_peer = ureq->rts_peer;
		ereq->rts_sbuf = ureq->rts_sbuf;
		ereq->send_msgoff = ureq->send_msgoff;
		ereq->recv_msgoff = min(ureq->recv_msgoff, msglen);
		if (ereq->recv_msgoff) {
			psmi_mq_mtucpy(ereq->buf,
				       (const void *)ureq->buf,
				       ereq->recv_msgoff);
		}
		if (ereq->send_msgoff) {
			psmi_sysbuf_free(ureq->buf);
		}
		ereq->rts_callback = ureq->rts_callback;
		ereq->rts_reqidx_peer = ureq->rts_reqidx_peer;
		ereq->type = ureq->type;
		ereq->rts_callback(ereq, 0);
		break;
	default:
		fprintf(stderr, "Unexpected state %d in req %p\n", ureq->state,
			ureq);
		fprintf(stderr, "type=%d, mq=%p, tag=%08x.%08x.%08x\n",
			ureq->type, ureq->mq, ureq->tag.tag[0],
			ureq->tag.tag[1], ureq->tag.tag[2]);
		abort();
	}

	psmi_mq_req_free(ureq);
	return 0;
}
