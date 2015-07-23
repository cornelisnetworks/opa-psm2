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

#ifndef MQ_INT_H
#define MQ_INT_H

#include "psm_user.h"

#if 0
typedef psm_error_t(*psm_mq_unexpected_callback_fn_t)
	(psm_mq_t mq, uint16_t mode, psm_epaddr_t epaddr,
	 uint64_t tag, uint32_t send_msglen, const void *payload,
	 uint32_t paylen);
#endif

struct psm_mq {
	psm_ep_t ep;		/**> ep back pointer */
	mpool_t sreq_pool;
	mpool_t rreq_pool;

	/*psm_mq_unexpected_callback_fn_t unexpected_callback; */
	struct mqsq expected_q;	/**> Preposted (expected) queue */
	struct mqsq unexpected_q;
				/**> Unexpected queue */
	struct mqq completed_q;	/**> Completed queue */

	struct mqsq outoforder_q;
				/**> OutofOrder queue */
	 STAILQ_HEAD(, psm_mq_req) eager_q;
				       /**> eager request queue */

	uint32_t hfi_thresh_rv;
	uint32_t shm_thresh_rv;
	uint32_t hfi_window_rv;
	int memmode;

	psm_mq_stats_t stats;	/**> MQ stats, accumulated by each PTL */
	int print_stats;
};

#define MQ_HFI_THRESH_TINY	8
#define MQ_HFI_THRESH_EGR_SDMA    34000
#define MQ_HFI_THRESH_EGR_SDMA_SQ 8192

#define MQE_TYPE_IS_SEND(type)	((type) & MQE_TYPE_SEND)
#define MQE_TYPE_IS_RECV(type)	((type) & MQE_TYPE_RECV)

#define MQE_TYPE_SEND		0x1000
#define MQE_TYPE_RECV		0x2000
#define MQE_TYPE_FLAGMASK	0x0fff
#define MQE_TYPE_WAITING	0x0001
#define MQE_TYPE_WAITING_PEER	0x0004
#define MQE_TYPE_EAGER_QUEUE	0x0008

#define MQ_STATE_COMPLETE	0
#define MQ_STATE_POSTED		1
#define MQ_STATE_MATCHED	2
#define MQ_STATE_UNEXP		3
#define MQ_STATE_UNEXP_RV	4
#define MQ_STATE_FREE		5

/*
 * These must match the ips protocol message opcode.
 */
#define MQ_MSG_TINY		0xc1
#define MQ_MSG_SHORT		0xc2
#define MQ_MSG_EAGER		0xc3
#define MQ_MSG_LONGRTS		0xc4

/*
 * Descriptor allocation limits.
 * The 'LIMITS' predefines fill in a psmi_rlimits_mpool structure
 */
#define MQ_SENDREQ_LIMITS {					\
	    .env = "PSM_MQ_SENDREQS_MAX",			\
	    .descr = "Max num of isend requests in flight",	\
	    .env_level = PSMI_ENVVAR_LEVEL_USER,		\
	    .minval = 1,					\
	    .maxval = ~0,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = { 1024, 1048576 },	\
	    .mode[PSMI_MEMMODE_MINIMAL] = { 1024, 65536 },	\
	    .mode[PSMI_MEMMODE_LARGE]   = { 8192, 16777216 }	\
	}

#define MQ_RECVREQ_LIMITS {					\
	    .env = "PSM_MQ_RECVREQS_MAX",			\
	    .descr = "Max num of irecv requests in flight",	\
	    .env_level = PSMI_ENVVAR_LEVEL_USER,		\
	    .minval = 1,					\
	    .maxval = ~0,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = { 1024, 1048576 },	\
	    .mode[PSMI_MEMMODE_MINIMAL] = { 1024, 65536 },	\
	    .mode[PSMI_MEMMODE_LARGE]   = { 8192, 16777216 }	\
	}

typedef psm_error_t(*mq_rts_callback_fn_t) (psm_mq_req_t req, int was_posted);
typedef psm_error_t(*mq_testwait_callback_fn_t) (psm_mq_req_t *req);

/* receive mq_req, the default */
struct psm_mq_req {
	struct {
		psm_mq_req_t next;
		psm_mq_req_t *pprev;	/* used in completion queue */
		 STAILQ_ENTRY(psm_mq_req) nextq;	/* used for eager only */
	};
	uint32_t state;
	uint32_t type;
	psm_mq_t mq;

	/* Tag matching vars */
	psm_epaddr_t peer;
	psm_mq_tag_t tag;
	psm_mq_tag_t tagsel;	/* used for receives */

	/* Some PTLs want to get notified when there's a test/wait event */
	mq_testwait_callback_fn_t testwait_callback;

	/* Buffer attached to request.  May be a system buffer for unexpected
	 * messages or a user buffer when an expected message */
	uint8_t *buf;
	uint32_t buf_len;
	uint32_t error_code;

	uint16_t msg_seqnum;	/* msg seq num for mctxt */
	uint32_t recv_msglen;	/* Message length we are ready to receive */
	uint32_t send_msglen;	/* Message length from sender */
	uint32_t recv_msgoff;	/* Message offset into buf */
	union {
		uint32_t send_msgoff;	/* Bytes received so far.. can be larger than buf_len */
		uint32_t recv_msgposted;
	};
	uint32_t rts_reqidx_peer;

	/* Used for request to send messages */
	void *context;		/* user context associated to sends or receives */

	/* Used to keep track of unexpected rendezvous */
	mq_rts_callback_fn_t rts_callback;
	psm_epaddr_t rts_peer;
	uintptr_t rts_sbuf;

	/* PTLs get to store their own per-request data.  MQ manages the allocation
	 * by allocating psm_mq_req so that ptl_req_data has enough space for all
	 * possible PTLs.
	 */
	union {
		void *ptl_req_ptr;	/* when used by ptl as pointer */
		uint8_t ptl_req_data[0];	/* when used by ptl for "inline" data */
	};
};

void psmi_mq_mtucpy(void *vdest, const void *vsrc, uint32_t nchars);

#if defined(__x86_64__)
void psmi_mq_mtucpy_safe(void *vdest, const void *vsrc, uint32_t nchars);
#else
#define psmi_mq_mtucpy_safe psmi_mq_mtucpy
#endif

/*
 * Optimize for 0-8 byte case, but also handle others.
 */
PSMI_ALWAYS_INLINE(
void
mq_copy_tiny(uint32_t *dest, uint32_t *src, uint8_t len))
{
	switch (len) {
	case 8:
		*dest++ = *src++;
	case 4:
		*dest++ = *src++;
	case 0:
		return;
	case 7:
	case 6:
	case 5:
		*dest++ = *src++;
		len -= 4;
	case 3:
	case 2:
	case 1:
		break;
	default:		/* greater than 8 */
		psmi_mq_mtucpy(dest, src, len);
		return;
	}
	uint8_t *dest1 = (uint8_t *) dest;
	uint8_t *src1 = (uint8_t *) src;
	switch (len) {
	case 3:
		*dest1++ = *src1++;
	case 2:
		*dest1++ = *src1++;
	case 1:
		*dest1++ = *src1++;
	}
}

/* Typedef describing a function to populate a psm_mq_status(2)_t given a
 * matched request.  The purpose of this typedef is to avoid duplicating
 * code to handle both PSM v1 and v2 status objects.  Outer routines pass in
 * either mq_status_copy or mq_status2_copy and the inner routine calls that
 * provided routine to fill in the correct status type.
 */
typedef void (*psmi_mq_status_copy_t) (psm_mq_req_t req, void *status);

/*
 * Given an req with buffer ubuf of length ubuf_len,
 * fill in the req's status and return the amount of bytes the request
 * can receive.
 *
 * The function sets status truncation errors. Basically what MPI_Status does.
 */
PSMI_ALWAYS_INLINE(
void
mq_status_copy(psm_mq_req_t req, psm_mq_status_t *status))
{
	status->msg_tag = *((uint64_t *) req->tag.tag);
	status->msg_length = req->send_msglen;
	status->nbytes = req->recv_msglen;
	status->error_code = req->error_code;
	status->context = req->context;
}

PSMI_ALWAYS_INLINE(
void
mq_status2_copy(psm_mq_req_t req, psm_mq_status2_t *status))
{
	status->msg_peer = req->peer;
	status->msg_tag = req->tag;
	status->msg_length = req->send_msglen;
	status->nbytes = req->recv_msglen;
	status->error_code = req->error_code;
	status->context = req->context;
}

PSMI_ALWAYS_INLINE(
uint32_t
mq_set_msglen(psm_mq_req_t req, uint32_t recvlen, uint32_t sendlen))
{
	req->send_msglen = sendlen;
	if (recvlen < sendlen) {
		req->recv_msglen = recvlen;
		req->error_code = PSM_MQ_TRUNCATION;
		return recvlen;
	} else {
		req->recv_msglen = sendlen;
		req->error_code = PSM_OK;
		return sendlen;
	}
}

#ifndef PSM_DEBUG
/*! Append to Queue */
PSMI_ALWAYS_INLINE(void mq_qq_append(struct mqq *q, psm_mq_req_t req))
{
	req->next = NULL;
	req->pprev = q->lastp;
	*(q->lastp) = req;
	q->lastp = &req->next;
}
#else
#define mq_qq_append(q, req)					\
	do {							\
		(req)->next = NULL;				\
			(req)->pprev = (q)->lastp;		\
			*((q)->lastp) = (req);			\
			(q)->lastp = &(req)->next;		\
			if (q == &(req)->mq->completed_q)	\
				_HFI_VDBG("Moving (req)=%p to completed queue on %s, %d\n",	\
					(req), __FILE__, __LINE__);	\
	} while (0)
#endif

PSMI_ALWAYS_INLINE(void mq_sq_append(struct mqsq *q, psm_mq_req_t req))
{
	req->next = NULL;
	*(q->lastp) = req;
	q->lastp = &req->next;
}

PSMI_ALWAYS_INLINE(void mq_qq_remove(struct mqq *q, psm_mq_req_t req))
{
	if (req->next != NULL)
		req->next->pprev = req->pprev;
	else
		q->lastp = req->pprev;
	*(req->pprev) = req->next;
}

psm_error_t psmi_mq_req_init(psm_mq_t mq);
psm_error_t psmi_mq_req_fini(psm_mq_t mq);
psm_mq_req_t psmi_mq_req_alloc(psm_mq_t mq, uint32_t type);
#define      psmi_mq_req_free(req)  psmi_mpool_put(req)

/*
 * Main receive progress engine, for shmops and hfi, in mq.c
 */
psm_error_t psmi_mq_malloc(psm_mq_t *mqo);
psm_error_t psmi_mq_initialize_defaults(psm_mq_t mq);
psm_error_t psmi_mq_free(psm_mq_t mq);

/* Three functions that handle all MQ stuff */
#define MQ_RET_MATCH_OK	0
#define MQ_RET_UNEXP_OK 1
#define MQ_RET_UNEXP_NO_RESOURCES 2
#define MQ_RET_DATA_OK 3
#define MQ_RET_DATA_OUT_OF_ORDER 4

void psmi_mq_handle_rts_complete(psm_mq_req_t req);
int psmi_mq_handle_data(psm_mq_t mq, psm_mq_req_t req,
			uint32_t offset, const void *payload, uint32_t paylen);
int psmi_mq_handle_rts(psm_mq_t mq, psm_epaddr_t src, psm_mq_tag_t *tag,
		       uint32_t msglen, const void *payload, uint32_t paylen,
		       int msgorder, mq_rts_callback_fn_t cb,
		       psm_mq_req_t *req_o);
int psmi_mq_handle_envelope(psm_mq_t mq, psm_epaddr_t src, psm_mq_tag_t *tag,
			    uint32_t msglen, uint32_t offset,
			    const void *payload, uint32_t paylen, int msgorder,
			    uint32_t opcode, psm_mq_req_t *req_o);
int psmi_mq_handle_outoforder(psm_mq_t mq, psm_mq_req_t req);

void psmi_mq_stats_register(psm_mq_t mq, mpspawn_stats_add_fn add_fn);

/*! @brief Try to match against an mqsq using a tag only
 *
 * @param[in] q Match Queue
 * @param[in] src Source (sender) epaddr, may NOT be PSM_MQ_ANY_ADDR.
 * @param[in] tag Input Tag
 * @param[in] remove Non-zero to remove the req from the queue
 *
 * @returns NULL if no match or an mq request if there is a match
 */
PSMI_ALWAYS_INLINE(
psm_mq_req_t
mq_req_match(struct mqsq *q, psm_epaddr_t src, psm_mq_tag_t *tag, int remove))
{
	psm_mq_req_t *curp;
	psm_mq_req_t cur;

	psmi_assert(src != PSM_MQ_ANY_ADDR);
	for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
		if ((cur->peer == PSM_MQ_ANY_ADDR || src == cur->peer) &&
		    !((tag->tag[0] ^ cur->tag.tag[0]) & cur->tagsel.tag[0]) &&
		    !((tag->tag[1] ^ cur->tag.tag[1]) & cur->tagsel.tag[1]) &&
		    !((tag->tag[2] ^ cur->tag.tag[2]) & cur->tagsel.tag[2])) {
			/* match! */
			if (remove) {
				if ((*curp = cur->next) == NULL) /* fix tail */
					q->lastp = curp;
				cur->next = NULL;
			}
			return cur;
		}
	}
	return NULL; /* no match */
}

PSMI_ALWAYS_INLINE(
psm_mq_req_t
mq_ooo_match(struct mqsq *q, void *msgctl, uint16_t msg_seqnum))
{
	psm_mq_req_t *curp;
	psm_mq_req_t cur;

	for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
		if (cur->ptl_req_ptr == msgctl && cur->msg_seqnum == msg_seqnum) {
			/* match! */
			if ((*curp = cur->next) == NULL)	/* fix tail */
				q->lastp = curp;
			cur->next = NULL;
			return cur;
		}
	}
	return NULL; /* no match */
}

PSMI_ALWAYS_INLINE(
psm_mq_req_t
mq_eager_match(psm_mq_t mq, void *peer, uint16_t msg_seqnum))
{
	psm_mq_req_t cur;

	cur = STAILQ_FIRST(&mq->eager_q);
	while (cur) {
		if (cur->ptl_req_ptr == peer && cur->msg_seqnum == msg_seqnum)
			return cur;
		cur = STAILQ_NEXT(cur, nextq);
	}
	return NULL;		/* no match */
}

#if 0
/* Not exposed in public psm, but may extend parts of PSM 2.1 to support
 * this feature before 2.3 */
psm_mq_unexpected_callback_fn_t
psmi_mq_register_unexpected_callback(psm_mq_t mq,
				     psm_mq_unexpected_callback_fn_t fn);
#endif

PSMI_ALWAYS_INLINE(void psmi_mq_stats_rts_account(psm_mq_req_t req))
{
	psm_mq_t mq = req->mq;
	if (MQE_TYPE_IS_SEND(req->type)) {
		mq->stats.tx_num++;
		mq->stats.tx_rndv_num++;
		mq->stats.tx_rndv_bytes += req->send_msglen;
	} else {
		mq->stats.rx_user_num++;
		mq->stats.rx_user_bytes += req->recv_msglen;
	}
	return;
}

#endif
