/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2016 Intel Corporation.

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

  Copyright(c) 2016 Intel Corporation.

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

/* Copyright (c) 2016 Intel Corporation. All rights reserved. */

#include "psm_user.h"
#include "psm2_hal.h"

#include "ips_scb.h"
#include "ips_tid.h"
#include "ips_tidflow.h"
#include "ips_proto.h"
#include "ips_expected_proto.h"
#include "ips_proto_help.h"
#include "psm_mq_internal.h"

/*
 * Timer callbacks.  When we need work to be done out of the receive process
 * loop, we schedule work on timers to be done at a later time.
 */
static psm2_error_t
ips_tid_pendsend_timer_callback(struct psmi_timer *timer, uint64_t current);

static psm2_error_t
ips_tid_pendtids_timer_callback(struct psmi_timer *timer, uint64_t current);

static void
ips_protoexp_do_tf_seqerr(void *vpprotoexp
			  /* actually: struct ips_protoexp *protoexp */,
			  void *vptidrecvc
			  /* actually: struct ips_tid_recv_desc *tidrecvc */,
			  struct ips_message_header *p_hdr);
static void
ips_protoexp_do_tf_generr(void *vpprotoexp
			  /* actually: struct ips_protoexp *protoexp */,
			  void *vptidrecvc
			  /* actually: struct ips_tid_recv_desc *tidrecvc */,
			   struct ips_message_header *p_hdr);

static void ips_tid_scbavail_callback(struct ips_scbctrl *scbc, void *context);
static void ips_tid_avail_callback(struct ips_tid *tidc, void *context);
static void ips_tidflow_avail_callback(struct ips_tf *tfc, void *context);

/* Defined at the ptl-level (breaks abstractions but needed for shared vs
 * non-shared contexts */
extern int ips_ptl_recvq_isempty(const struct ptl *ptl);

static psm2_error_t ips_tid_recv_free(struct ips_tid_recv_desc *tidrecvc);
static psm2_error_t ips_tid_send_exp(struct ips_tid_send_desc *tidsendc);

#ifdef PSM_CUDA
static
void psmi_cuda_run_prefetcher(struct ips_protoexp *protoexp,
			      struct ips_tid_send_desc *tidsendc);
static void psmi_attach_chb_to_tidsendc(struct ips_protoexp *protoexp,
					psm2_mq_req_t req,
					struct ips_tid_send_desc *tidsendc,
					struct ips_cuda_hostbuf *chb_prev,
					uint32_t tsess_srcoff,
					uint32_t tsess_length,
					uint32_t tsess_unaligned_start,
					psm2_chb_match_type_t type);
#endif

psm2_error_t
MOCKABLE(ips_protoexp_init)(const psmi_context_t *context,
		  const struct ips_proto *proto,
		  uint32_t protoexp_flags,
		  int num_of_send_bufs,
		  int num_of_send_desc, struct ips_protoexp **protoexp_o)
{
	struct ips_protoexp *protoexp = NULL;
	uint32_t tidmtu_max;
	psm2_error_t err = PSM2_OK;

	protoexp = (struct ips_protoexp *)
	    psmi_calloc(context->ep, UNDEFINED, 1, sizeof(struct ips_protoexp));
	if (protoexp == NULL) {
		err = PSM2_NO_MEMORY;
		goto fail;
	}
	*protoexp_o = protoexp;

	protoexp->ptl = (const struct ptl *)proto->ptl;
	protoexp->proto = (struct ips_proto *)proto;
	protoexp->timerq = proto->timerq;
	srand48_r((long int) getpid(), &protoexp->tidflow_drand48_data);
	protoexp->tid_flags = protoexp_flags;

	if (context->ep->memmode == PSMI_MEMMODE_MINIMAL) {
		protoexp->tid_flags |= IPS_PROTOEXP_FLAG_CTS_SERIALIZED;
	}

	{
		/*
		 * Adjust the session window size so that tid-grant message can
		 * fit into a single frag size packet for single transfer, PSM
		 * must send tid-grant message with a single packet.
		 */
		uint32_t fragsize, winsize;

		if (proto->flags & IPS_PROTO_FLAG_SDMA)
			fragsize = proto->epinfo.ep_mtu;
		else
			fragsize = proto->epinfo.ep_piosize;

		winsize = 2 * PSMI_PAGESIZE	/* bytes per tid-pair */
			/* space in packet */
			* min((fragsize - sizeof(ips_tid_session_list)),
			/* space in tidsendc/tidrecvc descriptor */
			PSM_TIDLIST_BUFSIZE)
			/ sizeof(uint32_t);	/* convert to tid-pair */

		if (proto->mq->hfi_base_window_rv > winsize)
			proto->mq->hfi_base_window_rv = winsize;
	}

	/* Must be initialized already */
	/* Comment out because of Klockwork scanning critical error. CQ 11/16/2012
	   psmi_assert_always(proto->ep != NULL && proto->ep->mq != NULL &&
	   proto->ep->mq->rreq_pool != NULL &&
	   proto->ep->mq->sreq_pool != NULL);
	 */
	psmi_assert_always(proto->timerq != NULL);

	/* These request pools are managed by the MQ component */
	protoexp->tid_sreq_pool = proto->ep->mq->sreq_pool;
	protoexp->tid_rreq_pool = proto->ep->mq->rreq_pool;

	/* tid traffic xfer type */
	if (proto->flags & IPS_PROTO_FLAG_SPIO)
		protoexp->tid_xfer_type = PSM_TRANSFER_PIO;
	else
		protoexp->tid_xfer_type = PSM_TRANSFER_DMA;

	/* ctrl ack/nak xfer type */
	if (proto->flags & IPS_PROTO_FLAG_SDMA)
		protoexp->ctrl_xfer_type = PSM_TRANSFER_DMA;
	else
		protoexp->ctrl_xfer_type = PSM_TRANSFER_PIO;

	/* Initialize tid flow control. */
	err = ips_tf_init(protoexp, context, &protoexp->tfc,
			       ips_tidflow_avail_callback);
	if (err != PSM2_OK)
		goto fail;

	if (proto->flags & IPS_PROTO_FLAG_SPIO)
		tidmtu_max = proto->epinfo.ep_piosize;
	else
		tidmtu_max = proto->epinfo.ep_mtu;

	protoexp->tid_send_fragsize = tidmtu_max;

	if ((err = ips_tid_init(context, protoexp,
				ips_tid_avail_callback, protoexp)))
		goto fail;

	if ((err = ips_scbctrl_init(context, num_of_send_desc, 0,
				    0, 0, ips_tid_scbavail_callback,
				    protoexp, &protoexp->tid_scbc_rv)))
		goto fail;

	{
		/* Determine interval to generate headers (relevant only when header
		 * suppression is enabled) else headers will always be generated.
		 *
		 * The PSM2_EXPECTED_HEADERS environment variable can specify the
		 * packet interval to generate headers at. Else a header packet is
		 * generated every
		 * min(PSM_DEFAULT_EXPECTED_HEADER, window_size/tid_send_fragsize).
		 * Note: A header is always generated for the last packet in the flow.
		 */

		union psmi_envvar_val env_exp_hdr;
		uint32_t defval = min(PSM_DEFAULT_EXPECTED_HEADER,
				      proto->mq->hfi_base_window_rv /
				      protoexp->tid_send_fragsize);

		psmi_getenv("PSM2_EXPECTED_HEADERS",
			    "Interval to generate expected protocol headers",
			    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
			    (union psmi_envvar_val)defval, &env_exp_hdr);

		protoexp->hdr_pkt_interval = env_exp_hdr.e_uint;
		/* Account for flow credits - Should try to have atleast 4 headers
		 * generated per window.
		 */
		protoexp->hdr_pkt_interval =
		    max(min
			(protoexp->hdr_pkt_interval, proto->flow_credits >> 2),
			1);

		if (protoexp->hdr_pkt_interval != env_exp_hdr.e_uint) {
			_HFI_VDBG
			    ("Overriding PSM2_EXPECTED_HEADERS=%u to be '%u'\n",
			     env_exp_hdr.e_uint, protoexp->hdr_pkt_interval);
		}

	}

	{
		union psmi_envvar_val env_rts_cts_interleave;

		psmi_getenv("PSM2_RTS_CTS_INTERLEAVE",
			    "Interleave the handling of RTS to provide a fair distribution between multiple senders",
			    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
			    (union psmi_envvar_val)0, &env_rts_cts_interleave);
		if (env_rts_cts_interleave.e_uint)
			protoexp->tid_flags |= IPS_PROTOEXP_FLAG_RTS_CTS_INTERLEAVE;
	}

	/* Send descriptors.
	 *
	 * There can be up to 2^32 of these send descriptors.  We conservatively
	 * allocate 256 but large node configurations can allocate up to sdesc_num
	 * of these (they are about 2k each).
	 * We impose a theoretical limit of 2^30.
	 */
	{
		struct psmi_rlimit_mpool rlim = TID_SENDSESSIONS_LIMITS;
		uint32_t maxsz, chunksz;

		if ((err = psmi_parse_mpool_env(protoexp->proto->mq, 1,
						&rlim, &maxsz, &chunksz)))
			goto fail;

		protoexp->tid_desc_send_pool =
		    psmi_mpool_create(sizeof(struct ips_tid_send_desc), chunksz,
				      maxsz, 0, DESCRIPTORS, NULL, NULL);

		if (protoexp->tid_desc_send_pool == NULL) {
			err = psmi_handle_error(proto->ep, PSM2_NO_MEMORY,
						"Couldn't allocate tid descriptor memory pool");
			goto fail;
		}
	}

	/* Receive descriptors are an array in tidflow structure. */

	/* This pool can never be smaller than the max number of rreqs that can be
	 * allocated. */
	{
		uint32_t rreq_per_chunk, rreq_max;

		psmi_assert_always(protoexp->proto->mq->rreq_pool != NULL);

		psmi_mpool_get_obj_info(protoexp->proto->mq->rreq_pool,
					&rreq_per_chunk, &rreq_max);

		protoexp->tid_getreq_pool =
		    psmi_mpool_create(sizeof(struct ips_tid_get_request),
				      rreq_per_chunk, rreq_max, 0, DESCRIPTORS,
				      NULL, NULL);

		if (protoexp->tid_getreq_pool == NULL) {
			err = psmi_handle_error(proto->ep, PSM2_NO_MEMORY,
						"Couldn't allocate getreq descriptor memory pool");
			goto fail;
		}
	}

	/* Timers to handle requeueing of work out of the receive path */
	psmi_timer_entry_init(&protoexp->timer_send,
			      ips_tid_pendsend_timer_callback, protoexp);
	STAILQ_INIT(&protoexp->pend_sendq);
	psmi_timer_entry_init(&protoexp->timer_getreqs,
			      ips_tid_pendtids_timer_callback, protoexp);
	STAILQ_INIT(&protoexp->pend_getreqsq);

	protoexp->tid_page_offset_mask = PSMI_PAGESIZE - 1;
	protoexp->tid_page_mask = ~(PSMI_PAGESIZE - 1);

	/*
	 * After ips_tid_init(), we know if we use tidcache or not.
	 * if tid cache is used, we can't use tid debug.
	 */
#ifdef PSM_DEBUG
	if (protoexp->tidc.tid_array == NULL)
		protoexp->tid_flags |= IPS_PROTOEXP_FLAG_TID_DEBUG;
#endif

	if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG) {
		int i;
		protoexp->tid_info = (struct ips_tidinfo *)
		    psmi_calloc(context->ep, UNDEFINED, IPS_TID_MAX_TIDS,
				sizeof(struct ips_tidinfo));
		if (protoexp->tid_info == NULL) {
			err = PSM2_NO_MEMORY;
			goto fail;
		}
		for (i = 0; i < IPS_TID_MAX_TIDS; i++) {
			protoexp->tid_info[i].state = TIDSTATE_FREE;
			protoexp->tid_info[i].tidrecvc = NULL;
			protoexp->tid_info[i].tid = 0xFFFFFFFF;
		}
	} else
		protoexp->tid_info = NULL;

#ifdef PSM_CUDA
	{
		if (PSMI_IS_CUDA_ENABLED &&
			 !(proto->flags & IPS_PROTO_FLAG_GPUDIRECT_RDMA_RECV)) {
			struct psmi_rlimit_mpool rlim = CUDA_HOSTBUFFER_LIMITS;
			uint32_t maxsz, chunksz, max_elements;

			if ((err = psmi_parse_mpool_env(protoexp->proto->mq, 1,
							&rlim, &maxsz, &chunksz)))
				goto fail;

			/* the maxsz is the amount in MB, not the number of entries,
			 * since the element size depends on the window size */
			max_elements = (maxsz*1024*1024) / proto->mq->hfi_base_window_rv;
			/* mpool requires max_elements to be power of 2. round down. */
			max_elements = 1 << (31 - __builtin_clz(max_elements));
			protoexp->cuda_hostbuf_recv_cfg.bufsz =
				proto->mq->hfi_base_window_rv;

			protoexp->cuda_hostbuf_pool_recv =
				psmi_mpool_create_for_cuda(sizeof(struct ips_cuda_hostbuf),
							   chunksz, max_elements, 0,
							   UNDEFINED, NULL, NULL,
							   psmi_cuda_hostbuf_alloc_func,
							   (void *)
							   &protoexp->cuda_hostbuf_recv_cfg);

			if (protoexp->cuda_hostbuf_pool_recv == NULL) {
				err = psmi_handle_error(proto->ep, PSM2_NO_MEMORY,
							"Couldn't allocate CUDA host receive buffer pool");
				goto fail;
			}

			protoexp->cuda_hostbuf_small_recv_cfg.bufsz =
				CUDA_SMALLHOSTBUF_SZ;
			protoexp->cuda_hostbuf_pool_small_recv =
				psmi_mpool_create_for_cuda(sizeof(struct ips_cuda_hostbuf),
							   chunksz, max_elements, 0,
							   UNDEFINED, NULL, NULL,
							   psmi_cuda_hostbuf_alloc_func,
							   (void *)
							   &protoexp->cuda_hostbuf_small_recv_cfg);

			if (protoexp->cuda_hostbuf_pool_small_recv == NULL) {
				err = psmi_handle_error(proto->ep, PSM2_NO_MEMORY,
							"Couldn't allocate CUDA host small receive buffer pool");
				goto fail;
			}

			PSMI_CUDA_CALL(cuStreamCreate,
				&protoexp->cudastream_recv,
				CU_STREAM_NON_BLOCKING);
			STAILQ_INIT(&protoexp->cudapend_getreqsq);
		} else {
			protoexp->cuda_hostbuf_pool_recv = NULL;
			protoexp->cuda_hostbuf_pool_small_recv = NULL;
		}
	}
#endif
	psmi_assert(err == PSM2_OK);
	return err;

fail:
#ifdef PSM_CUDA
	if (protoexp != NULL && protoexp->cuda_hostbuf_pool_recv != NULL)
		psmi_mpool_destroy(protoexp->cuda_hostbuf_pool_recv);
	if (protoexp != NULL && protoexp->cuda_hostbuf_pool_small_recv != NULL)
		psmi_mpool_destroy(protoexp->cuda_hostbuf_pool_small_recv);
#endif
	if (protoexp != NULL && protoexp->tid_getreq_pool != NULL)
		psmi_mpool_destroy(protoexp->tid_getreq_pool);
	if (protoexp != NULL && protoexp->tid_desc_send_pool != NULL)
		psmi_mpool_destroy(protoexp->tid_desc_send_pool);
	if (protoexp != NULL)
		ips_scbctrl_fini(&protoexp->tid_scbc_rv);
	if (protoexp != NULL)
		psmi_free(protoexp);
	return err;
}
MOCK_DEF_EPILOGUE(ips_protoexp_init);

psm2_error_t ips_protoexp_fini(struct ips_protoexp *protoexp)
{
	psm2_error_t err = PSM2_OK;

#ifdef PSM_CUDA
	if(PSMI_IS_CUDA_ENABLED &&
		 !(protoexp->proto->flags & IPS_PROTO_FLAG_GPUDIRECT_RDMA_RECV)) {
		psmi_mpool_destroy(protoexp->cuda_hostbuf_pool_small_recv);
		psmi_mpool_destroy(protoexp->cuda_hostbuf_pool_recv);
		PSMI_CUDA_CALL(cuStreamDestroy, protoexp->cudastream_recv);
	}
#endif
	psmi_mpool_destroy(protoexp->tid_getreq_pool);
	psmi_mpool_destroy(protoexp->tid_desc_send_pool);

	if ((err = ips_scbctrl_fini(&protoexp->tid_scbc_rv)))
		goto fail;

	if ((err = ips_tid_fini(&protoexp->tidc)))
		goto fail;

	if ((err = ips_tf_fini(&protoexp->tfc)))
		goto fail;

	if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG)
		psmi_free(protoexp->tid_info);

	psmi_free(protoexp);

fail:
	return err;
}

/* New scbs now available.  If we have pending sends or pending get requests,
 * turn on the timer so it can be processed. */
static
void ips_tid_scbavail_callback(struct ips_scbctrl *scbc, void *context)
{
	struct ips_protoexp *protoexp = (struct ips_protoexp *)context;

	if (!STAILQ_EMPTY(&protoexp->pend_sendq))
		psmi_timer_request(protoexp->timerq,
				   &protoexp->timer_send, PSMI_TIMER_PRIO_1);
	if (!STAILQ_EMPTY(&protoexp->pend_getreqsq))
		psmi_timer_request(protoexp->timerq,
				   &protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);
	return;
}

/* New Tids are available. If there are pending get requests put the
 * get timer on the timerq so it can be processed. */
static
void ips_tid_avail_callback(struct ips_tid *tidc, void *context)
{
	struct ips_protoexp *protoexp = (struct ips_protoexp *)context;

	if (!STAILQ_EMPTY(&protoexp->pend_getreqsq))
		psmi_timer_request(protoexp->timerq,
				   &protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);
	return;
}

/* New Tid Flows are available. If there are pending get requests put the
 * get timer on the timerq so it can be processed. */
static
void ips_tidflow_avail_callback(struct ips_tf *tfc, void *context)
{
	struct ips_protoexp *protoexp = (struct ips_protoexp *)context;

	if (!STAILQ_EMPTY(&protoexp->pend_getreqsq))
	{
		psmi_timer_request(protoexp->timerq,
				   &protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);
	}
	return;
}

/*
 * The tid get request is always issued from within the receive progress loop,
 * which is why we always enqueue the request instead of issuing it directly.
 * Eventually, if we expose tid_get to users, we will want to differentiate
 * when the request comes from the receive progress loop from cases where the
 * tid_get is issued directly from user code.
 *
 */
psm2_error_t
ips_protoexp_tid_get_from_token(struct ips_protoexp *protoexp,
				void *buf,
				uint32_t length,
				psm2_epaddr_t epaddr,
				uint32_t remote_tok,
				uint32_t flags,
				ips_tid_completion_callback_t callback,
				void *context)
{
	struct ips_tid_get_request *getreq;
	int count, tids, tidflows;
	uint64_t nbytes;

	PSM2_LOG_MSG("entering");
	psmi_assert((((ips_epaddr_t *) epaddr)->window_rv % PSMI_PAGESIZE) == 0);
	getreq = (struct ips_tid_get_request *)
	    psmi_mpool_get(protoexp->tid_getreq_pool);

	/* We can't *really* run out of these here because we always allocate as
	 * much as available receive reqs */
	if_pf(getreq == NULL)
	{
		PSM2_LOG_MSG("leaving");
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
			      "Ran out of 'getreq' descriptors");
	}

	getreq->tidgr_protoexp = protoexp;
	getreq->tidgr_epaddr = epaddr;
	getreq->tidgr_lbuf = buf;
	getreq->tidgr_length = length;
	getreq->tidgr_sendtoken = remote_tok;
	getreq->tidgr_ucontext = context;
	getreq->tidgr_callback = callback;
	getreq->tidgr_offset = 0;
	getreq->tidgr_bytesdone = 0;
	getreq->tidgr_flags = flags;

#ifdef PSM_CUDA
	psm2_mq_req_t req = (psm2_mq_req_t)context;
	if ((req->is_buf_gpu_mem &&
	    !(protoexp->proto->flags & IPS_PROTO_FLAG_GPUDIRECT_RDMA_RECV)) ||
	    ((req->is_buf_gpu_mem &&
	     (protoexp->proto->flags & IPS_PROTO_FLAG_GPUDIRECT_RDMA_RECV) &&
	     gpudirect_recv_threshold &&
	     length > gpudirect_recv_threshold))) {
		getreq->cuda_hostbuf_used = 1;
		getreq->tidgr_cuda_bytesdone = 0;
		STAILQ_INIT(&getreq->pend_cudabuf);
	} else
		getreq->cuda_hostbuf_used = 0;
#endif

	/* nbytes is the bytes each channel should transfer. */
	count = ((ips_epaddr_t *) epaddr)->msgctl->ipsaddr_count;
#ifdef PSM_CUDA
	if (req->is_buf_gpu_mem)
		nbytes = PSMI_ALIGNUP((length + count - 1) / count, PSMI_GPU_PAGESIZE);
	else
#endif
		nbytes = PSMI_ALIGNUP((length + count - 1) / count, PSMI_PAGESIZE);
	getreq->tidgr_rndv_winsz =
	    min(nbytes, ((ips_epaddr_t *) epaddr)->window_rv);
	/* must be within the tid window size */
	if (getreq->tidgr_rndv_winsz > PSM_TID_WINSIZE)
		getreq->tidgr_rndv_winsz = PSM_TID_WINSIZE;

	STAILQ_INSERT_TAIL(&protoexp->pend_getreqsq, getreq, tidgr_next);
	tids = ips_tid_num_available(&protoexp->tidc);
	tidflows = ips_tf_available(&protoexp->tfc);

	if (tids > 0 && tidflows > 0)
		ips_tid_pendtids_timer_callback(&protoexp->timer_getreqs, 0);
	else if (tids != -1 && tidflows != -1)
		psmi_timer_request(protoexp->timerq, &protoexp->timer_getreqs,
				   PSMI_TIMER_PRIO_1);
	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}

/* List of perf events */
#define _ips_logeventid_tid_send_reqs	0	/* out of tid send descriptors */

#define ips_logevent_id(event)	 _ips_logeventid_ ## event
#define ips_logevent(proto, event, ptr) ips_logevent_inner(proto, ips_logevent_id(event), ptr)

static
void ips_logevent_inner(struct ips_proto *proto, int eventid, void *context)
{
	uint64_t t_now = get_cycles();

	switch (eventid) {
	case ips_logevent_id(tid_send_reqs):{
			psm2_epaddr_t epaddr = (psm2_epaddr_t) context;
			proto->psmi_logevent_tid_send_reqs.count++;

			if (t_now >=
			    proto->psmi_logevent_tid_send_reqs.next_warning) {
				psmi_handle_error(PSMI_EP_LOGEVENT, PSM2_OK,
						  "Non-fatal temporary exhaustion of send tid dma descriptors "
						  "(elapsed=%.3fs, source LID=0x%x/context=%d, count=%lld)",
						  (double)
						  cycles_to_nanosecs(t_now -
								     proto->
								     t_init) /
						  1.0e9,
						  (int)psm2_epid_nid(epaddr->
								    epid),
						  (int)psm2_epid_context(epaddr->
									epid),
						  (long long)proto->
						  psmi_logevent_tid_send_reqs.
						  count);
				proto->psmi_logevent_tid_send_reqs.
				    next_warning =
				    t_now +
				    sec_2_cycles(proto->
						 psmi_logevent_tid_send_reqs.
						 interval_secs);
			}
		}
		break;

	default:
		break;
	}

	return;
}

/*
 * Expected Protocol.
 *
 * We're granted tids (as part of a tid get request) and expected to fulfill
 * the request by associating the request's sendtoken to a tid send descriptor.
 *
 * It's possible to be out of tid send descriptors when somehow all allocated
 * descriptors can't complete all of their sends.  For example, the targets of
 * the sends may be busy in computation loops and not processing incoming
 * packets.
 */

void
ips_protoexp_send_tid_grant(struct ips_tid_recv_desc *tidrecvc)
{
	ips_epaddr_t *ipsaddr = tidrecvc->ipsaddr;
	struct ips_proto *proto = tidrecvc->protoexp->proto;
	psmi_assert(proto->msgflowid < EP_FLOW_LAST);
	struct ips_flow *flow = &ipsaddr->flows[proto->msgflowid];
	ips_scb_t *scb;

	scb = tidrecvc->grantscb;
	ips_scb_opcode(scb) = OPCODE_LONG_CTS;
	scb->ips_lrh.khdr.kdeth0 = 0;
	scb->ips_lrh.mdata = tidrecvc->tidflow_genseq.psn_val;
	scb->ips_lrh.data[0] = tidrecvc->rdescid;
	scb->ips_lrh.data[1].u32w1 = tidrecvc->getreq->tidgr_length;
	scb->ips_lrh.data[1].u32w0 = tidrecvc->getreq->tidgr_sendtoken;

	ips_scb_buffer(scb) = (void *)&tidrecvc->tid_list;
	ips_scb_length(scb) = tidrecvc->tsess_tidlist_length;

	PSM2_LOG_EPM(OPCODE_LONG_CTS,PSM2_LOG_TX, proto->ep->epid,
		    flow->ipsaddr->epaddr.epid ,"tidrecvc->getreq->tidgr_sendtoken; %d",
		    tidrecvc->getreq->tidgr_sendtoken);

	ips_proto_flow_enqueue(flow, scb);
	flow->flush(flow, NULL);
}

void
ips_protoexp_send_tid_completion(struct ips_tid_recv_desc *tidrecvc,
				ptl_arg_t sdescid)
{
	ips_epaddr_t *ipsaddr = tidrecvc->ipsaddr;
	struct ips_proto *proto = tidrecvc->protoexp->proto;
	psmi_assert(proto->msgflowid < EP_FLOW_LAST);
	struct ips_flow *flow = &ipsaddr->flows[proto->msgflowid];
	ips_scb_t *scb;

	PSM2_LOG_EPM(OPCODE_EXPTID_COMPLETION,PSM2_LOG_TX, proto->ep->epid,
		    flow->ipsaddr->epaddr.epid ,"sdescid._desc_idx: %d",
		    sdescid._desc_idx);
	scb = tidrecvc->completescb;

	ips_scb_opcode(scb) = OPCODE_EXPTID_COMPLETION;
	scb->ips_lrh.khdr.kdeth0 = 0;
	scb->ips_lrh.data[0] = sdescid;

	/* Attached tidflow gen/seq */
	scb->ips_lrh.mdata = tidrecvc->tidflow_genseq.psn_val;

	ips_proto_flow_enqueue(flow, scb);
	flow->flush(flow, NULL);

	if (tidrecvc->protoexp->tid_flags & IPS_PROTOEXP_FLAG_CTS_SERIALIZED) {
		flow->flags &= ~IPS_FLOW_FLAG_SKIP_CTS;                                  /* Let the next CTS be processed */
		ips_tid_pendtids_timer_callback(&tidrecvc->protoexp->timer_getreqs, 0);  /* and make explicit progress for it. */
	}
}

#ifdef PSM_CUDA
static
void psmi_deallocate_chb(struct ips_cuda_hostbuf* chb)
{
	PSMI_CUDA_CALL(cuMemFreeHost, chb->host_buf);
	PSMI_CUDA_CALL(cuEventDestroy, chb->copy_status);
	psmi_free(chb);
	return;
}
#endif

int
ips_protoexp_recv_tid_completion(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_epaddr *ipsaddr = rcv_ev->ipsaddr;
	ptl_arg_t desc_id = p_hdr->data[0];
	struct ips_tid_send_desc *tidsendc;

	PSM2_LOG_MSG("entering");
	PSM2_LOG_EPM(OPCODE_EXPTID_COMPLETION,PSM2_LOG_RX,rcv_ev->ipsaddr->epaddr.epid,
		    rcv_ev->proto->ep->mq->ep->epid,"desc_id._desc_idx: %d",desc_id._desc_idx);

	if (!ips_proto_is_expected_or_nak(rcv_ev))
	{
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_CONTINUE;
	}

	if (__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ)
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq,
				   &ipsaddr->flows[ips_proto_flowid(p_hdr)]);

	ips_proto_process_ack(rcv_ev);

	/*
	 * Get the session send descriptor and complete.
	 */
	tidsendc = (struct ips_tid_send_desc *)
	    psmi_mpool_find_obj_by_index(protoexp->tid_desc_send_pool,
					 desc_id._desc_idx);
	_HFI_VDBG("desc_id=%d (%p)\n", desc_id._desc_idx, tidsendc);
	if (tidsendc == NULL) {
		_HFI_ERROR
		    ("exptid comp: Index %d is out of range\n",
		     desc_id._desc_idx);
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_CONTINUE;
	} else {
		ptl_arg_t desc_tidsendc;

		psmi_mpool_get_obj_index_gen_count(tidsendc,
						   &desc_tidsendc._desc_idx,
						   &desc_tidsendc._desc_genc);

		_HFI_VDBG("desc_req:id=%d,gen=%d desc_sendc:id=%d,gen=%d\n",
			  desc_id._desc_idx, desc_id._desc_genc,
			  desc_tidsendc._desc_idx, desc_tidsendc._desc_genc);

		/* See if the reference is still live and valid */
		if (desc_tidsendc.u64 != desc_id.u64) {
			_HFI_ERROR("exptid comp: Genc %d does not match\n",
				desc_id._desc_genc);
			PSM2_LOG_MSG("leaving");
			return IPS_RECVHDRQ_CONTINUE;
		}
	}

	if (!STAILQ_EMPTY(&tidsendc->tidflow.scb_unacked)) {
		struct ips_message_header hdr;

		/* Hack to handle the tidflow */
		hdr.data[0] = rcv_ev->p_hdr->data[0];
		hdr.ack_seq_num = rcv_ev->p_hdr->mdata;
		hdr.khdr.kdeth0 = __cpu_to_le32(3 << HFI_KHDR_TIDCTRL_SHIFT);
		rcv_ev->p_hdr = &hdr;

		/*
		 * This call should directly complete the tidflow
		 * and free all scb on the unacked queue.
		 */
		ips_proto_process_ack(rcv_ev);

		/* Keep KW happy. */
		rcv_ev->p_hdr = NULL;
		/* Prove that the scb will not leak in the unacked queue: */
		psmi_assert(STAILQ_EMPTY(&tidsendc->tidflow.scb_unacked));
	}

	psm2_mq_req_t req = tidsendc->mqreq;
	/* Check if we can complete the send request. */
	req->send_msgoff += tidsendc->length;

#ifdef PSM_CUDA
	if (req->cuda_hostbuf_used) {
		if (tidsendc->cuda_num_buf == 1) {
			tidsendc->cuda_hostbuf[0]->bytes_read +=
				tidsendc->tid_list.tsess_length;
			if(tidsendc->cuda_hostbuf[0]->bytes_read ==
				tidsendc->cuda_hostbuf[0]->size){
				STAILQ_REMOVE(&req->sendreq_prefetch,
					      tidsendc->cuda_hostbuf[0],
					      ips_cuda_hostbuf, req_next);
				if (tidsendc->cuda_hostbuf[0]->is_tempbuf)
					psmi_deallocate_chb(tidsendc->cuda_hostbuf[0]);
				else {
					tidsendc->cuda_hostbuf[0]->req = NULL;
					tidsendc->cuda_hostbuf[0]->offset = 0;
					tidsendc->cuda_hostbuf[0]->bytes_read = 0;
					psmi_mpool_put(tidsendc->cuda_hostbuf[0]);
				}
				psmi_cuda_run_prefetcher(protoexp, tidsendc);
			}
		} else
			psmi_free(tidsendc->userbuf);
	}
#endif
	if (req->send_msgoff == req->req_data.send_msglen) {
		psmi_mq_handle_rts_complete(req);
	}

	psmi_mpool_put(tidsendc);

	PSM2_LOG_MSG("leaving");
	return IPS_RECVHDRQ_CONTINUE;
}

int ips_protoexp_data(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_proto *proto = rcv_ev->proto;
	struct ips_protoexp *protoexp = proto->protoexp;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_tid_recv_desc *tidrecvc;
	ptl_arg_t desc_id;
	psmi_seqnum_t sequence_num;

	psmi_assert(_get_proto_hfi_opcode(p_hdr) == OPCODE_EXPTID);

	PSM2_LOG_MSG("entering");

	desc_id._desc_idx = ips_proto_flowid(p_hdr);
	PSM2_LOG_EPM(OPCODE_EXPTID,PSM2_LOG_RX,rcv_ev->ipsaddr->epaddr.epid,
		    proto->ep->mq->ep->epid,"desc_id._desc_idx: %d", desc_id._desc_idx);

	desc_id._desc_genc = p_hdr->exp_rdescid_genc;

	tidrecvc = &protoexp->tfc.tidrecvc[desc_id._desc_idx];

	if (tidrecvc->rdescid._desc_genc != desc_id._desc_genc) {
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_CONTINUE;		/* skip */
	}

	/* IBTA CCA handling for expected flow. */
	if (rcv_ev->is_congested & IPS_RECV_EVENT_FECN) {
		/* Mark flow to generate BECN in control packet */
		tidrecvc->tidflow.flags |= IPS_FLOW_FLAG_GEN_BECN;
		/* Update stats for congestion encountered */
		proto->epaddr_stats.congestion_pkts++;
		/* Clear FECN event */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
	}

	sequence_num.psn_val = __be32_to_cpu(p_hdr->bth[2]);

	if_pf (PSM_HAL_ERROR_OK != psmi_hal_tidflow_check_update_pkt_seq(
		    protoexp,sequence_num,tidrecvc,p_hdr,
		    ips_protoexp_do_tf_generr,ips_protoexp_do_tf_seqerr))
			return IPS_RECVHDRQ_CONTINUE;

	/* Reset the swapped generation count as we received a valid packet */
	tidrecvc->tidflow_nswap_gen = 0;

	/* Do some sanity checking */
	psmi_assert_always(tidrecvc->state == TIDRECVC_STATE_BUSY);
	int recv_completion = (tidrecvc->recv_tidbytes ==
			       (p_hdr->exp_offset + ips_recvhdrq_event_paylen(rcv_ev)));

	/* If sender requested an ACK with the packet and it is not the last
	 * packet, or if the incoming flow faced congestion, respond with an
	 * ACK packet. The ACK when congested will have the BECN bit set.
	 */
	if (((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) &&
		!recv_completion) ||
	    (tidrecvc->tidflow.flags & IPS_FLOW_FLAG_GEN_BECN)) {
		ips_scb_t ctrlscb;

		/* Ack sender with descriptor index */
		ctrlscb.scb_flags = 0;
		ctrlscb.ips_lrh.data[0] = p_hdr->exp_sdescid;
		ctrlscb.ips_lrh.ack_seq_num = tidrecvc->tidflow_genseq.psn_val;

		ips_proto_send_ctrl_message(&tidrecvc->tidflow,
					    OPCODE_ACK,
					    &tidrecvc->ctrl_msg_queued,
					    &ctrlscb, ctrlscb.cksum, 0);
	}

	/* If RSM is a HW capability, and RSM has found a TID packet marked
	 * with FECN, the payload will be written to the eager buffer, and
	 * we will have a payload pointer here.  In that case, copy the payload
	 * into the user's buffer.  If RSM did not intercept this EXPTID
	 * packet, the HFI will handle the packet payload. Possibly should
	 * assert(0 < paylen < MTU).
	 */
	if (psmi_hal_has_cap(PSM_HAL_CAP_RSM_FECN_SUPP) &&
	    ips_recvhdrq_event_payload(rcv_ev) &&
	    ips_recvhdrq_event_paylen(rcv_ev))
		psmi_mq_mtucpy(tidrecvc->buffer + p_hdr->exp_offset,
			       ips_recvhdrq_event_payload(rcv_ev),
			       ips_recvhdrq_event_paylen(rcv_ev));

	/* If last packet then we are done. We send a tid transfer completion
	 * packet back to sender, free all tids and close the current tidflow
	 * as well as tidrecvc descriptor.
	 * Note: If we were out of tidflow, this will invoke the callback to
	 * schedule pending transfer.
	 */
	if (recv_completion) {
		/* copy unaligned data if any */
		uint8_t *dst, *src;

		if (tidrecvc->tid_list.tsess_unaligned_start) {
			dst = (uint8_t *)tidrecvc->buffer;
			src = (uint8_t *)p_hdr->exp_ustart;
#ifdef PSM_CUDA
			if (tidrecvc->is_ptr_gpu_backed) {
				PSMI_CUDA_CALL(cuMemcpyHtoD, (CUdeviceptr)dst, src,
					       tidrecvc->tid_list.tsess_unaligned_start);
			} else
#endif
				ips_protoexp_unaligned_copy(dst, src,
							    tidrecvc->tid_list.tsess_unaligned_start);
		}

		if (tidrecvc->tid_list.tsess_unaligned_end) {
			dst = (uint8_t *)tidrecvc->buffer +
				tidrecvc->recv_msglen -
				tidrecvc->tid_list.tsess_unaligned_end;
			src = (uint8_t *)p_hdr->exp_uend;
#ifdef PSM_CUDA
			if (tidrecvc->is_ptr_gpu_backed) {
				PSMI_CUDA_CALL(cuMemcpyHtoD, (CUdeviceptr)dst, src,
					       tidrecvc->tid_list.tsess_unaligned_end);
			} else
#endif
			  ips_protoexp_unaligned_copy(dst, src,
						      tidrecvc->tid_list.tsess_unaligned_end);
		}

		/* reply tid transfer completion packet to sender */
		ips_protoexp_send_tid_completion(tidrecvc, p_hdr->exp_sdescid);

		/* Mark receive as done */
		ips_tid_recv_free(tidrecvc);
	}
	PSM2_LOG_MSG("leaving");

	return IPS_RECVHDRQ_CONTINUE;
}

#ifndef PSM_DEBUG
#  define ips_dump_tids(tid_list, msg, ...)
#else
static
void ips_dump_tids(ips_tid_session_list *tid_list, const char *msg, ...)
{
	char buf[256];
	size_t off = 0;
	int i, num_tids = tid_list->tsess_tidcount;

	va_list argptr;
	va_start(argptr, msg);
	off += vsnprintf(buf, sizeof(buf) - off, msg, argptr);
	va_end(argptr);

	for (i = 0; i < num_tids && off < (sizeof(buf) - 1); i++)
		off += snprintf(buf + off, sizeof(buf) - off, "%d%s",
				IPS_TIDINFO_GET_TID(tid_list->tsess_list[i]),
				i < num_tids - 1 ? "," : "");

	_HFI_VDBG("%s\n", buf);
	return;
}
#endif

static
void ips_expsend_tiderr(struct ips_tid_send_desc *tidsendc)
{
	char buf[256];
	size_t off = 0;
	int i;

	off += snprintf(buf + off, sizeof(buf) - off,
			"Remaining bytes: %d Member id %d is not in tid_session_id=%d :",
			tidsendc->remaining_tidbytes, tidsendc->tid_idx,
			tidsendc->rdescid._desc_idx);

	for (i = 0; i < tidsendc->tid_list.tsess_tidcount + 1; i++)
		off += snprintf(buf + off, sizeof(buf) - off, "%d,",
				IPS_TIDINFO_GET_TID(tidsendc->tid_list.
						    tsess_list[i]));
	psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
			  "Trying to use tid idx %d and there are %d members: %s\n",
			  tidsendc->tid_idx, tidsendc->tid_list.tsess_tidcount,
			  buf);
	return;
}

#ifdef PSM_CUDA
static
psm2_error_t
psmi_cuda_reclaim_hostbufs(struct ips_tid_get_request *getreq)
{
	struct ips_protoexp *protoexp = getreq->tidgr_protoexp;
	struct ips_tid_getreq_cuda_hostbuf_pend *cmemcpyhead =
		&getreq->pend_cudabuf;
	struct ips_cuda_hostbuf *chb;
	CUresult status;

	/* Get the getreq's first memcpy op */
	while (!STAILQ_EMPTY(cmemcpyhead)) {
		chb = STAILQ_FIRST(cmemcpyhead);
		PSMI_CUDA_CHECK_EVENT(chb->copy_status, status);
		if (status != CUDA_SUCCESS) {
			/* At least one of the copies is still
			 * in progress. Schedule the timer,
			 * then leave the CUDA progress phase
			 * and check for other pending TID work.
			 */
			psmi_timer_request(protoexp->timerq,
					   &protoexp->timer_getreqs,
					   PSMI_TIMER_PRIO_1);
			return PSM2_OK_NO_PROGRESS;
		}
		/* The getreq's oldest cudabuf is done. Reclaim it. */
		getreq->tidgr_cuda_bytesdone += chb->size;
		STAILQ_REMOVE_HEAD(cmemcpyhead, next);
		psmi_mpool_put(chb);
	}
	return PSM2_OK;
}

static
struct ips_cuda_hostbuf* psmi_allocate_chb(uint32_t window_len)
{
	struct ips_cuda_hostbuf* chb = (struct ips_cuda_hostbuf*)
						psmi_calloc(PSMI_EP_NONE,
							    UNDEFINED, 1,
							    sizeof(struct ips_cuda_hostbuf));
	if (chb == NULL) {
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_NO_MEMORY,
						"Couldn't allocate cuda host buffers ");
	}
	PSMI_CUDA_CALL(cuMemHostAlloc,
			       (void **) &chb->host_buf,
			       window_len,
			       CU_MEMHOSTALLOC_PORTABLE);
	PSMI_CUDA_CALL(cuEventCreate, &chb->copy_status, CU_EVENT_DEFAULT);
	return chb;
}

static
void psmi_cuda_run_prefetcher(struct ips_protoexp *protoexp,
			      struct ips_tid_send_desc *tidsendc)
{
	struct ips_proto *proto = protoexp->proto;
	struct ips_cuda_hostbuf *chb = NULL;
	psm2_mq_req_t req = tidsendc->mqreq;
	uint32_t offset, window_len;

	/* try to push the prefetcher forward */
	if (req->prefetch_send_msgoff < req->req_data.send_msglen) {
		/* some data remains to be sent */
		offset = req->prefetch_send_msgoff;
		window_len =
			ips_cuda_next_window(tidsendc->ipsaddr->window_rv,
					     offset, req->req_data.buf_len);
		if (window_len <= CUDA_SMALLHOSTBUF_SZ)
			chb = (struct ips_cuda_hostbuf *) psmi_mpool_get(
				proto->cuda_hostbuf_pool_small_send);
		if (chb == NULL)
			chb = (struct ips_cuda_hostbuf *) psmi_mpool_get(
				proto->cuda_hostbuf_pool_send);
		/* were any buffers available for the prefetcher? */
		if (chb == NULL)
			return;
		req->prefetch_send_msgoff += window_len;
		chb->offset = offset;
		chb->size = window_len;
		chb->req = req;
		chb->gpu_buf = (CUdeviceptr) req->req_data.buf + offset;
		chb->bytes_read = 0;
		PSMI_CUDA_CALL(cuMemcpyDtoHAsync,
			       chb->host_buf, chb->gpu_buf,
			       window_len,
			       proto->cudastream_send);
		PSMI_CUDA_CALL(cuEventRecord, chb->copy_status,
			       proto->cudastream_send);

		STAILQ_INSERT_TAIL(&req->sendreq_prefetch, chb, req_next);
		return;
	}
	return;
}

static
void psmi_attach_chb_to_tidsendc(struct ips_protoexp *protoexp,
				 psm2_mq_req_t req,
				 struct ips_tid_send_desc *tidsendc,
				 struct ips_cuda_hostbuf *chb_prev,
				 uint32_t tsess_srcoff,
				 uint32_t tsess_length,
				 uint32_t tsess_unaligned_start,
				 psm2_chb_match_type_t type)
{
	struct ips_proto *proto = protoexp->proto;
	struct ips_cuda_hostbuf *chb = NULL;
	uint32_t offset, window_len, attached=0;

	/* try to push the prefetcher forward */
	while (req->prefetch_send_msgoff < tsess_srcoff + tsess_length) {
		/* some data remains to be sent */
		offset = req->prefetch_send_msgoff;
		window_len =
			ips_cuda_next_window(tidsendc->ipsaddr->window_rv,
					     offset, req->req_data.buf_len);
		if (window_len <= CUDA_SMALLHOSTBUF_SZ)
			chb = (struct ips_cuda_hostbuf *) psmi_mpool_get(
				proto->cuda_hostbuf_pool_small_send);
		if (chb == NULL)
			chb = (struct ips_cuda_hostbuf *) psmi_mpool_get(
				proto->cuda_hostbuf_pool_send);

		/* were any buffers available? If not force allocate */
		if (chb == NULL) {
			chb = psmi_allocate_chb(window_len);
			psmi_assert(chb);
			chb->is_tempbuf = 1;
		}
		req->prefetch_send_msgoff += window_len;
		chb->offset = offset;
		chb->size = window_len;
		chb->req = req;
		chb->gpu_buf = (CUdeviceptr) req->req_data.buf + offset;
		chb->bytes_read = 0;
		PSMI_CUDA_CALL(cuMemcpyDtoHAsync,
			       chb->host_buf, chb->gpu_buf,
			       window_len,
			       proto->cudastream_send);
		PSMI_CUDA_CALL(cuEventRecord, chb->copy_status,
			       proto->cudastream_send);

		STAILQ_INSERT_TAIL(&req->sendreq_prefetch, chb, req_next);
		if (type == PSMI_CUDA_PARTIAL_MATCH_FOUND) {
			if ((tsess_srcoff < chb->offset)
			     && ((tsess_srcoff + tsess_length) > chb->offset)) {
				tidsendc->cuda_hostbuf[0] = chb_prev;
				tidsendc->cuda_hostbuf[1] = chb;
				tidsendc->cuda_num_buf = 2;
				void *buffer = psmi_malloc(PSMI_EP_NONE, UNDEFINED,
						tsess_length);
				tidsendc->userbuf =
					(void *)((uintptr_t) buffer);
				tidsendc->buffer =
					(void *)((uintptr_t)tidsendc->userbuf +
						tsess_unaligned_start);
				return;
			}
		} else {
			if (attached) {
				tidsendc->cuda_hostbuf[0] = chb_prev;
				tidsendc->cuda_hostbuf[1] = chb;
				tidsendc->cuda_num_buf = 2;
				void *buffer = psmi_malloc(PSMI_EP_NONE, UNDEFINED,
						tsess_length);
				tidsendc->userbuf =
					(void *)((uintptr_t) buffer);
				tidsendc->buffer =
					(void *)((uintptr_t)tidsendc->userbuf +
						tsess_unaligned_start);
				attached = 0;
				return;
			}
			if ((tsess_srcoff > chb->offset)
			    && (tsess_srcoff < (chb->offset + chb->size))
			     && ((tsess_srcoff + tsess_length) > (chb->offset + chb->size))) {
				chb_prev = chb;
				attached = 1;
				chb = NULL;
				continue;
			} else if ((chb->offset <= tsess_srcoff) &&
				  ((tsess_srcoff + tsess_length) <=
				   (chb->offset+chb->size))) {
				tidsendc->cuda_hostbuf[0] = chb;
				tidsendc->cuda_hostbuf[1] = NULL;
				tidsendc->cuda_num_buf = 1;
				tidsendc->userbuf =
					(void *)((uintptr_t) chb->host_buf +
						tsess_srcoff - chb->offset);
				tidsendc->buffer =
					(void *)((uintptr_t)tidsendc->userbuf +
							tsess_unaligned_start );
				return;
			} else
				chb = NULL;
		}
	}
}


static
psm2_chb_match_type_t psmi_find_match_in_prefeteched_chb(struct ips_cuda_hostbuf* chb,
				       ips_tid_session_list *tid_list,
				       uint32_t prefetch_send_msgoff)
{
	/* To get a match:
	 * 1. Tid list offset + length is contained within a chb
	 * 2. Tid list offset + length is contained within
	 * the prefetched offset of this req.
	 * 3. Tid list offset + length is partially prefetched
	 * within one chb. (A partial match)
	 */
	if (chb->offset <= tid_list->tsess_srcoff) {
		if ((chb->offset + chb->size) >=
		    (tid_list->tsess_srcoff + tid_list->tsess_length)) {
			return PSMI_CUDA_FULL_MATCH_FOUND;
		} else {
			if((chb->offset + chb->size) > tid_list->tsess_srcoff){
				if(((chb->offset + (2 * chb->size)) >
				   (tid_list->tsess_srcoff + tid_list->tsess_length)) &&
						  ((prefetch_send_msgoff) >=
						   (tid_list->tsess_srcoff + tid_list->tsess_length))){
					return PSMI_CUDA_SPLIT_MATCH_FOUND;
				} else if((tid_list->tsess_srcoff + tid_list->tsess_length)
					> prefetch_send_msgoff) {
					return PSMI_CUDA_PARTIAL_MATCH_FOUND;
				}
			}
		}
	}
	return PSMI_CUDA_CONTINUE;
}
#endif

psm2_error_t
ips_tid_send_handle_tidreq(struct ips_protoexp *protoexp,
			   ips_epaddr_t *ipsaddr,
			   psm2_mq_req_t req,
			   ptl_arg_t rdescid,
			   uint32_t tidflow_genseq,
			   ips_tid_session_list *tid_list,
			   uint32_t tid_list_size)
{
	struct ips_tid_send_desc *tidsendc;
	uint32_t i, j, *src, *dst;

	PSM2_LOG_MSG("entering");
	psmi_assert(tid_list_size > sizeof(ips_tid_session_list));
	psmi_assert(tid_list_size <= sizeof(tidsendc->filler));
	psmi_assert(tid_list->tsess_tidcount > 0);
	psmi_assert((rdescid._desc_genc>>16) == 0);

	tidsendc = (struct ips_tid_send_desc *)
	    psmi_mpool_get(protoexp->tid_desc_send_pool);
	if (tidsendc == NULL) {
		PSM2_LOG_MSG("leaving");
		ips_logevent(protoexp->proto, tid_send_reqs, ipsaddr);
		return PSM2_EP_NO_RESOURCES;
	}

	req->ptl_req_ptr = (void *)tidsendc;
	tidsendc->protoexp = protoexp;

	/* Uniquely identify this send descriptor in space and time */
	tidsendc->sdescid._desc_idx = psmi_mpool_get_obj_index(tidsendc);
	tidsendc->sdescid._desc_genc = psmi_mpool_get_obj_gen_count(tidsendc);
	tidsendc->rdescid = rdescid;
	tidsendc->ipsaddr = ipsaddr;
	tidsendc->mqreq = req;

	/*
	 * Copy received tidinfo to local tidsendc buffer.
	 * while doing the copy, we try to merge the tids based on
	 * following rules:
	 * 1. both tids are virtually contiguous(i and i+1 in the array);
	 * 2. both tids have the same tidpair value;
	 * 3. first tid (i) has tidctrl=1;
	 * 4. second tid (i+1) has tidctrl=2;
	 * 5. total length does not exceed 512 pages (2M);
	 * 6. The h/w supports merged tid_ctrl's.
	 *
	 * The restriction of 512 pages comes from the limited number
	 * of bits we have for KDETH.OFFSET:
	 *   - The entire mapping space provided through TIDs is to be
	 *     viewed as a zero-based address mapping.
	 *   - We have 15 bits in KDETH offset field through which we
	 *     can address upto a maximum of 2MB.
	 *     (with 64-byte offset mode or KDETH.OM = 1)
	 *   - Assuming a 4KB page size, 2MB/4KB = 512 pages.
	 */
	psmi_mq_mtucpy_host_mem(&tidsendc->tid_list, tid_list,
				sizeof(ips_tid_session_list));
	ips_dump_tids(tid_list, "Received %d tids: ",
				tid_list->tsess_tidcount);

	if (psmi_hal_has_cap(PSM_HAL_CAP_MERGED_TID_CTRLS))
	{
		src = tid_list->tsess_list;
		dst = tidsendc->tid_list.tsess_list;
		dst[0] = src[0];
		j = 0; i = 1;
		while (i < tid_list->tsess_tidcount) {
			if ((((dst[j]>>IPS_TIDINFO_TIDCTRL_SHIFT)+1) ==
			     (src[i]>>IPS_TIDINFO_TIDCTRL_SHIFT)) &&
			    (((dst[j]&IPS_TIDINFO_LENGTH_MASK)+
			      (src[i]&IPS_TIDINFO_LENGTH_MASK)) <=
			     		PSM_MAX_NUM_PAGES_IN_TIDPAIR)) {
				/* merge 'i' to 'j'
				 * (We need to specify "tidctrl" value as 3
				 *  if we merge the individual tid-pairs.
				 *  Doing that here) */
				dst[j] += (2 << IPS_TIDINFO_TIDCTRL_SHIFT) +
					(src[i] & IPS_TIDINFO_LENGTH_MASK);
				i++;
				if (i == tid_list->tsess_tidcount) break;
			}
			j++;
			/* copy 'i' to 'j' */
			dst[j] = src[i];
			i++;
		}
		tidsendc->tid_list.tsess_tidcount = j + 1;
		tid_list = &tidsendc->tid_list;
	}
	else
	{
		tidsendc->tid_list.tsess_tidcount = tid_list->tsess_tidcount;
		psmi_mq_mtucpy(&tidsendc->tid_list.tsess_list, tid_list->tsess_list,
			       tid_list->tsess_tidcount * sizeof(tid_list->tsess_list[0]));
		tid_list = &tidsendc->tid_list;
	}

	/* Initialize tidflow for window. Use path requested by remote endpoint */
	ips_flow_init(&tidsendc->tidflow, protoexp->proto, ipsaddr,
		      protoexp->tid_xfer_type, PSM_PROTOCOL_TIDFLOW,
		      IPS_PATH_LOW_PRIORITY, EP_FLOW_TIDFLOW);
	tidsendc->tidflow.xmit_seq_num.psn_val = tidflow_genseq;
	tidsendc->tidflow.xmit_ack_num.psn_val = tidflow_genseq;

	tidsendc->userbuf =
	    (void *)((uintptr_t) req->req_data.buf + tid_list->tsess_srcoff);
	tidsendc->buffer = (void *)((uintptr_t)tidsendc->userbuf +
				tid_list->tsess_unaligned_start);
	tidsendc->length = tid_list->tsess_length;
	tidsendc->ctrl_msg_queued = 0;
	tidsendc->frag_size = min(protoexp->tid_send_fragsize,
		tidsendc->tidflow.frag_size);

#ifdef PSM_CUDA
	/* Matching on previous prefetches and initiating next prefetch */
	struct ips_cuda_hostbuf *chb = NULL, *chb_next = NULL;
	psm2_chb_match_type_t rc = PSMI_CUDA_CONTINUE;

	/* check if the prefetcher has a buffer ready to use */
	tidsendc->cuda_hostbuf[0] = NULL;
	tidsendc->cuda_hostbuf[1] = NULL;
	tidsendc->cuda_num_buf = 0;
	if (req->cuda_hostbuf_used) {
		/* To get a match:
		 * 1. Tid list offset + length is contained within a chb
		 * 2. Tid list offset + length is contained within
		 * the prefetched offset of this req.
		 * 3. Tid list offset + length is partially prefetched
		 * within one chb. (A partial match)
		 */
		STAILQ_FOREACH(chb, &req->sendreq_prefetch, req_next) {
			rc = psmi_find_match_in_prefeteched_chb(chb,
								tid_list,
								req->prefetch_send_msgoff);
			if (rc < PSMI_CUDA_CONTINUE)
				break;
		}
		if (rc == PSMI_CUDA_FULL_MATCH_FOUND) {
			tidsendc->userbuf =
				(void *)((uintptr_t) chb->host_buf+
					 tid_list->tsess_srcoff - chb->offset);
			tidsendc->buffer =
				(void *)((uintptr_t)tidsendc->userbuf +
					 tid_list->tsess_unaligned_start);
			/* now associate the buffer with the tidsendc */
			tidsendc->cuda_hostbuf[0] = chb;
			tidsendc->cuda_hostbuf[1] = NULL;
			tidsendc->cuda_num_buf = 1;
		} else if (rc == PSMI_CUDA_SPLIT_MATCH_FOUND){
			void *buffer = psmi_malloc(PSMI_EP_NONE, UNDEFINED,
					tid_list->tsess_length);
			tidsendc->userbuf =
				(void *)((uintptr_t) buffer);
			tidsendc->buffer =
				(void *)((uintptr_t)tidsendc->userbuf +
				tid_list->tsess_unaligned_start);
			chb_next = STAILQ_NEXT(chb, req_next);
			tidsendc->cuda_hostbuf[0] = chb;
			tidsendc->cuda_hostbuf[1] = chb_next;
			tidsendc->cuda_num_buf = 2;
		} else if (rc == PSMI_CUDA_PARTIAL_MATCH_FOUND) {
			psmi_attach_chb_to_tidsendc(protoexp, req,
						    tidsendc,
						    chb,
						    tid_list->tsess_srcoff,
						    tid_list->tsess_length,
						    tid_list->tsess_unaligned_start,
						    rc);
		} else {
			psmi_attach_chb_to_tidsendc(protoexp, req,
						    tidsendc,
						    NULL,
						    tid_list->tsess_srcoff,
						    tid_list->tsess_length,
						    tid_list->tsess_unaligned_start,
						    PSMI_CUDA_CONTINUE);
		}
	}
#endif

	/* frag size must be 64B multiples */
	tidsendc->frag_size &= (~63);
	tidsendc->is_complete = 0;
	tidsendc->tid_idx = 0;
	tidsendc->frame_send = 0;

	tidsendc->tidbytes = 0;
	tidsendc->remaining_tidbytes = tid_list->tsess_length -
	    tid_list->tsess_unaligned_start - tid_list->tsess_unaligned_end;
	tidsendc->remaining_bytes_in_tid =
	    (IPS_TIDINFO_GET_LENGTH(tid_list->tsess_list[0]) << 12) -
	    tid_list->tsess_tidoffset;
	tidsendc->offset_in_tid = tid_list->tsess_tidoffset;

	_HFI_EXP
	    ("alloc tidsend=%4d tidrecv=%4d srcoff=%6d length=%6d,s=%d,e=%d\n",
	     tidsendc->sdescid._desc_idx, rdescid._desc_idx,
	     tid_list->tsess_srcoff, tid_list->tsess_length,
	     tid_list->tsess_unaligned_start, tid_list->tsess_unaligned_end);

	ips_tid_send_exp(tidsendc);

	/* Add as a pending op and ring up the timer */
	if (tidsendc->is_complete == 0) {
		STAILQ_INSERT_TAIL(&protoexp->pend_sendq, tidsendc, next);
		psmi_timer_request(protoexp->timerq, &protoexp->timer_send,
			   PSMI_TIMER_PRIO_1);
	}

	PSM2_LOG_MSG("leaving");
	/* Consider breaking out of progress engine here */
	return PSM2_OK;
}

static
ips_scb_t *
ips_scb_prepare_tid_sendctrl(struct ips_flow *flow,
			     struct ips_tid_send_desc *tidsendc)
{
	struct ips_protoexp *protoexp = tidsendc->protoexp;
	uint32_t *tsess_list = tidsendc->tid_list.tsess_list;
	uint32_t tid, omode, offset, chunk_size;
	uint32_t startidx, endidx;
	uint32_t frame_len, nfrag;
	uint8_t *bufptr = tidsendc->buffer;
	ips_scb_t *scb;

	uint8_t is_payload_per_frag_leq_8dw = 0;
	 /* If payload in the first and last nfrag is less then or equal
	  * to 8DW we disable header suppression so as to detect uncorrectable
	  * errors which will otherwise be non-detectable(since header is
	  * suppressed we lose RHF.EccErr)
	  */
	if ((scb = ips_scbctrl_alloc(&protoexp->tid_scbc_rv, 1, 0, 0)) == NULL)
		return NULL;

	/*
	 * Make sure the next offset is in 64B multiples with the tid.
	 */
	frame_len =
	    min(tidsendc->remaining_bytes_in_tid, tidsendc->remaining_tidbytes);
	if (frame_len > tidsendc->frag_size) {
		frame_len =
		    tidsendc->frag_size - (tidsendc->offset_in_tid & 63);
	}
	/*
	 * Frame length is the amount of payload to be included in a particular
	 * frag of the scb, so we check if frame len is less than or equal
	 * to 8DW. If length is less then then or equal to 8DW for the first
	 * frag then we avoid header suppression
	 */
	if (frame_len <= 32)
		is_payload_per_frag_leq_8dw = 1;

	/*
	 * Using large offset mode based on offset length.
	 */
	if (tidsendc->offset_in_tid < 131072) {	/* 2^15 * 4 */
		psmi_assert((tidsendc->offset_in_tid % 4) == 0);
		offset = tidsendc->offset_in_tid / 4;
		omode = 0;
	} else {
		psmi_assert((tidsendc->offset_in_tid % 64) == 0);
		offset = tidsendc->offset_in_tid / 64;
		omode = 1;
	}
	startidx = tidsendc->tid_idx;
	tid = IPS_TIDINFO_GET_TID(tsess_list[startidx]);
	scb->ips_lrh.khdr.kdeth0 = (offset & HFI_KHDR_OFFSET_MASK) |
	    (omode << HFI_KHDR_OM_SHIFT) | (tid << HFI_KHDR_TID_SHIFT);

	scb->tidctrl = IPS_TIDINFO_GET_TIDCTRL(tsess_list[startidx]);
	scb->tsess = (uint32_t *) &tsess_list[startidx];

	/*
	 * Payload and buffer address for current packet. payload_size
	 * must be the first packet size because it is used to initialize
	 * the packet header.
	 */
	scb->payload_size = frame_len;
	ips_scb_buffer(scb) = (void *)bufptr;
	scb->frag_size = tidsendc->frag_size;

	/*
	 * Other packet fields.
	 */
	PSM2_LOG_EPM(OPCODE_EXPTID,PSM2_LOG_TX, protoexp->proto->ep->epid,
		    flow->ipsaddr->epaddr.epid,
		    "psmi_mpool_get_obj_index(tidsendc->mqreq): %d, tidsendc->rdescid._desc_idx: %d, tidsendc->sdescid._desc_idx: %d",
		    psmi_mpool_get_obj_index(tidsendc->mqreq),tidsendc->rdescid._desc_idx,tidsendc->sdescid._desc_idx);
	ips_scb_opcode(scb) = OPCODE_EXPTID;
	scb->ips_lrh.exp_sdescid = tidsendc->sdescid;
	scb->ips_lrh.exp_rdescid_genc = (uint16_t)tidsendc->rdescid._desc_genc;
	scb->ips_lrh.exp_offset = tidsendc->tidbytes;

	scb->tidsendc = tidsendc;
	SLIST_NEXT(scb, next) = NULL;

	/*
	 * Loop over the tid session list, count the frag number and payload size.
	 */
	nfrag = 1;
	chunk_size = frame_len;
	while (1) {
		/* Record last tididx used */
		endidx = tidsendc->tid_idx;
		/* Check if all tidbytes are done */
		tidsendc->remaining_tidbytes -= frame_len;
		if (!tidsendc->remaining_tidbytes) {
			/* We do another frame length check for the last frag */
			if (frame_len <= 32)
				is_payload_per_frag_leq_8dw = 1;
			break;
		}

		/* Update in current tid */
		tidsendc->remaining_bytes_in_tid -= frame_len;
		tidsendc->offset_in_tid += frame_len;
		psmi_assert((tidsendc->offset_in_tid >= 128*1024) ?
			    ((tidsendc->offset_in_tid % 64) == 0) :
			    ((tidsendc->offset_in_tid %  4) == 0));

		/* Done with this tid, move on to the next tid */
		if (!tidsendc->remaining_bytes_in_tid) {
			tidsendc->tid_idx++;
			psmi_assert_always(tidsendc->tid_idx <
				    tidsendc->tid_list.tsess_tidcount);
			tidsendc->remaining_bytes_in_tid =
			    IPS_TIDINFO_GET_LENGTH(tsess_list
						   [tidsendc->tid_idx]) << 12;
			tidsendc->offset_in_tid = 0;
		}

		/* For PIO, only single packet per scb allowed */
		if (flow->transfer == PSM_TRANSFER_PIO) {
			break;
		}

		frame_len =
		    min(tidsendc->remaining_bytes_in_tid,
			tidsendc->remaining_tidbytes);
		if (frame_len > tidsendc->frag_size)
			frame_len = tidsendc->frag_size;
		nfrag++;
		chunk_size += frame_len;
	}

	scb->nfrag = nfrag;
	if (nfrag > 1) {
		scb->nfrag_remaining = scb->nfrag;
		scb->chunk_size = scb->chunk_size_remaining = chunk_size;
	}
	scb->tsess_length = (endidx - startidx + 1) * sizeof(uint32_t);

	/* Keep track of latest buffer location so we restart at the
	 * right location, if we don't complete the transfer */
	tidsendc->buffer = bufptr + chunk_size;
	tidsendc->tidbytes += chunk_size;

	if (flow->transfer == PSM_TRANSFER_DMA &&
	    psmi_hal_has_cap(PSM_HAL_CAP_DMA_HSUPP_FOR_32B_MSGS)) {
		is_payload_per_frag_leq_8dw = 0;
	}

	/* If last packet, we want a completion notification */
	if (!tidsendc->remaining_tidbytes) {
		/* last packet/chunk, attach unaligned data */
		uint8_t *dst, *src;

		if (tidsendc->tid_list.tsess_unaligned_start) {
			dst = (uint8_t *)scb->ips_lrh.exp_ustart;
			src = (uint8_t *)tidsendc->userbuf;
#ifdef PSM_CUDA
			if (IS_TRANSFER_BUF_GPU_MEM(scb) && !tidsendc->mqreq->cuda_hostbuf_used) {
				PSMI_CUDA_CALL(cuMemcpyDtoH, dst, (CUdeviceptr)src,
						tidsendc->tid_list.tsess_unaligned_start);
			} else
#endif
				ips_protoexp_unaligned_copy(dst, src,
						tidsendc->tid_list.tsess_unaligned_start);
		}

		if (tidsendc->tid_list.tsess_unaligned_end) {
			dst = (uint8_t *)&scb->ips_lrh.exp_uend;
			src = (uint8_t *)tidsendc->userbuf +
				tidsendc->length -
				tidsendc->tid_list.tsess_unaligned_end;
#ifdef PSM_CUDA
			if (IS_TRANSFER_BUF_GPU_MEM(scb) && !tidsendc->mqreq->cuda_hostbuf_used) {
				PSMI_CUDA_CALL(cuMemcpyDtoH, dst, (CUdeviceptr)src,
						tidsendc->tid_list.tsess_unaligned_end);
			} else
#endif
				ips_protoexp_unaligned_copy(dst, src,
						tidsendc->tid_list.tsess_unaligned_end);
		}
		/*
		 * If the number of fragments is greater then one and
		 * "no header suppression" flag is unset then we go
		 * ahead and suppress the header */
		if ((scb->nfrag > 1) && (!is_payload_per_frag_leq_8dw))
			scb->scb_flags |= IPS_SEND_FLAG_HDRSUPP;
		else
			scb->scb_flags |= IPS_SEND_FLAG_ACKREQ;

		tidsendc->is_complete = 1;
	} else {
		/* Do not suppress header every hdr_pkt_interval */
		if ((++tidsendc->frame_send %
				protoexp->hdr_pkt_interval) == 0)
			/* Request an ACK */
			scb->scb_flags |= IPS_SEND_FLAG_ACKREQ;
		else {
			if (!is_payload_per_frag_leq_8dw) {
				/* Request hdr supp */
				scb->scb_flags |= IPS_SEND_FLAG_HDRSUPP;
			}
		}
		/* assert only single packet per scb */
		psmi_assert(scb->nfrag == 1);
	}

#ifdef PSM_CUDA
	if (tidsendc->mqreq->is_buf_gpu_mem &&		/* request's buffer comes from GPU realm */
	   !tidsendc->mqreq->cuda_hostbuf_used) {	/* and it was NOT moved to HOST memory */
		scb->mq_req = tidsendc->mqreq;		/* so let's mark it per scb, not to check its locality again */
		ips_scb_flags(scb) |= IPS_SEND_FLAG_PAYLOAD_BUF_GPU;
	}
#endif

	return scb;
}

/*
 * Returns:
 *
 * PSM2_OK: scb was allocated for at least one frame, the packet may be queued
 *         or actually sent.
 *
 * PSM2_OK_NO_PROGRESS: Reached a limit on the maximum number of sends we allow
 *		       to be enqueued before polling receive queue.
 *
 * PSM2_EP_NO_RESOURCES: No scbs, available, a callback will be issued when more
 *                      scbs become available.
 *
 * PSM2_TIMEOUT: PIO-busy or DMA-busy, stop trying to send for now.
 *
 */

static
psm2_error_t ips_tid_send_exp(struct ips_tid_send_desc *tidsendc)
{
	ips_scb_t *scb = NULL;
	psm2_error_t err = PSM2_OK, err_f;
	struct ips_protoexp *protoexp = tidsendc->protoexp;
	struct ips_proto *proto = protoexp->proto;
	struct ips_flow *flow = &tidsendc->tidflow;

#ifdef PSM_CUDA
	struct ips_cuda_hostbuf *chb, *chb_next;
	CUresult chb_status;
	uint32_t offset_in_chb, i;
	for (i = 0; i < tidsendc->cuda_num_buf; i++) {
		chb = tidsendc->cuda_hostbuf[i];
		if (chb) {
			PSMI_CUDA_CHECK_EVENT(chb->copy_status, chb_status);
			if (chb_status != CUDA_SUCCESS) {
				err = PSM2_OK_NO_PROGRESS;
				PSM2_LOG_MSG("leaving");
				return err;
			}
		}
	}

	if (tidsendc->cuda_num_buf == 2) {
		chb = tidsendc->cuda_hostbuf[0];
		chb_next = tidsendc->cuda_hostbuf[1];
		offset_in_chb = tidsendc->tid_list.tsess_srcoff - chb->offset;
		/* Copying data from multiple cuda
		 * host buffers into a bounce buffer.
		 */
		memcpy(tidsendc->buffer, chb->host_buf +
			offset_in_chb, chb->size-offset_in_chb);
		memcpy(tidsendc->buffer+ chb->size -
			offset_in_chb, chb_next->host_buf,
			tidsendc->tid_list.tsess_srcoff +
			tidsendc->tid_list.tsess_length - chb_next->offset);

		chb->bytes_read += chb->size - offset_in_chb;
		chb_next->bytes_read += tidsendc->tid_list.tsess_srcoff +
				  tidsendc->tid_list.tsess_length -
				  chb_next->offset;
		if(chb->bytes_read == chb->size) {
			STAILQ_REMOVE(&tidsendc->mqreq->sendreq_prefetch, chb,
				       ips_cuda_hostbuf, req_next);
			if (chb->is_tempbuf)
				psmi_deallocate_chb(chb);
			else {
				chb->req = NULL;
				chb->offset = 0;
				chb->bytes_read = 0;
				psmi_mpool_put(chb);
			}
			psmi_cuda_run_prefetcher(protoexp, tidsendc);
		 }
		if(chb_next->bytes_read == chb_next->size) {
			STAILQ_REMOVE(&tidsendc->mqreq->sendreq_prefetch, chb_next,
				       ips_cuda_hostbuf, req_next);
			if (chb_next->is_tempbuf)
				psmi_deallocate_chb(chb_next);
			else{
				chb_next->req = NULL;
				chb_next->offset = 0;
				chb_next->bytes_read = 0;
				psmi_mpool_put(chb_next);
			}
			psmi_cuda_run_prefetcher(protoexp, tidsendc);
		}
	}
#endif
	/*
	 * We aggressively try to grab as many scbs as possible, enqueue them to a
	 * flow and flush them when either we're out of scbs our we've completely
	 * filled the send request.
	 */
	while (!tidsendc->is_complete) {
		if_pf(tidsendc->tid_list.tsess_tidcount &&
		      (tidsendc->tid_idx >= tidsendc->tid_list.tsess_tidcount ||
		       tidsendc->tid_idx < 0))
			ips_expsend_tiderr(tidsendc);

		if ((scb =
		     ips_scb_prepare_tid_sendctrl(flow, tidsendc)) == NULL) {
			proto->stats.scb_exp_unavail_cnt++;
			err = PSM2_EP_NO_RESOURCES;
			break;
		} else {
			ips_proto_flow_enqueue(flow, scb);
		}
	}

	if (!SLIST_EMPTY(&flow->scb_pend)) {	/* Something to flush */
		int num_sent;

		err_f = flow->flush(flow, &num_sent);

		if (err != PSM2_EP_NO_RESOURCES) {
			/* PSM2_EP_NO_RESOURCES is reserved for out-of-scbs */
			if (err_f == PSM2_EP_NO_RESOURCES)
				err = PSM2_TIMEOUT;	/* force a resend reschedule */
			else if (err_f == PSM2_OK && num_sent > 0 &&
				 !ips_ptl_recvq_isempty(protoexp->ptl))
				err = PSM2_OK_NO_PROGRESS;	/* force a rcvhdrq service */
		}
	}

	PSM2_LOG_MSG("leaving");
	return err;
}

static
psm2_error_t
ips_tid_pendsend_timer_callback(struct psmi_timer *timer, uint64_t current)
{
	struct ips_protoexp *protoexp = (struct ips_protoexp *)timer->context;
	struct ips_tid_send_pend *phead = &protoexp->pend_sendq;
	struct ips_tid_send_desc *tidsendc;
	psm2_error_t err = PSM2_OK;

	while (!STAILQ_EMPTY(phead)) {
		tidsendc = STAILQ_FIRST(phead);

		err = ips_tid_send_exp(tidsendc);

		if (tidsendc->is_complete)
			STAILQ_REMOVE_HEAD(phead, next);

		if (err == PSM2_OK) {
			/* Was able to complete the send, keep going */
		} else if (err == PSM2_EP_NO_RESOURCES) {
			/* No more sendbufs available, sendbuf callback will requeue this
			 * timer */
			break;
		} else if (err == PSM2_TIMEOUT) {
			/* Always a case of try later:
			 * On PIO flow, means no send pio bufs available
			 * On DMA flow, means kernel can't queue request or would have to block
			 */
			psmi_timer_request(protoexp->proto->timerq,
					   &protoexp->timer_send,
					   get_cycles() +
					   protoexp->proto->timeout_send);
			break;
		} else {
			/* Forced to reschedule later so we can check receive queue */
			psmi_assert(err == PSM2_OK_NO_PROGRESS);
			psmi_timer_request(protoexp->proto->timerq,
					   &protoexp->timer_send,
					   PSMI_TIMER_PRIO_1);
			break;
		}
	}

	return PSM2_OK;
}

/* Right now, in the kernel we are allowing for virtually non-contiguous pages,
   in a single call, and we are therefore locking one page at a time, but since
   the intended use of this routine is for a single group of
   virtually contiguous pages, that should change to improve
   performance.  That means possibly changing the calling MPI code.
   Doing so gets rid of some of the loop stuff here, and in the driver,
   and allows for a single call to the core VM code in the kernel,
   rather than one per page, definitely improving performance. */

static
psm2_error_t
ips_tid_recv_alloc_frag(struct ips_protoexp *protoexp,
			struct ips_tid_recv_desc *tidrecvc,
			uint32_t nbytes_this)
{
	ips_tid_session_list *tid_list = &tidrecvc->tid_list;
	uintptr_t bufptr = (uintptr_t) tidrecvc->buffer;
	uint32_t size = nbytes_this;
	psm2_error_t err = PSM2_OK;
	uintptr_t pageaddr;
	uint32_t tidoff, pageoff, pagelen, reglen, num_tids;

	psmi_assert(size >= 4);

	/*
	 * The following calculation does not work when size < 4
	 * and bufptr is byte aligned, it can get negative value.
	 */
	tid_list->tsess_unaligned_start = (bufptr & 3) ? (4 - (bufptr & 3)) : 0;
	size -= tid_list->tsess_unaligned_start;
	bufptr += tid_list->tsess_unaligned_start;

	tid_list->tsess_unaligned_end = size & 3;
	size -= tid_list->tsess_unaligned_end;

	psmi_assert(size > 0);

#ifdef PSM_CUDA
	/* Driver pins GPU pages when using GPU Direct RDMA for TID recieves,
	 * to accomadate this change the calculations of pageaddr, pagelen
	 * and pageoff have been modified to take GPU page size into
	 * consideration.
	 */
	if (tidrecvc->is_ptr_gpu_backed) {
		uint64_t page_mask = ~(PSMI_GPU_PAGESIZE -1);
		uint32_t page_offset_mask = (PSMI_GPU_PAGESIZE -1);
		pageaddr = bufptr & page_mask;
		pagelen = (uint32_t) (PSMI_GPU_PAGESIZE +
			  ((bufptr + size - 1) & page_mask) -
			  (bufptr & page_mask));
		tidoff = pageoff = (uint32_t) (bufptr & page_offset_mask);
	} else
#endif
	{
		pageaddr = bufptr & protoexp->tid_page_mask;
		pagelen = (uint32_t) (PSMI_PAGESIZE +
			  ((bufptr + size - 1) & protoexp->tid_page_mask) -
			  (bufptr & protoexp->tid_page_mask));
		tidoff = pageoff = (uint32_t) (bufptr & protoexp->tid_page_offset_mask);
	}

	reglen = pagelen;
	if (protoexp->tidc.tid_array) {
		if ((err = ips_tidcache_acquire(&protoexp->tidc,
			    (void *)pageaddr, &reglen,
			    (uint32_t *) tid_list->tsess_list, &num_tids,
			    &tidoff
#ifdef PSM_CUDA
			    , tidrecvc->is_ptr_gpu_backed
#endif
			    )))
			goto fail;
	} else {
		if ((err = ips_tid_acquire(&protoexp->tidc,
			    (void *)pageaddr, &reglen,
			    (uint32_t *) tid_list->tsess_list, &num_tids
#ifdef PSM_CUDA
			    , tidrecvc->is_ptr_gpu_backed
#endif
			)))
			goto fail;
	}

	/*
	 * PSM2 currently provides storage space enough to hold upto
	 * 1024 tids. (PSM_TIDLIST_BUFSIZE). So, make sure we
	 * don't get more than what we can hold from the tidcache here.
	 *
	 * The reason for 1024 tids comes from the PSM_TID_WINSIZE value
	 * (currently 4MB. So, if in future, there is a change to this macro,
	 * then you would need a change to PSM_TIDLIST_BUFSIZE as well).
	 *
	 * Assuming a 4KB page size, to be able to receive
	 * a message of 4MB size, we'd need an maximum of 4MB/4KB = 1024 tids.
	 */
	psmi_assert(num_tids > 0);
	psmi_assert(num_tids <= (PSM_TID_WINSIZE/PSM_TIDLIST_BUFSIZE));
	if (reglen > pagelen) {
		err = psmi_handle_error(protoexp->tidc.context->ep,
			    PSM2_EP_DEVICE_FAILURE,
			    "PSM tid registration: "
			    "register more pages than asked");
		goto fail;
	} else if (reglen < pagelen) {
		/*
		 * driver registered less pages, update PSM records.
		 */
		tid_list->tsess_unaligned_end = 0;
		tidrecvc->recv_tidbytes = reglen - pageoff;
		tidrecvc->recv_msglen = tid_list->tsess_unaligned_start +
		    tidrecvc->recv_tidbytes;
	} else {
		tidrecvc->recv_tidbytes = size;
		tidrecvc->recv_msglen = nbytes_this;
	}

	tid_list->tsess_tidcount = num_tids;
	tid_list->tsess_tidoffset = tidoff;

	ips_dump_tids(tid_list, "Registered %d tids: ", num_tids);

fail:
	return err;
}

static
psm2_error_t
ips_tid_recv_alloc(struct ips_protoexp *protoexp,
		   ips_epaddr_t *ipsaddr,
		   const struct ips_tid_get_request *getreq,
		   uint32_t nbytes_this, struct ips_tid_recv_desc **ptidrecvc)
{
	psm2_error_t err;
	ips_scb_t *grantscb, *completescb;
	struct ips_tid_recv_desc *tidrecvc;

	PSM2_LOG_MSG("entering");
	/* Allocate all necessary resources. */

	/* 1. allocate a tid grant scb. */
	grantscb = ips_scbctrl_alloc(&protoexp->tid_scbc_rv, 1, 0, 0);
	if (grantscb == NULL) {
		/* ips_tid_scbavail_callback() will reschedule */
		PSM2_LOG_MSG("leaving");
		return PSM2_EP_NO_RESOURCES;
	}

	/* 2. allocate a tid complete scb. */
	completescb = ips_scbctrl_alloc(&protoexp->tid_scbc_rv, 1, 0, 0);
	if (completescb == NULL) {
		ips_scbctrl_free(grantscb);
		/* ips_tid_scbavail_callback() will reschedule */
		PSM2_LOG_MSG("leaving");
		return PSM2_EP_NO_RESOURCES;
	}

	/* 3. allocate a tid flow entry. */
	err = ips_tf_allocate(&protoexp->tfc, &tidrecvc);
	if (err != PSM2_OK) {
		ips_scbctrl_free(completescb);
		ips_scbctrl_free(grantscb);
		/* Unable to get a tidflow for expected protocol. */
		psmi_timer_request(protoexp->timerq,
			&protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);
		PSM2_LOG_MSG("leaving");
		return err;
	}

#ifdef PSM_CUDA
       psm2_mq_req_t req = (psm2_mq_req_t)getreq->tidgr_ucontext;

       if (req->is_buf_gpu_mem)
               tidrecvc->is_ptr_gpu_backed = !getreq->cuda_hostbuf_used;
       else
               tidrecvc->is_ptr_gpu_backed = req->is_buf_gpu_mem;

	/* 4. allocate a cuda bounce buffer, if required */
	struct ips_cuda_hostbuf *chb = NULL;
	if (getreq->cuda_hostbuf_used) {
		if (nbytes_this <= CUDA_SMALLHOSTBUF_SZ)
			chb = (struct ips_cuda_hostbuf *)
				psmi_mpool_get(
					protoexp->cuda_hostbuf_pool_small_recv);
		if (chb == NULL)
			chb = (struct ips_cuda_hostbuf *)
				psmi_mpool_get(
					protoexp->cuda_hostbuf_pool_recv);
		if (chb == NULL) {
			/* Unable to get a cudahostbuf for TID.
			 * Release the resources we're holding and reschedule.*/
			ips_tf_deallocate(&protoexp->tfc,
					  tidrecvc->rdescid._desc_idx);
			ips_scbctrl_free(completescb);
			ips_scbctrl_free(grantscb);
			psmi_timer_request(protoexp->timerq,
					   &protoexp->timer_getreqs,
					   PSMI_TIMER_PRIO_1);
			PSM2_LOG_MSG("leaving");
			return PSM2_EP_NO_RESOURCES;
		}

		tidrecvc->cuda_hostbuf = chb;
		tidrecvc->buffer = chb->host_buf;
		chb->size = 0;
		chb->gpu_buf = (CUdeviceptr) getreq->tidgr_lbuf +
					getreq->tidgr_offset;
	} else {
		chb = NULL;
		tidrecvc->buffer = (void *)((uintptr_t) getreq->tidgr_lbuf +
					    getreq->tidgr_offset);
		tidrecvc->cuda_hostbuf = NULL;
	}
#else
	tidrecvc->buffer =
	    (void *)((uintptr_t) getreq->tidgr_lbuf + getreq->tidgr_offset);
#endif

	/* 5. allocate some tids from driver. */
	err = ips_tid_recv_alloc_frag(protoexp, tidrecvc, nbytes_this);
	if (err != PSM2_OK) {
#ifdef PSM_CUDA
		if (chb)
			psmi_mpool_put(chb);
#endif
		ips_tf_deallocate(&protoexp->tfc, tidrecvc->rdescid._desc_idx);
		ips_scbctrl_free(completescb);
		ips_scbctrl_free(grantscb);
		/* Unable to register tids */
		psmi_timer_request(protoexp->timerq,
			&protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);
		PSM2_LOG_MSG("leaving");
		return err;
	}

	if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG) {
		int num_tids = tidrecvc->tid_list.tsess_tidcount;
		int tid, i;
		for (i = 0; i < num_tids; i++) {
			tid =
			    IPS_TIDINFO_GET_TID(tidrecvc->tid_list.
					tsess_list[i]) * 2 +
			    IPS_TIDINFO_GET_TIDCTRL(tidrecvc->tid_list.
					tsess_list[i]) - 1;
			psmi_assert(protoexp->tid_info[tid].state ==
				    TIDSTATE_FREE);
			psmi_assert(protoexp->tid_info[tid].tidrecvc == NULL);
			psmi_assert(protoexp->tid_info[tid].tid == 0xFFFFFFFF);
			protoexp->tid_info[tid].state = TIDSTATE_USED;
			protoexp->tid_info[tid].tidrecvc = tidrecvc;
			protoexp->tid_info[tid].tid =
			    tidrecvc->tid_list.tsess_list[i];
		}
	}

	/* Initialize recv descriptor */
	tidrecvc->ipsaddr = ipsaddr;
	tidrecvc->getreq = (struct ips_tid_get_request *)getreq;

	/* Initialize tidflow, instead calling generic routine:
	   ips_flow_init(&tidrecvc->tidflow, protoexp->proto, ipsaddr,
		      protoexp->ctrl_xfer_type, PSM_PROTOCOL_TIDFLOW,
		      IPS_PATH_LOW_PRIORITY, EP_FLOW_TIDFLOW);
	 * only reset following necessary field. */
	tidrecvc->tidflow.ipsaddr = ipsaddr;
	tidrecvc->tidflow.flags = 0;

	tidrecvc->tidflow_nswap_gen = 0;
	tidrecvc->tidflow_genseq.psn_gen = tidrecvc->tidflow_active_gen;
	tidrecvc->tidflow_genseq.psn_seq = 0;	/* Always start sequence number at 0 (zero),
	 	 	 	 	 	   in order to prevent wraparound sequence numbers */
	psmi_hal_tidflow_set_entry(
			      tidrecvc->rdescid._desc_idx,
			      tidrecvc->tidflow_genseq.psn_gen,
			      tidrecvc->tidflow_genseq.psn_seq,
			      tidrecvc->context->psm_hw_ctxt);

	tidrecvc->tid_list.tsess_srcoff = getreq->tidgr_offset;
	tidrecvc->tid_list.tsess_length = tidrecvc->recv_msglen;

	tidrecvc->ctrl_msg_queued = 0;
	tidrecvc->state = TIDRECVC_STATE_BUSY;

	tidrecvc->stats.nSeqErr = 0;
	tidrecvc->stats.nGenErr = 0;
	tidrecvc->stats.nReXmit = 0;
	tidrecvc->stats.nErrChkReceived = 0;

	/* This gets sent out as a control message, so we need to force 4-byte IB
	 * alignment */
	tidrecvc->tsess_tidlist_length = (uint16_t)
	    PSMI_ALIGNUP((sizeof(ips_tid_session_list) +
			  (tidrecvc->tid_list.tsess_tidcount *
			   sizeof(uint32_t))), 4);

	_HFI_EXP("alloc tidrecv=%d, paylen=%d, ntid=%d\n",
		 tidrecvc->rdescid._desc_idx,
		 tidrecvc->tsess_tidlist_length,
		 tidrecvc->tid_list.tsess_tidcount);

	tidrecvc->grantscb = grantscb;
	tidrecvc->completescb = completescb;

	*ptidrecvc = tidrecvc; /* return to caller */
	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}

static
psm2_error_t
ips_tid_pendtids_timer_callback(struct psmi_timer *timer, uint64_t current)
{
	struct ips_tid_get_pend *phead =
	    &((struct ips_protoexp *)timer->context)->pend_getreqsq;
	struct ips_protoexp *protoexp;
	struct ips_tid_get_request *getreq;
	struct ips_tid_recv_desc *tidrecvc;
	ips_epaddr_t *ipsaddr;
	uint32_t nbytes_this, count;
	int ret;

	PSM2_LOG_MSG("entering");

#ifdef PSM_CUDA
	if (!(((struct ips_protoexp *)timer->context)->proto->flags
		& IPS_PROTO_FLAG_GPUDIRECT_RDMA_RECV) ||
		((((struct ips_protoexp *)timer->context)->proto->flags &
		   IPS_PROTO_FLAG_GPUDIRECT_RDMA_RECV) &&
		   gpudirect_recv_threshold)) {
		/* Before processing pending TID requests, first try to free up
		 * any CUDA host buffers that are now idle. */
		struct ips_tid_get_cudapend *cphead =
			&((struct ips_protoexp *)timer->context)->cudapend_getreqsq;
		psm2_error_t err;

		/* See if any CUDA memcpys are in progress. Grab the first getreq... */
		while (!STAILQ_EMPTY(cphead)) {
			getreq = STAILQ_FIRST(cphead);

			err = psmi_cuda_reclaim_hostbufs(getreq);
			if (err == PSM2_OK_NO_PROGRESS)
				goto cudapend_exit;

			/* This pending cuda getreq has no more CUDA ops queued up.
			 * Either it's completely done, or the CUDA copies have caught
			 * up with the TID data xfer, but the TID xfer itself is not
			 * finished.
			 */
			if (getreq->tidgr_cuda_bytesdone == getreq->tidgr_length) {
				/* TID xfer is done.
				 * We should only get here if:
				 * this was involved a cuda copy, and
				 * the TIX xfer is done.
				 */
				psmi_assert(getreq->cuda_hostbuf_used);
				psmi_assert(getreq->tidgr_length ==
					    getreq->tidgr_offset);

				/* Remove from the cudapend list, and reclaim */
				getreq->tidgr_protoexp = NULL;
				getreq->tidgr_epaddr = NULL;
				STAILQ_REMOVE_HEAD(cphead, tidgr_next);

				/* mark the req as done */
				if (getreq->tidgr_callback)
					getreq->tidgr_callback(getreq->tidgr_ucontext);
				psmi_mpool_put(getreq);
			} else
				break; /* CUDA xfers in progress. Leave. */
		}
	}
cudapend_exit:
#endif

	while (!STAILQ_EMPTY(phead)) {
		getreq = STAILQ_FIRST(phead);
		ipsaddr = (ips_epaddr_t *) (getreq->tidgr_epaddr);
		count = ipsaddr->msgctl->ipsaddr_count;

ipsaddr_next:
		ipsaddr = ipsaddr->msgctl->ipsaddr_next;
		ipsaddr->msgctl->ipsaddr_next = ipsaddr->next;
		protoexp = ((psm2_epaddr_t) ipsaddr)->proto->protoexp;

		if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_CTS_SERIALIZED) {
			psmi_assert(protoexp->proto->msgflowid < EP_FLOW_LAST);
			struct ips_flow *flow = &ipsaddr->flows[protoexp->proto->msgflowid];
			if (flow->flags & IPS_FLOW_FLAG_SKIP_CTS) {
				break;                                    /* skip sending next CTS */
			}
		}

#ifdef PSM_CUDA
		if (getreq->cuda_hostbuf_used) {
			/* If this is a large transfer, we may be able to
			 * start reclaiming before all of the data is sent. */
			psmi_cuda_reclaim_hostbufs(getreq);
		}
#endif
		/*
		 * Calculate the next window size, avoid the last
		 * window too small.
		 */
		nbytes_this = getreq->tidgr_length - getreq->tidgr_offset;
		if (nbytes_this >= 2 * getreq->tidgr_rndv_winsz)
			nbytes_this = getreq->tidgr_rndv_winsz;
		else if (nbytes_this > getreq->tidgr_rndv_winsz)
			nbytes_this /= 2;

		/*
		 * If there is a next window and the next window
		 * length is greater than PAGESIZE, make sure the window
		 * starts on a page boundary.
		 */
#ifdef PSM_CUDA
		psm2_mq_req_t req = (psm2_mq_req_t)getreq->tidgr_ucontext;
		if (req->is_buf_gpu_mem){
			if (((getreq->tidgr_offset + nbytes_this) <
					getreq->tidgr_length) &&
					nbytes_this > PSMI_GPU_PAGESIZE) {
				uint32_t pageoff =
					(((uintptr_t)getreq->tidgr_lbuf) &
						(PSMI_GPU_PAGESIZE - 1)) +
					getreq->tidgr_offset + nbytes_this;
				nbytes_this -= pageoff & (PSMI_GPU_PAGESIZE - 1);
			}
		} else
#endif
		{
			if ((getreq->tidgr_offset + nbytes_this) <
					getreq->tidgr_length &&
					nbytes_this > PSMI_PAGESIZE) {
				uint32_t pageoff =
					(((uintptr_t)getreq->tidgr_lbuf) &
						(PSMI_PAGESIZE - 1)) +
					getreq->tidgr_offset + nbytes_this;
				nbytes_this -= pageoff & (PSMI_PAGESIZE - 1);
			}
		}

		psmi_assert(nbytes_this >= 4);
		psmi_assert(nbytes_this <= PSM_TID_WINSIZE);

		if ((ret = ips_tid_num_available(&protoexp->tidc)) <= 0) {
			/* We're out of tids. If this process used all the resource,
			 * the free callback will reschedule the operation, otherwise,
			 * we reschedule it here */
			if (ret == 0)
			{
				psmi_timer_request(protoexp->timerq,
						   &protoexp->timer_getreqs,
						   PSMI_TIMER_PRIO_1);
			}
		} else if ((ret = ips_tf_available(&protoexp->tfc)) <= 0) {
			/* We're out of tidflow. If this process used all the resource,
			 * the free callback will reschedule the operation, otherwise,
			 * we reschedule it here */
			if (ret == 0)
			{
				psmi_timer_request(protoexp->timerq,
						   &protoexp->timer_getreqs,
						   PSMI_TIMER_PRIO_1);
			}
		} else if (ips_tid_recv_alloc(protoexp, ipsaddr,
			      getreq, nbytes_this, &tidrecvc) == PSM2_OK) {
			ips_protoexp_send_tid_grant(tidrecvc);

			if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_CTS_SERIALIZED) {
				/*
				 * Once the CTS was sent, we mark it per 'flow' object
				 * not to proceed with next CTSes until that one is done.
				 */
				struct ips_proto *proto = tidrecvc->protoexp->proto;
				psmi_assert(proto->msgflowid < EP_FLOW_LAST);
				struct ips_flow *flow = &ipsaddr->flows[proto->msgflowid];
				flow->flags |= IPS_FLOW_FLAG_SKIP_CTS;
			}

			/*
			 * nbytes_this is the asked length for this session,
			 * ips_tid_recv_alloc() might register less pages, the
			 * real length is in tidrecvc->recv_msglen.
			 */
			getreq->tidgr_offset += tidrecvc->recv_msglen;
			psmi_assert(getreq->tidgr_offset <=
				    getreq->tidgr_length);
			_HFI_VDBG("GRANT tididx=%d srcoff=%d nbytes=%d/%d\n",
				  tidrecvc->rdescid._desc_idx,
				  getreq->tidgr_offset, tidrecvc->recv_msglen,
				  getreq->tidgr_length);

			if (getreq->tidgr_offset == getreq->tidgr_length) {
#ifdef PSM_CUDA
				if (getreq->cuda_hostbuf_used) {
					/* this completes the tid xfer setup.
					   move to the pending cuda ops queue,
					   set the timer to catch completion */
					STAILQ_REMOVE_HEAD(phead, tidgr_next);
					STAILQ_INSERT_TAIL(
						&getreq->tidgr_protoexp->cudapend_getreqsq,
						getreq, tidgr_next);
					psmi_timer_request(getreq->tidgr_protoexp->timerq,
							   &getreq->tidgr_protoexp->timer_getreqs,
							   PSMI_TIMER_PRIO_1);
					continue;
				}
#endif
				getreq->tidgr_protoexp = NULL;
				getreq->tidgr_epaddr = NULL;
				STAILQ_REMOVE_HEAD(phead, tidgr_next);
				continue;	/* try next grant request */
			}
			else if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_RTS_CTS_INTERLEAVE) {
				/* In case of multi rail, PSM sends one CTS per request
				 * per card after which the request is moved to the end
				 * of the queue.
				 */
				count--;
				if (count)
					goto ipsaddr_next;
				STAILQ_REMOVE_HEAD(phead, tidgr_next);
				STAILQ_INSERT_TAIL(phead, getreq ,tidgr_next);
				continue;
			}

			/* created a tidrecvc, reset count */
			count = ipsaddr->msgctl->ipsaddr_count;
			goto ipsaddr_next;	/* try next fragment on next ipsaddr */
		}

		/*
		 * We need to loop until we can't get a tidrecvc on all
		 * ipsaddrs, then the callbacks on the home protoexp where
		 * getreq is linked can resume this routine. Otherwise, we
		 * might make this getreq to be orphaned and cause deadlock.
		 */
		count--;
		if (count)
			goto ipsaddr_next;
		break;
	}
	PSM2_LOG_MSG("leaving");
	return PSM2_OK;		/* XXX err-broken */
}

#ifdef PSM_CUDA
static
void psmi_cudamemcpy_tid_to_device(struct ips_tid_recv_desc *tidrecvc)
{
	struct ips_protoexp *protoexp = tidrecvc->protoexp;
	struct ips_cuda_hostbuf *chb;

	chb = tidrecvc->cuda_hostbuf;
	chb->size += tidrecvc->recv_tidbytes + tidrecvc->tid_list.tsess_unaligned_start +
			tidrecvc->tid_list.tsess_unaligned_end;

	PSMI_CUDA_CALL(cuMemcpyHtoDAsync,
		       chb->gpu_buf, chb->host_buf,
		       tidrecvc->recv_tidbytes + tidrecvc->tid_list.tsess_unaligned_start +
							tidrecvc->tid_list.tsess_unaligned_end,
		       protoexp->cudastream_recv);
	PSMI_CUDA_CALL(cuEventRecord, chb->copy_status,
		       protoexp->cudastream_recv);

	STAILQ_INSERT_TAIL(&tidrecvc->getreq->pend_cudabuf, chb, next);
	tidrecvc->cuda_hostbuf = NULL;
	ips_tid_pendtids_timer_callback(&tidrecvc->getreq->tidgr_protoexp->timer_getreqs,0);
}
#endif

static
psm2_error_t ips_tid_recv_free(struct ips_tid_recv_desc *tidrecvc)
{
	struct ips_protoexp *protoexp = tidrecvc->protoexp;
	struct ips_tid_get_request *getreq = tidrecvc->getreq;
	int tidcount = tidrecvc->tid_list.tsess_tidcount;
	psm2_error_t err = PSM2_OK;

	psmi_assert(getreq != NULL);
	psmi_assert(tidcount > 0);
	psmi_assert(tidrecvc->state == TIDRECVC_STATE_BUSY);

#ifdef PSM_CUDA
	if (tidrecvc->cuda_hostbuf)
		psmi_cudamemcpy_tid_to_device(tidrecvc);
#endif

	if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG) {
		int tid, i;

		for (i = 0; i < tidcount; i++) {
			tid =
			    IPS_TIDINFO_GET_TID(tidrecvc->tid_list.
					tsess_list[i]) * 2 +
			    IPS_TIDINFO_GET_TIDCTRL(tidrecvc->tid_list.
					tsess_list[i]) - 1;
			psmi_assert(protoexp->tid_info[tid].state ==
				    TIDSTATE_USED);
			psmi_assert(protoexp->tid_info[tid].tidrecvc ==
				    tidrecvc);
			psmi_assert(protoexp->tid_info[tid].tid ==
				    tidrecvc->tid_list.tsess_list[i]);
			protoexp->tid_info[tid].state = TIDSTATE_FREE;
			protoexp->tid_info[tid].tidrecvc = NULL;
			protoexp->tid_info[tid].tid = 0xFFFFFFFF;
		}
	}

	ips_dump_tids(&tidrecvc->tid_list, "Deregistered %d tids: ",
		      tidrecvc->tid_list.tsess_tidcount);

	if (protoexp->tidc.tid_array) {
		if ((err = ips_tidcache_release(&protoexp->tidc,
			tidrecvc->tid_list.tsess_list, tidcount)))
			goto fail;
	} else {
		if ((err = ips_tid_release(&protoexp->tidc,
			tidrecvc->tid_list.tsess_list, tidcount)))
			goto fail;
	}

	getreq->tidgr_bytesdone += tidrecvc->recv_msglen;

	_HFI_EXP("req=%p bytes=%d/%d\n",
		 getreq->tidgr_ucontext,
		 getreq->tidgr_bytesdone, getreq->tidgr_length);

	tidrecvc->state = TIDRECVC_STATE_FREE;

	/* finally free the tidflow */
	ips_tf_deallocate(&protoexp->tfc, tidrecvc->rdescid._desc_idx);

	if (getreq->tidgr_bytesdone == getreq->tidgr_length) {
#ifdef PSM_CUDA
		/* if cuda, we handle callbacks when the cuda xfer is done */
		if (!getreq->cuda_hostbuf_used) {
			if (getreq->tidgr_callback)
				getreq->tidgr_callback(getreq->tidgr_ucontext);
			psmi_mpool_put(getreq);
		}
#else
		if (getreq->tidgr_callback)
			getreq->tidgr_callback(getreq->tidgr_ucontext);
		psmi_mpool_put(getreq);
#endif
	} else {
		/* We just released some tids.
		 * If requests are waiting on tids to be
		 * freed, queue up the timer */
		if (getreq->tidgr_offset < getreq->tidgr_length) {
			ips_tid_pendtids_timer_callback(&getreq->
							tidgr_protoexp->
							timer_getreqs, 0);
		}
	}

	if (!STAILQ_EMPTY(&protoexp->pend_getreqsq)) {
		psmi_timer_request(protoexp->timerq,
				   &protoexp->timer_getreqs,
				   PSMI_TIMER_PRIO_1);
	}

fail:
	return err;
}

void
ips_protoexp_handle_tiderr(const struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_tid_recv_desc *tidrecvc;
	struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;

	ptl_arg_t desc_id;
	int tidpair = (__le32_to_cpu(p_hdr->khdr.kdeth0) >>
		   HFI_KHDR_TID_SHIFT) & HFI_KHDR_TID_MASK;
	int tidctrl = (__le32_to_cpu(p_hdr->khdr.kdeth0) >>
		   HFI_KHDR_TIDCTRL_SHIFT) & HFI_KHDR_TIDCTRL_MASK;
	int tid0, tid1, tid;

	psmi_assert(_get_proto_hfi_opcode(p_hdr) == OPCODE_EXPTID);

	/* Expected sends not enabled */
	if (protoexp == NULL)
		return;

	/* Not doing extra tid debugging or not really a tiderr */
	if (!(protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG) ||
	    !(psmi_hal_rhf_get_all_err_flags(rcv_ev->psm_hal_rhf) & PSMI_HAL_RHF_ERR_TID))
		return;

	if (psmi_hal_rhf_get_rx_type(rcv_ev->psm_hal_rhf) != PSM_HAL_RHF_RX_TYPE_EXPECTED) {
		_HFI_ERROR("receive type %d is not "
			   "expected in tid debugging\n", psmi_hal_rhf_get_rx_type(rcv_ev->psm_hal_rhf));
		return;
	}

	desc_id._desc_idx = ips_proto_flowid(p_hdr);
	desc_id._desc_genc = p_hdr->exp_rdescid_genc;

	tidrecvc = &protoexp->tfc.tidrecvc[desc_id._desc_idx];

	if (tidctrl != 3)
		tid0 = tid1 = tidpair * 2 + tidctrl - 1;
	else {
		tid0 = tidpair * 2;
		tid1 = tid0 + 1;
	}

	for (tid = tid0; tid <= tid1; tid++) {
		if (protoexp->tid_info[tid].state == TIDSTATE_USED)
			continue;

		char buf[128];
		char *s = "invalid (not even in table)";

		if (tidrecvc->rdescid._desc_genc ==
				    desc_id._desc_genc)
			s = "valid";
		else {
			snprintf(buf, sizeof(buf) - 1,
				 "wrong generation (gen=%d,received=%d)",
				 tidrecvc->rdescid._desc_genc,
				 desc_id._desc_genc);
			buf[sizeof(buf) - 1] = '\0';
			s = buf;
		}

		if (protoexp->tid_info[tid].tidrecvc != tidrecvc) {
			_HFI_ERROR
			    ("tid %d not a known member of tidsess %d\n",
			     tid, desc_id._desc_idx);
		}

		_HFI_ERROR("tid %d is marked unused (session=%d): %s\n", tid,
			   desc_id._desc_idx, s);
	}
	return;
}

void
ips_protoexp_handle_data_err(const struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_tid_recv_desc *tidrecvc;
	struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	int hdr_err = psmi_hal_rhf_get_all_err_flags(rcv_ev->psm_hal_rhf) & PSMI_HAL_RHF_ERR_KHDRLEN;
	uint8_t op_code = _get_proto_hfi_opcode(p_hdr);
	char pktmsg[128];
	char errmsg[256];

	psmi_assert(_get_proto_hfi_opcode(p_hdr) == OPCODE_EXPTID);

	/* Expected sends not enabled */
	if (protoexp == NULL)
		return;

	ips_proto_get_rhf_errstring(psmi_hal_rhf_get_all_err_flags(rcv_ev->psm_hal_rhf), pktmsg,
				    sizeof(pktmsg));

	snprintf(errmsg, sizeof(errmsg),
		 "%s pkt type opcode 0x%x at hd=0x%x %s\n",
		 (psmi_hal_rhf_get_rx_type(rcv_ev->psm_hal_rhf) == PSM_HAL_RHF_RX_TYPE_EAGER) ? "Eager" :
		 (psmi_hal_rhf_get_rx_type(rcv_ev->psm_hal_rhf) == PSM_HAL_RHF_RX_TYPE_EXPECTED) ? "Expected" :
		 (psmi_hal_rhf_get_rx_type(rcv_ev->psm_hal_rhf) == PSM_HAL_RHF_RX_TYPE_NON_KD) ? "Non-kd" :
		 "<Error>", op_code, rcv_ev->recvq->state->hdrq_head,
		 pktmsg);

	if (!hdr_err) {
		ptl_arg_t desc_id;
		psmi_seqnum_t sequence_num;

		desc_id._desc_idx = ips_proto_flowid(p_hdr);
		desc_id._desc_genc = p_hdr->exp_rdescid_genc;

		tidrecvc = &protoexp->tfc.tidrecvc[desc_id._desc_idx];

		if (tidrecvc->rdescid._desc_genc != desc_id._desc_genc) {
			/* Print this at very verbose level. Noisy links can have a few of
			 * these! */
			_HFI_VDBG
			    ("Data Error Pkt and Recv Generation Mismatch: %s",
			     errmsg);
			return;	/* skip */
		}

		if (tidrecvc->state == TIDRECVC_STATE_FREE) {
			_HFI_EPDBG
			    ("Data Error Pkt for a Completed Rendezvous: %s",
			     errmsg);
			return;	/* skip */
		}

		/* See if CRC error for a previous packet */
		sequence_num.psn_val = __be32_to_cpu(p_hdr->bth[2]);
		if (sequence_num.psn_gen == tidrecvc->tidflow_genseq.psn_gen) {
			/* Try to recover the flow by restarting from previous known good
			 * sequence (possible if the packet with CRC error is after the "known
			 * good PSN" else we can't restart the flow.
			 */
			return ips_protoexp_do_tf_seqerr(protoexp,
					tidrecvc, p_hdr);
		} else {
			/* Print this at very verbose level */
			_HFI_VDBG
			    ("Data Error Packet. GenMismatch: Yes. Tidrecvc: %p. "
			     "Pkt Gen.Seq: %d.%d, TF Gen.Seq: %d.%d. %s\n",
			     tidrecvc, sequence_num.psn_gen,
			     sequence_num.psn_seq,
			     tidrecvc->tidflow_genseq.psn_gen,
			     tidrecvc->tidflow_genseq.psn_seq, errmsg);
		}

	} else {
		_HFI_VDBG("HDR_ERROR: %s\n", errmsg);
	}

}

psm2_error_t
ips_protoexp_flow_newgen(struct ips_tid_recv_desc *tidrecvc)
{
	psmi_assert_always(tidrecvc->state == TIDRECVC_STATE_BUSY);
	ips_tfgen_allocate(&tidrecvc->protoexp->tfc,
				 tidrecvc->rdescid._desc_idx,
				 &tidrecvc->tidflow_active_gen);

	/* Update tidflow table with new generation number */
	tidrecvc->tidflow_genseq.psn_gen = tidrecvc->tidflow_active_gen;
	psmi_hal_tidflow_set_entry(
			      tidrecvc->rdescid._desc_idx,
			      tidrecvc->tidflow_genseq.psn_gen,
			      tidrecvc->tidflow_genseq.psn_seq,
			      tidrecvc->context->psm_hw_ctxt);

	/* Increment swapped generation count for tidflow */
	tidrecvc->tidflow_nswap_gen++;
	return PSM2_OK;
}

void
ips_protoexp_handle_tf_seqerr(const struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_tid_recv_desc *tidrecvc;
	ptl_arg_t desc_id;

	psmi_assert_always(protoexp != NULL);
	psmi_assert(_get_proto_hfi_opcode(p_hdr) == OPCODE_EXPTID);

	desc_id._desc_idx = ips_proto_flowid(p_hdr);
	desc_id._desc_genc = p_hdr->exp_rdescid_genc;

	tidrecvc = &protoexp->tfc.tidrecvc[desc_id._desc_idx];

	if (tidrecvc->rdescid._desc_genc == desc_id._desc_genc
			&& tidrecvc->state == TIDRECVC_STATE_BUSY)
		ips_protoexp_do_tf_seqerr(protoexp, tidrecvc, p_hdr);

	return;
}

static
void ips_protoexp_do_tf_seqerr(void *vpprotoexp
			       /* actually: struct ips_protoexp *protoexp */,
			       void *vptidrecvc
			       /* actually: struct ips_tid_recv_desc *tidrecvc */,
			       struct ips_message_header *p_hdr)
{
	struct ips_protoexp *protoexp = (struct ips_protoexp *) vpprotoexp;
	struct ips_tid_recv_desc *tidrecvc = (struct ips_tid_recv_desc *) vptidrecvc;
	psmi_seqnum_t sequence_num, tf_sequence_num;
	ips_scb_t ctrlscb;

	/* Update stats for sequence errors */
	tidrecvc->stats.nSeqErr++;

	sequence_num.psn_val = __be32_to_cpu(p_hdr->bth[2]);

	/* Only care about sequence error for currently active generation */
	if (tidrecvc->tidflow_active_gen != sequence_num.psn_gen)
		return;

	/* If a "large" number of swapped generation we are loosing packets
	 * for this flow. Request throttling of tidflow by generating a
	 * BECN. With header suppression we will miss some FECN packet
	 * on OPA hence keeping track of swapped generation is another
	 * mechanism to do congestion control for tidflows.
	 *
	 * For mismatched sender/receiver/link speeds we can get into a
	 * deadly embrace where minimal progress is made due to generation
	 * mismatch errors. This can occur if we wrap around the generation
	 * count without making progress. Hence in cases where the swapped
	 * generation count is > 254 stop sending BECN (and the NAK) so the
	 * send -> receiver pipeline is flushed with an error check and things
	 * can sync up. This should be an extremely rare event.
	 */

	if_pf(tidrecvc->tidflow_nswap_gen >= 254)
		return;	/* Do not send NAK. Let error check kick in. */

	if_pf((tidrecvc->tidflow_nswap_gen > 4) &&
	      (protoexp->proto->flags & IPS_PROTO_FLAG_CCA)) {
		_HFI_CCADBG("Generating BECN. Number of swapped gen: %d.\n",
				tidrecvc->tidflow_nswap_gen);
		/* Mark flow to generate BECN in control packet */
		tidrecvc->tidflow.flags |= IPS_FLOW_FLAG_GEN_BECN;

		/* Update stats for congestion encountered */
		protoexp->proto->epaddr_stats.congestion_pkts++;
	}

	/* Get the latest seq from hardware tidflow table, if that value is
	 * reliable. The value is not reliable if context sharing is used,
	 * because context sharing might drop packet even though hardware
	 * has received it successfully. The hardware table may also be
	 * incorrect if RSM is intercepting TID & FECN & SH packets.
	 * We can handle this condition by taking the most recent PSN whether
	 * it comes from the tidflow table or from PSM's own accounting.
	 */
	if (!tidrecvc->context->tf_ctrl) {
		uint64_t tf;
		uint32_t seqno=0;

		psmi_hal_tidflow_get(tidrecvc->rdescid._desc_idx, &tf,
				     tidrecvc->context->psm_hw_ctxt);
		psmi_hal_tidflow_get_seqnum(tf, &seqno);
		tf_sequence_num.psn_val = seqno;

		if (psmi_hal_has_cap(PSM_HAL_CAP_RSM_FECN_SUPP)) {
			if (tf_sequence_num.psn_val > tidrecvc->tidflow_genseq.psn_seq)
				tidrecvc->tidflow_genseq.psn_seq = tf_sequence_num.psn_seq;
		}
		else
			tidrecvc->tidflow_genseq.psn_seq = tf_sequence_num.psn_seq;
	}

	/* Swap generation for the flow. */
	ips_protoexp_flow_newgen(tidrecvc);

	ctrlscb.scb_flags = 0;
	ctrlscb.ips_lrh.data[0] = p_hdr->exp_sdescid;
	/* Keep peer generation but use my last received sequence */
	sequence_num.psn_seq = tidrecvc->tidflow_genseq.psn_seq;
	ctrlscb.ips_lrh.ack_seq_num = sequence_num.psn_val;

	/* My new generation and last received sequence */
	ctrlscb.ips_lrh.data[1].u32w0 = tidrecvc->tidflow_genseq.psn_val;

	ips_proto_send_ctrl_message(&tidrecvc->tidflow,
				    OPCODE_NAK,
				    &tidrecvc->ctrl_msg_queued,
				    &ctrlscb, ctrlscb.cksum, 0);

	/* Update stats for retransmit */
	tidrecvc->stats.nReXmit++;

	return;
}

void
ips_protoexp_handle_tf_generr(const struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_tid_recv_desc *tidrecvc;
	ptl_arg_t desc_id;

	psmi_assert_always(protoexp != NULL);
	psmi_assert(_get_proto_hfi_opcode(p_hdr) == OPCODE_EXPTID);

	/* For a generation error our NAK crossed on the wire or this is a stale
	 * packet. Error recovery should sync things up again. Just drop this
	 * packet.
	 */
	desc_id._desc_idx = ips_proto_flowid(p_hdr);
	desc_id._desc_genc = p_hdr->exp_rdescid_genc;

	tidrecvc = &protoexp->tfc.tidrecvc[desc_id._desc_idx];

	if (tidrecvc->rdescid._desc_genc == desc_id._desc_genc
			&& tidrecvc->state == TIDRECVC_STATE_BUSY)
		ips_protoexp_do_tf_generr(protoexp, tidrecvc, p_hdr);

	return;
}

static
void ips_protoexp_do_tf_generr(void *vpprotoexp
			       /* actually: struct ips_protoexp *protoexp */,
			       void *vptidrecvc
			       /* actually: struct ips_tid_recv_desc *tidrecvc */,
			       struct ips_message_header *p_hdr)
{
	struct ips_tid_recv_desc *tidrecvc = (struct ips_tid_recv_desc *) vptidrecvc;
	/* Update stats for generation errors */
	tidrecvc->stats.nGenErr++;

	/* If packet faced congestion we may want to generate
	 * a CN packet to rate control sender.
	 */

	return;
}
