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

/* Copyright (c) 2003-2016 Intel Corporation. All rights reserved. */

#include "psm2_mock_testing.h"
#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

static uint32_t non_dw_mul_sdma = 0;

void
ips_proto_mq_set_non_dw_mul_sdma(uint32_t mode)
{
	non_dw_mul_sdma = mode;
}

PSMI_NEVER_INLINE(ips_scb_t *
		  ips_poll_scb(struct ips_proto *proto,
			       int npkts, int len, uint32_t flags, int istiny))
{
	ips_scb_t *scb = NULL;
	psmi_assert(npkts > 0);
	psm2_error_t err;

	proto->stats.scb_egr_unavail_cnt++;

	PSMI_BLOCKUNTIL(proto->ep, err,
			((scb =
			  (istiny ?
			   ips_scbctrl_alloc_tiny(&proto->scbc_egr) :
			   ips_scbctrl_alloc(&proto->scbc_egr, npkts, len,
					     flags))) != NULL));
	psmi_assert(scb != NULL);
	return scb;
}

PSMI_ALWAYS_INLINE(ips_scb_t *mq_alloc_tiny(struct ips_proto *proto))
{
	ips_scb_t *scb = ips_scbctrl_alloc_tiny(&proto->scbc_egr);
	/* common case should branch right through */
	if_pt(scb != NULL)
	    return scb;
	else
	return ips_poll_scb(proto, 1, 0, 0, 1);
}

PSMI_ALWAYS_INLINE(
ips_scb_t *
mq_alloc_pkts(struct ips_proto *proto, int npkts, int len, uint32_t flags))
{
	psmi_assert(npkts > 0);
	ips_scb_t *scb = ips_scbctrl_alloc(&proto->scbc_egr, npkts, len, flags);
	if_pt(scb != NULL) {
		return scb;
	}
	else {
		return ips_poll_scb(proto, npkts, len, flags,
				    0 /* not tiny scb */);
	}
}

static
int ips_proto_mq_eager_complete(void *reqp, uint32_t nbytes)
{
	psm2_mq_req_t req = (psm2_mq_req_t) reqp;

	/* This code path is executed when the send is on a device buffer
	 * and the receive is completed using eager buffers. As there is no
	 * completion notification sent to the sender, this is the only place
	 * where send side chb's can be freed and put back into the mpool.
	 */
#ifdef PSM_CUDA
	struct ips_cuda_hostbuf *chb;
	if (req->cuda_hostbuf_used) {
		while (!STAILQ_EMPTY(&req->sendreq_prefetch)) {
			/* If any prefetched buffers weren't used, they
			   must be reclaimed here. */
			chb = STAILQ_FIRST(&req->sendreq_prefetch);
			STAILQ_REMOVE_HEAD(&req->sendreq_prefetch,
						   req_next);
			psmi_mpool_put(chb);
		}
	}
#endif

	req->send_msgoff += nbytes;
	/*
	 * the reason to use >= is because
	 * we may have DW pad in nbytes.
	 */
	if (req->send_msgoff >= req->send_msglen) {
		req->state = MQ_STATE_COMPLETE;
		ips_barrier();
		if(!psmi_is_req_internal(req))
			mq_qq_append(&req->mq->completed_q, req);
	}
	return IPS_RECVHDRQ_CONTINUE;
}

static
int ips_proto_mq_rv_complete(void *reqp)
{
	psm2_mq_req_t req = (psm2_mq_req_t) reqp;
	psmi_mq_handle_rts_complete(req);

	return IPS_RECVHDRQ_CONTINUE;
}

static
void ips_proto_mq_rv_complete_exp(void *reqp)
{
	ips_proto_mq_rv_complete(reqp);
	return;
}

PSMI_ALWAYS_INLINE(
void
ips_shortcpy(void *vdest, const void *vsrc, uint32_t nchars))
{
	unsigned char *dest = vdest;
	const unsigned char *src = vsrc;

#ifdef PSM_CUDA
	if (PSMI_IS_CUDA_ENABLED && (PSMI_IS_CUDA_MEM(vdest) || PSMI_IS_CUDA_MEM((void *) vsrc))) {
		PSMI_CUDA_CALL(cudaMemcpy,
			       vdest, vsrc, nchars, cudaMemcpyDefault);
		return;
	}
#endif

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
	return;
}

extern psm2_error_t ips_ptl_poll(ptl_t *ptl, int _ignored);

/*
 * Mechanism to capture PIO-ing or DMA-ing the MQ message envelope
 *
 * Recoverable errors:
 * PSM2_OK: If PIO, envelope is sent.
 *	   If DMA, all queued up packets on flow were flushed.
 *
 * Recoverable errors converted to PSM2_OK just before return:
 * PSM2_OK_NO_PROGRESS: DMA-only, flushed 1 but not all queued packets.
 * PSM2_EP_NO_RESOURCES:
 *	   If PIO, no pio available or cable currently pulled.
 *	   If DMA, can be that no scb's available to handle unaligned packets
 *	           or writev returned a recoverable error (no mem for
 *	           descriptors, dma interrupted or no space left in dma queue).
 *
 * Unrecoverable errors (PIO or DMA).
 * PSM2_EP_DEVICE_FAILURE: Unexpected error calling writev(), chip failure,
 *			  rxe/txe parity error.
 * PSM2_EP_NO_NETWORK: No network, no lid, ...
 */
PSMI_ALWAYS_INLINE(
psm2_error_t
ips_mq_send_envelope(struct ips_proto *proto, struct ips_flow *flow,
		     struct ips_scb *scb, int do_flush))
{
	psm2_error_t err = PSM2_OK;

	ips_proto_flow_enqueue(flow, scb);

	if ((flow->transfer == PSM_TRANSFER_PIO) || do_flush)
		err = flow->flush(flow, NULL);

	if (do_flush)
		err = ips_recv_progress_if_busy(proto->ptl, err);

	/* As per the PSM error model (or lack thereof), PSM clients expect to see
	 * only PSM2_OK as a recoverable error */
	if (err == PSM2_EP_NO_RESOURCES || err == PSM2_OK_NO_PROGRESS)
		err = PSM2_OK;
	return err;
}

/*
 * We don't use message striping for middle message protocol,
 * Tests on sandy-bridge two HFIs show lower bandwidth if
 * message striping is used.
 */
ustatic
psm2_error_t
ips_ptl_mq_eager(struct ips_proto *proto, psm2_mq_req_t req,
		 struct ips_flow *flow, psm2_mq_tag_t *tag, const void *ubuf,
		 uint32_t len)
{
	ips_epaddr_t *ipsaddr = flow->ipsaddr;
	psm2_error_t err = PSM2_OK;
	uintptr_t buf = (uintptr_t) ubuf;
	uint32_t nbytes_left, pktlen, offset, chunk_size;
	uint16_t msgseq, padding;
	ips_scb_t *scb;
	uint32_t is_non_dw_mul_allowed = IPS_NON_DW_MUL_NOT_ALLOWED;

	psmi_assert(len > 0);
	psmi_assert(req != NULL);

	if (flow->transfer == PSM_TRANSFER_DMA) {
		psmi_assert((proto->flags & IPS_PROTO_FLAG_SPIO) == 0);
		/* max chunk size is the rv window size */
		chunk_size = proto->mq->hfi_window_rv;
		is_non_dw_mul_allowed = non_dw_mul_sdma;
	} else {
		psmi_assert((proto->flags & IPS_PROTO_FLAG_SDMA) == 0);
		chunk_size = flow->frag_size;
	}
	msgseq = ipsaddr->msgctl->mq_send_seqnum++;

	nbytes_left = len;
	offset = 0;
	do {
		if (is_non_dw_mul_allowed) {
			// no need to care about padding if non-double word multiple message size is allowed.
			padding = 0;
		} else {
			padding = nbytes_left & 0x3;
		}

		if (padding) {
			psmi_assert(nbytes_left > flow->frag_size);
			/* over reading should be OK on sender because
			 * the padding area is within the whole buffer,
			 * receiver will discard the extra bytes via
			 * padcnt in packet header
			 */
			padding = 4 - padding;
			pktlen = flow->frag_size - padding;
		} else {
			pktlen = min(chunk_size, nbytes_left);
			psmi_assert(((pktlen & 0x3) == 0) || (IPS_NON_DW_MUL_ALLOWED == is_non_dw_mul_allowed));
		}

		scb = mq_alloc_pkts(proto, 1, 0, 0);
		psmi_assert(scb != NULL);

		ips_scb_opcode(scb) = OPCODE_EAGER;
		scb->ips_lrh.khdr.kdeth0 = msgseq;
		ips_scb_copy_tag(scb->ips_lrh.tag, tag->tag);
		ips_scb_hdrdata(scb).u32w1 = len;
		ips_scb_hdrdata(scb).u32w0 = offset;	/* initial offset */

		_HFI_VDBG
		    ("payload=%p, thislen=%d, frag_size=%d, nbytes_left=%d\n",
		     (void *)buf, pktlen, flow->frag_size, nbytes_left);
		ips_scb_buffer(scb) = (void *)buf;

		buf += pktlen;
		offset += pktlen;
		nbytes_left -= pktlen;

		pktlen += padding;
		psmi_assert(((pktlen & 0x3) == 0) || (IPS_NON_DW_MUL_ALLOWED == is_non_dw_mul_allowed));

		scb->frag_size = flow->frag_size;
		scb->nfrag = (pktlen + flow->frag_size - 1) / flow->frag_size;
		if (scb->nfrag > 1) {
			ips_scb_length(scb) = flow->frag_size;
			scb->nfrag_remaining = scb->nfrag;
			scb->chunk_size =
				scb->chunk_size_remaining = pktlen;
		} else
			ips_scb_length(scb) = pktlen;

		if (nbytes_left == 0) {	/* last segment/packet */
			ips_scb_cb(scb) = ips_proto_mq_eager_complete;
			ips_scb_cb_param(scb) = req;

			/* Set ACKREQ if single packet per scb. For multi
			 * packets per scb, it is SDMA, driver will set
			 * ACKREQ in last packet, we only need ACK for
			 * last packet.
			 */
			if (scb->nfrag == 1)
				ips_scb_flags(scb) |= IPS_SEND_FLAG_ACKREQ;
		} else {
			req->send_msgoff += pktlen;
		}

		ips_proto_flow_enqueue(flow, scb);
		if (flow->transfer == PSM_TRANSFER_PIO) {
			/* we need to flush the pio pending queue as quick as possible */
			err = flow->flush(flow, NULL);
		}

	} while (nbytes_left);

	/* after all sdma setup, flush sdma queue,
	 * we want one system call to handle as many scbs as possible.
	 */
	if (flow->transfer == PSM_TRANSFER_DMA) {
		err = flow->flush(flow, NULL);
	}

	/* before return, try to make some progress. */
	if (err == PSM2_EP_NO_RESOURCES || err == PSM2_OK_NO_PROGRESS) {
		err =
		    ips_recv_progress_if_busy(proto->ptl, PSM2_EP_NO_RESOURCES);
	}

	return err;
}

static
psm2_error_t
ips_ptl_mq_rndv(struct ips_proto *proto, psm2_mq_req_t req,
		ips_epaddr_t *ipsaddr, const void *buf, uint32_t len)
{
	struct ips_flow *flow = &ipsaddr->flows[proto->msgflowid];
	psm2_error_t err = PSM2_OK;
	ips_scb_t *scb;

	PSM2_LOG_MSG("entering");
	req->buf = (void *)buf;
	req->buf_len = len;
	req->send_msglen = len;
	req->recv_msgoff = 0;
	req->rts_peer = (psm2_epaddr_t) ipsaddr;

	scb = mq_alloc_pkts(proto, 1, 0, 0);
	psmi_assert(scb);
	ips_scb_opcode(scb) = OPCODE_LONG_RTS;
	ips_scb_flags(scb) |= IPS_SEND_FLAG_ACKREQ;
	if (req->type & MQE_TYPE_WAITING)
		ips_scb_flags(scb) |= IPS_SEND_FLAG_BLOCKING;

	scb->ips_lrh.khdr.kdeth0 = ipsaddr->msgctl->mq_send_seqnum++;
	ips_scb_copy_tag(scb->ips_lrh.tag, req->tag.tag);
	ips_scb_hdrdata(scb).u32w1 = len;
	ips_scb_hdrdata(scb).u32w0 = psmi_mpool_get_obj_index(req);

	if (len <= flow->frag_size &&
#ifdef PSM_CUDA
	    !req->is_buf_gpu_mem &&
#endif
	    !(len & 0x3)) {
		ips_scb_buffer(scb) = (void *)buf;
		ips_scb_length(scb) = len;
		req->send_msgoff = len;
	} else {
		ips_scb_length(scb) = 0;
		req->send_msgoff = 0;
	}

#ifdef PSM_CUDA
	/* Used to indicate to the receiver that the send
	 * is issued on a device buffer. This helps the
	 * receiver select TID instead of using eager buffers.
	 */
	if (req->is_buf_gpu_mem)
		ips_scb_flags(scb) |= IPS_SEND_FLAG_GPU_BUF;
	req->cuda_hostbuf_used = 0;
	if ((!(proto->flags & IPS_PROTO_FLAG_GPUDIRECT_RDMA_SEND) &&
	   req->is_buf_gpu_mem &&
	    (len > GPUDIRECT_THRESH_RV)) ||
	    ((proto->flags & IPS_PROTO_FLAG_GPUDIRECT_RDMA_SEND)  &&
	    req->is_buf_gpu_mem &&
	    (len > gpudirect_send_threshold))) {
		/* send from intermediate host buffer */
		struct ips_cuda_hostbuf *chb;
		uint32_t offset, window_len;
		int prefetch_lookahead = 0;

		STAILQ_INIT(&req->sendreq_prefetch);
		offset = 0;
		req->cuda_hostbuf_used = 1;

		/* start prefetching */
		req->prefetch_send_msgoff = 0;
		while ((offset < len) &&
		       (prefetch_lookahead < proto->cuda_prefetch_limit)) {
			chb = NULL;
			window_len =
				ips_cuda_next_window(proto->mq->hfi_window_rv,
						     offset, len);

			if (window_len <= CUDA_SMALLHOSTBUF_SZ)
				chb = (struct ips_cuda_hostbuf *)
					psmi_mpool_get(
					proto->cuda_hostbuf_pool_small_send);
			if (chb == NULL)
				chb = (struct ips_cuda_hostbuf *)
					psmi_mpool_get(
					proto->cuda_hostbuf_pool_send);

			/* any buffers available? */
			if (chb == NULL)
				break;

			req->prefetch_send_msgoff += window_len;

			chb->offset = offset;
			chb->size = window_len;
			chb->req = req;
			chb->gpu_buf = (void *) buf + offset;
			chb->bytes_read = 0;

			PSMI_CUDA_CALL(cudaMemcpyAsync,
				       chb->host_buf, chb->gpu_buf,
				       window_len,
				       cudaMemcpyDeviceToHost,
				       proto->cudastream_send);
			PSMI_CUDA_CALL(cudaEventRecord,
				       chb->copy_status,
				       proto->cudastream_send);

			STAILQ_INSERT_TAIL(&req->sendreq_prefetch, chb,
					   req_next);
			offset += window_len;
			prefetch_lookahead++;
		}
	}
#endif

	PSM_LOG_EPM_COND(len > proto->mq->hfi_thresh_rv && proto->protoexp,OPCODE_LONG_RTS,PSM_LOG_EPM_TX,proto->ep->epid, req->rts_peer->epid,
			    "ips_scb_hdrdata(scb).u32w0: %d",ips_scb_hdrdata(scb).u32w0);

	if ((err = ips_mq_send_envelope(proto, flow, scb, PSMI_TRUE)))
		goto fail;

	/* Assume that we already put a few rndv requests in flight.  This helps
	 * for bibw microbenchmarks and doesn't hurt the 'blocking' case since
	 * we're going to poll anyway */
	psmi_poll_internal(proto->ep, 1);

fail:
	_HFI_VDBG
	    ("[rndv][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x][req=%p/%d]: %s\n",
	     psmi_epaddr_get_name(proto->ep->epid),
	     psmi_epaddr_get_name(req->rts_peer->epid), buf, len,
	     req->tag.tag[0], req->tag.tag[1], req->tag.tag[2], req,
	     psmi_mpool_get_obj_index(req), psm2_error_get_string(err));
	PSM2_LOG_MSG("leaving");
	return err;
}

psm2_error_t
ips_proto_mq_isend(psm2_mq_t mq, psm2_epaddr_t mepaddr, uint32_t flags,
		   psm2_mq_tag_t *tag, const void *ubuf, uint32_t len,
		   void *context, psm2_mq_req_t *req_o)
{
	psm2_error_t err = PSM2_OK;
	struct ips_proto *proto;
	struct ips_flow *flow;
	ips_epaddr_t *ipsaddr;
	ips_scb_t *scb;
	psm2_mq_req_t req;

	req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND);
	if_pf(req == NULL)
	    return PSM2_NO_MEMORY;

	ipsaddr = ((ips_epaddr_t *) mepaddr)->msgctl->ipsaddr_next;
	ipsaddr->msgctl->ipsaddr_next = ipsaddr->next;
	proto = ((psm2_epaddr_t) ipsaddr)->proto;

	req->send_msglen = len;
	req->tag = *tag;
	req->context = context;

#ifdef PSM_CUDA
	/* CUDA documentation dictates the use of SYNC_MEMOPS attribute
	 * when the buffer pointer received into PSM has been allocated
	 * by the application. This guarantees the all memory operations
	 * to this region of memory (used by multiple layers of the stack)
	 * always synchronize
	 */
	if (PSMI_IS_CUDA_ENABLED && PSMI_IS_CUDA_MEM((void*)ubuf)) {
		int trueflag = 1;
		PSMI_CUDA_CALL(cuPointerSetAttribute, &trueflag,
			       CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
			      (CUdeviceptr)ubuf);
		req->is_buf_gpu_mem = 1;
		goto do_rendezvous;
	} else
		req->is_buf_gpu_mem = 0;
#endif

	if (flags & PSM2_MQ_FLAG_SENDSYNC) {
		goto do_rendezvous;
	} else if (len <= mq->hfi_thresh_tiny) {
		flow = &ipsaddr->flows[proto->msgflowid];
		scb = mq_alloc_tiny(proto);
		psmi_assert(scb);
		ips_scb_opcode(scb) = OPCODE_TINY;
		scb->ips_lrh.khdr.kdeth0 =
		    ((len & HFI_KHDR_TINYLEN_MASK) << HFI_KHDR_TINYLEN_SHIFT) |
		    ipsaddr->msgctl->mq_send_seqnum++;
		ips_scb_copy_tag(scb->ips_lrh.tag, tag->tag);

		mq_copy_tiny((uint32_t *) &ips_scb_hdrdata(scb),
			     (uint32_t *) ubuf, len);
		err = ips_mq_send_envelope(proto, flow, scb, PSMI_TRUE);
		if (err != PSM2_OK)
			return err;

		/* We can mark this op complete since all the data is now copied
		 * into an SCB that remains live until it is remotely acked */
		req->state = MQ_STATE_COMPLETE;
		mq_qq_append(&mq->completed_q, req);
		_HFI_VDBG
		    ("[itiny][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x][req=%p]\n",
		     psmi_epaddr_get_name(mq->ep->epid),
		     psmi_epaddr_get_name(((psm2_epaddr_t) ipsaddr)->epid), ubuf,
		     len, tag->tag[0], tag->tag[1], tag->tag[2], req);
	} else if (len <= ipsaddr->flows[proto->msgflowid].frag_size) {
		uint32_t paylen = len & ~0x3;

		scb = mq_alloc_pkts(proto, 1, 0, 0);
		psmi_assert(scb);

		ips_scb_opcode(scb) = OPCODE_SHORT;
		scb->ips_lrh.khdr.kdeth0 = ipsaddr->msgctl->mq_send_seqnum++;
		ips_scb_hdrdata(scb).u32w1 = len;
		ips_scb_copy_tag(scb->ips_lrh.tag, tag->tag);

		ips_scb_buffer(scb) = (void *)ubuf;
		ips_scb_length(scb) = paylen;
		if (len > paylen) {
			/* there are nonDW bytes, copy to header */
			mq_copy_tiny((uint32_t *)&ips_scb_hdrdata(scb).u32w0,
				(uint32_t *)((uintptr_t)ubuf + paylen),
				len - paylen);

			/* for complete callback */
			req->send_msgoff = len - paylen;
		} else {
			req->send_msgoff = 0;
		}

		/*
		 * Need ack for send side completion because we
		 * send from user buffer.
		 */
		ips_scb_flags(scb) |= IPS_SEND_FLAG_ACKREQ;

		flow = &ipsaddr->flows[proto->msgflowid];
		err = ips_mq_send_envelope(proto, flow, scb, PSMI_TRUE);
		if (err != PSM2_OK)
			return err;

		/*
		 * It should be OK to check the buffer address in
		 * 'scb' to be changed, when this scb is done, the
		 * address is set to NULL when scb is put back to
		 * scb pool. Even if the same scb is re-used, it
		 * is not possible to set to this 'buf' address.
		 */
		if (ips_scb_buffer(scb) == (void *)ubuf) {
			/* continue to send from user buffer */
			ips_scb_cb(scb) = ips_proto_mq_eager_complete;
			ips_scb_cb_param(scb) = req;
		} else {
			/* mark the message done */
			req->state = MQ_STATE_COMPLETE;
			mq_qq_append(&mq->completed_q, req);
		}
		_HFI_VDBG
		    ("[ishrt][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x][req=%p]\n",
		     psmi_epaddr_get_name(mq->ep->epid),
		     psmi_epaddr_get_name(((psm2_epaddr_t) ipsaddr)->epid), ubuf,
		     len, tag->tag[0], tag->tag[1], tag->tag[2], req);
	} else if (len <= mq->hfi_thresh_rv) {
		if (len <= proto->iovec_thresh_eager) {
			/* use PIO transfer */
			psmi_assert((proto->flags & IPS_PROTO_FLAG_SDMA) == 0);
			flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
		} else {
			/* use SDMA transfer */
			psmi_assert((proto->flags & IPS_PROTO_FLAG_SPIO) == 0);
			flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA];
		}

		req->send_msgoff = 0;
		err = ips_ptl_mq_eager(proto, req, flow, tag, ubuf, len);
		if (err != PSM2_OK)
			return err;

		_HFI_VDBG
		    ("[ilong][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x][req=%p]\n",
		     psmi_epaddr_get_name(mq->ep->epid),
		     psmi_epaddr_get_name(((psm2_epaddr_t) ipsaddr)->epid), ubuf,
		     len, tag->tag[0], tag->tag[1], tag->tag[2], req);
	} else {		/* skip eager accounting below */
do_rendezvous:
		err = ips_ptl_mq_rndv(proto, req, ipsaddr, ubuf, len);
		*req_o = req;
		return err;
	}

	*req_o = req;
	mq->stats.tx_num++;
	mq->stats.tx_eager_num++;
	mq->stats.tx_eager_bytes += len;

	return err;
}

psm2_error_t
ips_proto_mq_send(psm2_mq_t mq, psm2_epaddr_t mepaddr, uint32_t flags,
		  psm2_mq_tag_t *tag, const void *ubuf, uint32_t len)
{
	psm2_error_t err = PSM2_OK;
	struct ips_proto *proto;
	struct ips_flow *flow;
	ips_epaddr_t *ipsaddr;
	ips_scb_t *scb;

	ipsaddr = ((ips_epaddr_t *) mepaddr)->msgctl->ipsaddr_next;
	ipsaddr->msgctl->ipsaddr_next = ipsaddr->next;
	proto = ((psm2_epaddr_t) ipsaddr)->proto;

#ifdef PSM_CUDA
	int gpu_mem;
	if (PSMI_IS_CUDA_ENABLED && PSMI_IS_CUDA_MEM((void*)ubuf)) {
		gpu_mem = 1;
		goto do_rendezvous;
	} else
		gpu_mem = 0;
#endif

	if (flags & PSM2_MQ_FLAG_SENDSYNC) {
		goto do_rendezvous;
	} else if (len <= mq->hfi_thresh_tiny) {
		flow = &ipsaddr->flows[proto->msgflowid];
		scb = mq_alloc_tiny(proto);
		psmi_assert(scb);
		ips_scb_opcode(scb) = OPCODE_TINY;
		scb->ips_lrh.khdr.kdeth0 =
		    ((len & HFI_KHDR_TINYLEN_MASK) << HFI_KHDR_TINYLEN_SHIFT) |
		    ipsaddr->msgctl->mq_send_seqnum++;
		ips_scb_copy_tag(scb->ips_lrh.tag, tag->tag);

		mq_copy_tiny((uint32_t *) &ips_scb_hdrdata(scb),
			     (uint32_t *) ubuf, len);
		err = ips_mq_send_envelope(proto, flow, scb, PSMI_TRUE);
		if (err != PSM2_OK)
			return err;

		_HFI_VDBG("[tiny][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x]\n",
			  psmi_epaddr_get_name(mq->ep->epid),
			  psmi_epaddr_get_name(((psm2_epaddr_t) ipsaddr)->epid),
			  ubuf, len, tag->tag[0], tag->tag[1], tag->tag[2]);
	} else if (len <= ipsaddr->flows[proto->msgflowid].frag_size) {
		uint32_t paylen = len & ~0x3;

		scb = mq_alloc_pkts(proto, 1, 0, 0);
		psmi_assert(scb);

		ips_scb_opcode(scb) = OPCODE_SHORT;
		scb->ips_lrh.khdr.kdeth0 = ipsaddr->msgctl->mq_send_seqnum++;
		ips_scb_hdrdata(scb).u32w1 = len;
		ips_scb_copy_tag(scb->ips_lrh.tag, tag->tag);

		ips_scb_buffer(scb) = (void *)ubuf;
		ips_scb_length(scb) = paylen;
		if (len > paylen) {
			/* there are nonDW bytes, copy to header */
			mq_copy_tiny((uint32_t *)&ips_scb_hdrdata(scb).u32w0,
				(uint32_t *)((uintptr_t)ubuf + paylen),
				len - paylen);
		}

		/*
		 * Need ack for send side completion because we
		 * send from user buffer.
		 */
		ips_scb_flags(scb) |= IPS_SEND_FLAG_ACKREQ;

		flow = &ipsaddr->flows[proto->msgflowid];
		err = ips_mq_send_envelope(proto, flow, scb, PSMI_TRUE);
		if (err != PSM2_OK)
			return err;

		/*
		 * It should be OK to check the buffer address in
		 * 'scb' to be changed, when this scb is done, the
		 * address is set to NULL when scb is put back to
		 * scb pool. Even if the same scb is re-used, it
		 * is not possible to set to this 'ubuf' address.
		 */
		if (ips_scb_buffer(scb) == (void *)ubuf) {
			if (flow->transfer != PSM_TRANSFER_PIO ||
			    paylen > proto->scb_bufsize ||
			    !ips_scbctrl_bufalloc(scb)) {
				/* sdma transfer (can't change user buffer),
				 * or, payload is larger than bounce buffer,
				 * or, can't allocate bounce buffer,
				 * send from user buffer till complete */
				PSMI_BLOCKUNTIL(mq->ep, err,
					ips_scb_buffer(scb) != (void*)ubuf);
				if (err > PSM2_OK_NO_PROGRESS)
					return err;
				err = PSM2_OK;
			} else {
				/* copy to bounce buffer */
				ips_shortcpy(ips_scb_buffer(scb),
					(void*)ubuf, paylen);
			}
		}
		_HFI_VDBG("[shrt][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x]\n",
			  psmi_epaddr_get_name(mq->ep->epid),
			  psmi_epaddr_get_name(((psm2_epaddr_t) ipsaddr)->epid),
			  ubuf, len, tag->tag[0], tag->tag[1], tag->tag[2]);
	} else if (len <= mq->hfi_thresh_rv) {
		psm2_mq_req_t req;

		if (len <= proto->iovec_thresh_eager_blocking) {
			/* use PIO transfer */
			psmi_assert((proto->flags & IPS_PROTO_FLAG_SDMA) == 0);
			flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
		} else {
			/* use SDMA transfer */
			psmi_assert((proto->flags & IPS_PROTO_FLAG_SPIO) == 0);
			flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA];
		}

		/* Block until we can get a req */
		PSMI_BLOCKUNTIL(mq->ep, err,
				(req =
				 psmi_mq_req_alloc(mq, MQE_TYPE_SEND)));
		if (err > PSM2_OK_NO_PROGRESS)
			return err;

		req->type |= MQE_TYPE_WAITING;
		req->send_msglen = len;
		req->tag = *tag;
		req->send_msgoff = 0;
		req->flags |= PSMI_REQ_FLAG_IS_INTERNAL;

		err = ips_ptl_mq_eager(proto, req, flow, tag, ubuf, len);
		if (err != PSM2_OK)
			return err;

		psmi_mq_wait_internal(&req);

		_HFI_VDBG("[long][%s->%s][b=%p][m=%d][t=%08x.%08x.%08x]\n",
			  psmi_epaddr_get_name(mq->ep->epid),
			  psmi_epaddr_get_name(((psm2_epaddr_t) ipsaddr)->epid),
			  ubuf, len, tag->tag[0], tag->tag[1], tag->tag[2]);
	} else {
		psm2_mq_req_t req;
do_rendezvous:
		/* Block until we can get a req */
		PSMI_BLOCKUNTIL(mq->ep, err,
				(req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND)));
		if (err > PSM2_OK_NO_PROGRESS)
			return err;

		req->type |= MQE_TYPE_WAITING;
		req->tag = *tag;
		req->flags |= PSMI_REQ_FLAG_IS_INTERNAL;

#ifdef PSM_CUDA
		/* CUDA documentation dictates the use of SYNC_MEMOPS attribute
		 * when the buffer pointer received into PSM has been allocated
		 * by the application. This guarantees the all memory operations
		 * to this region of memory (used by multiple layers of the stack)
		 * always synchronize
		 */
		if (gpu_mem) {
			int trueflag = 1;
			PSMI_CUDA_CALL(cuPointerSetAttribute, &trueflag,
				       CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
				      (CUdeviceptr)ubuf);
			req->is_buf_gpu_mem = 1;
		} else
			req->is_buf_gpu_mem = 0;
#endif

		err = ips_ptl_mq_rndv(proto, req, ipsaddr, ubuf, len);
		if (err != PSM2_OK)
			return err;
		psmi_mq_wait_internal(&req);
		return err;	/* skip accounting, done separately at completion time */
	}

	mq->stats.tx_num++;
	mq->stats.tx_eager_num++;
	mq->stats.tx_eager_bytes += len;

	return err;
}

static
psm2_error_t
ips_proto_mq_rts_match_callback(psm2_mq_req_t req, int was_posted)
{
	psm2_epaddr_t epaddr = req->rts_peer;
	struct ips_proto *proto = epaddr->proto;

	/* We have a match.
	 * We may already set with first packet,
	 * If we're doing eager-based r-v, just send back the sreq and length and
	 * have the sender complete the send.
	 */
	PSM2_LOG_MSG("entering");
#ifdef PSM_CUDA
	/* Cases where we do not use TIDs:
	 * 1) Recv on a host buffer, Send on a gpu buffer and len is less than 3 bytes
	 * 2) Recv on a host buffer, Send on a host buffer and len is less than hfi_thresh_rv
	 * 3) Recv on gpu buf and len is less than 3 bytes
	 * 4) Expected protocol not initialized.
	 */
	if ((!req->is_buf_gpu_mem && ((req->is_sendbuf_gpu_mem &&
	     req->recv_msglen <= GPUDIRECT_THRESH_RV)||
	    (!req->is_sendbuf_gpu_mem &&
	     req->recv_msglen <= proto->mq->hfi_thresh_rv))) ||
	    (req->is_buf_gpu_mem && req->recv_msglen <= GPUDIRECT_THRESH_RV) ||
	    proto->protoexp == NULL) {	/* no expected tid recieve */
#else
	if (req->recv_msglen <= proto->mq->hfi_thresh_rv ||/* less rv theshold */
	    proto->protoexp == NULL) {  /* no expected tid recieve */
#endif
		/* there is no order requirement, try to push CTS request
		 * directly, if fails, then queue it for later try. */
		if (ips_proto_mq_push_cts_req(proto, req) != PSM2_OK) {
			struct ips_pend_sends *pends = &proto->pend_sends;
			struct ips_pend_sreq *sreq =
			    psmi_mpool_get(proto->pend_sends_pool);
			psmi_assert(sreq != NULL);
			if (sreq == NULL)
			{
				PSM2_LOG_MSG("leaving");
				return PSM2_NO_MEMORY;
			}
			sreq->type = IPS_PENDSEND_EAGER_REQ;
			sreq->req = req;

			STAILQ_INSERT_TAIL(&pends->pendq, sreq, next);
			psmi_timer_request(proto->timerq, &pends->timer,
					   PSMI_TIMER_PRIO_1);
		}
	} else {
		ips_protoexp_tid_get_from_token(proto->protoexp, req->buf,
						req->recv_msglen, epaddr,
						req->rts_reqidx_peer,
						req->
						type & MQE_TYPE_WAITING_PEER ?
						IPS_PROTOEXP_TIDGET_PEERWAIT :
						0, ips_proto_mq_rv_complete_exp,
						req);
	}

	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}

psm2_error_t
ips_proto_mq_push_cts_req(struct ips_proto *proto, psm2_mq_req_t req)
{
	ips_epaddr_t *ipsaddr = (ips_epaddr_t *) (req->rts_peer);
	struct ips_flow *flow;
	ips_scb_t *scb;
	ptl_arg_t *args;

	PSM2_LOG_MSG("entering");
	psmi_assert(proto->msgflowid < EP_FLOW_LAST);
	flow = &ipsaddr->flows[proto->msgflowid];
	scb = ips_scbctrl_alloc(&proto->scbc_egr, 1, 0, 0);
	if (scb == NULL)
	{
		PSM2_LOG_MSG("leaving");
		return PSM2_OK_NO_PROGRESS;
	}

	args = (ptl_arg_t *) ips_scb_uwords(scb);

	ips_scb_opcode(scb) = OPCODE_LONG_CTS;
	scb->ips_lrh.khdr.kdeth0 = 0;
	args[0].u32w0 = psmi_mpool_get_obj_index(req);
	args[1].u32w1 = req->recv_msglen;
	args[1].u32w0 = req->rts_reqidx_peer;

	PSM_LOG_EPM(OPCODE_LONG_CTS,PSM_LOG_EPM_TX, proto->ep->epid,
		    flow->ipsaddr->epaddr.epid ,"req->rts_reqidx_peer: %d",
		    req->rts_reqidx_peer);

	ips_proto_flow_enqueue(flow, scb);
	flow->flush(flow, NULL);

	/* have already received enough bytes */
	if (req->recv_msgoff == req->recv_msglen) {
		ips_proto_mq_rv_complete(req);
	}

	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}

psm2_error_t
ips_proto_mq_push_rts_data(struct ips_proto *proto, psm2_mq_req_t req)
{
	psm2_error_t err = PSM2_OK;
	uintptr_t buf = (uintptr_t) req->buf + req->recv_msgoff;
	ips_epaddr_t *ipsaddr = (ips_epaddr_t *) (req->rts_peer);
	uint32_t nbytes_left = req->send_msglen - req->recv_msgoff;
	uint32_t nbytes_sent = 0;
	uint32_t nbytes_this, chunk_size;
	uint16_t frag_size, unaligned_bytes;
	struct ips_flow *flow;
	ips_scb_t *scb;

	psmi_assert(nbytes_left > 0);

	PSM2_LOG_MSG("entering.");
	if (
#ifdef PSM_CUDA
		req->is_buf_gpu_mem ||
#endif
		req->send_msglen > proto->iovec_thresh_eager) {
		/* use SDMA transfer */
		psmi_assert((proto->flags & IPS_PROTO_FLAG_SPIO) == 0);
		flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA];
		frag_size = flow->path->pr_mtu;
		/* max chunk size is the rv window size */
		chunk_size = proto->mq->hfi_window_rv;
	} else {
		/* use PIO transfer */
		psmi_assert((proto->flags & IPS_PROTO_FLAG_SDMA) == 0);
		flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
		chunk_size = frag_size = flow->frag_size;
	}

	do {
		/*
		 * don't try to call progression routine such as:
		 * ips_recv_progress_if_busy() in this loop,
		 * it will cause recursive call of this function.
		 */

		/*
		 * When tid code path is enabled, we don’t allocate scbc_rv
		 * objects. If the message is less than the hfi_thresh_rv,
		 * we normally use eager protocol to do the transfer.
		 * However, if it is sync send, we use the rendezvous
		 * rts/cts/rts-data protocol.
		 * In this case, because scbc_rv is null,
		 * we use scbc_egr instead.
		 */

		scb = ips_scbctrl_alloc(proto->scbc_rv ? proto->scbc_rv
					: &proto->scbc_egr, 1, 0, 0);
		if (scb == NULL) {
			err = PSM2_OK_NO_PROGRESS;
			break;
		}

		ips_scb_opcode(scb) = OPCODE_LONG_DATA;
		scb->ips_lrh.khdr.kdeth0 = 0;
		scb->ips_lrh.data[0].u32w0 = req->rts_reqidx_peer;
		scb->ips_lrh.data[1].u32w1 = req->send_msglen;

		/* attached unaligned bytes into packet header */
		unaligned_bytes = nbytes_left & 0x3;
		if (unaligned_bytes) {
			mq_copy_tiny((uint32_t *)&scb->ips_lrh.mdata,
				(uint32_t *)buf, unaligned_bytes);

			/* position to send */
			buf += unaligned_bytes;
			req->recv_msgoff += unaligned_bytes;
			psmi_assert(req->recv_msgoff < 4);

			/* for complete callback */
			req->send_msgoff += unaligned_bytes;

			nbytes_left -= unaligned_bytes;
			nbytes_sent += unaligned_bytes;
		}
		scb->ips_lrh.data[1].u32w0 = req->recv_msgoff;
		ips_scb_buffer(scb) = (void *)buf;

		scb->frag_size = frag_size;
		nbytes_this = min(chunk_size, nbytes_left);
		if (nbytes_this > 0)
			scb->nfrag = (nbytes_this + frag_size - 1) / frag_size;
		else
			scb->nfrag = 1;

		if (scb->nfrag > 1) {
			ips_scb_length(scb) = frag_size;
			scb->nfrag_remaining = scb->nfrag;
			scb->chunk_size =
				scb->chunk_size_remaining = nbytes_this;
		} else
			ips_scb_length(scb) = nbytes_this;

		buf += nbytes_this;
		req->recv_msgoff += nbytes_this;
		nbytes_sent += nbytes_this;
		nbytes_left -= nbytes_this;
		if (nbytes_left == 0) {
			/* because of scb callback, use eager complete */
			ips_scb_cb(scb) = ips_proto_mq_eager_complete;
			ips_scb_cb_param(scb) = req;

			/* Set ACKREQ if single packet per scb. For multi
			 * packets per scb, it is SDMA, driver will set
			 * ACKREQ in last packet, we only need ACK for
			 * last packet.
			 */
			if (scb->nfrag == 1)
				ips_scb_flags(scb) |= IPS_SEND_FLAG_ACKREQ;
		} else {
			req->send_msgoff += nbytes_this;
		}

		ips_proto_flow_enqueue(flow, scb);
		if (flow->transfer == PSM_TRANSFER_PIO) {
			/* we need to flush the pio pending queue as quick as possible */
			flow->flush(flow, NULL);
		}

	} while (nbytes_left);

	/* for sdma, if some bytes are queued, flush them */
	if (flow->transfer == PSM_TRANSFER_DMA && nbytes_sent) {
		flow->flush(flow, NULL);
	}

	PSM2_LOG_MSG("leaving.");

	return err;
}

int
ips_proto_mq_handle_cts(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	struct ips_proto *proto = rcv_ev->proto;
	psm2_mq_t mq = proto->ep->mq;
	struct ips_flow *flow;
	psm2_mq_req_t req;
	uint32_t paylen;

	/*
	 * if PSN does not match, drop the packet.
	 */
	PSM2_LOG_MSG("entering");
	if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event *)rcv_ev))
	{
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_CONTINUE;
	}
	req = psmi_mpool_find_obj_by_index(mq->sreq_pool, p_hdr->data[1].u32w0);
	psmi_assert(req != NULL);

	/*
	 * if there is payload, it is expected tid protocol
	 * with tid session info as the payload.
	 */
	paylen = ips_recvhdrq_event_paylen(rcv_ev);
	if (paylen > 0) {
		ips_tid_session_list *payload =
			ips_recvhdrq_event_payload(rcv_ev);
		psmi_assert(paylen == 0 || payload);
		PSM_LOG_EPM(OPCODE_LONG_CTS,PSM_LOG_EPM_RX,rcv_ev->ipsaddr->epaddr.epid,
			    mq->ep->epid,"p_hdr->data[1].u32w0 %d",
			    p_hdr->data[1].u32w0);
		proto->epaddr_stats.tids_grant_recv++;

		psmi_assert(p_hdr->data[1].u32w1 > mq->hfi_thresh_rv);
		psmi_assert(proto->protoexp != NULL);

		/* ptl_req_ptr will be set to each tidsendc */
		if (req->ptl_req_ptr == NULL) {
			req->send_msglen = p_hdr->data[1].u32w1;
		}
		psmi_assert(req->send_msglen == p_hdr->data[1].u32w1);

		if (ips_tid_send_handle_tidreq(proto->protoexp,
					       rcv_ev->ipsaddr, req, p_hdr->data[0],
					       p_hdr->mdata, payload, paylen) == 0)
			proto->psmi_logevent_tid_send_reqs.next_warning = 0;
	} else {
		req->rts_reqidx_peer = p_hdr->data[0].u32w0; /* eager receive only */
		req->send_msglen = p_hdr->data[1].u32w1;

		if (req->send_msgoff >= req->send_msglen) {
			/* already sent enough bytes, may truncate so using >= */
			ips_proto_mq_rv_complete(req);
		} else if (ips_proto_mq_push_rts_data(proto, req) != PSM2_OK) {
			/* there is no order requirement, tried to push RTS data
			 * directly and not done, so queue it for later try. */
			struct ips_pend_sreq *sreq =
				psmi_mpool_get(proto->pend_sends_pool);
			psmi_assert(sreq != NULL);

			sreq->type = IPS_PENDSEND_EAGER_DATA;
			sreq->req = req;
			STAILQ_INSERT_TAIL(&proto->pend_sends.pendq, sreq, next);
			/* Make sure it's processed by timer */
			psmi_timer_request(proto->timerq, &proto->pend_sends.timer,
					   PSMI_TIMER_PRIO_1);
		}
	}

	flow = &rcv_ev->ipsaddr->flows[ips_proto_flowid(p_hdr)];
	if ((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) ||
	    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq, flow);

	ips_proto_process_ack(rcv_ev);

	PSM2_LOG_MSG("leaving");
	return IPS_RECVHDRQ_CONTINUE;
}

int
ips_proto_mq_handle_rts(struct ips_recvhdrq_event *rcv_ev)
{
	int ret = IPS_RECVHDRQ_CONTINUE;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_flow *flow = &ipsaddr->flows[ips_proto_flowid(p_hdr)];
	psm2_mq_t mq = rcv_ev->proto->mq;
	ips_msgctl_t *msgctl = ipsaddr->msgctl;
	enum ips_msg_order msgorder;
	char *payload;
	uint32_t paylen;
	psm2_mq_req_t req;

	/*
	 * if PSN does not match, drop the packet.
	 */
	PSM2_LOG_MSG("entering");
	if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event *)rcv_ev))
	{
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_CONTINUE;
	}

	msgorder = ips_proto_check_msg_order(ipsaddr, flow,
		__le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK,
		&ipsaddr->msgctl->mq_recv_seqnum);
	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE))
	{
		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_REVISIT;
	}

	payload = ips_recvhdrq_event_payload(rcv_ev);
	paylen = ips_recvhdrq_event_paylen(rcv_ev);
	/* either no payload or whole message */
	psmi_assert(paylen == 0 || paylen >= p_hdr->data[1].u32w1);

	/*
	 * We can't have past message sequence here. For eager message,
	 * it must always have an eager queue matching because even in
	 * truncation case the code logic will wait till all packets
	 * have been received.
	 */
	psmi_assert(msgorder != IPS_MSG_ORDER_PAST);

	_HFI_VDBG("tag=%llx reqidx_peer=%d, msglen=%d\n",
		  (long long)p_hdr->data[0].u64,
		  p_hdr->data[1].u32w0, p_hdr->data[1].u32w1);

	int rc = psmi_mq_handle_rts(mq,
				    (psm2_epaddr_t) &ipsaddr->msgctl->
				    master_epaddr,
				    (psm2_mq_tag_t *) p_hdr->tag,
				    p_hdr->data[1].u32w1, payload, paylen,
				    msgorder, ips_proto_mq_rts_match_callback,
				    &req);
	if (unlikely(rc == MQ_RET_UNEXP_NO_RESOURCES)) {
		uint32_t psn_mask = ((psm2_epaddr_t)ipsaddr)->proto->psn_mask;

		flow->recv_seq_num.psn_num =
			(flow->recv_seq_num.psn_num - 1) & psn_mask;
		ipsaddr->msgctl->mq_recv_seqnum--;

		PSM2_LOG_MSG("leaving");
		return IPS_RECVHDRQ_REVISIT;
	}

	req->rts_peer = (psm2_epaddr_t) ipsaddr;
	req->rts_reqidx_peer = p_hdr->data[1].u32w0;
	if (req->send_msglen > mq->hfi_thresh_rv)
	{
		PSM_LOG_EPM(OPCODE_LONG_RTS,PSM_LOG_EPM_RX,req->rts_peer->epid,mq->ep->epid,
			    "req->rts_reqidx_peer: %d",req->rts_reqidx_peer);
	}
	if (p_hdr->flags & IPS_SEND_FLAG_BLOCKING)
		req->type |= MQE_TYPE_WAITING_PEER;

#ifdef PSM_CUDA
	if (p_hdr->flags & IPS_SEND_FLAG_GPU_BUF)
		req->is_sendbuf_gpu_mem = 1;
	else
		req->is_sendbuf_gpu_mem = 0;
#endif

	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE_RECV)) {
		/* for out of order matching only */
		req->msg_seqnum =
		    __le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK;
		req->ptl_req_ptr = (void *)msgctl;

		msgctl->outoforder_count++;
		mq_qq_append(&mq->outoforder_q, req);

		ret = IPS_RECVHDRQ_BREAK;
	} else {
		ipsaddr->msg_toggle = 0;

		if (rc == MQ_RET_MATCH_OK)
			ips_proto_mq_rts_match_callback(req, 1);

		/* XXX if blocking, break out of progress loop */

		if (msgctl->outoforder_count)
			ips_proto_mq_handle_outoforder_queue(mq, msgctl);

		if (rc == MQ_RET_UNEXP_OK)
			ret = IPS_RECVHDRQ_BREAK;
	}

	if ((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) ||
	    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq, flow);

	ips_proto_process_ack(rcv_ev);

	PSM2_LOG_MSG("leaving");
	return ret;
}

int
ips_proto_mq_handle_tiny(struct ips_recvhdrq_event *rcv_ev)
{
	int ret = IPS_RECVHDRQ_CONTINUE;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_flow *flow = &ipsaddr->flows[ips_proto_flowid(p_hdr)];
	psm2_mq_t mq = rcv_ev->proto->mq;
	ips_msgctl_t *msgctl = ipsaddr->msgctl;
	enum ips_msg_order msgorder;
	char *payload;
	uint32_t paylen;
	psm2_mq_req_t req;

	/*
	 * if PSN does not match, drop the packet.
	 */
	if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event *)rcv_ev))
		return IPS_RECVHDRQ_CONTINUE;

	msgorder = ips_proto_check_msg_order(ipsaddr, flow,
		__le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK,
		&ipsaddr->msgctl->mq_recv_seqnum);
	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE))
		return IPS_RECVHDRQ_REVISIT;

	payload = (void *)&p_hdr->hdr_data;
	paylen = (__le32_to_cpu(p_hdr->khdr.kdeth0) >>
		  HFI_KHDR_TINYLEN_SHIFT) & HFI_KHDR_TINYLEN_MASK;

	/*
	 * We can't have past message sequence here. For eager message,
	 * it must always have an eager queue matching because even in
	 * truncation case the code logic will wait till all packets
	 * have been received.
	 */
	psmi_assert(msgorder != IPS_MSG_ORDER_PAST);

	_HFI_VDBG("tag=%08x.%08x.%08x opcode=%d, msglen=%d\n",
		  p_hdr->tag[0], p_hdr->tag[1], p_hdr->tag[2],
		  OPCODE_TINY, p_hdr->hdr_data.u32w1);

	/* store in req below too! */
	int rc = psmi_mq_handle_envelope(mq,
				(psm2_epaddr_t) &ipsaddr->msgctl->master_epaddr,
				(psm2_mq_tag_t *) p_hdr->tag, paylen, 0,
				payload, paylen, msgorder, OPCODE_TINY, &req);
	if (unlikely(rc == MQ_RET_UNEXP_NO_RESOURCES)) {
		uint32_t psn_mask = ((psm2_epaddr_t)ipsaddr)->proto->psn_mask;

		flow->recv_seq_num.psn_num =
			(flow->recv_seq_num.psn_num - 1) & psn_mask;
		ipsaddr->msgctl->mq_recv_seqnum--;

		return IPS_RECVHDRQ_REVISIT;
	}

	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE_RECV)) {
		/* for out of order matching only */
		req->msg_seqnum =
		    __le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK;
		req->ptl_req_ptr = (void *)msgctl;

		msgctl->outoforder_count++;
		mq_qq_append(&mq->outoforder_q, req);

		ret = IPS_RECVHDRQ_BREAK;
	} else {
		ipsaddr->msg_toggle = 0;

		if (msgctl->outoforder_count)
			ips_proto_mq_handle_outoforder_queue(mq, msgctl);

		if (rc == MQ_RET_UNEXP_OK)
			ret = IPS_RECVHDRQ_BREAK;
	}

	if ((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) ||
	    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq, flow);

	ips_proto_process_ack(rcv_ev);

	return ret;
}

int
ips_proto_mq_handle_short(struct ips_recvhdrq_event *rcv_ev)
{
	int ret = IPS_RECVHDRQ_CONTINUE;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_flow *flow = &ipsaddr->flows[ips_proto_flowid(p_hdr)];
	psm2_mq_t mq = rcv_ev->proto->mq;
	ips_msgctl_t *msgctl = ipsaddr->msgctl;
	enum ips_msg_order msgorder;
	char *payload;
	uint32_t paylen;
	psm2_mq_req_t req;

	/*
	 * if PSN does not match, drop the packet.
	 */
	if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event *)rcv_ev))
		return IPS_RECVHDRQ_CONTINUE;

	msgorder = ips_proto_check_msg_order(ipsaddr, flow,
		__le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK,
		&ipsaddr->msgctl->mq_recv_seqnum);
	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE))
		return IPS_RECVHDRQ_REVISIT;

	payload = ips_recvhdrq_event_payload(rcv_ev);
	paylen = ips_recvhdrq_event_paylen(rcv_ev);
	psmi_assert(paylen == 0 || payload);

	/*
	 * We can't have past message sequence here. For eager message,
	 * it must always have an eager queue matching because even in
	 * truncation case the code logic will wait till all packets
	 * have been received.
	 */
	psmi_assert(msgorder != IPS_MSG_ORDER_PAST);

	_HFI_VDBG("tag=%08x.%08x.%08x opcode=%d, msglen=%d\n",
		  p_hdr->tag[0], p_hdr->tag[1], p_hdr->tag[2],
		  OPCODE_SHORT, p_hdr->hdr_data.u32w1);

	/* store in req below too! */
	int rc = psmi_mq_handle_envelope(mq,
				(psm2_epaddr_t) &ipsaddr->msgctl->master_epaddr,
				(psm2_mq_tag_t *) p_hdr->tag,
				p_hdr->hdr_data.u32w1, p_hdr->hdr_data.u32w0,
				payload, paylen, msgorder, OPCODE_SHORT, &req);
	if (unlikely(rc == MQ_RET_UNEXP_NO_RESOURCES)) {
		uint32_t psn_mask = ((psm2_epaddr_t)ipsaddr)->proto->psn_mask;

		flow->recv_seq_num.psn_num =
			(flow->recv_seq_num.psn_num - 1) & psn_mask;
		ipsaddr->msgctl->mq_recv_seqnum--;

		return IPS_RECVHDRQ_REVISIT;
	}

	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE_RECV)) {
		/* for out of order matching only */
		req->msg_seqnum =
		    __le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK;
		req->ptl_req_ptr = (void *)msgctl;

		msgctl->outoforder_count++;
		mq_qq_append(&mq->outoforder_q, req);

		ret = IPS_RECVHDRQ_BREAK;
	} else {
		ipsaddr->msg_toggle = 0;

		if (msgctl->outoforder_count)
			ips_proto_mq_handle_outoforder_queue(mq, msgctl);

		if (rc == MQ_RET_UNEXP_OK)
			ret = IPS_RECVHDRQ_BREAK;
	}

	if ((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) ||
	    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq, flow);

	ips_proto_process_ack(rcv_ev);

	return ret;
}

int
ips_proto_mq_handle_eager(struct ips_recvhdrq_event *rcv_ev)
{
	int ret = IPS_RECVHDRQ_CONTINUE;
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
	struct ips_flow *flow = &ipsaddr->flows[ips_proto_flowid(p_hdr)];
	psm2_mq_t mq = rcv_ev->proto->mq;
	ips_msgctl_t *msgctl = ipsaddr->msgctl;
	enum ips_msg_order msgorder;
	char *payload;
	uint32_t paylen;
	psm2_mq_req_t req;

	/*
	 * if PSN does not match, drop the packet.
	 */
	if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event *)rcv_ev))
		return IPS_RECVHDRQ_CONTINUE;

	msgorder = ips_proto_check_msg_order(ipsaddr, flow,
		__le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK,
		&ipsaddr->msgctl->mq_recv_seqnum);
	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE))
		return IPS_RECVHDRQ_REVISIT;

	payload = ips_recvhdrq_event_payload(rcv_ev);
	paylen = ips_recvhdrq_event_paylen(rcv_ev);
	psmi_assert(paylen == 0 || payload);

	if (msgorder == IPS_MSG_ORDER_PAST ||
			msgorder == IPS_MSG_ORDER_FUTURE_RECV) {
		req = mq_eager_match(mq, msgctl,
		    __le32_to_cpu(p_hdr->khdr.kdeth0)&HFI_KHDR_MSGSEQ_MASK);
		/*
		 * It is future message sequence or past message sequence,
		 * and there is request matching in eager queue, we handle
		 * the packet data and return. We can't go continue to
		 * match envelope.
		 * Past message sequence must always have a matching!!!
		 * error is caught below.
		 */
		if (req) {
			psmi_mq_handle_data(mq, req,
				p_hdr->data[1].u32w0, payload, paylen);

			if (msgorder == IPS_MSG_ORDER_FUTURE_RECV)
				ret = IPS_RECVHDRQ_BREAK;

			if ((__be32_to_cpu(p_hdr->bth[2]) &
			    IPS_SEND_FLAG_ACKREQ) ||
			    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
				ips_proto_send_ack((struct ips_recvhdrq *)
					rcv_ev->recvq, flow);

			ips_proto_process_ack(rcv_ev);

			return ret;
		}

		psmi_assert(msgorder == IPS_MSG_ORDER_FUTURE_RECV);
		/*
		 * For future message sequence, since there is no eager
		 * queue matching yet, this must be the first packet for
		 * the message sequence. And of course, expected message
		 * sequence is always the first packet for the sequence.
		 */
	}

	/*
	 * We can't have past message sequence here. For eager message,
	 * it must always have an eager queue matching because even in
	 * truncation case the code logic will wait till all packets
	 * have been received.
	 */
	psmi_assert(msgorder != IPS_MSG_ORDER_PAST);

	_HFI_VDBG("tag=%08x.%08x.%08x opcode=%d, msglen=%d\n",
		p_hdr->tag[0], p_hdr->tag[1], p_hdr->tag[2],
		OPCODE_EAGER, p_hdr->hdr_data.u32w1);

	/* store in req below too! */
	int rc = psmi_mq_handle_envelope(mq,
				(psm2_epaddr_t) &ipsaddr->msgctl->master_epaddr,
				(psm2_mq_tag_t *) p_hdr->tag,
				p_hdr->hdr_data.u32w1, p_hdr->hdr_data.u32w0,
				payload, paylen, msgorder, OPCODE_EAGER, &req);
	if (unlikely(rc == MQ_RET_UNEXP_NO_RESOURCES)) {
		uint32_t psn_mask = ((psm2_epaddr_t)ipsaddr)->proto->psn_mask;

		flow->recv_seq_num.psn_num =
			(flow->recv_seq_num.psn_num - 1) & psn_mask;
		ipsaddr->msgctl->mq_recv_seqnum--;

		return IPS_RECVHDRQ_REVISIT;
	}

	/* for both outoforder matching and eager matching */
	req->msg_seqnum =
		    __le32_to_cpu(p_hdr->khdr.kdeth0) & HFI_KHDR_MSGSEQ_MASK;
	req->ptl_req_ptr = (void *)msgctl;

	if (unlikely(msgorder == IPS_MSG_ORDER_FUTURE_RECV)) {
		msgctl->outoforder_count++;
		mq_qq_append(&mq->outoforder_q, req);

		ret = IPS_RECVHDRQ_BREAK;
	} else {
		ipsaddr->msg_toggle = 0;

		if (msgctl->outoforder_count)
			ips_proto_mq_handle_outoforder_queue(mq, msgctl);

		if (rc == MQ_RET_UNEXP_OK)
			ret = IPS_RECVHDRQ_BREAK;
	}

	if ((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) ||
	    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq, flow);

	ips_proto_process_ack(rcv_ev);

	return ret;
}

/*
 * Progress the out of order queue to see if any message matches
 * current receiving sequence number.
 */
void
ips_proto_mq_handle_outoforder_queue(psm2_mq_t mq, ips_msgctl_t *msgctl)
{
	psm2_mq_req_t req;

	do {
		req =
		    mq_ooo_match(&mq->outoforder_q, msgctl,
				 msgctl->mq_recv_seqnum);
		if (req == NULL)
			return;

		msgctl->outoforder_count--;
		msgctl->mq_recv_seqnum++;

		psmi_mq_handle_outoforder(mq, req);

	} while (msgctl->outoforder_count > 0);

	return;
}

int
ips_proto_mq_handle_data(struct ips_recvhdrq_event *rcv_ev)
{
	struct ips_message_header *p_hdr = rcv_ev->p_hdr;
	psm2_mq_t mq = rcv_ev->proto->mq;
	char *payload;
	uint32_t paylen;
	psm2_mq_req_t req;
	struct ips_flow *flow;

	/*
	 * if PSN does not match, drop the packet.
	 */
	if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event *)rcv_ev))
		return IPS_RECVHDRQ_CONTINUE;

	req = psmi_mpool_find_obj_by_index(mq->rreq_pool, p_hdr->data[0].u32w0);
	psmi_assert(req != NULL);
	psmi_assert(p_hdr->data[1].u32w1 == req->send_msglen);

	/*
	 * if a packet has very small offset, it must have unaligned data
	 * attached in the packet header, and this must be the first packet
	 * for that message.
	 */
	if (p_hdr->data[1].u32w0 < 4 && p_hdr->data[1].u32w0 > 0) {
		psmi_assert(p_hdr->data[1].u32w0 == (req->send_msglen&0x3));
		mq_copy_tiny((uint32_t *)req->buf,
				(uint32_t *)&p_hdr->mdata,
				p_hdr->data[1].u32w0);
		req->send_msgoff += p_hdr->data[1].u32w0;
	}

	payload = ips_recvhdrq_event_payload(rcv_ev);
	paylen = ips_recvhdrq_event_paylen(rcv_ev);
	psmi_assert(paylen == 0 || payload);

	psmi_mq_handle_data(mq, req, p_hdr->data[1].u32w0, payload, paylen);

	flow = &rcv_ev->ipsaddr->flows[ips_proto_flowid(p_hdr)];
	if ((__be32_to_cpu(p_hdr->bth[2]) & IPS_SEND_FLAG_ACKREQ) ||
	    (flow->flags & IPS_FLOW_FLAG_GEN_BECN))
		ips_proto_send_ack((struct ips_recvhdrq *)rcv_ev->recvq, flow);

	ips_proto_process_ack(rcv_ev);

	return IPS_RECVHDRQ_CONTINUE;
}
