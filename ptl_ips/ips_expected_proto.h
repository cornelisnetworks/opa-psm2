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

/*
 * Control and state structure for one instance of the expected protocol.  The
 * protocol depends on some upcalls from internal portions of the receive
 * protocol (such as opcodes dedicated for expected protocol handling)
 */

/*
 * Expected tid operations are carried out over "sessions".  One session is a
 * collection of N tids where N is determined by the expected message window
 * size (-W option or PSM2_MQ_RNDV_HFI_WINDOW).  Since naks can cause
 * retransmissions, each session has an session index (_desc_idx) and a
 * generation count (_desc_genc) to be able to identify if retransmitted
 * packets reference the correct session.
 *
 * index and generation count are each 4 bytes encoded in one ptl_arg.  They
 * could be compressed further but we have the header space, so we don't
 * bother.
 */
#define _desc_idx   u32w0
#define _desc_genc  u32w1

/*
 * For debug and/or other reasons, we can log the state of each tid and
 * optionally associate it to a particular receive descriptor
 */

#define TIDSTATE_FREE	0
#define TIDSTATE_USED	1

struct ips_tidinfo {
	uint32_t tid;
	uint32_t state;
	struct ips_tid_recv_desc *tidrecvc;
};

/* Generate an expected header every 16 packets */
#define PSM_DEFAULT_EXPECTED_HEADER 16

struct ips_protoexp {
	const struct ptl *ptl;
	struct ips_proto *proto;
	struct psmi_timer_ctrl *timerq;
	struct ips_tid tidc;
	struct ips_tf tfc;

	psm_transfer_type_t ctrl_xfer_type;
	psm_transfer_type_t tid_xfer_type;
	struct ips_scbctrl tid_scbc_rv;
	mpool_t tid_desc_send_pool;
	mpool_t tid_getreq_pool;
	mpool_t tid_sreq_pool;	/* backptr into proto->ep->mq */
	mpool_t tid_rreq_pool;	/* backptr into proto->ep->mq */
	struct drand48_data tidflow_drand48_data;
	uint32_t tid_flags;
	uint32_t tid_send_fragsize;
	uint32_t tid_page_offset_mask;
	uint64_t tid_page_mask;
	uint32_t hdr_pkt_interval;
	struct ips_tidinfo *tid_info;

	 STAILQ_HEAD(ips_tid_send_pend,	/* pending exp. sends */
		     ips_tid_send_desc) pend_sendq;
	struct psmi_timer timer_send;

	 STAILQ_HEAD(ips_tid_get_pend, ips_tid_get_request) pend_getreqsq;	/* pending tid reqs */
	struct psmi_timer timer_getreqs;

#ifdef PSM_CUDA
	STAILQ_HEAD(ips_tid_get_cudapend, /* pending cuda transfers */
		    ips_tid_get_request) cudapend_getreqsq;
	struct ips_cuda_hostbuf_mpool_cb_context cuda_hostbuf_recv_cfg;
	struct ips_cuda_hostbuf_mpool_cb_context cuda_hostbuf_small_recv_cfg;
	mpool_t cuda_hostbuf_pool_recv;
	mpool_t cuda_hostbuf_pool_small_recv;
	cudaStream_t cudastream_recv;
#endif
};

/*
 * TID member list format used in communication.
 * Since the compiler does not make sure the bit fields order,
 * we use mask and shift defined below.
typedef struct {
	uint32_t length:11;	// in page unit, max 1024 pages
	uint32_t reserved:9;	// for future usage
	uint32_t tidctrl:2;	// hardware defined tidctrl value
	uint32_t tid:10;	// hardware only support 10bits
}
ips_tid_session_member;
 */
#define IPS_TIDINFO_LENGTH_SHIFT	0
#define IPS_TIDINFO_LENGTH_MASK		0x7ff
#define IPS_TIDINFO_TIDCTRL_SHIFT	20
#define IPS_TIDINFO_TIDCTRL_MASK	0x3
#define IPS_TIDINFO_TID_SHIFT		22
#define IPS_TIDINFO_TID_MASK		0x3ff

#define IPS_TIDINFO_GET_LENGTH(tidinfo)	\
	(((tidinfo)>>IPS_TIDINFO_LENGTH_SHIFT)&IPS_TIDINFO_LENGTH_MASK)
#define IPS_TIDINFO_GET_TIDCTRL(tidinfo) \
	(((tidinfo)>>IPS_TIDINFO_TIDCTRL_SHIFT)&IPS_TIDINFO_TIDCTRL_MASK)
#define IPS_TIDINFO_GET_TID(tidinfo) \
	(((tidinfo)>>IPS_TIDINFO_TID_SHIFT)&IPS_TIDINFO_TID_MASK)

typedef struct {
	uint8_t  tsess_unaligned_start;	/* unaligned bytes at starting */
	uint8_t  tsess_unaligned_end;	/* unaligned bytes at ending */
	uint16_t tsess_tidcount;	/* tid number for the session */
	uint32_t tsess_tidoffset;	/* offset in first tid */
	uint32_t tsess_srcoff;	/* source offset from beginning */
	uint32_t tsess_length;	/* session length, including start/end */

	uint32_t tsess_list[0];	/* must be last in struct */
} ips_tid_session_list;

/*
 * Send-side expected send descriptors.
 *
 * Descriptors are allocated when tid grant requests are received (the 'target'
 * side of an RDMA get request).  Descriptors are added to a pending queue of
 * expected sends and processed one at a time (scb's are requested and messages
 * sent until all fragments of the descriptor's length are put on the wire).
 *
 */
#define TIDSENDC_SDMA_VEC_DEFAULT	260

struct ips_tid_send_desc {
	struct ips_protoexp *protoexp;
	 STAILQ_ENTRY(ips_tid_send_desc) next;

	/* Filled in at allocation time */
	ptl_arg_t sdescid;	/* sender descid */
	ptl_arg_t rdescid;	/* reciever descid */
	ips_epaddr_t *ipsaddr;
	psm2_mq_req_t mqreq;

	/* tidflow to send tid traffic */
	struct ips_flow tidflow;

	/* Iterated during send progress */
	void *userbuf;		/* user privided buffer */
	void *buffer;
	uint32_t length;	/* total length, includint start/end */

	uint32_t tidbytes;	/* bytes sent over tid so far */
	uint32_t remaining_tidbytes;
	uint32_t offset_in_tid;	/* could be more than page */
	uint32_t remaining_bytes_in_tid;

	uint16_t frame_send;
	uint16_t tid_idx;
	uint16_t is_complete;
	uint16_t frag_size;
	/* bitmap of queued control messages for flow */
	uint16_t ctrl_msg_queued;

#ifdef PSM_CUDA
	/* As size of cuda_hostbuf is less than equal to window size,
	 * there is a guarantee that the maximum number of host bufs we
	 * would need to attach to a tidsendc would be 2
	 */
	struct ips_cuda_hostbuf *cuda_hostbuf[2];
	/* Number of hostbufs attached */
	uint8_t cuda_num_buf;
#endif
	/*
	 * tid_session_list is 24 bytes, plus 512 tidpair for 2048 bytes,
	 * so the max possible tid window size mq->hfi_window_rv is 4M.
	 * However, PSM must fit tid grant message into a single transfer
	 * unit, either PIO or SDMA, PSM will shrink the window accordingly.
	 */
	uint16_t tsess_tidlist_length;
	union {
		ips_tid_session_list tid_list;
		uint8_t filler[PSM_TIDLIST_BUFSIZE+
			sizeof(ips_tid_session_list)];
	};
};

#define TIDRECVC_STATE_FREE      0
#define TIDRECVC_STATE_BUSY      1

struct ips_expected_recv_stats {
	uint32_t nSeqErr;
	uint32_t nGenErr;
	uint32_t nReXmit;
	uint32_t nErrChkReceived;
};

struct ips_tid_recv_desc {
	const psmi_context_t *context;
	struct ips_protoexp *protoexp;

	ptl_arg_t rdescid;	/* reciever descid */
	ips_epaddr_t *ipsaddr;
	struct ips_tid_get_request *getreq;

	/* scb to send tid grant CTS */
	ips_scb_t *grantscb;
	/* scb to send tid data completion */
	ips_scb_t *completescb;

	/* tidflow to only send ctrl msg ACK and NAK */
	struct ips_flow tidflow;

	/* TF protocol state (recv) */
	uint32_t state;
	uint32_t tidflow_active_gen;
	uint32_t tidflow_nswap_gen;
	psmi_seqnum_t tidflow_genseq;

#ifdef PSM_CUDA
	struct ips_cuda_hostbuf *cuda_hostbuf;
	uint8_t is_ptr_gpu_backed;
#endif

	void *buffer;
	uint32_t recv_msglen;
	uint32_t recv_tidbytes;	/* exlcude start/end trim */

	struct ips_expected_recv_stats stats;

	/* bitmap of queued control messages for */
	uint16_t ctrl_msg_queued;
	/*
	 * tid_session_list is 24 bytes, plus 512 tidpair for 2048 bytes,
	 * so the max possible tid window size mq->hfi_window_rv is 4M.
	 * However, PSM must fit tid grant message into a single transfer
	 * unit, either PIO or SDMA, PSM will shrink the window accordingly.
	 */
	uint16_t tsess_tidlist_length;
	union {
		ips_tid_session_list tid_list;
		uint8_t filler[PSM_TIDLIST_BUFSIZE+
			sizeof(ips_tid_session_list)];
	};
};

/*
 * Get requests, issued by MQ when there's a match on a large message.  Unlike
 * an RDMA get, the initiator identifies the location of the data at the target
 * using a 'send token' instead of a virtual address.  This, of course, assumes
 * that the target has already registered the token and communicated it to the
 * initiator beforehand (it actually sends the token as part of the initial
 * MQ message that contains the MQ tag).
 *
 * The operation is semantically a two-sided RDMA get.
 */
typedef void (*ips_tid_completion_callback_t) (void *);

struct ips_tid_get_request {
	STAILQ_ENTRY(ips_tid_get_request) tidgr_next;
	struct ips_protoexp *tidgr_protoexp;
	psm2_epaddr_t tidgr_epaddr;

	void *tidgr_lbuf;
	uint32_t tidgr_length;
	uint32_t tidgr_rndv_winsz;
	uint32_t tidgr_sendtoken;
	ips_tid_completion_callback_t tidgr_callback;
	void *tidgr_ucontext;

	uint32_t tidgr_offset;	/* offset in bytes */
	uint32_t tidgr_bytesdone;
	uint32_t tidgr_flags;

#ifdef PSM_CUDA
	int cuda_hostbuf_used;
	uint32_t tidgr_cuda_bytesdone;
	STAILQ_HEAD(ips_tid_getreq_cuda_hostbuf_pend,	/* pending exp. sends */
		    ips_cuda_hostbuf) pend_cudabuf;
#endif
};

/*
 * Descriptor limits, structure contents of struct psmi_rlimit_mpool for
 * normal, min and large configurations.
 */
#define TID_SENDSESSIONS_LIMITS {				\
	    .env = "PSM2_TID_SENDSESSIONS_MAX",			\
	    .descr = "Tid max send session descriptors",	\
	    .env_level = PSMI_ENVVAR_LEVEL_HIDDEN,		\
	    .minval = 1,					\
	    .maxval = 1<<30,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = { 256,  8192 },	\
	    .mode[PSMI_MEMMODE_MINIMAL] = {   1,     1 },	\
	    .mode[PSMI_MEMMODE_LARGE]   = { 512, 16384 }	\
	}

/*
 * Expected send support
 */
/*
 * The expsend token is currently always a pointer to a MQ request.  It is
 * echoed on the wire throughout various phases of the expected send protocol
 * to identify a particular send.
 */
psm2_error_t
MOCKABLE(ips_protoexp_init)(const psmi_context_t *context,
			      const struct ips_proto *proto,
			      uint32_t protoexp_flags, int num_of_send_bufs,
			      int num_of_send_desc,
			      struct ips_protoexp **protoexp_o);
MOCK_DCL_EPILOGUE(ips_protoexp_init);

psm2_error_t ips_protoexp_fini(struct ips_protoexp *protoexp);
void ips_protoexp_handle_tiderr(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_handle_data_err(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_handle_tf_seqerr(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_handle_tf_generr(const struct ips_recvhdrq_event *rcv_ev);

int ips_protoexp_data(struct ips_recvhdrq_event *rcv_ev);
int ips_protoexp_recv_tid_completion(struct ips_recvhdrq_event *rcv_ev);

psm2_error_t ips_protoexp_flow_newgen(struct ips_tid_recv_desc *tidrecvc);

PSMI_ALWAYS_INLINE(
void ips_protoexp_unaligned_copy(uint8_t *dst, uint8_t *src, uint16_t len))
{
	while (len) {
		dst[len-1] = src[len-1];
		len--;
	}
}

/*
 * Peer is waiting (blocked) for this request
 */
#define IPS_PROTOEXP_TIDGET_WAIT	0x1
#define IPS_PROTOEXP_TIDGET_PEERWAIT	0x2
psm2_error_t ips_protoexp_tid_get_from_token(struct ips_protoexp *protoexp,
			    void *buf, uint32_t length,
			    psm2_epaddr_t epaddr,
			    uint32_t remote_tok, uint32_t flags,
			    ips_tid_completion_callback_t
			    callback, void *context);
psm2_error_t
ips_tid_send_handle_tidreq(struct ips_protoexp *protoexp,
			    ips_epaddr_t *ipsaddr, psm2_mq_req_t req,
			    ptl_arg_t rdescid, uint32_t tidflow_genseq,
			    ips_tid_session_list *tid_list,
			    uint32_t tid_list_size);
