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

#ifndef _IPS_PROTO_H
#define _IPS_PROTO_H

#include "psm_user.h"

#include "ips_recvhdrq.h"
#include "ips_tid.h"
#include "ips_scb.h"
#include "ips_epstate.h"
#include "ips_spio.h"
#include "ips_stats.h"
#include "ips_proto_am.h"
#include "ips_tidflow.h"
#include "ips_path_rec.h"

typedef enum ips_path_type {
	IPS_PATH_LOW_PRIORITY,
	IPS_PATH_NORMAL_PRIORITY,
	IPS_PATH_HIGH_PRIORITY,
	IPS_PATH_MAX_PRIORITY
} ips_path_type_t;

/*
 * Local Endpoint info.
 *
 * Contains information necessary for composing packets for the local endpoint
 */
struct ips_epinfo {
	uint16_t ep_base_lid;
	uint8_t ep_baseqp;
	uint8_t ep_lmc;
	opa_rate ep_link_rate;
	uint16_t ep_context;
	uint16_t ep_subcontext;
	uint16_t ep_hfi_type;
	uint16_t ep_sl;		/* HFI_SL only when path record not used */
	uint16_t ep_mtu;
	uint16_t ep_piosize;
	uint16_t ep_pkey;	/* PSM_PKEY only when path record not used */
	uint16_t ep_jkey;
	uint64_t ep_timeout_ack;	/* PSM_ERRCHK_TIMEOUT if no path record */
	uint64_t ep_timeout_ack_max;
	uint32_t ep_timeout_ack_factor;
};

/*
 * Remote Endpoint info.
 *
 * Contains information necessary for composing packets for a remote endpoint
 */
#define IPS_MAX_PATH_LMC 3
typedef struct ips_path_grp {
	/* For LMC/Torus keep list of base and max dlid. Used for pkt verification */
	uint16_t pg_base_lid;
	uint8_t pg_num_paths[IPS_PATH_MAX_PRIORITY];
	uint8_t pg_next_path[IPS_PATH_MAX_PRIORITY];
	ips_path_rec_t *pg_path[0][IPS_PATH_MAX_PRIORITY];
} ips_path_grp_t;

/*
 * Control messages.
 *
 * ips low-level control messages to ensure reliability of eager packets.
 *
 */
struct ips_proto;
psm_error_t ips_proto_init(const psmi_context_t *context, const struct ptl *ptl, int num_of_send_bufs, int num_of_send_desc, uint32_t imm_size, const struct psmi_timer_ctrl *timerq,	/* PTL's timerq */
			   const struct ips_epstate *epstate,	/* PTL's epstate */
			   const struct ips_spio *spioc,	/* PTL's spio control */
			   struct ips_proto *proto);	/* output protocol */

psm_error_t ips_proto_fini(struct ips_proto *proto, int force,
			   uint64_t timeout);

/*
 * Control message structures
 */
#define CTRL_MSG_QEUEUE_SIZE 64	/* power of two */

struct ips_ctrlq_elem {
	uint8_t message_type;
	uint16_t *msg_queue_mask;
	ips_scb_t msg_scb;
};

struct ips_ctrlq {
	/* Queued control messages, queued when pio is busy */
	struct ips_proto *ctrlq_proto;

	uint32_t ctrlq_head;
	uint32_t ctrlq_tail;
	uint32_t ctrlq_overflow;

	struct ips_ctrlq_elem ctrlq_cqe[CTRL_MSG_QEUEUE_SIZE] PSMI_CACHEALIGN;
	struct psmi_timer ctrlq_timer;	/* when in timerq */
};

/*
 * Connect/disconnect, as implemented by ips
 */
psm_error_t ips_proto_connect(struct ips_proto *proto, int numep,
			      const psm_epid_t *array_of_epid,
			      const int *array_of_epid_mask,
			      psm_error_t *array_of_errors,
			      psm_epaddr_t *array_of_epaddr,
			      uint64_t timeout_in);

psm_error_t ips_proto_disconnect(struct ips_proto *proto, int force, int numep,
				 const psm_epaddr_t array_of_epaddr[],
				 const int array_of_epaddr_mask[],
				 psm_error_t array_of_errors[],
				 uint64_t timeout_in);

int ips_proto_isconnected(struct ips_epaddr *ipsaddr);

/*
 * Pending operation structures
 */
struct ips_pend_sreq {
	STAILQ_ENTRY(ips_pend_sreq) next;
	psm_mq_req_t req;
	uint32_t type;
};

#define IPS_PENDSEND_EAGER_DATA	1
#define IPS_PENDSEND_EAGER_REQ	2
#define IPS_PENDSEND_EXP_TIDS	3
#define IPS_PENDSEND_EXP_SENDS	4

STAILQ_HEAD(ips_pendsendq, ips_pend_sreq);

struct ips_pend_sends {
	struct ips_proto *proto;	/* back ptr */
	struct psmi_timer timer;
	struct ips_pendsendq pendq;
};

/*
 * One instance of the protocol
 */

struct ips_protoexp;

struct ips_proto_stats {
	uint64_t pio_busy_cnt;
	uint64_t writev_busy_cnt;
	uint64_t writev_compl_eagain;
	uint64_t writev_compl_delay;
	uint64_t scb_egr_unavail_cnt;
	uint64_t scb_exp_unavail_cnt;
	uint64_t hdr_overflow;
	uint64_t egr_overflow;
	uint64_t lid_zero_errs;
	uint64_t unknown_packets;
	uint64_t stray_packets;
};

struct ips_proto_error_stats {
	uint64_t num_icrc_err;
	uint64_t num_ecc_err;
	uint64_t num_len_err;
	uint64_t num_tid_err;
	uint64_t num_dc_err;
	uint64_t num_dcunc_err;
	uint64_t num_khdrlen_err;
};

/*
 * Updates to these stats must be reflected in ips_ptl_epaddr_stats_init
 */
struct ips_proto_epaddr_stats {
	uint64_t err_chk_send;
	uint64_t err_chk_recv;
	uint64_t nak_send;
	uint64_t nak_recv;
	uint64_t connect_req;
	uint64_t disconnect_req;
	uint64_t tids_grant_send;
	uint64_t tids_grant_recv;
	uint64_t send_rexmit;
	uint64_t congestion_pkts;	/* IB CCA FECN packets */
};

/* OPP support structure. */
struct opp_api {
	void *(*op_path_find_hca) (const char *name, void **device);
	void *(*op_path_open) (void *device, int port_num);
	void (*op_path_close) (void *context);
	int (*op_path_get_path_by_rec) (void *context, ibta_path_rec_t *query,
					ibta_path_rec_t *response);
};

struct ips_ibta_compliance_fn {
	psm_error_t(*get_path_rec) (struct ips_proto *proto, uint16_t slid,
				    uint16_t dlid, uint16_t desthfi_type,
				    unsigned long timeout,
				    ips_path_grp_t **ppathgrp);
	psm_error_t(*fini) (struct ips_proto *proto);
};

/* please don't change the flow id order */
typedef enum ips_epaddr_flow {
	EP_FLOW_GO_BACK_N_PIO,
	EP_FLOW_GO_BACK_N_DMA,
	EP_FLOW_TIDFLOW,	/* Can either pio or dma for tidflow */
	EP_FLOW_LAST		/* Keep this the last endpoint flow */
} ips_epaddr_flow_t;

typedef enum psm_transfer_type {
	PSM_TRANSFER_PIO,
	PSM_TRANSFER_DMA,
	PSM_TRANSFER_LAST	/* Keep this the last transfer type */
} psm_transfer_type_t;

typedef enum psm_protocol_type {
	PSM_PROTOCOL_GO_BACK_N,
	PSM_PROTOCOL_TIDFLOW,
	PSM_PROTOCOL_LAST	/* Keep this the last protocol type */
} psm_protocol_type_t;

struct ips_proto {
	struct ptl *ptl;	/* cached */
	psm_ep_t ep;		/* cached, for errors */
	psm_mq_t mq;		/* cached, for mq handling */
	int fd;			/* cached, for writev ops */

	/* Pending sends */
	struct ips_pend_sends pend_sends;
	struct ips_epstate *epstate;
	struct psmi_timer_ctrl *timerq;

	struct ips_protoexp *protoexp;
	struct ips_scbctrl *scbc_rv;
	struct ips_spio *spioc;
	struct ips_scbctrl scbc_egr;
	struct ips_epinfo epinfo;

	ips_scb_t **sdma_scb_queue;
	struct hfi1_sdma_comp_entry *sdma_comp_queue;
	uint16_t sdma_queue_size;
	uint16_t sdma_fill_index;
	uint16_t sdma_done_index;
	uint16_t sdma_avail_counter;

	uint64_t timeout_send;
	uint32_t flags;
	uint32_t iovec_thresh_eager;
	uint32_t iovec_thresh_eager_blocking;
	uint32_t psn_mask;
	uint32_t scb_bufsize;
	uint16_t flow_credits;
	mpool_t pend_sends_pool;
	mpool_t timer_pool;
	struct ips_ibta_compliance_fn ibta;
	struct ips_proto_stats stats;
	struct ips_proto_error_stats error_stats;
	struct ips_proto_epaddr_stats epaddr_stats;

	struct ips_proto_am proto_am;

	struct ips_ctrlq ctrlq;
	/* pure sdma mode, use dma flow, otherwise, use pio flow */
	ips_epaddr_flow_t msgflowid;

	/* Handling tid errors */
	uint32_t tiderr_cnt;
	uint32_t tiderr_max;
	uint64_t tiderr_tnext;
	uint64_t tiderr_warn_interval;

	uint64_t t_init;
	uint64_t t_fini;
	uint32_t runid_key;

	int num_connected_to;
	int num_connected_from;
	int num_disconnect_requests;

	/* misc state variables. */

	/* Smallest interval in cycles between which we warn about stray
	 * messages This is a per-endpoint quantity, overridable with
	 * PSM_STRAY_WARN_INTERVAL We use the same interval to send the "die"
	 * message.
	 */
	uint64_t stray_warn_interval;
	int done_warning;
	int done_once;
	int num_bogus_warnings;
	struct {
		uint32_t interval_secs;
		uint64_t next_warning;
		uint64_t count;
	} psmi_logevent_tid_send_reqs;

	/* SL2SC and SC2VL table for protocol */
	uint16_t sl2sc[32];
	uint16_t sc2vl[32];

	/* CCA per port */
	uint16_t *cct;		/* cct table */
	uint16_t ccti_size;	/* ccti table size */
	uint16_t ccti_limit;	/* should be <= size-1 */

	uint16_t ccti_portctrl;	/* QP or SL CC */
	uint32_t ccti_ctrlmap;	/* map for valid sl */
	struct cace {		/* CACongestionEntry */
		uint8_t ccti_increase;	/* steps to increase */
		/* uint16_t  ccti_timer;*/ /* CCTI Timer in units of 1.024 usec */
		uint64_t ccti_timer_cycles; /* coverted from us_2_cycles() */
		uint8_t ccti_threshold;	/* threshod to make log */
		uint8_t ccti_min;	/* min value for ccti */
	} cace[32];		/* 32 service levels */

	/* Path record support */
	uint8_t ips_ipd_delay[IBV_RATE_300_GBPS + 1];
	struct hsearch_data ips_path_rec_hash;
	struct hsearch_data ips_path_grp_hash;
	void *opp_lib;
	void *hndl;
	void *device;
	void *opp_ctxt;
	struct opp_api opp_fn;

/*
 * Control message queue for pending messages.
 *
 * Control messages are queued as pending when no PIO is available for sending
 * the message.  They are composed on the fly and do not need buffering.
 *
 * Variables here are write once (at init) and read afterwards (except the msg
 * queue overflow counters).
 */
	uint32_t ctrl_msg_queue_overflow;
	uint32_t ctrl_msg_queue_enqueue;
	uint32_t message_type_to_index[256];
#define message_type2index(proto, msg_type) (proto->message_type_to_index[(msg_type)])

};

/*
 * Endpoint address, encapsulates per-endpoint protocol metadata
 *
 * Directly implements the ptl epaddr.
 */
typedef psm_error_t(*ips_flow_flush_fn_t) (struct ips_flow *, int *nflushed);

struct ips_flow {
	SLIST_ENTRY(ips_flow) next;	/* List of flows with pending acks */
	ips_flow_flush_fn_t flush;	/* flush function for this flow */

	struct ips_epaddr *ipsaddr;	/* back pointer, remote endpoint */
	ips_path_rec_t *path;	/* Path to use for flow */

	uint16_t flowid:2;	/* flow id: pio(0) or dma(1) or tidflow(2) */
	uint16_t transfer:3;	/* spio or sdma */
	uint16_t protocol:3;	/* go-back-n or tidflow */
	uint16_t flags:8;	/* flow state flags */

	uint16_t cca_ooo_pkts;	/* cca out of order packets */
	uint16_t cwin;		/* Size of congestion window */
	uint16_t ack_interval;	/* interval to ack packets */
	uint16_t ack_counter;	/* counter to ack packets */
	int16_t  credits;	/* Current credits available to send on flow */

	psmi_seqnum_t xmit_seq_num;	/* transmit packet sequence number */
	psmi_seqnum_t xmit_ack_num;	/* acked packet sequence number */
	psmi_seqnum_t recv_seq_num;	/* recieved packet sequence number */

	psmi_timer *timer_send;	/* timer for frames that got a busy PIO */
	psmi_timer *timer_ack;	/* timer for unacked frames */

	 STAILQ_HEAD(ips_scb_unackedq, ips_scb) scb_unacked;	/* unacked queue */
	 SLIST_HEAD(ips_scb_pendlist, ips_scb) scb_pend;	/* pending queue */

#ifdef PSM_DEBUG
	uint32_t scb_num_pending;	/* pending scb counter */
	uint32_t scb_num_unacked;	/* unacked scb counter */
#endif
};

#define IPS_FLOW_MSG_TOGGLE_OOO_MASK	(1 << 0)	/* ooo msg check */
#define IPS_FLOW_MSG_TOGGLE_UNEXP_MASK	(1 << 1)	/* unexp msg check */
/*
 * Make sure ips_epaddr_t and psm_epaddr_t can be converted each other.
 */
struct ips_epaddr {
	struct psm_epaddr epaddr;	/* inlined psm level epaddr */
	struct ips_msgctl *msgctl;	/* ips level msg control */

	struct ips_epaddr *next;	/* linklist */

	struct ips_flow flows[EP_FLOW_LAST - 1];	/* pio and dma */
	ips_path_grp_t *pathgrp;	/* pointer to slid/dlid group in hash */

	uint32_t connidx_to;	/* peer's connection idx */
	uint32_t connidx_from;	/* my connection idx */

	uint16_t ctrl_msg_queued;	/* bitmap of queued control messages to be send */
	uint16_t frag_size;	/* flow[proto->msgflowid] fragment size */

	uint8_t  hpp_index;	/* high priority index */
	uint8_t  context;	/* real context value */
	uint8_t  subcontext;	/* sub context, 3 bits, 5 bits for future */
	uint8_t  msg_toggle;	/* only 2 bits used, 6 bits for future */

	/* this portion is only for connect/disconnect */
	uint64_t s_timeout;	/* used as a time in close */
	uint32_t runid_key;	/* peer process pid */
	uint32_t credit:2;	/* credit to connect/disconnect: 0 or 1 */
	uint32_t cstate_to:3;	/* connection state to, max 7 */
	uint32_t cstate_from:3;	/* connection state from, max 7 */
	uint32_t delay_in_ms:8;	/* disconnect delay in ms */
	uint32_t cerror_to:8;	/* error code during connection */
	uint32_t cerror_from:8;	/* error code during connection */
};

/*
 * ips_msgctl_t is per connection struct.
 */
struct ips_msgctl {
	struct ips_epaddr master_epaddr; /* Master rail's epaddr */

	struct ips_epaddr *ipsaddr_next; /* next ipsaddr to send packet */
	uint16_t mq_send_seqnum;	 /* next sending message sequence */
	uint16_t mq_recv_seqnum;	 /* next receiving message sequence */
	uint16_t am_send_seqnum;	 /* next sending message sequence */
	uint16_t am_recv_seqnum;	 /* next receiving message sequence */
	uint16_t ipsaddr_count;		 /* number of ipsaddr to use */
	uint16_t outoforder_count;	 /* number of outoforder messages */
};

static inline __attribute__ ((unused))
void IPS_MCTXT_APPEND(ips_epaddr_t *head, ips_epaddr_t *node)
{
	ips_epaddr_t *cur;

	/* The new node is inserted before head. */
	node->next = head;

	/* Circle around the linked list to head's predecessor and update. */
	for (cur = head; cur->next != head; cur = cur->next);
	cur->next = node;
}

static inline __attribute__ ((unused))
void IPS_MCTXT_REMOVE(ips_epaddr_t *node)
{
	ips_epaddr_t *cur;

	/* Circle around to node's predecessor and update. */
	for (cur = node; cur->next != node; cur = cur->next);
	cur->next = node->next;
	node->next = node;
}

/*
 * Send support on scbs.
 *
 */
void ips_flow_init(struct ips_flow *flow, struct ips_proto *proto,
		   ips_epaddr_t *ipsaddr, psm_transfer_type_t transfer_type,
		   psm_protocol_type_t protocol, ips_path_type_t path_type,
		   uint32_t flow_index);

void ips_scb_prepare_flow(ips_scb_t *scb, ips_epaddr_t *ipsaddr,
			  struct ips_flow *flow);

void ips_proto_flow_enqueue(struct ips_flow *flow, ips_scb_t *scb);

psm_error_t ips_proto_flow_flush_pio(struct ips_flow *flow, int *nflushed);
psm_error_t ips_proto_flow_flush_dma(struct ips_flow *flow, int *nflushed);

/* Wrapper for enqueue + flush */
psm_error_t ips_proto_scb_pio_send(struct ips_flow *flow, ips_scb_t *scb);

void ips_proto_scb_dma_enqueue(struct ips_proto *proto, ips_scb_t *scb);
psm_error_t ips_proto_scb_dma_flush(struct ips_proto *proto,
				    ips_epaddr_t *ipsaddr, int *nflushed);
psm_error_t ips_proto_dma_wait_until(struct ips_proto *proto, ips_scb_t *scb);
psm_error_t ips_proto_dma_completion_update(struct ips_proto *proto);

psm_error_t ips_dma_transfer_frame(struct ips_proto *proto,
				   struct ips_flow *flow, ips_scb_t *scb,
				   void *payload, uint32_t paylen,
				   uint32_t have_cksum, uint32_t cksum);

/*
 * Protocol receive processing
 *
 */
/* Error handling for unknown packet, packet is unknown when epid doesn't match
 * in epstate table */
int ips_proto_process_unknown(const struct ips_recvhdrq_event *rcv_ev);
/* Exposed for fastpath only */
int ips_proto_process_ack(struct ips_recvhdrq_event *rcv_ev);
int ips_proto_process_nak(struct ips_recvhdrq_event *rcv_ev);
/* Handling error cases */
int ips_proto_process_packet_error(struct ips_recvhdrq_event *rcv_ev);

/*
 * Protocol exception handling and frame dumps
 */
void ips_proto_get_rhf_errstring(uint32_t err, char *msg, size_t len);
void ips_proto_dump_err_stats(struct ips_proto *proto);
void ips_proto_show_rhf_errors(const uint32_t *rhdr);
void ips_proto_show_header(struct ips_message_header *p_hdr, char *msg);
void ips_proto_dump_frame(void *frame, int lenght, char *message);
void ips_proto_dump_data(void *data, int data_length);
void ips_proto_dump_eager(uint32_t *curr_rcv_hdr);

/*
 * Checksum of ips packets
 */
uint32_t ips_crc_calculate(uint32_t len, uint8_t *data, uint32_t crc);

/*
 * Matched-Queue processing and sends
 */
psm_error_t ips_proto_mq_push_cts_req(struct ips_proto *proto,
				      psm_mq_req_t req);
psm_error_t ips_proto_mq_push_rts_data(struct ips_proto *proto,
				       psm_mq_req_t req);
int ips_proto_mq_handle_cts(struct ips_recvhdrq_event *rcv_ev);
int ips_proto_mq_handle_rts(struct ips_recvhdrq_event *rcv_ev);
int ips_proto_mq_handle_tiny(struct ips_recvhdrq_event *rcv_ev);
int ips_proto_mq_handle_short(struct ips_recvhdrq_event *rcv_ev);
int ips_proto_mq_handle_eager(struct ips_recvhdrq_event *rcv_ev);
void ips_proto_mq_handle_outoforder_queue(psm_mq_t mq, ips_msgctl_t *msgctl);
int ips_proto_mq_handle_data(struct ips_recvhdrq_event *rcv_ev);

psm_error_t ips_proto_mq_send(psm_mq_t mq, psm_epaddr_t epaddr,
			      uint32_t flags, psm_mq_tag_t *tag,
			      const void *ubuf, uint32_t len);

psm_error_t ips_proto_mq_isend(psm_mq_t mq, psm_epaddr_t epaddr,
			       uint32_t flags, psm_mq_tag_t *tag,
			       const void *ubuf, uint32_t len, void *context,
			       psm_mq_req_t *req_o);

int ips_proto_am(struct ips_recvhdrq_event *rcv_ev);

/*
 * IPS packet service routine table.
 */
typedef int (*ips_packet_service_fn_t)(struct ips_recvhdrq_event *rcv_ev);
extern ips_packet_service_fn_t
	ips_packet_service_routine[OPCODE_FUTURE_FROM-OPCODE_RESERVED];

/* IBTA feature related functions (path record, sl2sc2vl etc.) */
psm_error_t ips_ibta_init_sl2sc2vl_table(struct ips_proto *proto);
psm_error_t ips_ibta_link_updown_event(struct ips_proto *proto);
psm_error_t ips_ibta_init(struct ips_proto *proto);
psm_error_t ips_ibta_fini(struct ips_proto *proto);

#endif /* _IPS_PROTO_H */
