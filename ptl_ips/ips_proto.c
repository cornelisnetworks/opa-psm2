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

/*
 * IPS - Interconnect Protocol Stack.
 */

#include <assert.h>
#include <sys/uio.h>		/* writev */
#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_proto_help.h"

/*
 * Control message types have their own flag to determine whether a message of
 * that type is queued or not.  These flags are kept in a state bitfield.
 */
#define CTRL_MSG_ACK_QUEUED                     0x0001
#define CTRL_MSG_NAK_QUEUED                     0x0002
#define CTRL_MSG_BECN_QUEUED                    0x0004
#define CTRL_MSG_ERR_CHK_QUEUED                 0x0008
#define CTRL_MSG_ERR_CHK_GEN_QUEUED             0x0010
#define CTRL_MSG_CONNECT_REQUEST_QUEUED		0x0020
#define CTRL_MSG_CONNECT_REPLY_QUEUED		0x0040
#define CTRL_MSG_DISCONNECT_REQUEST_QUEUED	0x0080
#define CTRL_MSG_DISCONNECT_REPLY_QUEUED	0x0100

static void ctrlq_init(struct ips_ctrlq *ctrlq, struct ips_proto *proto);
static psm2_error_t proto_sdma_init(struct ips_proto *proto,
				   const psmi_context_t *context);

psm2_error_t
ips_proto_init(const psmi_context_t *context, const ptl_t *ptl,
	       int num_of_send_bufs, int num_of_send_desc, uint32_t imm_size,
	       const struct psmi_timer_ctrl *timerq,
	       const struct ips_epstate *epstate,
	       const struct ips_spio *spioc, struct ips_proto *proto)
{
	const struct hfi1_ctxt_info *ctxt_info = &context->ctrl->ctxt_info;
	const struct hfi1_base_info *base_info = &context->ctrl->base_info;
	uint32_t protoexp_flags, cksum_sz;
	union psmi_envvar_val env_tid, env_cksum, env_mtu;
	psm2_error_t err = PSM2_OK;

	/*
	 * Checksum packets within PSM. Default is off.
	 * This is heavy weight and done in software so not recommended for
	 * production runs.
	 */

	psmi_getenv("PSM2_CHECKSUM",
		    "Enable checksum of messages (0 disables checksum)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		    (union psmi_envvar_val)0, &env_cksum);

	memset(proto, 0, sizeof(struct ips_proto));
	proto->ptl = (ptl_t *) ptl;
	proto->ep = context->ep;	/* cached */
	proto->mq = context->ep->mq;	/* cached */
	proto->fd = context->fd;	/* cached */
	proto->pend_sends.proto = proto;
	psmi_timer_entry_init(&proto->pend_sends.timer,
			      ips_proto_timer_pendq_callback,
			      &proto->pend_sends);
	STAILQ_INIT(&proto->pend_sends.pendq);
	proto->epstate = (struct ips_epstate *)epstate;
	proto->timerq = (struct psmi_timer_ctrl *)timerq;
	proto->spioc = (struct ips_spio *)spioc;

	proto->epinfo.ep_baseqp = base_info->bthqp;
	proto->epinfo.ep_context = ctxt_info->ctxt;	/* "real" context */
	proto->epinfo.ep_subcontext = ctxt_info->subctxt;
	proto->epinfo.ep_hfi_type = psmi_epid_hfi_type(context->epid);
	proto->epinfo.ep_jkey = base_info->jkey;

	/* If checksums enabled we insert checksum at end of packet */
	cksum_sz = env_cksum.e_uint ? PSM_CRC_SIZE_IN_BYTES : 0;
	proto->epinfo.ep_mtu = context->ep->mtu;
	/* Decrement checksum */
	proto->epinfo.ep_mtu -= cksum_sz;

	/* See if user specifies a lower MTU to use */
	if (!psmi_getenv
	    ("PSM_MTU", "MTU specified by user: 1-7,256-8192,10240]",
	     PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
	     (union psmi_envvar_val)-1, &env_mtu)) {
		if (env_mtu.e_int != 256 && env_mtu.e_int != 512
		    && env_mtu.e_int != 1024 && env_mtu.e_int != 2048
		    && env_mtu.e_int != 4096 && env_mtu.e_int != 8192
		    && env_mtu.e_int != 10240) {
			if (env_mtu.e_int < OPA_MTU_MIN ||
			    env_mtu.e_int > OPA_MTU_MAX)
				env_mtu.e_int = OPA_MTU_8192;
			env_mtu.e_int =
			    opa_mtu_enum_to_int((enum opa_mtu)env_mtu.e_int);
		}
		if (proto->epinfo.ep_mtu > env_mtu.e_int)
			proto->epinfo.ep_mtu = env_mtu.e_int;
	}

	/*
	 * The PIO size should not include the ICRC because it is
	 * stripped by HW before delivering to receiving buffer.
	 * We decide to use minimum 3 PIO buffers so that PSM has
	 * turn-around time to do PIO transfer. Each credit is a
	 * block of 64 bytes. Also PIO buffer size must not be
	 * bigger than MTU.
	 */
	proto->epinfo.ep_piosize = (ctxt_info->credits / 3) * 64 -
	    (sizeof(struct ips_message_header) + HFI_PCB_SIZE_IN_BYTES +
	     cksum_sz);
	proto->epinfo.ep_piosize =
	    min(proto->epinfo.ep_piosize, proto->epinfo.ep_mtu);

	/* Keep PIO as multiple of cache line size */
	if (proto->epinfo.ep_piosize > PSM_CACHE_LINE_BYTES)
		proto->epinfo.ep_piosize &= ~(PSM_CACHE_LINE_BYTES - 1);

	/* Save back to hfi level. */
	context->ctrl->__hfi_mtusize = proto->epinfo.ep_mtu;
	context->ctrl->__hfi_piosize = proto->epinfo.ep_piosize;

	/* sdma completion queue */
	proto->sdma_comp_queue =
	    (struct hfi1_sdma_comp_entry *) base_info->sdma_comp_bufbase;
	proto->sdma_queue_size = ctxt_info->sdma_ring_size;
	/* don't use the last slot */
	proto->sdma_avail_counter = proto->sdma_queue_size - 1;
	proto->sdma_fill_index = 0;
	proto->sdma_done_index = 0;
	proto->sdma_scb_queue = (struct ips_scb **)
		psmi_calloc(proto->ep, UNDEFINED,
		proto->sdma_queue_size, sizeof(struct ips_scb *));
	if (proto->sdma_scb_queue == NULL) {
		err = PSM2_NO_MEMORY;
		goto fail;
	}

	proto->timeout_send = us_2_cycles(IPS_PROTO_SPIO_RETRY_US_DEFAULT);
	proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking = ~0U;
	proto->scb_bufsize = PSMI_ALIGNUP(proto->epinfo.ep_mtu, PSMI_PAGESIZE),
	    proto->t_init = get_cycles();
	proto->t_fini = 0;
	proto->flags = env_cksum.e_uint ? IPS_PROTO_FLAG_CKSUM : 0;
	proto->runid_key = getpid();

	proto->num_connected_to = 0;
	proto->num_connected_from = 0;
	proto->num_disconnect_requests = 0;
	proto->stray_warn_interval = (uint64_t) -1;
	proto->done_warning = 0;
	proto->done_once = 0;
	proto->num_bogus_warnings = 0;
	proto->psmi_logevent_tid_send_reqs.interval_secs = 15;
	proto->psmi_logevent_tid_send_reqs.next_warning = 0;
	proto->psmi_logevent_tid_send_reqs.count = 0;

	/* Initialize IBTA related stuff (path record, SL2VL, CCA etc.) */
	if ((err = ips_ibta_init(proto)))
		goto fail;

	{
		/* User asks for HFI loopback? */
		union psmi_envvar_val env_loopback;

		psmi_getenv("PSM2_HFI_LOOPBACK",
			"PSM uses HFI loopback (default is disabled i.e. 0)",
			PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT_FLAGS,
			(union psmi_envvar_val)0, /* Disabled by default */
			&env_loopback);

		if (env_loopback.e_uint)
			proto->flags |= IPS_PROTO_FLAG_LOOPBACK;
	}

	{
		/* Disable coalesced ACKs? */
		union psmi_envvar_val env_coalesce_acks;

		psmi_getenv("PSM2_COALESCE_ACKS", "Coalesce ACKs on the wire (default is enabled i.e. 1)", PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT_FLAGS, (union psmi_envvar_val)1,	/* Enabled by default */
			    &env_coalesce_acks);

		if (env_coalesce_acks.e_uint)
			proto->flags |= IPS_PROTO_FLAG_COALESCE_ACKS;
	}

	{
		/* Number of credits per flow */
		union psmi_envvar_val env_flow_credits;
		int df_flow_credits = min(PSM_FLOW_CREDITS, num_of_send_desc);

		psmi_getenv("PSM2_FLOW_CREDITS",
			    "Number of unacked packets (credits) per flow (default is 64)",
			    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
			    (union psmi_envvar_val)df_flow_credits,
			    &env_flow_credits);
		proto->flow_credits = env_flow_credits.e_uint;
	}

	/*
	 * Pre-calculate the PSN mask to support 24 or 31 bits PSN.
	 */
	if ((context->runtime_flags & HFI1_CAP_EXTENDED_PSN)) {
		proto->psn_mask = 0x7FFFFFFF;
	} else {
		proto->psn_mask = 0xFFFFFF;
	}

	/*
	 * Initialize SDMA, otherwise, turn on all PIO.
	 */
	if ((context->runtime_flags & HFI1_CAP_SDMA)) {
		if ((err = proto_sdma_init(proto, context)))
			goto fail;
	} else {
		proto->flags |= IPS_PROTO_FLAG_SPIO;
		proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking =
		    ~0U;
	}

	/*
	 * Setup the protocol wide short message ep flow.
	 */
	if (proto->flags & IPS_PROTO_FLAG_SDMA) {
		proto->msgflowid = EP_FLOW_GO_BACK_N_DMA;
	} else {
		proto->msgflowid = EP_FLOW_GO_BACK_N_PIO;
	}

	/*
	 * Clone sendreq mpool configuration for pend sends config
	 */
	{
		uint32_t chunks, maxsz;

		psmi_assert_always(proto->ep->mq->sreq_pool != NULL);
		psmi_mpool_get_obj_info(proto->ep->mq->sreq_pool, &chunks,
					&maxsz);

		proto->pend_sends_pool =
		    psmi_mpool_create(sizeof(struct ips_pend_sreq), chunks,
				      maxsz, 0, DESCRIPTORS, NULL, NULL);
		if (proto->pend_sends_pool == NULL) {
			err = PSM2_NO_MEMORY;
			goto fail;
		}
	}

	/*
	 * Create a pool of timers for flow ack/send timer and path_rec timer.
	 * The default scb is num_of_send_desc=4K, we use max number of 4X
	 * of that to be sure we don't run out of timers.
	 */
	{
		uint32_t chunks, maxsz;

		chunks = 256;
		maxsz = 4 * num_of_send_desc;

		proto->timer_pool =
		    psmi_mpool_create(sizeof(struct psmi_timer), chunks, maxsz,
				      0, DESCRIPTORS, NULL, NULL);
		if (proto->timer_pool == NULL) {
			err = PSM2_NO_MEMORY;
			goto fail;
		}
	}

	/*
	 * Register ips protocol statistics
	 *
	 * We put a (*) in the output to denote stats that may cause a drop in
	 * performance.
	 *
	 * We put a (**) in the output of those stats that "should never happen"
	 */
	{
		struct psmi_stats_entry entries[] = {
			PSMI_STATS_DECLU64("pio busy count",
					   &proto->stats.pio_busy_cnt),
			/* Throttling by kernel */
			PSMI_STATS_DECLU64("writev busy cnt",
					   &proto->stats.writev_busy_cnt),
			/* When local dma completion is in the way... */
			PSMI_STATS_DECLU64("writev compl. eagain",
					   &proto->stats.writev_compl_eagain),
			/* When remote completion happens before local completion */
			PSMI_STATS_DECLU64("writev compl. delay (*)",
					   &proto->stats.writev_compl_delay),
			PSMI_STATS_DECLU64("scb unavail eager count",
					   &proto->stats.scb_egr_unavail_cnt),
			PSMI_STATS_DECLU64("scb unavail exp count",
					   &proto->stats.scb_exp_unavail_cnt),
			PSMI_STATS_DECLU64("rcvhdr overflows",	/* Normal egr/hdr ovflw */
					   &proto->stats.hdr_overflow),
			PSMI_STATS_DECLU64("rcveager overflows",
					   &proto->stats.egr_overflow),
			PSMI_STATS_DECLU64("lid zero errs (**)",	/* shouldn't happen */
					   &proto->stats.lid_zero_errs),
			PSMI_STATS_DECLU64("unknown packets (**)",	/* shouldn't happen */
					   &proto->stats.unknown_packets),
			PSMI_STATS_DECLU64("stray packets (*)",
					   &proto->stats.stray_packets),
			PSMI_STATS_DECLU64("pio stalls (*)",	/* shouldn't happen too often */
					   &proto->spioc->spio_num_stall_total),
			PSMI_STATS_DECLU64("ICRC error (*)",
					   &proto->error_stats.num_icrc_err),
			PSMI_STATS_DECLU64("ECC error ",
					   &proto->error_stats.num_ecc_err),
			PSMI_STATS_DECLU64("Len error",
					   &proto->error_stats.num_len_err),
			PSMI_STATS_DECLU64("TID error ",
					   &proto->error_stats.num_tid_err),
			PSMI_STATS_DECLU64("DC error ",
					   &proto->error_stats.num_dc_err),
			PSMI_STATS_DECLU64("DCUNC error ",
					   &proto->error_stats.num_dcunc_err),
			PSMI_STATS_DECLU64("KHDRLEN error ",
					   &proto->error_stats.num_khdrlen_err),

		};

		err =
		    psmi_stats_register_type
		    ("OPA low-level protocol stats",
		     PSMI_STATSTYPE_IPSPROTO, entries,
		     PSMI_STATS_HOWMANY(entries), NULL);
		if (err != PSM2_OK)
			goto fail;
	}

	/*
	 * Control Queue and messaging
	 */
	ctrlq_init(&proto->ctrlq, proto);

	/*
	 * Receive-side handling
	 */
	if ((err = ips_proto_recv_init(proto)))
		goto fail;

	/*
	 * Eager buffers.  We don't care to receive a callback when eager buffers
	 * are newly released since we actively poll for new bufs.
	 */
	if ((err = ips_scbctrl_init(context, num_of_send_desc,
				    num_of_send_bufs, imm_size,
				    proto->scb_bufsize, NULL, NULL,
				    &proto->scbc_egr)))
		goto fail;

	/*
	 * Expected protocol handling.
	 * If we enable tid-based expected rendezvous, the expected protocol code
	 * handles its own rv scb buffers.  If not, we have to enable eager-based
	 * rendezvous and we allocate scb buffers for it.
	 */
	psmi_getenv("PSM2_TID",
		    "Tid proto flags (0 disables protocol)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		    (union psmi_envvar_val)IPS_PROTOEXP_FLAGS_DEFAULT,
		    &env_tid);
	protoexp_flags = env_tid.e_uint;

	if (protoexp_flags & IPS_PROTOEXP_FLAG_ENABLED) {
		proto->scbc_rv = NULL;
		if ((err = ips_protoexp_init(context, proto, protoexp_flags,
					     num_of_send_bufs, num_of_send_desc,
					     &proto->protoexp)))
			goto fail;
	} else {
		proto->protoexp = NULL;
		proto->scbc_rv = (struct ips_scbctrl *)
		    psmi_calloc(proto->ep, DESCRIPTORS,
				1, sizeof(struct ips_scbctrl));
		if (proto->scbc_rv == NULL) {
			err = PSM2_NO_MEMORY;
			goto fail;
		}
		/*
		 * Rendezvous buffers. We want to get a callback for rendezvous bufs
		 * since we asynchronously try to make progress on these sends and only
		 * schedule them on the timerq if there are pending sends and available
		 * bufs.
		 */
		if ((err =
		     ips_scbctrl_init(context, num_of_send_desc,
				      0 /* no bufs */ ,
				      0, 0 /* bufsize==0 */ ,
				      ips_proto_rv_scbavail_callback,
				      proto, proto->scbc_rv)))
			goto fail;
	}

	/*
	 * Parse the tid error settings from the environment.
	 * <interval_secs>:<max_count_before_exit>
	 */
	{
		int tvals[2];
		char *tid_err;
		union psmi_envvar_val env_tiderr;

		tid_err = "-1:0";	/* no tiderr warnings, never exits */
		tvals[0] = -1;
		tvals[1] = 0;

		if (!psmi_getenv("PSM2_TID_ERROR",
				 "Tid error control <intval_secs:max_errors>",
				 PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
				 (union psmi_envvar_val)tid_err, &env_tiderr)) {
			/* not using default values */
			tid_err = env_tiderr.e_str;
			psmi_parse_str_tuples(tid_err, 2, tvals);
		}
		if (tvals[0] >= 0)
			proto->tiderr_warn_interval = sec_2_cycles(tvals[0]);
		else
			proto->tiderr_warn_interval = UINT64_MAX;
		proto->tiderr_max = tvals[1];
		_HFI_PRDBG("Tid error control: warning every %d secs%s, "
			   "fatal error after %d tid errors%s\n",
			   tvals[0], (tvals[0] < 0) ? " (no warnings)" : "",
			   tvals[1], (tvals[1] == 0) ? " (never fatal)" : "");
	}

	/*
	 * Active Message interface.  AM requests compete with MQ for eager
	 * buffers, since request establish the amount of buffering in the network
	 * (maximum number of requests in flight).  AM replies use the same amount
	 * of request buffers -- we can never run out of AM reply buffers because a
	 * request handler can only be run if we have at least one reply buffer (or
	 * else the AM request is dropped).
	 */
	if ((err = ips_proto_am_init(proto, num_of_send_bufs, num_of_send_desc,
				     imm_size, &proto->proto_am)))
		goto fail;

#if 0
	if (!host_pid) {
		char ipbuf[INET_ADDRSTRLEN], *p;
		host_pid = (uint32_t) getpid();
		host_ipv4addr = psmi_get_ipv4addr();	/* already be */
		if (host_ipv4addr == 0) {
			_HFI_DBG("Unable to obtain local IP address, "
				 "not fatal but some features may be disabled\n");
		} else if (host_ipv4addr == __cpu_to_be32(0x7f000001)) {
			_HFI_INFO("Localhost IP address is set to the "
				  "loopback address 127.0.0.1, "
				  "not fatal but some features may be disabled\n");
		} else {
			p = (char *)inet_ntop(AF_INET,
					      (const void *)&host_ipv4addr,
					      ipbuf, sizeof(ipbuf));
			_HFI_PRDBG("Ethernet Host IP=%s and PID=%d\n", p,
				   host_pid);
		}

		/* Store in big endian for use in ERR_CHK */
		host_pid = __cpu_to_be32(host_pid);
	}
#endif

fail:
	return err;
}

psm2_error_t
ips_proto_fini(struct ips_proto *proto, int force, uint64_t timeout_in)
{
	struct psmi_eptab_iterator itor;
	uint64_t t_start;
	uint64_t t_grace_start, t_grace_time, t_grace_finish, t_grace_interval;
	psm2_epaddr_t epaddr;
	psm2_error_t err = PSM2_OK;
	int i;
	union psmi_envvar_val grace_intval;

	psmi_getenv("PSM2_CLOSE_GRACE_PERIOD",
		    "Additional grace period in seconds for closing end-point.",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)0, &grace_intval);

	if (getenv("PSM2_CLOSE_GRACE_PERIOD")) {
		t_grace_time = grace_intval.e_uint * SEC_ULL;
	} else if (timeout_in > 0) {
		/* default to half of the close time-out */
		t_grace_time = timeout_in / 2;
	} else {
		/* propagate the infinite time-out case */
		t_grace_time = 0;
	}

	if (t_grace_time > 0 && t_grace_time < PSMI_MIN_EP_CLOSE_TIMEOUT)
		t_grace_time = PSMI_MIN_EP_CLOSE_TIMEOUT;

	/* At close we will busy wait for the grace interval to see if any
	 * receive progress is made. If progress is made we will wait for
	 * another grace interval, until either no progress is made or the
	 * entire grace period has passed. If the grace interval is too low
	 * we may miss traffic and exit too early. If the grace interval is
	 * too large the additional time spent while closing the program
	 * will become visible to the user. */
	psmi_getenv("PSM2_CLOSE_GRACE_INTERVAL",
		    "Grace interval in seconds for closing end-point.",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)0, &grace_intval);

	if (getenv("PSM2_CLOSE_GRACE_INTERVAL")) {
		t_grace_interval = grace_intval.e_uint * SEC_ULL;
	} else {
		/* A heuristic is used to scale up the timeout linearly with
		 * the number of endpoints, and we allow one second per 1000
		 * endpoints. */
		t_grace_interval = (proto->ep->connections * SEC_ULL) / 1000;
	}

	if (t_grace_interval < PSMI_MIN_EP_CLOSE_GRACE_INTERVAL)
		t_grace_interval = PSMI_MIN_EP_CLOSE_GRACE_INTERVAL;
	if (t_grace_interval > PSMI_MAX_EP_CLOSE_GRACE_INTERVAL)
		t_grace_interval = PSMI_MAX_EP_CLOSE_GRACE_INTERVAL;

	PSMI_PLOCK_ASSERT();

	t_start = proto->t_fini = get_cycles();

	/* Close whatever has been left open */
	if (proto->num_connected_to > 0) {
		int num_disc = 0;
		int *mask;
		psm2_error_t *errs;
		psm2_epaddr_t *epaddr_array;

		psmi_epid_itor_init(&itor, proto->ep);
		while ((epaddr = psmi_epid_itor_next(&itor))) {
			if (epaddr->ptlctl->ptl == proto->ptl)
				num_disc++;
		}
		psmi_epid_itor_fini(&itor);
		mask =
		    (int *)psmi_calloc(proto->ep, UNDEFINED, num_disc,
				       sizeof(int));
		errs = (psm2_error_t *)
		    psmi_calloc(proto->ep, UNDEFINED, num_disc,
				sizeof(psm2_error_t));
		epaddr_array = (psm2_epaddr_t *)
		    psmi_calloc(proto->ep, UNDEFINED, num_disc,
				sizeof(psm2_epaddr_t));

		if (errs == NULL || epaddr_array == NULL || mask == NULL) {
			if (epaddr_array)
				psmi_free(epaddr_array);
			if (errs)
				psmi_free(errs);
			if (mask)
				psmi_free(mask);
			err = PSM2_NO_MEMORY;
			goto fail;
		}
		psmi_epid_itor_init(&itor, proto->ep);
		i = 0;
		while ((epaddr = psmi_epid_itor_next(&itor))) {
			if (epaddr->ptlctl->ptl == proto->ptl) {
				mask[i] = 1;
				epaddr_array[i] = epaddr;
				i++;
				IPS_MCTXT_REMOVE((ips_epaddr_t *) epaddr);
			}
		}
		psmi_epid_itor_fini(&itor);
		err = ips_proto_disconnect(proto, force, num_disc, epaddr_array,
					   mask, errs, timeout_in);
		psmi_free(mask);
		psmi_free(errs);
		psmi_free(epaddr_array);
	}

	t_grace_start = get_cycles();

	while (psmi_cycles_left(t_grace_start, t_grace_time)) {
		uint64_t t_grace_interval_start = get_cycles();
		int num_disconnect_requests = proto->num_disconnect_requests;
		PSMI_BLOCKUNTIL(proto->ep, err,
				(proto->num_connected_from == 0 ||
				 !psmi_cycles_left(t_start, timeout_in)) &&
				(!psmi_cycles_left
				 (t_grace_interval_start, t_grace_interval)
				 || !psmi_cycles_left(t_grace_start,
						      t_grace_time)));
		if (num_disconnect_requests == proto->num_disconnect_requests) {
			/* nothing happened in this grace interval so break out early */
			break;
		}
	}

	t_grace_finish = get_cycles();

	_HFI_PRDBG
	    ("Closing endpoint disconnect left to=%d,from=%d after %d millisec of grace (out of %d)\n",
	     proto->num_connected_to, proto->num_connected_from,
	     (int)(cycles_to_nanosecs(t_grace_finish - t_grace_start) /
		   MSEC_ULL), (int)(t_grace_time / MSEC_ULL));

	if ((err = ips_ibta_fini(proto)))
		goto fail;

	if ((err = ips_proto_am_fini(&proto->proto_am)))
		goto fail;

	if ((err = ips_scbctrl_fini(&proto->scbc_egr)))
		goto fail;

	ips_proto_recv_fini(proto);

	if (proto->protoexp) {
		if ((err = ips_protoexp_fini(proto->protoexp)))
			goto fail;
	} else {
		ips_scbctrl_fini(proto->scbc_rv);
		psmi_free(proto->scbc_rv);
	}

	psmi_mpool_destroy(proto->pend_sends_pool);
	psmi_mpool_destroy(proto->timer_pool);

	psmi_free(proto->sdma_scb_queue);

fail:
	proto->t_fini = proto->t_init = 0;
	return err;
}

static
psm2_error_t
proto_sdma_init(struct ips_proto *proto, const psmi_context_t *context)
{
	union psmi_envvar_val env_sdma, env_hfiegr;
	psm2_error_t err = PSM2_OK;

	/*
	 * Only initialize if RUNTIME_SDMA is enabled.
	 */
	psmi_assert_always(context->runtime_flags & HFI1_CAP_SDMA);

	psmi_getenv("PSM2_SDMA",
		    "hfi send dma flags (0 disables send dma, 2 disables send pio, "
		    "1 for both sdma/spio, default 1)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		    (union psmi_envvar_val)1, &env_sdma);
	if (env_sdma.e_uint == 0)
		proto->flags |= IPS_PROTO_FLAG_SPIO;
	else if (env_sdma.e_uint == 2)
		proto->flags |= IPS_PROTO_FLAG_SDMA;

	if (!(proto->flags & (IPS_PROTO_FLAG_SDMA | IPS_PROTO_FLAG_SPIO))) {
		/* use both spio and sdma */
		proto->iovec_thresh_eager = MQ_HFI_THRESH_EGR_SDMA_SQ;
		proto->iovec_thresh_eager_blocking = MQ_HFI_THRESH_EGR_SDMA;

		if (!psmi_getenv("PSM2_MQ_EAGER_SDMA_SZ",
				 "hfi pio-to-sdma eager switchover",
				 PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
				 (union psmi_envvar_val)
				 MQ_HFI_THRESH_EGR_SDMA_SQ, &env_hfiegr)) {
			/* Has to be at least 1 MTU */
			proto->iovec_thresh_eager =
			    proto->iovec_thresh_eager_blocking =
			    max(proto->epinfo.ep_piosize, env_hfiegr.e_uint);
		}
	} else if (proto->flags & IPS_PROTO_FLAG_SDMA) {	/* all sdma */
		proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking =
		    0;
	} else if (proto->flags & IPS_PROTO_FLAG_SPIO) {	/* all spio */
		proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking =
		    ~0U;
	}

	return err;
}

static
void ctrlq_init(struct ips_ctrlq *ctrlq, struct ips_proto *proto)
{
	/* clear the ctrl send queue */
	memset(ctrlq, 0, sizeof(*ctrlq));

	proto->message_type_to_index[OPCODE_ACK] = CTRL_MSG_ACK_QUEUED;
	proto->message_type_to_index[OPCODE_NAK] = CTRL_MSG_NAK_QUEUED;
	proto->message_type_to_index[OPCODE_BECN] = CTRL_MSG_BECN_QUEUED;
	proto->message_type_to_index[OPCODE_ERR_CHK] = CTRL_MSG_ERR_CHK_QUEUED;
	proto->message_type_to_index[OPCODE_ERR_CHK_GEN] =
	    CTRL_MSG_ERR_CHK_GEN_QUEUED;
	proto->message_type_to_index[OPCODE_CONNECT_REQUEST] =
	    CTRL_MSG_CONNECT_REQUEST_QUEUED;
	proto->message_type_to_index[OPCODE_CONNECT_REPLY] =
	    CTRL_MSG_CONNECT_REPLY_QUEUED;
	proto->message_type_to_index[OPCODE_DISCONNECT_REQUEST] =
	    CTRL_MSG_DISCONNECT_REQUEST_QUEUED;
	proto->message_type_to_index[OPCODE_DISCONNECT_REPLY] =
	    CTRL_MSG_DISCONNECT_REPLY_QUEUED;

	ctrlq->ctrlq_head = ctrlq->ctrlq_tail = 0;
	ctrlq->ctrlq_overflow = 0;
	ctrlq->ctrlq_proto = proto;

	/*
	 * We never enqueue ctrl messages with real payload. If we do,
	 * the queue 'elem_payload' size needs to be big enough.
	 * Note: enqueue nak/ack is very important for performance.
	 */
	proto->ctrl_msg_queue_enqueue =
	    CTRL_MSG_ACK_QUEUED |
	    CTRL_MSG_NAK_QUEUED |
	    CTRL_MSG_BECN_QUEUED;

	psmi_timer_entry_init(&ctrlq->ctrlq_timer,
			      ips_proto_timer_ctrlq_callback, ctrlq);

	return;
}

static __inline__ void _build_ctrl_message(struct ips_proto *proto,
			struct ips_flow *flow, uint8_t message_type,
			ips_scb_t *ctrlscb, uint32_t paylen)
{
	uint32_t tot_paywords = (sizeof(struct ips_message_header) +
		HFI_CRC_SIZE_IN_BYTES + paylen) >> BYTE2DWORD_SHIFT;
	ips_epaddr_t *ipsaddr = flow->ipsaddr;
	struct ips_message_header *p_hdr = &ctrlscb->ips_lrh;
	ips_path_rec_t *ctrl_path =
	    ipsaddr->pathgrp->pg_path[ipsaddr->
				      hpp_index][IPS_PATH_HIGH_PRIORITY];

	if ((proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE) &&
	    (++ipsaddr->hpp_index >=
	     ipsaddr->pathgrp->pg_num_paths[IPS_PATH_HIGH_PRIORITY]))
		ipsaddr->hpp_index = 0;

	/* Control messages go over the control path. */
	p_hdr->lrh[0] = __cpu_to_be16(HFI_LRH_BTH |
				      ((ctrl_path->pr_sl & HFI_LRH_SL_MASK) <<
				       HFI_LRH_SL_SHIFT) |
				      ((proto->sl2sc[ctrl_path->pr_sl] &
					HFI_LRH_SC_MASK) << HFI_LRH_SC_SHIFT));
	p_hdr->lrh[1] = ctrl_path->pr_dlid;
	p_hdr->lrh[2] = __cpu_to_be16(tot_paywords & HFI_LRH_PKTLEN_MASK);
	p_hdr->lrh[3] = ctrl_path->pr_slid;

	p_hdr->bth[0] = __cpu_to_be32(ctrl_path->pr_pkey |
				      (message_type << HFI_BTH_OPCODE_SHIFT));

	/* If flow is congested then generate a BECN for path. */
	if_pf(flow->flags & IPS_FLOW_FLAG_GEN_BECN) {
		p_hdr->bth[1] = __cpu_to_be32(ipsaddr->context |
					      ipsaddr->
					      subcontext <<
					      HFI_BTH_SUBCTXT_SHIFT | flow->
					      flowid << HFI_BTH_FLOWID_SHIFT |
					      proto->epinfo.
					      ep_baseqp << HFI_BTH_QP_SHIFT | 1
					      << HFI_BTH_BECN_SHIFT);
		flow->flags &= ~IPS_FLOW_FLAG_GEN_BECN;
	}
	else {
		p_hdr->bth[1] = __cpu_to_be32(ipsaddr->context |
					      ipsaddr->
					      subcontext <<
					      HFI_BTH_SUBCTXT_SHIFT | flow->
					      flowid << HFI_BTH_FLOWID_SHIFT |
					      proto->epinfo.
					      ep_baseqp << HFI_BTH_QP_SHIFT);
	}

	/* p_hdr->bth[2] already set by caller, or don't care */
	/* p_hdr->ack_seq_num already set by caller, or don't care */

	p_hdr->connidx = ipsaddr->connidx_to;
	p_hdr->flags = 0;

	p_hdr->khdr.kdeth0 = __cpu_to_le32(
			(ctrlscb->flags & IPS_SEND_FLAG_INTR) |
			(IPS_PROTO_VERSION << HFI_KHDR_KVER_SHIFT));
	p_hdr->khdr.kdeth1 = __cpu_to_le32(proto->epinfo.ep_jkey);

	return;
}

psm2_error_t
ips_proto_timer_ctrlq_callback(struct psmi_timer *timer, uint64_t t_cyc_expire)
{
	struct ips_ctrlq *ctrlq = (struct ips_ctrlq *)timer->context;
	struct ips_proto *proto = ctrlq->ctrlq_proto;
	struct ips_ctrlq_elem *cqe;
	uint32_t have_cksum;
	psm2_error_t err;

	have_cksum = proto->flags & IPS_PROTO_FLAG_CKSUM;
	/* service ctrl send queue first */
	while (ctrlq->ctrlq_cqe[ctrlq->ctrlq_tail].msg_queue_mask) {
		cqe = &ctrlq->ctrlq_cqe[ctrlq->ctrlq_tail];

		if (cqe->msg_scb.flow->transfer == PSM_TRANSFER_PIO) {
			err = ips_spio_transfer_frame(proto,
				cqe->msg_scb.flow, &cqe->msg_scb.pbc,
				cqe->msg_scb.cksum, 0, PSMI_TRUE,
				have_cksum, cqe->msg_scb.cksum[0]);
		} else {
			err = ips_dma_transfer_frame(proto,
				cqe->msg_scb.flow, &cqe->msg_scb,
				cqe->msg_scb.cksum, 0,
				have_cksum, cqe->msg_scb.cksum[0]);
		}

		if (err == PSM2_OK) {
			ips_proto_epaddr_stats_set(proto, cqe->message_type);
			*cqe->msg_queue_mask &=
			    ~message_type2index(proto, cqe->message_type);
			cqe->msg_queue_mask = NULL;
			ctrlq->ctrlq_tail =
			    (ctrlq->ctrlq_tail + 1) % CTRL_MSG_QEUEUE_SIZE;
		} else {
			psmi_assert(err == PSM2_EP_NO_RESOURCES);

			if (proto->flags & IPS_PROTO_FLAG_SDMA)
				proto->stats.writev_busy_cnt++;
			else
				proto->stats.pio_busy_cnt++;
			/* re-request a timer expiration */
			psmi_timer_request(proto->timerq, &ctrlq->ctrlq_timer,
					   PSMI_TIMER_PRIO_0);
			return PSM2_OK;
		}
	}

	return PSM2_OK;
}

psm2_error_t
ips_proto_send_ctrl_message(struct ips_flow *flow, uint8_t message_type,
			uint16_t *msg_queue_mask, ips_scb_t *ctrlscb,
			void *payload, uint32_t paylen)
{
	psm2_error_t err = PSM2_EP_NO_RESOURCES;
	ips_epaddr_t *ipsaddr = flow->ipsaddr;
	struct ips_proto *proto = ((psm2_epaddr_t) ipsaddr)->proto;
	struct ips_ctrlq *ctrlq = &proto->ctrlq;
	struct ips_ctrlq_elem *cqe = ctrlq->ctrlq_cqe;
	uint32_t have_cksum;

	psmi_assert(message_type >= OPCODE_ACK &&
			message_type <= OPCODE_DISCONNECT_REPLY);
	psmi_assert((paylen & 0x3) == 0);	/* require 4-byte multiple */
	psmi_assert(flow->ipsaddr->frag_size >=
			(paylen + PSM_CRC_SIZE_IN_BYTES));

	/* Drain queue if non-empty */
	if (cqe[ctrlq->ctrlq_tail].msg_queue_mask)
		ips_proto_timer_ctrlq_callback(&ctrlq->ctrlq_timer, 0ULL);

	/* finish setup control message header */
	_build_ctrl_message(proto, flow, message_type, ctrlscb, paylen);

	/* If enabled checksum control message */
	have_cksum = proto->flags & IPS_PROTO_FLAG_CKSUM;
	if (have_cksum) {
		ctrlscb->ips_lrh.flags |= IPS_SEND_FLAG_PKTCKSUM;
		ips_do_cksum(proto, &ctrlscb->ips_lrh,
				payload, paylen, ctrlscb->cksum);
	}

	/*
	 * for ACK/NAK/BECN, we use the fast flow to send over, otherwise,
	 * we use the original flow
	 */
	if (message_type == OPCODE_ACK ||
	    message_type == OPCODE_NAK ||
	    message_type == OPCODE_BECN)
	{
		psmi_assert(proto->msgflowid < EP_FLOW_LAST);
		flow = &ipsaddr->flows[proto->msgflowid];
	}

	switch (flow->transfer) {
	case PSM_TRANSFER_PIO:
		err = ips_spio_transfer_frame(proto, flow,
			     &ctrlscb->pbc, payload, paylen,
			     PSMI_TRUE, have_cksum, ctrlscb->cksum[0]);
		break;
	case PSM_TRANSFER_DMA:
		err = ips_dma_transfer_frame(proto, flow,
			     ctrlscb, payload, paylen,
			     have_cksum, ctrlscb->cksum[0]);
		break;
	default:
		err = PSM2_INTERNAL_ERR;
		break;
	}

	if (err == PSM2_OK)
		ips_proto_epaddr_stats_set(proto, message_type);

	_HFI_VDBG("transfer_frame of opcode=0x%x,remote_lid=%d,"
		  "src=%p,len=%d returns %d\n",
		  (int)_get_proto_hfi_opcode(&ctrlscb->ips_lrh),
		  __be16_to_cpu(ctrlscb->ips_lrh.lrh[1]), payload, paylen, err);

	if (err != PSM2_EP_NO_RESOURCES)
		return err;
	if (proto->flags & IPS_PROTO_FLAG_SDMA)
		proto->stats.writev_busy_cnt++;
	else
		proto->stats.pio_busy_cnt++;

	if (proto->ctrl_msg_queue_enqueue & proto->
	    message_type_to_index[message_type]) {
		/* We only queue control msg without payload */
		psmi_assert(paylen == 0);

		if ((*msg_queue_mask) & proto->
		    message_type_to_index[message_type]) {
			/* This type of control message is already queued, skip it */
			err = PSM2_OK;
		} else if (cqe[ctrlq->ctrlq_head].msg_queue_mask == NULL) {
			/* entry is free */
			*msg_queue_mask |=
			    message_type2index(proto, message_type);

			cqe[ctrlq->ctrlq_head].message_type = message_type;
			cqe[ctrlq->ctrlq_head].msg_queue_mask = msg_queue_mask;
			psmi_mq_mtucpy(&cqe[ctrlq->ctrlq_head].msg_scb.ips_lrh,
					&ctrlscb->ips_lrh, sizeof(ctrlscb->ips_lrh));
			cqe[ctrlq->ctrlq_head].msg_scb.flow = flow;
			cqe[ctrlq->ctrlq_head].msg_scb.cksum[0] = ctrlscb->cksum[0];

			ctrlq->ctrlq_head =
			    (ctrlq->ctrlq_head + 1) % CTRL_MSG_QEUEUE_SIZE;
			/* _HFI_INFO("requesting ctrlq timer for msgtype=%d!\n", message_type); */
			psmi_timer_request(proto->timerq, &ctrlq->ctrlq_timer,
					   PSMI_TIMER_PRIO_0);

			err = PSM2_OK;
		} else {
			proto->ctrl_msg_queue_overflow++;
		}
	}

	return err;
}

void ips_proto_flow_enqueue(struct ips_flow *flow, ips_scb_t *scb)
{
	ips_epaddr_t *ipsaddr = flow->ipsaddr;
	struct ips_proto *proto = ((psm2_epaddr_t) ipsaddr)->proto;

	ips_scb_prepare_flow_inner(proto, ipsaddr, flow, scb);
	if ((proto->flags & IPS_PROTO_FLAG_CKSUM) &&
	    (scb->tidctrl == 0) && (scb->nfrag == 1)) {
		scb->ips_lrh.flags |= IPS_SEND_FLAG_PKTCKSUM;
		ips_do_cksum(proto, &scb->ips_lrh,
			     scb->payload, scb->payload_size, &scb->cksum[0]);
	}

	/* If this is the first scb on flow, pull in both timers. */
	if (STAILQ_EMPTY(&flow->scb_unacked)) {
		flow->timer_ack =
		    (struct psmi_timer *)psmi_mpool_get(proto->timer_pool);
		psmi_assert(flow->timer_ack != NULL);
		psmi_timer_entry_init(flow->timer_ack,
				      ips_proto_timer_ack_callback, flow);
		flow->timer_send =
		    (struct psmi_timer *)psmi_mpool_get(proto->timer_pool);
		psmi_assert(flow->timer_send != NULL);
		psmi_timer_entry_init(flow->timer_send,
				      ips_proto_timer_send_callback, flow);
	}

	/* Every flow has a pending head that points into the unacked queue.
	 * If sends are already pending, process those first */
	if (SLIST_EMPTY(&flow->scb_pend))
		SLIST_FIRST(&flow->scb_pend) = scb;

	/* Insert scb into flow's unacked queue */
	STAILQ_INSERT_TAIL(&flow->scb_unacked, scb, nextq);

#ifdef PSM_DEBUG
	/* update scb counters in flow. */
	flow->scb_num_pending++;
	flow->scb_num_unacked++;
#endif
}

/*
 * This function attempts to flush the current list of pending
 * packets through PIO.
 *
 * Recoverable errors:
 * PSM2_OK: Packet triggered through PIO.
 * PSM2_EP_NO_RESOURCES: No PIO bufs available or cable pulled.
 *
 * Unrecoverable errors:
 * PSM2_EP_NO_NETWORK: No network, no lid, ...
 * PSM2_EP_DEVICE_FAILURE: Chip failures, rxe/txe parity, etc.
 */
psm2_error_t
ips_proto_flow_flush_pio(struct ips_flow *flow, int *nflushed)
{
	struct ips_proto *proto = ((psm2_epaddr_t) (flow->ipsaddr))->proto;
	struct ips_scb_pendlist *scb_pend = &flow->scb_pend;
	int num_sent = 0;
	uint64_t t_cyc;
	ips_scb_t *scb;
	psm2_error_t err = PSM2_OK;

	/* Out of credits - ACKs/NAKs reclaim recredit or congested flow */
	if_pf((flow->credits <= 0) || (flow->flags & IPS_FLOW_FLAG_CONGESTED)) {
		if (nflushed)
			*nflushed = 0;
		return PSM2_EP_NO_RESOURCES;
	}

	while (!SLIST_EMPTY(scb_pend) && flow->credits > 0) {
		scb = SLIST_FIRST(scb_pend);
		psmi_assert(scb->nfrag == 1);

		if ((err = ips_spio_transfer_frame(proto, flow, &scb->pbc,
						   scb->payload,
						   scb->payload_size,
						   PSMI_FALSE,
						   scb->ips_lrh.
						   flags &
						   IPS_SEND_FLAG_PKTCKSUM,
						   scb->cksum[0])) == PSM2_OK) {
			t_cyc = get_cycles();
			scb->flags &= ~IPS_SEND_FLAG_PENDING;
			scb->ack_timeout = proto->epinfo.ep_timeout_ack;
			scb->abs_timeout = proto->epinfo.ep_timeout_ack + t_cyc;
			psmi_timer_request(proto->timerq, flow->timer_ack,
					   scb->abs_timeout);
			num_sent++;
			flow->credits--;
			SLIST_REMOVE_HEAD(scb_pend, next);
#ifdef PSM_DEBUG
			flow->scb_num_pending--;
#endif

		} else
			break;
	}

	/* If out of flow credits re-schedule send timer */
	if (!SLIST_EMPTY(scb_pend)) {
		proto->stats.pio_busy_cnt++;
		psmi_timer_request(proto->timerq, flow->timer_send,
				   get_cycles() + proto->timeout_send);
	}

	if (nflushed != NULL)
		*nflushed = num_sent;

	return err;
}

/*
 * Flush all packets currently marked as pending
 */
static psm2_error_t scb_dma_send(struct ips_proto *proto, struct ips_flow *flow,
				struct ips_scb_pendlist *slist, int *num_sent);

/*
 * Flush all packets queued up on a flow via send DMA.
 *
 * Recoverable errors:
 * PSM2_OK: Able to flush entire pending queue for DMA.
 * PSM2_OK_NO_PROGRESS: Flushed at least 1 but not all pending packets for DMA.
 * PSM2_EP_NO_RESOURCES: No scb's available to handle unaligned packets
 *                      or writev returned a recoverable error (no mem for
 *                      descriptors, dma interrupted or no space left in dma
 *                      queue).
 *
 * Unrecoverable errors:
 * PSM2_EP_DEVICE_FAILURE: Unexpected error calling writev(), chip failure,
 *			  rxe/txe parity error.
 * PSM2_EP_NO_NETWORK: No network, no lid, ...
 */
psm2_error_t
ips_proto_flow_flush_dma(struct ips_flow *flow, int *nflushed)
{
	struct ips_proto *proto = ((psm2_epaddr_t) (flow->ipsaddr))->proto;
	struct ips_scb_pendlist *scb_pend = &flow->scb_pend;
	ips_scb_t *scb = NULL;
	psm2_error_t err = PSM2_OK;
	int nsent = 0;

	/* Out of credits - ACKs/NAKs reclaim recredit or congested flow */
	if_pf((flow->credits <= 0) || (flow->flags & IPS_FLOW_FLAG_CONGESTED)) {
		if (nflushed)
			*nflushed = 0;
		return PSM2_EP_NO_RESOURCES;
	}

	if (SLIST_EMPTY(scb_pend))
		goto success;

	err = scb_dma_send(proto, flow, scb_pend, &nsent);
	if (err != PSM2_OK && err != PSM2_EP_NO_RESOURCES &&
	    err != PSM2_OK_NO_PROGRESS)
		goto fail;

	if (nsent > 0) {
		uint64_t t_cyc = get_cycles();
		int i = 0;
		/*
		 * inflight counter proto->iovec_cntr_next_inflight should not drift
		 * from completion counter proto->iovec_cntr_last_completed away too
		 * far because we only have very small scb counter compared with
		 * uint32_t counter value.
		 */
#ifdef PSM_DEBUG
		flow->scb_num_pending -= nsent;
#endif
		SLIST_FOREACH(scb, scb_pend, next) {
			if (++i > nsent)
				break;
			scb->flags &= ~IPS_SEND_FLAG_PENDING;
			scb->ack_timeout =
			    scb->nfrag * proto->epinfo.ep_timeout_ack;
			scb->abs_timeout =
			    scb->nfrag * proto->epinfo.ep_timeout_ack + t_cyc;

			psmi_assert(proto->sdma_scb_queue
					[proto->sdma_fill_index] == NULL);
			proto->sdma_scb_queue[proto->sdma_fill_index] = scb;
			scb->dma_complete = 0;

			proto->sdma_avail_counter--;
			proto->sdma_fill_index++;
			if (proto->sdma_fill_index == proto->sdma_queue_size)
				proto->sdma_fill_index = 0;

			/* Flow credits can temporarily go to negative for
			 * packets tracking purpose, because we have sdma
			 * chunk processing which can't send exact number
			 * of packets as the number of credits.
			 */
			flow->credits -= scb->nfrag;
		}
		SLIST_FIRST(scb_pend) = scb;
	}

	if (SLIST_FIRST(scb_pend) != NULL) {
		psmi_assert(flow->scb_num_pending > 0);

		switch (flow->protocol) {
		case PSM_PROTOCOL_TIDFLOW:
			/* For Tidflow we can cancel the ack timer if we have flow credits
			 * available and schedule the send timer. If we are out of flow
			 * credits then the ack timer is scheduled as we are waiting for
			 * an ACK to reclaim credits. This is required since multiple
			 * tidflows may be active concurrently.
			 */
			if (flow->credits > 0) {
				/* Cancel ack timer and reschedule send timer. Increment
				 * writev_busy_cnt as this really is DMA buffer exhaustion.
				 */
				psmi_timer_cancel(proto->timerq,
						  flow->timer_ack);
				psmi_timer_request(proto->timerq,
						   flow->timer_send,
						   get_cycles() +
						   (proto->timeout_send << 1));
				proto->stats.writev_busy_cnt++;
			} else {
				/* Re-instate ACK timer to reap flow credits */
				psmi_timer_request(proto->timerq,
						   flow->timer_ack,
						   get_cycles() +
						   (proto->epinfo.
						    ep_timeout_ack >> 2));
			}

			break;
		case PSM_PROTOCOL_GO_BACK_N:
		default:
			if (flow->credits > 0) {
				/* Schedule send timer and increment writev_busy_cnt */
				psmi_timer_request(proto->timerq,
						   flow->timer_send,
						   get_cycles() +
						   (proto->timeout_send << 1));
				proto->stats.writev_busy_cnt++;
			} else {
				/* Schedule ACK timer to reap flow credits */
				psmi_timer_request(proto->timerq,
						   flow->timer_ack,
						   get_cycles() +
						   (proto->epinfo.
						    ep_timeout_ack >> 2));
			}
			break;
		}
	} else {
		/* Schedule ack timer */
		psmi_timer_cancel(proto->timerq, flow->timer_send);
		psmi_timer_request(proto->timerq, flow->timer_ack,
				   get_cycles() + proto->epinfo.ep_timeout_ack);
	}

	/* We overwrite error with its new meaning for flushing packets */
	if (nsent > 0)
		if (scb)
			err = PSM2_OK_NO_PROGRESS;	/* partial flush */
		else
			err = PSM2_OK;	/* complete flush */
	else
		err = PSM2_EP_NO_RESOURCES;	/* no flush at all */

success:
fail:
	if (nflushed)
		*nflushed = nsent;

	return err;
}

/*
 * Fault injection in dma sends. Since DMA through writev() is all-or-nothing,
 * we don't inject faults on a packet-per-packet basis since the code gets
 * quite complex.  Instead, each call to flush_dma or transfer_frame is treated
 * as an "event" and faults are generated according to the IPS_FAULTINJ_DMASEND
 * setting.
 *
 * The effect is as if the event was successful but dropped on the wire
 * somewhere.
 */
PSMI_ALWAYS_INLINE(int dma_do_fault())
{

	if_pf(PSMI_FAULTINJ_ENABLED()) {
		PSMI_FAULTINJ_STATIC_DECL(fi, "dmalost", 1,
					  IPS_FAULTINJ_DMALOST);
		return psmi_faultinj_is_fault(fi);
	}
	else
	return 0;
}

/*
 * Driver defines the following sdma completion error code, returned
 * as negative value:
 * #define SDMA_TXREQ_S_OK        0
 * #define SDMA_TXREQ_S_SENDERROR 1
 * #define SDMA_TXREQ_S_ABORTED   2
 * #define SDMA_TXREQ_S_SHUTDOWN  3
 *
 * When hfi is in freeze mode, driver will complete all the pending
 * sdma request as aborted. Since PSM needs to recover from hfi
 * freeze mode, this routine ignore aborted error.
 */
psm2_error_t ips_proto_dma_completion_update(struct ips_proto *proto)
{
	ips_scb_t *scb;
	struct hfi1_sdma_comp_entry *comp;

	while (proto->sdma_done_index != proto->sdma_fill_index) {
		comp = &proto->sdma_comp_queue[proto->sdma_done_index];

		if (comp->status == QUEUED)
			return PSM2_OK;

		/* Mark sdma request is complete */
		scb = proto->sdma_scb_queue[proto->sdma_done_index];
		if (scb) {
			scb->dma_complete = 1;
			proto->sdma_scb_queue[proto->sdma_done_index] = NULL;
		}

		if (comp->status == ERROR && ((int)comp->errcode) != -2) {
			psm2_error_t err =
			   psmi_handle_error(proto->ep, PSM2_EP_DEVICE_FAILURE,
				"SDMA completion error: %d (fd=%d, index=%d)",
				0 - comp->errcode,
				proto->fd,
				proto->sdma_done_index);
			return err;
		}

		proto->sdma_avail_counter++;
		proto->sdma_done_index++;
		if (proto->sdma_done_index == proto->sdma_queue_size)
			proto->sdma_done_index = 0;
	}

	return PSM2_OK;
}

/* ips_dma_transfer_frame is used only for control messages, and is
 * not enabled by default, and not tested by QA; expected send
 * dma goes through scb_dma_send() */
psm2_error_t
ips_dma_transfer_frame(struct ips_proto *proto, struct ips_flow *flow,
		       ips_scb_t *scb, void *payload, uint32_t paylen,
		       uint32_t have_cksum, uint32_t cksum)
{
	ssize_t ret;
	psm2_error_t err;
	struct sdma_req_info *sdmahdr;
	uint16_t iovcnt;
	struct iovec iovec[2];

	/* See comments above for fault injection */
	if_pf(dma_do_fault())
	    return PSM2_OK;

	/*
	 * Check if there is a sdma queue slot.
	 */
	if (proto->sdma_avail_counter == 0) {
		err = ips_proto_dma_completion_update(proto);
		if (err)
			return err;

		if (proto->sdma_avail_counter == 0) {
			return PSM2_EP_NO_RESOURCES;
		}
	}

	/*
	 * If we have checksum, put to the end of payload. We make sure
	 * there is enough space in payload for us to put 8 bytes checksum.
	 * for control message, payload is internal PSM buffer, not user buffer.
	 */
	if (have_cksum) {
		uint32_t *ckptr = (uint32_t *) ((char *)payload + paylen);
		*ckptr = cksum;
		ckptr++;
		*ckptr = cksum;
		paylen += PSM_CRC_SIZE_IN_BYTES;
	}

	/*
	 * Setup PBC.
	 */
	ips_proto_pbc_update(proto, flow, PSMI_TRUE,
			     &scb->pbc, HFI_MESSAGE_HDR_SIZE, paylen);

	/*
	 * Setup SDMA header and io vector.
	 */
	sdmahdr = psmi_get_sdma_req_info(scb);
	sdmahdr->npkts = 1;
	sdmahdr->fragsize = flow->ipsaddr->frag_size;

	sdmahdr->comp_idx = proto->sdma_fill_index;
	psmi_assert(proto->sdma_comp_queue
		[proto->sdma_fill_index].status != QUEUED);

	iovcnt = 1;
	iovec[0].iov_base = sdmahdr;
	iovec[0].iov_len = HFI_SDMA_HDR_SIZE;
	if (paylen > 0) {
		iovcnt++;
		iovec[1].iov_base = payload;
		iovec[1].iov_len = paylen;
	}
	sdmahdr->ctrl = 1 |
	    (EAGER << HFI1_SDMA_REQ_OPCODE_SHIFT) |
	    (iovcnt << HFI1_SDMA_REQ_IOVCNT_SHIFT);

	/*
	 * Write into driver to do SDMA work.
	 */
	ret = hfi_cmd_writev(proto->fd, iovec, iovcnt);

	if (ret > 0) {
		psmi_assert_always(ret == 1);

		proto->sdma_avail_counter--;
		proto->sdma_fill_index++;
		if (proto->sdma_fill_index == proto->sdma_queue_size)
			proto->sdma_fill_index = 0;

		/*
		 * Wait for completion of this control message if
		 * stack buffer payload is used. This should not be
		 * a performance issue because sdma control message
		 * is not a performance code path.
		 */
		if (iovcnt > 1) {
			/* Setup scb ready for completion. */
			psmi_assert(proto->sdma_scb_queue
					[sdmahdr->comp_idx] == NULL);
			proto->sdma_scb_queue[sdmahdr->comp_idx] = scb;
			scb->dma_complete = 0;

			/* Wait for completion */
			err = ips_proto_dma_wait_until(proto, scb);
		} else
			err = PSM2_OK;
	} else {
		/*
		 * ret == 0: Driver did not queue packet. Try later.
		 * ENOMEM: No kernel memory to queue request, try later? *
		 * ECOMM: Link may have gone down
		 * EINTR: Got interrupt while in writev
		 */
		if (ret == 0 || errno == ENOMEM || errno == ECOMM
		    || errno == EINTR)
			err = PSM2_EP_NO_RESOURCES;
		else
			err =
			    psmi_handle_error(proto->ep, PSM2_EP_DEVICE_FAILURE,
					      "Unhandled error in writev(): %s (fd=%d,iovec=%p,len=%d)",
					      strerror(errno), proto->fd,
					      &iovec, 1);
	}

	return err;
}

/*
 * Caller still expects num_sent to always be correctly set in case of an
 * error.
 *
 * Recoverable errors:
 * PSM2_OK: At least one packet was successfully queued up for DMA.
 * PSM2_EP_NO_RESOURCES: No scb's available to handle unaligned packets
 *                      or writev returned a recoverable error (no mem for
 *                      descriptors, dma interrupted or no space left in dma
 *                      queue).
 * PSM2_OK_NO_PROGRESS: Cable pulled.
 *
 * Unrecoverable errors:
 * PSM2_EP_DEVICE_FAILURE: Error calling hfi_sdma_inflight() or unexpected
 *                        error in calling writev(), or chip failure, rxe/txe
 *                        parity error.
 * PSM2_EP_NO_NETWORK: No network, no lid, ...
 */
static
psm2_error_t
scb_dma_send(struct ips_proto *proto, struct ips_flow *flow,
	     struct ips_scb_pendlist *slist, int *num_sent)
{
	psm2_error_t err = PSM2_OK;
	struct sdma_req_info *sdmahdr;
	struct ips_scb *scb;
	struct iovec *iovec;
	uint16_t iovcnt;

	unsigned int vec_idx = 0;
	unsigned int scb_idx = 0, scb_sent = 0;
	unsigned int num=0, max_elem;
	uint32_t have_cksum;
	uint32_t fillidx;
	int16_t credits;
	ssize_t ret;

	/* See comments above for fault injection */
	if_pf(dma_do_fault())
	    goto fail;

	/* Check how many SCBs to send based on flow credits */
	credits = flow->credits;
	psmi_assert(SLIST_FIRST(slist) != NULL);
	SLIST_FOREACH(scb, slist, next) {
		num++;
		credits -= scb->nfrag;
		if (credits <= 0)
			break;
	}
	if (proto->sdma_avail_counter < num) {
		/* if there is not enough sdma slot,
		 * update and use what we have.
		 */
		err = ips_proto_dma_completion_update(proto);
		if (err)
			goto fail;
		if (proto->sdma_avail_counter == 0) {
			err = PSM2_EP_NO_RESOURCES;
			goto fail;
		}
		if (proto->sdma_avail_counter < num)
			num = proto->sdma_avail_counter;
	}

	/* header, payload, checksum, tidarray */
	max_elem = 4 * num;
	iovec = alloca(sizeof(struct iovec) * max_elem);

	if_pf(iovec == NULL) {
		err = psmi_handle_error(PSMI_EP_NORETURN, PSM2_NO_MEMORY,
					"alloca for %d bytes failed in writev",
					(int)(sizeof(struct iovec) * max_elem));
		goto fail;
	}

	fillidx = proto->sdma_fill_index;
	SLIST_FOREACH(scb, slist, next) {
		/* Can't exceed posix max writev count */
		if (vec_idx + (int)!!(scb->payload_size > 0) >= UIO_MAXIOV)
			break;

		psmi_assert(vec_idx < max_elem);
		psmi_assert_always((scb->payload_size & 0x3) == 0);

		/* Checksum all eager packets */
		have_cksum = scb->ips_lrh.flags & IPS_SEND_FLAG_PKTCKSUM;

		/*
		 * Setup PBC.
		 */
		ips_proto_pbc_update(proto, flow, PSMI_FALSE,
				     &scb->pbc, HFI_MESSAGE_HDR_SIZE,
				     scb->payload_size +
				     (have_cksum ? PSM_CRC_SIZE_IN_BYTES : 0));

		sdmahdr = psmi_get_sdma_req_info(scb);
		sdmahdr->npkts = scb->nfrag > 1 ?
			scb->nfrag_remaining : scb->nfrag;
		sdmahdr->fragsize = scb->frag_size ?
			scb->frag_size : flow->ipsaddr->frag_size;

		sdmahdr->comp_idx = fillidx;
		psmi_assert(proto->sdma_comp_queue[fillidx].status != QUEUED);
		fillidx++;
		if (fillidx == proto->sdma_queue_size)
			fillidx = 0;

		/*
		 * Setup io vector.
		 */
		iovec[vec_idx].iov_base = sdmahdr;
		iovec[vec_idx].iov_len = HFI_SDMA_HDR_SIZE;
		vec_idx++;
		iovcnt = 1;
		_HFI_VDBG("hdr=%p,%d\n",
			  iovec[vec_idx - 1].iov_base,
			  (int)iovec[vec_idx - 1].iov_len);

		if (scb->payload_size > 0) {
			/*
			 * OPA1 supports byte-aligned payload. If it is
			 * single packet per scb, use payload_size, else
			 * multi-packets per scb, use remaining chunk_size.
			 * payload_size is the remaining chunk first packet
			 * length.
			 */
			iovec[vec_idx].iov_base = scb->payload;
			iovec[vec_idx].iov_len = scb->nfrag > 1 ?
				scb->chunk_size_remaining : scb->payload_size;
			vec_idx++;
			iovcnt++;

			_HFI_VDBG("seqno=%d hdr=%p,%d payload=%p,%d\n",
				  scb->seq_num.psn_num,
				  iovec[vec_idx - 2].iov_base,
				  (int)iovec[vec_idx - 2].iov_len,
				  iovec[vec_idx - 1].iov_base,
				  (int)iovec[vec_idx - 1].iov_len);

		}

		/* If checksum then update checksum  */
		if (have_cksum) {
			scb->cksum[1] = scb->cksum[0];
			iovec[vec_idx].iov_base = scb->cksum;
			iovec[vec_idx].iov_len = PSM_CRC_SIZE_IN_BYTES;
			vec_idx++;
			iovcnt++;

			_HFI_VDBG("chsum=%p,%d\n",
				  iovec[vec_idx - 1].iov_base,
				  (int)iovec[vec_idx - 1].iov_len);
		}

		/*
		 * If it is TID receive, attached tid info.
		 */
		if (scb->tidctrl) {
			iovec[vec_idx].iov_base = scb->tsess;
			iovec[vec_idx].iov_len = scb->tsess_length;
			vec_idx++;
			iovcnt++;

			sdmahdr->ctrl = 1 |
			    (EXPECTED << HFI1_SDMA_REQ_OPCODE_SHIFT) |
			    (iovcnt << HFI1_SDMA_REQ_IOVCNT_SHIFT);

			_HFI_VDBG("tid-info=%p,%d\n",
				  iovec[vec_idx - 1].iov_base,
				  (int)iovec[vec_idx - 1].iov_len);
		} else {
			sdmahdr->ctrl = 1 |
			    (EAGER << HFI1_SDMA_REQ_OPCODE_SHIFT) |
			    (iovcnt << HFI1_SDMA_REQ_IOVCNT_SHIFT);
		}

		/* Can bound the number to send by 'num' */
		if (++scb_idx == num)
			break;
	}
	psmi_assert(vec_idx > 0);
	ret = hfi_cmd_writev(proto->fd, iovec, vec_idx);

	/*
	 * Successfully wrote entire vector
	 */
	if (ret < 0) {
		/* ENOMEM: No kernel memory to queue request, try later?
		 * ECOMM: Link may have gone down
		 * EINTR: Got interrupt while in writev
		 */
		if (errno == ENOMEM || errno == ECOMM || errno == EINTR) {
			err = psmi_context_check_status((const psmi_context_t *)
							&proto->ep->context);
			if (err == PSM2_OK)
				err = PSM2_EP_NO_RESOURCES;
		} else {
			err =
			    psmi_handle_error(proto->ep, PSM2_EP_DEVICE_FAILURE,
					      "Unexpected error in writev(): %s (errno=%d) "
					      "(fd=%d,iovec=%p,len=%d)",
					      strerror(errno), errno, proto->fd,
					      iovec, vec_idx);
			goto fail;
		}
	} else {
		/* No need for inflight system call, we can infer it's value from
		 * writev's return value */
		scb_sent += ret;
	}

fail:
	*num_sent = scb_sent;
	psmi_assert(*num_sent <= num && *num_sent >= 0);
	return err;
}

/*
 * Because we only lazily reap send dma completions, it's possible that we
 * receive a packet's remote acknowledgement before seeing that packet's local
 * completion.  As part of processing ack packets and releasing scbs, we issue
 * a wait for the local completion if the scb is marked as having been sent via
 * send dma.
 */
psm2_error_t
ips_proto_dma_wait_until(struct ips_proto *proto, ips_scb_t *scb)
{
	psm2_error_t err = PSM2_OK;
	int spin_cnt = 0;
	int did_yield = 0;

	PSMI_PROFILE_BLOCK();

	do {
		if (spin_cnt++ == proto->ep->yield_spin_cnt) {
			/* Have to yield holding the PSM lock, mostly because we don't
			 * support another thread changing internal state at this point in
			 * the code.
			 */
			did_yield = 1;
			spin_cnt = 0;
			sched_yield();
		}

		err = ips_proto_dma_completion_update(proto);
		if (err)
			return err;
	} while (scb->dma_complete == 0);

	if (did_yield)
		proto->stats.writev_compl_delay++;

	PSMI_PROFILE_UNBLOCK();

	return err;
}

psm2_error_t
ips_proto_timer_ack_callback(struct psmi_timer *current_timer,
			     uint64_t current)
{
	struct ips_flow *flow = (struct ips_flow *)current_timer->context;
	struct ips_proto *proto = ((psm2_epaddr_t) (flow->ipsaddr))->proto;
	uint64_t t_cyc_next = get_cycles();
	psmi_seqnum_t err_chk_seq;
	ips_scb_t *scb, ctrlscb;
	uint8_t message_type;

	if (STAILQ_EMPTY(&flow->scb_unacked))
		return PSM2_OK;

	scb = STAILQ_FIRST(&flow->scb_unacked);

	if (current >= scb->abs_timeout) {
		int done_local = 0;

		/* We have to ensure that the send is at least locally complete before
		 * sending an error check or else earlier data can get to the
		 * destination *after* we pio or dma this err_chk.
		 */
		if (flow->transfer == PSM_TRANSFER_DMA) {
			/* error is caught inside this routine */
			ips_proto_dma_completion_update(proto);

			if (scb->dma_complete)
				done_local = 1;
			else
				proto->stats.writev_compl_eagain++;
		} else
			done_local = 1;	/* Always done for PIO flows */

		scb->ack_timeout =
		    min(scb->ack_timeout * proto->epinfo.ep_timeout_ack_factor,
			proto->epinfo.ep_timeout_ack_max);
		scb->abs_timeout = t_cyc_next + scb->ack_timeout;

		if (done_local) {
			_HFI_VDBG
			    ("sending err_chk flow=%d with first=%d,last=%d\n",
			     flow->flowid,
			     STAILQ_FIRST(&flow->scb_unacked)->seq_num.psn_num,
			     STAILQ_LAST(&flow->scb_unacked, ips_scb,
					 nextq)->seq_num.psn_num);

			ctrlscb.flags = 0;
			if (proto->flags & IPS_PROTO_FLAG_RCVTHREAD)
				ctrlscb.flags |= IPS_SEND_FLAG_INTR;

			err_chk_seq = (SLIST_EMPTY(&flow->scb_pend)) ?
					flow->xmit_seq_num :
					SLIST_FIRST(&flow->scb_pend)->seq_num;

			if (flow->protocol == PSM_PROTOCOL_TIDFLOW) {
				message_type = OPCODE_ERR_CHK_GEN;
				err_chk_seq.psn_seq -= 1;
				/* Receive descriptor index */
				ctrlscb.ips_lrh.data[0].u64 =
					scb->tidsendc->rdescid.u64;
				/* Send descriptor index */
				ctrlscb.ips_lrh.data[1].u64 =
					scb->tidsendc->sdescid.u64;
			} else {
				PSM2_LOG_MSG("sending ERR_CHK message");
				message_type = OPCODE_ERR_CHK;
				err_chk_seq.psn_num = (err_chk_seq.psn_num - 1)
					& proto->psn_mask;
			}
			ctrlscb.ips_lrh.bth[2] =
					__cpu_to_be32(err_chk_seq.psn_num);

			ips_proto_send_ctrl_message(flow, message_type,
					&flow->ipsaddr->ctrl_msg_queued,
					&ctrlscb, ctrlscb.cksum, 0);
		}

		t_cyc_next = get_cycles() + scb->ack_timeout;
	} else
		t_cyc_next += (scb->abs_timeout - current);

	psmi_timer_request(proto->timerq, current_timer, t_cyc_next);

	return PSM2_OK;
}

psm2_error_t
ips_proto_timer_send_callback(struct psmi_timer *current_timer,
			      uint64_t current)
{
	struct ips_flow *flow = (struct ips_flow *)current_timer->context;
	struct ips_proto *proto = ((psm2_epaddr_t) (flow->ipsaddr))->proto;

	/* If flow is marked as congested adjust injection rate - see process nak
	 * when a congestion NAK is received.
	 */
	if_pf(flow->flags & IPS_FLOW_FLAG_CONGESTED) {

		/* Clear congestion flag and decrease injection rate */
		flow->flags &= ~IPS_FLOW_FLAG_CONGESTED;
		if ((flow->path->pr_ccti +
		     proto->cace[flow->path->pr_sl].ccti_increase) <=
		    proto->ccti_limit)
			ips_cca_adjust_rate(flow->path,
					    proto->cace[flow->path->pr_sl].
					    ccti_increase);
	}

	flow->flush(flow, NULL);

	return PSM2_OK;
}

psm2_error_t ips_cca_adjust_rate(ips_path_rec_t *path_rec, int cct_increment)
{
	struct ips_proto *proto = path_rec->proto;
	uint16_t prev_ipd, prev_divisor;

	/* Increment/decrement ccti for path */
	psmi_assert_always(path_rec->pr_ccti >=
			   proto->cace[path_rec->pr_sl].ccti_min);
	path_rec->pr_ccti += cct_increment;

	/* Determine new active IPD.  */
	prev_ipd = path_rec->pr_active_ipd;
	prev_divisor = path_rec->pr_cca_divisor;
	if ((path_rec->pr_static_ipd) &&
	    ((path_rec->pr_static_ipd + 1) >
	     (proto->cct[path_rec->pr_ccti] & CCA_IPD_MASK))) {
		path_rec->pr_active_ipd = path_rec->pr_static_ipd + 1;
		path_rec->pr_cca_divisor = 0;
	} else {
		path_rec->pr_active_ipd =
		    proto->cct[path_rec->pr_ccti] & CCA_IPD_MASK;
		path_rec->pr_cca_divisor =
		    proto->cct[path_rec->pr_ccti] >> CCA_DIVISOR_SHIFT;
	}

	_HFI_CCADBG("CCA: %s injection rate to <%x.%x> from <%x.%x>\n",
		    (cct_increment > 0) ? "Decreasing" : "Increasing",
		    path_rec->pr_cca_divisor, path_rec->pr_active_ipd,
		    prev_divisor, prev_ipd);

	/* Reschedule CCA timer if this path is still marked as congested */
	if (path_rec->pr_ccti > proto->cace[path_rec->pr_sl].ccti_min) {
		if (path_rec->pr_timer_cca == NULL) {
			path_rec->pr_timer_cca =
			    (struct psmi_timer *)psmi_mpool_get(proto->
								timer_pool);
			psmi_assert(path_rec->pr_timer_cca != NULL);
			psmi_timer_entry_init(path_rec->pr_timer_cca,
					      ips_cca_timer_callback, path_rec);
		}
		psmi_timer_request(proto->timerq,
				   path_rec->pr_timer_cca,
				   get_cycles() +
				   proto->cace[path_rec->pr_sl].
				   ccti_timer_cycles);
	} else if (path_rec->pr_timer_cca) {
		psmi_mpool_put(path_rec->pr_timer_cca);
		path_rec->pr_timer_cca = NULL;
	}

	return PSM2_OK;
}

psm2_error_t
ips_cca_timer_callback(struct psmi_timer *current_timer, uint64_t current)
{
	ips_path_rec_t *path_rec = (ips_path_rec_t *) current_timer->context;

	/* Increase injection rate for flow. Decrement CCTI */
	if (path_rec->pr_ccti > path_rec->proto->cace[path_rec->pr_sl].ccti_min)
		return ips_cca_adjust_rate(path_rec, -1);

	psmi_mpool_put(path_rec->pr_timer_cca);
	path_rec->pr_timer_cca = NULL;
	return PSM2_OK;
}
