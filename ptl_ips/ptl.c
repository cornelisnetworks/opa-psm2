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

/* This file implements the PSM PTL for ips */
#include "psm_user.h"
#include "psm2_hal.h"
#include "ptl_ips.h"
#include "psm_mq_internal.h"

int ips_ptl_recvq_isempty(const struct ptl *ptl);

static
int
ips_subcontext_ignore(struct ips_recvhdrq_event *rcv_ev,
		      uint32_t subcontext)
{
	return IPS_RECVHDRQ_CONTINUE;
}

static
int
ips_subcontext_process(struct ips_recvhdrq_event *rcv_ev,
		       uint32_t subcontext)
{
	struct ptl_shared *recvshc = ((struct ptl_ips *)(rcv_ev->proto->ptl))->recvshc;
	if_pt(subcontext != recvshc->subcontext &&
	      subcontext < recvshc->subcontext_cnt) {
		return psmi_hal_forward_packet_to_subcontext(&recvshc->writeq[subcontext],
							     rcv_ev, subcontext,
							     rcv_ev->recvq->context->psm_hw_ctxt);
	}
	else {
		_HFI_VDBG
			("Drop pkt for subcontext %d out of %d (I am %d) : errors 0x%x\n",
			 (int)subcontext, (int)recvshc->subcontext_cnt,
			 (int)recvshc->subcontext, psmi_hal_rhf_get_all_err_flags(rcv_ev->psm_hal_rhf));
                return IPS_RECVHDRQ_BREAK;
	}
}

static psm2_error_t shrecvq_init(ptl_t *ptl, const psmi_context_t *context);
static psm2_error_t shrecvq_fini(ptl_t *ptl);

static size_t ips_ptl_sizeof(void)
{
	return sizeof(struct ptl_ips);
}

static
int ips_ptl_epaddr_stats_num(void)
{
	return sizeof(struct ips_proto_epaddr_stats) / sizeof(uint64_t);
}

static
int ips_ptl_epaddr_stats_init(char **desc, uint16_t *flags)
{
	int num_stats =
	    sizeof(struct ips_proto_epaddr_stats) / sizeof(uint64_t);
	int i;

	/* All stats are uint64_t */
	for (i = 0; i < num_stats; i++)
		flags[i] = MPSPAWN_STATS_REDUCTION_ALL |
		    MPSPAWN_STATS_SKIP_IF_ZERO;

	desc[0] = "errchecks sent";
	desc[1] = "errchecks recv";
	desc[2] = "naks sent";
	desc[3] = "naks recv";
	desc[4] = "connect reqs sent";
	desc[5] = "disconnect reqs sent";
	desc[6] = "tid grants sent";
	desc[7] = "tid grants recv";
	desc[8] = "send rexmit";
	desc[9] = "congestion packets";

	return num_stats;
}

int ips_ptl_epaddr_stats_get(psm2_epaddr_t epaddr, uint64_t *stats_o)
{
	int i, num_stats =
	    sizeof(struct ips_proto_epaddr_stats) / sizeof(uint64_t);
	uint64_t *stats_i = (uint64_t *) &epaddr->proto->epaddr_stats;

	for (i = 0; i < num_stats; i++)
		stats_o[i] = stats_i[i];

	return num_stats;
}

static
psm2_error_t
psmi_context_check_status_callback(struct psmi_timer *t, uint64_t current)
{
	struct ptl_ips *ptl = (struct ptl_ips *)t->context;
	const uint64_t current_count = get_cycles();
	psm2_error_t err;

	err = psmi_context_check_status(ptl->context);
	if (err == PSM2_OK || err == PSM2_OK_NO_PROGRESS)
	{
		int rc = psmi_hal_spio_process_events((struct ptl *)ptl);
		err = rc >= 0 ? PSM2_OK : PSM2_INTERNAL_ERR;
	}
	psmi_timer_request_always(&ptl->timerq, &ptl->status_timer,
				  current_count + ptl->status_cyc_timeout);

	return err;
}

static
psm2_error_t ips_ptl_init(const psm2_ep_t ep, ptl_t *ptl_gen, ptl_ctl_t *ctl)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	psm2_error_t err = PSM2_OK;
	uint32_t num_of_send_bufs = ep->hfi_num_sendbufs;
	uint32_t num_of_send_desc = ep->hfi_num_descriptors;
	uint32_t imm_size = ep->hfi_imm_size;
	const psmi_context_t *context = &ep->context;
	const int enable_shcontexts = (psmi_hal_get_subctxt_cnt(context->psm_hw_ctxt) > 0);
	const uint64_t current_count = get_cycles();

	/* Preconditions */
	psmi_assert_always(ep != NULL);
	psmi_assert_always(ep->epaddr != NULL);
	psmi_assert_always(ep->epid != 0);
	psmi_assert_always(ep->hfi_num_sendbufs > 0);

	memset(ptl, 0, sizeof(struct ptl_ips));

	ptl->ep = ep;		/* back pointer */
	ptl->epid = ep->epid;	/* cache epid */
	ptl->epaddr = ep->epaddr;	/* cache a copy */
	ptl->ctl = ctl;
	ptl->context = context;

	memset(ctl, 0, sizeof(*ctl));
	/* Fill in the control structure */
	ctl->ep = ep;
	ctl->ptl = ptl_gen;
	ctl->ep_poll = enable_shcontexts ? ips_ptl_shared_poll : ips_ptl_poll;
	ctl->ep_connect = ips_ptl_connect;
	ctl->ep_disconnect = ips_ptl_disconnect;
	ctl->mq_send = ips_proto_mq_send;
	ctl->mq_isend = ips_proto_mq_isend;

	ctl->am_get_parameters = ips_am_get_parameters;

	ctl->am_short_request = ips_am_short_request;
	ctl->am_short_reply = ips_am_short_reply;

	ctl->epaddr_stats_num = ips_ptl_epaddr_stats_num;
	ctl->epaddr_stats_init = ips_ptl_epaddr_stats_init;
	ctl->epaddr_stats_get = ips_ptl_epaddr_stats_get;

	ctl->msg_size_thresh_query = ips_proto_msg_size_thresh_query;

	/*
	 * Runtime flags in 'ptl' are different from runtime flags in 'context'.
	 * In 'context', runtime flags reflect what the driver is capable of.
	 * In 'ptl', runtime flags reflect the features we can or want to use in
	 *           the driver's supported runtime flags.
	 */

	/*
	 * This timer is to be used to check the context's status at every
	 * PSMI_CONTEXT_STATUS_CHECK_INTERVAL_MSECS.  This is useful to detect when
	 * the link transitions from the DOWN state to the UP state.  We can thus
	 * stop aggregating link failure messages once we detect that the link is
	 * up.
	 */
	psmi_timer_entry_init(&ptl->status_timer,
			      psmi_context_check_status_callback, ptl);

	/* cache the context's status timeout in cycles */
	ptl->status_cyc_timeout =
	    ms_2_cycles(PSMI_CONTEXT_STATUS_CHECK_INTERVAL_MSECS);

	/*
	 * Retransmissions and pending operations are kept in a timer structure
	 * (queue).  The timerq is shared to various internal IPS interfaces so
	 * that they too may schedule events on the timer queue.  The timerq is
	 * drained in the progress function.
	 */
	if ((err = psmi_timer_init(&ptl->timerq)))
		goto fail;

	/* start the context's status timer */
	psmi_timer_request_always(&ptl->timerq, &ptl->status_timer,
				  current_count + ptl->status_cyc_timeout);

	/*
	 * Epstate maps endpoint ids (epid integers) to ipsaddr (structs). Mappings
	 * are added/removed by the connect portion of the ips protocol and lookup
	 * is made by the receive queue processing component.
	 */
	if ((err = ips_epstate_init(&ptl->epstate, context)))
		goto fail;

	/*
	 * Context sharing, setup subcontext ureg page.
	 */
	if (enable_shcontexts) {
		struct ptl_shared *recvshc;

		recvshc = (struct ptl_shared *)
		    psmi_calloc(ep, UNDEFINED, 1, sizeof(struct ptl_shared));
		if (recvshc == NULL) {
			err = PSM2_NO_MEMORY;
			goto fail;
		}

		ptl->recvshc = recvshc;
		recvshc->ptl = ptl_gen;

		/* Initialize recvshc fields */
		recvshc->context = psmi_hal_get_context(context->psm_hw_ctxt);
		recvshc->subcontext = psmi_hal_get_subctxt(context->psm_hw_ctxt);
		recvshc->subcontext_cnt = psmi_hal_get_subctxt_cnt(context->psm_hw_ctxt);
		psmi_assert_always(recvshc->subcontext_cnt <=
				   PSM_HAL_MAX_SHARED_CTXTS);
		psmi_assert_always(recvshc->subcontext <
				   recvshc->subcontext_cnt);

		/*
		 * Using ep->context to avoid const modifier since this function
		 * will modify the content in ep->context.
		 */
		if ((err = psmi_hal_subcontext_ureg_get(ptl_gen,
							recvshc->subcontext_ureg, context->psm_hw_ctxt)))
			goto fail;

		/* Note that the GEN1 HAL instance initializes struct ips_subcontext_ureg
		   during context open. */

		recvshc->context_lock = &recvshc->hwcontext_ctrl->context_lock;
		if (recvshc->subcontext == 0) {
			if (pthread_spin_init(recvshc->context_lock,
					      PTHREAD_PROCESS_SHARED) != 0) {
				err =
				    psmi_handle_error(ptl->ep,
						      PSM2_EP_DEVICE_FAILURE,
						      "Couldn't initialize process-shared spin lock");
				goto fail;
			}
		}
	}
	/*
	 * Hardware send pio used by eager and control messages.
	 */
	if ((err = psmi_hal_spio_init(context, ptl_gen, &ptl->spioc)))
		goto fail;

	/*
	 * Actual ips protocol handling.
	 */
	if ((err =
	     ips_proto_init(context, ptl_gen, num_of_send_bufs, num_of_send_desc,
			    imm_size, &ptl->timerq, &ptl->epstate, ptl->spioc,
			    &ptl->proto)))
		goto fail;

	/*
	 * Hardware receive hdr/egr queue, services incoming packets and issues
	 * callbacks for protocol handling in proto_recv.  It uses the epstate
	 * interface to determine if a packet is known or unknown.
	 */
	if (!enable_shcontexts) {
		struct ips_recvhdrq_callbacks recvq_callbacks;
		recvq_callbacks.callback_packet_unknown =
		    ips_proto_process_unknown;
		recvq_callbacks.callback_subcontext = ips_subcontext_ignore;
		recvq_callbacks.callback_error = ips_proto_process_packet_error;
		if ((err =
		     ips_recvhdrq_init(context, &ptl->epstate, &ptl->proto,
				       &recvq_callbacks,
				       0, &ptl->recvq,
				       &ptl->recvq_state,
				       PSM_HAL_CL_Q_RX_HDR_Q)))
			goto fail;
	}
	/*
	 * Software receive hdr/egr queue, used in shared contexts.
	 */
	else if ((err = shrecvq_init(ptl_gen, context)))
		goto fail;

	/*
	 * Receive thread, always initialized but not necessary creates a
	 * pthread.
	 */
	if ((err = ips_ptl_rcvthread_init(ptl_gen, &ptl->recvq)))
		goto fail;
fail:
	return err;
}

static psm2_error_t ips_ptl_fini(ptl_t *ptl_gen, int force, uint64_t timeout_in)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	psm2_error_t err = PSM2_OK;
	const int enable_shcontexts = (psmi_hal_get_subctxt_cnt(ptl->context->psm_hw_ctxt) > 0);

	if ((err = ips_proto_fini(&ptl->proto, force, timeout_in)))
		goto fail;

	/* We have to cancel the thread after terminating the protocol because
	 * connect/disconnect packets use interrupts and the kernel doesn't
	 * like to have no pollers waiting */
	if ((err = ips_ptl_rcvthread_fini(ptl_gen)))
		goto fail;

	if ((err = ips_epstate_fini(&ptl->epstate)))
		goto fail;

	if ((err = psmi_hal_spio_fini(&ptl->spioc, ptl->context->psm_hw_ctxt)))
		goto fail;

	if ((err = psmi_timer_fini(&ptl->timerq)))
		goto fail;


	if (enable_shcontexts && (err = shrecvq_fini(ptl_gen)))
		goto fail;

fail:
	return err;
}

static
psm2_error_t
ips_ptl_optctl(const void *core_obj, int optname,
	       void *optval, uint64_t *optlen, int get)
{
	psm2_error_t err = PSM2_OK;

	switch (optname) {
	case PSM2_IB_OPT_EP_SL:
		{
			/* Core object is psm2_epaddr */
			psm2_epaddr_t epaddr = (psm2_epaddr_t) core_obj;
			ips_epaddr_t *ipsaddr = (ips_epaddr_t *) epaddr;

			/* If endpoint does not use IB ignore for set, complain for get */
			if (epaddr->ptlctl->ep_connect != ips_ptl_connect) {
				if (get)
					err =
					    psmi_handle_error(PSMI_EP_LOGEVENT,
							      PSM2_PARAM_ERR,
							      "Invalid EP transport");
				goto exit_fn;
			}

			/* Sanity check option length */
			if (*optlen < sizeof(uint8_t)) {
				err =
				    psmi_handle_error(PSMI_EP_LOGEVENT,
						      PSM2_PARAM_ERR,
						      "Option value length error");
				*optlen = sizeof(unsigned);
				goto exit_fn;
			}

			if (get) {
				/* Get returns the SL for the PIO flow */
				*((uint8_t *) optval) =
				    (uint8_t) ipsaddr->
				    flows[EP_FLOW_GO_BACK_N_PIO].path->pr_sl;
			} else {
				uint16_t new_sl;

				/* Sanity check if SL is within range */
				new_sl = (uint16_t) *(uint8_t *) optval;
				if (new_sl > PSMI_SL_MAX) {
					err =
					    psmi_handle_error(PSMI_EP_LOGEVENT,
						      PSM2_PARAM_ERR,
						      "Invalid SL value %u. %d<= SL <=%d.",
						      new_sl, PSMI_SL_MIN, PSMI_SL_MAX);
					goto exit_fn;
				}

				/* Set new SL for all flows */
				ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO].path->
				    pr_sl = new_sl;
				ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA].path->
				    pr_sl = new_sl;
			}
		}
		break;
	case PSM2_IB_OPT_DF_SL:
		{
			/* Set default SL to be used by an endpoint for all communication */
			/* Core object is psm2_epaddr */
			psm2_ep_t ep = (psm2_ep_t) core_obj;

			/* Make sure ep is specified */
			if (!ep) {
				err =
				    psmi_handle_error(PSMI_EP_LOGEVENT,
						      PSM2_PARAM_ERR,
						      "Invalid PSM Endpoint");
				goto exit_fn;
			}

			/* Sanity check option length */
			if (*optlen < sizeof(uint8_t)) {
				err =
				    psmi_handle_error(PSMI_EP_LOGEVENT,
						      PSM2_PARAM_ERR,
						      "Option value length error");
				*optlen = sizeof(uint8_t);
				goto exit_fn;
			}

			if (get) {
				*((uint8_t *) optval) =
					((struct ptl_ips *)(ep->ptl_ips.ptl))->proto.epinfo.ep_sl;
			} else {
				uint16_t new_sl;

				/* Sanity check if SL is within range */
				new_sl = (uint16_t) *(uint8_t *) optval;
				if (new_sl > PSMI_SL_MAX) {
					err =
					    psmi_handle_error(PSMI_EP_LOGEVENT,
						      PSM2_PARAM_ERR,
						      "Invalid SL value %u. %d<= SL <=%d.",
						      new_sl, PSMI_SL_MIN, PSMI_SL_MAX);
					goto exit_fn;
				}

				((struct ptl_ips *)(ep->ptl_ips.ptl))->proto.epinfo.ep_sl =
				    (uint8_t) new_sl;
			}
		}
		break;
	default:
		err =
		    psmi_handle_error(NULL, PSM2_PARAM_ERR,
				      "Unknown PSM2_IB option %u.", optname);
	}

exit_fn:
	return err;
}

static
psm2_error_t
ips_ptl_setopt(const void *component_obj, int optname,
	       const void *optval, uint64_t optlen)
{
	return ips_ptl_optctl(component_obj, optname, (void *)optval, &optlen,
			      0);
}

static
psm2_error_t
ips_ptl_getopt(const void *component_obj, int optname,
	       void *optval, uint64_t *optlen)
{
	return ips_ptl_optctl(component_obj, optname, optval, optlen, 1);
}

static
uint32_t
ips_ptl_rcvthread_is_enabled(const ptl_t *ptl)
{
	return psmi_hal_has_sw_status(PSM_HAL_PSMI_RUNTIME_RX_THREAD_STARTED);
}

psm2_error_t ips_ptl_poll(ptl_t *ptl_gen, int _ignored)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	const uint64_t current_count = get_cycles();
	const int do_lock = PSMI_LOCK_DISABLED &&
		psmi_hal_has_sw_status(PSM_HAL_PSMI_RUNTIME_RX_THREAD_STARTED);
	psm2_error_t err = PSM2_OK_NO_PROGRESS;
	psm2_error_t err2;

	if (!ips_recvhdrq_isempty(&ptl->recvq)) {
		if (do_lock && !ips_recvhdrq_trylock(&ptl->recvq))
			return err;
		if (ptl->recvq.proto->flags & IPS_PROTO_FLAG_CCA_PRESCAN) {
			ips_recvhdrq_scan_cca(&ptl->recvq);
		}
		err = ips_recvhdrq_progress(&ptl->recvq);
		if (do_lock)
			ips_recvhdrq_unlock(&ptl->recvq);
		if_pf(err > PSM2_OK_NO_PROGRESS)
		    return err;
		err2 =
		    psmi_timer_process_if_expired(&(ptl->timerq),
						  current_count);
		if (err2 != PSM2_OK_NO_PROGRESS)
			return err2;
		else
			return err;
	}

	/*
	 * Process timer expirations after servicing receive queues (some packets
	 * may have been acked, some requests-to-send may have been queued).
	 *
	 * It's safe to look at the timer without holding the lock because it's not
	 * incorrect to be wrong some of the time.
	 */
	if (psmi_timer_is_expired(&(ptl->timerq), current_count)) {
		if (do_lock)
			ips_recvhdrq_lock(&ptl->recvq);
		err = psmi_timer_process_expired(&(ptl->timerq), current_count);
		if (do_lock)
			ips_recvhdrq_unlock(&ptl->recvq);
	}

	return err;
}

PSMI_INLINE(int ips_try_lock_shared_context(struct ptl_shared *recvshc))
{
	return pthread_spin_trylock(recvshc->context_lock);
}

PSMI_INLINE(void ips_unlock_shared_context(struct ptl_shared *recvshc))
{
	pthread_spin_unlock(recvshc->context_lock);
}

psm2_error_t ips_ptl_shared_poll(ptl_t *ptl_gen, int _ignored)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	const uint64_t current_count = get_cycles();
	psm2_error_t err = PSM2_OK_NO_PROGRESS;
	psm2_error_t err2;
	struct ptl_shared *recvshc = ptl->recvshc;
	psmi_assert(recvshc != NULL);

	/* The following header queue checks are speculative (but safe)
	 * until this process has acquired the lock. The idea is to
	 * minimize lock contention due to processes spinning on the
	 * shared context. */
	if (ips_recvhdrq_isempty(&recvshc->recvq)) {
		if (!ips_recvhdrq_isempty(&ptl->recvq) &&
		    ips_try_lock_shared_context(recvshc) == 0) {
			/* check that subcontext is empty while under lock to avoid
			 * re-ordering of incoming packets (since packets from
			 * hardware context will be processed immediately). */
			if_pt(ips_recvhdrq_isempty(&recvshc->recvq)) {
				if (ptl->recvq.proto->flags & IPS_PROTO_FLAG_CCA_PRESCAN) {
					ips_recvhdrq_scan_cca(&ptl->recvq);
				}
				err = ips_recvhdrq_progress(&ptl->recvq);
			}
			ips_unlock_shared_context(recvshc);
		}
	}

	if_pf(err > PSM2_OK_NO_PROGRESS)
	    return err;

	if (!ips_recvhdrq_isempty(&recvshc->recvq)) {
		if (recvshc->recvq.proto->flags & IPS_PROTO_FLAG_CCA_PRESCAN) {
			ips_recvhdrq_scan_cca(&recvshc->recvq);
		}
		err2 = ips_recvhdrq_progress(&recvshc->recvq);
		if (err2 != PSM2_OK_NO_PROGRESS) {
			err = err2;
		}
	}

	if_pf(err > PSM2_OK_NO_PROGRESS)
	    return err;

	/*
	 * Process timer expirations after servicing receive queues (some packets
	 * may have been acked, some requests-to-send may have been queued).
	 */
	err2 = psmi_timer_process_if_expired(&(ptl->timerq), current_count);
	if (err2 != PSM2_OK_NO_PROGRESS)
		err = err2;

	return err;
}

int ips_ptl_recvq_isempty(const ptl_t *ptl_gen)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	struct ptl_shared *recvshc = ptl->recvshc;

	if (recvshc != NULL && !ips_recvhdrq_isempty(&recvshc->recvq))
		return 0;
	return ips_recvhdrq_isempty(&ptl->recvq);
}

/*
 * Legacy ips_get_stat -- do nothing.
 */
int ips_get_stat(psm2_epaddr_t epaddr, ips_sess_stat *stats)
{
	memset(stats, 0, sizeof(ips_sess_stat));
	return 0;
}

static psm2_error_t shrecvq_init(ptl_t *ptl_gen, const psmi_context_t *context)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	struct ptl_shared *recvshc = ptl->recvshc;
	struct ips_recvhdrq_callbacks recvq_callbacks;
	psm2_error_t err = PSM2_OK;
	int i;

	/* Initialize (shared) hardware context recvq (ptl->recvq) */
	/* NOTE: uses recvq in ptl structure for shared h/w context */
	recvq_callbacks.callback_packet_unknown = ips_proto_process_unknown;
	recvq_callbacks.callback_subcontext = ips_subcontext_process;
	recvq_callbacks.callback_error = ips_proto_process_packet_error;
	if ((err = ips_recvhdrq_init(context, &ptl->epstate, &ptl->proto,
				     &recvq_callbacks,
				     recvshc->subcontext,
				     &ptl->recvq,
				     &recvshc->hwcontext_ctrl->recvq_state,
				     PSM_HAL_CL_Q_RX_HDR_Q))) {
		goto fail;
	}

	/* Initialize software subcontext (recvshc->recvq). Subcontexts do */
	/* not require the rcvhdr copy feature. */
	recvq_callbacks.callback_subcontext = ips_subcontext_ignore;
	if ((err = ips_recvhdrq_init(context, &ptl->epstate, &ptl->proto,
				     &recvq_callbacks,
				     recvshc->subcontext,
				     &recvshc->recvq, &recvshc->recvq_state,
				     PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(recvshc->subcontext)))) {
		goto fail;
	}

	/* Initialize each recvshc->writeq for shared contexts */
	for (i = 0; i < recvshc->subcontext_cnt; i++) {
		if ((err = ips_writehdrq_init(context,
					      &recvshc->writeq[i],
					      &recvshc->subcontext_ureg[i]->
					      writeq_state,
					      i))) {
			goto fail;
		}
	}

	if (err == PSM2_OK)
		_HFI_DBG
		    ("Context sharing in use: lid %d, context %d, sub-context %d\n",
		     (int)psm2_epid_nid(ptl->epid), recvshc->context,
		     recvshc->subcontext);
fail:
	return err;
}

static psm2_error_t shrecvq_fini(ptl_t *ptl_gen)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	psm2_error_t err = PSM2_OK;
	int i;

	/* disable my write header queue before deallocation */
	i = ptl->recvshc->subcontext;
	ptl->recvshc->subcontext_ureg[i]->writeq_state.enabled = 0;
	psmi_free(ptl->recvshc);
	return err;
}

psm2_error_t
ips_ptl_connect(ptl_t *ptl_gen, int numep, const psm2_epid_t *array_of_epid,
		const int *array_of_epid_mask, psm2_error_t *array_of_errors,
		psm2_epaddr_t *array_of_epaddr, uint64_t timeout_in)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	psm2_error_t err;
	psm2_ep_t ep;
	psm2_epid_t *epid_array = NULL;
	psm2_error_t *error_array = NULL;
	psm2_epaddr_t *epaddr_array = NULL;
	ips_epaddr_t *ipsaddr_master, *ipsaddr;
	int *mask_array = NULL;
	int i;

	PSMI_LOCK_ASSERT(ptl->ep->mq->progress_lock);
	err = ips_proto_connect(&ptl->proto, numep, array_of_epid,
				array_of_epid_mask, array_of_errors,
				array_of_epaddr, timeout_in);
	if (err)
		return err;

	psmi_assert_always(ptl->ep->mctxt_master == ptl->ep);
	if (ptl->ep->mctxt_next == ptl->ep)
		return err;

	/* make the additional mutil-context connections. */
	epid_array = (psm2_epid_t *)
	    psmi_malloc(ptl->ep, UNDEFINED, sizeof(psm2_epid_t) * numep);
	mask_array = (int *)
	    psmi_malloc(ptl->ep, UNDEFINED, sizeof(int) * numep);
	error_array = (psm2_error_t *)
	    psmi_malloc(ptl->ep, UNDEFINED, sizeof(psm2_error_t) * numep);
	epaddr_array = (psm2_epaddr_t *)
	    psmi_malloc(ptl->ep, UNDEFINED, sizeof(psm2_epaddr_t) * numep);
	if (!epid_array || !mask_array || !error_array || !epaddr_array) {
		goto fail;
	}

	ep = ptl->ep->mctxt_next;
	while (ep != ep->mctxt_master) {

		/* Setup the mask array and epid array. */
		for (i = 0; i < numep; i++) {
			if (array_of_epid_mask[i]
			    && array_of_errors[i] == PSM2_OK) {
				ipsaddr_master =
				    (ips_epaddr_t *) array_of_epaddr[i];
				ipsaddr = ipsaddr_master->next;
				mask_array[i] = 0;
				while (ipsaddr != ipsaddr_master) {
					if (((psm2_epaddr_t) ipsaddr)->proto->
					    ep == ep) {
						mask_array[i] = 1;
						epid_array[i] =
						    ((psm2_epaddr_t) ipsaddr)->
						    epid;
						break;
					}
					ipsaddr = ipsaddr->next;
				}
			} else {
				mask_array[i] = 0;
			}
		}

		/* Make the real protocol connections. */
		err =
			ips_proto_connect(&((struct ptl_ips *)(ep->ptl_ips.ptl))->proto,
					  numep, epid_array, mask_array, error_array,
					  epaddr_array, timeout_in);
		if (err)
			goto fail;

		ep = ep->mctxt_next;
	}

fail:
	if (epid_array)
		psmi_free(epid_array);
	if (mask_array)
		psmi_free(mask_array);
	if (error_array)
		psmi_free(error_array);
	if (epaddr_array)
		psmi_free(epaddr_array);

	return err;
}

psm2_error_t
ips_ptl_disconnect(ptl_t *ptl_gen, int force, int numep,
		   psm2_epaddr_t array_of_epaddr[],
		   const int array_of_epaddr_mask[],
		   psm2_error_t array_of_errors[], uint64_t timeout_in)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	int *array_of_epaddr_mask_internal, i;
	psm2_error_t err;

	/*
	 * Copy true values from array_of_epaddr_mask, provided that their
	 * respective epaddr is an ips one.
	 * Newly created mask will be used for the protocol disconnect call
	 * instead.
	 */
	PSMI_LOCK_ASSERT(ptl->ep->mq->progress_lock);
	array_of_epaddr_mask_internal = psmi_calloc(ptl->ep, UNDEFINED,
						    sizeof(int), numep);
	if (!array_of_epaddr_mask_internal)
		return PSM2_NO_MEMORY;

	for (i = 0; i < numep; ++i) {
		if (array_of_epaddr_mask[i] && array_of_epaddr[i]
		    && array_of_epaddr[i]->ptlctl->ptl == ptl_gen) {
			array_of_epaddr_mask_internal[i] = 1;
		}
	}

	err = ips_proto_disconnect(&ptl->proto, force, numep, array_of_epaddr,
				   array_of_epaddr_mask_internal,
				   array_of_errors, timeout_in);

	psmi_free(array_of_epaddr_mask_internal);
	return err;
}

/* Only symbol we expose out of here */
struct ptl_ctl_init
psmi_ptl_ips = {
	ips_ptl_sizeof, ips_ptl_init, ips_ptl_fini, ips_ptl_setopt,
	    ips_ptl_getopt
};

struct ptl_ctl_rcvthread
psmi_ptl_ips_rcvthread = {
	ips_ptl_rcvthread_is_enabled,
	ips_ptl_rcvthread_transfer_ownership,
};
