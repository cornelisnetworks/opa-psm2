/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2017 Intel Corporation.

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

  Copyright(c) 2017 Intel Corporation.

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

/* Copyright (c) 2003-2017 Intel Corporation. All rights reserved. */

/* included header files  */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sched.h>

#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "psm_hal_gen1_spio.h"
#include "ips_proto_params.h"

/* Report PIO stalls every 20 seconds at the least */
#define SPIO_STALL_WARNING_INTERVAL	  (nanosecs_to_cycles(20e9))
#define SPIO_MAX_CONSECUTIVE_SEND_FAIL	  (1<<20)	/* 1M */
/* RESYNC_CONSECUTIVE_SEND_FAIL has to be a multiple of MAX_CONSECUTIVE */
#define SPIO_RESYNC_CONSECUTIVE_SEND_FAIL (1<<4)	/* 16 */

static void spio_report_stall(struct ips_spio *ctrl,
			      uint64_t t_cyc_now, uint64_t send_failures);

static void spio_handle_stall(struct ips_spio *ctrl, uint64_t send_failures);

static psm2_error_t spio_reset_hfi(struct ips_spio *ctrl);
static psm2_error_t spio_reset_hfi_shared(struct ips_spio *ctrl);
static psm2_error_t spio_credit_return_update(struct ips_spio *ctrl);
static psm2_error_t spio_credit_return_update_shared(struct ips_spio *ctrl);

static PSMI_HAL_INLINE psm2_error_t
ips_spio_init(const struct psmi_context *context, struct ptl *ptl,
	      struct ips_spio *ctrl
#ifdef PSM_AVX512
	      , int is_avx512_enabled
#endif
	      )
{
	cpuid_t id;
	hfp_gen1_pc_private *psm_hw_ctxt = context->psm_hw_ctxt;
	struct _hfi_ctrl *con_ctrl = psm_hw_ctxt->ctrl;

	ctrl->ptl = ptl;
	ctrl->context = context;
	ctrl->unit_id = context->ep->unit_id;
	ctrl->portnum = context->ep->portnum;

	pthread_spin_init(&ctrl->spio_lock, PTHREAD_PROCESS_PRIVATE);
	ctrl->spio_credits_addr = (volatile __le64 *)  con_ctrl->base_info.sc_credits_addr;
	ctrl->spio_bufbase_sop  = (volatile uint64_t *)con_ctrl->base_info.pio_bufbase_sop;
	ctrl->spio_bufbase      = (volatile uint64_t *)con_ctrl->base_info.pio_bufbase;

	ctrl->spio_consecutive_failures = 0;
	ctrl->spio_num_stall = 0ULL;
	ctrl->spio_num_stall_total = 0ULL;
	ctrl->spio_next_stall_warning = 0ULL;
	ctrl->spio_last_stall_cyc = 0ULL;
	ctrl->spio_init_cyc = get_cycles();

	ctrl->spio_total_blocks = con_ctrl->ctxt_info.credits;
	ctrl->spio_block_index = 0;

	ctrl->spio_ctrl = (struct ips_spio_ctrl *)context->spio_ctrl;
	if (!ctrl->spio_ctrl) {
		ctrl->spio_ctrl = (volatile struct ips_spio_ctrl *)
		    psmi_calloc(context->ep, UNDEFINED, 1,
				sizeof(struct ips_spio_ctrl));
		if (ctrl->spio_ctrl == NULL) {
			return PSM2_NO_MEMORY;
		}

		ctrl->spio_reset_hfi = spio_reset_hfi;
		ctrl->spio_credit_return_update =
				spio_credit_return_update;
	} else {
		ctrl->spio_reset_hfi = spio_reset_hfi_shared;
		ctrl->spio_credit_return_update =
				spio_credit_return_update_shared;
	}

	/*
	 * Only the master process can initialize.
	 */
	if (psmi_hal_get_subctxt(context->psm_hw_ctxt) == 0) {
		pthread_spin_init(&ctrl->spio_ctrl->spio_ctrl_lock,
					PTHREAD_PROCESS_SHARED);

		ctrl->spio_ctrl->spio_write_in_progress = 0;
		ctrl->spio_ctrl->spio_reset_count = 0;
		ctrl->spio_ctrl->spio_frozen_count = 0;

		ctrl->spio_ctrl->spio_available_blocks =
				ctrl->spio_total_blocks;
		ctrl->spio_ctrl->spio_block_index = 0;
		ctrl->spio_ctrl->spio_fill_counter = 0;

		psmi_assert(SPIO_CREDITS_Counter
			    (ctrl->spio_ctrl->spio_credits.value) == 0);
		psmi_assert(SPIO_CREDITS_Status
			    (ctrl->spio_ctrl->spio_credits.value) == 0);

		ctrl->spio_ctrl->spio_credits.credit_return =
				*ctrl->spio_credits_addr;
	}

	/*
	 * Setup the PIO block copying routines.
	 */

	get_cpuid(0x1, 0, &id);

	/* 16B copying supported */
	ctrl->spio_blockcpy_med = (id.edx & (1<<SSE2_BIT)) ?
		hfi_pio_blockcpy_128 : hfi_pio_blockcpy_64;

	get_cpuid(0x7, 0, &id);

	/* 32B copying supported */
	ctrl->spio_blockcpy_large = (id.ebx & (1<<AVX2_BIT)) ?
		hfi_pio_blockcpy_256 : ctrl->spio_blockcpy_med;

#ifdef PSM_AVX512
	/* 64B copying supported */
	ctrl->spio_blockcpy_large = (is_avx512_enabled && (id.ebx & (1<<AVX512F_BIT))) ?
		hfi_pio_blockcpy_512 : ctrl->spio_blockcpy_large;

#endif


#ifdef PSM_CUDA
	ctrl->cuda_pio_buffer = NULL;
#endif

	_HFI_PRDBG("ips_spio_init() done\n");

	return PSM2_OK;
}

static PSMI_HAL_INLINE psm2_error_t ips_spio_fini(struct ips_spio *ctrl)
{
#ifdef PSM_CUDA
	if (PSMI_IS_CUDA_ENABLED && ctrl->cuda_pio_buffer != NULL)
		PSMI_CUDA_CALL(cuMemFreeHost, (void *) ctrl->cuda_pio_buffer);
#endif
	spio_report_stall(ctrl, get_cycles(), 0ULL);
	if (!ctrl->context->spio_ctrl)
		psmi_free((void *)ctrl->spio_ctrl);
	return PSM2_OK;
}

static PSMI_HAL_INLINE
void
spio_report_stall(struct ips_spio *ctrl, uint64_t t_cyc_now,
		  uint64_t send_failures)
{
	size_t off = 0;
	char buf[1024];

	if (ctrl->spio_num_stall == 0)
		return;

	if (send_failures > 0) {
		char bufctr[128];
		uint64_t tx_stat, rx_stat;
		int ret;

		off = snprintf(buf, sizeof(buf) - 1,
			       "PIO Send context %d with total blocks %d , available blocks %d, "
			       "fill counter %d, free counter %d ",
			       (int)psm2_epid_context(ctrl->context->epid),
			       ctrl->spio_total_blocks,
			       ctrl->spio_ctrl->spio_available_blocks,
			       ctrl->spio_ctrl->spio_fill_counter,
			       SPIO_CREDITS_Counter(ctrl->spio_ctrl->
						    spio_credits.value));
		buf[off] = '\0';

		/* In case hfifs isn't running */
		ret = hfi_get_single_portctr(ctrl->unit_id, ctrl->portnum,
					     "TxPkt", &tx_stat);
		if (ret != -1) {
			ret = hfi_get_single_portctr(ctrl->unit_id,
						     ctrl->portnum, "RxPkt",
						     &rx_stat);
			if (ret != -1) {
				snprintf(bufctr, sizeof(bufctr) - 1,
					 "(TxPktCnt=%llu,RxPktCnt=%llu)",
					 (unsigned long long)tx_stat,
					 (unsigned long long)rx_stat);
				bufctr[sizeof(bufctr) - 1] = '\0';
			} else
				bufctr[0] = '\0';
		} else
			bufctr[0] = '\0';

		_HFI_DBG
		    ("PIO Send Stall after at least %.2fM failed send attempts "
		     "(elapsed=%.3fs, last=%.3fs, pio_stall_count=%lld) %s %s\n",
		     send_failures / 1e6,
		     PSMI_CYCLES_TO_SECSF(t_cyc_now - ctrl->spio_init_cyc),
		     PSMI_CYCLES_TO_SECSF(t_cyc_now -
					  ctrl->spio_last_stall_cyc),
		     (unsigned long long)ctrl->spio_num_stall,
		     bufctr[0] != '\0' ? bufctr : "", buf);
	} else {
		_HFI_DBG
		    ("PIO Send Stall Summary: count=%llu, last=%.3fs, elapsed=%.3fs",
		     (unsigned long long)ctrl->spio_num_stall,
		     PSMI_CYCLES_TO_SECSF(t_cyc_now - ctrl->spio_init_cyc),
		     PSMI_CYCLES_TO_SECSF(t_cyc_now -
					  ctrl->spio_last_stall_cyc));
	}

	return;
}

static PSMI_HAL_INLINE void spio_handle_stall(struct ips_spio *ctrl, uint64_t send_failures)
{
	uint64_t t_cyc_now = get_cycles();

	/* We handle the pio-stall every time but only report something every 20
	 * seconds.  We print a summary at the end while closing the device */
	ctrl->spio_num_stall++;
	ctrl->spio_num_stall_total++;

	if (ctrl->spio_next_stall_warning <= t_cyc_now) {
		/* If context status is ok (i.e. no cables pulled or anything) */
		if (psmi_context_check_status(ctrl->context) == PSM2_OK)
			spio_report_stall(ctrl, t_cyc_now, send_failures);
		ctrl->spio_next_stall_warning =
		    get_cycles() + SPIO_STALL_WARNING_INTERVAL;
	}

	/* re-initialize our shadow from the real registers; by this time,
	 * we know the hardware has to have done the update.
	 * Also, kernel check may have changed things.
	 */
	ctrl->spio_credit_return_update(ctrl);

	ctrl->spio_last_stall_cyc = t_cyc_now;

	return;
}

/*
 * A send context halt is detected in several ways:
 * 1. during pio for normal credit return update;
 * 2. during events process when no event;
 * when a hfi is frozen, we recover hfi by calling this routine.
 */
static PSMI_HAL_INLINE void spio_reset_context(struct ips_spio *ctrl)
{
	/* if there are too many reset, teardown process */
	ctrl->spio_ctrl->spio_reset_count++;
	if (ctrl->spio_ctrl->spio_reset_count > IPS_CTXT_RESET_MAX)
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
			"Too many send context reset, teardown...\n");

	/*
	 * Because there are many epaddrs and many flows using the
	 * same PIO queue, it is hard to search all the unacked
	 * queue and find the correct retry point. Instead we just
	 * let the upper level flow control to NAK the packets and
	 * do the retry from the right point.
	 */

	/* Call into driver to reset send context, driver will
	 * block this routine until the send context is actually
	 * reset.
	 */
	ips_wmb();
	if (psmi_hal_hfi_reset_context(ctrl->context->psm_hw_ctxt))
		psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
			"Send context reset failed: %d.\n", errno);

	/* Reset spio shared control struct. */
	ctrl->spio_ctrl->spio_available_blocks =
			ctrl->spio_total_blocks;
	ctrl->spio_ctrl->spio_block_index = 0;
	ctrl->spio_ctrl->spio_fill_counter = 0;
	/* Get updated credit return again after reset. */
	ctrl->spio_ctrl->spio_credits.credit_return =
			*ctrl->spio_credits_addr;

	psmi_assert(SPIO_CREDITS_Counter
			(ctrl->spio_ctrl->spio_credits.value) == 0);
	psmi_assert(SPIO_CREDITS_Status
			(ctrl->spio_ctrl->spio_credits.value) == 0);
}

/*
 * hfi frozen is detected when checking events from driver,
 * psm calls to check events in the main receive loop
 * when there is no normal traffic.
 */
static PSMI_HAL_INLINE void spio_reset_hfi_internal(struct ips_spio *ctrl)
{
	struct ips_recvhdrq *recvq = &((struct ptl_ips *)(ctrl->ptl))->recvq;
	struct ips_proto *proto = (struct ips_proto *)&((struct ptl_ips *)(ctrl->ptl))->proto;

	/* Reset receive queue state, this must be done first
	 * because after send context reset, hardware start to
	 * receive new packets.
	 */
	recvq->state->hdrq_head = 0;
	recvq->state->rcv_egr_index_head = NO_EAGER_UPDATE;
	recvq->state->num_hdrq_done = 0;
	recvq->state->hdr_countdown = 0;

	/* set the expected sequence number to 1. */
	if (!(get_psm_gen1_hi()->hfp_private.dma_rtail))
		psmi_hal_set_rhf_expected_sequence_number(1, recvq->psm_hal_cl_hdrq,
							  ((struct ptl_ips *)proto->ptl)->context->psm_hw_ctxt);

	/* Reset send context */
	spio_reset_context(ctrl);

	/* Reset sdma completion queue, this should be done last
	 * because when send context is reset, driver will complete
	 * all the sdma requests with error code -2. This error
	 * code is ignored by PSM, but other error codes are
	 * caught inside the routine.
	 */
	while (proto->sdma_done_index != proto->sdma_fill_index)
		ips_proto_dma_completion_update(proto);
}

static PSMI_HAL_INLINE psm2_error_t spio_reset_hfi(struct ips_spio *ctrl)
{
	/* Drain receive header queue before reset hfi, we use
	 * the main progression loop to do this so we return from
	 * here.
	 */
	if (!ips_recvhdrq_isempty(&((struct ptl_ips *)(ctrl->ptl))->recvq))
		return PSM2_OK_NO_PROGRESS;

	/* do the real reset work:
	 * 1. reset receive header queue;
	 * 2. reset send context;
	 * 3. dain sdma completion queue;
	 */
	spio_reset_hfi_internal(ctrl);

	return PSM2_OK;
}

/*
 * There is a shared count and per process count, all initialized to
 * zero. If a process' local count is equal to shared count, it is
 * the first process and does the hfi reset, this process also move
 * both counts up by one. If a process' local count is not equal to
 * the shared count, it means other process has done the hfi reset,
 * it just saves the shared count to local count and return. All the
 * operation are locked by spio_ctrl_lock.
 */
static PSMI_HAL_INLINE psm2_error_t spio_reset_hfi_shared(struct ips_spio *ctrl)
{
	volatile struct ips_spio_ctrl *spio_ctrl = ctrl->spio_ctrl;

	/* Drain receive header queue before reset hfi, we use
	 * the main progression loop to do this so we return from
	 * here. We don't reset software receive header queue.
	 */
	if (!ips_recvhdrq_isempty(&((struct ptl_ips *)(ctrl->ptl))->recvq))
		return PSM2_OK_NO_PROGRESS;

	pthread_spin_lock(&spio_ctrl->spio_ctrl_lock);

	/*
	 * In context sharing mode, if there is a subcontext
	 * process in PIO writing, we need to wait till the PIO
	 * writing is done. So we spin wait here. If other
	 * process comes here and does the hfi reset, it should
	 * be perfectly fine.
	 */
	while (ctrl->spio_ctrl->spio_write_in_progress) {
		pthread_spin_unlock(&spio_ctrl->spio_ctrl_lock);
		usleep(1000);
		pthread_spin_lock(&spio_ctrl->spio_ctrl_lock);
	}

	if (ctrl->spio_frozen_count == ctrl->spio_ctrl->spio_frozen_count) {
		ctrl->spio_frozen_count++;
		ctrl->spio_ctrl->spio_frozen_count++;

		spio_reset_hfi_internal(ctrl);
	} else
		ctrl->spio_frozen_count = ctrl->spio_ctrl->spio_frozen_count;

	pthread_spin_unlock(&spio_ctrl->spio_ctrl_lock);

	return PSM2_OK;
}

/*
 * return value:
 * PSM2_OK: new credits updated;
 * PSM2_OK_NO_PROGRESS: no new credits;
 */
static PSMI_HAL_INLINE psm2_error_t
spio_credit_return_update(struct ips_spio *ctrl)
{
	uint64_t credit_return;

	credit_return = *ctrl->spio_credits_addr;
	/* Update available blocks based on fill counter and free counter */
	if (ctrl->spio_ctrl->spio_credits.credit_return == credit_return)
		return PSM2_OK_NO_PROGRESS;

	ctrl->spio_ctrl->spio_credits.credit_return = credit_return;

	/* If Status is set, then send context is halted */
	if (SPIO_CREDITS_Status(ctrl->spio_ctrl->spio_credits.value)) {
		spio_reset_context(ctrl);
	} else {
		/*
		 * OPA1 has 1M PIO buffer, but each context can have max 64K,
		 * which is 1K 64B blocks, so the distance between fill counter
		 * and credit return counter is no more than 1024; Both fill
		 * counter and credit return counter are 11 bits value,
		 * representing range [0, 2047].
		 */
		psmi_assert((ctrl->spio_ctrl->spio_available_blocks +
			((ctrl->spio_ctrl->spio_fill_counter -
			SPIO_CREDITS_Counter(ctrl->spio_ctrl->spio_credits.
					    value)) & 0x7FF)) <=
			ctrl->spio_total_blocks);
		ctrl->spio_ctrl->spio_available_blocks =
			ctrl->spio_total_blocks -
			((ctrl->spio_ctrl->spio_fill_counter -
			SPIO_CREDITS_Counter(ctrl->spio_ctrl->spio_credits.
					   value)) & 0x7FF);

		/* a successful credit update, clear reset count */
		ctrl->spio_ctrl->spio_reset_count = 0;
	}

	return PSM2_OK;
}

/*
 * return value:
 * PSM2_OK: new credits updated;
 * PSM2_OK_NO_PROGRESS: no new credits;
 */
static PSMI_HAL_INLINE psm2_error_t
spio_credit_return_update_shared(struct ips_spio *ctrl)
{
	uint64_t credit_return;

	pthread_spin_lock(&ctrl->spio_ctrl->spio_ctrl_lock);

	credit_return = *ctrl->spio_credits_addr;
	/* Update available blocks based on fill counter and free counter */
	if (ctrl->spio_ctrl->spio_credits.credit_return == credit_return) {
		pthread_spin_unlock(&ctrl->spio_ctrl->spio_ctrl_lock);
		return PSM2_OK_NO_PROGRESS;
	}

	ctrl->spio_ctrl->spio_credits.credit_return = credit_return;

	/* If Status is set, then send context is halted */
	if (SPIO_CREDITS_Status(ctrl->spio_ctrl->spio_credits.value)) {
		/*
		 * In context sharing mode, if there is a subcontext
		 * process in PIO writing, we need to wait till the PIO
		 * writing is done. So we spin wait here. Other processes
		 * won't come here because for them, there is NO new
		 * credit return change (the first 'if' check in this
		 * routine).
		 */
		while (ctrl->spio_ctrl->spio_write_in_progress) {
			pthread_spin_unlock(&ctrl->spio_ctrl->spio_ctrl_lock);
			usleep(1000);
			pthread_spin_lock(&ctrl->spio_ctrl->spio_ctrl_lock);
		}

		spio_reset_context(ctrl);
	} else {
		/*
		 * OPA1 has 1M PIO buffer, but each context can have max 64K,
		 * which is 1K 64B blocks, so the distance between fill counter
		 * and credit return counter is no more than 1024; Both fill
		 * counter and credit return counter are 11 bits value,
		 * representing range [0, 2047].
		 */
		psmi_assert((ctrl->spio_ctrl->spio_available_blocks +
			((ctrl->spio_ctrl->spio_fill_counter -
			SPIO_CREDITS_Counter(ctrl->spio_ctrl->spio_credits.
					    value)) & 0x7FF)) <=
			ctrl->spio_total_blocks);
		ctrl->spio_ctrl->spio_available_blocks =
			ctrl->spio_total_blocks -
			((ctrl->spio_ctrl->spio_fill_counter -
			SPIO_CREDITS_Counter(ctrl->spio_ctrl->spio_credits.
					   value)) & 0x7FF);

		/* a successful credit update, clear reset count */
		ctrl->spio_ctrl->spio_reset_count = 0;
	}

	pthread_spin_unlock(&ctrl->spio_ctrl->spio_ctrl_lock);

	return PSM2_OK;
}

/*
 * Check and process events
 * return value:
 *  PSM2_OK: normal events processing;
 *  PSM2_OK_NO_PROGRESS: no event is processed;
 */
static PSMI_HAL_INLINE psm2_error_t
ips_spio_process_events(const struct ptl *ptl_gen)
{
	struct ptl_ips *ptl = (struct ptl_ips *)ptl_gen;
	struct ips_spio *ctrl = ptl->proto.spioc;
	uint64_t event_mask;
	int rc = psmi_hal_get_hfi_event_bits(&event_mask,ctrl->context->psm_hw_ctxt);

	if (rc)
		return PSM2_OK_NO_PROGRESS;

	/*
	 * If there is no event, try do credit return update
	 * to catch send context halt.
	 */
	if_pf(event_mask == 0)
		return ctrl->spio_credit_return_update(ctrl);

	/*
	 * Process mmu invalidation event, this will invalidate
	 * all caching items removed by mmu notifier.
	 */
	if (event_mask & PSM_HAL_HFI_EVENT_TID_MMU_NOTIFY) {
		/*
		 * driver will clear the event bit before return,
		 * PSM does not need to ack the event.
		 */
		return ips_tidcache_invalidation(&ptl->proto.protoexp->tidc);
	}

	/* Check if HFI is frozen */
	if (event_mask & PSM_HAL_HFI_EVENT_FROZEN) {
		/* if no progress, return and retry */
		if (ctrl->spio_reset_hfi(ctrl) != PSM2_OK)
			return PSM2_OK_NO_PROGRESS;
	}

	/* First ack the driver the receipt of the events */
	_HFI_VDBG("Acking event(s) 0x%" PRIx64 " to qib driver.\n",
		  (uint64_t) event_mask);

	psmi_hal_ack_hfi_event(event_mask, ctrl->context->psm_hw_ctxt);

	if (event_mask & PSM_HAL_HFI_EVENT_LINKDOWN) {
		/* A link down event can clear the LMC and SL2VL
		 * change as those events are implicitly handled
		 * in the link up/down event handler.
		 */
		event_mask &=
			    ~(PSM_HAL_HFI_EVENT_LMC_CHANGE |
				PSM_HAL_HFI_EVENT_SL2VL_CHANGE);
		ips_ibta_link_updown_event(&((struct ptl_ips *)(ctrl->ptl))->proto);
		_HFI_VDBG("Link down detected.\n");
	}

	if (event_mask & PSM_HAL_HFI_EVENT_LID_CHANGE) {
		/* Display a warning that LID change has occurred during
		 * the run. This is not supported in the current
		 * implementation and in general is bad for the SM to
		 * re-assign LIDs during a run.
		 */
		_HFI_INFO
		    ("Warning! LID change detected during run. "
			"Old LID: %d, New Lid: %d\n",
		     (int)PSMI_EPID_GET_LID(ctrl->context->epid),
		     (int)psmi_hal_get_port_lid(ctrl->unit_id,
					   ctrl->portnum));
	}

	if (event_mask & PSM_HAL_HFI_EVENT_LMC_CHANGE)
			_HFI_INFO("Fabric LMC changed.\n");

	if (event_mask & PSM_HAL_HFI_EVENT_SL2VL_CHANGE) {
		_HFI_INFO("SL2VL mapping changed for port.\n");
		ips_ibta_init_sl2sc_table(&((struct ptl_ips *)(ctrl->ptl))->proto);
	}

	return PSM2_OK;
}

static PSMI_HAL_INLINE void
spio_handle_resync(struct ips_spio *ctrl, uint64_t consecutive_send_failed)
{
	/* hfi_force_pio_avail_update(ctrl->context->ctrl); */

	if (!(consecutive_send_failed & (SPIO_MAX_CONSECUTIVE_SEND_FAIL - 1)))
		spio_handle_stall(ctrl, consecutive_send_failed);
}

/*
 * This function attempts to write a packet to a PIO.
 *
 * Recoverable errors:
 * PSM2_OK: Packet triggered through PIO.
 * PSM2_EP_NO_RESOURCES: No PIO bufs available or cable pulled.
 *
 * Unrecoverable errors:
 * PSM2_EP_NO_NETWORK: No network, no lid, ...
 * PSM2_EP_DEVICE_FAILURE: Chip failures, rxe/txe parity, etc.
 */
static inline psm2_error_t
ips_spio_transfer_frame(struct ips_proto *proto, struct ips_flow *flow,
			struct psm_hal_pbc *pbc, uint32_t *payload,
			uint32_t length, uint32_t isCtrlMsg,
			uint32_t cksum_valid, uint32_t cksum
#ifdef PSM_CUDA
			, uint32_t is_cuda_payload
#endif
			)
{
	struct ips_spio *ctrl = proto->spioc;
	volatile struct ips_spio_ctrl *spio_ctrl = ctrl->spio_ctrl;
	volatile uint64_t *pioaddr;
	uint32_t paylen, nblks;
	psm2_error_t err = PSM2_OK;
	int do_lock = psmi_hal_has_sw_status(PSM_HAL_PSMI_RUNTIME_RX_THREAD_STARTED);

	if (do_lock)
		pthread_spin_lock(&ctrl->spio_lock);

#ifdef PSM_FI
	if_pf(PSMI_FAULTINJ_ENABLED()) {
		PSMI_FAULTINJ_STATIC_DECL(fi_lost, "piosend", 1,
					  IPS_FAULTINJ_PIOLOST);
		PSMI_FAULTINJ_STATIC_DECL(fi_busy, "piobusy", 1,
					  IPS_FAULTINJ_PIOBUSY);
		if (psmi_faultinj_is_fault(fi_lost)) {
			if (do_lock)
				pthread_spin_unlock(&ctrl->spio_lock);
			return PSM2_OK;
		} else if (psmi_faultinj_is_fault(fi_busy))
			goto fi_busy;
		/* else fall through normal processing path, i.e. no faults */
	}
#endif /* #ifdef PSM_FI */

	psmi_assert((length & 0x3) == 0);
	paylen = length + (cksum_valid ? PSM_CRC_SIZE_IN_BYTES : 0);
	nblks = 1 + ((paylen + 63) >> 6);

	if (spio_ctrl->spio_available_blocks < nblks) {
		ctrl->spio_credit_return_update(ctrl);

		if_pf(spio_ctrl->spio_available_blocks < nblks) {
			/* Check unit status */
#ifdef PSM_FI
fi_busy:
#endif /* #ifdef PSM_FI */
			if ((err =
			     psmi_context_check_status(ctrl->context)) ==
			    PSM2_OK) {
				if (0 ==
				    (++ctrl->
				     spio_consecutive_failures &
				     (SPIO_RESYNC_CONSECUTIVE_SEND_FAIL - 1)))
					spio_handle_resync(ctrl,
							   ctrl->
							   spio_consecutive_failures);
				err = PSM2_EP_NO_RESOURCES;
			}
			/* If cable is pulled, we don't count it as a consecutive failure,
			 * we just make it as though no send pio was available */
			else if (err == PSM2_OK_NO_PROGRESS)
				err = PSM2_EP_NO_RESOURCES;
			/* else something bad happened in check_status */
			if (do_lock)
				pthread_spin_unlock(&ctrl->spio_lock);
			return err;
		}
	}

	/*
	 * if context->spio_ctrl is set, it is pointing to shared context ureg
	 * page, and we are using context sharing.
	 */
	if (ctrl->context->spio_ctrl) {
		pthread_spin_lock(&spio_ctrl->spio_ctrl_lock);
		if (spio_ctrl->spio_available_blocks < nblks) {
			pthread_spin_unlock(&spio_ctrl->spio_ctrl_lock);

			if (do_lock)
				pthread_spin_unlock(&ctrl->spio_lock);
			return PSM2_EP_NO_RESOURCES;
		}
	}

	_HFI_VDBG("credits: total %d, avail %d index %d, fill %d "
		  "free %d: %d %d %d %d %d; addr %llx\n",
		  ctrl->spio_total_blocks,
		  spio_ctrl->spio_available_blocks,
		  spio_ctrl->spio_block_index,
		  spio_ctrl->spio_fill_counter,
		  SPIO_CREDITS_Counter(spio_ctrl->spio_credits.value),
		  SPIO_CREDITS_Status(spio_ctrl->spio_credits.value),
		  SPIO_CREDITS_DueToPbc(spio_ctrl->spio_credits.value),
		  SPIO_CREDITS_DueToTheshold(spio_ctrl->spio_credits.value),
		  SPIO_CREDITS_DueToErr(spio_ctrl->spio_credits.value),
		  SPIO_CREDITS_DueToForce(spio_ctrl->spio_credits.value),
		  *ctrl->spio_credits_addr);

	/*
	 * Save the assigned locally, update the shared for other processes.
	 */
	ctrl->spio_block_index = spio_ctrl->spio_block_index;
	spio_ctrl->spio_available_blocks -= nblks;
	/* fill counter should be 11 bits value, same as credit return counter */
	spio_ctrl->spio_fill_counter =
	    (spio_ctrl->spio_fill_counter + nblks) & 0x7FF;
	spio_ctrl->spio_block_index += nblks;
	if (spio_ctrl->spio_block_index >= ctrl->spio_total_blocks)
		spio_ctrl->spio_block_index -= ctrl->spio_total_blocks;

	/*
	 * Unlock in context sharing mode, but increase refcount to
	 * indicate I am in progress to write to PIO blocks.
	 */
	if (ctrl->context->spio_ctrl) {
		spio_ctrl->spio_write_in_progress++;
		pthread_spin_unlock(&spio_ctrl->spio_ctrl_lock);
	}

	ctrl->spio_num_stall = 0;	/* now able to send, so clear if set */
	ctrl->spio_consecutive_failures = 0;
	if (do_lock)
		pthread_spin_unlock(&ctrl->spio_lock);

	_HFI_VDBG("PIO write: nblks %d length %d, paylen %d\n", nblks, length,
		  paylen);

	/* Setup PBC for this packet */
	ips_proto_pbc_update(proto, flow, isCtrlMsg,
			     pbc, sizeof(struct ips_message_header), paylen);

	/* Write to PIO: SOP block */
	pioaddr = ctrl->spio_bufbase_sop + ctrl->spio_block_index * 8;
	if (++ctrl->spio_block_index == ctrl->spio_total_blocks)
		ctrl->spio_block_index = 0;

	ctrl->spio_blockcpy_med(pioaddr, (uint64_t *) pbc, 1);
	_HFI_VDBG("pio qw write sop %p: 8\n", pioaddr);

	/* Write to PIO: other blocks of payload */
#ifdef PSM_CUDA
	if (is_cuda_payload) {
		if (ctrl->cuda_pio_buffer == NULL) {
			PSMI_CUDA_CALL(cuMemHostAlloc, (void **) &ctrl->cuda_pio_buffer,
							MAX_CUDA_MTU, CU_MEMHOSTALLOC_PORTABLE);
		}
		/* Since the implementation of cuMemcpy is unknown,
		   and the HFI specifies several conditions for how PIO
		   writes must occur, for safety reasons we should not assume
		   that cuMemcpy will follow the HFI's requirements.
		   The cuMemcpy should instead write into a buffer in
		   host memory, and then PSM can copy to the HFI as usual. */
		PSMI_CUDA_CALL(cuMemcpyDtoH, ctrl->cuda_pio_buffer,
			       (CUdeviceptr)payload, paylen);
		payload = (uint32_t *) ctrl->cuda_pio_buffer;
	}
#endif
	if (length >= 64) {

		ips_spio_blockcpy_fn_t blockcpy_fn;
		if (length >= 256) {
			blockcpy_fn = ctrl->spio_blockcpy_large;
		}
		else {
			blockcpy_fn = ctrl->spio_blockcpy_med;
		}

		uint32_t blks2send = length >> 6;
		uint32_t blks2end =
			ctrl->spio_total_blocks - ctrl->spio_block_index;

		pioaddr = ctrl->spio_bufbase + ctrl->spio_block_index * 8;
		if (blks2end >= blks2send) {
			blockcpy_fn(pioaddr,
					(uint64_t *)payload, blks2send);
			_HFI_VDBG("pio blk write %p: %d\n",
					pioaddr, blks2send);
			ctrl->spio_block_index += blks2send;
			if (ctrl->spio_block_index == ctrl->spio_total_blocks)
				ctrl->spio_block_index = 0;
			payload += blks2send*16;
		} else {
			blockcpy_fn(pioaddr,
					(uint64_t *)payload, blks2end);
			_HFI_VDBG("pio blk write %p: %d\n",
					pioaddr, blks2end);
			payload += blks2end*16;

			pioaddr = ctrl->spio_bufbase;
			blockcpy_fn(pioaddr,
				    (uint64_t *)payload, (blks2send-blks2end));
			_HFI_VDBG("pio blk write %p: %d\n",
					pioaddr, (blks2send-blks2end));
			ctrl->spio_block_index = blks2send - blks2end;
			payload += (blks2send-blks2end)*16;
		}

		length -= blks2send*64;
	}

	/*
	 * The following code makes sure to write to pioaddr in
	 * qword granularity, this is required by hardware.
	 */
	paylen = length + (cksum_valid ? PSM_CRC_SIZE_IN_BYTES : 0);
	if (paylen > 0) {
		uint32_t blkbuf[32];
		uint32_t qws = length >> 3;
		uint32_t dws = 0;

		pioaddr = ctrl->spio_bufbase + ctrl->spio_block_index * 8;
		if (++ctrl->spio_block_index == ctrl->spio_total_blocks)
			ctrl->spio_block_index = 0;

		/* Write the remaining qwords of payload */
		if (qws) {
			hfi_qwordcpy_safe(pioaddr, (uint64_t *) payload, qws);
			_HFI_VDBG("pio qw write %p: %d\n", pioaddr, qws);
			payload += qws << 1;
			length -= qws << 3;

			pioaddr += qws;
			paylen -= qws << 3;
		}

		/* if we have last one dword payload */
		if (length > 0) {
			blkbuf[dws++] = payload[0];
		}
		/* if we have checksum to attach */
		if (paylen > length) {
			blkbuf[dws++] = cksum;
			blkbuf[dws++] = cksum;
		}

		/* Write the rest of qwords of current block */
		hfi_qwordcpy_safe(pioaddr, (uint64_t *) blkbuf, 8 - qws);
		_HFI_VDBG("pio qw write %p: %d\n", pioaddr, 8 - qws);

		if (paylen > ((8 - qws) << 3)) {
			/* We need another block */
			pioaddr =
			    ctrl->spio_bufbase + ctrl->spio_block_index * 8;
			if (++ctrl->spio_block_index == ctrl->spio_total_blocks)
				ctrl->spio_block_index = 0;

			/* Write the last block */
			hfi_qwordcpy_safe(pioaddr,
					  (uint64_t *) &blkbuf[(8 - qws) << 1],
					  8);
			_HFI_VDBG("pio qw write %p: %d\n", pioaddr, 8);
		}
	}
	/*
	 * In context sharing, we need to track who is in progress of
	 * writing to PIO block, this is for halted send context reset.
	 * I am done with PIO blocks writing, decrease the refcount.
	 */
	if (ctrl->context->spio_ctrl) {
		pthread_spin_lock(&spio_ctrl->spio_ctrl_lock);
		spio_ctrl->spio_write_in_progress--;
		pthread_spin_unlock(&spio_ctrl->spio_ctrl_lock);
	}

	return err;
}				/* ips_spio_transfer_frame() */
