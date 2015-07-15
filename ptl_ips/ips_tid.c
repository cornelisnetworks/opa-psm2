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

#include "ips_tid.h"

psm_error_t ips_ptl_handle_check_unit_status(psm_ep_t ep, int ips_rc);

psm_error_t
ips_tid_init(const psmi_context_t *context,
	     struct ips_tid *tidc, ips_tid_avail_cb_fn_t cb, void *cb_context)
{
	const struct hfi1_ctxt_info *ctxt_info = &context->ctrl->ctxt_info;

	struct psmi_stats_entry entries[] = {
		PSMI_STATS_DECL("tid update count", MPSPAWN_STATS_REDUCTION_ALL,
				NULL, &tidc->tid_num_total),
	};

	tidc->context = context;
	/* these are in group unit, a group is 8 tids or 4 tidpairs */
	tidc->tid_num_total = 0;
	tidc->tid_num_inuse = 0;
	tidc->tid_avail_cb = cb;
	tidc->tid_avail_context = cb_context;

	tidc->tid_ctrl = (struct ips_tid_ctrl *)context->tid_ctrl;
	if (!tidc->tid_ctrl) {
		tidc->tid_ctrl = (struct ips_tid_ctrl *)
		    psmi_calloc(context->ep, UNDEFINED, 1,
				sizeof(struct ips_tid_ctrl));
		if (tidc->tid_ctrl == NULL) {
			return PSM_NO_MEMORY;
		}
	}

	/*
	 * Only the master process can initialize.
	 */
	if (ctxt_info->subctxt == 0) {
		pthread_spin_init(&tidc->tid_ctrl->tid_ctrl_lock,
					PTHREAD_PROCESS_SHARED);

		/* check if exp tids are multiple of 8 (a group) */
		if (context->ctrl->__hfi_tidexpcnt % 8)
			return psmi_handle_error(context->ep,
			      PSM_INTERNAL_ERR,
			      "Expected tids(%d) are not multi-groups(8)",
			      context->ctrl->__hfi_tidexpcnt);

		tidc->tid_ctrl->tid_num_max =
		    context->ctrl->__hfi_tidexpcnt >> 3;
		tidc->tid_ctrl->tid_num_avail = tidc->tid_ctrl->tid_num_max;
	}

	return psmi_stats_register_type(PSMI_STATS_NO_HEADING,
					PSMI_STATSTYPE_TIDS,
					entries,
					PSMI_STATS_HOWMANY(entries), tidc);
}

psm_error_t ips_tid_fini(struct ips_tid *tidc)
{
	if (!tidc->context->tid_ctrl)
		psmi_free(tidc->tid_ctrl);
	return PSM_OK;
}

psm_error_t
ips_tid_acquire(struct ips_tid *tidc,
		const void *buf, uint32_t *length,
		uint32_t *tid_array, uint32_t *tidcnt, ips_tidmap_t tid_map)
{
	struct ips_tid_ctrl *ctrl = tidc->tid_ctrl;
	psm_error_t err = PSM_OK;
	int ngrp;
	int rc;

	psmi_assert(((uintptr_t) buf & 0xFFF) == 0);
	psmi_assert(((*length) & 0xFFF) == 0);

	if (tidc->context->tid_ctrl)
		pthread_spin_lock(&ctrl->tid_ctrl_lock);

	if (!ctrl->tid_num_avail) {
		err = PSM_EP_NO_RESOURCES;
		goto fail;
	}

	rc = hfi_update_tid(tidc->context->ctrl,
			    (uint64_t) (uintptr_t) buf, length,
			    (uint64_t) (uintptr_t) tid_array, tidcnt,
			    (uint64_t) (uintptr_t) tid_map);
	if (rc != 0) {
		/* Unable to pin pages? retry later */
		err = PSM_EP_DEVICE_FAILURE;
		goto fail;
	}

	psmi_assert((*tidcnt) > 0);
	ngrp = ((*tidcnt) + 3) >> 2;
	psmi_assert(ctrl->tid_num_avail >= ngrp);
	ctrl->tid_num_avail -= ngrp;
	tidc->tid_num_total += ngrp;
	tidc->tid_num_inuse += ngrp;

fail:
	if (tidc->context->tid_ctrl)
		pthread_spin_unlock(&ctrl->tid_ctrl_lock);
	return err;
}

psm_error_t
ips_tid_release(struct ips_tid *tidc, ips_tidmap_t tidmap, uint32_t ntids)
{
	struct ips_tid_ctrl *ctrl = tidc->tid_ctrl;
	psm_error_t err = PSM_OK;
	int ngrp;

	psmi_assert(ntids > 0);
	if (tidc->context->tid_ctrl)
		pthread_spin_lock(&ctrl->tid_ctrl_lock);

	if (hfi_free_tid(tidc->context->ctrl, ntids,
			 (uint64_t) (uintptr_t) tidmap)) {
		if (tidc->context->tid_ctrl)
			pthread_spin_unlock(&ctrl->tid_ctrl_lock);

		/* If failed to unpin pages, it's fatal error */
		err = psmi_handle_error(tidc->context->ep,
			PSM_EP_DEVICE_FAILURE,
			"Failed to tid free %d tidpairs",
			ntids);
		goto fail;
	}
	ngrp = (ntids + 3) >> 2;
	ctrl->tid_num_avail += ngrp;
	if (tidc->context->tid_ctrl)
		pthread_spin_unlock(&ctrl->tid_ctrl_lock);

	tidc->tid_num_inuse -= ngrp;
	/* If an available callback is registered invoke it */
	if (((tidc->tid_num_inuse + ngrp) == ctrl->tid_num_max)
	    && tidc->tid_avail_cb)
		tidc->tid_avail_cb(tidc, tidc->tid_avail_context);

fail:
	return err;
}
