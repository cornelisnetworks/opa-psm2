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
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

psm2_error_t
ips_tid_init(const psmi_context_t *context, struct ips_protoexp *protoexp,
	     ips_tid_avail_cb_fn_t cb, void *cb_context)
{
	const struct hfi1_user_info *user_info = &context->user_info;
	const struct hfi1_base_info *base_info = &context->ctrl->base_info;
	const struct hfi1_ctxt_info *ctxt_info = &context->ctrl->ctxt_info;
	struct ips_tid *tidc = &protoexp->tidc;

	struct psmi_stats_entry entries[] = {
		PSMI_STATS_DECL("tid update count", MPSPAWN_STATS_REDUCTION_ALL,
				NULL, &tidc->tid_num_total),
	};

	tidc->context = context;
	tidc->protoexp = protoexp;
	tidc->tid_num_total = 0;
	tidc->tid_num_inuse = 0;
	tidc->tid_avail_cb = cb;
	tidc->tid_avail_context = cb_context;
	tidc->tid_array = NULL;
	tidc->invalidation_event = (uint64_t *)
		(ptrdiff_t) base_info->events_bufbase;

	/*
	 * PSM uses tid registration caching only if driver has enabled it.
	 */
	if (!(tidc->context->runtime_flags & HFI1_CAP_TID_UNMAP)) {
		int i;
		cl_qmap_t *p_map;

		tidc->tid_array = (uint32_t *)
			psmi_calloc(context->ep, UNDEFINED,
				context->ctrl->__hfi_tidexpcnt,
				sizeof(uint32_t));
		if (tidc->tid_array == NULL)
			return PSM2_NO_MEMORY;

		/*
		 * first is root node, last is terminator node.
		 */
		p_map = &tidc->tid_cachemap;
		p_map->root = (cl_map_item_t *)
			psmi_calloc(context->ep, UNDEFINED,
				context->ctrl->__hfi_tidexpcnt + 2,
				sizeof(cl_map_item_t));
		if (p_map->root == NULL)
			return PSM2_NO_MEMORY;

		/* setup the RB tree map */
		p_map->nil_item = &p_map->root
			[context->ctrl->__hfi_tidexpcnt + 1];

		p_map->root->p_up = p_map->root;
		p_map->root->p_left = p_map->nil_item;
		p_map->root->p_right = p_map->nil_item;
		p_map->root->color = CL_MAP_BLACK;

		p_map->nil_item->p_up = p_map->nil_item;
		p_map->nil_item->p_left = p_map->nil_item;
		p_map->nil_item->p_right = p_map->nil_item;
		p_map->nil_item->color = CL_MAP_BLACK;

		NTID = 0;
		NIDLE = 0;
		IPREV(IHEAD) = INEXT(IHEAD) = IHEAD;
		for (i = 1; i <= context->ctrl->__hfi_tidexpcnt; i++) {
			INVALIDATE(i) = 1;
		}

		/*
		 * if not shared context, all tids are used by the same
		 * process. Otherwise, subcontext process can only cache
		 * its own portion. Driver makes the same tid number
		 * assignment to subcontext processes.
		 */
		tidc->tid_cachesize = context->ctrl->__hfi_tidexpcnt;
		if (user_info->subctxt_cnt > 0) {
			uint16_t remainder = tidc->tid_cachesize %
					user_info->subctxt_cnt;
			tidc->tid_cachesize /= user_info->subctxt_cnt;
			if (ctxt_info->subctxt < remainder)
				tidc->tid_cachesize++;
		}
	}

	/*
	 * Setup shared control structure.
	 */
	tidc->tid_ctrl = (struct ips_tid_ctrl *)context->tid_ctrl;
	if (!tidc->tid_ctrl) {
		tidc->tid_ctrl = (struct ips_tid_ctrl *)
		    psmi_calloc(context->ep, UNDEFINED, 1,
				sizeof(struct ips_tid_ctrl));
		if (tidc->tid_ctrl == NULL) {
			return PSM2_NO_MEMORY;
		}
	}

	/*
	 * Only the master process can initialize.
	 */
	if (ctxt_info->subctxt == 0) {
		pthread_spin_init(&tidc->tid_ctrl->tid_ctrl_lock,
					PTHREAD_PROCESS_SHARED);

		tidc->tid_ctrl->tid_num_max =
			    context->ctrl->__hfi_tidexpcnt;
		tidc->tid_ctrl->tid_num_avail = tidc->tid_ctrl->tid_num_max;
	}

	return psmi_stats_register_type(PSMI_STATS_NO_HEADING,
					PSMI_STATSTYPE_TIDS,
					entries,
					PSMI_STATS_HOWMANY(entries), tidc);
}

psm2_error_t ips_tid_fini(struct ips_tid *tidc)
{
	if (tidc->tid_array)
		ips_tidcache_cleanup(tidc);

	if (!tidc->context->tid_ctrl)
		psmi_free(tidc->tid_ctrl);

	return PSM2_OK;
}

psm2_error_t
ips_tid_acquire(struct ips_tid *tidc,
		const void *buf, uint32_t *length,
		uint32_t *tid_array, uint32_t *tidcnt)
{
	struct ips_tid_ctrl *ctrl = tidc->tid_ctrl;
	psm2_error_t err = PSM2_OK;
	int rc;

	psmi_assert(((uintptr_t) buf & 0xFFF) == 0);
	psmi_assert(((*length) & 0xFFF) == 0);

	if (tidc->context->tid_ctrl)
		pthread_spin_lock(&ctrl->tid_ctrl_lock);

	if (!ctrl->tid_num_avail) {
		err = PSM2_EP_NO_RESOURCES;
		goto fail;
	}

	rc = hfi_update_tid(tidc->context->ctrl,
		    (uint64_t) (uintptr_t) buf, length,
		    (uint64_t) (uintptr_t) tid_array, tidcnt);
	if (rc < 0) {
		/* Unable to pin pages? retry later */
		err = PSM2_EP_DEVICE_FAILURE;
		goto fail;
	}

	psmi_assert((*tidcnt) > 0);
	psmi_assert(ctrl->tid_num_avail >= (*tidcnt));
	ctrl->tid_num_avail -= (*tidcnt);
	tidc->tid_num_total += (*tidcnt);
	tidc->tid_num_inuse += (*tidcnt);

fail:
	if (tidc->context->tid_ctrl)
		pthread_spin_unlock(&ctrl->tid_ctrl_lock);

	return err;
}

psm2_error_t
ips_tid_release(struct ips_tid *tidc,
		uint32_t *tid_array, uint32_t tidcnt)
{
	struct ips_tid_ctrl *ctrl = tidc->tid_ctrl;
	psm2_error_t err = PSM2_OK;

	psmi_assert(tidcnt > 0);
	if (tidc->context->tid_ctrl)
		pthread_spin_lock(&ctrl->tid_ctrl_lock);

	if (hfi_free_tid(tidc->context->ctrl,
		    (uint64_t) (uintptr_t) tid_array, tidcnt) < 0) {
		if (tidc->context->tid_ctrl)
			pthread_spin_unlock(&ctrl->tid_ctrl_lock);

		/* If failed to unpin pages, it's fatal error */
		err = psmi_handle_error(tidc->context->ep,
			PSM2_EP_DEVICE_FAILURE,
			"Failed to tid free %d tids",
			tidcnt);
		goto fail;
	}

	ctrl->tid_num_avail += tidcnt;
	if (tidc->context->tid_ctrl)
		pthread_spin_unlock(&ctrl->tid_ctrl_lock);

	tidc->tid_num_inuse -= tidcnt;
	/* If an available callback is registered invoke it */
	if (((tidc->tid_num_inuse + tidcnt) == ctrl->tid_num_max)
	    && tidc->tid_avail_cb)
		tidc->tid_avail_cb(tidc, tidc->tid_avail_context);

fail:
	return err;
}
