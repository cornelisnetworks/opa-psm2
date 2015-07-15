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

#include "ips_subcontext.h"
#include "ips_spio.h"
#include "ips_tid.h"
#include "ips_tidflow.h"
#include "ptl_ips.h"

psm_error_t
ips_subcontext_ureg_get(ptl_t *ptl, uint32_t subcontext_cnt,
			psmi_context_t *context,
			struct ips_subcontext_ureg **uregp)
{
	const struct hfi1_base_info *base_info = &context->ctrl->base_info;
	uintptr_t all_subcontext_uregbase =
	    (uintptr_t) base_info->subctxt_uregbase;
	int i;

	psmi_assert_always(all_subcontext_uregbase != 0);
	for (i = 0; i < HFI1_MAX_SHARED_CTXTS; i++) {
		struct ips_subcontext_ureg *subcontext_ureg =
		    (struct ips_subcontext_ureg *)all_subcontext_uregbase;
		*uregp++ = (i < subcontext_cnt) ? subcontext_ureg : NULL;
		all_subcontext_uregbase += sizeof(struct ips_subcontext_ureg);
	}

	ptl->recvshc->hwcontext_ctrl =
	    (struct ips_hwcontext_ctrl *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_hwcontext_ctrl);

	context->spio_ctrl = (void *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_spio_ctrl);

	context->tid_ctrl = (void *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_tid_ctrl);

	context->tf_ctrl = (void *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_tf_ctrl);

	psmi_assert((all_subcontext_uregbase -
		     (uintptr_t) base_info->subctxt_uregbase) <= PSMI_PAGESIZE);

	return PSM_OK;
}
