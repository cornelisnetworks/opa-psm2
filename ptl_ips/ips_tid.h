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

/* included header files  */

#ifndef _IPS_TID_H
#define _IPS_TID_H

#include "psm_user.h"

struct ips_tid;

typedef void (*ips_tid_avail_cb_fn_t) (struct ips_tid *, void *context);

/* Each tid group(8 tids) needs a bit */
#define IPS_TID_MAX_TIDS    2048
typedef uint64_t ips_tidmap_t[IPS_TID_MAX_TIDS / 8 / 64];

struct ips_tid_ctrl {
	pthread_spinlock_t tid_ctrl_lock;
	uint32_t tid_num_max;
	uint32_t tid_num_avail;
} __attribute__ ((aligned(64)));

struct ips_tid {
	const psmi_context_t *context;
	ips_tid_avail_cb_fn_t tid_avail_cb;
	void *tid_avail_context;
	struct ips_tid_ctrl *tid_ctrl;

	uint64_t tid_num_total;
	uint32_t tid_num_inuse;
};

psm_error_t ips_tid_init(const psmi_context_t *context,
			 struct ips_tid *tidc,
			 ips_tid_avail_cb_fn_t cb, void *cb_context);
psm_error_t ips_tid_fini(struct ips_tid *tidc);

/* Acquiring tids.
 * Buffer base has to be aligned on page boundary
 * Buffer length has to be multiple pages
 */
psm_error_t ips_tid_acquire(struct ips_tid *tidc, const void *buf,	/* input buffer, aligned to page boundary */
			    uint32_t *len,	/* buffer length, aligned to page size */
			    uint32_t *tid_array,	/* output tidarray, */
			    uint32_t *num_tid,	/* output of tid count */
			    ips_tidmap_t tidmap);	/* output tidmap */

psm_error_t ips_tid_release(struct ips_tid *tidc, ips_tidmap_t tidmap,	/* input tidmap */
			    uint32_t ntids);	/* intput number of tids to release */
PSMI_INLINE(int ips_tid_num_available(struct ips_tid *tidc))
{
	if (tidc->tid_ctrl->tid_num_avail == 0) {
		if (tidc->tid_ctrl->tid_num_max == tidc->tid_num_inuse)
			return -1;
		else
			return 0;
	}

	return tidc->tid_ctrl->tid_num_avail;
}

#endif /* _IPS_TID_H */
