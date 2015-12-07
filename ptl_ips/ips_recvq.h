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

#ifndef _IPS_RECVQ_H
#define _IPS_RECVQ_H

#include "psm_user.h"

struct ips_recvq_params {
	volatile __le64 *tail_register;	/* location of tail */
	volatile __le64 *head_register;	/* location of head */
	uint32_t *base_addr;	/* base address of q */
	uint32_t elemsz;	/* size of q elements (in words) */
	uint32_t elemcnt;	/* num of q elements (in words) */
};

/*
 * Tables to map eager indexes into their buffer addresses
 *
 * If function returns NULL, no memory has been allocated and the error handler
 * has been executed on 'ep' and hence assume status PSM2_NO_MEMORY.
 */
void **ips_recvq_egrbuf_table_alloc(psm2_ep_t ep,
				    void *base, uint32_t bufnum,
				    uint32_t bufsize);
void ips_recvq_egrbuf_table_free(void **buftable);

/*
 * Accessor inlines for reading and writing to hdrq/egrq registers
 */
PSMI_ALWAYS_INLINE(
void *
ips_recvq_egr_index_2_ptr(void **egrq_buftable, int index, int offset))
{
	return (void *)((char *)egrq_buftable[index] + offset);
}

PSMI_INLINE(
void
ips_recvq_head_update(const struct ips_recvq_params *recvq, uint64_t newhead))
{
	*recvq->head_register = __cpu_to_le64(newhead);
	return;
}

PSMI_INLINE(
uint64_t
ips_recvq_head_get(const struct ips_recvq_params *recvq))
{
	uint64_t res = __le64_to_cpu(*recvq->head_register);
	ips_rmb();
	return res;
}

PSMI_INLINE(
void
ips_recvq_tail_update(const struct ips_recvq_params *recvq, uint64_t newtail))
{
	*recvq->tail_register = __cpu_to_le64(newtail);
	return;
}

PSMI_INLINE(
uint64_t
ips_recvq_tail_get(const struct ips_recvq_params *recvq))
{
	uint64_t res = __le64_to_cpu(*recvq->tail_register);
	ips_rmb();
	return res;
}

#endif /* _IPS_RECVQ_H */
