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

/* This file contains the initialization functions used by the low
   level hfi protocol code. */

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>

#include "valgrind/valgrind.h"
#include "valgrind/memcheck.h"

#include "ipserror.h"
#include "opa_user.h"

#include <sched.h>

#define ALIGN(x, a) (((x)+(a)-1)&~((a)-1))

/* It is allowed to have multiple devices (and of different types)
   simultaneously opened and initialized, although this (still! Oct 07)
   implemented.  This routine is used by the low level hfi protocol code (and
   any other code that has similar low level functionality).
   This is the only routine that takes a file descriptor, rather than an
   struct _hfi_ctrl *.  The struct _hfi_ctrl * used for everything
   else is returned as part of hfi1_base_info.
*/
struct _hfi_ctrl *hfi_userinit(int fd, struct hfi1_user_info *uinfo)
{
	struct _hfi_ctrl *spctrl = NULL;
	struct hfi1_ctxt_info *cinfo;
	struct hfi1_base_info *binfo;
	void *tmp;
	uint64_t *tmp64;
	struct hfi1_cmd c;
	uintptr_t pg_mask;
	int __hfi_pg_sz;

	/* First get the page size */
	__hfi_pg_sz = sysconf(_SC_PAGESIZE);
	pg_mask = ~(intptr_t) (__hfi_pg_sz - 1);

	if (!(spctrl = calloc(1, sizeof(struct _hfi_ctrl)))) {
		_HFI_INFO("can't allocate memory for hfi_ctrl: %s\n",
			  strerror(errno));
		goto err;
	}
	cinfo = &spctrl->ctxt_info;
	binfo = &spctrl->base_info;

	_HFI_VDBG("uinfo: ver %x, alg %d, subc_cnt %d, subc_id %d\n",
		  uinfo->userversion, uinfo->hfi1_alg,
		  uinfo->subctxt_cnt, uinfo->subctxt_id);

	/* 1. ask driver to assign context to current process */
	memset(&c, 0, sizeof(struct hfi1_cmd));
	c.type = HFI1_CMD_ASSIGN_CTXT;
	c.len = sizeof(*uinfo);
	c.addr = (__u64) uinfo;

	if (hfi_cmd_write(fd, &c, sizeof(c)) == -1) {
		_HFI_INFO("assign_context command failed: %s\n",
			  strerror(errno));
		goto err;
	}

	/* 2. get context info from driver */
	c.type = HFI1_CMD_CTXT_INFO;
	c.len = sizeof(*cinfo);
	c.addr = (__u64) cinfo;

	if (hfi_cmd_write(fd, &c, sizeof(c)) == -1) {
		_HFI_INFO("CTXT_INFO command failed: %s\n", strerror(errno));
		goto err;
	}

	/* sanity checking... */
	if (cinfo->rcvtids%8) {
		_HFI_INFO("rcvtids not 8 multiple: %d\n", cinfo->rcvtids);
		goto err;
	}
	if (cinfo->egrtids%8) {
		_HFI_INFO("egrtids not 8 multiple: %d\n", cinfo->egrtids);
		goto err;
	}
	if (cinfo->rcvtids < cinfo->egrtids) {
		_HFI_INFO("rcvtids(%d) < egrtids(%d)\n",
				cinfo->rcvtids, cinfo->egrtids);
		goto err;
	}
	if (cinfo->rcvhdrq_cnt%32) {
		_HFI_INFO("rcvhdrq_cnt not 32 multiple: %d\n",
				cinfo->rcvhdrq_cnt);
		goto err;
	}
	if (cinfo->rcvhdrq_entsize%64) {
		_HFI_INFO("rcvhdrq_entsize not 64 multiple: %d\n",
				cinfo->rcvhdrq_entsize);
		goto err;
	}
	if (cinfo->rcvegr_size%__hfi_pg_sz) {
		_HFI_INFO("rcvegr_size not page multiple: %d\n",
				cinfo->rcvegr_size);
		goto err;
	}

	_HFI_VDBG("ctxtinfo: runtime_flags %llx, rcvegr_size %d\n",
		  cinfo->runtime_flags, cinfo->rcvegr_size);
	_HFI_VDBG("ctxtinfo: active %d, unit %d, ctxt %d, subctxt %d\n",
		  cinfo->num_active, cinfo->unit, cinfo->ctxt, cinfo->subctxt);
	_HFI_VDBG("ctxtinfo: rcvtids %d, credits %d\n",
		  cinfo->rcvtids, cinfo->credits);
	_HFI_VDBG("ctxtinfo: numa %d, cpu %x, send_ctxt %d\n",
		  cinfo->numa_node, cinfo->rec_cpu, cinfo->send_ctxt);
	_HFI_VDBG("ctxtinfo: rcvhdrq_cnt %d, rcvhdrq_entsize %d\n",
		  cinfo->rcvhdrq_cnt, cinfo->rcvhdrq_entsize);
	_HFI_VDBG("ctxtinfo: egrtids %d, sdma_ring_size %d\n",
		  cinfo->egrtids, cinfo->sdma_ring_size);

	/* if affinity has not been setup, set it */
	if ((!getenv("HFI_NO_CPUAFFINITY") && cinfo->rec_cpu != (__u16) -1) ||
		getenv("HFI_FORCE_CPUAFFINITY")) {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(cinfo->rec_cpu, &cpuset);
		if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
			_HFI_INFO("Couldn't set runon processor %u "
				  "(unit:context %u:%u) (%u active chips): %s\n",
				  cinfo->rec_cpu, cinfo->unit, cinfo->ctxt,
				  cinfo->num_active, strerror(errno));
		}
	}

	/* 4. Get user base info from driver */
	c.type = HFI1_CMD_USER_INFO;
	c.len = sizeof(*binfo);
	c.addr = (__u64) binfo;

	if (hfi_cmd_write(fd, &c, sizeof(c)) == -1) {
		_HFI_INFO("BASE_INFO command failed: %s\n", strerror(errno));
		goto err;
	}

	_HFI_VDBG("baseinfo: hwver %x, swver %x, jkey %d, qp %d\n",
		  binfo->hw_version, binfo->sw_version,
		  binfo->jkey, binfo->bthqp);
	_HFI_VDBG("baseinfo: credit_addr %llx, sop %llx, pio %llx\n",
		  binfo->sc_credits_addr, binfo->pio_bufbase_sop,
		  binfo->pio_bufbase);
	_HFI_VDBG("baseinfo: hdrbase %llx, egrbase %llx, sdmabase %llx\n",
		  binfo->rcvhdr_bufbase, binfo->rcvegr_bufbase,
		  binfo->sdma_comp_bufbase);
	_HFI_VDBG("baseinfo: ureg %llx, eventbase %llx, "
		  "statusbase %llx, tailaddr %llx\n", binfo->user_regbase,
		  binfo->events_bufbase, binfo->status_bufbase,
		  binfo->rcvhdrtail_base);

	/*
	 * Check if driver version matches PSM version,
	 * this is different from PSM API version.
	 */
	if ((binfo->sw_version >> HFI1_SWMAJOR_SHIFT) != hfi_get_user_major_version()) {
		_HFI_INFO
		    ("User major version 0x%x not same as driver major 0x%x\n",
		     hfi_get_user_major_version(), binfo->sw_version >> HFI1_SWMAJOR_SHIFT);
		if ((binfo->sw_version >> HFI1_SWMAJOR_SHIFT) < hfi_get_user_major_version())
			goto err;	/* else assume driver knows how to be compatible */
	} else if ((binfo->sw_version & 0xffff) != HFI1_USER_SWMINOR) {
		_HFI_PRDBG
		    ("User minor version 0x%x not same as driver minor 0x%x\n",
		     HFI1_USER_SWMINOR, binfo->sw_version & 0xffff);
	}

	/* Map the PIO credits address */
	if ((tmp = hfi_mmap64(0, __hfi_pg_sz,
			      PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
			      (__off64_t) binfo->sc_credits_addr &
			      pg_mask)) == MAP_FAILED) {
		_HFI_INFO("mmap of sc_credits_addr (%llx) failed: %s\n",
			  (unsigned long long)binfo->sc_credits_addr,
			  strerror(errno));
		goto err;
	} else {
		hfi_touch_mmap(tmp, __hfi_pg_sz);
		binfo->sc_credits_addr = (uint64_t) (uintptr_t) tmp |
		    (binfo->sc_credits_addr & ~pg_mask);
		_HFI_VDBG("sc_credits_addr %llx\n",
			  binfo->sc_credits_addr);
	}

	/* Map the PIO buffer SOP address */
	if ((tmp = hfi_mmap64(0, cinfo->credits * 64,
			      PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd,
			      (__off64_t) binfo->pio_bufbase_sop & pg_mask))
	    == MAP_FAILED) {
		_HFI_INFO("mmap of pio buffer sop at %llx failed: %s\n",
			  (unsigned long long)binfo->pio_bufbase_sop,
			  strerror(errno));
		goto err;
	} else {
		/* Do not try to read the PIO buffers; they are mapped write */
		/* only.  We'll fault them in as we write to them. */
		binfo->pio_bufbase_sop = (uintptr_t) tmp;
		_HFI_VDBG("pio_bufbase_sop %llx\n",
			  binfo->pio_bufbase_sop);
	}

	/* Map the PIO buffer address */
	if ((tmp = hfi_mmap64(0, cinfo->credits * 64,
			      PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd,
			      (__off64_t) binfo->pio_bufbase & pg_mask)) ==
	    MAP_FAILED) {
		_HFI_INFO("mmap of pio buffer at %llx failed: %s\n",
			  (unsigned long long)binfo->pio_bufbase,
			  strerror(errno));
		goto err;
	} else {
		/* Do not try to read the PIO buffers; they are mapped write */
		/* only.  We'll fault them in as we write to them. */
		binfo->pio_bufbase = (uintptr_t) tmp;
		_HFI_VDBG("sendpio_bufbase %llx\n", binfo->pio_bufbase);
	}

	/* Map the receive header queue */
	if ((tmp =
	     hfi_mmap64(0, cinfo->rcvhdrq_cnt * cinfo->rcvhdrq_entsize,
			PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
			(__off64_t) binfo->rcvhdr_bufbase & pg_mask)) ==
	    MAP_FAILED) {
		_HFI_INFO("mmap of rcvhdrq at %llx failed: %s\n",
			  (unsigned long long)binfo->rcvhdr_bufbase,
			  strerror(errno));
		goto err;
	} else {
		/* for use in protocol code */
		hfi_touch_mmap(tmp,
			       cinfo->rcvhdrq_cnt * cinfo->rcvhdrq_entsize);
		binfo->rcvhdr_bufbase = (uintptr_t) tmp;	/* set to mapped address */
		_HFI_VDBG("rcvhdr_bufbase %llx\n", binfo->rcvhdr_bufbase);
	}

	/* Map the receive eager buffer */
	if ((tmp =
	     hfi_mmap64(0, cinfo->egrtids * cinfo->rcvegr_size,
			PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
			(__off64_t) binfo->rcvegr_bufbase & pg_mask)) ==
	    MAP_FAILED) {
		_HFI_INFO("mmap of rcvegrq bufs from %llx failed: %s\n",
			  (unsigned long long)binfo->rcvegr_bufbase,
			  strerror(errno));
		goto err;
	} else {
		hfi_touch_mmap(tmp, cinfo->egrtids * cinfo->rcvegr_size);
		binfo->rcvegr_bufbase = (uint64_t) (uintptr_t) tmp;
		_HFI_VDBG("rcvegr_bufbase %llx\n", binfo->rcvegr_bufbase);
	}

	/* Map the sdma completion queue */
	if (!(cinfo->runtime_flags & HFI1_CAP_SDMA)) {
		binfo->sdma_comp_bufbase = 0;
	} else
	    if ((tmp =
		 hfi_mmap64(0, cinfo->sdma_ring_size *
				sizeof(struct hfi1_sdma_comp_entry),
			    PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
			    (__off64_t) binfo->sdma_comp_bufbase & pg_mask)) ==
		MAP_FAILED) {
		_HFI_INFO
		    ("mmap of sdma completion queue from %llx failed: %s\n",
		     (unsigned long long)binfo->sdma_comp_bufbase,
		     strerror(errno));
		goto err;
	} else {
		binfo->sdma_comp_bufbase = (uint64_t) (uintptr_t) tmp;
	}
	_HFI_VDBG("sdma_comp_bufbase %llx\n", binfo->sdma_comp_bufbase);

	/* Map RXE per-context CSRs */
	if ((tmp = hfi_mmap64(0, __hfi_pg_sz,
			      PROT_WRITE | PROT_READ, MAP_SHARED | MAP_LOCKED,
			      fd,
			      (__off64_t) binfo->user_regbase & pg_mask)) ==
	    MAP_FAILED) {
		_HFI_INFO("mmap of user registers at %llx failed: %s\n",
			  (unsigned long long)binfo->user_regbase,
			  strerror(errno));
		goto err;
	} else {
		/* we don't try to fault these in, no need */
		binfo->user_regbase = (uint64_t) (uintptr_t) tmp;
		_HFI_VDBG("user_regbase %llx\n", binfo->user_regbase);
	}

	/*
	 * Set up addresses for optimized register writeback routines.
	 * This is for the real onchip registers, shared context or not
	 */
	tmp64 = (uint64_t *) tmp;
	spctrl->__hfi_rcvhdrtail = (volatile __le64 *)&tmp64[ur_rcvhdrtail];
	spctrl->__hfi_rcvhdrhead = (volatile __le64 *)&tmp64[ur_rcvhdrhead];
	spctrl->__hfi_rcvegrtail =
	    (volatile __le64 *)&tmp64[ur_rcvegrindextail];
	spctrl->__hfi_rcvegrhead =
	    (volatile __le64 *)&tmp64[ur_rcvegrindexhead];
	spctrl->__hfi_rcvofftail =
	    (volatile __le64 *)&tmp64[ur_rcvegroffsettail];

	if (!(cinfo->runtime_flags & HFI1_CAP_HDRSUPP)) {
		spctrl->__hfi_rcvtidflow = spctrl->regs;
		spctrl->__hfi_tfvalid = 0;
	} else {
		spctrl->__hfi_rcvtidflow =
		    (volatile __le64 *)&tmp64[ur_rcvtidflowtable];
		spctrl->__hfi_tfvalid = 1;
	}

	/* Map the rcvhdrq tail register address */
	if (!(cinfo->runtime_flags & HFI1_CAP_DMA_RTAIL)) {
		/*
		 * We don't use receive header queue tail register to detect
		 * new packets, but here we save the address for
		 * false-eager-full recovery.
		 */
		binfo->rcvhdrtail_base =
		    (uint64_t) (uintptr_t) spctrl->__hfi_rcvhdrtail;
		spctrl->__hfi_rcvtail = (__le64 *) binfo->rcvhdrtail_base;
	} else
	    if ((tmp = hfi_mmap64(0, __hfi_pg_sz,
				  PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
				  (__off64_t) binfo->rcvhdrtail_base &
				  pg_mask)) == MAP_FAILED) {
		_HFI_INFO("mmap of rcvhdrq tail addr %llx failed: %s\n",
			  (unsigned long long)binfo->rcvhdrtail_base,
			  strerror(errno));
		goto err;
	} else {
		hfi_touch_mmap(tmp, __hfi_pg_sz);
		binfo->rcvhdrtail_base = (uint64_t) (uintptr_t) tmp;
		spctrl->__hfi_rcvtail = (__le64 *) binfo->rcvhdrtail_base;
	}
	_HFI_VDBG("rcvhdr_tail_addr %llx\n", binfo->rcvhdrtail_base);

	/* Map the event page */
	if ((tmp = hfi_mmap64(0, __hfi_pg_sz,
			      PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
			      (__off64_t) binfo->events_bufbase & pg_mask)) ==
	    MAP_FAILED) {
		_HFI_INFO("mmap of status page at %llx failed: %s\n",
			  (unsigned long long)binfo->events_bufbase,
			  strerror(errno));
		goto err;
	} else {
		binfo->events_bufbase = (uint64_t) (uintptr_t) tmp |
		    (binfo->events_bufbase & ~pg_mask);
		_HFI_VDBG("events_bufbase %llx\n", binfo->events_bufbase);
	}

	/* Map the status page */
	if ((tmp = hfi_mmap64(0, __hfi_pg_sz,
			      PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
			      (__off64_t) binfo->status_bufbase & pg_mask)) ==
	    MAP_FAILED) {
		_HFI_INFO("mmap of status page (%llx) failed: %s\n",
			  (unsigned long long)binfo->status_bufbase,
			  strerror(errno));
		goto err;
	} else {
		binfo->status_bufbase = (uintptr_t) tmp;
		_HFI_VDBG("status_bufbase %llx\n", binfo->status_bufbase);
	}

	/* If subcontext is used, map the buffers */
	if (uinfo->subctxt_cnt) {
		unsigned num_subcontexts = uinfo->subctxt_cnt;
		size_t size;

		size = __hfi_pg_sz;
		if ((tmp = hfi_mmap64(0, size,
				      PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_LOCKED, fd,
				      (__off64_t) binfo->subctxt_uregbase &
				      pg_mask)) == MAP_FAILED) {
			_HFI_INFO
			    ("mmap of subcontext uregbase array (%llx) failed: %s\n",
			     (unsigned long long)binfo->subctxt_uregbase,
			     strerror(errno));
			goto err;
		} else {
			hfi_touch_mmap(tmp, size);
			binfo->subctxt_uregbase = (uint64_t) (uintptr_t) tmp;
			_HFI_VDBG("subctxt_uregbase %llx\n",
				  binfo->subctxt_uregbase);
		}

		size = ALIGN(cinfo->rcvhdrq_cnt * cinfo->rcvhdrq_entsize,
			     __hfi_pg_sz) * num_subcontexts;
		if ((tmp = hfi_mmap64(0, size,
				      PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_LOCKED, fd,
				      (__off64_t) binfo->subctxt_rcvhdrbuf &
				      pg_mask)) == MAP_FAILED) {
			_HFI_INFO
			    ("mmap of subcontext rcvhdr_base array (%llx) failed: %s\n",
			     (unsigned long long)binfo->subctxt_rcvhdrbuf,
			     strerror(errno));
			goto err;
		} else {
			hfi_touch_mmap(tmp, size);
			binfo->subctxt_rcvhdrbuf = (uint64_t) (uintptr_t) tmp;
			_HFI_VDBG("subctxt_rcvhdrbuf %llx\n",
				  binfo->subctxt_rcvhdrbuf);
		}

		size = ALIGN(cinfo->egrtids * cinfo->rcvegr_size,
			     __hfi_pg_sz) * num_subcontexts;
		if ((tmp = hfi_mmap64(0, size,
				      PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_LOCKED, fd,
				      (__off64_t) binfo->subctxt_rcvegrbuf &
				      pg_mask)) == MAP_FAILED) {
			_HFI_INFO
			    ("mmap of subcontext rcvegrbuf array (%llx) failed: %s\n",
			     (unsigned long long)binfo->subctxt_rcvegrbuf,
			     strerror(errno));
			goto err;
		} else {
			hfi_touch_mmap(tmp, size);
			binfo->subctxt_rcvegrbuf = (uint64_t) (uintptr_t) tmp;
			_HFI_VDBG("subctxt_rcvegrbuf %llx\n",
				  binfo->subctxt_rcvegrbuf);
		}
	}

	/* Save some info. */
	spctrl->fd = fd;
	spctrl->__hfi_unit = cinfo->unit;
	/*
	 * driver should provide the port where the context is opened for, But
	 * OPA driver does not have port interface to psm because there is only
	 * one port. So we hardcode the port to 1 here. When we work on the
	 * version of PSM for the successor to OPA, we should have port returned
	 * from driver and will be set accordingly.
	 */
	/* spctrl->__hfi_port = cinfo->port; */
	spctrl->__hfi_port = 1;
	spctrl->__hfi_tidegrcnt = cinfo->egrtids;
	spctrl->__hfi_tidexpcnt = cinfo->rcvtids - cinfo->egrtids;

	return spctrl;

err:
	if (spctrl)
		free(spctrl);
	return NULL;
}
