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

/* This file contains hfi service routine interface used by the low */
/* level hfi protocol code. */

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
#include <time.h>

#include "opa_user_gen1.h"

/* touch the pages, with a 32 bit read */
void hfi_touch_mmap(void *m, size_t bytes)
{
	volatile uint32_t *b = (volatile uint32_t *)m, c;
	size_t i;		/* m is always page aligned, so pgcnt exact */
	int __hfi_pg_sz;
	/* First get the page size */
	__hfi_pg_sz = sysconf(_SC_PAGESIZE);
	if (getenv("HFI_DEBUG_NO_TOUCH")) {
		_HFI_VDBG(" HFI_DEBUG_NO_TOUCH %lu mmap'ed pages starting at %p\n",
			  (unsigned long)bytes / __hfi_pg_sz, m);
		_HFI_DBG_SLEEP;
		return;
	}
	_HFI_VDBG(" Touch %lu mmap'ed pages starting at %p\n",
		  (unsigned long)bytes / __hfi_pg_sz, m);
	_HFI_DBG_SLEEP;
	bytes /= sizeof(c);
	for (i = 0; i < bytes; i += __hfi_pg_sz / sizeof(c))
		c = b[i];
	_HFI_VDBG(" After Touch %lu mmap'ed pages starting at %p\n",
		  (unsigned long)bytes / __hfi_pg_sz, m);
	_HFI_DBG_SLEEP;
}

/* ack event bits, and clear them.  Usage is check *spi_sendbuf_status,
   pass bits you are prepared to handle to hfi_event_ack(), perform the
   appropriate actions for bits that were set, and then (if appropriate)
   check the bits again. */
int hfi_event_ack(struct _hfi_ctrl *ctrl, __u64 ackbits)
{
	struct hfi1_cmd cmd;

	cmd.type = PSMI_HFI_CMD_ACK_EVENT;
	cmd.len = 0;
	cmd.addr = ackbits;

	_HFI_VDBG(" PSMI_HFI_CMD_ACK_EVENT:%u\n",__LINE__);
	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno != EINVAL)	/* not implemented in driver. */
			_HFI_DBG("event ack failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Tell the driver to change the way packets can generate interrupts.

 HFI1_POLL_TYPE_URGENT: Generate interrupt only when packet sets
 HFI_KPF_INTR
 HFI1_POLL_TYPE_ANYRCV: wakeup on any rcv packet (when polled on).

 PSM: Uses TYPE_URGENT in ips protocol
*/
int hfi_poll_type(struct _hfi_ctrl *ctrl, uint16_t poll_type)
{
	struct hfi1_cmd cmd;

	cmd.type = PSMI_HFI_CMD_POLL_TYPE;
	cmd.len = 0;
	cmd.addr = (uint64_t) poll_type;

	_HFI_VDBG(" PSMI_HFI_CMD_POLL_TYPE:%u\n",__LINE__);
	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno != EINVAL)	/* not implemented in driver */
			_HFI_INFO(" poll type failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* set the send context pkey to check BTH pkey in each packet.
   driver should check its pkey table to see if it can find
   this pkey, if not, driver should return error. */
int hfi_set_pkey(struct _hfi_ctrl *ctrl, uint16_t pkey)
{
	struct hfi1_cmd cmd;
	struct hfi1_base_info tbinfo;

	cmd.type = PSMI_HFI_CMD_SET_PKEY;
	cmd.len = 0;
	cmd.addr = (uint64_t) pkey;

	_HFI_VDBG(" Setting context pkey to 0x%04x.\n", pkey);
	_HFI_VDBG(" PSMI_HFI_CMD_SET_PKEY:%u\n",__LINE__);
	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		_HFI_INFO(" Setting context pkey to 0x%04x failed: %s\n",
			  pkey, strerror(errno));
		return -1;
	} else {
		_HFI_VDBG(" Successfully set context pkey to 0x%04x.\n", pkey);
	}

        if (getenv("PSM2_SELINUX")) {
		/*
		 * If SELinux is in use the kernel may have changed our JKey based on
		 * what we supply for the PKey so go ahead and interrogate the user info
		 * again and update our saved copy. In the future there may be a new
		 * IOCTL to get the JKey only. For now, this temporary workaround works.
		 */
		cmd.type = PSMI_HFI_CMD_USER_INFO;
		cmd.len = sizeof(tbinfo);
		cmd.addr = (uint64_t) &tbinfo;

		_HFI_VDBG(" PSMI_HFI_CMD_USER_INFO:%u\n",__LINE__);
		if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
			_HFI_VDBG(" BASE_INFO command failed in setpkey: %s\n",
				  strerror(errno));
			return -1;
		}
		_HFI_VDBG(" PSM2_SELINUX is set, updating jkey to 0x%04x\n", tbinfo.jkey);
		ctrl->base_info.jkey = tbinfo.jkey;
	}
	return 0;
}

/* Tell the driver to reset the send context. if the send context
   if halted, reset it, if not, return error back to caller.
   After context reset, the credit return should be reset to
   zero by a hardware credit return DMA.
   Driver will return ENOLCK if the reset is timeout, in this
   case PSM needs to re-call again. */
int hfi_reset_context(struct _hfi_ctrl *ctrl)
{
	struct hfi1_cmd cmd;

	cmd.type = PSMI_HFI_CMD_CTXT_RESET;
	cmd.len = 0;
	cmd.addr = 0;

retry:

	_HFI_VDBG(" PSMI_HFI_CMD_CTXT_RESET:%u\n",__LINE__);
	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno == ENOLCK)
			goto retry;

		if (errno != EINVAL)
			_HFI_INFO(" reset ctxt failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* wait for a received packet for our context
   This allows us to not busy wait, if nothing has happened for a
   while, which allows better measurements of cpu utilization, and
   in some cases, slightly better performance.  Called where we would
   otherwise call sched_yield().  It is not guaranteed that a packet
   has arrived, so the normal checking loop(s) should be done.

   PSM: not used as is, PSM has it's own use of polling for interrupt-only
   packets (sets hfi_poll_type to TYPE_URGENT) */
int hfi_wait_for_packet(struct _hfi_ctrl *ctrl)
{
	return hfi_cmd_wait_for_packet(ctrl->fd);
}

/* These have been fixed to read the values, but they are not
 * compatible with the hfi driver, they return new info with
 * the qib driver
 */
static int hfi_count_names(const char *namep)
{
	int n = 0;
	while (*namep != '\0') {
		if (*namep == '\n')
			n++;
		namep++;
	}
	return n;
}

int hfi_lookup_stat(const char *attr, char *namep, uint64_t *stats,
		    uint64_t *s)
{
	const char *p;
	int i, ret = -1, len = strlen(attr);
	int nelem = hfi_count_names(namep);

	for (i = 0; i < nelem; i++) {
		p = hfi_get_next_name(&namep);
		if (p == NULL)
			break;
		if (strncasecmp(p, attr, len + 1) == 0) {
			ret = i;
			*s = stats[i];
		}
	}
	return ret;
}

int hfi_get_single_portctr(int unit, int port, const char *attr, uint64_t *s)
{
	int nelem, n = 0, ret = -1;
	char *namep = NULL;
	uint64_t *stats = NULL;

	nelem = hfi_get_ctrs_port_names(unit, &namep);
	if (nelem == -1 || namep == NULL)
		goto bail;
	stats = calloc(nelem, sizeof(uint64_t));
	if (stats == NULL)
		goto bail;
	n = hfi_get_ctrs_port(unit, port, stats, nelem);
	if (n != nelem)
		goto bail;
	ret = hfi_lookup_stat(attr, namep, stats, s);
bail:
	if (namep != NULL)
		free(namep);
	if (stats != NULL)
		free(stats);
	return ret;
}
