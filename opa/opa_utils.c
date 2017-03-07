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

#ifdef PSM_VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#endif

#include "ipserror.h"
#include "opa_user.h"

/* keep track whether we disabled mmap in malloc */
int __hfi_malloc_no_mmap = 0;

/* touch the pages, with a 32 bit read */
void hfi_touch_mmap(void *m, size_t bytes)
{
	volatile uint32_t *b = (volatile uint32_t *)m, c;
	size_t i;		/* m is always page aligned, so pgcnt exact */
	int __hfi_pg_sz;

	/* First get the page size */
	__hfi_pg_sz = sysconf(_SC_PAGESIZE);

	_HFI_VDBG("Touch %lu mmap'ed pages starting at %p\n",
		  (unsigned long)bytes / __hfi_pg_sz, m);
	bytes /= sizeof(c);
	for (i = 0; i < bytes; i += __hfi_pg_sz / sizeof(c))
		c = b[i];
}

/* flush the eager buffers, by setting the eager index head to eager index tail
   if eager buffer queue is full.

   Called when we had eager buffer overflows (ERR_TID/HFI_RHF_H_TIDERR
   was set in RHF errors), and no good eager packets were received, so
   that eager head wasn't advanced.  */

void hfi_flush_egr_bufs(struct _hfi_ctrl *ctrl)
{
	uint64_t head = __le64_to_cpu(*ctrl->__hfi_rcvegrhead);
	uint64_t tail = __le64_to_cpu(*ctrl->__hfi_rcvegrtail);

	if ((head % ctrl->__hfi_tidegrcnt) ==
	    ((tail + 1) % ctrl->__hfi_tidegrcnt)) {
		_HFI_DBG
		    ("eager array full after overflow, flushing (head %llx, tail %llx\n",
		     (long long)head, (long long)tail);
		*ctrl->__hfi_rcvegrhead = __cpu_to_le64(tail);
	}
}

/* stop_start == 0 disables receive on the context, for use in queue
   overflow conditions.  stop_start==1 re-enables, to be used to
   re-init the software copy of the head register */
int hfi_manage_rcvq(struct _hfi_ctrl *ctrl, uint32_t stop_start)
{
	struct hfi1_cmd cmd;

	cmd.type = PSMI_HFI_CMD_RECV_CTRL;
	cmd.len = 0;
	cmd.addr = (uint64_t) stop_start;

	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno != EINVAL)	/* not implemented in driver */
			_HFI_INFO("manage rcvq failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
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

	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno != EINVAL)	/* not implemented in driver */
			_HFI_INFO("poll type failed: %s\n", strerror(errno));
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

	cmd.type = PSMI_HFI_CMD_SET_PKEY;
	cmd.len = 0;
	cmd.addr = (uint64_t) pkey;

	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno != EINVAL)
			_HFI_INFO("set pkey failed: %s\n", strerror(errno));
		return -1;
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
	if (hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd)) == -1) {
		if (errno == ENOLCK)
			goto retry;

		if (errno != EINVAL)
			_HFI_INFO("reset ctxt failed: %s\n", strerror(errno));
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

const char *hfi_get_next_name(char **names)
{
	char *p, *start;

	p = start = *names;
	while (*p != '\0' && *p != '\n') {
		p++;
	}
	if (*p == '\n') {
		*p = '\0';
		p++;
		*names = p;
		return start;
	} else
		return NULL;
}

void hfi_release_names(char *namep)
{
	/* names were initialised in the data section before. Now
	 * they are allocated when hfi_hfifs_read() is called. Allocation
	 * for names is done only once at init time. Should we eventually
	 * have an "stats_type_unregister" type of routine to explicitly
	 * deallocate memory and free resources ?
	 */
#if 0
	if (namep != NULL)
		free(namep);
#endif
}

int hfi_get_stats_names_count()
{
	char *namep;
	int c;

	c = hfi_get_stats_names(&namep);
	free(namep);
	return c;
}

int hfi_get_ctrs_unit_names_count(int unitno)
{
	char *namep;
	int c;

	c = hfi_get_ctrs_unit_names(unitno, &namep);
	free(namep);
	return c;
}

int hfi_get_ctrs_port_names_count(int unitno)
{
	char *namep;
	int c;

	c = hfi_get_ctrs_port_names(unitno, &namep);
	free(namep);
	return c;
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

uint64_t hfi_get_single_stat(const char *attr, uint64_t *s)
{
	int nelem, n = 0, ret = -1;
	char *namep = NULL;
	uint64_t *stats = NULL;

	nelem = hfi_get_stats_names(&namep);
	if (nelem == -1 || namep == NULL)
		goto bail;
	stats = calloc(nelem, sizeof(uint64_t));
	if (stats == NULL)
		goto bail;
	n = hfi_get_stats(stats, nelem);
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

uint64_t hfi_get_single_unitctr(int unit, const char *attr, uint64_t *s)
{
	int nelem, n = 0, ret = -1;
	char *namep = NULL;
	uint64_t *stats = NULL;

	nelem = hfi_get_ctrs_unit_names(unit, &namep);
	if (nelem == -1 || namep == NULL)
		goto bail;
	stats = calloc(nelem, sizeof(uint64_t));
	if (stats == NULL)
		goto bail;
	n = hfi_get_ctrs_unit(unit, stats, nelem);
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

/*
 * Add a constructor function to disable mmap if asked to do so by the user
 */
static void init_mallopt_disable_mmap(void) __attribute__ ((constructor));

static void init_mallopt_disable_mmap(void)
{
	char *env = getenv("HFI_DISABLE_MMAP_MALLOC");

	if (env && *env) {
		if (mallopt(M_MMAP_MAX, 0) && mallopt(M_TRIM_THRESHOLD, -1)) {
			__hfi_malloc_no_mmap = 1;
		}
	}

	return;
}
