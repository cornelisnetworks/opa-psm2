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

#include <sys/poll.h>

#include "ptl_ips.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_recvhdrq.h"

/* All in milliseconds */
#define RCVTHREAD_TO_MIN_FREQ	    10	/* min of 10 polls per sec */
#define RCVTHREAD_TO_MAX_FREQ	    100	/* max of 100 polls per sec */
#define RCVTHREAD_TO_SHIFT	    1

struct ptl_rcvthread;

static void *ips_ptl_pollintr(void *recvthreadc);
static psm_error_t rcvthread_initstats(ptl_t *ptl);
static psm_error_t rcvthread_initsched(struct ptl_rcvthread *rcvc);

struct ptl_rcvthread {
	const psmi_context_t *context;
	const ptl_t *ptl;
	struct ips_recvhdrq *recvq;

	pthread_t hdrq_threadid;
	uint64_t t_start_cyc;
	int pipefd[2];

	/* stats and some for scheduling */
	uint64_t pollcnt;
	uint64_t pollcnt_to;
	uint64_t pollcyc;
	uint64_t pollok;

	/* For scheduling interrupt thread */
	int timeout_period_min;
	int timeout_period_max;
	int timeout_shift;
	uint64_t pollok_last;
	uint64_t pollcnt_last;
	uint32_t last_timeout;
};

/*
 * The receive thread knows about the ptl interface, so it can muck with it
 * directly.
 */
psm_error_t ips_ptl_rcvthread_init(ptl_t *ptl, struct ips_recvhdrq *recvq)
{
	psm_error_t err = PSM_OK;
	struct ptl_rcvthread *rcvc;

	ptl->rcvthread =
	    psmi_calloc(ptl->ep, UNDEFINED, 1, sizeof(struct ptl_rcvthread));
	if (ptl->rcvthread == NULL) {
		err = PSM_NO_MEMORY;
		goto fail;
	}
	rcvc = ptl->rcvthread;

	rcvc->recvq = recvq;
	rcvc->ptl = ptl;
	rcvc->context = ptl->context;
	rcvc->t_start_cyc = get_cycles();

	if (ptl->runtime_flags & PSMI_RUNTIME_RCVTHREAD) {

		if ((err = rcvthread_initsched(rcvc)))
			goto fail;

		/* Create a pipe so we can synchronously terminate the thread */
		if (pipe(rcvc->pipefd) != 0) {
			err = psmi_handle_error(ptl->ep, PSM_EP_DEVICE_FAILURE,
						"Cannot create a pipe for receive thread: %s\n",
						strerror(errno));
			goto fail;
		}

		if (pthread_create(&rcvc->hdrq_threadid, NULL,
				   ips_ptl_pollintr, ptl->rcvthread)) {
			close(rcvc->pipefd[0]);
			close(rcvc->pipefd[1]);
			err = psmi_handle_error(ptl->ep, PSM_EP_DEVICE_FAILURE,
						"Cannot start receive thread: %s\n",
						strerror(errno));
			goto fail;
		}

	}

	if ((err = rcvthread_initstats(ptl)))
		goto fail;

fail:
	return err;
}

psm_error_t ips_ptl_rcvthread_fini(ptl_t *ptl)
{
	struct ptl_rcvthread *rcvc = (struct ptl_rcvthread *)ptl->rcvthread;
	uint64_t t_now;
	double t_cancel_us;
	psm_error_t err = PSM_OK;

	PSMI_PLOCK_ASSERT();

	if (ptl->rcvthread == NULL)
		return err;

	if (ptl->runtime_flags & PSMI_RUNTIME_RCVTHREAD) {
		t_now = get_cycles();

		/* Disable interrupts then kill the receive thread */
		if (psmi_context_interrupt_isenabled
		    ((psmi_context_t *) ptl->context))
			if ((err =
			     psmi_context_interrupt_set((psmi_context_t *) ptl->
							context, 0)))
				goto fail;

		/* Close the pipe so we can have the thread synchronously exit.
		   On Linux just closing the pipe does not wake up the receive
		   thread.
		 */
		if (write(rcvc->pipefd[1], (const void *)&t_now,
			  sizeof(uint64_t)) == -1 ||
		    close(rcvc->pipefd[1]) == -1) {
			_HFI_VDBG
			    ("unable to close pipe to receive thread cleanly\n");
		}
		pthread_join(rcvc->hdrq_threadid, NULL);
		t_cancel_us =
		    (double)cycles_to_nanosecs(get_cycles() - t_now) / 1e3;

		_HFI_PRDBG("rcvthread poll success %lld/%lld times, "
			   "thread cancelled in %.3f us\n",
			   (long long)rcvc->pollok, (long long)rcvc->pollcnt,
			   t_cancel_us);

	}

	psmi_free(ptl->rcvthread);

fail:
	return err;
}

psm_error_t rcvthread_initsched(struct ptl_rcvthread *rcvc)
{
	union psmi_envvar_val env_to;
	char buf[192];
	char *rcv_freq = buf;
	int no_timeout = 0;
	int tvals[3] = { RCVTHREAD_TO_MIN_FREQ,
		RCVTHREAD_TO_MAX_FREQ,
		RCVTHREAD_TO_SHIFT
	};
	snprintf(buf, sizeof(buf) - 1, "%d:%d:%d", RCVTHREAD_TO_MIN_FREQ,
		 RCVTHREAD_TO_MAX_FREQ, RCVTHREAD_TO_SHIFT);
	buf[sizeof(buf) - 1] = '\0';

	if (!psmi_getenv("PSM_RCVTHREAD_FREQ",
			 "Thread timeouts (per sec) <min_freq[:max_freq[:shift_freq]]>",
			 PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
			 (union psmi_envvar_val)rcv_freq, &env_to)) {
		/* not using default values */
		int nparsed = psmi_parse_str_tuples(env_to.e_str, 3, tvals);
		int invalid = 0;

		if (nparsed < 1 || (nparsed > 0 && tvals[0] == 0) ||
		    (nparsed > 1 && tvals[1] == 0)) {
			no_timeout = 1;
		} else {
			if (nparsed > 0 && tvals[0] > 1000)
				invalid = 1;
			if (nparsed > 1
			    && (tvals[1] > 1000 || tvals[1] < tvals[0]))
				invalid = 1;
			if (nparsed > 2 && tvals[2] > 10)
				invalid = 1;
		}

		if (invalid) {
			_HFI_INFO
			    ("Overriding invalid request for RcvThread frequency"
			     " settings of %s to be <%d:%d:%d>\n", env_to.e_str,
			     RCVTHREAD_TO_MIN_FREQ, RCVTHREAD_TO_MAX_FREQ,
			     RCVTHREAD_TO_SHIFT);
			tvals[0] = RCVTHREAD_TO_MIN_FREQ;
			tvals[1] = RCVTHREAD_TO_MAX_FREQ;
			tvals[2] = RCVTHREAD_TO_SHIFT;
		}
	}

	if (no_timeout) {
		rcvc->last_timeout = -1;
		_HFI_PRDBG("PSM_RCVTHREAD_FREQ set to only interrupt "
			   "(no timeouts)\n");
	} else {
		/* Convert freq to period in microseconds (for poll()) */
		rcvc->timeout_period_max = 1000 / tvals[0];
		rcvc->timeout_period_min = 1000 / tvals[1];
		rcvc->timeout_shift = tvals[2];
		/* Start in the middle of min and max */
		rcvc->last_timeout = (rcvc->timeout_period_min +
				      rcvc->timeout_period_max) / 2;
		_HFI_PRDBG("PSM_RCVTHREAD_FREQ converted to period "
			   "min=%dms,max=%dms,shift=%d\n",
			   rcvc->timeout_period_min, rcvc->timeout_period_max,
			   rcvc->timeout_shift);
	}
	return PSM_OK;
}

static
int rcvthread_next_timeout(struct ptl_rcvthread *rcvc)
{
	uint64_t pollok_diff = rcvc->pollok - rcvc->pollok_last;

	if (pollok_diff > 0) {
		if (rcvc->last_timeout > rcvc->timeout_period_min)
			/* By default, be less aggressive, but there's a more aggressive
			 * alternative if need be */
#if 1
			rcvc->last_timeout >>= rcvc->timeout_shift;
#else
			rcvc->last_timeout = rcvc->timeout_period_min;
#endif
	} else {		/* we had less progress */
		if (rcvc->last_timeout < rcvc->timeout_period_max)
			rcvc->last_timeout <<= rcvc->timeout_shift;
	}

	rcvc->pollok_last = rcvc->pollok;
	rcvc->pollcnt_last = rcvc->pollcnt;
	return (int)rcvc->last_timeout;
}

extern int ips_in_rcvthread;

/*
 * Receiver thread support.
 *
 * By default, polling in the driver asks the chip to generate an interrupt on
 * every packet.  When the driver supports POLLURG we can switch the poll mode
 * to one that requests interrupts only for packets that contain an urgent bit
 * (and optionally enable interrupts for hdrq overflow events).  When poll
 * returns an event, we *try* to make progress on the receive queue but simply
 * go back to sleep if we notice that the main thread is already making
 * progress.
 */
static
void *ips_ptl_pollintr(void *rcvthreadc)
{
	struct ptl_rcvthread *rcvc = (struct ptl_rcvthread *)rcvthreadc;
	struct ips_recvhdrq *recvq = rcvc->recvq;
	psmi_context_t *context = (psmi_context_t *) rcvc->context;
	int fd_dev = context->fd;
	int fd_pipe = rcvc->pipefd[0];
	psm_ep_t ep = context->ep;
	struct pollfd pfd[2];
	int ret;
	int next_timeout = rcvc->last_timeout;
	uint64_t t_cyc;
	psm_error_t err;

	/* No reason to have many of these, keep this as a backup in case the
	 * recvhdrq init function is misused */
	psmi_assert_always((recvq->runtime_flags & PSMI_RUNTIME_RCVTHREAD));

	/* Switch driver to a mode where it can interrupt on urgent packets */
	if (psmi_context_interrupt_set((psmi_context_t *)
				       rcvc->context, 1) == PSM_EP_NO_RESOURCES) {
		_HFI_PRDBG
		    ("hfi_poll_type feature not present in driver, turning "
		     "off internal progress thread\n");
		return NULL;
	}

	_HFI_PRDBG("Enabled communication thread on URG packets\n");

	while (1) {
		pfd[0].fd = fd_dev;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = fd_pipe;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;

		ret = poll(pfd, 2, next_timeout);
		t_cyc = get_cycles();

		if_pf(ret < 0) {
			if (errno == EINTR)
				_HFI_DBG("got signal, keep polling\n");
			else
				psmi_handle_error(PSMI_EP_NORETURN,
						  PSM_INTERNAL_ERR,
						  "Receive thread poll() error: %s",
						  strerror(errno));
		}
		else
	if (pfd[1].revents) {
		/* Any type of event on this fd means exit, should be POLLHUP */
		_HFI_DBG("close thread: revents=0x%x\n", pfd[1].revents);
		close(fd_pipe);
		break;
	} else {
		rcvc->pollcnt++;

		if (ret == 0 || pfd[0].revents & (POLLIN | POLLERR)) {
			if (PSMI_PLOCK_DISABLED) {
				/* We do this check without acquiring the lock, no sense to
				 * adding the overhead and it doesn't matter if we're
				 * wrong. */
				if (ips_recvhdrq_isempty(recvq))
					continue;
				if (!ips_recvhdrq_trylock(recvq))
					continue;
				err = ips_recvhdrq_progress(recvq);
				if (err == PSM_OK)
					rcvc->pollok++;
				else
					rcvc->pollcyc += get_cycles() - t_cyc;
				ips_recvhdrq_unlock(recvq);
			} else if (!PSMI_PLOCK_TRY()) {
				/* If we time out, we service shm and hfi.  If not, we
				 * assume to have received an hfi interrupt and service
				 * only hfi.
				 */
				err = psmi_poll_internal(ep,
							 ret ==
							 0 ? PSMI_TRUE :
							 PSMI_FALSE);

				if (err == PSM_OK) {
					rcvc->pollok++;
					/*
					   if (rcvc->pollok % 1000 == 0 && rcvc->pollok >= 1000)
					   _HFI_INFO("pollok = %lld\n", (unsigned long long)rcvc->pollok);
					 */
				} else
					rcvc->pollcyc += get_cycles() - t_cyc;
				PSMI_PUNLOCK();
			}
		}

		if (ret == 0) {	/* change timeout only on timed out poll */
			rcvc->pollcnt_to++;
			next_timeout = rcvthread_next_timeout(rcvc);
		}
	}
	}

	return NULL;
}

static uint64_t rcvthread_stats_pollok(void *context)
{
	struct ptl_rcvthread *rcvc = (struct ptl_rcvthread *)context;
	double ratio = 0.0;
	uint64_t ratio_u;
	if (rcvc->pollcnt > 0)
		ratio = (double)rcvc->pollok * 100.0 / rcvc->pollcnt;
	memcpy(&ratio_u, &ratio, sizeof(uint64_t));
	return ratio_u;
}

static uint64_t rcvthread_stats_pollcyc(void *context)
{
	struct ptl_rcvthread *rcvc = (struct ptl_rcvthread *)context;
	/* log in milliseconds */
	return (uint64_t) ((double)cycles_to_nanosecs(rcvc->pollcyc) / 1.0e6);
}

static psm_error_t rcvthread_initstats(ptl_t *ptl)
{
	struct ptl_rcvthread *rcvc = (struct ptl_rcvthread *)ptl->rcvthread;
	struct psmi_stats_entry entries[] = {
		PSMI_STATS_DECL("intrthread schedule count",
				MPSPAWN_STATS_REDUCTION_ALL |
				MPSPAWN_STATS_SKIP_IF_ZERO,
				NULL, &rcvc->pollcnt),
		PSMI_STATS_DECL("intrthread schedule success (%)",
				MPSPAWN_STATS_REDUCTION_ALL |
				MPSPAWN_STATS_TYPE_DOUBLE,
				rcvthread_stats_pollok, NULL),
		PSMI_STATS_DECL("intrthread timeout count",
				MPSPAWN_STATS_REDUCTION_ALL |
				MPSPAWN_STATS_SKIP_IF_ZERO,
				NULL, &rcvc->pollcnt_to),
		PSMI_STATS_DECL("intrthread wasted time (ms)",
				MPSPAWN_STATS_REDUCTION_ALL,
				rcvthread_stats_pollcyc, NULL)
	};

	/* If we don't want a thread, make sure we still initialize the counters
	 * but set them to NaN instead */
	if (!(ptl->runtime_flags & PSMI_RUNTIME_RCVTHREAD)) {
		int i;
		static uint64_t ctr_nan = MPSPAWN_NAN;
		for (i = 0; i < (int)PSMI_STATS_HOWMANY(entries); i++) {
			entries[i].getfn = NULL;
			entries[i].u.val = &ctr_nan;
		}
	}

	return psmi_stats_register_type(PSMI_STATS_NO_HEADING,
					PSMI_STATSTYPE_RCVTHREAD,
					entries,
					PSMI_STATS_HOWMANY(entries), rcvc);
}
