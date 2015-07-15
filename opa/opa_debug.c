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


#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <execinfo.h>
#include <fcntl.h>
#include <ucontext.h>
#include "opa_user.h"

unsigned hfi_debug = 1;
char *__hfi_mylabel = NULL;
FILE *__hfi_dbgout;
static void init_hfi_mylabel(void) __attribute__ ((constructor));
static void init_hfi_backtrace(void) __attribute__ ((constructor));
static void init_hfi_dbgfile(void) __attribute__ ((constructor));

static void init_hfi_mylabel(void)
{
	char lbl[1024];
	char hostname[80];
	char *e;
	/* By default, try to come up with a decent default label, it will be
	 * overriden later.  Try getting rank, if that's not available revert to
	 * pid. */
	gethostname(hostname, 80);
	lbl[0] = '\0';
	hostname[sizeof(hostname) - 1] = '\0';
	if ((((e = getenv("PSC_MPI_RANK")) && *e)) ||
	    (((e = getenv("MPI_RANKID")) && *e)) ||
	    (((e = getenv("MPIRUN_RANK")) && *e))) {
		char *ep;
		unsigned long val;
		val = strtoul(e, &ep, 10);
		if (ep != e)	/* valid conversion */
			snprintf(lbl, 1024, "%s.%lu", hostname, val);
	}
	if (lbl[0] == '\0')
		snprintf(lbl, 1024, "%s.%u", hostname, getpid());
	__hfi_mylabel = strdup(lbl);
}

static void hfi_sighdlr(int sig, siginfo_t *p1, void *ucv)
{
	/* we make these static to try and avoid issues caused
	   by stack overflow that might have gotten us here. */
	static void *backaddr[128];	/* avoid stack usage */
	static char buf[150], hname[64], fname[128];
	static int i, j, fd, id;
	extern char *__progname;

	/* If this is a SIGINT do not display backtrace. Just invoke exit
	   handlers */
	if ((sig == SIGINT) || (sig == SIGTERM))
		exit(1);

	id = snprintf(buf, sizeof(buf),
		      "\n%.60s:%u terminated with signal %d", __progname,
		      getpid(), sig);
	if (ucv) {
		static ucontext_t *uc;
		uc = (ucontext_t *) ucv;
		id += snprintf(buf + id, sizeof(buf) - id, " at PC=%lx SP=%lx",
#if defined(__x86_64__)
			       (unsigned long)uc->uc_mcontext.gregs[REG_RIP],
			       (unsigned long)uc->uc_mcontext.gregs[REG_RSP]);
#elif defined(__i386__)
			       (unsigned long)uc->uc_mcontext.gregs[REG_EIP],
			       (unsigned long)uc->uc_mcontext.gregs[REG_ESP]);
#else
			       0ul, 0ul);
#warning No stack pointer or instruction pointer for this arch
#endif
	}
	id += snprintf(buf + id, sizeof(buf) - id, ".  Backtrace:\n");
	(void)write(2, buf, id);

	i = backtrace(backaddr, sizeof(backaddr) / sizeof(backaddr[0]));
	if (i > 2)		/* skip ourselves and backtrace */
		j = 2, i -= j;
	else
		j = 0;
	backtrace_symbols_fd(backaddr + j, i, 2);
	(void)fsync(2);

	/* Try to write it to a file as well, in case the rest doesn't make it
	   out. Do it second, in case we get a second failure (more likely).
	   We might eventually want to print some more of the registers to the
	   btr file, to aid debugging, but not for now.  Truncate the program
	   name if overly long, so we always get pid and (at least part of)
	   hostname. */
	(void)gethostname(hname, sizeof(hname));
	hname[sizeof(hname) - 1] = '\0';
	snprintf(fname, sizeof(fname), "%s.80s-%u,%.32s.btr", __progname,
		 getpid(), hname);
	if ((fd = open(fname, O_CREAT | O_WRONLY, 0644)) >= 0) {
		(void)write(fd, buf, id);
		backtrace_symbols_fd(backaddr + j, i, fd);
		(void)fsync(fd);
		(void)close(fd);
	}
	exit(1);		/* not _exit(), want atexit handlers to get run */
}

/* We do this as a constructor so any user program that sets signal handlers
   for these will override our settings, but we still get backtraces if they
   don't.
*/
static void init_hfi_backtrace(void)
{
	/* we need to track memory corruption */
	static struct sigaction act;	/* easier than memset */
	act.sa_sigaction = hfi_sighdlr;
	act.sa_flags = SA_SIGINFO;

	if (!getenv("HFI_NO_BACKTRACE")) {
		/* permanent, although probably
		   undocumented way to disable backtraces. */
		(void)sigaction(SIGSEGV, &act, NULL);
		(void)sigaction(SIGBUS, &act, NULL);
		(void)sigaction(SIGILL, &act, NULL);
		(void)sigaction(SIGABRT, &act, NULL);
		(void)sigaction(SIGINT, &act, NULL);
		(void)sigaction(SIGTERM, &act, NULL);
	}
}

/* if HFI_DEBUG_FILENAME is set in the environment, then all the
   debug prints (not info and error) will go to that file.
   %h is expanded to the hostname, and %p to the pid, if present. */
static void init_hfi_dbgfile(void)
{
	char *fname = getenv("HFI_DEBUG_FILENAME");
	char *exph, *expp, tbuf[1024];
	FILE *newf;

	if (!fname) {
		__hfi_dbgout = stdout;
		return;
	}
	exph = strstr(fname, "%h");	/* hostname */
	expp = strstr(fname, "%p");	/* pid */
	if (exph || expp) {
		int baselen;
		char hname[256], pid[12];
		if (exph) {
			*hname = hname[sizeof(hname) - 1] = 0;
			gethostname(hname, sizeof(hname) - 1);
			if (!*hname)
				strcpy(hname, "[unknown]");
		}
		if (expp)
			snprintf(pid, sizeof(pid), "%d", getpid());
		if (exph && expp) {
			if (exph < expp) {
				baselen = exph - fname;
				snprintf(tbuf, sizeof(tbuf), "%.*s%s%.*s%s%s",
					 baselen, fname, hname,
					 (int)(expp - (exph + 2)), exph + 2,
					 pid, expp + 2);
			} else {
				baselen = expp - fname;
				snprintf(tbuf, sizeof(tbuf), "%.*s%s%.*s%s%s",
					 baselen, fname, pid,
					 (int)(exph - (expp + 2)), expp + 2,
					 hname, exph + 2);
			}
		} else if (exph) {
			baselen = exph - fname;
			snprintf(tbuf, sizeof(tbuf), "%.*s%s%s",
				 baselen, fname, hname, exph + 2);
		} else {
			baselen = expp - fname;
			snprintf(tbuf, sizeof(tbuf), "%.*s%s%s",
				 baselen, fname, pid, expp + 2);
		}
		fname = tbuf;
	}
	newf = fopen(fname, "a");
	if (!newf) {
		_HFI_ERROR
		    ("Unable to open \"%s\" for debug output, using stdout: %s\n",
		     fname, strerror(errno));
		__hfi_dbgout = stdout;
	} else {
		__hfi_dbgout = newf;
		setlinebuf(__hfi_dbgout);
	}
}

void hfi_set_mylabel(char *label)
{
	__hfi_mylabel = label;
}

char *hfi_get_mylabel()
{
	return __hfi_mylabel;
}
