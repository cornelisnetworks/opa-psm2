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

#include "opa_user.h"

/* keep track whether we disabled mmap in malloc */
int __hfi_malloc_no_mmap = 0;

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
