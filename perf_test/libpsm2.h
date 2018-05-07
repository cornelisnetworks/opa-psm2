/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2018 Intel Corporation.

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

  Copyright(c) 2018 Intel Corporation.

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

#ifndef _LIBPSM_H_
#define _LIBPSM_H_
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <psm2.h>
#include <psm2_mq.h>

extern psm2_epaddr_t *libpsm2_epaddrs;
extern psm2_ep_t libpsm2_ep;
extern psm2_mq_t libpsm2_mq;
extern int libpsm2_mpi_rank;

#define PSM2_TAG 0xF
#define PSM2_TAGSEL 0xF
#define MAX_PSM2_RANKS 2 /* only one server/client supported now */

#define PSM2_ERR(err, msg) fprintf(stderr, "%s %s\n", \
		msg, psm2_error_get_string(err));

int libpsm2_init(int sock, int is_server);
void libpsm2_shutdown(void);

static inline void post_irecv(void *buf, uint32_t len, uint64_t tag,
		uint64_t tagsel, uint32_t rank, psm2_mq_req_t *req)
{
	psm2_mq_irecv(libpsm2_mq, tag, tagsel, 0, buf, len, NULL, req);
}

static inline void post_isend(void *buf, uint32_t len, uint64_t tag,
		uint32_t rank, psm2_mq_req_t *req)
{
	psm2_mq_isend(libpsm2_mq, libpsm2_epaddrs[rank],
			0, tag, buf, len, NULL, req);
}

static inline void post_send(void *buf, uint32_t len,
		uint64_t tag, uint32_t rank)
{
	psm2_mq_send(libpsm2_mq, libpsm2_epaddrs[rank], 0, tag, buf, len);
}

static inline int cancel(psm2_mq_req_t *req)
{
	int ret = psm2_mq_cancel(req);

	if (ret == PSM2_OK)
		psm2_mq_test(req, NULL);
	return ret == PSM2_OK;
}

static inline int test(psm2_mq_req_t *req, psm2_mq_status_t *status)
{
	return (psm2_mq_test(req, status) == PSM2_OK);
}

static inline uint64_t get_cycles(void)
{
	uint64_t v;
	uint32_t a, d;

	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	v = ((uint64_t)a) | (((uint64_t)d)<<32);

	return v;
}

static inline void psm2_waitall(int num_req, psm2_mq_req_t *req_list,
		psm2_mq_status_t *st_list)
{
	int cnt = 0;
	int c[num_req];
	int w;

	for (w = 0; w < num_req; w++)
		c[w] = 0;

	if (!st_list) {
		do {
			psm2_poll(libpsm2_ep);

			for (w = 0; w < num_req; w++) {
				if (!c[w] && psm2_mq_test(&req_list[w], NULL) == PSM2_OK) {
					c[w] = 1;
					cnt++;
				}
			}
		} while (cnt < num_req);
	} else {
		do {
			psm2_poll(libpsm2_ep);

			for (w = 0; w < num_req; w++) {
				if (!c[w] && psm2_mq_test(&req_list[w], &st_list[w]) == PSM2_OK) {
					c[w] = 1;
					cnt++;
				}
			}
		} while (cnt < num_req);
	}
}

void print_psm2_stats(void);
#endif
