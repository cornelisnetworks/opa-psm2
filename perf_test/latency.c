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

#include <stdio.h>
#include <stdlib.h>

#include "libpsm2.h"
#include "psm2perf.h"

int run_latency(struct benchmark_info *info, int sock);

int main(int argc, char **argv)
{
	int ret = 0;

	struct benchmark_info *info = init_benchmark(argc, argv);
	if (info == NULL) {
		ret = -1;
		goto bail;
	}

	int sock = open_socket(info->server, info->is_server, SERVER_PORT);
	if (sock < 0) {
		ret = -1;
		goto bail;
	}

	ret = exchange_info(sock, info);
	if (ret == -1)
		goto bail;

	ret = libpsm2_init(sock, info->is_server);
	if (ret == -1)
		goto bail;

	if (info->run_flush) {
		printf("Flushing L3 Cache... will take a few seconds\n");
		printf("Flushed L3 cache (%ld)\n",flush_l3cache());
	}

	ret = run_latency(info, sock);
	if (info->show_mqstats)
		print_psm2_stats();
	libpsm2_shutdown();

bail:
	if (sock > 0)
		close(sock);
	if (info != NULL)
		free(info);
	return ret;
}

int run_latency(struct benchmark_info *info, int sock)
{
	unsigned long long time_start, time_end;
	double time_elapsed = 0;
	int msize, i;
	int iters[2] = {ITERS_LARGE, ITERS_SMALL}, iter = iters[0];
	psm2_mq_req_t req;
	printf("# PSM2 Ping Pong Latency Test\n");
	printf("# Message Size(B)      Latency(us)\n");

	iter = iters[0];
	for (msize = info->min_msg_sz; msize <= info->max_msg_sz; msize *= 2) {
		if (msize > LARGE_MSG)
			iter = iters[1];

		if (info->is_server) {
			// warmup
			for (i = 0; i < iter; i++) {
				post_send(sbuff, msize, 0xF, info->partner);
				post_irecv(rbuff, msize, 0xF, 0xF, info->partner, &req);
				psm2_mq_wait(&req, NULL);
			}

			TIMER(time_start);
			for (i = 0; i < iter; i++) {
				post_send(sbuff, msize, 0xF, info->partner);
				post_irecv(rbuff, msize, 0xF, 0xF, info->partner, &req);
				psm2_mq_wait(&req, NULL);
			}
			TIMER(time_end);

			time_end -= time_start;
			time_elapsed = (double) time_end / info->cpu_freq / iter / 2;
		} else {
			for (i = 0; i < 2 * iter; i++) {
				post_irecv(rbuff, msize, 0xF, 0xF, info->partner, &req);
				psm2_mq_wait(&req, NULL);
				post_send(sbuff, msize, 0xF, info->partner);
			}
		}

		if (info->is_server)
			SEND(sock, time_elapsed, double);
		else
			RECV(sock, time_elapsed, double);

		printf("%-15d  %15.2f\n", msize, 1e6 * time_elapsed);
	}

	return 0;
bail:
	return -1;
}
