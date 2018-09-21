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

#ifndef _PSM2PERF_H_
#define _PSM2PERF_H_
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* Executing this function before running a benchmark
 * can help get more consistent results.
 */
static inline long flush_l3cache()
{
	const long l3_cache_size_sc = sysconf(_SC_LEVEL3_CACHE_SIZE);
	const long l3_cache_size = (l3_cache_size_sc == -1) ?
		(28*1024*1024) : (l3_cache_size_sc);
	int i, j;
	if (l3_cache_size_sc == -1)
		printf("WARN: could not get L3 cache size from sysconf().\n"
		       "using: %ld instead.\n", l3_cache_size);
	/* allocating and scribbling twice the size of L3 cache in order to
	 ensure the L3 cache is invalidated. */
	char *_cache_flush = malloc(2*l3_cache_size);
	if (_cache_flush == NULL)
	{
		perror("memory allocation failure");
		exit(1);
	}
	for (i = 0; i < 80; i++)
		for (j = 0; j < l3_cache_size*2; j++)
			_cache_flush[j] = i * j;
	free(_cache_flush);
	return l3_cache_size;
}

#define SEND(sock, data, type)						\
	do {								\
		if (send(sock, (void *)&data, sizeof(type), 0) == -1) {	\
			perror("send");					\
			goto bail;					\
		}							\
	} while (0)

#define RECV(sock, data, type)						\
	do {								\
		if (recv(sock, (void *)&data, sizeof(type), 0) == -1) {	\
			perror("recv");					\
			goto bail;					\
		}							\
	} while (0)

#define TIMER(a) { a = get_cycles(); }

#define LARGE_MSG    65536
#define HOSTNAME_SZ  256
#define ITERS_SMALL  50
#define ITERS_MEDIUM 500
#define ITERS_LARGE  50000
#define SERVER_PORT  33087
#define MAX_CLIENTS  1
#define STR_SZ       1024

/* Defaults */
#define MIN_MSG_SZ   1
#define MAX_MSG_SZ   (4*1048576)
#define WINDOW       64

char server_name[HOSTNAME_SZ];

char sbuff[MAX_MSG_SZ];
char rbuff[MAX_MSG_SZ];

struct benchmark_info {
	double cpu_freq;
	char hostname[HOSTNAME_SZ];
	char server[HOSTNAME_SZ];
	int is_server;
	int partner;

	/* These are selected by the client, sent to server */
	long min_msg_sz;
	long max_msg_sz;
	int run_flush;
	int show_mqstats;
};

struct benchmark_info *init_benchmark(int argc, char **argv);
int open_socket(char *server_name, int is_server, int port);
int exchange_info(int sock, struct benchmark_info *info);
float get_cpu_rate(void);
#endif
