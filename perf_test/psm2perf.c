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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include "psm2perf.h"

/* Only return positive numbers from string, -1 on error */
static long str_to_positive_long(const char *str)
{
	char *end;
	long num = strtol(optarg, &end, 10);

	if (end == str) {
		fprintf(stderr, "Could not parse input %s\n", str);
		return -1;
	} else if ((num == LONG_MAX || num == LONG_MIN) && errno == ERANGE) {
		fprintf(stderr, "Underflow or overflow in %s\n", str);
		return -1;
	} else if (num > 0)
		return num;

	fprintf(stderr,
			"Expected a positive, non-zero number, got %ld\n", num);
	return -1;
}

static void print_usage(char *name)
{
	const char usage[] =
		"usage: %s [server] [-m size] [-M size] [-f --flush] [-h --help]\n"
		"options:\n"
		"server, server node to connect to, this node will be the client\n"
		"-m, starting message size in bytes (default %i)\n"
		"-M, ending message size in bytes (default %i)\n"
		"-f/--flush, flush L3 cache before benchmark\n"
		"--mqstats, show psm2 mq counters\n"
		"-h/--help, show this help message\n";
	fprintf(stderr, usage, name, MIN_MSG_SZ, MAX_MSG_SZ);
}

/* Get settings from argv on the client so they can be sent to server */
struct benchmark_info *init_benchmark(int argc, char **argv)
{
	int opt_idx = 0, got_args = 0, c;
	struct benchmark_info *info = (struct benchmark_info *)
		malloc(sizeof(struct benchmark_info));

	if (info == NULL) {
		perror("benchmark_info malloc");
		return NULL;
	}

	const struct option long_options[] = {
		{"flush", no_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"mqstats", no_argument, &info->show_mqstats, 1},
		{0, 0, 0, 0}
	};

	// Force reset of optind
	optind = 1;

	// Set default values
	info->run_flush = 0;
	info->min_msg_sz = MIN_MSG_SZ;
	info->max_msg_sz = MAX_MSG_SZ;
	info->show_mqstats = 0;

	while (1) {
		c = getopt_long(argc, argv, "fm:M:h",
				long_options, &opt_idx);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			if (long_options[opt_idx].flag != 0)
				break;
			break;
		case 'f':
			info->run_flush = 1;
			got_args = 1;
			break;
		case 'm':
			info->min_msg_sz = str_to_positive_long(optarg);
			got_args = 1;
			if (info->min_msg_sz == -1) {
				fprintf(stderr, "Invalid number for m\n");
				goto bail;
			}
			break;
		case 'M':
			info->max_msg_sz = str_to_positive_long(optarg);
			got_args = 1;
			if (info->max_msg_sz == -1) {
				fprintf(stderr, "Invalid number for M\n");
				goto bail;
			}
			if (info->max_msg_sz < info->min_msg_sz) {
				fprintf(stderr, "Max msg size larger than Min size\n");
				goto bail;
			}
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			goto bail;
		}
	}

	if (gethostname(info->hostname, HOSTNAME_SZ) != 0) {
		perror("gethostname");
		goto bail;
	}
	// Guarantee a null termination to info->hostname:
	info->hostname[HOSTNAME_SZ-1] = 0;
	info->cpu_freq = get_cpu_rate() * 1e6;
	if (info->cpu_freq == 0.0)
		goto bail;

	// Server will be the process with no positional arguments
	if (argc == optind) {
		info->is_server = 1;
		info->partner = 1;
		strncpy(info->server, info->hostname, HOSTNAME_SZ);
		// Guarantee a null termination to info->server:
		info->server[HOSTNAME_SZ-1] = 0;
		if (got_args)
			printf("WARN: all arguments ignored for server\n");
	// Found a positional argument, desginates client process
	} else if (optind == (argc - 1)) {
		info->is_server = 0;
		info->partner = 0;
		strncpy(info->server, argv[optind], HOSTNAME_SZ);
		// Guarantee a null termination to info->server:
		info->server[HOSTNAME_SZ-1] = 0;
	} else {
		print_usage(argv[0]);
		fprintf(stderr, "Found extra positional arguments\n");
		goto bail;
	}

	return info;
bail:
	free(info);
	return NULL;
}

/* Get cpu freq from /proc/cpuinfo, return 0.0 on fail */
float get_cpu_rate(void)
{
	FILE *fd;
	char buf[STR_SZ];
	char tmp[STR_SZ];
	float rate;
	char mhz_str[] = "cpu MHz";

	fd = fopen("/proc/cpuinfo", "r");
	if (fd == NULL) {
		perror("fopen /proc/cpuinfo");
		return 0.0;
	}

	while (fgets(buf, STR_SZ, fd) != NULL) {
		if (strncmp(buf, mhz_str, strlen(mhz_str)) == 0) {
			if (sscanf(buf, "%[^:]:%f", tmp, &rate) == 2) {
				fclose(fd);
				return rate;
			}
		}
	}

	fclose(fd);
	fprintf(stderr, "Could not find cpu MHz in /proc/cpuinfo\n");
	return 0.0;
}

/* Open socket between server and client */
int open_socket(char *server_name, int is_server, int port)
{
	int sock, close_immed = 1;
	socklen_t remote_len;
	struct hostent *server;
	struct sockaddr_in server_addr, remote_addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Could not open socket");
		return sock;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&close_immed, sizeof(close_immed))) {
		perror("setsockopt");
		goto bail;
	}

	server = gethostbyname(server_name);
	if (server == NULL) {
		fprintf(stderr, "Error in gethostbyname\n");
		goto bail;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	if (is_server) {
		if (bind(sock,
					(struct sockaddr *) &server_addr,
					sizeof(server_addr)) == -1) {
			perror("bind");
			goto bail;
		}

		if (listen(sock, MAX_CLIENTS) == -1) {
			perror("listen");
			goto bail;
		}

		remote_len = sizeof(remote_addr);
		sock = accept(sock,
				(struct sockaddr *) &remote_addr,
				&remote_len);
		if (sock < 0) {
			perror("accept");
			return sock;
		}
	} else {
		memcpy(&server_addr.sin_addr, server->h_addr_list[0],
				server->h_length);
		if (connect(sock,
					(struct sockaddr *)&server_addr,
					sizeof(server_addr)) == -1) {
			perror("connect");
			goto bail;
		}
	}

	return sock;
bail:
	close(sock);
	return -1;
}

/* Send client options to server, return 0 on success, -1 on failure */
int exchange_info(int sock, struct benchmark_info *info)
{
	if (info->is_server) {
		RECV(sock, info->min_msg_sz, long);
		RECV(sock, info->max_msg_sz, long);
		RECV(sock, info->run_flush, int);
		RECV(sock, info->show_mqstats, int);
	} else {
		SEND(sock, info->min_msg_sz, long);
		SEND(sock, info->max_msg_sz, long);
		SEND(sock, info->run_flush, int);
		SEND(sock, info->show_mqstats, int);
	}

	return 0;
bail:
	fprintf(stderr, "%s failure\n", __func__);
	return -1;
}
