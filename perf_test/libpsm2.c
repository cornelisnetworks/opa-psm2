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

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "libpsm2.h"
#include "psm2perf.h"

int libpsm2_rank;

psm2_epaddr_t *libpsm2_epaddrs;
psm2_ep_t libpsm2_ep;
psm2_mq_t libpsm2_mq;
static psm2_epid_t libpsm2_epid;

/* Initialize psm2, return 0 on success, -1 on failure */
int libpsm2_init(int sock, int is_server)
{
	int i;
	psm2_error_t err, epid_errs[MAX_PSM2_RANKS];
	psm2_uuid_t uuid;
	psm2_epid_t *epids = NULL;
	psm2_epaddr_t *epaddrs = NULL;
	int ver_major = PSM2_VERNO_MAJOR;
	int ver_minor = PSM2_VERNO_MINOR;

	libpsm2_rank = 0;
	if (!is_server)
		libpsm2_rank = 1;

	libpsm2_epaddrs = (psm2_epaddr_t *)
		malloc(sizeof(psm2_epaddr_t) * MAX_PSM2_RANKS);
	if (libpsm2_epaddrs == NULL) {
		perror("malloc libpsm2_epaddrs");
		goto bail;
	}

	epids = (psm2_epid_t *) malloc(sizeof(psm2_epid_t) * MAX_PSM2_RANKS);
	if (epids == NULL) {
		perror("malloc epids");
		goto bail;
	}

	epaddrs = (psm2_epaddr_t *) malloc(sizeof(psm2_epaddr_t) * MAX_PSM2_RANKS);
	if (epaddrs == NULL) {
		perror("malloc epaddrs");
		goto bail;
	}

	err = psm2_init(&ver_major, &ver_minor);
	if (err != PSM2_OK) {
		PSM2_ERR(err, "psm2_init failure\n");
		goto bail;
	}

	// Generate and exchange the uuid for this job
	if (is_server) {
		psm2_uuid_generate(uuid);
		SEND(sock, uuid, psm2_uuid_t);
	} else
		RECV(sock, uuid, psm2_uuid_t);

	err = psm2_ep_open(uuid, NULL, &libpsm2_ep, &libpsm2_epid);
	if (err != PSM2_OK) {
		PSM2_ERR(err, "psm2_ep_open error\n");
		goto bail;
	}
	epids[libpsm2_rank] = libpsm2_epid;

	err = psm2_mq_init(libpsm2_ep, PSM2_MQ_ORDERMASK_NONE,
			NULL, 0, &libpsm2_mq);
	if (err != PSM2_OK) {
		PSM2_ERR(err, "psm2_mq_init failure\n");
		goto bail;
	}

	// Exchange server and client epids
	SEND(sock, libpsm2_epid, psm2_epid_t);
	RECV(sock, epids[(libpsm2_rank + 1) % MAX_PSM2_RANKS], psm2_epid_t);

	err = psm2_ep_connect(libpsm2_ep,
			MAX_PSM2_RANKS,
			epids,
			NULL,
			epid_errs,
			epaddrs,
			0);
	if (err != PSM2_OK) {
		PSM2_ERR(err, "psm2_ep_connect failure\n");
		goto bail;
	}

	// Save the epaddrs for later
	for (i = 0; i < MAX_PSM2_RANKS; i++)
		libpsm2_epaddrs[i] = epaddrs[i];

	free(epids);
	free(epaddrs);
	return 0;

bail:
	fprintf(stderr, "%s failed\n", __func__);
	if (epids != NULL)
		free(epids);
	if (epaddrs != NULL)
		free(epaddrs);
	if (libpsm2_epaddrs != NULL)
		free(libpsm2_epaddrs);
	if (libpsm2_mq != NULL)
		psm2_mq_finalize(libpsm2_mq);
	if (libpsm2_ep != NULL)
		psm2_ep_close(libpsm2_ep, PSM2_EP_CLOSE_GRACEFUL, -1);
	psm2_finalize();
	return -1;
}

/* Only psm2_mq_finalize can return something other than PSM2_OK.
 * Ignoring if psm2_mq_finalize has a problem.
 */
void libpsm2_shutdown(void)
{
	free(libpsm2_epaddrs);

	int err = psm2_mq_finalize(libpsm2_mq);

	if (err != PSM2_OK)
		PSM2_ERR(err, "psm2_mq_finalize failure\n");

	psm2_ep_close(libpsm2_ep, PSM2_EP_CLOSE_GRACEFUL, -1);
	psm2_finalize();
}

void print_psm2_stats(void)
{
	psm2_mq_stats_t stats;

	psm2_mq_get_stats(libpsm2_mq, &stats);
	printf("PSM2 MQ STATS:\n");
	printf("rx_user_bytes %lu\n", stats.rx_user_bytes);
	printf("rx_user_num %lu\n", stats.rx_user_num);
	printf("rx_sys_bytes %lu\n", stats.rx_sys_bytes);
	printf("rx_sys_num %lu\n", stats.rx_sys_num);

	printf("tx_num %lu\n", stats.tx_num);
	printf("tx_eager_num %lu\n", stats.tx_eager_num);
	printf("tx_eager_bytes %lu\n", stats.tx_eager_bytes);
	printf("tx_rndv_num %lu\n", stats.tx_rndv_num);
	printf("tx_rndv_bytes %lu\n", stats.tx_rndv_bytes);

	printf("tx_shm_num %lu\n", stats.tx_shm_num);
	printf("rx_shm_num %lu\n", stats.rx_shm_num);

	printf("rx_sysbuf_num %lu\n", stats.rx_sysbuf_num);
	printf("rx_sysbuf_bytes %lu\n", stats.rx_sysbuf_bytes);
}
