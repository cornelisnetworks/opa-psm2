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

/* Copyright (c) 2009-2014 Intel Corporation. All rights reserved. */


#ifndef _IPS_PATH_REC_H_
#define _IPS_PATH_REC_H_

#include <search.h>

/* Default size of path record hash table */
#define DF_PATH_REC_HASH_SIZE 2047

/* Default size of path group hash table */
#define DF_PATH_GRP_HASH_SIZE 255

/* Default size of CCT table. Must be multiple of 64 */
#define DF_CCT_TABLE_SIZE 128

/* CCT max IPD delay. */
#define DF_CCT_MAX_IPD_DELAY_US 21

/* CCA divisor shift */
#define CCA_DIVISOR_SHIFT 14

/* CCA ipd mask */
#define CCA_IPD_MASK 0x3FFF

/* A lot of these are IBTA specific defines that are available in other header
 * files. To minimize dependencies with PSM build process they are listed
 * here. Most of this is used to implement IBTA compliance features with PSM
 * like path record query etc.
 */

enum opa_mtu {
	IBTA_MTU_256  = 1,
	IBTA_MTU_512  = 2,
	IBTA_MTU_1024 = 3,
	IBTA_MTU_2048 = 4,
	IBTA_MTU_4096 = 5,
	OPA_MTU_8192  = 6,
	OPA_MTU_10240 = 7,
	IBTA_MTU_MIN  = IBTA_MTU_256,
	OPA_MTU_MIN   = IBTA_MTU_256,
	OPA_MTU_MAX   = OPA_MTU_10240,
};

typedef enum {
        IBV_RATE_MAX      = 0,
        IBV_RATE_2_5_GBPS = 2,
        IBV_RATE_5_GBPS   = 5,
        IBV_RATE_10_GBPS  = 3,
        IBV_RATE_20_GBPS  = 6,
        IBV_RATE_30_GBPS  = 4,
        IBV_RATE_40_GBPS  = 7,
        IBV_RATE_60_GBPS  = 8,
        IBV_RATE_80_GBPS  = 9,
        IBV_RATE_120_GBPS = 10,
        IBV_RATE_14_GBPS  = 11,
        IBV_RATE_56_GBPS  = 12,
        IBV_RATE_112_GBPS = 13,
        IBV_RATE_168_GBPS = 14,
        IBV_RATE_25_GBPS  = 15,
        IBV_RATE_100_GBPS = 16,
        IBV_RATE_200_GBPS = 17,
        IBV_RATE_300_GBPS = 18
} opa_rate;

static inline int opa_mtu_enum_to_int(enum opa_mtu mtu)
{
	switch (mtu) {
	case IBTA_MTU_256:
		return 256;
	case IBTA_MTU_512:
		return 512;
	case IBTA_MTU_1024:
		return 1024;
	case IBTA_MTU_2048:
		return 2048;
	case IBTA_MTU_4096:
		return 4096;
	case OPA_MTU_8192:
		return 8192;
	case OPA_MTU_10240:
		return 10240;
	default:
		return -1;
	}
}

/* This is same as ob_path_rec from ib_types.h. Listed here to be self
 * contained to minimize dependencies during build etc.
 */
typedef struct _ibta_path_rec {
	uint64_t service_id;	/* net order */
	uint8_t dgid[16];
	uint8_t sgid[16];
	uint16_t dlid;		/* net order */
	uint16_t slid;		/* net order */
	uint32_t hop_flow_raw;	/* net order */
	uint8_t tclass;
	uint8_t num_path;
	uint16_t pkey;		/* net order */
	uint16_t qos_class_sl;	/* net order */
	uint8_t mtu;		/* IBTA encoded */
	uint8_t rate;		/* IBTA encoded */
	uint8_t pkt_life;	/* IBTA encoded */
	uint8_t preference;
	uint8_t resv2[6];
} ibta_path_rec_t;

/*
 * PSM IPS path record components for endpoint.
 */
struct ips_proto;
typedef struct ips_path_rec {
	uint16_t pr_slid;	/* For Torus/non zero LMC fabrics this can be diff */
	uint16_t pr_dlid;
	uint16_t pr_mtu;
	uint16_t pr_pkey;
	uint16_t pr_static_ipd;	/* Static rate IPD from path record */
	uint8_t pr_sl;

	/* IBTA CCA parameters per path */
	uint8_t pr_cca_divisor;	/* CCA divisor [14:15] in CCT entry */
	uint16_t pr_active_ipd;	/* The current active IPD. max(static,cct) */
	uint16_t pr_ccti;	/* CCA table index */
	psmi_timer *pr_timer_cca;	/* Congestion timer for epr_ccti increment. */
	struct ips_proto *proto;	/* for global info */
} ips_path_rec_t;

psm_error_t ips_opp_init(struct ips_proto *proto);

#endif
