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

#ifndef PTL_IPS_IPS_CONFIG_H
#define PTL_IPS_IPS_CONFIG_H

#include "psm_config.h"

/* Allocate new epaddrs in chunks of 128 */
#define PTL_EPADDR_ALLOC_CHUNK  128

/* Generate an expected header every 16 packets */
#define PSM_DEFAULT_EXPECTED_HEADER 16

#define DF_OPP_LIBRARY "libopasadb.so.1.0.0"
#define DATA_VFABRIC_OFFSET 8

/* Send retransmission */
#define IPS_PROTO_SPIO_RETRY_US_DEFAULT	2	/* in uS */

#define IPS_PROTO_ERRCHK_MS_MIN_DEFAULT	160	/* in millisecs */
#define IPS_PROTO_ERRCHK_MS_MAX_DEFAULT	640	/* in millisecs */
#define IPS_PROTO_ERRCHK_FACTOR_DEFAULT 2
#define PSM_TID_TIMEOUT_DEFAULT "160:640:2"	/* update from above params */

/* We have to get an MTU of at least 2K, or else this breaks some assumptions
 * in the packets that handle tid descriptors
 */
#define IPS_PROTOEXP_MIN_MTU		2048

#ifdef PSM_FI

/* Fault injection, becomes parameters to psmi_faultinj_getspec so
 * a comma-delimited list of
 *   "spec_name", num, denom
 * Where num/denom means fault num out of every denom.
 * The defines set 'denum' and assume that num is set to 1
 *
 * These values are all defaults, each is overridable via
 * PSM2_FI_<spec_name> in the environment (and yes, spec_name is in lowercase
 * *in the environment* just to minimize it appearing in the wild).  The format
 * there is <num:denom:initial_seed> so the same thing except that one can set
 * a specific seed to the random number generator.
 */
#define IPS_FAULTINJ_DMALOST	20	/* 1 every 20 dma writev get lost */
#define IPS_FAULTINJ_PIOLOST	100	/* 1 every 100 pio writes get lost */
#define IPS_FAULTINJ_PIOBUSY	10	/* 1 every 10 pio sends get busy */
#define IPS_FAULTINJ_RECVLOST	200	/* 1 every 200 pkts dropped at recv */

#endif /* #ifdef PSM_FI */

/* TID */

/* Max tids a context can support */
#define IPS_TID_MAX_TIDS    2048
/* Max tid-session buffer size */
#define PSM_TIDLIST_BUFSIZE 4096
/* Max tid-session window size */
#define PSM_TID_WINSIZE     (4*1024*1024)
/* Max number of packets for a single TID flow, fitting tid-session window.
 * In PSM2 packet integrity is realized by PSN (Packet Sequence Number),
 * which is kept as 11 bits field (for 9B KDETH),
 * giving max value 2048 (0 - 2047) */
#define PSM_TID_MAX_PKTS    2048
/* Total number of combined pages from the Tid-pair to be merged */
#define PSM_MAX_NUM_PAGES_IN_TIDPAIR    512


/* rcv thread */
/* All in milliseconds */
#define RCVTHREAD_TO_MIN_FREQ	    10	/* min of 10 polls per sec */
#define RCVTHREAD_TO_MAX_FREQ	    100	/* max of 100 polls per sec */
#define RCVTHREAD_TO_SHIFT	    1

/* ptl.c */
#define PSMI_CONTEXT_STATUS_CHECK_INTERVAL_MSECS	250

/* ips_proto_recv.c */
#define PSM_STRAY_WARN_INTERVAL_DEFAULT_SECS	30

/*
 * Easy switch to (say) _HFI_INFO if debugging in the expected protocol is
 * needed
 */
#define _HFI_EXP _HFI_VDBG

#endif /* PTL_IPS_IPS_CONFIG_H */
