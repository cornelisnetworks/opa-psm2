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

/*
 * interface to OPA Interconnect Protocol Stack
 *
 * This file contains the function prototypes of the interconnect protocol
 * stack. It should be included in all the clients of the stack, such as MPI.
 */

#ifndef ipserror_h
#define ipserror_h

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
#define IPS_RC_OK 0
#define IPS_RC_ERROR (-1)
#define IPS_RC_PENDING (-2)
#define IPS_RC_EXIST (-3)
#define IPS_RC_MAX_ENTRIES_EXCEEDED (-4)
#define IPS_RC_NOT_ENOUGH_BUFFERS   (-100)
#define IPS_RC_NO_FREE_MEM  (-101)
#define IPS_RC_NAME_LOOKUP_FAILED   (-102)
#define IPS_RC_PARAM_ERROR  (-103)
#define IPS_RC_UNKNOWN_DEVICE   (-104)
#define IPS_RC_DEVICE_INIT_FAILED   (-105)
#define IPS_RC_DATA_TRUNCATED   (-106)
#define IPS_RC_INVALID_RANK (-107)
#define IPS_RC_INVALID_OPCODE   (-108)
#define IPS_RC_PEER_NOT_READY   (-109)
#define IPS_RC_PEER_CLOSED  (-110)
#define IPS_RC_DEST_EQUAL_LOCAL_RANK    (-111)
#define IPS_RC_DEVICE_ERROR  (-112)
#define IPS_RC_NETWORK_DOWN  (-113)
#define IPS_RC_NOT_ENOUGH_FREE_TIDS   (-114)
#define IPS_RC_NO_RESOURCE_AVAILABLE (-115)
#define IPS_RC_HW_UPDATE_FAILED (-116)
#define IPS_RC_PARTITION_ERROR   (-117)
#define IPS_RC_RUN_ERROR (-118)
#define IPS_RC_ALREADY_OPEN (-119)
#define IPS_RC_WAS_CLOSED (-120)
#define IPS_RC_DEST_EQUAL_LOCAL_LID    (-121)
#define IPS_RC_BUFFER_ALIGMENT_ERROR  (-122)
#define IPS_RC_LENGTH_ALIGMENT_ERROR  (-123)
#define IPS_RC_INVALID_DATA_LENGTH   (-124)
#define IPS_RC_BUSY (-125)
#define IPS_RC_INIT_TIMEOUT_EXPIRED (-126)
#define IPS_RC_NO_PORTS_AVAILABLE (-127)
#define IPS_RC_TRANSFER_INCOMPLETE (-128)
#define IPS_RC_SYSERR (-129)	/* errno has meaning, if no further errors since this error */
#define IPS_RC_STARTUP_ERR (-130)

/* Performance Counters Error Codes */
#define IPS_RCPERF_INIT_FAILED          (-200)
#define IPS_RCPERF_EVENT_SETUP_FAILED   (-201)
#define IPS_RCPERF_REG_DEFAULT_SET      (-202)
#define IPS_RCPERF_UNSUPPORTED_CPU      (-203)
#define IPS_RCPERF_REG_GET_FAILED       (-204)
#define IPS_RCPERF_SET_EVENT_STR_FAILED (-205)
#define IPS_RCPERF_INVALID_REGISTER     (-206)

char *ips_err_str(int);

#ifdef __cplusplus
}				/* extern "C" */
#endif
#endif
