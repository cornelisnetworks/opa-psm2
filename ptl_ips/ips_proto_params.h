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

#ifndef _IPS_PROTO_PARAMS_H
#define _IPS_PROTO_PARAMS_H

/*
 * send method: dma, pio;
 * recv method: tid, egr;
 *
 * send-recv mode combinations: 1=on, 0=off
 * A: dma:1, pio=1, tid=1, egr=1;
 * B: dma:0, pio=1, tid=1, egr=1;
 * C: dma:1, pio=0, tid=1, egr=1;
 * D: dma:1, pio=1, tid=0, egr=1;
 * E: dma:0, pio=1, tid=0, egr=1;
 * F: dma:1, pio=0, tid=0, egr=1;
 *
 * message packet type:
 * T: tiny; S: short; E: eager;
 * LR: long rts; LC: long cts; LD: long data;
 * ED: expected data; EC: expected completion;
 * C: ctrl msg;
 *
 * send,recv method for each packet type and each send-recv mode
 * -------------------------------------------------------------------
 * |    |  A       | B       | C       | D       | E       | F       |
 * -------------------------------------------------------------------
 * | T  |  pio,egr | pio,egr | dma,egr | pio,egr | pio,egr | dma,egr |
 * -------------------------------------------------------------------
 * | S  |  pio,egr | pio,egr | dma,egr | pio,egr | pio,egr | dma,egr |
 * -------------------------------------------------------------------
 * | E  |  pio,egr | pio,egr | dma,egr | pio,egr | pio,egr | dma,egr |<threshold
 * -------------------------------------------------------------------
 * | E  |  dma,egr | pio,egr | dma,egr | dma,egr | pio,egr | dma,egr |>threshold
 * -------------------------------------------------------------------
 * | LR |  pio,egr | pio,egr | dma,egr | pio,egr | pio,egr | dma,egr |
 * -------------------------------------------------------------------
 * | LC |  pio,egr | pio,egr | dma,egr | pio,egr | pio,egr | dma,egr |
 * -------------------------------------------------------------------
 * | LD |  x       | x       | x       | pio,egr | pio,egr | dma,egr |<threshold
 * -------------------------------------------------------------------
 * | LD |  x       | x       | x       | dma,egr | pio,egr | dma,egr |>threshold
 * -------------------------------------------------------------------
 * | ED |  dma,tid | pio,tid | dma,tid | x       | x       | x       |
 * -------------------------------------------------------------------
 * | EC |  pio,egr | pio,egr | dma,egr | x       | x       | x       |
 * -------------------------------------------------------------------
 * | C  |  pio,egr | pio,egr | dma,egr | pio,egr | pio,egr | dma,egr |
 * -------------------------------------------------------------------
 */

/* Constants */
#define BYTE2DWORD_SHIFT 2
#define LOWER_16_BITS 0xFFFF
#define PSM_CACHE_LINE_BYTES 64
#define PSM_FLOW_CREDITS 64
#define PSM_CRC_SIZE_IN_BYTES 8

/*
 * version of protocol header (known to chip also).
 * This value for OPA is defined in spec.
 */
#define IPS_PROTO_VERSION 0x1

/* Send retransmission */
#define IPS_PROTO_SPIO_RETRY_US_DEFAULT	2	/* in uS */

#define IPS_PROTO_ERRCHK_MS_MIN_DEFAULT	160	/* in millisecs */
#define IPS_PROTO_ERRCHK_MS_MAX_DEFAULT	640	/* in millisecs */
#define IPS_PROTO_ERRCHK_FACTOR_DEFAULT 2
#define PSM_TID_TIMEOUT_DEFAULT "160:640:2"	/* update from above params */

/* time conversion macros */
#define us_2_cycles(us) nanosecs_to_cycles(1000ULL*(us))
#define ms_2_cycles(ms)  nanosecs_to_cycles(1000000ULL*(ms))
#define sec_2_cycles(sec) nanosecs_to_cycles(1000000000ULL*(sec))

/* Per-flow flags */
#define IPS_FLOW_FLAG_NAK_SEND	    0x01
#define IPS_FLOW_FLAG_PENDING_ACK   0x02
#define IPS_FLOW_FLAG_PENDING_NAK   0x04
#define IPS_FLOW_FLAG_GEN_BECN      0x08
#define IPS_FLOW_FLAG_CONGESTED     0x10

/* tid session expected send flags  */
#define EXP_SEND_FLAG_CLEAR_ALL 0x00
#define EXP_SEND_FLAG_FREE_TIDS 0x01

#define TIMEOUT_INFINITE 0xFFFFFFFFFFFFFFFFULL	/* 64 bit all-one's  */

/*
 * scb flags for wire,
 * Only the lower 6 bits are wire-protocol options
 */
#define IPS_SEND_FLAG_NONE              0x00
#define IPS_SEND_FLAG_BLOCKING		0x01	/* blocking send */
#define IPS_SEND_FLAG_PKTCKSUM          0x02	/* Has packet checksum */
#define IPS_SEND_FLAG_AMISTINY		0x04	/* AM is tiny, exclusive */
#define IPS_SEND_FLAG_PROTO_OPTS        0x3f	/* only 6bits wire flags */

/* scb flags */
#define IPS_SEND_FLAG_PENDING		0x0100
#define IPS_SEND_FLAG_PERSISTENT	0x0200

/* 0x10000000, interrupt when done */
#define IPS_SEND_FLAG_INTR		(1<<HFI_KHDR_INTR_SHIFT)
/* 0x20000000, header suppression */
#define IPS_SEND_FLAG_HDRSUPP		(1<<HFI_KHDR_SH_SHIFT)
/* 0x80000000, request ack (normal) */
#define IPS_SEND_FLAG_ACKREQ		(1<<HFI_BTH_ACK_SHIFT)

/* proto flags */
#define IPS_PROTO_FLAG_SDMA		0x01	/* all sdma, no pio */
#define IPS_PROTO_FLAG_SPIO		0x02	/* all spio, no dma */
#define IPS_PROTO_FLAG_RCVTHREAD	0x04	/* psm recv thread is on */
#define IPS_PROTO_FLAG_LOOPBACK		0x08	/* psm loopback over hfi */
#define IPS_PROTO_FLAG_CKSUM            0x10	/* psm checksum is on */

/* Coalesced ACKs (On by default) */
#define IPS_PROTO_FLAG_COALESCE_ACKS    0x20

/* Use Path Record query (off by default) */
#define IPS_PROTO_FLAG_QUERY_PATH_REC   0x40

/* Path selection policies:
 *
 * (a) Adaptive - Dynamically determine the least loaded paths using various
 * feedback mechanism - Completion time via ACKs, NAKs, CCA using BECNs.
 *
 * (b) Static schemes  -
 *     (i) static_src  - Use path keyed off source context
 *    (ii) static_dest - Use path keyed off destination context
 *   (iii) static_base - Use only the base lid path - default till Oct'09.
 *
 * The default is adaptive. If a zero lmc network is used then there exists
 * just one path between endpoints the (b)(iii) case above.
 *
 */

#define IPS_PROTO_FLAG_PPOLICY_ADAPTIVE 0x200
#define IPS_PROTO_FLAG_PPOLICY_STATIC_SRC 0x400
#define IPS_PROTO_FLAG_PPOLICY_STATIC_DST 0x800
#define IPS_PROTO_FLAG_PPOLICY_STATIC_BASE 0x1000

/* All static policies */
#define IPS_PROTO_FLAG_PPOLICY_STATIC 0x1c00

/* IBTA CCA Protocol support */
#define IPS_PROTO_FLAG_CCA 0x2000
#define IPS_PROTO_FLAG_CCA_PRESCAN 0x4000	/* Enable RAPID CCA prescanning */

#define IPS_PROTOEXP_FLAG_ENABLED	     0x01	/* default */
#define IPS_PROTOEXP_FLAG_HDR_SUPP           0x02	/* Header suppression enabled */
#define IPS_PROTOEXP_FLAG_TID_DEBUG	     0x04	/* *not* default */
#define IPS_PROTOEXP_FLAG_RTS_CTS_INTERLEAVE 0x08	/* Interleave RTS handling. */
#define IPS_PROTOEXP_FLAGS_DEFAULT	     IPS_PROTOEXP_FLAG_ENABLED

/* We have to get an MTU of at least 2K, or else this breaks some assumptions
 * in the packets that handle tid descriptors
 */
#define IPS_PROTOEXP_MIN_MTU		2048

/* Fault injection, becomes parameters to psmi_faultinj_getspec so
 * a comma-delimited list of
 *   "spec_name", num, denom
 * Where num/denom means fault num out of every denom.
 * The defines set 'denum' and assume that num is set to 1
 *
 * These values are all defaults, each is overridable via
 * PSM_FI_<spec_name> in the environment (and yes, spec_name is in lowercase
 * *in the environment* just to minimize it appearing in the wild).  The format
 * there is <num:denom:initial_seed> so the same thing except that one can set
 * a specific seed to the random number generator.
 */
#if 1
#define IPS_FAULTINJ_DMALOST	20	/* 1 every 20 dma writev get lost */
#define IPS_FAULTINJ_PIOLOST	100	/* 1 every 100 pio writes get lost */
#define IPS_FAULTINJ_PIOBUSY	10	/* 1 every 10 pio sends get busy */
#define IPS_FAULTINJ_RECVLOST	200	/* 1 every 200 pkts dropped at recv */
#else
#define IPS_FAULTINJ_DMALOST	500	/* 1 every 500 dma writev get lost */
#define IPS_FAULTINJ_PIOLOST	3000	/* 1 every 3000 pio writes get lost */
#define IPS_FAULTINJ_PIOBUSY	100	/* 1 every 100 pio sends get busy */
#define IPS_FAULTINJ_RECVLOST	500	/* 1 every 500 pkts dropped at recv */
#endif

#endif /* _IPS_PROTO_PARAMS_H */
