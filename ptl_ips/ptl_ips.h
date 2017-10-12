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

#ifndef _IPS_PTL_H
#define _IPS_PTL_H

#include "psm_user.h"
#include "psm_mq_internal.h"

#include "ips_proto_params.h"
#include "ips_proto.h"
#include "ips_spio.h"
#include "ips_recvhdrq.h"
#include "ips_writehdrq.h"
#include "ips_epstate.h"
#include "ips_stats.h"
#include "ips_subcontext.h"

struct ptl_shared;

/*
 * PTL at the ips level (for OPA)
 *
 * This PTL structure glues all the ips components together.
 *
 * * ips timer, shared by various components, allows each component to
 *   schedule time-based expiration callbacks on the timerq.
 * * HW receive queue
 * * send control block to handle eager messages
 * * instantiation of the ips protocol
 * * endpoint state, to map endpoint indexes into structures
 *
 *   Receive-side
 *
 *          ----[   proto    ]
 *         /       ^      ^
 *        |        |      |
 *        |     packet  packet
 *        |	known   unknown
 *   add_endpt      \ /
 *        |          |
 *        `----> [epstate]
 *                   ^
 *                   |
 *               lookup_endpt
 *                   |
 *                [recvq]
 *                   |
 *                 poll
 *
 */
/* Updates to this struct must be reflected in PTL_IPS_SIZE in ptl_fwd.h */
/* IPS knows it functions as a PTL whenever ptl->ep is non-NULL */
struct ptl {
	psm2_ep_t ep;		/* back ptr */
	psm2_epid_t epid;	/* cached from ep */
	psm2_epaddr_t epaddr;	/* cached from ep */
	ips_epaddr_t *ipsaddr;	/* cached from epaddr */
	ptl_ctl_t *ctl;		/* cached from init */
	const psmi_context_t *context;	/* cached from init */

	struct ips_spio spioc;	/* PIO send control */
	struct ips_proto proto;	/* protocol instance: timerq, epstate, spio */

	/* Receive header queue and receive queue processing */
	uint32_t runtime_flags;
	struct psmi_timer_ctrl timerq;
	struct ips_epstate epstate;	/* map incoming packets */
	struct ips_recvhdrq_state recvq_state;
	struct ips_recvhdrq recvq;	/* HW recvq: epstate, proto */

	/* timer to check the context's status */
	struct psmi_timer status_timer;

	/* context's status check timeout in cycles -- cached */
	uint64_t status_cyc_timeout;

	/* Shared contexts context */
	struct ptl_shared *recvshc;

	/* Rcv thread context */
	struct ptl_rcvthread *rcvthread;
}
#ifndef PACK_STRUCT_STL
#define PACK_STRUCT_STL /* nothing */
#endif
 __attribute__ ((PACK_STRUCT_STL aligned(16)));

/*
 * Sample implementation of shared contexts context.
 *
 * In shared mode, the hardware queue is serviced by more than one process.
 * Each process also mirrors the hardware queue in software (represented by an
 * ips_recvhdrq).  For packets we service in the hardware queue that are not
 * destined for us, we write them in other processes's receive queues
 * (represented by an ips_writehdrq).
 *
 */
struct ptl_shared {
	ptl_t *ptl;		/* backptr to main ptl */
	uint32_t context;
	uint32_t subcontext;
	uint32_t subcontext_cnt;

	pthread_spinlock_t *context_lock;
	struct ips_subcontext_ureg *subcontext_ureg[HFI1_MAX_SHARED_CTXTS];
	struct ips_hwcontext_ctrl *hwcontext_ctrl;
	struct ips_recvhdrq recvq;	/* subcontext receive queue */
	struct ips_recvhdrq_state recvq_state;	/* subcontext receive queue state */
	struct ips_writehdrq writeq[HFI1_MAX_SHARED_CTXTS];	/* peer subcontexts */
};

/*
 * Connect/disconnect are wrappers around psm proto's connect/disconnect,
 * mostly to abstract away PSM-specific stuff from ips internal structures
 */
psm2_error_t ips_ptl_connect(ptl_t *ptl, int numep,
			    const psm2_epid_t *array_of_epid,
			    const int *array_of_epid_mask,
			    psm2_error_t *array_of_errors,
			    psm2_epaddr_t *array_of_epaddr,
			    uint64_t timeout_in);

psm2_error_t ips_ptl_disconnect(ptl_t *ptl, int force, int numep,
			       psm2_epaddr_t array_of_epaddr[],
			       const int array_of_epaddr_mask[],
			       psm2_error_t array_of_errors[],
			       uint64_t timeout_in);

/*
 * Generic Poll function for ips-level ptl
 */
psm2_error_t ips_ptl_poll(ptl_t *ptl, int _ignored);
psm2_error_t ips_ptl_shared_poll(ptl_t *ptl, int _ignored);

/*
 * Support for receive thread
 */
psm2_error_t ips_ptl_rcvthread_init(ptl_t *ptl, struct ips_recvhdrq *recvq);
psm2_error_t ips_ptl_rcvthread_fini(ptl_t *ptl);
void ips_ptl_rcvthread_transfer_ownership(ptl_t *from_ptl, ptl_t *to_ptl);

#endif /* _IPS_PTL_H */
