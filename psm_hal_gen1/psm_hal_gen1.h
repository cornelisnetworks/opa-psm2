/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2017 Intel Corporation.

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

  Copyright(c) 2017 Intel Corporation.

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

#include "psm_user.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "psm_hal_gen1_spio.h"
#include "psm_mq_internal.h"
#include "opa_user_gen1.h"

#define LAST_RHF_SEQNO 13

typedef struct
{
	volatile uint64_t *cl_q_head;
	volatile uint64_t *cl_q_tail;
	union
	{
		/* hdr_qe's are only present in *_RX_HDR_Q* CL Q types: */
		struct
		{
			uint32_t rx_hdrq_rhf_seq;
			uint32_t *p_rx_hdrq_rhf_seq;
			uint32_t *hdrq_base_addr;
		} hdr_qe;  /* header queue entry */
		/* egr_buffs's are only present in *_RX_EGR_Q* CL Q types: */
		void **egr_buffs;
	};
} psm_hal_gen1_cl_q_t;

COMPILE_TIME_ASSERT(MAX_SHARED_CTXTS_MUST_MATCH, PSM_HAL_MAX_SHARED_CTXTS == HFI1_MAX_SHARED_CTXTS);

/* Private struct on a per-context basis. */
typedef struct _hfp_gen1_pc_private
{
	struct _hfi_ctrl	    *ctrl; /* driver opaque hfi_proto */
	psm_hal_gen1_cl_q_t         cl_qs[PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(7) + 1];
	struct ips_hwcontext_ctrl  *hwcontext_ctrl;
	struct ips_subcontext_ureg *subcontext_ureg[HFI1_MAX_SHARED_CTXTS];
	struct ips_spio		    spio_ctrl;
	struct hfi1_user_info_dep   user_info;
} hfp_gen1_pc_private;

/* At the end of each scb struct, we have space reserved to accommodate
 * three structures (for GEN1)-
 * struct psm_hal_sdma_req_info, struct psm_hal_pbc and struct ips_message_header.
 * The HIC should get the size needed for the extended memory region
 * using a HAL call (psmi_hal_get_scb_extended_mem_size). For Gen1, this API
 * will return the size of the below struct psm_hal_gen1_scb_extended
 * aligned up to be able to fit struct psm_hal_pbc on a 64-byte boundary.
 */

#define PSMI_SHARED_CONTEXTS_ENABLED_BY_DEFAULT   1

struct psm_hal_gen1_scb_extended {
	union
	{
		struct sdma_req_info sri1;
		struct sdma_req_info_v6_3 sri2;
	};
	struct {
		struct psm_hal_pbc pbc;
		struct ips_message_header ips_lrh;
	} PSMI_CACHEALIGN;
};

/* declare the hfp_gen1_private struct */
typedef struct _hfp_gen1_private
{
	/* GEN1 specific data that are common to all contexts: */
	int      sdmahdr_req_size;
	int      dma_rtail;
	uint32_t hdrq_rhf_off;
} hfp_gen1_private_t;

/* declare hfp_gen1_t struct, (combines public psmi_hal_instance_t
   together with a private struct) */
typedef struct _hfp_gen1
{
	psmi_hal_instance_t phi;
	hfp_gen1_private_t  hfp_private;
} hfp_gen1_t;

static const struct
{
	uint32_t hfi1_event_bit, psmi_hal_hfi_event_bit;
} hfi1_events_map[] =
{
	{ HFI1_EVENT_FROZEN,		PSM_HAL_HFI_EVENT_FROZEN	},
	{ HFI1_EVENT_LINKDOWN,		PSM_HAL_HFI_EVENT_LINKDOWN	},
	{ HFI1_EVENT_LID_CHANGE,	PSM_HAL_HFI_EVENT_LID_CHANGE	},
	{ HFI1_EVENT_LMC_CHANGE,	PSM_HAL_HFI_EVENT_LMC_CHANGE	},
	{ HFI1_EVENT_SL2VL_CHANGE,	PSM_HAL_HFI_EVENT_SL2VL_CHANGE	},
	{ HFI1_EVENT_TID_MMU_NOTIFY,	PSM_HAL_HFI_EVENT_TID_MMU_NOTIFY},
};
