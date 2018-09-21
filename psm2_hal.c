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
#include "psm2_hal.h"

#include "ptl_ips/ips_scb.h"

static SLIST_HEAD(, _psmi_hal_instance) head_hi;

/* define the current hal instance pointer */
psmi_hal_instance_t *psmi_hal_current_hal_instance = NULL;

/* psmi_hal_register_instance */
void psmi_hal_register_instance(psmi_hal_instance_t *psm_hi)
{
#define REJECT_IMPROPER_HI(MEMBER) if (!psm_hi->MEMBER) return

	/* If an attempt to register a hal instance contains a NULL func ptr, reject it. */
	/* To allow fast lookups, please keep this code segment alphabetized by hfp_*
	   func ptr member name: */
#if PSMI_HAL_INST_CNT > 1
	REJECT_IMPROPER_HI(hfp_ack_hfi_event);
	REJECT_IMPROPER_HI(hfp_check_rhf_sequence_number);
	REJECT_IMPROPER_HI(hfp_cl_q_empty);
	REJECT_IMPROPER_HI(hfp_close_context);
	REJECT_IMPROPER_HI(hfp_context_open);
	REJECT_IMPROPER_HI(hfp_dma_slot_available);
	REJECT_IMPROPER_HI(hfp_finalize);
	REJECT_IMPROPER_HI(hfp_forward_packet_to_subcontext);
	REJECT_IMPROPER_HI(hfp_free_tid);
	REJECT_IMPROPER_HI(hfp_get_bthqp);
	REJECT_IMPROPER_HI(hfp_get_cc_settings_bin);
	REJECT_IMPROPER_HI(hfp_get_cc_table_bin);
	REJECT_IMPROPER_HI(hfp_get_cl_q_head_index);
	REJECT_IMPROPER_HI(hfp_get_cl_q_tail_index);
	REJECT_IMPROPER_HI(hfp_get_context);
	REJECT_IMPROPER_HI(hfp_get_egr_buff);
	REJECT_IMPROPER_HI(hfp_get_fd);
	REJECT_IMPROPER_HI(hfp_get_gid_hi);
	REJECT_IMPROPER_HI(hfp_get_gid_lo);
	REJECT_IMPROPER_HI(hfp_get_hfi_event_bits);
	REJECT_IMPROPER_HI(hfp_get_hfi_type);
	REJECT_IMPROPER_HI(hfp_get_hw_status);
	REJECT_IMPROPER_HI(hfp_get_hw_status_freezemsg);
	REJECT_IMPROPER_HI(hfp_get_jkey);
	REJECT_IMPROPER_HI(hfp_get_lid);
	REJECT_IMPROPER_HI(hfp_get_mtu);
	REJECT_IMPROPER_HI(hfp_get_node_id);
	REJECT_IMPROPER_HI(hfp_get_num_contexts);
	REJECT_IMPROPER_HI(hfp_get_num_free_contexts);
	REJECT_IMPROPER_HI(hfp_get_pio_size);
	REJECT_IMPROPER_HI(hfp_get_pio_stall_cnt);
	REJECT_IMPROPER_HI(hfp_get_port_active);
	REJECT_IMPROPER_HI(hfp_get_port_gid);
	REJECT_IMPROPER_HI(hfp_get_port_index2pkey);
	REJECT_IMPROPER_HI(hfp_get_port_lid);
	REJECT_IMPROPER_HI(hfp_get_port_lmc);
	REJECT_IMPROPER_HI(hfp_get_port_num);
	REJECT_IMPROPER_HI(hfp_get_port_rate);
	REJECT_IMPROPER_HI(hfp_get_port_sc2vl);
	REJECT_IMPROPER_HI(hfp_get_port_sl2sc);
	REJECT_IMPROPER_HI(hfp_get_receive_event);
	REJECT_IMPROPER_HI(hfp_get_rhf_expected_sequence_number);
	REJECT_IMPROPER_HI(hfp_get_rx_egr_tid_cnt);
	REJECT_IMPROPER_HI(hfp_get_rx_hdr_q_cnt);
	REJECT_IMPROPER_HI(hfp_get_rx_hdr_q_ent_size);
	REJECT_IMPROPER_HI(hfp_get_sdma_req_size);
	REJECT_IMPROPER_HI(hfp_get_sdma_ring_size);
	REJECT_IMPROPER_HI(hfp_get_sdma_ring_slot_status);
	REJECT_IMPROPER_HI(hfp_get_subctxt);
	REJECT_IMPROPER_HI(hfp_get_subctxt_cnt);
	REJECT_IMPROPER_HI(hfp_get_tid_exp_cnt);
	REJECT_IMPROPER_HI(hfp_get_tidcache_invalidation);
	REJECT_IMPROPER_HI(hfp_get_unit_active);
	REJECT_IMPROPER_HI(hfp_get_unit_id);
	REJECT_IMPROPER_HI(hfp_get_user_major_bldtime_version);
	REJECT_IMPROPER_HI(hfp_get_user_major_runtime_version);
	REJECT_IMPROPER_HI(hfp_get_user_minor_bldtime_version);
	REJECT_IMPROPER_HI(hfp_get_user_minor_runtime_version);
	REJECT_IMPROPER_HI(hfp_hfi_reset_context);
	REJECT_IMPROPER_HI(hfp_poll_type);
	REJECT_IMPROPER_HI(hfp_retire_hdr_q_entry);
	REJECT_IMPROPER_HI(hfp_set_cl_q_head_index);
	REJECT_IMPROPER_HI(hfp_set_cl_q_tail_index);
	REJECT_IMPROPER_HI(hfp_set_effective_mtu);
	REJECT_IMPROPER_HI(hfp_set_pbc);
	REJECT_IMPROPER_HI(hfp_set_pio_size);
	REJECT_IMPROPER_HI(hfp_set_pkey);
	REJECT_IMPROPER_HI(hfp_set_rhf_expected_sequence_number);
	REJECT_IMPROPER_HI(hfp_set_tf_valid);
	REJECT_IMPROPER_HI(hfp_spio_fini);
	REJECT_IMPROPER_HI(hfp_spio_init);
	REJECT_IMPROPER_HI(hfp_spio_process_events);
	REJECT_IMPROPER_HI(hfp_spio_transfer_frame);
	REJECT_IMPROPER_HI(hfp_subcontext_ureg_get);
	REJECT_IMPROPER_HI(hfp_tidflow_check_update_pkt_seq);
	REJECT_IMPROPER_HI(hfp_tidflow_get);
	REJECT_IMPROPER_HI(hfp_tidflow_get_enabled);
	REJECT_IMPROPER_HI(hfp_tidflow_get_flowvalid);
	REJECT_IMPROPER_HI(hfp_tidflow_get_genmismatch);
	REJECT_IMPROPER_HI(hfp_tidflow_get_genval);
	REJECT_IMPROPER_HI(hfp_tidflow_get_hw);
	REJECT_IMPROPER_HI(hfp_tidflow_get_keep_after_seqerr);
	REJECT_IMPROPER_HI(hfp_tidflow_get_keep_on_generr);
	REJECT_IMPROPER_HI(hfp_tidflow_get_keep_payload_on_generr);
	REJECT_IMPROPER_HI(hfp_tidflow_get_seqmismatch);
	REJECT_IMPROPER_HI(hfp_tidflow_get_seqnum);
	REJECT_IMPROPER_HI(hfp_tidflow_reset);
	REJECT_IMPROPER_HI(hfp_tidflow_set_entry);
	REJECT_IMPROPER_HI(hfp_update_tid);
	REJECT_IMPROPER_HI(hfp_writev);
#endif
	REJECT_IMPROPER_HI(hfp_get_default_pkey);
	REJECT_IMPROPER_HI(hfp_get_num_ports);
	REJECT_IMPROPER_HI(hfp_get_num_units);
	REJECT_IMPROPER_HI(hfp_initialize);

	SLIST_INSERT_HEAD(&head_hi, psm_hi, next_hi);
}

/* psmi_hal_initialize */
int psmi_hal_initialize(void)
{
	if (SLIST_EMPTY(&head_hi))
		return -PSM_HAL_ERROR_NO_HI_REGISTERED;

	/* At this point, assuming there are multiple HAL INSTANCES that are
	   registered, and two or more of the HAL INSTANCES are capable
	   of initialization on a host, the environment variable PSM2_HAL_PREF
	   allows the user to identify the one HAL INSTANCE that is desired to
	   be used. The default policy is, when the PSM2_HAL_PREF is not set, the
	   first hal instance that successfully initializes is used. */

	union psmi_envvar_val env_hi_pref; /* HAL instance preference */
	psmi_getenv("PSM2_HAL_PREF",
		    "Indicate preference for HAL instance (Default is use first HAL"
		    " instance to successfully initialize))",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val)PSM_HAL_INSTANCE_ANY_GEN, &env_hi_pref);

	int wait; /* loop control variable */
	/* Optimization note:
	   The following code attempts to initialize two different times:
	   First time assumes that the driver is already up, and so it attempts to
	   initialize with the loop control variable: wait, set to 0.
	   The second time, when wait is set to 1, waits for the driver to come up.
	   (When the parameter to: hfp_get_num_units() call below is 0,
	   hfp_get_num_units() does not wait for the driver to come up.
	   When the parameter is non-zero, the hfp_get_num_units() call below,
	   will wait for the driver to come up.) */
	for (wait=0;wait <= 1;wait++)
	{
		struct _psmi_hal_instance *p;
		SLIST_FOREACH(p, &head_hi, next_hi)
		{
			if ((env_hi_pref.e_int == PSM_HAL_INSTANCE_ANY_GEN) ||
			    (p->type           == env_hi_pref.e_int))
			{
				int nunits = p->hfp_get_num_units(wait);
				int nports = p->hfp_get_num_ports();
				int dflt_pkey = p->hfp_get_default_pkey();
				if (nunits > 0 && nports > 0 && dflt_pkey > 0)
				{
					memset(&p->params,0,sizeof(p->params));
					int rv = p->hfp_initialize(p);
					if (!rv)
					{
						sysfs_init(p->hfi_sys_class_path);
						p->params.num_units = nunits;
						p->params.num_ports = nports;
						p->params.default_pkey = dflt_pkey;
						psmi_hal_current_hal_instance = p;
						return rv;
					}
				}
			}
		}
	}
	return -PSM_HAL_ERROR_INIT_FAILED;
}

#ifdef PSM2_MOCK_TESTING

void ips_ptl_non_dw_mul_sdma_init(void)
{
	uint16_t major_version = hfi_get_user_major_version();
	uint16_t minor_version = hfi_get_user_minor_version();
	int allow_non_dw_mul = 0;

	if ((major_version > HFI1_USER_SWMAJOR_NON_DW_MUL_MSG_SIZE_ALLOWED) ||
		((major_version == HFI1_USER_SWMAJOR_NON_DW_MUL_MSG_SIZE_ALLOWED) &&
		 (minor_version >= HFI1_USER_SWMINOR_NON_DW_MUL_MSG_SIZE_ALLOWED)))
	{
		allow_non_dw_mul = 1;
	}
	psmi_hal_current_hal_instance->params.cap_mask = 0;
	if (allow_non_dw_mul)
		psmi_hal_current_hal_instance->params.cap_mask |= PSM_HAL_CAP_NON_DW_MULTIPLE_MSG_SIZE;
}

void set_sdma_req_size_in_MOCK_HAL_instance(int sdma_req_size)
{
	extern int __psm_hal_mock_sma_req_size;

	__psm_hal_mock_sma_req_size = sdma_req_size;
}

void set_comp_entry(struct hfi1_sdma_comp_entry *pce)
{
	extern struct hfi1_sdma_comp_entry * __psm_hal_mock_hfi1_sdma_comp_entry;

	__psm_hal_mock_hfi1_sdma_comp_entry = pce;
}

#endif
