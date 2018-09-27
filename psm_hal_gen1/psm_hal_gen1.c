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

#if PSMI_HAL_INST_CNT > 1
#define PSMI_HAL_CAT_INL_SYM(KERNEL) hfp_gen1_ ## KERNEL
#include "psm2_hal_inline_t.h"
#include "psm_hal_inline_i.h"
#endif

/* define the singleton that implements hal for gen1 */
static hfp_gen1_t psm_gen1_hi = {
	/* start of public psmi_hal_instance_t data */
	.phi = {
		.type					  = PSM_HAL_INSTANCE_GEN1,
		.description				  = "PSM2 HAL instance for GEN1"
#ifdef PSM_CUDA
								" (cuda)"
#endif
									,
		.hfi_name				  = "hfi1",
		.hfi_sys_class_path			  = "/sys/class/infiniband/hfi1",
		.params					  = {0},

		/* The following methods are alphabetized */
#if PSMI_HAL_INST_CNT > 1
		.hfp_ack_hfi_event			  = hfp_gen1_ack_hfi_event,
		.hfp_check_rhf_sequence_number		  = hfp_gen1_check_rhf_sequence_number,
		.hfp_cl_q_empty				  = hfp_gen1_cl_q_empty,
		.hfp_close_context			  = hfp_gen1_close_context,
		.hfp_context_open			  = hfp_gen1_context_open,
		.hfp_dma_slot_available			  = hfp_gen1_dma_slot_available,
		.hfp_finalize				  = hfp_gen1_finalize,
		.hfp_forward_packet_to_subcontext	  = hfp_gen1_forward_packet_to_subcontext,
		.hfp_free_tid				  = hfp_gen1_free_tid,
		.hfp_get_bthqp				  = hfp_gen1_get_bthqp,
		.hfp_get_cc_settings_bin		  = hfp_gen1_get_cc_settings_bin,
		.hfp_get_cc_table_bin			  = hfp_gen1_get_cc_table_bin,
		.hfp_get_cl_q_head_index		  = hfp_gen1_get_cl_q_head_index,
		.hfp_get_cl_q_tail_index		  = hfp_gen1_get_cl_q_tail_index,
		.hfp_get_context			  = hfp_gen1_get_context,
		.hfp_get_egr_buff			  = hfp_gen1_get_egr_buff,
		.hfp_get_fd				  = hfp_gen1_get_fd,
		.hfp_get_gid_hi				  = hfp_gen1_get_gid_hi,
		.hfp_get_gid_lo				  = hfp_gen1_get_gid_lo,
		.hfp_get_hfi_event_bits			  = hfp_gen1_get_hfi_event_bits,
		.hfp_get_hfi_type			  = hfp_gen1_get_hfi_type,
		.hfp_get_hw_status			  = hfp_gen1_get_hw_status,
		.hfp_get_hw_status_freezemsg		  = hfp_gen1_get_hw_status_freezemsg,
		.hfp_get_jkey				  = hfp_gen1_get_jkey,
		.hfp_get_lid				  = hfp_gen1_get_lid,
		.hfp_get_node_id			  = hfp_gen1_get_node_id,
		.hfp_get_num_contexts			  = hfp_gen1_get_num_contexts,
		.hfp_get_num_free_contexts		  = hfp_gen1_get_num_free_contexts,
		.hfp_get_pio_size			  = hfp_gen1_get_pio_size,
		.hfp_get_pio_stall_cnt			  = hfp_gen1_get_pio_stall_cnt,
		.hfp_get_port_active			  = hfp_gen1_get_port_active,
		.hfp_get_port_gid			  = hfp_gen1_get_port_gid,
		.hfp_get_port_index2pkey		  = hfp_gen1_get_port_index2pkey,
		.hfp_get_port_lid			  = hfp_gen1_get_port_lid,
		.hfp_get_port_lmc			  = hfp_gen1_get_port_lmc,
		.hfp_get_port_num			  = hfp_gen1_get_port_num,
		.hfp_get_port_rate			  = hfp_gen1_get_port_rate,
		.hfp_get_port_sc2vl			  = hfp_gen1_get_port_sc2vl,
		.hfp_get_port_sl2sc			  = hfp_gen1_get_port_sl2sc,
		.hfp_get_receive_event			  = hfp_gen1_get_receive_event,
		.hfp_get_rhf_expected_sequence_number	  = hfp_gen1_get_rhf_expected_sequence_number,
		.hfp_get_rx_egr_tid_cnt			  = hfp_gen1_get_rx_egr_tid_cnt,
		.hfp_get_rx_hdr_q_cnt			  = hfp_gen1_get_rx_hdr_q_cnt,
		.hfp_get_rx_hdr_q_ent_size		  = hfp_gen1_get_rx_hdr_q_ent_size,
		.hfp_get_sdma_req_size			  = hfp_gen1_get_sdma_req_size,
		.hfp_get_sdma_ring_size			  = hfp_gen1_get_sdma_ring_size,
		.hfp_get_sdma_ring_slot_status		  = hfp_gen1_get_sdma_ring_slot_status,
		.hfp_get_subctxt			  = hfp_gen1_get_subctxt,
		.hfp_get_subctxt_cnt			  = hfp_gen1_get_subctxt_cnt,
		.hfp_get_tid_exp_cnt			  = hfp_gen1_get_tid_exp_cnt,
		.hfp_get_tidcache_invalidation		  = hfp_gen1_get_tidcache_invalidation,
		.hfp_get_unit_active			  = hfp_gen1_get_unit_active,
		.hfp_get_unit_id			  = hfp_gen1_get_unit_id,
		.hfp_get_user_major_bldtime_version	  = hfp_gen1_get_user_major_bldtime_version,
		.hfp_get_user_major_bldtime_version	  = hfp_gen1_get_user_major_bldtime_version,
		.hfp_get_user_major_runtime_version	  = hfp_gen1_get_user_major_runtime_version,
		.hfp_get_user_major_runtime_version	  = hfp_gen1_get_user_major_runtime_version,
		.hfp_get_user_minor_bldtime_version	  = hfp_gen1_get_user_minor_bldtime_version,
		.hfp_get_user_minor_bldtime_version	  = hfp_gen1_get_user_minor_bldtime_version,
		.hfp_get_user_minor_runtime_version	  = hfp_gen1_get_user_minor_runtime_version,
		.hfp_get_user_minor_runtime_version	  = hfp_gen1_get_user_minor_runtime_version,
		.hfp_hfi_reset_context			  = hfp_gen1_hfi_reset_context,
		.hfp_poll_type				  = hfp_gen1_poll_type,
		.hfp_retire_hdr_q_entry			  = hfp_gen1_retire_hdr_q_entry,
		.hfp_set_cl_q_head_index		  = hfp_gen1_set_cl_q_head_index,
		.hfp_set_cl_q_tail_index		  = hfp_gen1_set_cl_q_tail_index,
		.hfp_set_effective_mtu			  = hfp_gen1_set_effective_mtu,
		.hfp_set_pbc				  = hfp_gen1_set_pbc,
		.hfp_set_pio_size			  = hfp_gen1_set_pio_size,
		.hfp_set_pkey				  = hfp_gen1_set_pkey,
		.hfp_set_rhf_expected_sequence_number	  = hfp_gen1_set_rhf_expected_sequence_number,
		.hfp_set_tf_valid			  = hfp_gen1_set_tf_valid,
		.hfp_spio_fini				  = hfp_gen1_spio_fini,
		.hfp_spio_init				  = hfp_gen1_spio_init,
		.hfp_spio_process_events		  = hfp_gen1_spio_process_events,
		.hfp_spio_transfer_frame		  = hfp_gen1_spio_transfer_frame,
		.hfp_subcontext_ureg_get		  = hfp_gen1_subcontext_ureg_get,
		.hfp_tidflow_check_update_pkt_seq	  = hfp_gen1_tidflow_check_update_pkt_seq,
		.hfp_tidflow_get			  = hfp_gen1_tidflow_get,
		.hfp_tidflow_get_enabled		  = hfp_gen1_tidflow_get_enabled,
		.hfp_tidflow_get_flowvalid		  = hfp_gen1_tidflow_get_flowvalid,
		.hfp_tidflow_get_genmismatch		  = hfp_gen1_tidflow_get_genmismatch,
		.hfp_tidflow_get_genval			  = hfp_gen1_tidflow_get_genval,
		.hfp_tidflow_get_hw			  = hfp_gen1_tidflow_get_hw,
		.hfp_tidflow_get_keep_after_seqerr	  = hfp_gen1_tidflow_get_keep_after_seqerr,
		.hfp_tidflow_get_keep_on_generr		  = hfp_gen1_tidflow_get_keep_on_generr,
		.hfp_tidflow_get_keep_payload_on_generr	  = hfp_gen1_tidflow_get_keep_payload_on_generr,
		.hfp_tidflow_get_seqmismatch		  = hfp_gen1_tidflow_get_seqmismatch,
		.hfp_tidflow_get_seqnum			  = hfp_gen1_tidflow_get_seqnum,
		.hfp_tidflow_reset			  = hfp_gen1_tidflow_reset,
		.hfp_tidflow_set_entry			  = hfp_gen1_tidflow_set_entry,
		.hfp_update_tid				  = hfp_gen1_update_tid,
		.hfp_writev				  = hfp_gen1_writev,
#endif
		.hfp_get_default_pkey			  = hfp_gen1_get_default_pkey,
		.hfp_get_num_units			  = hfp_gen1_get_num_units,
		.hfp_get_num_ports			  = hfp_gen1_get_num_ports,
		.hfp_initialize				  = hfp_gen1_initialize,
	},
	/* start of private hfp_gen1_private data */
	.hfp_private = {
		.sdmahdr_req_size	= 0,
		.dma_rtail		= 0,
		.hdrq_rhf_off		= 0,
	}
};

/* __psmi_hal_gen1_constructor */
static void __attribute__ ((constructor)) __psmi_hal_gen1_constructor(void)
{
	psmi_hal_register_instance((psmi_hal_instance_t*)&psm_gen1_hi);
}
