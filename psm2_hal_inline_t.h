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

/* The psm2_hal_inline_t.h file serves as a template to allow all HAL
   instances to easily and conveniently declare their HAL methods. */

static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(initialize)
				(psmi_hal_instance_t *);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(finalize)
				(void);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_num_units)
				(int wait);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_num_ports)
				(void);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_unit_active)
				(int unit);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_node_id)
				(int unit, int *nodep);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_active)
				(int unit, int port);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_num_contexts)
				(int unit);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_num_free_contexts)
				(int unit);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(close_context)
				(psmi_hal_hw_context *);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(context_open)
				(int unit,
				 int port,
				 uint64_t open_timeout,
				 psm2_ep_t ep,
				 psm2_uuid_t const job_key,
				 psmi_context_t *psm_ctxt,
				 uint32_t cap_mask,
				 unsigned);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_index2pkey)
				(int unit, int port, int index);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_cc_settings_bin)
				(int unit, int port, char *ccabuf, size_t len_ccabuf);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_cc_table_bin)
				(int unit, int port, uint16_t **ccatp);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_lmc)
				(int unit, int port);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_rate)
				(int unit, int port);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_sl2sc)
				(int unit, int port, int sl);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_sc2vl)
				(int unit, int port, int sc);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(set_pkey)
				(psmi_hal_hw_context, uint16_t);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(poll_type)
				(uint16_t, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_lid)
				(int unit, int port);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_port_gid)
				(int unit, int port,
				uint64_t *hi, uint64_t *lo);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(free_tid)
				(psmi_hal_hw_context, uint64_t tidlist, uint32_t tidcnt);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_tidcache_invalidation)
				(psmi_hal_hw_context, uint64_t tidlist, uint32_t *tidcnt);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(update_tid)
				(psmi_hal_hw_context, uint64_t vaddr, uint32_t *length,
					       uint64_t tidlist, uint32_t *tidcnt,
					       uint16_t flags);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(writev)
				(const struct iovec *iov, int iovcnt, struct ips_epinfo *,
				 psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_sdma_ring_slot_status)
				(int slotIdx, psmi_hal_sdma_ring_slot_status *,
				 uint32_t *errorCode,void *);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(dma_slot_available)
				(int slotidx, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_hfi_event_bits)
				(uint64_t *event_bits, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(ack_hfi_event)
				(uint64_t ack_bits, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(hfi_reset_context)
				(psmi_hal_hw_context);
static PSMI_HAL_INLINE uint64_t PSMI_HAL_CAT_INL_SYM(get_hw_status)
				(psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_hw_status_freezemsg)
				(volatile char** msg, psmi_hal_hw_context);
static PSMI_HAL_INLINE uint16_t PSMI_HAL_CAT_INL_SYM(get_user_major_bldtime_version)
				(void);
static PSMI_HAL_INLINE uint16_t PSMI_HAL_CAT_INL_SYM(get_user_minor_bldtime_version)
				(void);
static PSMI_HAL_INLINE uint16_t PSMI_HAL_CAT_INL_SYM(get_user_major_runtime_version)
				(psmi_hal_hw_context);
static PSMI_HAL_INLINE uint16_t PSMI_HAL_CAT_INL_SYM(get_user_minor_runtime_version)
				(psmi_hal_hw_context);
static PSMI_HAL_INLINE psmi_hal_cl_idx PSMI_HAL_CAT_INL_SYM(get_cl_q_head_index)
				(psmi_hal_cl_q,
				 psmi_hal_hw_context);
static PSMI_HAL_INLINE psmi_hal_cl_idx PSMI_HAL_CAT_INL_SYM(get_cl_q_tail_index)
				(psmi_hal_cl_q,
				 psmi_hal_hw_context);
static PSMI_HAL_INLINE void PSMI_HAL_CAT_INL_SYM(set_cl_q_head_index)
				(psmi_hal_cl_idx,
				 psmi_hal_cl_q,
				 psmi_hal_hw_context);
static PSMI_HAL_INLINE void PSMI_HAL_CAT_INL_SYM(set_cl_q_tail_index)
				(psmi_hal_cl_idx,
				 psmi_hal_cl_q,
				 psmi_hal_hw_context);
static     inline      int PSMI_HAL_CAT_INL_SYM(cl_q_empty)
				(psmi_hal_cl_idx,
				 psmi_hal_cl_q,
				 psmi_hal_hw_context);
static     inline      int PSMI_HAL_CAT_INL_SYM(get_rhf)
				(psmi_hal_cl_idx, psmi_hal_raw_rhf_t *,
				 psmi_hal_cl_q, psmi_hal_hw_context);
static     inline      int PSMI_HAL_CAT_INL_SYM(get_ips_message_hdr)
				(psmi_hal_cl_idx, psmi_hal_raw_rhf_t, struct ips_message_header **,
				 psmi_hal_cl_q, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_receive_event)
				(psmi_hal_cl_idx head_idx, psmi_hal_hw_context,
				 struct ips_recvhdrq_event *);
static PSMI_HAL_INLINE void *PSMI_HAL_CAT_INL_SYM(get_egr_buff)
				(psmi_hal_cl_idx, psmi_hal_cl_q, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(retire_hdr_q_entry)
				(psmi_hal_cl_idx *, psmi_hal_cl_q, psmi_hal_hw_context,
				 uint32_t elemsz, uint32_t elemlast,
				 int *emptyp);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_rhf_expected_sequence_number)
				(unsigned int *, psmi_hal_cl_q, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(set_rhf_expected_sequence_number)
				(unsigned int, psmi_hal_cl_q, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(check_rhf_sequence_number)
				(unsigned int);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(set_pbc)
				(struct ips_proto *proto, struct ips_flow *flow,
				 uint32_t isCtrlMsg, struct psm_hal_pbc *dest, uint32_t hdrlen,
				 uint32_t paylen);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_set_entry)
				(uint32_t flowid, uint32_t genval, uint32_t seqnum,
				 psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_reset)
				(psmi_hal_hw_context, uint32_t flowid, uint32_t genval,
				 uint32_t seqnum);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get)
				(uint32_t flowid, uint64_t *ptf, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_hw)
				(uint32_t flowid, uint64_t *ptf, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_seqnum)
				(uint64_t val, uint32_t *pseqn);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_genval)
				(uint64_t val, uint32_t *pgv);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_check_update_pkt_seq)
				(void *vpprotoexp
				 /* actually a:
				    struct ips_protoexp *protoexp */,
				 psmi_seqnum_t sequence_num,
				 void *vptidrecvc
				 /* actually a:
				    struct ips_tid_recv_desc *tidrecvc */,
				 struct ips_message_header *p_hdr,
				 void (*ips_protoexp_do_tf_generr)
				 (void *vpprotoexp
				  /* actually a:
				     struct ips_protoexp *protoexp */,
				  void *vptidrecvc
				  /* actually a:
				     struct ips_tid_recv_desc *tidrecvc */,
				  struct ips_message_header *p_hdr),
				 void (*ips_protoexp_do_tf_seqerr)
				 (void *vpprotoexp
				  /* actually a:
				     struct ips_protoexp *protoexp */,
				  void *vptidrecvc
				  /* actually a:
				     struct ips_tid_recv_desc *tidrecvc */,
				  struct ips_message_header *p_hdr));
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_flowvalid)
				(uint64_t val, uint32_t *pfv);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_enabled)
				(uint64_t val, uint32_t *penabled);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_keep_after_seqerr)
				(uint64_t val, uint32_t *pkase);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_keep_on_generr)
				(uint64_t val, uint32_t *pkoge);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_keep_payload_on_generr)
				(uint64_t val, uint32_t *pkpoge);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_seqmismatch)
				(uint64_t val, uint32_t *psmm);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(tidflow_get_genmismatch)
				(uint64_t val, uint32_t *pgmm);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(forward_packet_to_subcontext)
				(struct ips_writehdrq *writeq,
				 struct ips_recvhdrq_event *rcv_ev,
				 uint32_t subcontext,
				 psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(subcontext_ureg_get)
				(ptl_t *ptl,
				 struct ips_subcontext_ureg **uregp,
				 psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(set_pio_size)
				(uint32_t, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(set_effective_mtu)
				(uint32_t, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(set_tf_valid)
				(uint32_t, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(get_default_pkey)
				(void);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(spio_init)
				(const psmi_context_t *context,
				 struct ptl *ptl, void **ctrl);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(spio_fini)
				(void **ctrl, psmi_hal_hw_context);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(spio_transfer_frame)
				(struct ips_proto *proto,
				 struct ips_flow *flow, struct psm_hal_pbc *pbc,
				 uint32_t *payload, uint32_t length,
				 uint32_t isCtrlMsg, uint32_t cksum_valid,
				 uint32_t cksum, psmi_hal_hw_context
#ifdef PSM_CUDA
				 , uint32_t is_cuda_payload
#endif
					);
static PSMI_HAL_INLINE int PSMI_HAL_CAT_INL_SYM(spio_process_events)
				(const struct ptl *ptl);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_bthqp)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_context)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE uint64_t PSMI_HAL_CAT_INL_SYM(get_gid_lo)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE uint64_t PSMI_HAL_CAT_INL_SYM(get_gid_hi)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_hfi_type)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_jkey)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_lid)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_pio_size)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_port_num)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_rx_egr_tid_cnt)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_rx_hdr_q_cnt)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_rx_hdr_q_ent_size)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_sdma_req_size)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_sdma_ring_size)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_subctxt)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_subctxt_cnt)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_tid_exp_cnt)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_unit_id)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_fd)
				(psmi_hal_hw_context ctxt);
static PSMI_HAL_INLINE int      PSMI_HAL_CAT_INL_SYM(get_pio_stall_cnt)
				(psmi_hal_hw_context,
				 uint64_t **);
