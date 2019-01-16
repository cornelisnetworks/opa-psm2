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

#include "psm_hal_gen1.h"

static inline struct _hfp_gen1 *get_psm_gen1_hi(void)
{
	return (struct _hfp_gen1*) psmi_hal_current_hal_instance;
}

/* hfp_gen1_initialize */
static PSMI_HAL_INLINE int hfp_gen1_initialize(psmi_hal_instance_t *phi)
{
	return 0;
}

/* hfp_gen1_finalize */
static PSMI_HAL_INLINE int hfp_gen1_finalize(void)
{
	return 0;
}

/* hfp_gen1_get_num_units */
static PSMI_HAL_INLINE int hfp_gen1_get_num_units(int wait)
{
	return hfi_get_num_units(wait);
}

/* hfp_gen1_get_num_ports */
static PSMI_HAL_INLINE int hfp_gen1_get_num_ports(void)
{
	return HFI_NUM_PORTS_GEN1;
}

/* hfp_gen1_get_unit_active */
static PSMI_HAL_INLINE int hfp_gen1_get_unit_active(int unit)
{
	return hfi_get_unit_active(unit);
}

/* hfp_gen1_get_port_active */
static PSMI_HAL_INLINE int hfp_gen1_get_port_active(int unit, int port)
{
	return hfi_get_port_active(unit, port);
}

/* hfp_gen1_get_contexts */
static PSMI_HAL_INLINE int hfp_gen1_get_num_contexts(int unit)
{
	int64_t nctxts=0;

	if (!hfi_sysfs_unit_read_s64(unit, "nctxts",
				     &nctxts, 0))
	{
		return (int)nctxts;
	}
	return -PSM_HAL_ERROR_GENERAL_ERROR;
}

/* hfp_gen1_get_num_free_contexts */
static PSMI_HAL_INLINE int hfp_gen1_get_num_free_contexts(int unit)
{
	int64_t nfreectxts=0;

	if (!hfi_sysfs_unit_read_s64(unit, "nfreectxts",
				     &nfreectxts, 0))
	{
		return (int)nfreectxts;
	}
	return -PSM_HAL_ERROR_GENERAL_ERROR;
}

/* hfp_gen1_close_context */
static PSMI_HAL_INLINE int hfp_gen1_close_context(psmi_hal_hw_context *ctxtp)
{
	if (!ctxtp || !*ctxtp)
		return PSM_HAL_ERROR_OK;

	int i;
	hfp_gen1_pc_private *psm_hw_ctxt = *ctxtp;

	ips_recvq_egrbuf_table_free(psm_hw_ctxt->cl_qs[PSM_HAL_CL_Q_RX_EGR_Q].egr_buffs);

	for (i=0;i < psm_hw_ctxt->user_info.subctxt_cnt;i++)
		ips_recvq_egrbuf_table_free(
			psm_hw_ctxt->cl_qs[
				PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(i)
				].egr_buffs);
	struct hfi1_base_info *binfo;
	struct hfi1_ctxt_info *cinfo;
	int __hfi_pg_sz = sysconf(_SC_PAGESIZE);
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	binfo = &ctrl->base_info;
	cinfo = &ctrl->ctxt_info;

	munmap((void*)PSMI_ALIGNDOWN(binfo->sc_credits_addr, __hfi_pg_sz),
	       __hfi_pg_sz);
	munmap((void*)PSMI_ALIGNDOWN(binfo->pio_bufbase_sop, __hfi_pg_sz),
	       cinfo->credits * 64);
	munmap((void*)PSMI_ALIGNDOWN(binfo->pio_bufbase, __hfi_pg_sz),
	       cinfo->credits * 64);
	munmap((void*)PSMI_ALIGNDOWN(binfo->rcvhdr_bufbase, __hfi_pg_sz),
	       cinfo->rcvhdrq_cnt * cinfo->rcvhdrq_entsize);
	munmap((void*)PSMI_ALIGNDOWN(binfo->rcvegr_bufbase, __hfi_pg_sz),
	       cinfo->egrtids * cinfo->rcvegr_size);
	munmap((void*)PSMI_ALIGNDOWN(binfo->sdma_comp_bufbase, __hfi_pg_sz),
	       cinfo->sdma_ring_size * sizeof(struct hfi1_sdma_comp_entry));
	/* only unmap the RTAIL if it was enabled in the first place */
	if (cinfo->runtime_flags & HFI1_CAP_DMA_RTAIL) {
		munmap((void*)PSMI_ALIGNDOWN(binfo->rcvhdrtail_base, __hfi_pg_sz),
		       __hfi_pg_sz);
	}
	munmap((void*)PSMI_ALIGNDOWN(binfo->user_regbase, __hfi_pg_sz),
	       __hfi_pg_sz);
	munmap((void*)PSMI_ALIGNDOWN(binfo->events_bufbase, __hfi_pg_sz),
	       __hfi_pg_sz);
	munmap((void*)PSMI_ALIGNDOWN(binfo->status_bufbase, __hfi_pg_sz),
	       __hfi_pg_sz);

	/* only unmap subcontext-related stuff it subcontexts are enabled */
	if (psm_hw_ctxt->user_info.subctxt_cnt > 0) {
		munmap((void*)PSMI_ALIGNDOWN(binfo->subctxt_uregbase, __hfi_pg_sz),
		       __hfi_pg_sz);
		munmap((void*)PSMI_ALIGNDOWN(binfo->subctxt_rcvhdrbuf, __hfi_pg_sz),
		       __hfi_pg_sz);
		munmap((void*)PSMI_ALIGNDOWN(binfo->subctxt_rcvegrbuf, __hfi_pg_sz),
		       __hfi_pg_sz);
	}

	close(psm_hw_ctxt->ctrl->fd);
	free(psm_hw_ctxt->ctrl);
	psmi_free(psm_hw_ctxt);

	return PSM_HAL_ERROR_OK;
}

/* Moved from psm_context.c */

ustatic PSMI_HAL_INLINE
int MOCKABLE(psmi_sharedcontext_params)(int *nranks, int *rankid);
MOCK_DCL_EPILOGUE(psmi_sharedcontext_params);
ustatic PSMI_HAL_INLINE psm2_error_t psmi_init_userinfo_params(psm2_ep_t ep,
					     int unit_id,
					     psm2_uuid_t const unique_job_key,
					     struct hfi1_user_info_dep *user_info);

/*
 * Prepare user_info params for driver open, used only in psmi_context_open
 */
ustatic PSMI_HAL_INLINE
psm2_error_t
psmi_init_userinfo_params(psm2_ep_t ep, int unit_id,
			  psm2_uuid_t const unique_job_key,
			  struct hfi1_user_info_dep *user_info)
{
	/* static variables, shared among rails */
	static int shcontexts_enabled = -1, rankid, nranks;

	int avail_contexts = 0, max_contexts, ask_contexts;
	int ranks_per_context = 0;
	psm2_error_t err = PSM2_OK;
	union psmi_envvar_val env_maxctxt, env_ranks_per_context;
	static int subcontext_id_start;

	memset(user_info, 0, sizeof(*user_info));
	user_info->userversion = HFI1_USER_SWMINOR|(hfi_get_user_major_version()<<HFI1_SWMAJOR_SHIFT);

	user_info->subctxt_id = 0;
	user_info->subctxt_cnt = 0;
	memcpy(user_info->uuid, unique_job_key, sizeof(user_info->uuid));

	if (shcontexts_enabled == -1) {
		shcontexts_enabled =
		    psmi_sharedcontext_params(&nranks, &rankid);
	}
	if (!shcontexts_enabled)
		return err;

	avail_contexts = hfi_get_num_contexts(unit_id, 0);

	if (avail_contexts == 0) {
		err = psmi_handle_error(NULL, PSM2_EP_NO_DEVICE,
					"PSM2 found 0 available contexts on opa device(s).");
		goto fail;
	}

	/* See if the user wants finer control over context assignments */
	if (!psmi_getenv("PSM2_MAX_CONTEXTS_PER_JOB",
			 "Maximum number of contexts for this PSM2 job",
			 PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
			 (union psmi_envvar_val)avail_contexts, &env_maxctxt)) {
		max_contexts = max(env_maxctxt.e_int, 1);		/* needs to be non-negative */
		ask_contexts = min(max_contexts, avail_contexts);	/* needs to be available */
	} else if (!psmi_getenv("PSM2_SHAREDCONTEXTS_MAX",
				"",  /* deprecated */
				PSMI_ENVVAR_LEVEL_HIDDEN | PSMI_ENVVAR_LEVEL_NEVER_PRINT,
				PSMI_ENVVAR_TYPE_INT,
				(union psmi_envvar_val)avail_contexts, &env_maxctxt)) {

		_HFI_INFO
		    ("The PSM2_SHAREDCONTEXTS_MAX env variable is deprecated. Please use PSM2_MAX_CONTEXTS_PER_JOB in future.\n");

		max_contexts = max(env_maxctxt.e_int, 1);		/* needs to be non-negative */
		ask_contexts = min(max_contexts, avail_contexts);	/* needs to be available */
	} else
		ask_contexts = max_contexts = avail_contexts;

	if (!psmi_getenv("PSM2_RANKS_PER_CONTEXT",
			 "Number of ranks per context",
			 PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
			 (union psmi_envvar_val)1, &env_ranks_per_context)) {
		ranks_per_context = max(env_ranks_per_context.e_int, 1);
		ranks_per_context = min(ranks_per_context, HFI1_MAX_SHARED_CTXTS);
	}

	/*
	 * See if we could get a valid ppn.  If not, approximate it to be the
	 * number of cores.
	 */
	if (nranks == -1) {
		long nproc = sysconf(_SC_NPROCESSORS_ONLN);
		if (nproc < 1)
			nranks = 1;
		else
			nranks = nproc;
	}

	/*
	 * Make sure that our guesses are good educated guesses
	 */
	if (rankid >= nranks) {
		_HFI_PRDBG
		    ("PSM2_SHAREDCONTEXTS disabled because lrank=%d,ppn=%d\n",
		     rankid, nranks);
		goto fail;
	}

	if (ranks_per_context) {
		int contexts =
		    (nranks + ranks_per_context - 1) / ranks_per_context;
		if (contexts > ask_contexts) {
			err = psmi_handle_error(NULL, PSM2_EP_NO_DEVICE,
						"Incompatible settings for "
						"PSM2_MAX_CONTEXTS_PER_JOB and PSM2_RANKS_PER_CONTEXT");
			goto fail;
		}
		ask_contexts = contexts;
	}

	/* group id based on total groups and local rank id */
	user_info->subctxt_id = subcontext_id_start + rankid % ask_contexts;
	/* this is for multi-rail, when we setup a new rail,
	 * we can not use the same subcontext ID as the previous
	 * rail, otherwise, the driver will match previous rail
	 * and fail.
	 */
	subcontext_id_start += ask_contexts;

	/* Need to compute with how many *other* peers we will be sharing the
	 * context */
	if (nranks > ask_contexts) {
		user_info->subctxt_cnt = nranks / ask_contexts;
		/* If ppn != multiple of contexts, some contexts get an uneven
		 * number of subcontexts */
		if (nranks % ask_contexts > rankid % ask_contexts)
			user_info->subctxt_cnt++;
		/* The case of 1 process "sharing" a context (giving 1 subcontext)
		 * is supcontexted by the driver and PSM. However, there is no
		 * need to share in this case so disable context sharing. */
		if (user_info->subctxt_cnt == 1)
			user_info->subctxt_cnt = 0;
		if (user_info->subctxt_cnt > HFI1_MAX_SHARED_CTXTS) {
			err = psmi_handle_error(NULL, PSM2_INTERNAL_ERR,
						"Calculation of subcontext count exceeded maximum supported");
			goto fail;
		}
	}
	/* else subcontext_cnt remains 0 and context sharing is disabled. */

	_HFI_PRDBG("PSM2_SHAREDCONTEXTS lrank=%d,ppn=%d,avail_contexts=%d,"
		   "max_contexts=%d,ask_contexts=%d,"
		   "ranks_per_context=%d,id=%u,cnt=%u\n",
		   rankid, nranks, avail_contexts, max_contexts,
		   ask_contexts, ranks_per_context,
		   user_info->subctxt_id, user_info->subctxt_cnt);
fail:
	return err;
}

ustatic
int MOCKABLE(psmi_sharedcontext_params)(int *nranks, int *rankid)
{
	union psmi_envvar_val enable_shcontexts;
	char *ppn_env = NULL, *lrank_env = NULL, *c;

	*rankid = -1;
	*nranks = -1;

#if 0
	/* DEBUG: Used to selectively test possible shared context and shm-only
	 * settings */
	unsetenv("PSC_MPI_NODE_RANK");
	unsetenv("PSC_MPI_PPN");
	unsetenv("MPI_LOCALRANKID");
	unsetenv("MPI_LOCALRANKS");
#endif

	/* We do not support context sharing for multiple endpoints */
	if (psmi_multi_ep_enabled) {
		return 0;
	}

	/* New name in 2.0.1, keep observing old name */
	psmi_getenv("PSM2_SHAREDCONTEXTS", "Enable shared contexts",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_YESNO,
		    (union psmi_envvar_val)
		    PSMI_SHARED_CONTEXTS_ENABLED_BY_DEFAULT,
		    &enable_shcontexts);
	if (!enable_shcontexts.e_int)
		return 0;

	/* We support two types of syntaxes to let users give us a hint what
	 * our local rankid is.  Moving towards MPI_, but still support PSC_ */
	if ((c = getenv("MPI_LOCALRANKID")) && *c != '\0') {
		lrank_env = "MPI_LOCALRANKID";
		ppn_env = "MPI_LOCALNRANKS";
	} else if ((c = getenv("PSC_MPI_PPN")) && *c != '\0') {
		ppn_env = "PSC_MPI_PPN";
		lrank_env = "PSC_MPI_NODE_RANK";
	}

	if (ppn_env != NULL && lrank_env != NULL) {
		union psmi_envvar_val env_rankid, env_nranks;

		psmi_getenv(lrank_env, "Shared context rankid",
			    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
			    (union psmi_envvar_val)-1, &env_rankid);

		psmi_getenv(ppn_env, "Shared context numranks",
			    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
			    (union psmi_envvar_val)-1, &env_nranks);

		*rankid = env_rankid.e_int;
		*nranks = env_nranks.e_int;

		return 1;
	} else
		return 0;
}
MOCK_DEF_EPILOGUE(psmi_sharedcontext_params);

/* moved from ips_subcontext.c */
static PSMI_HAL_INLINE psm2_error_t
divvy_shared_mem_ptrs(hfp_gen1_pc_private *pc_private,
		      psmi_context_t *context,
		      const struct hfi1_base_info *base_info)
{
	struct ips_hwcontext_ctrl **hwcontext_ctrl = &pc_private->hwcontext_ctrl;
	uint32_t subcontext_cnt                    = pc_private->user_info.subctxt_cnt;
	struct ips_subcontext_ureg **uregp         = &pc_private->subcontext_ureg[0];

	uintptr_t all_subcontext_uregbase =
	    (uintptr_t) base_info->subctxt_uregbase;
	int i;

	psmi_assert_always(all_subcontext_uregbase != 0);
	for (i = 0; i < HFI1_MAX_SHARED_CTXTS; i++) {
		struct ips_subcontext_ureg *subcontext_ureg =
		    (struct ips_subcontext_ureg *)all_subcontext_uregbase;
		*uregp++ = (i < subcontext_cnt) ? subcontext_ureg : NULL;
		all_subcontext_uregbase += sizeof(struct ips_subcontext_ureg);
	}

	*hwcontext_ctrl =
	    (struct ips_hwcontext_ctrl *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_hwcontext_ctrl);

	context->spio_ctrl = (void *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_spio_ctrl);

	context->tid_ctrl = (void *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_tid_ctrl);

	context->tf_ctrl = (void *)all_subcontext_uregbase;
	all_subcontext_uregbase += sizeof(struct ips_tf_ctrl);

	psmi_assert((all_subcontext_uregbase -
		     (uintptr_t) base_info->subctxt_uregbase) <= PSMI_PAGESIZE);

	return PSM2_OK;
}

static PSMI_HAL_INLINE
uint64_t get_cap_mask(uint64_t gen1_mask)
{
	static  const struct
	{
		uint64_t gen1_bit;
		uint32_t psmi_hal_bit;
	} bit_map[] =
	  {
		  { HFI1_CAP_SDMA,		  PSM_HAL_CAP_SDMA		     },
		  { HFI1_CAP_SDMA_AHG,		  PSM_HAL_CAP_SDMA_AHG	     },
		  { HFI1_CAP_EXTENDED_PSN,	  PSM_HAL_CAP_EXTENDED_PSN	     },
		  { HFI1_CAP_HDRSUPP,		  PSM_HAL_CAP_HDRSUPP	     },
		  { HFI1_CAP_USE_SDMA_HEAD,	  PSM_HAL_CAP_USE_SDMA_HEAD       },
		  { HFI1_CAP_MULTI_PKT_EGR,	  PSM_HAL_CAP_MULTI_PKT_EGR       },
		  { HFI1_CAP_NODROP_RHQ_FULL,	  PSM_HAL_CAP_NODROP_RHQ_FULL     },
		  { HFI1_CAP_NODROP_EGR_FULL,	  PSM_HAL_CAP_NODROP_EGR_FULL     },
		  { HFI1_CAP_TID_UNMAP,		  PSM_HAL_CAP_TID_UNMAP           },
		  { HFI1_CAP_PRINT_UNIMPL,	  PSM_HAL_CAP_PRINT_UNIMPL        },
		  { HFI1_CAP_ALLOW_PERM_JKEY,	  PSM_HAL_CAP_ALLOW_PERM_JKEY     },
		  { HFI1_CAP_NO_INTEGRITY,	  PSM_HAL_CAP_NO_INTEGRITY        },
		  { HFI1_CAP_PKEY_CHECK,	  PSM_HAL_CAP_PKEY_CHECK          },
		  { HFI1_CAP_STATIC_RATE_CTRL,	  PSM_HAL_CAP_STATIC_RATE_CTRL    },
		  { HFI1_CAP_SDMA_HEAD_CHECK,	  PSM_HAL_CAP_SDMA_HEAD_CHECK     },
		  { HFI1_CAP_EARLY_CREDIT_RETURN, PSM_HAL_CAP_EARLY_CREDIT_RETURN },
#ifdef PSM_CUDA
		  { HFI1_CAP_GPUDIRECT_OT,        PSM_HAL_CAP_GPUDIRECT_OT        },
#endif
	  };
	uint64_t rv = 0;
	int i;
	for (i=0;i < sizeof(bit_map)/sizeof(bit_map[0]);i++)
	{
		if (bit_map[i].gen1_bit & gen1_mask)
			rv |= bit_map[i].psmi_hal_bit;
	}
	return rv;
}

/* hfp_gen1_context_open */
static PSMI_HAL_INLINE int hfp_gen1_context_open(int unit,
				 int port,
				 uint64_t open_timeout,
				 psm2_ep_t ep,
				 psm2_uuid_t const job_key,
				 psmi_context_t *psm_ctxt,
				 uint32_t cap_mask,
				 unsigned retryCnt)
{
	hfp_gen1_pc_private *pc_private = psmi_malloc(ep, UNDEFINED, sizeof(hfp_gen1_pc_private));

	if_pf (!pc_private)
		return -PSM_HAL_ERROR_CANNOT_OPEN_CONTEXT;

	memset(pc_private,0,sizeof(hfp_gen1_pc_private));

	char dev_name[PATH_MAX];
	int fd = hfi_context_open_ex(unit, port, open_timeout,
					       dev_name, sizeof(dev_name));
	if (fd < 0)
	{
		psmi_free(pc_private);
		return -PSM_HAL_ERROR_CANNOT_OPEN_DEVICE;
	}
	psm2_error_t err = psmi_init_userinfo_params(ep,
						     unit,
						     job_key,
						     &pc_private->user_info);
	if (err)
	{
		psmi_free(pc_private);
		return -PSM_HAL_ERROR_GENERAL_ERROR;
	}

	/* attempt to assign the context via hfi_userinit() */
	int retry = 0;
	do {
		if (retry > 0)
			_HFI_INFO("hfi_userinit: failed, trying again (%d/%d)\n",
				  retry, retryCnt);
		pc_private->ctrl = hfi_userinit(fd, &pc_private->user_info);
	} while (pc_private->ctrl == NULL && ++retry <= retryCnt);

	if (!pc_private->ctrl)
	{
		psmi_free(pc_private);
		return -PSM_HAL_ERROR_CANNOT_OPEN_CONTEXT;
	}
	else
	{

		if (getenv("PSM2_IDENTIFY")) {
			printf("%s %s run-time driver interface v%d.%d\n",
			       hfi_get_mylabel(), hfi_ident_tag,
			       hfi_get_user_major_version(),
			       hfi_get_user_minor_version());
		}

		struct _hfi_ctrl *ctrl = pc_private->ctrl;
		int i;

		if (hfi_get_port_lid(ctrl->__hfi_unit,
				     ctrl->__hfi_port) <= 0) {
			err = psmi_handle_error(NULL,
						PSM2_EP_DEVICE_FAILURE,
						"Can't get HFI LID in psm2_ep_open: is SMA running?");
			goto bail;
		}
		uint64_t gid_lo,gid_hi;
		if (hfi_get_port_gid(ctrl->__hfi_unit,
				     ctrl->__hfi_port,
				     &gid_hi,
				     &gid_lo) == -1) {
			err =
				psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
						  "Can't get HFI GID in psm2_ep_open: is SMA running?");
			goto bail;
		}
		ep->unit_id = ctrl->__hfi_unit;
		ep->portnum = ctrl->__hfi_port;
		ep->gid_hi = gid_hi;
		ep->gid_lo = gid_lo;

		/* Endpoint out_sl contains the default SL to use for this endpoint. */
		/* Get the MTU for this SL. */
		int sc;
		if ((sc=hfi_get_port_sl2sc(ep->unit_id,
				       ctrl->__hfi_port,
				       ep->out_sl)) < 0) {
			sc = PSMI_SC_DEFAULT;
		}
		int vl;
		if ((vl = hfi_get_port_sc2vl(ep->unit_id,
					     ctrl->__hfi_port,
					     sc)) < 0) {
			vl = PSMI_VL_DEFAULT;
		}
		if (sc == PSMI_SC_ADMIN ||
		    vl == PSMI_VL_ADMIN) {
			err = psmi_handle_error(NULL, PSM2_INTERNAL_ERR,
						"Invalid sl: %d, please specify correct sl via HFI_SL",
						ep->out_sl);
			goto bail;
		}

		if ((ep->mtu = hfi_get_port_vl2mtu(ep->unit_id,
						   ctrl->__hfi_port,
						   vl)) < 0) {
			err =
				psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
						  "Can't get MTU for VL %d",
						  vl);
			goto bail;
		}

		get_psm_gen1_hi()->phi.params.cap_mask = cap_mask
			| get_cap_mask(ctrl->ctxt_info.runtime_flags)
			| PSM_HAL_CAP_MERGED_TID_CTRLS
			| PSM_HAL_CAP_RSM_FECN_SUPP;

		int driver_major = hfi_get_user_major_version();
		int driver_minor = hfi_get_user_minor_version();

		if ((driver_major > 6) ||
		    ((driver_major == 6) &&
		     (driver_minor >= 3)))
		{
			get_psm_gen1_hi()->phi.params.cap_mask |= PSM_HAL_CAP_DMA_HSUPP_FOR_32B_MSGS;
		}

		get_psm_gen1_hi()->hfp_private.sdmahdr_req_size = HFI_SDMA_HDR_SIZE;

		if (hfi_check_non_dw_mul_sdma())
			get_psm_gen1_hi()->phi.params.cap_mask |= PSM_HAL_CAP_NON_DW_MULTIPLE_MSG_SIZE;
		/* The dma_rtail member is: 1 when the HFI1_CAP_DMA_RTAIL bit is     set.
					    0 when the HFI1_CAP_DMA_RTAIL bit is NOT set. */
		get_psm_gen1_hi()->hfp_private.dma_rtail = 0 != (HFI1_CAP_DMA_RTAIL & ctrl->ctxt_info.runtime_flags);

		psm_ctxt->psm_hw_ctxt = pc_private;
		if (pc_private->user_info.subctxt_cnt > 0)
			divvy_shared_mem_ptrs(pc_private,
					      psm_ctxt,
					      &ctrl->base_info);

		/* Initialize all of the cl q's. */

		get_psm_gen1_hi()->hfp_private.hdrq_rhf_off = (ctrl->ctxt_info.rcvhdrq_entsize - 8) >> BYTE2DWORD_SHIFT;

		/* The following guard exists to workaround a critical issue flagged by KW to prevent
		   subscripting past the end of the cl_qs[] array in the following for () loop. */
		if (pc_private->user_info.subctxt_cnt <= HFI1_MAX_SHARED_CTXTS)
		{
			/* Here, we are initializing only the rx hdrq rhf seq for all subcontext
			   cl q's: */
			for (i=PSM_HAL_CL_Q_RX_HDR_Q_SC_0; i <
				     PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(pc_private->user_info.subctxt_cnt); i += 2)
			{
				psm_hal_gen1_cl_q_t *pcl_q = &(pc_private->cl_qs[i]);

				pcl_q->hdr_qe.p_rx_hdrq_rhf_seq = &pcl_q->hdr_qe.rx_hdrq_rhf_seq;
				if (get_psm_gen1_hi()->hfp_private.dma_rtail)
					pcl_q->hdr_qe.rx_hdrq_rhf_seq = 0;
				else
					pcl_q->hdr_qe.rx_hdrq_rhf_seq = 1;
			}
		}
		/* Next, initialize the hw rx hdr q and egr buff q: */
		{
			/* base address of user registers */
			volatile uint64_t *uregbase = (volatile uint64_t *)(uintptr_t) (ctrl->base_info.user_regbase);
			/* hw rx hdr q: */
			psm_hal_gen1_cl_q_t *pcl_q = &(pc_private->cl_qs[PSM_HAL_CL_Q_RX_HDR_Q]);
			pcl_q->cl_q_head = (volatile uint64_t *)&(uregbase[ur_rcvhdrhead]);
			pcl_q->cl_q_tail = (volatile uint64_t *)&(uregbase[ur_rcvhdrtail]);
			pcl_q->hdr_qe.hdrq_base_addr       = (uint32_t *) (ctrl->base_info.rcvhdr_bufbase);

			/* Initialize the ptr to the rx hdrq rhf seq: */
			if (pc_private->user_info.subctxt_cnt > 0)
				/* During sharing of a context, the h/w hdrq rhf_seq is placed in shared memory and is shared
				   by all subcontexts: */
				pcl_q->hdr_qe.p_rx_hdrq_rhf_seq    = &pc_private->hwcontext_ctrl->rx_hdrq_rhf_seq;
			else
				pcl_q->hdr_qe.p_rx_hdrq_rhf_seq    = &pcl_q->hdr_qe.rx_hdrq_rhf_seq;

			if (get_psm_gen1_hi()->hfp_private.dma_rtail)
				*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq = 0;
			else
				*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq = 1;
			/* hw egr buff q: */
			pcl_q = &pc_private->cl_qs[PSM_HAL_CL_Q_RX_EGR_Q];
			pcl_q->cl_q_head = (volatile uint64_t *)&(uregbase[ur_rcvegrindexhead]);
			pcl_q->cl_q_tail = (volatile uint64_t *)&(uregbase[ur_rcvegrindextail]);
			pcl_q->egr_buffs = ips_recvq_egrbuf_table_alloc(ep,
									  (void*)(ctrl->base_info.rcvegr_bufbase),
									  ctrl->ctxt_info.egrtids,
									  ctrl->ctxt_info.rcvegr_size);
		}
		/* Next, initialize the subcontext's rx hdr q and egr buff q: */
		for (i=0; i < pc_private->user_info.subctxt_cnt;i++)
		{
			/* Subcontexts mimic the HW registers but use different addresses
			 * to avoid cache contention. */
			volatile uint64_t *subcontext_uregbase;
			uint32_t *rcv_hdr, *rcv_egr;
			unsigned hdrsize, egrsize;
			unsigned pagesize = getpagesize();
			uint32_t subcontext = i;
			unsigned i = pagesize - 1;
			hdrsize =
				(ctrl->ctxt_info.rcvhdrq_cnt * ctrl->ctxt_info.rcvhdrq_entsize + i) & ~i;
			egrsize =
				(ctrl->ctxt_info.egrtids * ctrl->ctxt_info.rcvegr_size + i) & ~i;

			subcontext_uregbase = (uint64_t *)
			  (((uintptr_t) (ctrl->base_info.subctxt_uregbase)) +
			   (sizeof(struct ips_subcontext_ureg) * subcontext));
			{
				struct ips_subcontext_ureg *pscureg = (struct ips_subcontext_ureg *)subcontext_uregbase;

				if (subcontext == ctrl->ctxt_info.subctxt)
				{
					memset(pscureg, 0, sizeof(*pscureg));
					if (get_psm_gen1_hi()->hfp_private.dma_rtail)
						pscureg->writeq_state.hdrq_rhf_seq = 0;
					else
						pscureg->writeq_state.hdrq_rhf_seq = 1;
				}
			}

			rcv_hdr = (uint32_t *)
			  (((uintptr_t) (ctrl->base_info.subctxt_rcvhdrbuf)) +
			   (hdrsize * subcontext));
			rcv_egr = (uint32_t *)
				(((uintptr_t) ctrl->base_info.subctxt_rcvegrbuf +
				  (egrsize * subcontext)));

			/* rx hdr q: */
			psm_hal_gen1_cl_q_t *pcl_q = &(pc_private->cl_qs[PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext)]);
			pcl_q->hdr_qe.hdrq_base_addr = rcv_hdr;
			pcl_q->cl_q_head = (volatile uint64_t *)&subcontext_uregbase[ur_rcvhdrhead * 8];
			pcl_q->cl_q_tail = (volatile uint64_t *)&subcontext_uregbase[ur_rcvhdrtail * 8];

			/* egr q: */
			pcl_q = &(pc_private->cl_qs[PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(subcontext)]);
			pcl_q->cl_q_head = (volatile uint64_t *)&subcontext_uregbase[ur_rcvegrindexhead * 8];
			pcl_q->cl_q_tail = (volatile uint64_t *)&subcontext_uregbase[ur_rcvegrindextail * 8];
			pcl_q->egr_buffs = ips_recvq_egrbuf_table_alloc(
				ep,
				(void*)rcv_egr,
				ctrl->ctxt_info.egrtids,
				ctrl->ctxt_info.rcvegr_size);
		}
		return PSM_HAL_ERROR_OK;
	}
	return PSM_HAL_ERROR_OK;

bail:
	free(pc_private->ctrl);
	psmi_free(pc_private);
	return -PSM_HAL_ERROR_GENERAL_ERROR;
}

/* hfp_gen1_get_port_index2pkey */
static PSMI_HAL_INLINE int hfp_gen1_get_port_index2pkey(int unit, int port, int index)
{
	return hfi_get_port_index2pkey(unit, port, index);
}

static PSMI_HAL_INLINE int hfp_gen1_get_cc_settings_bin(int unit, int port, char *ccabuf, size_t len_ccabuf)
{
	return hfi_get_cc_settings_bin(unit, port, ccabuf, len_ccabuf);
}

static PSMI_HAL_INLINE int hfp_gen1_get_cc_table_bin(int unit, int port, uint16_t **ccatp)
{
	return hfi_get_cc_table_bin(unit, port, ccatp);
}

static PSMI_HAL_INLINE int hfp_gen1_get_port_lmc(int unit, int port)
{
	return hfi_get_port_lmc(unit, port);
}

static PSMI_HAL_INLINE int hfp_gen1_get_port_rate(int unit, int port)
{
	return hfi_get_port_rate(unit, port);
}

static PSMI_HAL_INLINE int hfp_gen1_get_port_sl2sc(int unit, int port, int sl)
{
	return hfi_get_port_sl2sc(unit, port, sl);
}

static PSMI_HAL_INLINE int hfp_gen1_get_port_sc2vl(int unit, int port, int sc)
{
	return hfi_get_port_sc2vl(unit, port, sc);
}

static PSMI_HAL_INLINE int hfp_gen1_set_pkey(psmi_hal_hw_context ctxt, uint16_t pkey)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	return hfi_set_pkey(psm_hw_ctxt->ctrl, pkey);
}

static PSMI_HAL_INLINE int hfp_gen1_poll_type(uint16_t poll_type, psmi_hal_hw_context ctxt)
{
	if (poll_type == PSMI_HAL_POLL_TYPE_URGENT)
		poll_type = HFI1_POLL_TYPE_URGENT;
	else
		poll_type = 0;
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	return hfi_poll_type(psm_hw_ctxt->ctrl, poll_type);
}

static PSMI_HAL_INLINE int hfp_gen1_get_port_lid(int unit, int port)
{
	return hfi_get_port_lid(unit, port);
}

static PSMI_HAL_INLINE int hfp_gen1_get_port_gid(int unit, int port,
				uint64_t *hi, uint64_t *lo)
{
	return hfi_get_port_gid(unit, port, hi, lo);
}

static PSMI_HAL_INLINE int hfp_gen1_free_tid(psmi_hal_hw_context ctxt, uint64_t tidlist, uint32_t tidcnt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	return hfi_free_tid(psm_hw_ctxt->ctrl, tidlist, tidcnt);
}

static PSMI_HAL_INLINE int hfp_gen1_get_tidcache_invalidation(psmi_hal_hw_context ctxt, uint64_t tidlist, uint32_t *tidcnt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	return hfi_get_invalidation(psm_hw_ctxt->ctrl, tidlist, tidcnt);
}

static PSMI_HAL_INLINE int hfp_gen1_update_tid(psmi_hal_hw_context ctxt, uint64_t vaddr, uint32_t *length,
					       uint64_t tidlist, uint32_t *tidcnt, uint16_t flags)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	return hfi_update_tid(psm_hw_ctxt->ctrl, vaddr, length, tidlist, tidcnt, flags);
}

static PSMI_HAL_INLINE int hfp_gen1_writev(const struct iovec *iov, int iovcnt, struct ips_epinfo *ignored, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = (hfp_gen1_pc_private *)ctxt;

	return hfi_cmd_writev(psm_hw_ctxt->ctrl->fd, iov, iovcnt);
}

static PSMI_HAL_INLINE int hfp_gen1_dma_slot_available(int slotidx, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	if (slotidx < 0 || slotidx >= ctrl->ctxt_info.sdma_ring_size)
		return -1;

	struct hfi1_sdma_comp_entry *sdma_comp_queue = (struct hfi1_sdma_comp_entry *)
	  ctrl->base_info.sdma_comp_bufbase;

	return sdma_comp_queue[slotidx].status != QUEUED;
}

static PSMI_HAL_INLINE int hfp_gen1_get_sdma_ring_slot_status(int slotIdx,
					      psmi_hal_sdma_ring_slot_status *status,
					      uint32_t *errorCode,
					      psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	if (slotIdx < 0 || slotIdx >= ctrl->ctxt_info.sdma_ring_size)
	{
		*status = PSM_HAL_SDMA_RING_ERROR;
		return -PSM_HAL_ERROR_GENERAL_ERROR;
	}

	struct hfi1_sdma_comp_entry *sdma_comp_queue = (struct hfi1_sdma_comp_entry *)
	  ctrl->base_info.sdma_comp_bufbase;

	switch (sdma_comp_queue[slotIdx].status)
	{
	case FREE:
		*status = PSM_HAL_SDMA_RING_AVAILABLE;
		break;
	case QUEUED:
		*status = PSM_HAL_SDMA_RING_QUEUED;
		break;
	case COMPLETE:
		*status = PSM_HAL_SDMA_RING_COMPLETE;
		break;
	case ERROR:
		*status = PSM_HAL_SDMA_RING_ERROR;
		break;
	default:
		*status = PSM_HAL_SDMA_RING_ERROR;
		return -PSM_HAL_ERROR_GENERAL_ERROR;
	}
	*errorCode = sdma_comp_queue[slotIdx].errcode;
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_get_hfi_event_bits(uint64_t *event_bits, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	uint64_t *pevents_mask = (uint64_t *)ctrl->base_info.events_bufbase;
	uint64_t events_mask   = *pevents_mask;
	uint64_t hal_hfi_event_bits = 0;
	int i;

	if (!events_mask)
	{
		*event_bits = 0;
		return PSM_HAL_ERROR_OK;
	}

	/* Encode hfi1_events as HAL event codes here */
	for (i = 0; i < sizeof(hfi1_events_map)/sizeof(hfi1_events_map[0]); i++)
	{
		if (events_mask & hfi1_events_map[i].hfi1_event_bit)
			hal_hfi_event_bits |=
				hfi1_events_map[i].psmi_hal_hfi_event_bit;
	}

	*event_bits = hal_hfi_event_bits;

	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_ack_hfi_event(uint64_t ack_bits, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	uint64_t hfi1_ack_bits = 0;
	int i;

	/* Decode from HAL event codes to hfi1_events */
	for (i = 0; i < sizeof(hfi1_events_map)/sizeof(hfi1_events_map[0]); i++)
	{
		if (ack_bits & hfi1_events_map[i].psmi_hal_hfi_event_bit)
			hfi1_ack_bits |=
				hfi1_events_map[i].hfi1_event_bit;
	}

	return hfi_event_ack(ctrl, hfi1_ack_bits);
}

static PSMI_HAL_INLINE int hfp_gen1_hfi_reset_context(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return hfi_reset_context(ctrl);
}

static PSMI_HAL_INLINE uint64_t hfp_gen1_get_hw_status(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	struct hfi1_status *status =
	    (struct hfi1_status *) ctrl->base_info.status_bufbase;
	uint64_t hw_status = 0;
	int i;

	static const struct
	{
		uint32_t hfi1_status_dev_bit, psmi_hal_status_bit;
	} status_dev_map[] =
	  {
		  { HFI1_STATUS_INITTED,	  PSM_HAL_HW_STATUS_INITTED },
		  { HFI1_STATUS_CHIP_PRESENT,	  PSM_HAL_HW_STATUS_CHIP_PRESENT },
		  { HFI1_STATUS_HWERROR,	  PSM_HAL_HW_STATUS_HWERROR },
	  };

	for (i=0; i < sizeof(status_dev_map)/sizeof(status_dev_map[0]); i++)
	{
		if (status->dev &status_dev_map[i].hfi1_status_dev_bit)
			hw_status |= status_dev_map[i].psmi_hal_status_bit;
	}

	static const struct
	{
		uint32_t hfi1_status_port_bit, psmi_hal_status_bit;
	} status_port_map[] =
	  {
		  { HFI1_STATUS_IB_READY,	  PSM_HAL_HW_STATUS_IB_READY },
		  { HFI1_STATUS_IB_CONF,	  PSM_HAL_HW_STATUS_IB_CONF },
	  };

	for (i=0; i < sizeof(status_port_map)/sizeof(status_port_map[0]); i++)
	{
		if (status->port &status_port_map[i].hfi1_status_port_bit)
			hw_status |= status_port_map[i].psmi_hal_status_bit;
	}

	return hw_status;
}

static PSMI_HAL_INLINE int hfp_gen1_get_hw_status_freezemsg(volatile char** msg, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	struct hfi1_status *status =
	    (struct hfi1_status *) ctrl->base_info.status_bufbase;

	*msg = (volatile char *) status->freezemsg;

	return PSM2_OK;
}

static PSMI_HAL_INLINE uint16_t hfp_gen1_get_user_major_bldtime_version()
{
	return HFI1_USER_SWMAJOR;
}

static PSMI_HAL_INLINE uint16_t hfp_gen1_get_user_minor_bldtime_version()
{
	return HFI1_USER_SWMINOR;
}

static PSMI_HAL_INLINE uint16_t hfp_gen1_get_user_major_runtime_version(psmi_hal_hw_context ctx)
{
	return hfi_get_user_major_version();
}

static PSMI_HAL_INLINE uint16_t hfp_gen1_get_user_minor_runtime_version(psmi_hal_hw_context ctx)
{
	return hfi_get_user_minor_version();
}

static inline
uint32_t
get_ht(volatile uint64_t *ht_register)
{
	uint64_t res = *ht_register;
	ips_rmb();
	return (uint32_t)res;
}

static inline
void
set_ht(volatile uint64_t *ht_register, uint64_t new_ht)
{
	*ht_register = new_ht;
	return;
}

/* hfp_gen1_get_cl_q_head_index */
static PSMI_HAL_INLINE psmi_hal_cl_idx hfp_gen1_get_cl_q_head_index(
						   psmi_hal_cl_q cl_q,
						   psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	return get_ht(psm_hw_ctxt->cl_qs[cl_q].cl_q_head);
}

/* hfp_gen1_get_cl_q_tail_index */
static PSMI_HAL_INLINE psmi_hal_cl_idx hfp_gen1_get_cl_q_tail_index(
						psmi_hal_cl_q cl_q,
						psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	return get_ht(psm_hw_ctxt->cl_qs[cl_q].cl_q_tail);
}

/* hfp_gen1_set_cl_q_head_index */
static PSMI_HAL_INLINE void hfp_gen1_set_cl_q_head_index(
							psmi_hal_cl_idx idx,
							psmi_hal_cl_q cl_q,
							psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	set_ht(psm_hw_ctxt->cl_qs[cl_q].cl_q_head, idx);
	return;
}

/* hfp_gen1_set_cl_q_tail_index */
static PSMI_HAL_INLINE void hfp_gen1_set_cl_q_tail_index(
							psmi_hal_cl_idx idx,
							psmi_hal_cl_q cl_q,
							psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	set_ht(psm_hw_ctxt->cl_qs[cl_q].cl_q_tail, idx);
	return;
}

/* hfp_gen1_cl_q_empty */
static inline int hfp_gen1_cl_q_empty(psmi_hal_cl_idx head_idx,
				      psmi_hal_cl_q cl_q,
				      psmi_hal_hw_context ctxt)
{
	if (!get_psm_gen1_hi()->hfp_private.dma_rtail)
	{
		hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
		psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];
		int seq = hfi_hdrget_seq(pcl_q->hdr_qe.hdrq_base_addr +
		     (head_idx + get_psm_gen1_hi()->hfp_private.hdrq_rhf_off));

		return (*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq != seq);
	}

	return (head_idx == hfp_gen1_get_cl_q_tail_index(cl_q, ctxt));
}

static inline int hfp_gen1_get_rhf(psmi_hal_cl_idx idx,
			    psmi_hal_raw_rhf_t *rhfp,
			    psmi_hal_cl_q cl_q,
			    psmi_hal_hw_context ctxt)

{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];
	uint32_t *pu32 = (pcl_q->hdr_qe.hdrq_base_addr +
			  (idx + get_psm_gen1_hi()->hfp_private.hdrq_rhf_off));
	*rhfp = *((psmi_hal_raw_rhf_t*)pu32);
	return PSM_HAL_ERROR_OK;
}

static inline int hfp_gen1_get_ips_message_hdr(psmi_hal_cl_idx idx,
					psmi_hal_raw_rhf_t rhf,
					struct ips_message_header **imhp,
					psmi_hal_cl_q cl_q,
					psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];
	uint32_t *pu32 = pcl_q->hdr_qe.hdrq_base_addr + (idx + hfi_hdrget_hdrq_offset((uint32_t *)&rhf));
	*imhp = (struct ips_message_header*)pu32;
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_get_receive_event(psmi_hal_cl_idx head_idx, psmi_hal_hw_context ctxt,
				      struct ips_recvhdrq_event *rcv_ev)
{
	int rv;

	if_pf ((rv=hfp_gen1_get_rhf(head_idx, &rcv_ev->psm_hal_rhf.raw_rhf, rcv_ev->psm_hal_hdr_q, ctxt)) !=
	       PSM_HAL_ERROR_OK)
		return rv;

	/* here, we turn off the TFSEQ err bit if set: */
	rcv_ev->psm_hal_rhf.decomposed_rhf = rcv_ev->psm_hal_rhf.raw_rhf & (~(PSMI_HAL_RHF_ERR_MASK_64(TFSEQ)));

	/* Now, get the lrh: */
	if_pf ((rv=hfp_gen1_get_ips_message_hdr(head_idx, rcv_ev->psm_hal_rhf.raw_rhf, &rcv_ev->p_hdr,
						rcv_ev->psm_hal_hdr_q, ctxt)) !=
	       PSM_HAL_ERROR_OK)
		return rv;

	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE void *hfp_gen1_get_egr_buff(psmi_hal_cl_idx idx,
				   psmi_hal_cl_q cl_q,
				   psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];
	return pcl_q->egr_buffs[idx];
}

static PSMI_HAL_INLINE int hfp_gen1_retire_hdr_q_entry(psmi_hal_cl_idx *idx,
				       psmi_hal_cl_q cl_q,
				       psmi_hal_hw_context ctxt,
				       uint32_t elemsz, uint32_t elemlast,
				       int *emptyp)
{
	psmi_hal_cl_idx tmp = *idx + elemsz;
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];

	if (!get_psm_gen1_hi()->hfp_private.dma_rtail)
	{
		(*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq)++;
		if (*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq > LAST_RHF_SEQNO)
			*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq = 1;
	}
	if_pf(tmp > elemlast)
		tmp = 0;
	*emptyp = hfp_gen1_cl_q_empty(tmp, cl_q, ctxt);
	*idx = tmp;
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_get_rhf_expected_sequence_number(unsigned int *pseqnum,
						psmi_hal_cl_q cl_q,
						psmi_hal_hw_context ctxt)

{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];

	*pseqnum = *pcl_q->hdr_qe.p_rx_hdrq_rhf_seq;
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_set_rhf_expected_sequence_number(unsigned int seqnum,
									 psmi_hal_cl_q cl_q,
									 psmi_hal_hw_context ctxt)

{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];

	*pcl_q->hdr_qe.p_rx_hdrq_rhf_seq = seqnum;
	return PSM_HAL_ERROR_OK;
}

/* Get pbc static rate value for flow for a given message length */
PSMI_ALWAYS_INLINE(
uint16_t
ips_proto_pbc_static_rate(struct ips_proto *proto, struct ips_flow *flow,
			  uint32_t msgLen))
{
	uint32_t rate = 0;

	/* The PBC rate is based on which HFI type as different media have different
	 * mechanism for static rate control.
	 */

	switch (proto->epinfo.ep_hfi_type) {
	case PSMI_HFI_TYPE_OPA1:
		{
		/*
		 * time_to_send is:
		 *
		 *  (packet_length) [bits] / (pkt_egress_rate) [bits/sec]
		 *  -----------------------------------------------------
		 *     fabric_clock_period == (1 / 805 * 10^6) [1/sec]
		 *
		 *   (where pkt_egress_rate is assumed to be 100 Gbit/s.)
		 */
		uint32_t time_to_send = (8 * msgLen * 805) / (100000);
		rate = (time_to_send >> flow->path->pr_cca_divisor) *
				(flow->path->pr_active_ipd);

		if (rate > 65535)
			rate = 65535;

		}
		break;

	default:
		rate = 0;
	}

	return (uint16_t) rate;
}

/* This is a helper function to convert Per Buffer Control to little-endian */
PSMI_ALWAYS_INLINE(
void ips_proto_pbc_to_le(struct psm_hal_pbc *pbc))
{
	pbc->pbc0 = __cpu_to_le32(pbc->pbc0);
	pbc->PbcStaticRateControlCnt = __cpu_to_le16(pbc->PbcStaticRateControlCnt);
	pbc->fill1 = __cpu_to_le16(pbc->fill1);
}

/* This is only used for SDMA cases; pbc is really a pointer to
 * struct ips_pbc_header * or the equivalent un-named structure
 * in ips_scb. Please note pcb will be in little-endian byte
 * order on return */
PSMI_ALWAYS_INLINE(
void
ips_proto_pbc_update(struct ips_proto *proto, struct ips_flow *flow,
		     uint32_t isCtrlMsg, struct psm_hal_pbc *pbc, uint32_t hdrlen,
		     uint32_t paylen))
{
	int dw = (sizeof(struct psm_hal_pbc) + hdrlen + paylen) >> BYTE2DWORD_SHIFT;
	int sc = proto->sl2sc[flow->path->pr_sl];
	int vl = proto->sc2vl[sc];
	uint16_t static_rate = 0;

	if_pf(!isCtrlMsg && flow->path->pr_active_ipd)
	    static_rate =
	    ips_proto_pbc_static_rate(proto, flow, hdrlen + paylen);

	pbc->pbc0 = (dw & HFI_PBC_LENGTHDWS_MASK) |
	    ((vl & HFI_PBC_VL_MASK) << HFI_PBC_VL_SHIFT) |
	    (((sc >> HFI_PBC_SC4_SHIFT) &
	      HFI_PBC_SC4_MASK) << HFI_PBC_DCINFO_SHIFT);

	pbc->PbcStaticRateControlCnt = static_rate & HFI_PBC_STATICRCC_MASK;

	/* Per Buffer Control must be in little-endian */
	ips_proto_pbc_to_le(pbc);

	return;
}

static PSMI_HAL_INLINE int hfp_gen1_check_rhf_sequence_number(unsigned int seqno)
{
	return (seqno <= LAST_RHF_SEQNO) ?
		PSM_HAL_ERROR_OK :
		PSM_HAL_ERROR_GENERAL_ERROR;
}

static PSMI_HAL_INLINE int hfp_gen1_set_pbc(struct ips_proto *proto, struct ips_flow *flow,
		     uint32_t isCtrlMsg, struct psm_hal_pbc *dest, uint32_t hdrlen,
		     uint32_t paylen)
{
	ips_proto_pbc_update(proto, flow, isCtrlMsg,
			     dest, hdrlen, paylen);

	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_set_entry(uint32_t flowid, uint32_t genval, uint32_t seqnum, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	hfi_tidflow_set_entry(ctrl, flowid, genval, seqnum);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_reset(psmi_hal_hw_context ctxt, uint32_t flowid, uint32_t genval, uint32_t seqnum)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	hfi_tidflow_reset(ctrl, flowid, genval, seqnum);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get(uint32_t flowid, uint64_t *ptf, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	*ptf = hfi_tidflow_get(ctrl, flowid);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_hw(uint32_t flowid, uint64_t *ptf, psmi_hal_hw_context ctxt)
{
	return hfp_gen1_tidflow_get(flowid, ptf, ctxt);
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_seqnum(uint64_t val, uint32_t *pseqn)
{
	*pseqn = hfi_tidflow_get_seqnum(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_genval(uint64_t val, uint32_t *pgv)
{
	*pgv = hfi_tidflow_get_genval(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_check_update_pkt_seq(void *vpprotoexp
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
							       struct ips_message_header *p_hdr)
		)
{
	struct ips_protoexp *protoexp = (struct ips_protoexp *) vpprotoexp;
	struct ips_tid_recv_desc *tidrecvc = (struct ips_tid_recv_desc *) vptidrecvc;

	if_pf(psmi_hal_has_sw_status(PSM_HAL_HDRSUPP_ENABLED)) {
		/* Drop packet if generation number does not match. There
		 * is a window that before we program the hardware tidflow
		 * table with new gen/seq, hardware might receive some
		 * packets with the old generation.
		 */
		if (sequence_num.psn_gen != tidrecvc->tidflow_genseq.psn_gen)
		{
			PSM2_LOG_MSG("leaving");
			return PSM_HAL_ERROR_GENERAL_ERROR;
		}

#ifdef PSM_DEBUG
		/* Check if new packet falls into expected seq range, we need
		 * to deal with wrap around of the seq value from 2047 to 0
		 * because seq is only 11 bits. */
		int16_t seq_off = (int16_t)(sequence_num.psn_seq -
					tidrecvc->tidflow_genseq.psn_seq);
		if (seq_off < 0)
			seq_off += 2048; /* seq is 11 bits */
		psmi_assert(seq_off < 1024);
#endif
		/* NOTE: with RSM in use, we should not automatically update
		 * our PSN from the HFI's PSN.  The HFI doesn't know about
		 * RSM interceptions.
		 */
		/* (DON'T!) Update the shadow tidflow_genseq */
		/* tidrecvc->tidflow_genseq.psn_seq = sequence_num.psn_seq + 1; */

	}
	/* Always check the sequence number if we get a header, even if SH. */
	if_pt(sequence_num.psn_num == tidrecvc->tidflow_genseq.psn_num) {
		/* Update the shadow tidflow_genseq */
		tidrecvc->tidflow_genseq.psn_seq = sequence_num.psn_seq + 1;

		/* update the fake tidflow table with new seq, this is for
		 * seqerr and err_chk_gen processing to get the latest
		 * valid sequence number */
		hfp_gen1_tidflow_set_entry(
			tidrecvc->rdescid._desc_idx,
			tidrecvc->tidflow_genseq.psn_gen,
			tidrecvc->tidflow_genseq.psn_seq,
			tidrecvc->context->psm_hw_ctxt);
	} else {
		/* Generation mismatch */
		if (sequence_num.psn_gen != tidrecvc->tidflow_genseq.psn_gen) {
			ips_protoexp_do_tf_generr(protoexp,
						tidrecvc, p_hdr);
			PSM2_LOG_MSG("leaving");
			return PSM_HAL_ERROR_GENERAL_ERROR;
		} else {
			/* Possible sequence mismatch error */
			/* First, check if this is a recoverable SeqErr -
			 * caused by a good packet arriving in a tidflow that
			 * has had a FECN bit set on some earlier packet.
			 */

			/* If this is the first RSM packet, our own PSN state
			 * is probably old.  Pull from the HFI if it has
			 * newer data.
			 */
			uint64_t tf;
			psmi_seqnum_t tf_sequence_num;

			hfp_gen1_tidflow_get(tidrecvc->rdescid._desc_idx, &tf,
					     tidrecvc->context->psm_hw_ctxt);
			hfp_gen1_tidflow_get_seqnum(tf, &tf_sequence_num.psn_val);

			if (tf_sequence_num.psn_val > tidrecvc->tidflow_genseq.psn_seq)
				tidrecvc->tidflow_genseq.psn_seq = tf_sequence_num.psn_seq;

			/* Now re-check the sequence numbers. */
			if (sequence_num.psn_seq > tidrecvc->tidflow_genseq.psn_seq) {
				/* It really was a sequence error.  Restart. */
				ips_protoexp_do_tf_seqerr(protoexp, tidrecvc, p_hdr);
				PSM2_LOG_MSG("leaving");
				return PSM_HAL_ERROR_GENERAL_ERROR;
			} else {
				/* False SeqErr.  We can accept this packet. */
				if (sequence_num.psn_seq == tidrecvc->tidflow_genseq.psn_seq)
					tidrecvc->tidflow_genseq.psn_seq++;
			}
		}
	}

	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_flowvalid(uint64_t val, uint32_t *pfv)
{
	*pfv = hfi_tidflow_get_flowvalid(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_enabled(uint64_t val, uint32_t *penabled)
{
	*penabled = hfi_tidflow_get_enabled(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_keep_after_seqerr(uint64_t val, uint32_t *pkase)
{
	*pkase = hfi_tidflow_get_keep_after_seqerr(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_keep_on_generr(uint64_t val, uint32_t *pkoge)
{
	*pkoge = hfi_tidflow_get_keep_on_generr(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_keep_payload_on_generr(uint64_t val, uint32_t *pkpoge)
{
	*pkpoge = hfi_tidflow_get_keep_payload_on_generr(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_seqmismatch(uint64_t val, uint32_t *psmm)
{
	*psmm = hfi_tidflow_get_seqmismatch(val);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_tidflow_get_genmismatch(uint64_t val, uint32_t *pgmm)
{
	*pgmm = hfi_tidflow_get_genmismatch(val);
	return PSM_HAL_ERROR_OK;
}

static inline int hfp_gen1_write_header_to_subcontext(struct ips_message_header *pimh,
					       psmi_hal_cl_idx idx,
					       psmi_hal_raw_rhf_t rhf,
					       psmi_hal_cl_q cl_q,
					       psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];
	uint32_t *pu32 = pcl_q->hdr_qe.hdrq_base_addr + (idx + hfi_hdrget_hdrq_offset((uint32_t *)&rhf));
	struct ips_message_header *piph_dest = (struct ips_message_header *)pu32;

	*piph_dest = *pimh;
	return PSM_HAL_ERROR_OK;
}

static inline
void
writehdrq_write_rhf_atomic(uint64_t *rhf_dest, uint64_t rhf_src)
{
	/*
	 * In 64-bit mode, we check in init that the rhf will always be 8-byte
	 * aligned
	 */
	*rhf_dest = rhf_src;
	return;
}

static inline int hfp_gen1_write_rhf_to_subcontext(psmi_hal_raw_rhf_t rhf,
					    psmi_hal_cl_idx idx,
					    uint32_t *phdrq_rhf_seq,
					    psmi_hal_cl_q cl_q,
					    psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	psm_hal_gen1_cl_q_t *pcl_q = &psm_hw_ctxt->cl_qs[cl_q];

	if (!get_psm_gen1_hi()->hfp_private.dma_rtail)
	{
		uint32_t rhf_seq = *phdrq_rhf_seq;
		hfi_hdrset_seq((uint32_t *) &rhf, rhf_seq);
		rhf_seq++;
		if (rhf_seq > LAST_RHF_SEQNO)
			rhf_seq = 1;

		*phdrq_rhf_seq = rhf_seq;
	}

	/* Now write the new rhf */
	writehdrq_write_rhf_atomic((uint64_t*)(pcl_q->hdr_qe.hdrq_base_addr +
					       (idx + get_psm_gen1_hi()->hfp_private.hdrq_rhf_off)),
				    rhf);
	return PSM_HAL_ERROR_OK;
}

static PSMI_HAL_INLINE int hfp_gen1_subcontext_ureg_get(ptl_t *ptl_gen,
					struct ips_subcontext_ureg **uregp,
					psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	int i;
	struct ptl_ips *ptl = (struct ptl_ips *) ptl_gen;

	ptl->recvshc->hwcontext_ctrl = psm_hw_ctxt->hwcontext_ctrl;
	for (i=0;i < psm_hw_ctxt->user_info.subctxt_cnt; i++)
		uregp[i] = psm_hw_ctxt->subcontext_ureg[i];
	return PSM_HAL_ERROR_OK;
}


static inline
int
ips_write_eager_packet(struct ips_writehdrq *writeq,
		       struct ips_recvhdrq_event *rcv_ev,
		       psmi_hal_cl_idx write_hdr_tail,
		       uint32_t subcontext,
		       psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	psmi_hal_cl_idx write_egr_tail;
	write_egr_tail = hfp_gen1_get_cl_q_tail_index(
					 PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(subcontext),
					 ctxt);
	uint32_t next_write_egr_tail = write_egr_tail;
	/* checksum is trimmed from paylen, we need to add back */
	uint32_t rcv_paylen = ips_recvhdrq_event_paylen(rcv_ev) +
	    (rcv_ev->has_cksum ? PSM_CRC_SIZE_IN_BYTES : 0);
	psmi_assert(rcv_paylen > 0);
	uint32_t egr_elemcnt = ctrl->ctxt_info.egrtids;
	uint32_t egr_elemsz = ctrl->ctxt_info.rcvegr_size;

	/* Loop as long as the write eager queue is NOT full */
	while (1) {
		next_write_egr_tail++;
		if (next_write_egr_tail >= egr_elemcnt)
			next_write_egr_tail = 0;
		psmi_hal_cl_idx egr_head;
		egr_head = hfp_gen1_get_cl_q_head_index(
				   PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(subcontext),
				   ctxt);
		if (next_write_egr_tail == egr_head) {
			break;
		}

		/* Move to next eager entry if leftover is not enough */
		if ((writeq->state->egrq_offset + rcv_paylen) >
		    egr_elemsz) {
			writeq->state->egrq_offset = 0;
			write_egr_tail = next_write_egr_tail;

			/* Update the eager buffer tail pointer */
			hfp_gen1_set_cl_q_tail_index(write_egr_tail,
						PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(subcontext),
						ctxt);
		} else {
			/* There is enough space in this entry! */
			/* Use pre-calculated address from look-up table */
			char *write_payload =
				hfp_gen1_get_egr_buff(write_egr_tail,
						      PSM_HAL_GET_SC_CL_Q_RX_EGR_Q(subcontext),
					ctxt)+
				writeq->state->egrq_offset;
			const char *rcv_payload =
			    ips_recvhdrq_event_payload(rcv_ev);

			psmi_assert(write_payload != NULL);
			psmi_assert(rcv_payload != NULL);
			psmi_mq_mtucpy(write_payload, rcv_payload, rcv_paylen);

			/* Fix up the rhf with the subcontext's eager index/offset */
			hfi_hdrset_egrbfr_index((uint32_t*)(&rcv_ev->psm_hal_rhf.raw_rhf),write_egr_tail);
			hfi_hdrset_egrbfr_offset((uint32_t *)(&rcv_ev->psm_hal_rhf.raw_rhf), (writeq->state->
								egrq_offset >> 6));
			/* Copy the header to the subcontext's header queue */
			hfp_gen1_write_header_to_subcontext(rcv_ev->p_hdr,
							    write_hdr_tail,
							    rcv_ev->psm_hal_rhf.raw_rhf,
							    PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
							    ctxt);

			/* Update offset to next 64B boundary */
			writeq->state->egrq_offset =
			    (writeq->state->egrq_offset + rcv_paylen +
			     63) & (~63);
			return IPS_RECVHDRQ_CONTINUE;
		}
	}

	/* At this point, the eager queue is full -- drop the packet. */
	/* Copy the header to the subcontext's header queue */

	/* Mark header with ETIDERR (eager overflow) */
	hfi_hdrset_err_flags((uint32_t*) (&rcv_ev->psm_hal_rhf.raw_rhf), HFI_RHF_TIDERR);

	/* Clear UseEgrBfr bit because payload is dropped */
	hfi_hdrset_use_egrbfr((uint32_t *)(&rcv_ev->psm_hal_rhf.raw_rhf), 0);
	hfp_gen1_write_header_to_subcontext(rcv_ev->p_hdr,
					    write_hdr_tail,
					    rcv_ev->psm_hal_rhf.raw_rhf,
					    PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
					    ctxt);
	return IPS_RECVHDRQ_BREAK;
}

static PSMI_HAL_INLINE
int
hfp_gen1_forward_packet_to_subcontext(struct ips_writehdrq *writeq,
				      struct ips_recvhdrq_event *rcv_ev,
				      uint32_t subcontext,
				      psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	psmi_hal_cl_idx write_hdr_head;
	psmi_hal_cl_idx write_hdr_tail;
	uint32_t hdrq_elemsz = ctrl->ctxt_info.rcvhdrq_entsize >> BYTE2DWORD_SHIFT;
	psmi_hal_cl_idx next_write_hdr_tail;
	int result = IPS_RECVHDRQ_CONTINUE;

	/* Drop packet if write header queue is disabled */
	if_pf (!writeq->state->enabled) {
		return IPS_RECVHDRQ_BREAK;
	}

	write_hdr_head = hfp_gen1_get_cl_q_head_index(
				     PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
				     ctxt);
	write_hdr_tail = hfp_gen1_get_cl_q_tail_index(
					 PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
				     ctxt);
	/* Drop packet if write header queue is full */
	next_write_hdr_tail = write_hdr_tail + hdrq_elemsz;
	if (next_write_hdr_tail > writeq->hdrq_elemlast) {
		next_write_hdr_tail = 0;
	}
	if (next_write_hdr_tail == write_hdr_head) {
		return IPS_RECVHDRQ_BREAK;
	}
	if (psmi_hal_rhf_get_use_egr_buff(rcv_ev->psm_hal_rhf))
	{
		result = ips_write_eager_packet(writeq, rcv_ev,
						write_hdr_tail,
						subcontext,
						ctxt);
	} else {
		/* Copy the header to the subcontext's header queue */
		hfp_gen1_write_header_to_subcontext(rcv_ev->p_hdr,
						    write_hdr_tail,
						    rcv_ev->psm_hal_rhf.raw_rhf,
						    PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
						    ctxt);
	}

	/* Ensure previous writes are visible before writing rhf seq or tail */
	ips_wmb();

	/* The following func call may modify the hdrq_rhf_seq */
	hfp_gen1_write_rhf_to_subcontext(rcv_ev->psm_hal_rhf.raw_rhf, write_hdr_tail,
					 &writeq->state->hdrq_rhf_seq,
					 PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
					 ctxt);
	/* The tail must be updated regardless of PSM_HAL_CAP_DMA_RTAIL
	 * since this tail is also used to keep track of where
	 * ips_writehdrq_append will write to next. For subcontexts there is
	 * no separate shadow copy of the tail. */
	hfp_gen1_set_cl_q_tail_index(next_write_hdr_tail,
				PSM_HAL_GET_SC_CL_Q_RX_HDR_Q(subcontext),
				ctxt);

	return result;
}

static PSMI_HAL_INLINE int hfp_gen1_set_pio_size(uint32_t pio_size, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	ctrl->__hfi_piosize = pio_size;

	return 0;
}

static PSMI_HAL_INLINE int hfp_gen1_set_effective_mtu(uint32_t eff_mtu, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	ctrl->__hfi_mtusize = eff_mtu;
	return 0;
}

static PSMI_HAL_INLINE int hfp_gen1_set_tf_valid(uint32_t tf_valid, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	ctrl->__hfi_tfvalid = tf_valid;
	return 0;
}

static PSMI_HAL_INLINE int hfp_gen1_get_default_pkey(void)
{
	return HFI_DEFAULT_P_KEY;
}

#include "psm_hal_gen1_spio.c"

static PSMI_HAL_INLINE int hfp_gen1_spio_init(const psmi_context_t *context,
		       struct ptl *ptl, void **ctrl)
{
	hfp_gen1_pc_private *psm_hw_ctxt = context->psm_hw_ctxt;

	int rc = ips_spio_init(context,ptl, &psm_hw_ctxt->spio_ctrl);
	if (rc >= 0)
	{
		*ctrl = &psm_hw_ctxt->spio_ctrl;
	}
	return rc;
}

static PSMI_HAL_INLINE int hfp_gen1_spio_fini(void **ctrl, psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	int rc = ips_spio_fini(&psm_hw_ctxt->spio_ctrl);

	if (!rc)
		*ctrl = NULL;
	return rc;
}

static PSMI_HAL_INLINE int hfp_gen1_spio_transfer_frame(struct ips_proto *proto,
					struct ips_flow *flow, struct psm_hal_pbc *pbc,
					uint32_t *payload, uint32_t length,
					uint32_t isCtrlMsg, uint32_t cksum_valid,
					uint32_t cksum, psmi_hal_hw_context ctxt
#ifdef PSM_CUDA
				, uint32_t is_cuda_payload
#endif
	)
{
	return ips_spio_transfer_frame(proto, flow, pbc,
					 payload, length, isCtrlMsg,
					 cksum_valid, cksum
#ifdef PSM_CUDA
				, is_cuda_payload
#endif
	);
}

static PSMI_HAL_INLINE int hfp_gen1_spio_process_events(const struct ptl *ptl)
{
	return ips_spio_process_events(ptl);
}

static PSMI_HAL_INLINE int hfp_gen1_get_node_id(int unit, int *nodep)
{
	int64_t node_id = hfi_sysfs_unit_read_node_s64(unit);
	*nodep = (int)node_id;
	if (node_id != -1)
		return PSM_HAL_ERROR_OK;
	else
		return -PSM_HAL_ERROR_GENERAL_ERROR;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_bthqp(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->base_info.bthqp;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_context(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->ctxt_info.ctxt;
}

static PSMI_HAL_INLINE uint64_t hfp_gen1_get_gid_lo(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	uint64_t gid_lo, gid_hi;
	if (hfi_get_port_gid(ctrl->__hfi_unit,
			     ctrl->__hfi_port, &gid_hi,
			     &gid_lo) == -1) {
		psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
				  "Can't get HFI GID in psm2_ep_open: is SMA running?");
	}
	return gid_lo;
}

static PSMI_HAL_INLINE uint64_t hfp_gen1_get_gid_hi(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	uint64_t gid_lo, gid_hi;
	if (hfi_get_port_gid(ctrl->__hfi_unit,
			     ctrl->__hfi_port, &gid_hi,
			     &gid_lo) == -1) {
		psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
				  "Can't get HFI GID in psm2_ep_open: is SMA running?");
	}
	return gid_hi;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_hfi_type(psmi_hal_hw_context ctxt)
{
	return PSM_HAL_INSTANCE_GEN1;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_jkey(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->base_info.jkey;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_lid(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;
	int lid;

	if ((lid = hfi_get_port_lid(ctrl->__hfi_unit,
				    ctrl->__hfi_port)) <= 0) {
		psmi_handle_error(NULL,
					PSM2_EP_DEVICE_FAILURE,
					"Can't get HFI LID in psm2_ep_open: is SMA running?");
	}
	return lid;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_pio_size(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return (ctrl->ctxt_info.credits / 2) * 64 -
		(sizeof(struct ips_message_header) + HFI_PCB_SIZE_IN_BYTES);
}

static PSMI_HAL_INLINE int      hfp_gen1_get_port_num(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->__hfi_port;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_rx_egr_tid_cnt(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->ctxt_info.egrtids;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_rx_hdr_q_cnt(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->ctxt_info.rcvhdrq_cnt;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_rx_hdr_q_ent_size(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->ctxt_info.rcvhdrq_entsize;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_sdma_req_size(psmi_hal_hw_context ctxt)
{
	return get_psm_gen1_hi()->hfp_private.sdmahdr_req_size;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_sdma_ring_size(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->ctxt_info.sdma_ring_size;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_subctxt(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->ctxt_info.subctxt;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_subctxt_cnt(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	return psm_hw_ctxt->user_info.subctxt_cnt;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_tid_exp_cnt(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->__hfi_tidexpcnt;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_unit_id(psmi_hal_hw_context ctxt)
{
	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;
	struct _hfi_ctrl *ctrl = psm_hw_ctxt->ctrl;

	return ctrl->__hfi_unit;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_fd(psmi_hal_hw_context ctxt)
{
	if (!ctxt)
		return -1;

	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	return psm_hw_ctxt->ctrl->fd;
}

static PSMI_HAL_INLINE int      hfp_gen1_get_pio_stall_cnt(psmi_hal_hw_context ctxt, uint64_t **pio_stall_cnt)
{

	if (!ctxt)
		return -PSM_HAL_ERROR_GENERAL_ERROR;

	hfp_gen1_pc_private *psm_hw_ctxt = ctxt;

	*pio_stall_cnt = &psm_hw_ctxt->spio_ctrl.spio_num_stall_total;

	return PSM_HAL_ERROR_OK;
}
