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

/* Copyright (c) 2003-2015 Intel Corporation. All rights reserved. */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "psm_user.h"

#define PSMI_SHARED_CONTEXTS_ENABLED_BY_DEFAULT   1
static int psmi_sharedcontext_params(int *nranks, int *rankid);
static int psmi_get_hfi_selection_algorithm(void);
static psm2_error_t psmi_init_userinfo_params(psm2_ep_t ep,
					     int unit_id,
					     psm2_uuid_t const unique_job_key,
					     struct hfi1_user_info *user_info);

psm2_error_t psmi_context_interrupt_set(psmi_context_t *context, int enable)
{
	int poll_type;
	int ret;

	if ((enable && (context->runtime_flags & PSMI_RUNTIME_INTR_ENABLED)) ||
	    (!enable && !(context->runtime_flags & PSMI_RUNTIME_INTR_ENABLED)))
		return PSM2_OK;

	if (enable)
		poll_type = HFI1_POLL_TYPE_URGENT;
	else
		poll_type = 0;

	ret = hfi_poll_type(context->ctrl, poll_type);

	if (ret != 0)
		return PSM2_EP_NO_RESOURCES;
	else {
		if (enable)
			context->runtime_flags |= PSMI_RUNTIME_INTR_ENABLED;
		else
			context->runtime_flags &= ~PSMI_RUNTIME_INTR_ENABLED;

		return PSM2_OK;
	}
}

int psmi_context_interrupt_isenabled(psmi_context_t *context)
{
	return context->runtime_flags & PSMI_RUNTIME_INTR_ENABLED;
}

psm2_error_t
psmi_context_open(const psm2_ep_t ep, long unit_id, long port,
		  psm2_uuid_t const job_key, int64_t timeout_ns,
		  psmi_context_t *context)
{
	long open_timeout = 0;
	int lid, sc, vl;
	uint64_t gid_hi, gid_lo;
	char dev_name[MAXPATHLEN];
	psm2_error_t err = PSM2_OK;
	uint32_t hfi_type;
	int retry_delay = 0;

	/*
	 * If shared contexts are enabled, try our best to schedule processes
	 * across one or many devices
	 */

	if (timeout_ns > 0)
		open_timeout = (long)(timeout_ns / MSEC_ULL);
	if (unit_id != HFI_UNIT_ID_ANY && unit_id >= 0)
		snprintf(dev_name, sizeof(dev_name), "%s_%u", HFI_DEVICE_PATH,
			 (unsigned)unit_id);
	else
		snprintf(dev_name, sizeof(dev_name), "%s", HFI_DEVICE_PATH);

	context->fd = hfi_context_open(unit_id, port, open_timeout);
	if (context->fd == -1) {
		err = psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
					"PSM can't open %s for reading and writing",
					dev_name);
		goto bail;
	}

	if ((err = psmi_init_userinfo_params(ep,
					     (int)unit_id, job_key,
					     &context->user_info)))
		goto bail;

retry_open:
	context->ctrl = hfi_userinit(context->fd, &context->user_info);
	if (!context->ctrl) {

		/* hfi_userinit returns EBUSY on hfi and ENODEV on qib when
		 * no contexts are available. Handle both drivers.
		 */
		if ((errno != ENETDOWN) && (errno != EBUSY)
		    && (errno != ENODEV))
			goto fail;

		if ((open_timeout == -1L) || (errno == EBUSY)
		    || (errno == ENODEV)) {
			if (!retry_delay) {
				_HFI_PRDBG("retrying open: %s, network down\n",
					   dev_name);
				retry_delay = 1;
			} else if (retry_delay < 17)
				retry_delay <<= 1;

			/* If device is still busy after 3 attempts give up. No contexts
			 * available.
			 */
			if (((errno == EBUSY) || (errno == ENODEV))
			    && retry_delay > 4)
				goto fail;

			sleep(retry_delay);
			goto retry_open;
		}

		err = psmi_handle_error(NULL, PSM2_EP_NO_NETWORK,
					"can't open %s, network down",
					dev_name);
		goto bail;
	}

	_HFI_VDBG("hfi_userinit() passed.\n");

	if (hfi_get_port_active(context->ctrl->__hfi_unit,
				    context->ctrl->__hfi_port) != 1) {
		err = psmi_handle_error(NULL,
					PSM2_EP_DEVICE_FAILURE,
					"Unit/port: %d/%d is not active.",
					context->ctrl->__hfi_unit,
					context->ctrl->__hfi_port);
		goto bail;
	}
	if ((lid = hfi_get_port_lid(context->ctrl->__hfi_unit,
				    context->ctrl->__hfi_port)) <= 0) {
		err = psmi_handle_error(NULL,
					PSM2_EP_DEVICE_FAILURE,
					"Can't get HFI LID in psm2_ep_open: is SMA running?");
		goto bail;
	}
	if (hfi_get_port_gid(context->ctrl->__hfi_unit,
			     context->ctrl->__hfi_port, &gid_hi,
			     &gid_lo) == -1) {
		err =
		    psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
				      "Can't get HFI GID in psm2_ep_open: is SMA running?");
		goto bail;
	}
	ep->unit_id = context->ctrl->__hfi_unit;
	ep->portnum = context->ctrl->__hfi_port;
	ep->gid_hi = gid_hi;
	ep->gid_lo = gid_lo;

	context->ep = (psm2_ep_t) ep;
	context->runtime_flags = context->ctrl->ctxt_info.runtime_flags;

	/* Get type of hfi assigned to context */
	hfi_type = psmi_get_hfi_type(context);

	/* Endpoint out_sl contains the default SL to use for this endpoint. */
	/* Get the MTU for this SL. */
	if ((sc = hfi_get_port_sl2sc(ep->unit_id,
				     context->ctrl->__hfi_port,
				     ep->out_sl)) < 0) {
		sc = PSMI_SC_DEFAULT;
	}
	if ((vl = hfi_get_port_sc2vl(ep->unit_id,
				     context->ctrl->__hfi_port, sc)) < 0) {
		vl = PSMI_VL_DEFAULT;
	}
	if (sc == PSMI_SC_ADMIN || vl == PSMI_VL_ADMIN) {
		err = psmi_handle_error(NULL, PSM2_INTERNAL_ERR,
			"Invalid sl: %d, please specify correct sl via HFI_SL",
			ep->out_sl);
		goto bail;
	}

	if ((ep->mtu = hfi_get_port_vl2mtu(ep->unit_id,
					   context->ctrl->__hfi_port,
					   vl)) < 0) {
		err =
		    psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
				      "Can't get MTU for VL %d", vl);
		goto bail;
	}

	/* Construct epid for this Endpoint */
	context->epid = PSMI_EPID_PACK(lid, context->ctrl->ctxt_info.ctxt,
				       context->ctrl->ctxt_info.subctxt,
				       context->ctrl->__hfi_unit,
				       hfi_type, 0x3ffffff);

	_HFI_VDBG
	    ("construct epid: lid %d ctxt %d subctxt %d hcatype %d mtu %d\n",
	     lid, context->ctrl->ctxt_info.ctxt,
	     context->ctrl->ctxt_info.subctxt, hfi_type, ep->mtu);

	goto ret;

fail:
	switch (errno) {
	case ENOENT:
	case ENODEV:
		err = psmi_handle_error(NULL, PSM2_EP_NO_DEVICE,
					"%s not found", dev_name);
		break;
	case ENXIO:
		err = psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
					"%s failure", dev_name);
		break;
	case EBUSY:
		err = psmi_handle_error(NULL, PSM2_EP_NO_PORTS_AVAIL,
					"No free opa contexts available on %s",
					dev_name);
		break;
	default:
		err = psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
					"Driver initialization failure on %s",
					dev_name);
		break;
	}
bail:
	_HFI_PRDBG("%s open failed: %d (%s)\n", dev_name, err, strerror(errno));
	if (context->fd != -1) {
		hfi_context_close(context->fd);
		context->fd = -1;
	}
ret:

	_HFI_VDBG("psmi_context_open() return %d\n", err);
	return err;
}

psm2_error_t psmi_context_close(psmi_context_t *context)
{
	if (context->fd >= 0) {
		hfi_context_close(context->fd);
		context->fd = -1;
	}
	return PSM2_OK;
}

/*
 * This function works whether a context is intiialized or not in a psm2_ep.
 *
 * Returns one of
 *
 * PSM2_OK: Port status is ok (or context not intialized yet but still "ok")
 * PSM2_OK_NO_PROGRESS: Cable pulled
 * PSM2_EP_NO_NETWORK: No network, no lid, ...
 * PSM2_EP_DEVICE_FAILURE: Chip failures, rxe/txe parity, etc.
 * The message follows the per-port status
 * As of 7322-ready driver, need to check port-specific qword for IB
 * as well as older unit-only.  For now, we don't have the port interface
 * defined, so just check port 0 qword for spi_status
 */
psm2_error_t psmi_context_check_status(const psmi_context_t *contexti)
{
	psm2_error_t err = PSM2_OK;
	psmi_context_t *context = (psmi_context_t *) contexti;
	struct hfi1_status *status =
	    (struct hfi1_status *)context->ctrl->base_info.status_bufbase;
	char *errmsg = NULL;

	/* Fatal chip-related errors */
	if (!(status->dev & HFI1_STATUS_CHIP_PRESENT) ||
	    !(status->dev & HFI1_STATUS_INITTED) ||
	    (status->dev & HFI1_STATUS_HWERROR)) {

		err = PSM2_EP_DEVICE_FAILURE;
		if (err != context->status_lasterr) {	/* report once */
			volatile char *errmsg_sp =
			    (volatile char *)status->freezemsg;
			if (*errmsg_sp)
				psmi_handle_error(context->ep, err,
						  "Hardware problem: %s",
						  errmsg_sp);
			else {
				if (status->dev & HFI1_STATUS_HWERROR)
					errmsg = "Hardware error";
				else
					errmsg = "Hardware not found";

				psmi_handle_error(context->ep, err, errmsg);
			}
		}
	}
	/* Fatal network-related errors with timeout: */
	else if (!(status->port & HFI1_STATUS_IB_CONF) ||
		 !(status->port & HFI1_STATUS_IB_READY)) {
		err = PSM2_EP_NO_NETWORK;
		if (err != context->status_lasterr) {	/* report once */
			context->networkLostTime = time(NULL);
		}
		else
		{
			time_t now = time(NULL);
			static const double thirtySeconds = 30.0;

			if (difftime(now,context->networkLostTime) > thirtySeconds)
			{
				volatile char *errmsg_sp =
					(volatile char *)status->freezemsg;

				psmi_handle_error(context->ep, err, "%s",
						  *errmsg_sp ? errmsg_sp :
						  "Network down");
			}
		}
	}

	if (err == PSM2_OK && context->status_lasterr != PSM2_OK)
		context->status_lasterr = PSM2_OK;	/* clear error */
	else if (err != PSM2_OK)
		context->status_lasterr = err;	/* record error */

	return err;
}

/*
 * Prepare user_info params for driver open, used only in psmi_context_open
 */
static
psm2_error_t
psmi_init_userinfo_params(psm2_ep_t ep, int unit_id,
			  psm2_uuid_t const unique_job_key,
			  struct hfi1_user_info *user_info)
{
	/* static variables, shared among rails */
	static int shcontexts_enabled = -1, rankid, nranks;

	int avail_contexts = 0, max_contexts, ask_contexts;
	int ranks_per_context = 0;
	psm2_error_t err = PSM2_OK;
	union psmi_envvar_val env_maxctxt, env_ranks_per_context;
	static int subcontext_id_start;

	memset(user_info, 0, sizeof(*user_info));
	user_info->userversion = HFI1_USER_SWMINOR|(HFI1_USER_SWMAJOR<<16);

	user_info->hfi1_alg = psmi_get_hfi_selection_algorithm();

	user_info->subctxt_id = 0;
	user_info->subctxt_cnt = 0;
	memcpy(user_info->uuid, unique_job_key, sizeof(user_info->uuid));

	if (shcontexts_enabled == -1) {
		shcontexts_enabled =
		    psmi_sharedcontext_params(&nranks, &rankid);
	}
	if (!shcontexts_enabled)
		return err;

	avail_contexts = hfi_get_num_contexts(unit_id);

	if (avail_contexts == 0) {
		err = psmi_handle_error(NULL, PSM2_EP_NO_DEVICE,
					"PSM found 0 available contexts on opa device(s).");
		goto fail;
	}

	/* See if the user wants finer control over context assignments */
	if (!psmi_getenv("PSM2_SHAREDCONTEXTS_MAX",
			 "Maximum number of contexts for this PSM job",
			 PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
			 (union psmi_envvar_val)avail_contexts, &env_maxctxt)) {
		max_contexts = max(env_maxctxt.e_int, 1);	/* needs to be non-negative */
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
		    ("PSM_SHAREDCONTEXTS disabled because lrank=%d,ppn=%d\n",
		     rankid, nranks);
		goto fail;
	}

	if (ranks_per_context) {
		int contexts =
		    (nranks + ranks_per_context - 1) / ranks_per_context;
		if (contexts > ask_contexts) {
			err = psmi_handle_error(NULL, PSM2_EP_NO_DEVICE,
						"Incompatible settings for "
						"PSM_SHAREDCONTEXTS_MAX and PSM_RANKS_PER_CONTEXT");
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

	_HFI_PRDBG("PSM_SHAREDCONTEXTS lrank=%d,ppn=%d,avail_contexts=%d,"
		   "max_contexts=%d,ask_contexts=%d,"
		   "ranks_per_context=%d,id=%u,cnt=%u\n",
		   rankid, nranks, avail_contexts, max_contexts,
		   ask_contexts, ranks_per_context,
		   user_info->subctxt_id, user_info->subctxt_cnt);
fail:
	return err;
}

static
int psmi_sharedcontext_params(int *nranks, int *rankid)
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
	}
	return 1;
}

static
int psmi_get_hfi_selection_algorithm(void)
{
	union psmi_envvar_val env_hfi1_alg;
	int hfi1_alg = HFI1_ALG_ACROSS;

	/* If a specific unit is set in the environment, use that one. */
	psmi_getenv("HFI_SELECTION_ALG",
		    "HFI Device Selection Algorithm to use. Round Robin (Default) "
		    "or Packed",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
		    (union psmi_envvar_val)"Round Robin", &env_hfi1_alg);

	if (!strcasecmp(env_hfi1_alg.e_str, "Round Robin"))
		hfi1_alg = HFI1_ALG_ACROSS;
	else if (!strcasecmp(env_hfi1_alg.e_str, "Packed"))
		hfi1_alg = HFI1_ALG_WITHIN;
	else {
		_HFI_ERROR
		    ("Unknown HFI selection algorithm %s. Defaulting to Round Robin "
		     "allocation of HFIs.\n", env_hfi1_alg.e_str);
		hfi1_alg = HFI1_ALG_ACROSS;
	}

	return hfi1_alg;
}
