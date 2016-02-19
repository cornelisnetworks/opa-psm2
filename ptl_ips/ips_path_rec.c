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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

static void ips_gen_ipd_table(struct ips_proto *proto)
{
	uint8_t delay = 0, step = 1;
	/* Based on our current link rate setup the IPD table */
	memset(proto->ips_ipd_delay, 0xFF, sizeof(proto->ips_ipd_delay));

	/*
	 * Based on the starting rate of the link, we let the code to
	 * fall through to next rate without 'break' in the code. The
	 * decrement is doubled at each rate level...
	 */
	switch (proto->epinfo.ep_link_rate) {
	case IBV_RATE_300_GBPS:
		proto->ips_ipd_delay[IBV_RATE_100_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_200_GBPS:
		proto->ips_ipd_delay[IBV_RATE_100_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_168_GBPS:
		proto->ips_ipd_delay[IBV_RATE_100_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_120_GBPS:
		proto->ips_ipd_delay[IBV_RATE_100_GBPS] = delay;
	case IBV_RATE_112_GBPS:
		proto->ips_ipd_delay[IBV_RATE_100_GBPS] = delay;
	case IBV_RATE_100_GBPS:
		proto->ips_ipd_delay[IBV_RATE_100_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_80_GBPS:
		proto->ips_ipd_delay[IBV_RATE_80_GBPS] = delay;
	case IBV_RATE_60_GBPS:
		proto->ips_ipd_delay[IBV_RATE_60_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_40_GBPS:
		proto->ips_ipd_delay[IBV_RATE_40_GBPS] = delay;
	case IBV_RATE_30_GBPS:
		proto->ips_ipd_delay[IBV_RATE_30_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_25_GBPS:
		proto->ips_ipd_delay[IBV_RATE_25_GBPS] = delay;
	case IBV_RATE_20_GBPS:
		proto->ips_ipd_delay[IBV_RATE_20_GBPS] = delay;
		delay += step;
		step *= 2;
	case IBV_RATE_10_GBPS:
		proto->ips_ipd_delay[IBV_RATE_10_GBPS] = delay;
	case IBV_RATE_5_GBPS:
		proto->ips_ipd_delay[IBV_RATE_5_GBPS] = delay;
	default:
		break;
	}
}

static psm2_error_t ips_gen_cct_table(struct ips_proto *proto)
{
	psm2_error_t err = PSM2_OK;
	uint32_t cca_divisor, ipdidx, ipdval = 1;
	uint16_t *cct_table;

	/* The CCT table is static currently. If it's already created then return */
	if (proto->cct)
		goto fail;

	/* Allocate the CCT table */
	cct_table = psmi_calloc(proto->ep, UNDEFINED,
				proto->ccti_size, sizeof(uint16_t));
	if (!cct_table) {
		err = PSM2_NO_MEMORY;
		goto fail;
	}

	if (proto->ccti_size)
	{
		/* The first table entry is always 0 i.e. no IPD delay */
		cct_table[0] = 0;
	}

	/* Generate the remaining CCT table entries */
	for (ipdidx = 1; ipdidx < proto->ccti_size; ipdidx += 4, ipdval++)
		for (cca_divisor = 0; cca_divisor < 4; cca_divisor++) {
			if ((ipdidx + cca_divisor) == proto->ccti_size)
				break;
			cct_table[ipdidx + cca_divisor] =
			    (((cca_divisor ^ 0x3) << CCA_DIVISOR_SHIFT) |
			     (ipdval & 0x3FFF));
			_HFI_VDBG("CCT[%d] = %x. Divisor: %x, IPD: %x\n",
				  ipdidx + cca_divisor,
				  cct_table[ipdidx + cca_divisor],
				  (cct_table[ipdidx + cca_divisor] >>
				   CCA_DIVISOR_SHIFT),
				  cct_table[ipdidx +
					    cca_divisor] & CCA_IPD_MASK);
		}

	/* On link up/down CCT is re-generated. If CCT table is previously created
	 * free it
	 */
	if (proto->cct) {
		psmi_free(proto->cct);
		proto->cct = NULL;
	}

	/* Update to the new CCT table */
	proto->cct = cct_table;

fail:
	return err;
}

static opa_rate ips_default_hfi_rate(uint16_t hfi_type)
{
	opa_rate rate;

	switch (hfi_type) {
	case PSMI_HFI_TYPE_OPA1:
		rate = IBV_RATE_100_GBPS;
		break;
	case PSMI_HFI_TYPE_OPA2:
		rate = IBV_RATE_120_GBPS;
		break;
	default:
		rate = IBV_RATE_MAX;
	}

	return rate;
}

static opa_rate ips_rate_to_enum(int link_rate)
{
	opa_rate rate;

	switch (link_rate) {
	case 300:
		rate = IBV_RATE_300_GBPS;
		break;
	case 200:
		rate = IBV_RATE_200_GBPS;
		break;
	case 100:
		rate = IBV_RATE_100_GBPS;
		break;
	case 25:
		rate = IBV_RATE_25_GBPS;
		break;
	case 168:
		rate = IBV_RATE_168_GBPS;
		break;
	case 112:
		rate = IBV_RATE_112_GBPS;
		break;
	case 56:
		rate = IBV_RATE_56_GBPS;
		break;
	case 14:
		rate = IBV_RATE_14_GBPS;
		break;
	case 120:
		rate = IBV_RATE_120_GBPS;
		break;
	case 80:
		rate = IBV_RATE_80_GBPS;
		break;
	case 60:
		rate = IBV_RATE_60_GBPS;
		break;
	case 40:
		rate = IBV_RATE_40_GBPS;
		break;
	case 30:
		rate = IBV_RATE_30_GBPS;
		break;
	case 20:
		rate = IBV_RATE_20_GBPS;
		break;
	case 10:
		rate = IBV_RATE_10_GBPS;
		break;
	case 5:
		rate = IBV_RATE_5_GBPS;
		break;
	default:
		rate = IBV_RATE_MAX;
	}

	return rate;
}

static psm2_error_t
ips_none_get_path_rec(struct ips_proto *proto,
		      uint16_t slid, uint16_t dlid, uint16_t desthfi_type,
		      unsigned long timeout, ips_path_rec_t **ppath_rec)
{
	psm2_error_t err = PSM2_OK;
	ips_path_rec_t *path_rec;
	ENTRY elid, *epath = NULL;
	char eplid[128];

	/* Query the path record cache */
	snprintf(eplid, sizeof(eplid), "%x_%x", slid, dlid);
	elid.key = eplid;
	hsearch_r(elid, FIND, &epath, &proto->ips_path_rec_hash);

	if (!epath) {
		elid.key =
		    psmi_calloc(proto->ep, UNDEFINED, 1, strlen(eplid) + 1);
		path_rec = (ips_path_rec_t *)
		    psmi_calloc(proto->ep, UNDEFINED, 1,
				sizeof(ips_path_rec_t));
		if (!elid.key || !path_rec) {
			if (elid.key)
				psmi_free(elid.key);
			if (path_rec)
				psmi_free(path_rec);
			return PSM2_NO_MEMORY;
		}

		/* Create path record */
		path_rec->pr_slid = slid;
		path_rec->pr_dlid = dlid;
		path_rec->pr_mtu = proto->epinfo.ep_mtu;
		path_rec->pr_pkey = proto->epinfo.ep_pkey;
		path_rec->pr_sl = proto->epinfo.ep_sl;

		/* Determine the IPD based on our local link rate and default link rate for
		 * remote hfi type.
		 */
		path_rec->pr_static_ipd =
		    proto->ips_ipd_delay[ips_default_hfi_rate(desthfi_type)];

		/* Setup CCA parameters for path */
		if (path_rec->pr_sl > PSMI_SL_MAX) {
			psmi_free(elid.key);
			psmi_free(path_rec);
			return PSM2_INTERNAL_ERR;
		}
		if (!(proto->ccti_ctrlmap & (1 << path_rec->pr_sl))) {
			_HFI_CCADBG("No CCA for sl %d, disable CCA\n",
				    path_rec->pr_sl);
			proto->flags &= ~IPS_PROTO_FLAG_CCA;
			proto->flags &= ~IPS_PROTO_FLAG_CCA_PRESCAN;
		}
		if (!(proto->ep->context.runtime_flags &
					HFI1_CAP_STATIC_RATE_CTRL)) {
			_HFI_CCADBG("No Static-Rate-Control, disable CCA\n");
			proto->flags &= ~IPS_PROTO_FLAG_CCA;
			proto->flags &= ~IPS_PROTO_FLAG_CCA_PRESCAN;
		}

		path_rec->proto = proto;
		path_rec->pr_ccti = proto->cace[path_rec->pr_sl].ccti_min;
		path_rec->pr_timer_cca = NULL;

		/* Determine active IPD for path. Is max of static rate and CCT table */
		if (!(proto->flags & IPS_PROTO_FLAG_CCA)) {
			path_rec->pr_active_ipd = 0;
			path_rec->pr_cca_divisor = 0;
		} else if ((path_rec->pr_static_ipd) &&
		    ((path_rec->pr_static_ipd + 1) >
		     (proto->cct[path_rec->pr_ccti] & CCA_IPD_MASK))) {
			path_rec->pr_active_ipd = path_rec->pr_static_ipd + 1;
			path_rec->pr_cca_divisor = 0;
		} else {
			/* Pick it from the CCT table */
			path_rec->pr_active_ipd =
			    proto->cct[path_rec->pr_ccti] & CCA_IPD_MASK;
			path_rec->pr_cca_divisor =
			    proto->cct[path_rec->pr_ccti] >> CCA_DIVISOR_SHIFT;
		}

		/* Add path record into cache */
		strcpy(elid.key, eplid);
		elid.data = (void *)path_rec;
		hsearch_r(elid, ENTER, &epath, &proto->ips_path_rec_hash);
	} else
		path_rec = (ips_path_rec_t *) epath->data;

	/* Return IPS path record */
	*ppath_rec = path_rec;

	return err;
}

static psm2_error_t
ips_none_path_rec(struct ips_proto *proto,
		  uint16_t slid, uint16_t dlid, uint16_t desthfi_type,
		  unsigned long timeout, ips_path_grp_t **ppathgrp)
{
	psm2_error_t err = PSM2_OK;
	uint16_t pidx, num_path = (1 << proto->epinfo.ep_lmc);
	uint16_t base_slid, base_dlid;
	ips_path_rec_t *path;
	ips_path_grp_t *pathgrp;
	ENTRY elid, *epath = NULL;
	char eplid[128];

	/* For the "none" path record resolution all paths are assumed to be of equal
	 * priority however since we want to isolate all control traffic (acks, naks)
	 * to a separate path for non zero LMC subnets the "first path" between a
	 * pair of endpoints is always the "higher" priority paths. The rest of the
	 * paths are the normal (and low priority) paths.
	 */

	/* Query the path record cache */
	snprintf(eplid, sizeof(eplid), "%x_%x", slid, dlid);
	elid.key = eplid;
	hsearch_r(elid, FIND, &epath, &proto->ips_path_grp_hash);

	if (epath) {		/* Find path group in cache */
		*ppathgrp = (ips_path_grp_t *) epath->data;
		return err;
	}

	/* If base lids are only used then reset num_path to 1 */
	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_BASE)
		num_path = 1;

	/* Allocate a new pathgroup */
	elid.key = psmi_calloc(proto->ep, UNDEFINED, 1, strlen(eplid) + 1);
	pathgrp = (ips_path_grp_t *)
	    psmi_calloc(proto->ep, UNDEFINED, 1, sizeof(ips_path_grp_t) +
			num_path * IPS_PATH_MAX_PRIORITY *
			sizeof(ips_path_rec_t *));
	if (!elid.key || !pathgrp) {
		if (elid.key)
			psmi_free(elid.key);
		if (pathgrp)
			psmi_free(pathgrp);
		err = PSM2_NO_MEMORY;
		goto fail;
	}

	/* dlid is the peer base lid */
	pathgrp->pg_base_lid = __be16_to_cpu(dlid);

	if (num_path > 1) {
		/* One control path and (num_path - 1) norm and low priority paths */
		pathgrp->pg_num_paths[IPS_PATH_HIGH_PRIORITY] = 1;
		pathgrp->pg_num_paths[IPS_PATH_NORMAL_PRIORITY] = num_path - 1;
		pathgrp->pg_num_paths[IPS_PATH_LOW_PRIORITY] = num_path - 1;
	} else {
		/* LMC of 0. Use the same path for all priorities */
		pathgrp->pg_num_paths[IPS_PATH_HIGH_PRIORITY] = 1;
		pathgrp->pg_num_paths[IPS_PATH_NORMAL_PRIORITY] = 1;
		pathgrp->pg_num_paths[IPS_PATH_LOW_PRIORITY] = 1;
	}

	/* For "none" path record we just setup 2^lmc paths. To get better load
	 * balance
	 */
	for (pidx = 0; pidx < num_path; pidx++) {
		base_slid = __cpu_to_be16(__be16_to_cpu(slid) + pidx);
		base_dlid = __cpu_to_be16(__be16_to_cpu(dlid) + pidx);

		err =
		    ips_none_get_path_rec(proto, base_slid, base_dlid,
					  desthfi_type, timeout, &path);
		if (err != PSM2_OK) {
			psmi_free(elid.key);
			psmi_free(pathgrp);
			goto fail;
		}

		if (num_path > 1) {
			if (pidx == 0) {
				/* First path is always the high priority path */
				pathgrp->pg_path[0][IPS_PATH_HIGH_PRIORITY] =
				    path;
			} else {
				pathgrp->pg_path[pidx -
						 1][IPS_PATH_NORMAL_PRIORITY] =
				    path;
				pathgrp->pg_path[pidx -
						 1][IPS_PATH_LOW_PRIORITY] =
				    path;
			}
		} else {
			pathgrp->pg_path[0][IPS_PATH_HIGH_PRIORITY] = path;
			pathgrp->pg_path[0][IPS_PATH_NORMAL_PRIORITY] = path;
			pathgrp->pg_path[0][IPS_PATH_LOW_PRIORITY] = path;
		}
	}

	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE) {
		pathgrp->pg_next_path[IPS_PATH_NORMAL_PRIORITY] =
		    proto->epinfo.ep_context %
		    pathgrp->pg_num_paths[IPS_PATH_NORMAL_PRIORITY];
		pathgrp->pg_next_path[IPS_PATH_LOW_PRIORITY] =
		    proto->epinfo.ep_context %
		    pathgrp->pg_num_paths[IPS_PATH_LOW_PRIORITY];
	}

	/* Add path record into cache */
	strcpy(elid.key, eplid);
	elid.data = (void *)pathgrp;
	hsearch_r(elid, ENTER, &epath, &proto->ips_path_grp_hash);

	*ppathgrp = pathgrp;

fail:
	if (err != PSM2_OK)
		_HFI_PRDBG
		    ("Unable to get path record for LID %x <---> DLID %x.\n",
		     slid, dlid);
	return err;
}

static psm2_error_t ips_none_path_rec_init(struct ips_proto *proto)
{
	psm2_error_t err = PSM2_OK;

	/* Obtain the SL and PKEY to use from the environment (HFI_SL & PSM_KEY) */
	proto->epinfo.ep_sl = proto->ep->out_sl;
	proto->epinfo.ep_pkey = (uint16_t) proto->ep->network_pkey;

	/*
	 * Parse the err_chk settings from the environment.
	 * <min_timeout>:<max_timeout>:<timeout_factor>
	 */
	{
		union psmi_envvar_val env_to;
		char *errchk_to = PSM_TID_TIMEOUT_DEFAULT;
		int tvals[3] = {
			IPS_PROTO_ERRCHK_MS_MIN_DEFAULT,
			IPS_PROTO_ERRCHK_MS_MAX_DEFAULT,
			IPS_PROTO_ERRCHK_FACTOR_DEFAULT
		};

		if (!psmi_getenv("PSM2_ERRCHK_TIMEOUT",
				 "Errchk timeouts in mS <min:max:factor>",
				 PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
				 (union psmi_envvar_val)errchk_to, &env_to)) {
			/* Not using default values, parse what we can */
			errchk_to = env_to.e_str;
			psmi_parse_str_tuples(errchk_to, 3, tvals);
			/* Adjust for max smaller than min, things would break */
			if (tvals[1] < tvals[0])
				tvals[1] = tvals[0];
		}

		proto->epinfo.ep_timeout_ack = ms_2_cycles(tvals[0]);
		proto->epinfo.ep_timeout_ack_max = ms_2_cycles(tvals[1]);
		proto->epinfo.ep_timeout_ack_factor = tvals[2];
	}

	proto->ibta.get_path_rec = ips_none_path_rec;
	proto->ibta.fini = NULL;

	/* With no path records queries set pkey manually */
	if (hfi_set_pkey(proto->ep->context.ctrl,
			 (uint16_t) proto->ep->network_pkey) != 0) {
		err = psmi_handle_error(proto->ep, PSM2_EP_DEVICE_FAILURE,
					"Couldn't set device pkey 0x%x: %s",
					(int)proto->ep->network_pkey,
					strerror(errno));
	}

	return err;
}

/* (Re)load the SL2VL table */
psm2_error_t ips_ibta_init_sl2sc2vl_table(struct ips_proto *proto)
{
	int ret, i;

	/* Get SL2SC table for unit, port */
	for (i = 0; i < 32; i++) {
		if ((ret =
		     hfi_get_port_sl2sc(proto->ep->context.ctrl->__hfi_unit,
					proto->ep->context.ctrl->__hfi_port,
					(uint8_t) i)) < 0) {
			/* Unable to get SL2SC. Set it to default */
			ret = PSMI_SC_DEFAULT;
		}

		proto->sl2sc[i] = (uint16_t) ret;
	}
	/* Get SC2VL table for unit, port */
	for (i = 0; i < 32; i++) {
		if ((ret =
		     hfi_get_port_sc2vl(proto->ep->context.ctrl->__hfi_unit,
					proto->ep->context.ctrl->__hfi_port,
					(uint8_t) i)) < 0) {
			/* Unable to get SC2VL. Set it to default */
			ret = PSMI_VL_DEFAULT;
		}

		proto->sc2vl[i] = (uint16_t) ret;
	}

	return PSM2_OK;
}

/* On link up/down we need to update some state */
psm2_error_t ips_ibta_link_updown_event(struct ips_proto *proto)
{
	psm2_error_t err = PSM2_OK;
	int ret;

	/* Get base lid, lmc and rate as these may have changed if the link bounced */
	proto->epinfo.ep_base_lid =
	    __cpu_to_be16((uint16_t) psm2_epid_nid(proto->ep->context.epid));

	if ((ret = hfi_get_port_lmc(proto->ep->context.ctrl->__hfi_unit,
				    proto->ep->context.ctrl->__hfi_port)) < 0) {
		err = psmi_handle_error(proto->ep, PSM2_EP_DEVICE_FAILURE,
					"Could obtain LMC for unit %u:%u. Error: %s",
					proto->ep->context.ctrl->__hfi_unit,
					proto->ep->context.ctrl->__hfi_port,
					strerror(errno));
		goto fail;
	}
	proto->epinfo.ep_lmc = min(ret, IPS_MAX_PATH_LMC);

	if ((ret = hfi_get_port_rate(proto->ep->context.ctrl->__hfi_unit,
				     proto->ep->context.ctrl->__hfi_port)) <
	    0) {
		err =
		    psmi_handle_error(proto->ep, PSM2_EP_DEVICE_FAILURE,
				      "Could obtain link rate for unit %u:%u. Error: %s",
				      proto->ep->context.ctrl->__hfi_unit,
				      proto->ep->context.ctrl->__hfi_port,
				      strerror(errno));
		goto fail;
	}
	proto->epinfo.ep_link_rate = ips_rate_to_enum(ret);

	/* Load the SL2SC2VL table */
	ips_ibta_init_sl2sc2vl_table(proto);

	/* Regenerate new IPD table for the updated link rate. */
	ips_gen_ipd_table(proto);

	/* Generate the CCT table.  */
	err = ips_gen_cct_table(proto);

fail:
	return err;
}

psm2_error_t ips_ibta_init(struct ips_proto *proto)
{
	psm2_error_t err = PSM2_OK;
	union psmi_envvar_val psm_path_policy;
	union psmi_envvar_val disable_cca;
	union psmi_envvar_val cca_prescan;

	/* Get the path selection policy */
	psmi_getenv("PSM2_PATH_SELECTION",
		    "Policy to use if multiple paths are available between endpoints. Options are adaptive, static_src, static_dest, static_base. Default is adaptive.",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
		    (union psmi_envvar_val)"adaptive", &psm_path_policy);

	if (!strcasecmp((const char *)psm_path_policy.e_str, "adaptive"))
		proto->flags |= IPS_PROTO_FLAG_PPOLICY_ADAPTIVE;
	else if (!strcasecmp((const char *)psm_path_policy.e_str, "static_src"))
		proto->flags |= IPS_PROTO_FLAG_PPOLICY_STATIC_SRC;
	else if (!strcasecmp
		 ((const char *)psm_path_policy.e_str, "static_dest"))
		proto->flags |= IPS_PROTO_FLAG_PPOLICY_STATIC_DST;
	else if (!strcasecmp
		 ((const char *)psm_path_policy.e_str, "static_base"))
		proto->flags |= IPS_PROTO_FLAG_PPOLICY_STATIC_BASE;

	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE)
		_HFI_PRDBG("Using adaptive path selection.\n");
	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_SRC)
		_HFI_PRDBG("Static path selection: Src Context\n");
	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_DST)
		_HFI_PRDBG("Static path selection: Dest Context\n");
	if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_BASE)
		_HFI_PRDBG("Static path selection: Base LID\n");

	psmi_getenv("PSM2_DISABLE_CCA",
		    "Disable use of Congestion Control Architecure (CCA) [enabled] ",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)0, &disable_cca);
	if (disable_cca.e_uint)
		_HFI_CCADBG("CCA is disabled for congestion control.\n");
	else {
		int i;
		char ccabuf[256];
		uint8_t *p;

		proto->flags |= IPS_PROTO_FLAG_CCA;
/*
 * If user set any environment variable, use self CCA.
 */
		if (getenv("PSM2_CCTI_INCREMENT") || getenv("PSM2_CCTI_TIMER")
		    || getenv("PSM2_CCTI_TABLE_SIZE")) {
			goto disablecca;
		}

		psmi_getenv("PSM2_CCA_PRESCAN",
                    "Enable Congestion Control Prescanning (disabled by default) ",
                    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
                    (union psmi_envvar_val)0, &cca_prescan);

		if (cca_prescan.e_uint)
			proto->flags |= IPS_PROTO_FLAG_CCA_PRESCAN;

/*
 * Check qib driver CCA setting, and try to use it if available.
 * Fall to self CCA setting if errors.
 */
		i = hfi_get_cc_settings_bin(proto->ep->context.ctrl->__hfi_unit,
					    proto->ep->context.ctrl->__hfi_port,
					    ccabuf);
		if (i <= 0) {
			goto disablecca;
		}
		p = (uint8_t *) ccabuf;
		memcpy(&proto->ccti_ctrlmap, p, 4);
		p += 4;
		memcpy(&proto->ccti_portctrl, p, 2);
		p += 2;
		for (i = 0; i < 32; i++) {
			proto->cace[i].ccti_increase = *p;
			p++;
			/* skip reserved u8 */
			p++;
			memcpy(&proto->cace[i].ccti_timer_cycles, p, 2);
			p += 2;
			proto->cace[i].ccti_timer_cycles =
			    us_2_cycles(proto->cace[i].ccti_timer_cycles);
			proto->cace[i].ccti_threshold = *p;
			p++;
			proto->cace[i].ccti_min = *p;
			p++;
		}

		i = hfi_get_cc_table_bin(proto->ep->context.ctrl->__hfi_unit,
					 proto->ep->context.ctrl->__hfi_port,
					 &proto->cct);
		if (i < 0) {
			err = PSM2_NO_MEMORY;
			goto fail;
		} else if (i == 0) {
			goto disablecca;
		}
		proto->ccti_limit = i;
		proto->ccti_size = proto->ccti_limit + 1;
		goto finishcca;

/*
 * Disable CCA.
 */
disablecca:
		proto->flags &= ~IPS_PROTO_FLAG_CCA;
		proto->flags &= ~IPS_PROTO_FLAG_CCA_PRESCAN;
	}

finishcca:
	/* Seed the random number generator with our pid */
	srand(getpid());

	/* Initialize path record/group hash table */
	hcreate_r(DF_PATH_REC_HASH_SIZE, &proto->ips_path_rec_hash);
	hcreate_r(DF_PATH_GRP_HASH_SIZE, &proto->ips_path_grp_hash);

	/* On startup treat it as a link up/down event to setup state . */
	if ((err = ips_ibta_link_updown_event(proto)) != PSM2_OK)
		goto fail;

	/* Setup the appropriate query interface for the endpoint */
	switch (proto->ep->path_res_type) {
	case PSM2_PATH_RES_OPP:
		err = ips_opp_init(proto);
		if (err != PSM2_OK)
			_HFI_ERROR
			    ("Unable to use OFED Plus Plus for path record queries.\n");
		break;
	case PSM2_PATH_RES_UMAD:
		_HFI_ERROR
		    ("Path record queries using UMAD is not supported in PSM version %d.%dx\n",
		     PSM2_VERNO_MAJOR, PSM2_VERNO_MINOR);
		err = PSM2_EPID_PATH_RESOLUTION;
		break;
	case PSM2_PATH_RES_NONE:
	default:
		err = ips_none_path_rec_init(proto);
	}

fail:
	return err;
}

psm2_error_t ips_ibta_fini(struct ips_proto *proto)
{
	psm2_error_t err = PSM2_OK;

	if (proto->ibta.fini)
		err = proto->ibta.fini(proto);

	/* Destroy the path record/group hash */
	hdestroy_r(&proto->ips_path_rec_hash);
	hdestroy_r(&proto->ips_path_grp_hash);

	return err;
}
