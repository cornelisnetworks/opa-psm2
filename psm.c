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

#include <dlfcn.h>
#include "psm_user.h"

static int psmi_verno_major = PSM2_VERNO_MAJOR;
static int psmi_verno_minor = PSM2_VERNO_MINOR;
static int psmi_verno = PSMI_VERNO_MAKE(PSM2_VERNO_MAJOR, PSM2_VERNO_MINOR);
static int psmi_verno_client_val;

#define PSMI_NOT_INITIALIZED    0
#define PSMI_INITIALIZED        1
#define PSMI_FINALIZED         -1	/* Prevent the user from calling psm2_init
					 * once psm_finalize has been called. */
static int psmi_isinit = PSMI_NOT_INITIALIZED;

int psmi_verno_client()
{
	return psmi_verno_client_val;
}

#ifdef PSMI_PLOCK_IS_SPINLOCK
psmi_spinlock_t psmi_progress_lock;
#elif defined(PSMI_PLOCK_IS_MUTEXLOCK)
pthread_mutex_t psmi_progress_lock = PTHREAD_MUTEX_INITIALIZER;
#elif defined(PSMI_PLOCK_IS_MUTEXLOCK_DEBUG)
pthread_mutex_t psmi_progress_lock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
pthread_t psmi_progress_lock_owner = PSMI_PLOCK_NO_OWNER;
#endif

/* This function is used to determine whether the current library build can
 * successfully communicate with another library that claims to be version
 * 'verno'.
 *
 * PSM 2.x is always ABI compatible, but this checks to see if two different
 * versions of the library can coexist.
 */
int psmi_verno_isinteroperable(uint16_t verno)
{
	if (PSMI_VERNO_GET_MAJOR(verno) != PSM2_VERNO_MAJOR)
		return 0;

	return 1;
}

int psmi_isinitialized()
{
	return (psmi_isinit == PSMI_INITIALIZED);
}

extern char psmi_hfi_revision[];

psm2_error_t __psm2_init(int *major, int *minor)
{
	psm2_error_t err = PSM2_OK;
	union psmi_envvar_val env_tmask;

	PSM2_LOG_MSG("entering");
	if (psmi_isinit == PSMI_INITIALIZED)
		goto update;

	if (psmi_isinit == PSMI_FINALIZED) {
		err = PSM2_IS_FINALIZED;
		goto fail;
	}

	if (major == NULL || minor == NULL) {
		err = PSM2_PARAM_ERR;
		goto fail;
	}
#ifdef PSM_DEBUG
	if (!getenv("PSM2_NO_WARN"))
		fprintf(stderr,
			"!!! WARNING !!! You are running an internal-only PSM *DEBUG* build.\n");
#endif

#ifdef PSM_PROFILE
	if (!getenv("PSM2_NO_WARN"))
		fprintf(stderr,
			"!!! WARNING !!! You are running an internal-only PSM *PROFILE* build.\n");
#endif

	/* Make sure we complain if fault injection is enabled */
	if (getenv("PSM2_FI") && !getenv("PSM2_NO_WARN"))
		fprintf(stderr,
			"!!! WARNING !!! You are running with fault injection enabled!\n");

	/* Make sure, as an internal check, that this version knows how to detect
	 * cmopatibility with other library versions it may communicate with */
	if (psmi_verno_isinteroperable(psmi_verno) != 1) {
		err = psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
					"psmi_verno_isinteroperable() not updated for current version!");
		goto fail;
	}

	/* The only way to not support a client is if the major number doesn't
	 * match */
	if (*major != PSM2_VERNO_MAJOR && *major != PSM2_VERNO_COMPAT_MAJOR) {
		err = psmi_handle_error(NULL, PSM2_INIT_BAD_API_VERSION,
					"This library does not implement version %d.%d",
					*major, *minor);
		goto fail;
	}

	/* Make sure we don't keep track of a client that claims a higher version
	 * number than we are */
	psmi_verno_client_val =
	    min(PSMI_VERNO_MAKE(*major, *minor), psmi_verno);

	psmi_isinit = PSMI_INITIALIZED;
	/* hfi_debug lives in libhfi.so */
	psmi_getenv("PSM2_TRACEMASK",
		    "Mask flags for tracing",
		    PSMI_ENVVAR_LEVEL_USER,
		    PSMI_ENVVAR_TYPE_ULONG_FLAGS,
		    (union psmi_envvar_val)hfi_debug, &env_tmask);
	hfi_debug = (long)env_tmask.e_ulong;

	/* The "real thing" is done in hfi_proto.c as a constructor function, but
	 * we getenv it here to report what we're doing with the setting */
	{
		extern int __hfi_malloc_no_mmap;
		union psmi_envvar_val env_mmap;
		char *env = getenv("HFI_DISABLE_MMAP_MALLOC");
		int broken = (env && *env && !__hfi_malloc_no_mmap);
		psmi_getenv("HFI_DISABLE_MMAP_MALLOC",
			    broken ? "Skipping mmap disable for malloc()" :
			    "Disable mmap for malloc()",
			    PSMI_ENVVAR_LEVEL_USER,
			    PSMI_ENVVAR_TYPE_YESNO,
			    (union psmi_envvar_val)0, &env_mmap);
		if (broken)
			_HFI_ERROR
			    ("Couldn't successfully disable mmap in mallocs "
			     "with mallopt()\n");
	}

	if (getenv("PSM2_IDENTIFY")) {
		Dl_info info_psm, info_hfi;
		_HFI_INFO("PSM2: %s version: %d.%d, from %s:%s\n", psmi_hfi_revision,
			  PSM2_VERNO_MAJOR,PSM2_VERNO_MINOR,
			  dladdr(psm2_init, &info_psm) ? info_psm.dli_fname :
			  "libpsm2 not available",
			  dladdr(hfi_userinit, &info_hfi) ? info_hfi.dli_fname :
			  "libhfi not available");
	}
#ifdef PSMI_PLOCK_IS_SPINLOCK
	psmi_spin_init(&psmi_progress_lock);
#endif

	if (getenv("PSM2_DIAGS")) {
		_HFI_INFO("Running diags...\n");
		psmi_diags();
	}

	psmi_faultinj_init();

	/* Initialize the unexpected system buffer allocator */
	err = psmi_sysbuf_init();
	if (err != PSM2_OK)
		goto fail;

	psmi_epid_init();

update:
	*major = (int)psmi_verno_major;
	*minor = (int)psmi_verno_minor;
fail:
	PSM2_LOG_MSG("leaving");
	return err;
}
PSMI_API_DECL(psm2_init)

psm2_error_t __psm2_finalize(void)
{
	struct psmi_eptab_iterator itor;
	char *hostname;
	psm2_ep_t ep;
	extern psm2_ep_t psmi_opened_endpoint;	/* in psm_endpoint.c */

	PSM2_LOG_MSG("entering");

	PSMI_ERR_UNLESS_INITIALIZED(NULL);

	ep = psmi_opened_endpoint;
	while (ep != NULL) {
		psmi_opened_endpoint = ep->user_ep_next;
		psm2_ep_close(ep, PSM2_EP_CLOSE_GRACEFUL,
			     2 * PSMI_MIN_EP_CLOSE_TIMEOUT);
		ep = psmi_opened_endpoint;
	}

	psmi_epid_fini();

	psmi_faultinj_fini();

	/* De-allocate memory for any allocated space to store hostnames */
	psmi_epid_itor_init(&itor, PSMI_EP_HOSTNAME);
	while ((hostname = psmi_epid_itor_next(&itor)))
		psmi_free(hostname);
	psmi_epid_itor_fini(&itor);

	char buf[128];
	psmi_sysbuf_getinfo(buf, sizeof(buf));
	_HFI_VDBG("%s", buf);
	psmi_sysbuf_fini();

	psmi_isinit = PSMI_FINALIZED;
	PSM2_LOG_MSG("leaving");
	return PSM2_OK;
}
PSMI_API_DECL(psm2_finalize)

/*
 * Function exposed in >= 1.05
 */
psm2_error_t
__psm2_map_nid_hostname(int num, const uint64_t *nids, const char **hostnames)
{
	int i;
	psm2_error_t err = PSM2_OK;

	PSM2_LOG_MSG("entering");

	PSMI_ERR_UNLESS_INITIALIZED(NULL);

	PSMI_PLOCK();

	if (nids == NULL || hostnames == NULL) {
		err = PSM2_PARAM_ERR;
		goto fail;
	}

	for (i = 0; i < num; i++) {
		if ((err = psmi_epid_set_hostname(nids[i], hostnames[i], 1)))
			break;
	}

fail:
	PSMI_PUNLOCK();
	PSM2_LOG_MSG("leaving");
	return err;
}
PSMI_API_DECL(psm2_map_nid_hostname)

void __psm2_epaddr_setlabel(psm2_epaddr_t epaddr, char const *epaddr_label)
{
	PSM2_LOG_MSG("entering");
	PSM2_LOG_MSG("leaving");
	return;			/* ignore this function */
}
PSMI_API_DECL(psm2_epaddr_setlabel)

void __psm2_epaddr_setctxt(psm2_epaddr_t epaddr, void *ctxt)
{

	/* Eventually deprecate this API to use set/get opt as this is unsafe. */
	PSM2_LOG_MSG("entering");
	psm2_setopt(PSM2_COMPONENT_CORE, (const void *)epaddr,
		   PSM2_CORE_OPT_EP_CTXT, (const void *)ctxt, sizeof(void *));
	PSM2_LOG_MSG("leaving");
}
PSMI_API_DECL(psm2_epaddr_setctxt)

void *__psm2_epaddr_getctxt(psm2_epaddr_t epaddr)
{
	psm2_error_t err;
	uint64_t optlen = sizeof(void *);
	void *result = NULL;

	PSM2_LOG_MSG("entering");
	/* Evetually deprecate this API to use set/get opt as this is unsafe. */
	err = psm2_getopt(PSM2_COMPONENT_CORE, (const void *)epaddr,
			 PSM2_CORE_OPT_EP_CTXT, (void *)&result, &optlen);

	PSM2_LOG_MSG("leaving");

	if (err == PSM2_OK)
		return result;
	else
		return NULL;
}
PSMI_API_DECL(psm2_epaddr_getctxt)

psm2_error_t
__psm2_setopt(psm2_component_t component, const void *component_obj,
	     int optname, const void *optval, uint64_t optlen)
{
	psm2_error_t rv;
	PSM2_LOG_MSG("entering");
	switch (component) {
	case PSM2_COMPONENT_CORE:
		rv = psmi_core_setopt(component_obj, optname, optval, optlen);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	case PSM2_COMPONENT_MQ:
		/* Use the deprecated MQ set/get opt for now which does not use optlen */
		rv = psm2_mq_setopt((psm2_mq_t) component_obj, optname, optval);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	case PSM2_COMPONENT_AM:
		/* Hand off to active messages */
		rv = psmi_am_setopt(component_obj, optname, optval, optlen);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	case PSM2_COMPONENT_IB:
		/* Hand off to IPS ptl to set option */
		rv = psmi_ptl_ips.setopt(component_obj, optname, optval,
					   optlen);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	}

	/* Unrecognized/unknown component */
	rv = psmi_handle_error(NULL, PSM2_PARAM_ERR, "Unknown component %u",
				 component);
	PSM2_LOG_MSG("leaving");
	return rv;
}
PSMI_API_DECL(psm2_setopt);

psm2_error_t
__psm2_getopt(psm2_component_t component, const void *component_obj,
	     int optname, void *optval, uint64_t *optlen)
{
	psm2_error_t rv;

	PSM2_LOG_MSG("entering");
	switch (component) {
	case PSM2_COMPONENT_CORE:
		rv = psmi_core_getopt(component_obj, optname, optval, optlen);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	case PSM2_COMPONENT_MQ:
		/* Use the deprecated MQ set/get opt for now which does not use optlen */
		rv = psm2_mq_getopt((psm2_mq_t) component_obj, optname, optval);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	case PSM2_COMPONENT_AM:
		/* Hand off to active messages */
		rv = psmi_am_getopt(component_obj, optname, optval, optlen);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	case PSM2_COMPONENT_IB:
		/* Hand off to IPS ptl to set option */
		rv = psmi_ptl_ips.getopt(component_obj, optname, optval,
					   optlen);
		PSM2_LOG_MSG("leaving");
		return rv;
		break;
	}

	/* Unrecognized/unknown component */
	rv = psmi_handle_error(NULL, PSM2_PARAM_ERR, "Unknown component %u",
				 component);
	PSM2_LOG_MSG("leaving");
	return rv;
}
PSMI_API_DECL(psm2_getopt);

psm2_error_t __psmi_poll_noop(ptl_t *ptl, int replyonly)
{
	PSM2_LOG_MSG("entering");
	PSM2_LOG_MSG("leaving");
	return PSM2_OK_NO_PROGRESS;
}
PSMI_API_DECL(psmi_poll_noop)

psm2_error_t __psm2_poll(psm2_ep_t ep)
{
	psm2_error_t err1 = PSM2_OK, err2 = PSM2_OK;
	psm2_ep_t tmp;

	PSM2_LOG_MSG("entering");

	PSMI_ASSERT_INITIALIZED();

	PSMI_PLOCK();

	tmp = ep;
	do {
		err1 = ep->ptl_amsh.ep_poll(ep->ptl_amsh.ptl, 0);	/* poll reqs & reps */
		if (err1 > PSM2_OK_NO_PROGRESS) {	/* some error unrelated to polling */
			PSMI_PUNLOCK();
			PSM2_LOG_MSG("leaving");
			return err1;
		}

		err2 = ep->ptl_ips.ep_poll(ep->ptl_ips.ptl, 0);	/* get into ips_do_work */
		if (err2 > PSM2_OK_NO_PROGRESS) {	/* some error unrelated to polling */
			PSMI_PUNLOCK();
			PSM2_LOG_MSG("leaving");
			return err2;
		}
		ep = ep->mctxt_next;
	} while (ep != tmp);

	/* This is valid because..
	 * PSM2_OK & PSM2_OK_NO_PROGRESS => PSM2_OK
	 * PSM2_OK & PSM2_OK => PSM2_OK
	 * PSM2_OK_NO_PROGRESS & PSM2_OK => PSM2_OK
	 * PSM2_OK_NO_PROGRESS & PSM2_OK_NO_PROGRESS => PSM2_OK_NO_PROGRESS */
	PSMI_PUNLOCK();
	PSM2_LOG_MSG("leaving");
	return (err1 & err2);
}
PSMI_API_DECL(psm2_poll)

psm2_error_t __psmi_poll_internal(psm2_ep_t ep, int poll_amsh)
{
	psm2_error_t err1 = PSM2_OK_NO_PROGRESS;
	psm2_error_t err2;
	psm2_ep_t tmp;

	PSM2_LOG_MSG("entering");
	PSMI_PLOCK_ASSERT();

	tmp = ep;
	do {
		if (poll_amsh) {
			err1 = ep->ptl_amsh.ep_poll(ep->ptl_amsh.ptl, 0);	/* poll reqs & reps */
			if (err1 > PSM2_OK_NO_PROGRESS) { /* some error unrelated to polling */
				PSM2_LOG_MSG("leaving");
				return err1;
			}
		}

		err2 = ep->ptl_ips.ep_poll(ep->ptl_ips.ptl, 0);	/* get into ips_do_work */
		if (err2 > PSM2_OK_NO_PROGRESS) { /* some error unrelated to polling */
			PSM2_LOG_MSG("leaving");
			return err2;
		}

		ep = ep->mctxt_next;
	} while (ep != tmp);
	PSM2_LOG_MSG("leaving");
	return (err1 & err2);
}
PSMI_API_DECL(psmi_poll_internal)
#ifdef PSM_PROFILE
/* These functions each have weak symbols */
void psmi_profile_block()
{
	;			/* empty for profiler */
}

void psmi_profile_unblock()
{
	;			/* empty for profiler */
}

void psmi_profile_reblock(int did_no_progress)
{
	;			/* empty for profiler */
}
#endif
