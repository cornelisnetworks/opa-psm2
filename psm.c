/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2016 Intel Corporation.

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

  Copyright(c) 2016 Intel Corporation.

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

/* Copyright (c) 2003-2016 Intel Corporation. All rights reserved. */

#include <dlfcn.h>
#include "psm_user.h"
#include "opa_revision.h"
#include "opa_udebug.h"
#include "psm_mq_internal.h"

static int psmi_verno_major = PSM2_VERNO_MAJOR;
static int psmi_verno_minor = PSM2_VERNO_MINOR;
static int psmi_verno = PSMI_VERNO_MAKE(PSM2_VERNO_MAJOR, PSM2_VERNO_MINOR);
static int psmi_verno_client_val;
int psmi_epid_ver;

#define PSMI_NOT_INITIALIZED    0
#define PSMI_INITIALIZED        1
#define PSMI_FINALIZED         -1	/* Prevent the user from calling psm2_init
					 * once psm_finalize has been called. */
static int psmi_isinit = PSMI_NOT_INITIALIZED;

/* Global lock used for endpoint creation and destroy
 * (in functions psm2_ep_open and psm2_ep_close) and also
 * for synchronization with recv_thread (so that recv_thread
 * will not work on an endpoint which is in a middle of closing). */
psmi_lock_t psmi_creation_lock;

#ifdef PSM_CUDA
int is_cuda_enabled;
int device_support_gpudirect;
int cuda_runtime_version;
int is_driver_gpudirect_enabled;
#endif

/*
 * Bit field that contains capability set.
 * Each bit represents different capability.
 * It is supposed to be filled with logical OR
 * on conditional compilation basis
 * along with future features/capabilities.
 * At the very beginning we start with Multi EPs.
 */
uint64_t psm2_capabilities_bitset = PSM2_MULTI_EP_CAP;

int psmi_verno_client()
{
	return psmi_verno_client_val;
}

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

int MOCKABLE(psmi_isinitialized)()
{
	return (psmi_isinit == PSMI_INITIALIZED);
}
MOCK_DEF_EPILOGUE(psmi_isinitialized);

#ifdef PSM_CUDA
int psmi_cuda_initialize()
{
	psm2_error_t err = PSM2_OK;
	int num_devices, dev;
	struct cudaDeviceProp dev_prop;
	char *dlerr;

	PSM2_LOG_MSG("entering");
	_HFI_VDBG("Enabling CUDA support.\n");

	psmi_cuda_lib = dlopen("libcuda.so", RTLD_LAZY);
	psmi_cudart_lib = dlopen("libcudart.so", RTLD_LAZY);
	if (!psmi_cuda_lib || !psmi_cudart_lib) {
		dlerr = dlerror();
		_HFI_ERROR("Unable to open libcuda.so and libcudart.so.  Error %s\n",
			   dlerr ? dlerr : "no dlerror()");
		goto fail;
	}

	psmi_cudaRuntimeGetVersion = dlsym(psmi_cudart_lib, "cudaRuntimeGetVersion");

	if (!psmi_cudaRuntimeGetVersion) {
		_HFI_ERROR
			("Unable to resolve symbols in CUDA libraries.\n");
		goto fail;
	}

	PSMI_CUDA_CALL(cudaRuntimeGetVersion, &cuda_runtime_version);
	if (cuda_runtime_version < 4010) {
		_HFI_ERROR("Please update CUDA runtime, required minimum version is 4.1 \n");
		goto fail;
	}


	psmi_cuCtxGetCurrent = dlsym(psmi_cuda_lib, "cuCtxGetCurrent");
	psmi_cuCtxSetCurrent = dlsym(psmi_cuda_lib, "cuCtxSetCurrent");
	psmi_cuPointerGetAttribute = dlsym(psmi_cuda_lib, "cuPointerGetAttribute");
	psmi_cuPointerSetAttribute = dlsym(psmi_cuda_lib, "cuPointerSetAttribute");

	psmi_cudaGetDeviceCount = dlsym(psmi_cudart_lib, "cudaGetDeviceCount");
	psmi_cudaGetDeviceProperties = dlsym(psmi_cudart_lib, "cudaGetDeviceProperties");
	psmi_cudaGetDevice = dlsym(psmi_cudart_lib, "cudaGetDevice");
	psmi_cudaSetDevice = dlsym(psmi_cudart_lib, "cudaSetDevice");
	psmi_cudaStreamCreate = dlsym(psmi_cudart_lib, "cudaStreamCreate");
	psmi_cudaDeviceSynchronize = dlsym(psmi_cudart_lib, "cudaDeviceSynchronize");
	psmi_cudaStreamSynchronize = dlsym(psmi_cudart_lib, "cudaStreamSynchronize");
	psmi_cudaEventCreate = dlsym(psmi_cudart_lib, "cudaEventCreate");
	psmi_cudaEventDestroy = dlsym(psmi_cudart_lib, "cudaEventDestroy");
	psmi_cudaEventQuery = dlsym(psmi_cudart_lib, "cudaEventQuery");
	psmi_cudaEventRecord = dlsym(psmi_cudart_lib, "cudaEventRecord");
	psmi_cudaEventSynchronize = dlsym(psmi_cudart_lib, "cudaEventSynchronize");
	psmi_cudaMalloc = dlsym(psmi_cudart_lib, "cudaMalloc");
	psmi_cudaHostAlloc = dlsym(psmi_cudart_lib, "cudaHostAlloc");
	psmi_cudaFreeHost = dlsym(psmi_cudart_lib, "cudaFreeHost");
	psmi_cudaMemcpy = dlsym(psmi_cudart_lib, "cudaMemcpy");
	psmi_cudaMemcpyAsync = dlsym(psmi_cudart_lib, "cudaMemcpyAsync");

	psmi_cudaIpcGetMemHandle = dlsym(psmi_cudart_lib, "cudaIpcGetMemHandle");
	psmi_cudaIpcOpenMemHandle = dlsym(psmi_cudart_lib, "cudaIpcOpenMemHandle");
	psmi_cudaIpcCloseMemHandle = dlsym(psmi_cudart_lib, "cudaIpcCloseMemHandle");

	if (!psmi_cuCtxGetCurrent || !psmi_cuCtxSetCurrent ||
	    !psmi_cuPointerGetAttribute || !psmi_cuPointerSetAttribute ||
	    !psmi_cudaGetDeviceCount || !psmi_cudaGetDeviceProperties ||
	    !psmi_cudaGetDevice || !psmi_cudaSetDevice ||
	    !psmi_cudaStreamCreate ||
	    !psmi_cudaDeviceSynchronize || !psmi_cudaStreamSynchronize ||
	    !psmi_cudaEventCreate || !psmi_cudaEventDestroy ||
	    !psmi_cudaEventQuery || !psmi_cudaEventRecord ||
	    !psmi_cudaEventSynchronize ||
	    !psmi_cudaMalloc || !psmi_cudaHostAlloc || !psmi_cudaFreeHost ||
	    !psmi_cudaMemcpy || !psmi_cudaMemcpyAsync || !psmi_cudaIpcGetMemHandle ||
	    !psmi_cudaIpcOpenMemHandle || !psmi_cudaIpcCloseMemHandle) {
		_HFI_ERROR
			("Unable to resolve symbols in CUDA libraries.\n");
		goto fail;
	}

	if (cuda_runtime_version > 7000) {
		psmi_cudaStreamCreateWithFlags = dlsym(psmi_cudart_lib,
						       "cudaStreamCreateWithFlags");
		if (!psmi_cudaStreamCreateWithFlags) {
			_HFI_ERROR
				("Unable to resolve symbols in CUDA libraries.\n");
			goto fail;
		}
	}

	/* Check if all devices support Unified Virtual Addressing. */
	PSMI_CUDA_CALL(cudaGetDeviceCount, &num_devices);
	for (dev = 0; dev < num_devices; dev++) {
		PSMI_CUDA_CALL(cudaGetDeviceProperties, &dev_prop, dev);
		if (dev_prop.unifiedAddressing != 1) {
			_HFI_ERROR("CUDA device %d does not support Unified Virtual Addressing.\n", dev);
			goto fail;
		}
		/* Only devices based on Kepler and
		 * above can support GPU Direct.
		 */
		if (dev_prop.major >= 3 && cuda_runtime_version >= 5000)
			device_support_gpudirect = 1;
		else {
			device_support_gpudirect = 0;
			_HFI_INFO("Device %d does not GPUDirect RDMA (Non-fatal error) \n", dev);
		}
	}
	PSM2_LOG_MSG("leaving");
	return err;
fail:
	err = psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR, "Unable to initialize PSM2 CUDA support.\n");
	return err;
}
#endif

psm2_error_t __psm2_init(int *major, int *minor)
{
	psm2_error_t err = PSM2_OK;
	union psmi_envvar_val env_tmask;

	psmi_log_initialize();

	PSM2_LOG_MSG("entering");
#ifdef RDPMC_PERF_FRAMEWORK
	psmi_rdpmc_perf_framework_init();
#endif /* RDPMC_PERF_FRAMEWORK */

	GENERIC_PERF_INIT();

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

	psmi_init_lock(&psmi_creation_lock);

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
	 * compatibility with other library versions it may communicate with */
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

	/* Check to see if we need to set Architecture flags to something
	 * besides big core Xeons */
	cpuid_t id;
	psmi_cpu_model = CPUID_MODEL_UNDEFINED;

	/* First check to ensure Genuine Intel */
	get_cpuid(0x0, 0, &id);
	if(id.ebx == CPUID_GENUINE_INTEL_EBX
		&& id.ecx == CPUID_GENUINE_INTEL_ECX
		&& id.edx == CPUID_GENUINE_INTEL_EDX)
	{
		/* Use cpuid with EAX=1 to get processor info */
		get_cpuid(0x1, 0, &id);
		psmi_cpu_model = CPUID_GENUINE_INTEL;
	}

	if( (psmi_cpu_model == CPUID_GENUINE_INTEL) &&
		(id.eax & CPUID_FAMILY_MASK) == CPUID_FAMILY_XEON)
	{
		psmi_cpu_model = ((id.eax & CPUID_MODEL_MASK) >> 4) |
				((id.eax & CPUID_EXMODEL_MASK) >> 12);
	}

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

	{
		union psmi_envvar_val env_epid_ver;
		psmi_getenv("PSM2_ADDR_FMT",
					"Used to force PSM2 to use a particular version of EPID",
					PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
					(union psmi_envvar_val)PSMI_EPID_VERNO_DEFAULT, &env_epid_ver);
		psmi_epid_ver = env_epid_ver.e_int;
		if (psmi_epid_ver > PSMI_MAX_EPID_VERNO_SUPPORTED) {
			psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
					  " The max epid version supported in this version of PSM2 is %d \n"
					  "Please upgrade PSM2 \n",
					  PSMI_MAX_EPID_VERNO_SUPPORTED);
			goto fail;
		} else if (psmi_epid_ver < PSMI_MIN_EPID_VERNO_SUPPORTED) {
			psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR,
					  " Invalid value provided through PSM2_ADDR_FMT \n");
			goto fail;
		}
	}

#ifdef PSM_CUDA
	union psmi_envvar_val env_enable_cuda;
	psmi_getenv("PSM2_CUDA",
		    "Enable (set envvar to 1) for cuda support in PSM (Disabled by default)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val)0, &env_enable_cuda);
	is_cuda_enabled = env_enable_cuda.e_int;
#endif

	if (getenv("PSM2_IDENTIFY")) {
                Dl_info info_psm;
		char ofed_delta[100] = "";
		strcat(strcat(ofed_delta," built for OFED DELTA "),psmi_hfi_IFS_version);
                printf("%s %s PSM2 v%d.%d%s\n"
		       "%s %s location %s\n"
		       "%s %s build date %s\n"
		       "%s %s src checksum %s\n"
                       "%s %s git checksum %s\n"
                       "%s %s built against driver interface v%d.%d\n",
			  hfi_get_mylabel(), hfi_ident_tag,
					     PSM2_VERNO_MAJOR,PSM2_VERNO_MINOR,
					     (strcmp(psmi_hfi_IFS_version,"") != 0) ? ofed_delta
#ifdef PSM_CUDA
						: "-cuda",
#else
						: "",
#endif
                          hfi_get_mylabel(), hfi_ident_tag, dladdr(psm2_init, &info_psm) ?
					     info_psm.dli_fname : "libpsm2 not available",
                          hfi_get_mylabel(), hfi_ident_tag, psmi_hfi_build_timestamp,
                          hfi_get_mylabel(), hfi_ident_tag, psmi_hfi_sources_checksum,
			  hfi_get_mylabel(), hfi_ident_tag,
					     (strcmp(psmi_hfi_git_checksum,"") != 0) ?
					     psmi_hfi_git_checksum : "<not available>",
			  hfi_get_mylabel(), hfi_ident_tag, HFI1_USER_SWMAJOR, HFI1_USER_SWMINOR);
	}

	if (getenv("PSM2_DIAGS")) {
		_HFI_INFO("Running diags...\n");
		psmi_diags();
	}

	psmi_multi_ep_init();

	psmi_faultinj_init();

	psmi_epid_init();

#ifdef PSM_CUDA
	if (PSMI_IS_CUDA_ENABLED) {
		err = psmi_cuda_initialize();
		if (err != PSM2_OK)
			goto fail;
	}
#endif

update:
	*major = (int)psmi_verno_major;
	*minor = (int)psmi_verno_minor;
fail:
	PSM2_LOG_MSG("leaving");
	return err;
}
PSMI_API_DECL(psm2_init)


uint64_t __psm2_get_capability_mask(uint64_t req_cap_mask)
{
	return (psm2_capabilities_bitset & req_cap_mask);
}
PSMI_API_DECL(psm2_get_capability_mask)


psm2_error_t __psm2_finalize(void)
{
	struct psmi_eptab_iterator itor;
	char *hostname;
	psm2_ep_t ep;

	PSM2_LOG_MSG("entering");

	PSMI_ERR_UNLESS_INITIALIZED(NULL);

	GENERIC_PERF_DUMP(stderr);
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

	psmi_isinit = PSMI_FINALIZED;
	PSM2_LOG_MSG("leaving");
	psmi_log_fini();
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

	if (nids == NULL || hostnames == NULL) {
		err = PSM2_PARAM_ERR;
		goto fail;
	}

	for (i = 0; i < num; i++) {
		if ((err = psmi_epid_set_hostname(nids[i], hostnames[i], 1)))
			break;
	}

fail:
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
	/* Eventually deprecate this API to use set/get opt as this is unsafe. */
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

	PSMI_LOCK(ep->mq->progress_lock);

	tmp = ep;
	do {
		err1 = ep->ptl_amsh.ep_poll(ep->ptl_amsh.ptl, 0);	/* poll reqs & reps */
		if (err1 > PSM2_OK_NO_PROGRESS) {	/* some error unrelated to polling */
			PSMI_UNLOCK(ep->mq->progress_lock);
			PSM2_LOG_MSG("leaving");
			return err1;
		}

		err2 = ep->ptl_ips.ep_poll(ep->ptl_ips.ptl, 0);	/* get into ips_do_work */
		if (err2 > PSM2_OK_NO_PROGRESS) {	/* some error unrelated to polling */
			PSMI_UNLOCK(ep->mq->progress_lock);
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
	PSMI_UNLOCK(ep->mq->progress_lock);
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
	PSMI_LOCK_ASSERT(ep->mq->progress_lock);

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
