/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2021 Cornelis Networks.
  Copyright(c) 2016 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Cornelis Networks, www.cornelisnetworks.com

  BSD LICENSE

  Copyright(c) 2021 Cornelis Networks.
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
#include "psm2_hal.h"
#include "opa_revision.h"
#include "psm_mq_internal.h"

static int psmi_verno_major = PSM2_VERNO_MAJOR;
static int psmi_verno_minor = PSM2_VERNO_MINOR;
static int psmi_verno = PSMI_VERNO_MAKE(PSM2_VERNO_MAJOR, PSM2_VERNO_MINOR);
static int psmi_verno_client_val;
int psmi_epid_ver;

// Special psmi_refcount values
#define PSMI_NOT_INITIALIZED    0
#define PSMI_FINALIZED         -1

// PSM2 doesn't support transitioning out of the PSMI_FINALIZED state
// once psmi_refcount is set to PSMI_FINALIZED, any further attempts to change
// psmi_refcount should be treated as an error
static int psmi_refcount = PSMI_NOT_INITIALIZED;

/* Global lock used for endpoint creation and destroy
 * (in functions psm2_ep_open and psm2_ep_close) and also
 * for synchronization with recv_thread (so that recv_thread
 * will not work on an endpoint which is in a middle of closing). */
psmi_lock_t psmi_creation_lock;

sem_t *sem_affinity_shm_rw = NULL;
int psmi_affinity_shared_file_opened = 0;
int psmi_affinity_semaphore_open = 0;
uint64_t *shared_affinity_ptr;
char *sem_affinity_shm_rw_name;
char *affinity_shm_name;

uint32_t psmi_cpu_model;

#ifdef PSM_CUDA
int is_cuda_enabled;
int is_gdr_copy_enabled;
int _device_support_gpudirect = -1; // -1 indicates "unset". See device_support_gpudirect().
int _gpu_p2p_supported = -1; // -1 indicates "unset". see gpu_p2p_supported().
int my_gpu_device = 0;
int cuda_lib_version;
int is_driver_gpudirect_enabled;
int is_cuda_primary_context_retain = 0;
uint32_t cuda_thresh_rndv;
uint32_t gdr_copy_threshold_send;
uint32_t gdr_copy_threshold_recv;

void *psmi_cuda_lib;
CUresult (*psmi_cuInit)(unsigned int  Flags );
CUresult (*psmi_cuCtxDetach)(CUcontext c);
CUresult (*psmi_cuCtxGetCurrent)(CUcontext *c);
CUresult (*psmi_cuCtxSetCurrent)(CUcontext c);
CUresult (*psmi_cuPointerGetAttribute)(void *data, CUpointer_attribute pa, CUdeviceptr p);
CUresult (*psmi_cuPointerSetAttribute)(void *data, CUpointer_attribute pa, CUdeviceptr p);
CUresult (*psmi_cuDeviceCanAccessPeer)(int *canAccessPeer, CUdevice dev, CUdevice peerDev);
CUresult (*psmi_cuDeviceGet)(CUdevice* device, int  ordinal);
CUresult (*psmi_cuDeviceGetAttribute)(int* pi, CUdevice_attribute attrib, CUdevice dev);
CUresult (*psmi_cuDriverGetVersion)(int* driverVersion);
CUresult (*psmi_cuDeviceGetCount)(int* count);
CUresult (*psmi_cuStreamCreate)(CUstream* phStream, unsigned int Flags);
CUresult (*psmi_cuStreamDestroy)(CUstream phStream);
CUresult (*psmi_cuStreamSynchronize)(CUstream phStream);
CUresult (*psmi_cuEventCreate)(CUevent* phEvent, unsigned int Flags);
CUresult (*psmi_cuEventDestroy)(CUevent hEvent);
CUresult (*psmi_cuEventQuery)(CUevent hEvent);
CUresult (*psmi_cuEventRecord)(CUevent hEvent, CUstream hStream);
CUresult (*psmi_cuEventSynchronize)(CUevent hEvent);
CUresult (*psmi_cuMemHostAlloc)(void** pp, size_t bytesize, unsigned int Flags);
CUresult (*psmi_cuMemFreeHost)(void* p);
CUresult (*psmi_cuMemcpy)(CUdeviceptr dst, CUdeviceptr src, size_t ByteCount);
CUresult (*psmi_cuMemcpyDtoD)(CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount);
CUresult (*psmi_cuMemcpyDtoH)(void* dstHost, CUdeviceptr srcDevice, size_t ByteCount);
CUresult (*psmi_cuMemcpyHtoD)(CUdeviceptr dstDevice, const void* srcHost, size_t ByteCount);
CUresult (*psmi_cuMemcpyDtoHAsync)(void* dstHost, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
CUresult (*psmi_cuMemcpyHtoDAsync)(CUdeviceptr dstDevice, const void* srcHost, size_t ByteCount, CUstream hStream);
CUresult (*psmi_cuIpcGetMemHandle)(CUipcMemHandle* pHandle, CUdeviceptr dptr);
CUresult (*psmi_cuIpcOpenMemHandle)(CUdeviceptr* pdptr, CUipcMemHandle handle, unsigned int Flags);
CUresult (*psmi_cuIpcCloseMemHandle)(CUdeviceptr dptr);
CUresult (*psmi_cuMemGetAddressRange)(CUdeviceptr* pbase, size_t* psize, CUdeviceptr dptr);
CUresult (*psmi_cuDevicePrimaryCtxGetState)(CUdevice dev, unsigned int* flags, int* active);
CUresult (*psmi_cuDevicePrimaryCtxRetain)(CUcontext* pctx, CUdevice dev);
CUresult (*psmi_cuCtxGetDevice)(CUdevice* device);
CUresult (*psmi_cuDevicePrimaryCtxRelease)(CUdevice device);
#endif

/*
 * Bit field that contains capability set.
 * Each bit represents different capability.
 * It is supposed to be filled with logical OR
 * on conditional compilation basis
 * along with future features/capabilities.
 */
uint64_t psm2_capabilities_bitset = PSM2_MULTI_EP_CAP | PSM2_LIB_REFCOUNT_CAP;

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
	return (psmi_refcount > 0);
}
MOCK_DEF_EPILOGUE(psmi_isinitialized);

#ifdef PSM_CUDA
int psmi_cuda_lib_load()
{
	psm2_error_t err = PSM2_OK;
	char *dlerr;

	PSM2_LOG_MSG("entering");
	_HFI_VDBG("Loading CUDA library.\n");

	psmi_cuda_lib = dlopen("libcuda.so.1", RTLD_LAZY);
	if (!psmi_cuda_lib) {
		dlerr = dlerror();
		_HFI_ERROR("Unable to open libcuda.so.  Error %s\n",
				dlerr ? dlerr : "no dlerror()");
		goto fail;
	}

	psmi_cuDriverGetVersion = dlsym(psmi_cuda_lib, "cuDriverGetVersion");

	if (!psmi_cuDriverGetVersion) {
		_HFI_ERROR
			("Unable to resolve symbols in CUDA libraries.\n");
		goto fail;
	}

	PSMI_CUDA_CALL(cuDriverGetVersion, &cuda_lib_version);
	if (cuda_lib_version < 7000) {
		_HFI_ERROR("Please update CUDA driver, required minimum version is 7.0\n");
		goto fail;
	}

	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuInit);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuCtxGetCurrent);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuCtxDetach);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuCtxSetCurrent);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuPointerGetAttribute);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuPointerSetAttribute);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDeviceCanAccessPeer);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDeviceGetAttribute);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDeviceGet);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDeviceGetCount);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuStreamCreate);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuStreamDestroy);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuStreamSynchronize);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuEventCreate);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuEventDestroy);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuEventQuery);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuEventRecord);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuEventSynchronize);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemHostAlloc);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemFreeHost);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemcpy);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemcpyDtoD);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemcpyDtoH);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemcpyHtoD);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemcpyDtoHAsync);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemcpyHtoDAsync);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuIpcGetMemHandle);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuIpcOpenMemHandle);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuIpcCloseMemHandle);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuMemGetAddressRange);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDevicePrimaryCtxGetState);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDevicePrimaryCtxRetain);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuDevicePrimaryCtxRelease);
	PSMI_CUDA_DLSYM(psmi_cuda_lib, cuCtxGetDevice);

	PSM2_LOG_MSG("leaving");
	return err;
fail:
	if (psmi_cuda_lib)
		dlclose(psmi_cuda_lib);
	err = psmi_handle_error(PSMI_EP_NORETURN, PSM2_INTERNAL_ERR, "Unable to load CUDA library.\n");
	return err;
}

int psmi_cuda_initialize()
{
	psm2_error_t err = PSM2_OK;

	PSM2_LOG_MSG("entering");
	_HFI_VDBG("Enabling CUDA support.\n");

	err = psmi_cuda_lib_load();
	if (err != PSM2_OK)
		goto fail;

	PSMI_CUDA_CALL(cuInit, 0);

	union psmi_envvar_val env_enable_gdr_copy;
	psmi_getenv("PSM2_GDRCOPY",
				"Enable (set envvar to 1) for gdr copy support in PSM (Enabled by default)",
				PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
				(union psmi_envvar_val)1, &env_enable_gdr_copy);
	is_gdr_copy_enabled = env_enable_gdr_copy.e_int;

	union psmi_envvar_val env_cuda_thresh_rndv;
	psmi_getenv("PSM2_CUDA_THRESH_RNDV",
				"RNDV protocol is used for message sizes greater than the threshold \n",
				PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
				(union psmi_envvar_val)CUDA_THRESH_RNDV, &env_cuda_thresh_rndv);
	cuda_thresh_rndv = env_cuda_thresh_rndv.e_int;

	if (cuda_thresh_rndv < 0 || cuda_thresh_rndv > CUDA_THRESH_RNDV)
	    cuda_thresh_rndv = CUDA_THRESH_RNDV;

	union psmi_envvar_val env_gdr_copy_thresh_send;
	psmi_getenv("PSM2_GDRCOPY_THRESH_SEND",
				"GDR Copy is turned off on the send side"
				" for message sizes greater than the threshold \n",
				PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
				(union psmi_envvar_val)GDR_COPY_THRESH_SEND, &env_gdr_copy_thresh_send);
	gdr_copy_threshold_send = env_gdr_copy_thresh_send.e_int;

	if (gdr_copy_threshold_send < 8 || gdr_copy_threshold_send > cuda_thresh_rndv)
		gdr_copy_threshold_send = GDR_COPY_THRESH_SEND;

	union psmi_envvar_val env_gdr_copy_thresh_recv;
	psmi_getenv("PSM2_GDRCOPY_THRESH_RECV",
				"GDR Copy is turned off on the recv side"
				" for message sizes greater than the threshold \n",
				PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
				(union psmi_envvar_val)GDR_COPY_THRESH_RECV, &env_gdr_copy_thresh_recv);
	gdr_copy_threshold_recv = env_gdr_copy_thresh_recv.e_int;

	if (gdr_copy_threshold_recv < 8)
		gdr_copy_threshold_recv = GDR_COPY_THRESH_RECV;

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
	union psmi_envvar_val devs;
	int devid_enabled[PTL_MAX_INIT];

	psmi_log_initialize();

	PSM2_LOG_MSG("entering");

	/* When PSM_PERF is enabled, the following code causes the
	   PMU to be programmed to measure instruction cycles of the
	   TX/RX speedpaths of PSM. */
	GENERIC_PERF_INIT();
	GENERIC_PERF_SET_SLOT_NAME(PSM_TX_SPEEDPATH_CTR, "TX");
	GENERIC_PERF_SET_SLOT_NAME(PSM_RX_SPEEDPATH_CTR, "RX");

	if (psmi_refcount > 0) {
		psmi_refcount++;
		goto update;
	}

	if (psmi_refcount == PSMI_FINALIZED) {
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

#ifdef PSM_FI
	/* Make sure we complain if fault injection is enabled */
	if (getenv("PSM2_FI") && !getenv("PSM2_NO_WARN"))
		fprintf(stderr,
			"!!! WARNING !!! You are running with fault injection enabled!\n");
#endif /* #ifdef PSM_FI */

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

	psmi_refcount++;
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

	if (getenv("PSM2_DIAGS")) {
		_HFI_INFO("Running diags...\n");
		psmi_diags();
	}

	psmi_multi_ep_init();

#ifdef PSM_FI
	psmi_faultinj_init();
#endif /* #ifdef PSM_FI */

	psmi_epid_init();

	psmi_getenv("PSM2_DEVICES",
		    "Ordered list of PSM-level devices",
		    PSMI_ENVVAR_LEVEL_USER,
		    PSMI_ENVVAR_TYPE_STR,
		    (union psmi_envvar_val)PSMI_DEVICES_DEFAULT, &devs);

	if ((err = psmi_parse_devices(devid_enabled, devs.e_str)))
		goto fail;

	/* setup a dummy (null) hal if we are not using PTL_DEVID_IPS */
	if (!psmi_device_is_enabled(devid_enabled, PTL_DEVID_IPS)) {
		psmi_hal_initialize_null();
	} else {
		int rc = psmi_hal_initialize();

		if (rc)
		{
			err = PSM2_INTERNAL_ERR;
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

	if (PSMI_IS_CUDA_ENABLED) {
		err = psmi_cuda_initialize();
		if (err != PSM2_OK)
			goto fail;
	}
#endif

update:
	if (getenv("PSM2_IDENTIFY")) {
                Dl_info info_psm;
		char ofed_delta[100] = "";
		strcat(strcat(ofed_delta," built for OFED DELTA "),psmi_hfi_IFS_version);
                printf("%s %s PSM2 v%d.%d%s\n"
		       "%s %s location %s\n"
		       "%s %s build date %s\n"
		       "%s %s src checksum %s\n"
                       "%s %s git checksum %s\n"
                       "%s %s built against driver interface v%d.%d\n"
                       "%s %s HAL instance code: %d, HAL description: \"%s\"\n",
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
		       hfi_get_mylabel(), hfi_ident_tag,
				psmi_hal_get_user_major_bldtime_version(),
				psmi_hal_get_user_minor_bldtime_version(),
		       hfi_get_mylabel(), hfi_ident_tag, psmi_hal_get_hal_instance_type(),
		       psmi_hal_get_hal_instance_description());
	}

	*major = (int)psmi_verno_major;
	*minor = (int)psmi_verno_minor;
fail:
	_HFI_DBG("psmi_refcount=%d,err=%u\n", psmi_refcount, err);

	PSM2_LOG_MSG("leaving");
	return err;
}
PSMI_API_DECL(psm2_init)

static
psm2_error_t psmi_get_psm2_config(psm2_mq_t     mq,
				  psm2_epaddr_t epaddr,
				  uint32_t *out)
{
	psm2_error_t rv = PSM2_INTERNAL_ERR;

	*out = 0;
	if (&mq->ep->ptl_ips == epaddr->ptlctl)
	{
		rv = PSM2_OK;
		*out |= PSM2_INFO_QUERY_CONFIG_IPS;
#ifdef PSM_CUDA
		if (PSMI_IS_CUDA_ENABLED)
		{
			*out |= PSM2_INFO_QUERY_CONFIG_CUDA;
			if (PSMI_IS_GDR_COPY_ENABLED)
				*out |= PSM2_INFO_QUERY_CONFIG_GDR_COPY;
		}
#endif
		{
			union psmi_envvar_val env_sdma;

			psmi_getenv("PSM2_SDMA",
				    "hfi send dma flags (0 disables send dma, 2 disables send pio, "
				    "1 for both sdma/spio, default 1)",
				    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
				    (union psmi_envvar_val)1, &env_sdma);
			if (env_sdma.e_uint == 0)
				*out |= PSM2_INFO_QUERY_CONFIG_PIO;
			else if (env_sdma.e_uint == 1)
				*out |= (PSM2_INFO_QUERY_CONFIG_PIO | PSM2_INFO_QUERY_CONFIG_DMA);
			else if (env_sdma.e_uint == 2)
				*out |= PSM2_INFO_QUERY_CONFIG_DMA;
		}
	}
	else if (&mq->ep->ptl_amsh == epaddr->ptlctl)
	{
		*out |= PSM2_INFO_QUERY_CONFIG_AMSH;
		rv = PSM2_OK;
	}
	else if (&mq->ep->ptl_self == epaddr->ptlctl)
	{
		*out |= PSM2_INFO_QUERY_CONFIG_SELF;
		rv = PSM2_OK;
	}
	return rv;
}

psm2_error_t __psm2_info_query(psm2_info_query_t q, void *out,
			       size_t nargs, psm2_info_query_arg_t args[])
{
	static const size_t expected_arg_cnt[PSM2_INFO_QUERY_LAST] =
	{
		0, /* PSM2_INFO_QUERY_NUM_UNITS         */
		0, /* PSM2_INFO_QUERY_NUM_PORTS         */
		1, /* PSM2_INFO_QUERY_UNIT_STATUS       */
		2, /* PSM2_INFO_QUERY_UNIT_PORT_STATUS  */
		1, /* PSM2_INFO_QUERY_NUM_FREE_CONTEXTS */
		1, /* PSM2_INFO_QUERY_NUM_CONTEXTS      */
		2, /* PSM2_INFO_QUERY_CONFIG            */
		3, /* PSM2_INFO_QUERY_THRESH            */
		3, /* PSM2_INFO_QUERY_DEVICE_NAME       */
	        2, /* PSM2_INFO_QUERY_MTU               */
		2, /* PSM2_INFO_QUERY_LINK_SPEED        */
		1, /* PSM2_INFO_QUERY_NETWORK_TYPE      */
		0, /* PSM2_INFO_QUERY_FEATURE_MASK      */
	};
	psm2_error_t rv = PSM2_INTERNAL_ERR;

	if ((q < 0) ||
	    (q >= PSM2_INFO_QUERY_LAST))
		return 	PSM2_IQ_INVALID_QUERY;

	if (nargs != expected_arg_cnt[q])
		return PSM2_PARAM_ERR;

	switch (q)
	{
	case PSM2_INFO_QUERY_NUM_UNITS:
		*((uint32_t*)out) = psmi_hal_get_num_units_();
		rv = PSM2_OK;
		break;
	case PSM2_INFO_QUERY_NUM_PORTS:
		*((uint32_t*)out) = psmi_hal_get_num_ports_();
		rv = PSM2_OK;
		break;
	case PSM2_INFO_QUERY_UNIT_STATUS:
		*((uint32_t*)out) = psmi_hal_get_unit_active(args[0].unit);
		rv = PSM2_OK;
		break;
	case PSM2_INFO_QUERY_UNIT_PORT_STATUS:
		*((uint32_t*)out) = psmi_hal_get_port_active(args[0].unit,
								args[1].port);
		rv = PSM2_OK;
		break;
	case PSM2_INFO_QUERY_NUM_FREE_CONTEXTS:
		*((uint32_t*)out) = psmi_hal_get_num_free_contexts(args[0].unit);
		rv = PSM2_OK;
		break;
	case PSM2_INFO_QUERY_NUM_CONTEXTS:
		*((uint32_t*)out) = psmi_hal_get_num_contexts(args[0].unit);
		rv = PSM2_OK;
		break;
	case PSM2_INFO_QUERY_CONFIG:
		{
			psm2_mq_t     mq     = args[0].mq;
			psm2_epaddr_t epaddr = args[1].epaddr;
			rv = psmi_get_psm2_config(mq, epaddr, (uint32_t*)out);
		}
		break;
	case PSM2_INFO_QUERY_THRESH:
		{
			psm2_mq_t                      mq     = args[0].mq;
			psm2_epaddr_t                  epaddr = args[1].epaddr;
			enum psm2_info_query_thresh_et iqt    = args[2].mstq;

			uint32_t                       config;
			rv = psmi_get_psm2_config(mq, epaddr, &config);
			if (rv == PSM2_OK)
			{
				*((uint32_t*)out) = 0;
				/* Delegate the call to the ptl member function: */
				rv = epaddr->ptlctl->msg_size_thresh_query(iqt, (uint32_t*)out, mq, epaddr);
			}
		}
		break;
	case PSM2_INFO_QUERY_DEVICE_NAME:
		{
			char         *hfiName       = (char*)out;
			psm2_mq_t     mq            = args[0].mq;
			psm2_epaddr_t epaddr        = args[1].epaddr;
			size_t        hfiNameLength = args[2].length;
			uint32_t      config;

			rv = psmi_get_psm2_config(mq, epaddr, &config);
			if (rv == PSM2_OK)
			{
				if (snprintf(hfiName, hfiNameLength, "%s_%d",
					     psmi_hal_get_hfi_name(),
					     psmi_hal_get_unit_id(mq->ep->context.psm_hw_ctxt))
				    < hfiNameLength)
					rv = PSM2_OK;
			}
		}
		break;
	case PSM2_INFO_QUERY_MTU:
		{
			psm2_mq_t     mq     = args[0].mq;
			psm2_epaddr_t epaddr = args[1].epaddr;
			uint32_t      config;

			rv = psmi_get_psm2_config(mq, epaddr, &config);
			if (rv == PSM2_OK)
			{
				*((uint32_t*)out) = mq->ep->mtu;
			}
		}
		break;
	case PSM2_INFO_QUERY_LINK_SPEED:
		{
			psm2_mq_t     mq     = args[0].mq;
			psm2_epaddr_t epaddr = args[1].epaddr;
			uint32_t      config;

			rv = psmi_get_psm2_config(mq, epaddr, &config);
			if (rv == PSM2_OK)
			{
				*((uint32_t*)out) = psmi_hal_get_port_rate(psmi_hal_get_unit_id(mq->ep->context.psm_hw_ctxt),
								       psmi_hal_get_port_num(mq->ep->context.psm_hw_ctxt));
			}
		}
		break;
	case PSM2_INFO_QUERY_NETWORK_TYPE:
		{
			char              *networkType      = (char*)out;
			size_t            networkTypeLength = args[0].length;
			const char *const cornelisopx          = "Cornelis(TM) OPX";
			if (networkTypeLength >= strlen(cornelisopx)+1)
			{
				strcpy(networkType,cornelisopx);
				rv = PSM2_OK;
			}
		}
		break;
	case PSM2_INFO_QUERY_FEATURE_MASK:
		{
#ifdef PSM_CUDA
		*((uint32_t*)out) = PSM2_INFO_QUERY_FEATURE_CUDA;
#else
		*((uint32_t*)out) = 0;
#endif /* #ifdef PSM_CUDA */
		}
		rv = PSM2_OK;
		break;
	default:
		break;
	}

	return rv;
}
PSMI_API_DECL(psm2_info_query)

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

	_HFI_DBG("psmi_refcount=%d\n", psmi_refcount);
	PSMI_ERR_UNLESS_INITIALIZED(NULL);
	psmi_assert(psmi_refcount > 0);
	psmi_refcount--;

	if (psmi_refcount > 0) {
		return PSM2_OK;
	}

	/* When PSM_PERF is enabled, the following line causes the
	   instruction cycles gathered in the current run to be dumped
	   to stderr. */
	GENERIC_PERF_DUMP(stderr);
	ep = psmi_opened_endpoint;
	while (ep != NULL) {
		psm2_ep_t saved_ep = ep->user_ep_next;
		psm2_ep_close(ep, PSM2_EP_CLOSE_GRACEFUL,
			     2 * PSMI_MIN_EP_CLOSE_TIMEOUT);
		psmi_opened_endpoint = ep = saved_ep;
	}

#ifdef PSM_FI
	psmi_faultinj_fini();
#endif /* #ifdef PSM_FI */

	/* De-allocate memory for any allocated space to store hostnames */
	psmi_epid_itor_init(&itor, PSMI_EP_HOSTNAME);
	while ((hostname = psmi_epid_itor_next(&itor)))
		psmi_free(hostname);
	psmi_epid_itor_fini(&itor);

	psmi_epid_fini();

	/* unmap shared mem object for affinity */
	if (psmi_affinity_shared_file_opened) {
		/*
		 * Start critical section to decrement ref count and unlink
		 * affinity shm file.
		 */
		psmi_sem_timedwait(sem_affinity_shm_rw, sem_affinity_shm_rw_name);

		shared_affinity_ptr[AFFINITY_SHM_REF_COUNT_LOCATION] -= 1;
		if (shared_affinity_ptr[AFFINITY_SHM_REF_COUNT_LOCATION] <= 0) {
			_HFI_VDBG("Unlink shm file for HFI affinity as there are no more users\n");
			shm_unlink(affinity_shm_name);
		} else {
			_HFI_VDBG("Number of affinity shared memory users left=%ld\n",
				  shared_affinity_ptr[AFFINITY_SHM_REF_COUNT_LOCATION]);
		}

		msync(shared_affinity_ptr, AFFINITY_SHMEMSIZE, MS_SYNC);

		/* End critical section */
		psmi_sem_post(sem_affinity_shm_rw, sem_affinity_shm_rw_name);

		munmap(shared_affinity_ptr, AFFINITY_SHMEMSIZE);
		psmi_free(affinity_shm_name);
		affinity_shm_name = NULL;
		psmi_affinity_shared_file_opened = 0;
	}

	if (psmi_affinity_semaphore_open) {
		_HFI_VDBG("Closing and Unlinking Semaphore: %s.\n", sem_affinity_shm_rw_name);
		sem_close(sem_affinity_shm_rw);
		sem_unlink(sem_affinity_shm_rw_name);
		psmi_free(sem_affinity_shm_rw_name);
		sem_affinity_shm_rw_name = NULL;
		psmi_affinity_semaphore_open = 0;
	}

	psmi_hal_finalize();
#ifdef PSM_CUDA
	if (is_cuda_primary_context_retain) {
		/*
		 * This code will be called during deinitialization, and if
		 * CUDA is deinitialized before PSM, then
		 * CUDA_ERROR_DEINITIALIZED will happen here
		 */
		CUdevice device;
		if (psmi_cuCtxGetDevice(&device) == CUDA_SUCCESS)
			PSMI_CUDA_CALL(cuDevicePrimaryCtxRelease, device);
	}
#endif

	psmi_refcount = PSMI_FINALIZED;
	PSM2_LOG_MSG("leaving");
	psmi_log_fini();

	psmi_stats_deregister_all();

	psmi_heapdebug_finalize();

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
