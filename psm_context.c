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
#include "psm_user.h"
#include "psm2_hal.h"

static int psmi_get_hfi_selection_algorithm(void);

psm2_error_t psmi_context_interrupt_set(psmi_context_t *context, int enable)
{
	int poll_type;
	int ret;

	if ((enable && psmi_hal_has_status(PSM_HAL_PSMI_RUNTIME_INTR_ENABLED)) ||
	    (!enable && !psmi_hal_has_status(PSM_HAL_PSMI_RUNTIME_INTR_ENABLED)))
		return PSM2_OK;

	if (enable)
		poll_type = PSMI_HAL_POLL_TYPE_URGENT;
	else
		poll_type = 0;

	ret = psmi_hal_poll_type(poll_type, context->psm_hw_ctxt);

	if (ret != 0)
		return PSM2_EP_NO_RESOURCES;
	else {
		if (enable)
			psmi_hal_add_status(PSM_HAL_PSMI_RUNTIME_INTR_ENABLED);
		else
			psmi_hal_sub_status(PSM_HAL_PSMI_RUNTIME_INTR_ENABLED);
		return PSM2_OK;
	}
}

int psmi_context_interrupt_isenabled(psmi_context_t *context)
{
	return psmi_hal_has_status(PSM_HAL_PSMI_RUNTIME_INTR_ENABLED);
}

/* Returns 1 when all of the active units have their free contexts
 * equal the number of contexts.  This is an indication that no
 * jobs are currently running.
 *
 * Note that this code is clearly racy (this code may happen concurrently
 * by two or more processes, and this point of observation,
 * occurs earlier in time to when the decision is made for deciding which
 * context to assign, which will also occurs earlier in time to when the
 * context is actually assigned.  And, when the context is finally
 * assigned, this will change the "nfreectxts" observed below.)
 */
static int psmi_all_active_units_have_max_freecontexts(int nunits)
{
	int u;

	for (u=0;u < nunits;u++)
	{
		if (psmi_hal_get_unit_active(u) > 0)
		{
			int nfreectxts=psmi_hal_get_num_free_contexts(u),
				nctxts=psmi_hal_get_num_contexts(u);
			if (nfreectxts > 0 && nctxts > 0)
			{
				if (nfreectxts != nctxts)
					return 0;
			}
		}
	}
	return 1;
}

/* returns the integer value of an environment variable, or 0 if the environment
 * variable is not set. */
static int psmi_get_envvar(const char *env)
{
	const char *env_val = getenv(env);

	if (env_val && *env_val)
	{
		int r = atoi(env_val);
		return (r >= 0) ? r : 0;
	}
	return 0;
}

/* returns the 8-bit hash value of an uuid. */
static inline
uint8_t
psmi_get_uuid_hash(psm2_uuid_t const uuid)
{
	int i;
	uint8_t hashed_uuid = 0;

	for (i=0; i < sizeof(psm2_uuid_t); ++i)
		hashed_uuid ^= *((uint8_t const *)uuid + i);

	return hashed_uuid;
}

int psmi_get_current_proc_location()
{
        int core_id, node_id;

	core_id = sched_getcpu();
	if (core_id < 0)
		return -EINVAL;

	node_id = numa_node_of_cpu(core_id);
	if (node_id < 0)
		return -EINVAL;

	return node_id;
}

static void
psmi_spread_hfi_selection(psm2_uuid_t const job_key, long *unit_start,
			     long *unit_end, int nunits)
{
	/* if the number of ranks on the host is 1 and ... */
	if ((psmi_get_envvar("MPI_LOCALNRANKS") == 1) &&
		/*
		 * All of the active units have free contexts equal the
		 * number of contexts.
		 */
	    psmi_all_active_units_have_max_freecontexts(nunits)) {
		/* we start looking at unit 0, and end at nunits-1: */
		*unit_start = 0;
		*unit_end = nunits - 1;
	} else {
		/* else, we are going to look at:
		   (a hash of the job key plus the local rank id) mod nunits. */

		*unit_start = (psmi_get_envvar("MPI_LOCALRANKID") +
			psmi_get_uuid_hash(job_key)) % nunits;
		if (*unit_start > 0)
			*unit_end = *unit_start - 1;
		else
			*unit_end = nunits-1;
	}
}

static int
psmi_create_and_open_affinity_shm(psm2_uuid_t const job_key)
{
	int shm_fd, ret;
	int first_to_create = 0;
	size_t shm_name_len = 256;
	shared_affinity_ptr = NULL;
	affinity_shm_name = NULL;
	affinity_shm_name = (char *) psmi_malloc(PSMI_EP_NONE, UNDEFINED, shm_name_len);

	psmi_assert_always(affinity_shm_name != NULL);
	snprintf(affinity_shm_name, shm_name_len,
		 AFFINITY_SHM_BASENAME".%d",
		 psmi_get_uuid_hash(job_key));
	shm_fd = shm_open(affinity_shm_name, O_RDWR | O_CREAT | O_EXCL,
			  S_IRUSR | S_IWUSR);
	if ((shm_fd < 0) && (errno == EEXIST)) {
		shm_fd = shm_open(affinity_shm_name, O_RDWR, S_IRUSR | S_IWUSR);
		if (shm_fd < 0) {
			_HFI_VDBG("Cannot open affinity shared mem fd:%s, errno=%d\n",
				  affinity_shm_name, errno);
			return shm_fd;
		}
	} else if (shm_fd > 0) {
		first_to_create = 1;
	} else {
		_HFI_VDBG("Cannot create affinity shared mem fd:%s, errno=%d\n",
			  affinity_shm_name, errno);
	}

	ret = ftruncate(shm_fd, AFFINITY_SHMEMSIZE);
	if ( ret < 0 )
		return ret;

	shared_affinity_ptr = (uint64_t *) mmap(NULL, AFFINITY_SHMEMSIZE, PROT_READ | PROT_WRITE,
					MAP_SHARED, shm_fd, 0);
	if (shared_affinity_ptr == MAP_FAILED) {
		_HFI_VDBG("Cannot mmap affinity shared memory. errno=%d\n",
			  errno);
		close(shm_fd);
		return -1;
	}
	close(shm_fd);

	psmi_affinity_shared_file_opened = 1;

	if (first_to_create) {
		_HFI_VDBG("Creating shm to store HFI affinity per socket\n");

		memset(shared_affinity_ptr, 0, AFFINITY_SHMEMSIZE);

		/*
		 * Once shm object is initialized, unlock others to be able to
		 * use it.
		 */
		psmi_sem_post(sem_affinity_shm_rw, sem_affinity_shm_rw_name);
	} else {
		_HFI_VDBG("Opening shm object to read/write HFI affinity per socket\n");
	}

	/*
	 * Start critical section to increment reference count when creating
	 * or opening shm object. Decrement of ref count will be done before
	 * closing the shm.
	 */
	if (psmi_sem_timedwait(sem_affinity_shm_rw, sem_affinity_shm_rw_name)) {
		_HFI_VDBG("Could not enter critical section to update shm refcount\n");
		return -1;
	}

	shared_affinity_ptr[AFFINITY_SHM_REF_COUNT_LOCATION] += 1;

	/* End critical section */
	psmi_sem_post(sem_affinity_shm_rw, sem_affinity_shm_rw_name);

	return 0;
}

/*
 * Spread HFI selection between units if we find more than one within a socket.
 */
static void
psmi_spread_hfi_within_socket(long *unit_start, long *unit_end, int node_id,
			      int *saved_hfis, int found, psm2_uuid_t const job_key)
{
	int ret, shm_location;

	/*
	 * Take affinity lock and open shared memory region to be able to
	 * accurately determine which HFI to pick for this process. If any
	 * issues, bail by picking first known HFI.
	 */
	if (!psmi_affinity_semaphore_open)
		goto spread_hfi_fallback;

	ret = psmi_create_and_open_affinity_shm(job_key);
	if (ret < 0)
		goto spread_hfi_fallback;

	shm_location = AFFINITY_SHM_HFI_INDEX_LOCATION + node_id;
	if (shm_location > AFFINITY_SHMEMSIZE)
		goto spread_hfi_fallback;

	/* Start critical section to read/write shm object */
	if (psmi_sem_timedwait(sem_affinity_shm_rw, sem_affinity_shm_rw_name)) {
		_HFI_VDBG("Could not enter critical section to update HFI index\n");
		goto spread_hfi_fallback;
	}

	*unit_start = *unit_end = shared_affinity_ptr[shm_location];
	shared_affinity_ptr[shm_location] =
		(shared_affinity_ptr[shm_location] + 1) % found;
	_HFI_VDBG("Selected HFI index= %ld, Next HFI=%ld, node = %d, local rank=%d, found=%d.\n",
		  *unit_start, shared_affinity_ptr[shm_location], node_id,
		  psmi_get_envvar("MPI_LOCALRANKID"), found);

	/* End Critical Section */
	psmi_sem_post(sem_affinity_shm_rw, sem_affinity_shm_rw_name);

	return;

spread_hfi_fallback:
	*unit_start = *unit_end = saved_hfis[0];
}

static void
psmi_create_affinity_semaphores(psm2_uuid_t const job_key)
{
	int ret;
	sem_affinity_shm_rw_name = NULL;
	size_t sem_len = 256;

	/*
	 * If already opened, no need to do anything else.
	 * This could be true for Multi-EP cases where a different thread has
	 * already created the semaphores. We don't need separate locks here as
	 * we are protected by the overall "psmi_creation_lock" which each
	 * thread will take in psm2_ep_open()
	 */
	if (psmi_affinity_semaphore_open)
		return;

	sem_affinity_shm_rw_name = (char *) psmi_malloc(PSMI_EP_NONE, UNDEFINED, sem_len);
	psmi_assert_always(sem_affinity_shm_rw_name != NULL);
	snprintf(sem_affinity_shm_rw_name, sem_len,
		 SEM_AFFINITY_SHM_RW_BASENAME".%d",
		 psmi_get_uuid_hash(job_key));

	ret = psmi_init_semaphore(&sem_affinity_shm_rw, sem_affinity_shm_rw_name,
				  S_IRUSR | S_IWUSR, 0);
	if (ret) {
		_HFI_VDBG("Cannot initialize semaphore: %s for read-write access to shm object.\n",
			  sem_affinity_shm_rw_name);
		sem_close(sem_affinity_shm_rw);
		psmi_free(sem_affinity_shm_rw_name);
		sem_affinity_shm_rw_name = NULL;
		return;
	}

	_HFI_VDBG("Semaphore: %s created for read-write access to shm object.\n",
		  sem_affinity_shm_rw_name);

	psmi_affinity_semaphore_open = 1;

	return;
}

static
psm2_error_t
psmi_compute_start_and_end_unit(long unit_param,int nunitsactive,int nunits,
				psm2_uuid_t const job_key,
				long *unit_start,long *unit_end)
{
	unsigned short hfi_sel_alg = PSMI_UNIT_SEL_ALG_ACROSS;
	int node_id, unit_id, found = 0;
	int saved_hfis[nunits];

	/* if the user did not set HFI_UNIT then ... */
	if (unit_param == HFI_UNIT_ID_ANY)
	{
		/* Get the actual selection algorithm from the environment: */
		hfi_sel_alg = psmi_get_hfi_selection_algorithm();
		/* If round-robin is selection algorithm and ... */
		if ((hfi_sel_alg == PSMI_UNIT_SEL_ALG_ACROSS) &&
		    /* there are more than 1 active units then ... */
		    (nunitsactive > 1))
		{
			/*
			 * Pick first HFI we find on same root complex
			 * as current task. If none found, fall back to
			 * load-balancing algorithm.
			 */
			node_id = psmi_get_current_proc_location();
			if (node_id >= 0) {
				for (unit_id = 0; unit_id < nunits; unit_id++) {
					if (psmi_hal_get_unit_active(unit_id) <= 0)
						continue;

					int node_id_i;

					if (!psmi_hal_get_node_id(unit_id, &node_id_i)) {
						if (node_id_i == node_id) {
							saved_hfis[found] = unit_id;
							found++;
						}
					}
				}

				if (found > 1) {
					psmi_create_affinity_semaphores(job_key);
					psmi_spread_hfi_within_socket(unit_start, unit_end,
								      node_id, saved_hfis,
								      found, job_key);
				} else if (found == 1) {
					*unit_start = *unit_end = saved_hfis[0];
				}
			}

			if (node_id < 0 || !found) {
				psmi_spread_hfi_selection(job_key, unit_start,
							  unit_end, nunits);
			}
		} else if ((hfi_sel_alg == PSMI_UNIT_SEL_ALG_ACROSS_ALL) &&
			 (nunitsactive > 1)) {
				psmi_spread_hfi_selection(job_key, unit_start,
							  unit_end, nunits);
		}
		else {
			*unit_start = 0;
			*unit_end = nunits - 1;
		}
	} else if (unit_param >= 0) {
		/* the user specified HFI_UNIT, we use it. */
		*unit_start = *unit_end = unit_param;
	} else {
		psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
				 "PSM2 can't open unit: %ld for reading and writing",
				 unit_param);
		return PSM2_EP_DEVICE_FAILURE;
	}

	return PSM2_OK;
}

psm2_error_t
psmi_context_open(const psm2_ep_t ep, long unit_param, long port,
		  psm2_uuid_t const job_key, int64_t timeout_ns,
		  psmi_context_t *context)
{
	long open_timeout = 0, unit_start, unit_end, unit_id, unit_id_prev;
	psm2_error_t err = PSM2_OK;
	int nunits = psmi_hal_get_num_units(), nunitsactive=0;

	/*
	 * If shared contexts are enabled, try our best to schedule processes
	 * across one or many devices
	 */

	/* if no units, then no joy. */
	if (nunits <= 0)
	{
		err = psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
					"PSM2 no hfi units are available");
		goto ret;
	}

	/* Calculate the number of active units: */
	for (unit_id=0;unit_id < nunits;unit_id++)
	{
		if (psmi_hal_get_unit_active(unit_id) > 0)
			nunitsactive++;
	}
	/* if no active units, then no joy. */
	if (nunitsactive == 0)
	{
		err = psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
					"PSM2 no hfi units are active");
		goto ret;
	}
	if (timeout_ns > 0)
		open_timeout = (long)(timeout_ns / MSEC_ULL);


	unit_start = 0; unit_end = nunits - 1;
	err = psmi_compute_start_and_end_unit(unit_param, nunitsactive,
					      nunits, job_key,
					      &unit_start, &unit_end);
	if (err != PSM2_OK)
		return err;

	/* this is the start of a loop that starts at unit_start and goes to unit_end.
	   but note that the way the loop computes the loop control variable is by
	   an expression involving the mod operator. */
	int success = 0;
	unit_id_prev = unit_id = unit_start;
	do
	{
		/* close previous opened unit fd before attempting open of current unit. */
		if (psmi_hal_get_fd(context->psm_hw_ctxt) > 0)
			psmi_hal_close_context(&context->psm_hw_ctxt);

		/* if the unit_id is not active, go to next one. */
		if (psmi_hal_get_unit_active(unit_id) <= 0) {
			unit_id_prev = unit_id;
			unit_id = (unit_id + 1) % nunits;
			continue;
		}

		/* open this unit. */
		int rv = psmi_hal_context_open(unit_id, port, open_timeout,
					       ep, job_key, context,
					       psmi_hal_has_status(PSM_HAL_PSMI_RUNTIME_RX_THREAD_STARTED),
					       HAL_CONTEXT_OPEN_RETRY_MAX);

		/* go to next unit if failed to open. */
		if (rv || context->psm_hw_ctxt == NULL) {
			unit_id_prev = unit_id;
			unit_id = (unit_id + 1) % nunits;
			continue;
		}

		success = 1;
		break;

	} while (unit_id_prev != unit_end);

	if (!success)
	{
		err = psmi_handle_error(NULL, PSM2_EP_DEVICE_FAILURE,
					"PSM2 can't open hfi unit: %ld",unit_param);
		goto bail;
	}

	context->ep = (psm2_ep_t) ep;

#ifdef PSM_CUDA
	/* Check backward compatibility bits here and save the info */
	if (psmi_hal_has_cap(PSM_HAL_CAP_GPUDIRECT_OT))
		is_driver_gpudirect_enabled = 1;
#endif
	_HFI_VDBG("hfi_userinit() passed.\n");

	/* Fetch hw parameters from HAL (that were obtained during opening the context above. */

	int lid           = psmi_hal_get_lid(context->psm_hw_ctxt);
	ep->unit_id       = psmi_hal_get_unit_id(context->psm_hw_ctxt);
	ep->portnum       = psmi_hal_get_port_num(context->psm_hw_ctxt);
	ep->gid_lo        = psmi_hal_get_gid_lo(context->psm_hw_ctxt);
	ep->gid_hi        = psmi_hal_get_gid_hi(context->psm_hw_ctxt);
	int ctxt          = psmi_hal_get_context(context->psm_hw_ctxt);
	int subctxt       = psmi_hal_get_subctxt(context->psm_hw_ctxt);
	uint32_t hfi_type = psmi_hal_get_hfi_type(context->psm_hw_ctxt);
	ep->mtu           = psmi_hal_get_mtu(context->psm_hw_ctxt);
	context->ep       = (psm2_ep_t) ep;

	/* Construct epid for this Endpoint */

	switch (PSMI_EPID_VERSION) {
		case PSMI_EPID_V1:
			context->epid = PSMI_EPID_PACK_V1(lid, ctxt,
								subctxt,
								ep->unit_id,
								PSMI_EPID_VERSION, 0x3ffffff);
			break;
		case PSMI_EPID_V2:
			context->epid = PSMI_EPID_PACK_V2(lid, ctxt,
								subctxt,
								PSMI_EPID_IPS_SHM, /*Not a only-shm epid */
								PSMI_EPID_VERSION, ep->gid_hi);
			break;
		default:
			/* Epid version is greater than max supportd version. */
			psmi_assert_always(PSMI_EPID_VERSION <= PSMI_EPID_V2);
			break;
	}

	_HFI_VDBG
	    ("construct epid: lid %d ctxt %d subctxt %d hcatype %d mtu %d\n",
	     lid, ctxt,
	     subctxt, hfi_type, ep->mtu);

	goto ret;

bail:
	_HFI_PRDBG("open failed: unit_id: %ld, err: %d (%s)\n", unit_id, err, strerror(errno));
	if (psmi_hal_get_fd(context->psm_hw_ctxt) > 0)
		psmi_hal_close_context(&context->psm_hw_ctxt);
ret:

	_HFI_VDBG("psmi_context_open() return %d\n", err);
	return err;
}

psm2_error_t psmi_context_close(psmi_context_t *context)
{
	if (psmi_hal_get_fd(context->psm_hw_ctxt) > 0)
		psmi_hal_close_context(&context->psm_hw_ctxt);

	return PSM2_OK;
}

/*
 * This function works whether a context is initialized or not in a psm2_ep.
 *
 * Returns one of
 *
 * PSM2_OK: Port status is ok (or context not initialized yet but still "ok")
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
	char *errmsg = NULL;
	uint64_t status = psmi_hal_get_hw_status(context->psm_hw_ctxt);

	/* Fatal chip-related errors */
	if (!(status & PSM_HAL_HW_STATUS_CHIP_PRESENT) ||
	    !(status & PSM_HAL_HW_STATUS_INITTED) ||
	    (status & PSM_HAL_HW_STATUS_HWERROR)) {

		err = PSM2_EP_DEVICE_FAILURE;
		if (err != context->status_lasterr) {	/* report once */
			volatile char *errmsg_sp="no err msg";

			psmi_hal_get_hw_status_freezemsg(&errmsg_sp,
							 context->psm_hw_ctxt);

			if (*errmsg_sp)
				psmi_handle_error(context->ep, err,
						  "Hardware problem: %s",
						  errmsg_sp);
			else {
				if (status & PSM_HAL_HW_STATUS_HWERROR)
					errmsg = "Hardware error";
				else
					errmsg = "Hardware not found";

				psmi_handle_error(context->ep, err,
						  "%s", errmsg);
			}
		}
	}
	/* Fatal network-related errors with timeout: */
	else if (!(status & PSM_HAL_HW_STATUS_IB_CONF) ||
		 !(status & PSM_HAL_HW_STATUS_IB_READY)) {
		err = PSM2_EP_NO_NETWORK;
		if (err != context->status_lasterr) {	/* report once */
			context->networkLostTime = time(NULL);
		}
		else
		{
			time_t now = time(NULL);
			static const double seventySeconds = 70.0;

			/* The linkup time duration for a system should allow the time needed
			   to complete 3 LNI passes which is:
			   50 seconds for a passive copper channel
			   65 seconds for optical channel.
			   (we add 5 seconds of margin.) */
			if (difftime(now,context->networkLostTime) > seventySeconds)
			{
				volatile char *errmsg_sp="no err msg";

				psmi_hal_get_hw_status_freezemsg(&errmsg_sp,
								 context->psm_hw_ctxt);

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

static
int psmi_get_hfi_selection_algorithm(void)
{
	union psmi_envvar_val env_hfi1_alg;
	int hfi1_alg = PSMI_UNIT_SEL_ALG_ACROSS;

	/* If a specific unit is set in the environment, use that one. */
	psmi_getenv("HFI_SELECTION_ALG",
		    "HFI Device Selection Algorithm to use. Round Robin (Default) "
		    ", Packed or Round Robin All.",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
		    (union psmi_envvar_val)"Round Robin", &env_hfi1_alg);

	if (!strcasecmp(env_hfi1_alg.e_str, "Round Robin"))
		hfi1_alg = PSMI_UNIT_SEL_ALG_ACROSS;
	else if (!strcasecmp(env_hfi1_alg.e_str, "Packed"))
		hfi1_alg = PSMI_UNIT_SEL_ALG_WITHIN;
	else if (!strcasecmp(env_hfi1_alg.e_str, "Round Robin All"))
		hfi1_alg = PSMI_UNIT_SEL_ALG_ACROSS_ALL;
	else {
		_HFI_ERROR
		    ("Unknown HFI selection algorithm %s. Defaulting to Round Robin "
		     "allocation of HFIs.\n", env_hfi1_alg.e_str);
		hfi1_alg = PSMI_UNIT_SEL_ALG_ACROSS;
	}

	return hfi1_alg;
}
