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

#ifdef PSM_CUDA

#include "psm_user.h"
#include "am_cuda_memhandle_cache.h"


/*
 * rbtree cruft
 */
struct _cl_map_item;

typedef struct
{
	unsigned long		start;		 /* start virtual address */
	CUipcMemHandle		cuda_ipc_handle; /* cuda ipc mem handle */
	CUdeviceptr		cuda_ipc_dev_ptr;/* Cuda device pointer */
	uint16_t		length;	 /* length*/
	psm2_epid_t             epid;
	struct _cl_map_item*	i_prev;	 /* idle queue previous */
	struct _cl_map_item*	i_next;	 /* idle queue next */
}__attribute__ ((aligned (128))) rbtree_cuda_memhandle_cache_mapitem_pl_t;

typedef struct {
	uint32_t		nelems;	/* number of elements in the cache */
} rbtree_cuda_memhandle_cache_map_pl_t;

static psm2_error_t am_cuda_memhandle_mpool_init(uint32_t memcache_size);

/*
 * Custom comparator
 */
typedef rbtree_cuda_memhandle_cache_mapitem_pl_t cuda_cache_item;

static int cuda_cache_key_cmp(const cuda_cache_item *a, const cuda_cache_item *b)
{
	// CUDA address space is associated with a host process.
	//
	// Regarding cuIpcOpenMemHandle(), CUDA driver API says "CUipcMemHandles
	// from each CUdevice in a given process may only be opened by one
	// CUcontext per CUdevice per other process." Not sure what would happen
	// if cuIpcOpenMemHandle() were called for an already-opened handle.
	//
	// if A is a sender's key item, B is a key already in the cache, and multi-ep
	// is disabled, A.epid != B.epid guarantees that A and B refer to different
	// GPU memory even if overlap(A,B). But if multi-ep is enabled,
	// A.epid != B.epid does not guarantee this.
	//
	// One option for handling multi-ep case without key collisions, evictions,
	// and cuIpcOpenMemHandle/cuIpcCloseMemHandle() thrashing is for sender to
	// always use the same epid for a given GPU address range.
	//
	// TLDR, when multi-ep is enabled, don't use .epid as part of the sender's
	// GPU memory key.
	if (!psmi_multi_ep_enabled) {
		if (a->epid < b->epid)
			return -1;
		if (a->epid > b->epid)
			return 1;
	}

	if ((a->start + a->length) <= b->start)
		return -1;
	if (a->start >= (b->start + b->length))
		return 1;

	return 0;
}


/*
 * Necessary rbtree cruft
 */
#define RBTREE_MI_PL  rbtree_cuda_memhandle_cache_mapitem_pl_t
#define RBTREE_MAP_PL rbtree_cuda_memhandle_cache_map_pl_t
#define RBTREE_CMP(a,b) cuda_cache_key_cmp((a), (b))
#define RBTREE_ASSERT                     psmi_assert
#define RBTREE_MAP_COUNT(PAYLOAD_PTR)     ((PAYLOAD_PTR)->nelems)
#define RBTREE_NO_EMIT_IPS_CL_QMAP_PREDECESSOR

#include "rbtree.h"
#include "rbtree.c"

/*
 * Convenience rbtree cruft
 */
#define NELEMS			cuda_memhandle_cachemap.payload.nelems

#define IHEAD			cuda_memhandle_cachemap.root
#define LAST			IHEAD->payload.i_prev
#define FIRST			IHEAD->payload.i_next
#define INEXT(x)		x->payload.i_next
#define IPREV(x)		x->payload.i_prev

/*
 * Actual module data
 */
static cl_qmap_t cuda_memhandle_cachemap; /* Global cache */
static uint8_t cuda_memhandle_cache_enabled;
static mpool_t cuda_memhandle_mpool;
static uint32_t cuda_memhandle_cache_size;

static uint64_t cache_hit_counter;
static uint64_t cache_miss_counter;
static uint64_t cache_evict_counter;
static uint64_t cache_collide_counter;

static void print_cuda_memhandle_cache_stats(void)
{
	_HFI_DBG("enabled=%u,size=%u,hit=%lu,miss=%lu,evict=%lu,collide=%lu\n",
		cuda_memhandle_cache_enabled, cuda_memhandle_cache_size,
		cache_hit_counter, cache_miss_counter,
		cache_evict_counter, cache_collide_counter);
}

/*
 * This is the callback function when mempool are resized or destroyed.
 * Upon calling cache fini mpool is detroyed which in turn calls this callback
 * which helps in closing all memhandles.
 */
static void
psmi_cuda_memhandle_cache_alloc_func(int is_alloc, void* context, void* obj)
{
	cl_map_item_t* memcache_item = (cl_map_item_t*)obj;
	if (!is_alloc) {
		if(memcache_item->payload.start)
			PSMI_CUDA_CALL(cuIpcCloseMemHandle,
				       memcache_item->payload.cuda_ipc_dev_ptr);
	}
}

/*
 * Creating mempool for cuda memhandle cache nodes.
 */
static psm2_error_t
am_cuda_memhandle_mpool_init(uint32_t memcache_size)
{
	psm2_error_t err;
	cuda_memhandle_cache_size = memcache_size;
	/* Creating a memory pool of size PSM2_CUDA_MEMCACHE_SIZE
	 * which includes the Root and NIL items
	 */
	cuda_memhandle_mpool = psmi_mpool_create_for_cuda(sizeof(cl_map_item_t),
					cuda_memhandle_cache_size,
					cuda_memhandle_cache_size, 0,
					UNDEFINED, NULL, NULL,
					psmi_cuda_memhandle_cache_alloc_func,
					NULL);
	if (cuda_memhandle_mpool == NULL) {
		err = psmi_handle_error(PSMI_EP_NORETURN, PSM2_NO_MEMORY,
				"Couldn't allocate CUDA host receive buffer pool");
		return err;
	}
	return PSM2_OK;
}

/*
 * Initialize rbtree.
 */
psm2_error_t am_cuda_memhandle_cache_init(uint32_t memcache_size)
{
	psm2_error_t err = am_cuda_memhandle_mpool_init(memcache_size);
	if (err != PSM2_OK)
		return err;

	cl_map_item_t *root, *nil_item;
	root = (cl_map_item_t *)psmi_calloc(NULL, UNDEFINED, 1, sizeof(cl_map_item_t));
	if (root == NULL)
		return PSM2_NO_MEMORY;
	nil_item = (cl_map_item_t *)psmi_calloc(NULL, UNDEFINED, 1, sizeof(cl_map_item_t));
	if (nil_item == NULL)
		return PSM2_NO_MEMORY;
	nil_item->payload.start = 0;
	nil_item->payload.epid = 0;
	nil_item->payload.length = 0;
	cuda_memhandle_cache_enabled = 1;
	ips_cl_qmap_init(&cuda_memhandle_cachemap,root,nil_item);
	NELEMS = 0;
	return PSM2_OK;
}

void am_cuda_memhandle_cache_map_fini()
{
	print_cuda_memhandle_cache_stats();

	if (cuda_memhandle_cachemap.nil_item)
		psmi_free(cuda_memhandle_cachemap.nil_item);
	if (cuda_memhandle_cachemap.root)
		psmi_free(cuda_memhandle_cachemap.root);
	if (cuda_memhandle_cache_enabled)
		psmi_mpool_destroy(cuda_memhandle_mpool);
	return;
}

/*
 * Insert at the head of Idleq.
 */
static void
am_cuda_idleq_insert(cl_map_item_t* memcache_item)
{
	if (FIRST == NULL) {
		FIRST = memcache_item;
		LAST = memcache_item;
		return;
	}
	INEXT(FIRST) = memcache_item;
	IPREV(memcache_item) = FIRST;
	FIRST = memcache_item;
	return;
}

/*
 * Remove least recent used element.
 */
static void
am_cuda_idleq_remove_last(cl_map_item_t* memcache_item)
{
	if (!INEXT(memcache_item)) {
		LAST = NULL;
		FIRST = NULL;
		return;
	}
	LAST = INEXT(memcache_item);
	IPREV(LAST) = NULL;
	return;
}

static void
am_cuda_idleq_remove(cl_map_item_t* memcache_item)
{
	if (LAST == memcache_item) {
		am_cuda_idleq_remove_last(memcache_item);
		return;
	}
	if (INEXT(memcache_item) == NULL) {
		INEXT(IPREV(memcache_item)) = NULL;
		return;
	}
	INEXT(IPREV(memcache_item)) = INEXT(memcache_item);
	IPREV(INEXT(memcache_item)) = IPREV(memcache_item);
	return;
}

static void
am_cuda_idleq_reorder(cl_map_item_t* memcache_item)
{
	if (FIRST == memcache_item && LAST == memcache_item ) {
		return;
	}
	am_cuda_idleq_remove(memcache_item);
	am_cuda_idleq_insert(memcache_item);
	return;
}

/*
 * After a successful cache hit, item is validated by doing a
 * memcmp on the handle stored and the handle we recieve from the
 * sender. If the validation fails the item is removed from the idleq,
 * the rbtree, is put back into the mpool and IpcCloseMemHandle function
 * is called.
 */
static psm2_error_t
am_cuda_memhandle_cache_validate(cl_map_item_t* memcache_item,
				 uintptr_t sbuf, CUipcMemHandle* handle,
				 uint32_t length, psm2_epid_t epid)
{
	if ((0 == memcmp(handle, &memcache_item->payload.cuda_ipc_handle,
			 sizeof(CUipcMemHandle)))
			 && sbuf == memcache_item->payload.start
			 && epid == memcache_item->payload.epid) {
		return PSM2_OK;
	}

	cache_collide_counter++;
	ips_cl_qmap_remove_item(&cuda_memhandle_cachemap, memcache_item);
	PSMI_CUDA_CALL(cuIpcCloseMemHandle,
		       memcache_item->payload.cuda_ipc_dev_ptr);
	am_cuda_idleq_remove(memcache_item);
	psmi_mpool_put(memcache_item);
	return PSM2_OK_NO_PROGRESS;
}

/*
 * Current eviction policy: Least Recently Used.
 */
static void
am_cuda_memhandle_cache_evict(void)
{
	cache_evict_counter++;
	cl_map_item_t *p_item = LAST;
	ips_cl_qmap_remove_item(&cuda_memhandle_cachemap, p_item);
	PSMI_CUDA_CALL(cuIpcCloseMemHandle, p_item->payload.cuda_ipc_dev_ptr);
	am_cuda_idleq_remove_last(p_item);
	psmi_mpool_put(p_item);
}

static psm2_error_t
am_cuda_memhandle_cache_register(uintptr_t sbuf, CUipcMemHandle* handle,
				 uint32_t length, psm2_epid_t epid,
				 CUdeviceptr cuda_ipc_dev_ptr)
{
	if (NELEMS == cuda_memhandle_cache_size)
		am_cuda_memhandle_cache_evict();

	cl_map_item_t* memcache_item = psmi_mpool_get(cuda_memhandle_mpool);
	/* memcache_item cannot be NULL as we evict
	 * before the call to mpool_get. Check has
	 * been fixed to help with klockwork analysis.
	 */
	if (memcache_item == NULL)
		return PSM2_NO_MEMORY;
	memcache_item->payload.start = sbuf;
	memcache_item->payload.cuda_ipc_handle = *handle;
	memcache_item->payload.cuda_ipc_dev_ptr = cuda_ipc_dev_ptr;
	memcache_item->payload.length = length;
	memcache_item->payload.epid = epid;
	ips_cl_qmap_insert_item(&cuda_memhandle_cachemap, memcache_item);
	am_cuda_idleq_insert(memcache_item);
	return PSM2_OK;
}

CUdeviceptr
am_cuda_memhandle_acquire(uintptr_t sbuf, CUipcMemHandle* handle,
				uint32_t length, psm2_epid_t epid)
{
	_HFI_VDBG("sbuf=%lu,handle=%p,length=%u,epid=%lu\n",
		sbuf, handle, length, epid);

	CUdeviceptr cuda_ipc_dev_ptr;
	if(!cuda_memhandle_cache_enabled) {
		PSMI_CUDA_CALL(cuIpcOpenMemHandle, &cuda_ipc_dev_ptr,
				 *handle, CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
		return cuda_ipc_dev_ptr;
	}

	cuda_cache_item key = {
		.start = (unsigned long) sbuf,
		.length= length,
		.epid = epid
	};

	/*
	 * The key used to search the cache is the senders buf address pointer.
	 * Upon a succesful hit in the cache, additional validation is required
	 * as multiple senders could potentially send the same buf address value.
	 */
	cl_map_item_t *p_item = ips_cl_qmap_searchv(&cuda_memhandle_cachemap, &key);
	if (p_item->payload.start &&
		am_cuda_memhandle_cache_validate(p_item, sbuf,
				   handle, length, epid) == PSM2_OK) {

		cache_hit_counter++;
		am_cuda_idleq_reorder(p_item);
		return p_item->payload.cuda_ipc_dev_ptr;
	} else if (!p_item->payload.start) {
		cache_miss_counter++;
	}

	PSMI_CUDA_CALL(cuIpcOpenMemHandle, &cuda_ipc_dev_ptr,
			 *handle, CU_IPC_MEM_LAZY_ENABLE_PEER_ACCESS);
	am_cuda_memhandle_cache_register(sbuf, handle,
					   length, epid, cuda_ipc_dev_ptr);
	return cuda_ipc_dev_ptr;
}

void
am_cuda_memhandle_release(CUdeviceptr cuda_ipc_dev_ptr)
{
	if(!cuda_memhandle_cache_enabled)
		PSMI_CUDA_CALL(cuIpcCloseMemHandle, cuda_ipc_dev_ptr);
	return;
}

#endif
