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

#include "psm_user.h"

/*
 *
 * System buffer (unexpected message) allocator
 *
 */

#define MM_FLAG_NONE  0
#define MM_FLAG_TRANSIENT  0x1
#define MM_NUM_OF_POOLS 7

struct psmi_mem_ctrl {
	struct psmi_mem_block_ctrl *free_list;
	uint32_t total_alloc;
	uint32_t current_available;
	uint32_t block_size;
	uint32_t flags;
	uint32_t replenishing_rate;
};

struct psmi_mem_block_ctrl {
	union {
		struct psmi_mem_ctrl *mem_handler;
		struct psmi_mem_block_ctrl *next;
	};
	char _redzone[PSM_VALGRIND_REDZONE_SZ];
};

struct psmi_sysbuf_allocator {
	int is_initialized;
	struct psmi_mem_ctrl handler_index[MM_NUM_OF_POOLS];
	uint64_t mem_ctrl_total_bytes;
};

static struct psmi_sysbuf_allocator psmi_sysbuf;


#if 0
/* There's a version with a basic wrapper around malloc, as a back up */
void *psmi_sysbuf_alloc(psm2_ep_t ep, uint32_t nbytes)
{
	return malloc(nbytes);
}

void psmi_sysbuf_free(psm2_ep_t ep, void *ptr)
{
	free(ptr);
}

#else

int psmi_sysbuf_init(void)
{
	int i;
	uint32_t block_sizes[] = { 256, 512, 1024,
		2048, 4096, 8192, (uint32_t) -1 };
	uint32_t replenishing_rate[] = { 128, 64, 32, 16, 8, 4, 0 };

	if (psmi_sysbuf.is_initialized)
		return PSM2_OK;

	for (i = 0; i < MM_NUM_OF_POOLS; i++) {
		psmi_sysbuf.handler_index[i].block_size = block_sizes[i];
		psmi_sysbuf.handler_index[i].current_available = 0;
		psmi_sysbuf.handler_index[i].free_list = NULL;
		psmi_sysbuf.handler_index[i].total_alloc = 0;
		psmi_sysbuf.handler_index[i].replenishing_rate =
			replenishing_rate[i];

		if (block_sizes[i] == -1) {
			psmi_assert_always(replenishing_rate[i] == 0);
			psmi_sysbuf.handler_index[i].flags =
				MM_FLAG_TRANSIENT;
		} else {
			psmi_assert_always(replenishing_rate[i] > 0);
			psmi_sysbuf.handler_index[i].flags = MM_FLAG_NONE;
		}
	}

	VALGRIND_CREATE_MEMPOOL(&psmi_sysbuf, PSM_VALGRIND_REDZONE_SZ,
				PSM_VALGRIND_MEM_UNDEFINED);

	/* Hit once on each block size so we have a pool that's allocated */
	for (i = 0; i < MM_NUM_OF_POOLS; i++) {
		void *ptr;
		if (block_sizes[i] == -1)
			continue;
		ptr = psmi_sysbuf_alloc(block_sizes[i]);
		psmi_assert(ptr);
		psmi_sysbuf_free(ptr);
	}

	return PSM2_OK;
}

void psmi_sysbuf_fini(void)
{
	struct psmi_mem_block_ctrl *block;
	struct psmi_mem_ctrl *handler_index;
	int i;

	if (!psmi_sysbuf.is_initialized)
		return;

	VALGRIND_DESTROY_MEMPOOL(&psmi_sysbuf);

	handler_index = psmi_sysbuf.handler_index;
	for (i = 0; i < MM_NUM_OF_POOLS; i++) {
		while ((block = handler_index[i].free_list) != NULL) {
			handler_index[i].free_list = block->next;
			psmi_free(block);
		}
	}
}

void psmi_sysbuf_getinfo(char *buf, size_t len)
{
	snprintf(buf, len - 1, "Sysbuf consumption: %" PRIu64 " bytes\n",
		 psmi_sysbuf.mem_ctrl_total_bytes);
	buf[len - 1] = '\0';
	return;
}

void *psmi_sysbuf_alloc(uint32_t alloc_size)
{
	struct psmi_mem_ctrl *mm_handler = psmi_sysbuf.handler_index;
	struct psmi_mem_block_ctrl *new_block;
	int replenishing;

	while (mm_handler->block_size < alloc_size)
		mm_handler++;

	replenishing = mm_handler->replenishing_rate;

	if (mm_handler->current_available == 0) { /* allocate more buffers */
		if (mm_handler->flags & MM_FLAG_TRANSIENT) {
			uint32_t newsz = alloc_size +
				sizeof(struct psmi_mem_block_ctrl) +
				PSM_VALGRIND_REDZONE_SZ;
			new_block = psmi_malloc(PSMI_EP_NONE,
					UNEXPECTED_BUFFERS, newsz);

			if (new_block) {
				new_block->mem_handler = mm_handler;
				new_block++;
				mm_handler->total_alloc++;
				psmi_sysbuf.mem_ctrl_total_bytes += newsz;
				VALGRIND_MEMPOOL_ALLOC(&psmi_sysbuf, new_block,
						       alloc_size);
			}
			return new_block;
		}

		do {
			uint32_t newsz =
			    mm_handler->block_size +
			    sizeof(struct psmi_mem_block_ctrl) +
			    PSM_VALGRIND_REDZONE_SZ;

			new_block = psmi_malloc(PSMI_EP_NONE,
					UNEXPECTED_BUFFERS, newsz);
			psmi_sysbuf.mem_ctrl_total_bytes += newsz;

			if (new_block) {
				mm_handler->current_available++;
				mm_handler->total_alloc++;

				new_block->next = mm_handler->free_list;
				mm_handler->free_list = new_block;
			}

		} while (--replenishing && new_block);
	}

	if (mm_handler->current_available) {
		mm_handler->current_available--;

		new_block = mm_handler->free_list;
		mm_handler->free_list = new_block->next;

		new_block->mem_handler = mm_handler;
		new_block++;

		VALGRIND_MEMPOOL_ALLOC(&psmi_sysbuf, new_block,
				mm_handler->block_size);
		return new_block;
	}

	return NULL;
}

void psmi_sysbuf_free(void *mem_to_free)
{
	struct psmi_mem_block_ctrl *block_to_free;
	struct psmi_mem_ctrl *mm_handler;

	block_to_free = (struct psmi_mem_block_ctrl *) mem_to_free - 1;
	mm_handler = block_to_free->mem_handler;

	VALGRIND_MEMPOOL_FREE(&psmi_sysbuf, mem_to_free);

	if (mm_handler->flags & MM_FLAG_TRANSIENT) {
		psmi_free(block_to_free);
	} else {
		block_to_free->next = mm_handler->free_list;
		mm_handler->free_list = block_to_free;

		mm_handler->current_available++;
	}

	return;
}
#endif


