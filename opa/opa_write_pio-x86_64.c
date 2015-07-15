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

/* This file contains the initialization functions used by the low
   level hfi protocol code. */

#include <sys/poll.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>

#include "ipserror.h"
#include "opa_user.h"

/*
 * These pio copy routines are here so they can be used by test code, as well
 * as by MPI, and can change independently of MPI
*/

/*
 * for processors that may not write store buffers in the order filled,
 * and when the store buffer is not completely filled (partial at end, or
 * interrupted and flushed) may write the partial buffer in
 * "random" order.  requires additional serialization
*/
void hfi_write_pio_force_order(volatile uint32_t *piob,
			       const struct hfi_pio_params *pioparm, void *hdr,
			       void *bdata)
{
	union hfi_pbc buf = {.qword = 0 };
	uint32_t cksum_len = pioparm->cksum_is_valid ?
	    HFI_CRC_SIZE_IN_BYTES : 0;

	buf.length =
	    __cpu_to_le16(((HFI_MESSAGE_HDR_SIZE + cksum_len +
			    pioparm->length) >> 2) + 1);
	if (pioparm->port > 1)
		buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) |
					     __PBC_IBPORT | pioparm->rate);
	else
		buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
					     pioparm->rate);

	*(volatile uint64_t *)piob = buf.qword;
	ips_wmb();		/* pbc must be forced to be first write to chip buffer */
	piob += 2;

	if (!pioparm->length) {
		uint32_t *dhdr, dcpywords;
		dcpywords = (HFI_MESSAGE_HDR_SIZE >> 2) - 1;
		hfi_dwordcpy_safe(piob, hdr, dcpywords);
		ips_wmb();
		dhdr = hdr;
		piob += dcpywords;
		dhdr += dcpywords;
		*piob++ = *dhdr;
	} else {
		uint32_t *pay2 = bdata, j;
		uint32_t len = pioparm->length;

		hfi_dwordcpy_safe(piob, hdr, HFI_MESSAGE_HDR_SIZE >> 2);
		piob += HFI_MESSAGE_HDR_SIZE >> 2;

		len >>= 2;
		if (len > 16) {
			uint32_t pay_words = 16 * ((len - 1) / 16);
			hfi_dwordcpy_safe(piob, pay2, pay_words);
			piob += pay_words;
			pay2 += pay_words;
			len -= pay_words;
		}
		/* now write the final chunk a word at a time, fence before trigger */
		for (j = 0; j < (len - 1); j++)
			*piob++ = *pay2++;
		ips_wmb();	/* flush the buffer out now, so */
		*piob++ = *pay2;
	}

	/* If checksum is enabled insert CRC at end of packet */
	if_pf(pioparm->cksum_is_valid) {
		int nCRCopies = HFI_CRC_SIZE_IN_BYTES >> 2;
		int nCRC = 0;

		while (nCRC < (nCRCopies - 1)) {
			*piob = pioparm->cksum;
			piob++;
			nCRC++;
		}

		ips_wmb();
		*piob = pioparm->cksum;
	}

	/* send it on it's way, now, rather than waiting for processor to
	 * get around to flushing it */
	ips_wmb();
}

/*
 * for processors that always write store buffers in the order filled,
 * and if store buffer not completely filled (partial at end, or
 * interrupted and flushed) always write the partial buffer in
 * address order.  Avoids serializing and flush instructions
 * where possible.
 */
void hfi_write_pio(volatile uint32_t *piob,
		   const struct hfi_pio_params *pioparm, void *hdr, void *bdata)
{
	union hfi_pbc buf = { 0 };
	uint32_t cksum_len = pioparm->cksum_is_valid ?
	    HFI_CRC_SIZE_IN_BYTES : 0;

	buf.length =
	    __cpu_to_le16(((HFI_MESSAGE_HDR_SIZE + cksum_len +
			    pioparm->length) >> 2) + 1);
	if (pioparm->port > 1)
		buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) |
					     __PBC_IBPORT | pioparm->rate);
	else
		buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
					     pioparm->rate);

	*(volatile uint64_t *)piob = buf.qword;
	piob += 2;
	asm volatile ("" :  :  : "memory");

	hfi_dwordcpy_safe(piob, hdr, HFI_MESSAGE_HDR_SIZE >> 2);

	asm volatile ("" :  :  : "memory");
	piob += HFI_MESSAGE_HDR_SIZE >> 2;

	if (pioparm->length)
		hfi_dwordcpy_safe(piob, (uint32_t *) bdata,
				  pioparm->length >> 2);

	/* If checksum is enabled insert CRC at end of packet */
	if_pf(pioparm->cksum_is_valid) {
		int nCRCopies = HFI_CRC_SIZE_IN_BYTES >> 2;
		int nCRC = 0;

		piob += pioparm->length >> 2;

		while (nCRC < (nCRCopies - 1)) {
			*piob = pioparm->cksum;
			piob++;
			nCRC++;
		}

		asm volatile ("" :  :  : "memory");
		*piob = pioparm->cksum;
	}

	/* send it on it's way, now, rather than waiting for processor to
	 * get around to flushing it */
	ips_wmb();
}

/*
 * here we trigger on a "special" address, so just bang it out
 * as fast as possible...
 */
static void
hfi_write_pio_special_trigger(volatile uint32_t *piob,
			      const struct hfi_pio_params *pioparm, void *hdr,
			      void *bdata, unsigned offset)
			      __attribute__ ((always_inline));

static void
hfi_write_pio_special_trigger(volatile uint32_t *piob,
			      const struct hfi_pio_params *pioparm,
			      void *hdr, void *bdata, unsigned offset)
{
	union hfi_pbc buf = { 0 };
	volatile uint32_t *piobs = piob;
	uint32_t cksum_len = pioparm->cksum_is_valid ?
	    HFI_CRC_SIZE_IN_BYTES : 0;

	buf.length =
	    __cpu_to_le16(((HFI_MESSAGE_HDR_SIZE + cksum_len +
			    pioparm->length) >> 2) + 1);
	if (pioparm->port > 1)
		buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) |
					     __PBC_IBPORT | pioparm->rate);
	else
		buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
					     pioparm->rate);

	*(volatile uint64_t *)piob = buf.qword;
	piob += 2;
	asm volatile ("" :  :  : "memory");

	hfi_dwordcpy_safe(piob, hdr, HFI_MESSAGE_HDR_SIZE >> 2);
	piob += HFI_MESSAGE_HDR_SIZE >> 2;
	asm volatile ("" :  :  : "memory");

	if (pioparm->length)
		hfi_dwordcpy_safe(piob, (uint32_t *) bdata,
				  pioparm->length >> 2);

	/* If checksum is enabled insert CRC at end of packet */
	if_pf(pioparm->cksum_is_valid) {
		int nCRCopies = HFI_CRC_SIZE_IN_BYTES >> 2;
		int nCRC = 0;

		piob += pioparm->length >> 2;

		while (nCRC < (nCRCopies - 1)) {
			*piob = pioparm->cksum;
			piob++;
			nCRC++;
		}

		asm volatile ("" :  :  : "memory");
		*piob = pioparm->cksum;
	}

	/*
	 * flush then write "special" then flush...
	 */
	ips_wmb();
	*(piobs + offset) = HFI_SPECIAL_TRIGGER_MAGIC;
	ips_wmb();
}

void hfi_write_pio_special_trigger2k(volatile uint32_t *piob,
				     const struct hfi_pio_params *pioparm,
				     void *hdr, void *bdata)
{
	hfi_write_pio_special_trigger(piob, pioparm, hdr, bdata, 1023);
}

void hfi_write_pio_special_trigger4k(volatile uint32_t *piob,
				     const struct hfi_pio_params *pioparm,
				     void *hdr, void *bdata)
{
	hfi_write_pio_special_trigger(piob, pioparm, hdr, bdata, 2047);
}
