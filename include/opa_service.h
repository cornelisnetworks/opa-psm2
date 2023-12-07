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

#ifndef OPA_SERVICE_H
#define OPA_SERVICE_H

/* This file contains all the lowest level routines calling into sysfs */
/* and qib driver. All other calls are based on these routines. */

#include <libgen.h>

#include "opa_intf.h"
#include "opa_udebug.h"
#include "opa_byteorder.h"

/* upper and lower bounds for HFI port numbers */
#define HFI_MIN_PORT 1
#ifndef JKR
#warning WFR
#define HFI_MAX_PORT 1
#else
#define HFI_MAX_PORT 2
#endif
/* any unit id to match. */
#define HFI_UNIT_ID_ANY ((long)-1)
/* any port num to match. */
#define HFI_PORT_NUM_ANY ((long)0)

/* Statistics maintained by the driver */
int hfi_get_stats(uint64_t *, int);
int hfi_get_stats_names(char **namep);
/* Counters maintained in the chip, globally, and per-prot */
int hfi_get_ctrs_unit(int unitno, uint64_t *, int);
int hfi_get_ctrs_unit_names(int unitno, char **namep);
int hfi_get_ctrs_port(int unitno, int port, uint64_t *, int);
int hfi_get_ctrs_port_names(int unitno, char **namep);

/* sysfs helper routines (only those currently used are exported;
 * try to avoid using others) */

/* Initializes the following sysfs helper routines.
   sysfs_init() returns 0 on success, non-zero on an error: */
int sysfs_init(const char *dflt_hfi_class_path);
/* Complementary */
void sysfs_fini(void);

/* read a string value into buff, no more than size bytes.
   returns the number of bytes read */
size_t hfi_sysfs_unit_port_read(uint32_t unit, uint32_t port, const char *attr,
			char *buff, size_t size);

/* read up to one page of malloc'ed data (caller must free), returning
   number of bytes read or -1 */
int hfi_hfifs_read(const char *attr, char **datap);
int hfi_hfifs_unit_read(uint32_t unit, const char *attr, char **data);

int64_t hfi_sysfs_unit_read_node_s64(uint32_t unit);
/* these read directly into supplied buffer and take a count */
int hfi_hfifs_rd(const char *, void *, int);
int hfi_hfifs_unit_rd(uint32_t unit, const char *, void *, int);

#endif /* OPA_SERVICE_H */
