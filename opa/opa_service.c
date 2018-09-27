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

/* This file contains hfi service routine interface used by the low
   level hfi protocol code. */

#include "opa_service.h"
#include "psmi_wrappers.h"

/* These have been fixed to read the values, but they are not
 * compatible with the hfi driver, they return new info with
 * the qib driver
 */
static int hfi_count_names(const char *namep)
{
	int n = 0;
	while (*namep != '\0') {
		if (*namep == '\n')
			n++;
		namep++;
	}
	return n;
}

int hfi_get_ctrs_unit_names(int unitno, char **namep)
{
	int i;
	i = hfi_hfifs_unit_read(unitno, "counter_names", namep);
	if (i < 0)
		return -1;
	else
		return hfi_count_names(*namep);
}

int hfi_get_ctrs_unit(int unitno, uint64_t *c, int nelem)
{
	int i;
	i = hfi_hfifs_unit_rd(unitno, "counters", c, nelem * sizeof(*c));
	if (i < 0)
		return -1;
	else
		return i / sizeof(*c);
}

int hfi_get_ctrs_port_names(int unitno, char **namep)
{
	int i;
	i = hfi_hfifs_unit_read(unitno, "portcounter_names", namep);
	if (i < 0)
		return -1;
	else
		return hfi_count_names(*namep);
}

int hfi_get_ctrs_port(int unitno, int port, uint64_t *c, int nelem)
{
	int i;
	char buf[32];
	snprintf(buf, sizeof(buf), "port%dcounters", port);
	i = hfi_hfifs_unit_rd(unitno, buf, c, nelem * sizeof(*c));
	if (i < 0)
		return -1;
	else
		return i / sizeof(*c);
}

int hfi_get_stats_names(char **namep)
{
	int i;
	i = hfi_hfifs_read("driver_stats_names", namep);
	if (i < 0)
		return -1;
	else
		return hfi_count_names(*namep);
}

int hfi_get_stats(uint64_t *s, int nelem)
{
	int i;
	i = hfi_hfifs_rd("driver_stats", s, nelem * sizeof(*s));
	if (i < 0)
		return -1;
	else
		return i / sizeof(*s);
}
