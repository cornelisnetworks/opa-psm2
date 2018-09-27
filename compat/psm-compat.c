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

#include <stdlib.h>
#include "../psm2.h"
#include "../psm2_mq.h"
#include "../psm2_am.h"

/* Functions from TS psm.h */
psm2_error_t
psm_init(int *major, int *minor)
{
  return psm2_init(major, minor);
}

psm2_error_t
psm_finalize(void)
{
  return psm2_finalize();
}

psm2_error_t
psm_map_nid_hostname(int num, const uint64_t *nids, const char **hostnames)
{
  return psm2_map_nid_hostname(num, nids, hostnames);
}

void
psm_epaddr_setlabel(psm2_epaddr_t epaddr, char const *epaddr_label)
{
  return psm2_epaddr_setlabel(epaddr, epaddr_label);
}

void
psm_epaddr_setctxt(psm2_epaddr_t epaddr, void *ctxt)
{
  psm2_epaddr_setctxt(epaddr, ctxt);
}

void *
psm_epaddr_getctxt(psm2_epaddr_t epaddr)
{
  return psm2_epaddr_getctxt(epaddr);
}

psm2_error_t
psm_setopt(psm2_component_t component, const void *component_obj,
       int optname, const void *optval, uint64_t optlen)
{
  return psm2_setopt(component, component_obj,
         optname, optval, optlen);
}

psm2_error_t
psm_getopt(psm2_component_t component, const void *component_obj,
       int optname, void *optval, uint64_t *optlen)
{
  return psm2_getopt(component, component_obj,
       optname, optval, optlen);
}

psm2_error_t
psm_poll(psm2_ep_t ep)
{
  return psm2_poll(ep);
}

void
psm_uuid_generate(psm2_uuid_t uuid_out)
{
    psm2_uuid_generate(uuid_out);
}

/* Functions from TS psm_am.h */
psm2_error_t
psm_am_register_handlers(psm2_ep_t ep,
       const psm2_am_handler_fn_t *handlers,
       int num_handlers, int *handlers_idx)
{
  return psm2_am_register_handlers(ep, handlers, num_handlers, handlers_idx);
}

psm2_error_t
psm_am_request_short(psm2_epaddr_t epaddr, psm2_handler_t handler,
           psm2_amarg_t *args, int nargs, void *src, size_t len,
           int flags, psm2_am_completion_fn_t completion_fn,
           void *completion_ctxt)
{
  return psm2_am_request_short(epaddr, handler, args, nargs, src, len, flags, completion_fn, completion_ctxt);
}

psm2_error_t
psm_am_reply_short(psm2_am_token_t token, psm2_handler_t handler,
         psm2_amarg_t *args, int nargs, void *src, size_t len,
         int flags, psm2_am_completion_fn_t completion_fn,
         void *completion_ctxt)
{
  return psm2_am_reply_short(token, handler, args, nargs, src, len, flags, completion_fn, completion_ctxt);
}

psm2_error_t
psm_am_get_parameters(psm2_ep_t ep, struct psm2_am_parameters *parameters,
      size_t sizeof_parameters_in,
      size_t *sizeof_parameters_out)
{
  return psm2_am_get_parameters(ep, parameters, sizeof_parameters_in, sizeof_parameters_out);
}


/* Functions from TS psm_error.h */

psm2_error_t
psm_error_defer(psm2_error_token_t token)
{
  return psm2_error_defer(token);
}

psm2_error_t
psm_error_register_handler(psm2_ep_t ep, const psm2_ep_errhandler_t errhandler)
{
  return psm2_error_register_handler(ep, errhandler);
}

const char *
psm_error_get_string(psm2_error_t error)
{
  return psm2_error_get_string(error);
}

/* Functions from TS psm_mq.h */
psm2_error_t
psm_mq_iprobe(psm2_mq_t mq, uint64_t tag, uint64_t tagsel, psm2_mq_status_t *status)
{
  return psm2_mq_iprobe(mq, tag, tagsel, status);
}

psm2_error_t
psm_mq_cancel(psm2_mq_req_t *ireq)
{
  return psm2_mq_cancel(ireq);
}

psm2_error_t
psm_mq_wait(psm2_mq_req_t *ireq, psm2_mq_status_t *status)
{
  return psm2_mq_wait(ireq, status);
}

psm2_error_t
psm_mq_test(psm2_mq_req_t *ireq, psm2_mq_status_t *status)
{
  return psm2_mq_test(ireq, status);
}

psm2_error_t
psm_mq_isend(psm2_mq_t mq, psm2_epaddr_t dest, uint32_t flags, uint64_t stag,
       const void *buf, uint32_t len, void *context, psm2_mq_req_t *req)
{
  return psm2_mq_isend(mq, dest, flags, stag, buf, len, context, req);
}

psm2_error_t
psm_mq_send(psm2_mq_t mq, psm2_epaddr_t dest, uint32_t flags, uint64_t stag,
      const void *buf, uint32_t len)
{
  return psm2_mq_send(mq, dest, flags, stag, buf, len);
}

psm2_error_t
psm_mq_irecv(psm2_mq_t mq, uint64_t tag, uint64_t tagsel, uint32_t flags,
        void *buf, uint32_t len, void *context, psm2_mq_req_t *reqo)
{
  return psm2_mq_irecv(mq, tag, tagsel, flags, buf, len, context, reqo);
}

psm2_error_t
psm_mq_ipeek(psm2_mq_t mq, psm2_mq_req_t *oreq, psm2_mq_status_t *status)
{
  return psm2_mq_ipeek(mq, oreq, status);
}

psm2_error_t
psm_mq_getopt(psm2_mq_t mq, int key, void *value)
{
  return psm2_mq_getopt(mq, key, value);
}

psm2_error_t
psm_mq_setopt(psm2_mq_t mq, int key, const void *value)
{
  return psm2_mq_setopt(mq, key, value);
}

psm2_error_t
psm_mq_init(psm2_ep_t ep, uint64_t tag_order_mask,
      const struct psm2_optkey *opts,
      int numopts, psm2_mq_t *mqo)
{
  return psm2_mq_init(ep, tag_order_mask, opts, numopts, mqo);
}

psm2_error_t
psm_mq_finalize(psm2_mq_t mq)
{
  return psm2_mq_finalize(mq);
}

void
psm_mq_get_stats(psm2_mq_t mq, psm2_mq_stats_t *stats)
{
  psm2_mq_get_stats(mq, stats);
}

/* Functions from TS psm_mq.h */
psm2_error_t
psm_ep_num_devunits(uint32_t *num_units_o)
{
  return psm2_ep_num_devunits(num_units_o);
}

uint64_t
psm_epid_nid(psm2_epid_t epid)
{
  return psm2_epid_nid(epid);
}

uint64_t
psm_epid_context(psm2_epid_t epid)
{
  return psm2_epid_context(epid);
}

uint64_t
psm_epid_port(psm2_epid_t epid)
{
  return psm2_epid_port(epid);
}

psm2_error_t
psm_ep_query (int *num_of_epinfo, psm2_epinfo_t *array_of_epinfo)
{
  return psm2_ep_query (num_of_epinfo, array_of_epinfo);
}

psm2_error_t
psm_ep_epid_lookup (psm2_epid_t epid, psm2_epconn_t *epconn)
{
  return psm2_ep_epid_lookup (epid, epconn);
}

psm2_error_t
psm_ep_epid_share_memory(psm2_ep_t ep, psm2_epid_t epid, int *result_o)
{
  return psm2_ep_epid_share_memory(ep, epid, result_o);
}

psm2_error_t
psm_ep_open_opts_get_defaults(struct psm2_ep_open_opts *opts)
{
  return psm2_ep_open_opts_get_defaults(opts);
}

psm2_error_t
psm_ep_open(psm2_uuid_t const unique_job_key, struct psm2_ep_open_opts const *opts_i,
      psm2_ep_t *epo, psm2_epid_t *epido)
{
  return psm2_ep_open(unique_job_key, opts_i, epo, epido);
}

psm2_error_t
psm_ep_close(psm2_ep_t ep, int mode, int64_t timeout_in)
{
  return psm2_ep_close(ep, mode, timeout_in);
}

psm2_error_t
psm_ep_connect(psm2_ep_t ep, int num_of_epid,
          psm2_epid_t const *array_of_epid,
          int const *array_of_epid_mask,
          psm2_error_t  *array_of_errors,
          psm2_epaddr_t *array_of_epaddr,
          int64_t timeout)
{
  return psm2_ep_connect(ep, num_of_epid, array_of_epid, array_of_epid_mask,
            array_of_errors, array_of_epaddr, timeout);
}
