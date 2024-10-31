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
#include "psm2_hal.h"
#include "ips_proto.h"
#include "ips_expected_proto.h"
#include "ips_proto_help.h"

void ips_proto_dump_frame(void *frame, int lenght, char *message)
{
	uint8_t *raw_frame = frame;
	int counter;
	char default_message[] = "<UNKNOWN>";

	if (!message)
		message = default_message;

	printf("\nHex dump of %i bytes at %p from %s\n", lenght, frame,
	       message);

	for (counter = 0; counter < lenght; counter++) {
		if ((counter % 16) == 0)
			printf("\n");

		if ((counter % 4) == 0)
			printf("   ");

		printf("%02X ", raw_frame[counter]);
	}
	printf("\n");
}

void ips_proto_dump_data(void *data, int data_length)
{
	int counter;
	uint8_t *payload = (uint8_t *) data;

	printf("\nHex dump of data, length = %i\n", data_length);

	for (counter = 0; counter < data_length; counter++) {
		if ((counter % 16) == 0)
			printf("\n %04d: ", counter);

		if ((counter % 4) == 0)
			printf("   ");

		printf("%02X ", payload[counter]);
	}
	printf("\n");
}

void ips_proto_show_header(struct ips_message_header *p_hdr, char *msg)
{
	psmi_seqnum_t ack_seq_num;

	printf("\nHeader decoding in hex: %s\n", msg ? msg : "");

	printf("LRH: VL4-LVer4-SL4-Res2-LNH2: %x\n",
	       __be16_to_cpu(p_hdr->lrh[0]));
	printf("LRH: DLID %x\n", __be16_to_cpu(p_hdr->lrh[1]));
	printf("LRH: Res4-PktLen12 %x\n", __be16_to_cpu(p_hdr->lrh[2]));
	printf("LRH: SLID %x\n", __be16_to_cpu(p_hdr->lrh[3]));

	printf("BTH: OpCode8-SE1-M1-PC2-TVer4-Pkey16 %x\n",
	       __be32_to_cpu(p_hdr->bth[0]));
	printf("BTH: F1-B1-Res6-DestQP24 %x\n", __be32_to_cpu(p_hdr->bth[1]));
	printf("BTH: A1-PSN31 %x\n", __be32_to_cpu(p_hdr->bth[2]));

	printf("IPH: jkey-hcrc %x\n", __le32_to_cpu(p_hdr->khdr.kdeth1));
	printf("IPH: kver-sh-intr-tidctrl-tid-om-offset %x\n",
	       __le32_to_cpu(p_hdr->khdr.kdeth0));

	printf("opcode %x\n", _get_proto_hfi_opcode(p_hdr));

	ack_seq_num.psn_num = p_hdr->ack_seq_num;
	if (GET_HFI_KHDR_TIDCTRL(__le32_to_cpu(p_hdr->khdr.kdeth0)))
		printf("TidFlow Flow: %x, Gen: %x, Seq: %x\n",
		       (__be32_to_cpu(p_hdr->bth[1]) >>
			HFI_BTH_FLOWID_SHIFT) & HFI_BTH_FLOWID_MASK,
		       (__be32_to_cpu(p_hdr->bth[2]) >>
			HFI_BTH_GEN_SHIFT) & HFI_BTH_GEN_MASK,
		       (__be32_to_cpu(p_hdr->bth[2]) >>
			HFI_BTH_SEQ_SHIFT) & HFI_BTH_SEQ_MASK);
	else if (ips_proto_flowid(p_hdr) == EP_FLOW_TIDFLOW)
		printf("ack_seq_num gen %x, seq %x\n",
		       ack_seq_num.psn_gen, ack_seq_num.psn_seq);
	else
		printf("ack_seq_num %x\n", ack_seq_num.psn_num);

	printf("src_rank/connidx %x\n", p_hdr->connidx);
	if (GET_HFI_KHDR_TIDCTRL(__le32_to_cpu(p_hdr->khdr.kdeth0)))
		printf("tid_session_gen %d\n", p_hdr->exp_rdescid_genc);
	printf("flags %x\n", p_hdr->flags);
}

/* linux doesn't have strlcat; this is a stripped down implementation */
/* not super-efficient, but we use it rarely, and only for short strings */
/* not fully standards conforming! */
static size_t psmi_strlcat(char *d, const char *s, size_t l)
{
	int dlen = strlen(d), slen, max;
	if (l <= dlen)		/* bug */
		return l;
	slen = strlen(s);
	max = l - (dlen + 1);
	if (slen > max)
		slen = max;
	memcpy(d + dlen, s, slen);
	d[dlen + slen] = '\0';
	return dlen + slen + 1;	/* standard says to return full length, not actual */
}

/* decode RHF errors; only used one place now, may want more later */
void ips_proto_get_rhf_errstring(uint32_t err, char *msg, size_t len)
{
	*msg = '\0';		/* if no errors, and so don't need to check what's first */

	if (err & PSMI_HAL_RHF_ERR_ICRC)
		psmi_strlcat(msg, "icrcerr ", len);
	if (err & PSMI_HAL_RHF_ERR_ECC)
		psmi_strlcat(msg, "eccerr ", len);
	if (err & PSMI_HAL_RHF_ERR_LEN)
		psmi_strlcat(msg, "lenerr ", len);
	if (err & PSMI_HAL_RHF_ERR_TID)
		psmi_strlcat(msg, "tiderr ", len);
	if (err & PSMI_HAL_RHF_ERR_DC)
		psmi_strlcat(msg, "dcerr ", len);
	if (err & PSMI_HAL_RHF_ERR_DCUN)
		psmi_strlcat(msg, "dcuncerr ", len);
	if (err & PSMI_HAL_RHF_ERR_KHDRLEN)
		psmi_strlcat(msg, "khdrlenerr ", len);
}

void ips_proto_dump_err_stats(struct ips_proto *proto)
{
	char err_stat_msg[2048];
	char tmp_buf[128];
	int len = sizeof(err_stat_msg);

	if (!(hfi_debug & __HFI_PKTDBG))
		return;

	*err_stat_msg = '\0';

	if (proto->error_stats.num_icrc_err ||
	    proto->error_stats.num_ecc_err ||
	    proto->error_stats.num_len_err ||
	    proto->error_stats.num_tid_err ||
	    proto->error_stats.num_dc_err ||
	    proto->error_stats.num_dcunc_err ||
	    proto->error_stats.num_khdrlen_err) {

		snprintf(tmp_buf, sizeof(tmp_buf), "ERROR STATS: ");

		if (proto->error_stats.num_icrc_err) {
			snprintf(tmp_buf, sizeof(tmp_buf), "ICRC: %" PRIu64 " ",
				 proto->error_stats.num_icrc_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}

		if (proto->error_stats.num_ecc_err) {
			snprintf(tmp_buf, sizeof(tmp_buf), "ECC: %" PRIu64 " ",
				 proto->error_stats.num_ecc_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}

		if (proto->error_stats.num_len_err) {
			snprintf(tmp_buf, sizeof(tmp_buf), "LEN: %" PRIu64 " ",
				 proto->error_stats.num_len_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}

		if (proto->error_stats.num_tid_err) {
			snprintf(tmp_buf, sizeof(tmp_buf), "TID: %" PRIu64 " ",
				 proto->error_stats.num_tid_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}

		if (proto->error_stats.num_dc_err) {
			snprintf(tmp_buf, sizeof(tmp_buf), "DC: %" PRIu64 " ",
				 proto->error_stats.num_dc_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}

		if (proto->error_stats.num_dcunc_err) {
			snprintf(tmp_buf, sizeof(tmp_buf),
				 "DCUNC: %" PRIu64 " ",
				 proto->error_stats.num_dcunc_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}

		if (proto->error_stats.num_khdrlen_err) {
			snprintf(tmp_buf, sizeof(tmp_buf),
				 "KHDRLEN: %" PRIu64 " ",
				 proto->error_stats.num_khdrlen_err);
			psmi_strlcat(err_stat_msg, tmp_buf, len);
		}
		psmi_strlcat(err_stat_msg, "\n", len);
	} else
		psmi_strlcat(err_stat_msg, "No previous errors.\n", len);

	_HFI_ERROR("%s", err_stat_msg);
}
