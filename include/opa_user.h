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

#ifndef OPA_USER_H
#define OPA_USER_H

/* This file contains all of the data structures and routines that are
   publicly visible and usable (to low level infrastructure code; it is
   not expected that any application, or even normal application-level library,
   will ever need to use any of this).

   Additional entry points and data structures that are used by these routines
   may be referenced in this file, but they should not be generally available;
   they are visible here only to allow use in inlined functions.  Any variable,
   data structure, or function that starts with a leading "_" is in this
   category.
*/

/* Include header files we need that are unlikely to otherwise be needed by */
/* programs. */
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <syslog.h>
#include "opa_intf.h"
#include "opa_common.h"
#include "opa_byteorder.h"
#include "opa_udebug.h"
#include "opa_service.h"

/*
 * The next set of defines are for packet headers, and chip register
 * and memory bits that are visible to and/or used by user-mode software
 * The other bits that are used only by the driver or diags are in
 * hfi_registers.h
 */

/* RcvHdrFlags bits */
#define HFI_RHF_LENGTH_MASK 0xFFF
#define HFI_RHF_LENGTH_SHIFT 0
#define HFI_RHF_RCVTYPE_MASK 0x7
#define HFI_RHF_RCVTYPE_SHIFT 12
#define HFI_RHF_USE_EGRBFR_MASK 0x1
#define HFI_RHF_USE_EGRBFR_SHIFT 15
#define HFI_RHF_EGRBFR_INDEX_MASK 0x7FF
#define HFI_RHF_EGRBFR_INDEX_SHIFT 16
#define HFI_RHF_SEQ_MASK 0xF
#define HFI_RHF_SEQ_SHIFT 28

#define HFI_RHF_EGRBFR_OFFSET_MASK 0xFFF
#define HFI_RHF_EGRBFR_OFFSET_SHIFT 0
#define HFI_RHF_HDRQ_OFFSET_MASK 0x1FF
#define HFI_RHF_HDRQ_OFFSET_SHIFT 12

#define HFI_RHF_ICRCERR 0x80000000
#define HFI_RHF_ECCERR 0x20000000
#define HFI_RHF_LENERR 0x10000000
#define HFI_RHF_TIDERR 0x08000000

#define HFI_RHF_TFGENERR 0x04000000
#define HFI_RHF_TFSEQERR 0x02000000
#define HFI_RHF_RCVTYPEERR 0x07000000

#define HFI_RHF_DCERR 0x00800000
#define HFI_RHF_DCUNCERR 0x00400000
#define HFI_RHF_KHDRLENERR 0x00200000
/* Change from 0xFFE00000 to 0xFDE00000, so that we don't commit to the
 * error path on a SeqErr too soon - with RSM, the HFI may report a
 * false SeqErr condition */
#define HFI_RHF_ERR_MASK 0xFDE00000

/* TidFlow related bits */
#define HFI_TF_SEQNUM_SHIFT                 0
#define HFI_TF_SEQNUM_MASK                  0x7ff
#define HFI_TF_GENVAL_SHIFT                 11
#define HFI_TF_GENVAL_MASK                  0xfffff

#define HFI_TF_FLOWVALID_SHIFT              32
#define HFI_TF_FLOWVALID_MASK               0x1
#define HFI_TF_HDRSUPP_ENABLED_SHIFT        33
#define HFI_TF_HDRSUPP_ENABLED_MASK         0x1

#define HFI_TF_KEEP_AFTER_SEQERR_SHIFT      34
#define HFI_TF_KEEP_AFTER_SEQERR_MASK       0x1
#define HFI_TF_KEEP_ON_GENERR_SHIFT         35
#define HFI_TF_KEEP_ON_GENERR_MASK          0x1
#define HFI_TF_KEEP_PAYLOAD_ON_GENERR_SHIFT 36
#define HFI_TF_KEEP_PAYLOAD_ON_GENERR_MASK  0x1
#define HFI_TF_STATUS_SHIFT                 37
#define HFI_TF_STATUS_MASK                  0x3
#define HFI_TF_STATUS_SEQMISMATCH_SHIFT     37
#define HFI_TF_STATUS_SEQMISMATCH_MASK      0x1
#define HFI_TF_STATUS_GENMISMATCH_SHIFT     38
#define HFI_TF_STATUS_GENMISMATCH_MASK      0x1

#define HFI_TF_INVALID			    (~0U)
#define HFI_TF_INVALID_GENERATION	    (~0U)
#define HFI_TF_NFLOWS                       32

/* PBC bits */
#define HFI_PBC_STATICRCC_SHIFT         0
#define HFI_PBC_STATICRCC_MASK          0xffff

#define HFI_PBC_SC4_SHIFT               4
#define HFI_PBC_SC4_MASK                0x1

#define HFI_PBC_INTR_SHIFT              31
#define HFI_PBC_DCINFO_SHIFT            30
#define HFI_PBC_TESTEBP_SHIFT           29
#define HFI_PBC_PACKETBYPASS_SHIFT      28
#define HFI_PBC_INSERTHCRC_SHIFT        26
#define HFI_PBC_INSERTHCRC_MASK         0x3
#define HFI_PBC_CREDITRETURN_SHIFT      25
#define HFI_PBC_INSERTBYPASSICRC_SHIFT  24
#define HFI_PBC_TESTBADICRC_SHIFT       23
#define HFI_PBC_FECN_SHIFT              22
#define HFI_PBC_VL_SHIFT                12
#define HFI_PBC_VL_MASK                 0xf
#define HFI_PBC_LENGTHDWS_SHIFT         0
#define HFI_PBC_LENGTHDWS_MASK          0xfff

/* IB - LRH header consts */
#define HFI_LRH_GRH 0x0003	/* 1. word of IB LRH - next header: GRH */
#define HFI_LRH_BTH 0x0002	/* 1. word of IB LRH - next header: BTH */
#define HFI_LRH_SC_SHIFT 12
#define HFI_LRH_SC_MASK 0xf
#define HFI_LRH_LVER_SHIFT 8
#define HFI_LRH_LVER_MASK 0xf
#define HFI_LRH_SL_SHIFT 4
#define HFI_LRH_SL_MASK 0xf
#define HFI_LRH_PKTLEN_MASK 0xfff

/* IB - BTH header consts */
#define HFI_BTH_OPCODE_SHIFT 24
#define HFI_BTH_OPCODE_MASK 0xff
#define HFI_BTH_SE_SHIFT 23
#define HFI_BTH_MIGREQ_SHIFT 22
#define HFI_BTH_EXTRA_BYTE_SHIFT 20
#define HFI_BTH_EXTRA_BYTE_MASK 3
#define HFI_BTH_TVER_SHIFT 16
#define HFI_BTH_TVER_MASK 0xF

#define HFI_BTH_BECN_SHIFT 30
#define HFI_BTH_FECN_SHIFT 31
#define HFI_BTH_QP_SHIFT 16
#define HFI_BTH_QP_MASK 0xff
#define HFI_BTH_FLOWID_SHIFT 11
#define HFI_BTH_FLOWID_MASK 0x1f
#define HFI_BTH_SUBCTXT_SHIFT 8
#define HFI_BTH_SUBCTXT_MASK 0x7

#define HFI_BTH_SEQ_SHIFT 0
#define HFI_BTH_SEQ_MASK 0x7ff
#define HFI_BTH_GEN_SHIFT 11
#define HFI_BTH_GEN_MASK 0xfffff
#define HFI_BTH_ACK_SHIFT 31

/* KDETH header consts */
#define HFI_KHDR_OFFSET_MASK 0x7fff
#define HFI_KHDR_OM_SHIFT 15
#define HFI_KHDR_TID_SHIFT 16
#define HFI_KHDR_TID_MASK 0x3ff
#define HFI_KHDR_TIDCTRL_SHIFT 26
#define HFI_KHDR_TIDCTRL_MASK 0x3
#define HFI_KHDR_INTR_SHIFT 28
#define HFI_KHDR_SH_SHIFT 29
#define HFI_KHDR_KVER_SHIFT 30
#define HFI_KHDR_KVER_MASK 0x3

#define HFI_KHDR_MSGSEQ_MASK 0xffff
#define HFI_KHDR_TINYLEN_MASK 0xf
#define HFI_KHDR_TINYLEN_SHIFT 16
#define HFI_KHDR_EGRFLAGS_SHIFT 20
#define HFI_KHDR_EGRFLAGS_MASK 0x3f

#define GET_HFI_KHDR_TIDCTRL(val) \
	(((val) >> HFI_KHDR_TIDCTRL_SHIFT) & \
	HFI_KHDR_TIDCTRL_MASK)

#ifdef PSM_CUDA
extern int is_driver_gpudirect_enabled;

static __inline__ int _psmi_is_driver_gpudirect_enabled() __attribute__((always_inline));

static __inline__ int
_psmi_is_driver_gpudirect_enabled()
{
	return is_driver_gpudirect_enabled;
}
#define PSMI_IS_DRIVER_GPUDIRECT_ENABLED _psmi_is_driver_gpudirect_enabled()
#endif

/* this portion only defines what we currently use */
struct hfi_pbc {
	__u32 pbc0;
	__u16 PbcStaticRateControlCnt;
	__u16 fill1;
};

/* hfi kdeth header format */
struct hfi_kdeth {
	__u32 kdeth0;

	union {
		struct {
			__u16 job_key;
			__u16 hcrc;
		};
		__u32 kdeth1;
	};
};

/* misc. */
#define HFI_CRC_SIZE_IN_BYTES 4
#define HFI_PCB_SIZE_IN_BYTES 8

#define HFI_EAGER_TIDCTRL 0x0

#define HFI_DEFAULT_SERVICE_ID 0x1000117500000000ULL
#define HFI_DEFAULT_P_KEY 0x8001 /* fabric default pkey for app traffic */

#if 0
#define HFI_PERMISSIVE_LID 0xFFFF
#define HFI_AETH_CREDIT_SHIFT 24
#define HFI_AETH_CREDIT_MASK 0x1F
#define HFI_AETH_CREDIT_INVAL 0x1F
#define HFI_PSN_MASK 0xFFFFFF
#define HFI_MSN_MASK 0xFFFFFF
#define HFI_QPN_MASK 0xFFFFFF
#define HFI_MULTICAST_LID_BASE 0xC000
#define HFI_MULTICAST_QPN 0xFFFFFF
#endif

/* Receive Header Queue: receive type (from hfi) */
#define RCVHQ_RCV_TYPE_EXPECTED  0
#define RCVHQ_RCV_TYPE_EAGER     1
#define RCVHQ_RCV_TYPE_NON_KD    2
#define RCVHQ_RCV_TYPE_ERROR     3

/* OPA PSM assumes that the message header is always 56 bytes. */
#define HFI_MESSAGE_HDR_SIZE	56
/* Usable bytes in header (hdrsize - lrh - bth) */
#define HFI_MESSAGE_HDR_SIZE_HFI       (HFI_MESSAGE_HDR_SIZE-20)
/* SPIO includes 8B PBC and message header */
#define HFI_SPIO_HDR_SIZE      (8+56)
/*
 * SDMA includes 8B sdma hdr, 8B PBC, and message header.
 * If we are using GPU workloads, we need to set a new
 * "flags" member which takes another 2 bytes in the
 * sdma hdr. We let the driver know of this 2 extra bytes
 * at runtime when we set the length for the iovecs.
 */
#define HFI_SDMA_HDR_SIZE      (8+8+56)

/* functions for extracting fields from rcvhdrq entries for the driver.
 */
static inline __u32 hfi_hdrget_err_flags(const __le32 *rbuf)
{
	return __le32_to_cpu(rbuf[1]) & HFI_RHF_ERR_MASK;
}

static inline __u32 hfi_hdrget_rcv_type(const __le32 *rbuf)
{
	return (__le32_to_cpu(rbuf[0]) >> HFI_RHF_RCVTYPE_SHIFT)
	    & HFI_RHF_RCVTYPE_MASK;
}

static inline __u32 hfi_hdrget_length_in_bytes(const __le32 *rbuf)
{
	return ((__le32_to_cpu(rbuf[0]) >> HFI_RHF_LENGTH_SHIFT)
		& HFI_RHF_LENGTH_MASK) << 2;
}

static inline __u32 hfi_hdrget_egrbfr_index(const __le32 *rbuf)
{
	return (__le32_to_cpu(rbuf[0]) >> HFI_RHF_EGRBFR_INDEX_SHIFT)
	    & HFI_RHF_EGRBFR_INDEX_MASK;
}

static inline __u32 hfi_hdrget_seq(const __le32 *rbuf)
{
	return (__le32_to_cpu(rbuf[0]) >> HFI_RHF_SEQ_SHIFT)
	    & HFI_RHF_SEQ_MASK;
}

static inline __u32 hfi_hdrget_hdrq_offset(const __le32 *rbuf)
{
	return (__le32_to_cpu(rbuf[1]) >> HFI_RHF_HDRQ_OFFSET_SHIFT)
	    & HFI_RHF_HDRQ_OFFSET_MASK;
}

static inline __u32 hfi_hdrget_egrbfr_offset(const __le32 *rbuf)
{
	return (__le32_to_cpu(rbuf[1]) >> HFI_RHF_EGRBFR_OFFSET_SHIFT)
	    & HFI_RHF_EGRBFR_OFFSET_MASK;
}

static inline __u32 hfi_hdrget_use_egrbfr(const __le32 *rbuf)
{
	return (__le32_to_cpu(rbuf[0]) >> HFI_RHF_USE_EGRBFR_SHIFT)
	    & HFI_RHF_USE_EGRBFR_MASK;
}

/* interval timing routines */
/* Convert a count of cycles to elapsed nanoseconds */
/* this is only accurate for reasonably large numbers of cycles (at least tens)
*/
static __inline__ uint64_t cycles_to_nanosecs(uint64_t)
					  __attribute__ ((always_inline));
/* convert elapsed nanoseconds to elapsed cycles */
/* this is only accurate for reasonably large numbers of nsecs (at least tens)
*/
static __inline__ uint64_t nanosecs_to_cycles(uint64_t)
					  __attribute__ ((always_inline));
/* get current count of nanoseconds from unspecified base value (only useful
   for intervals) */
static __inline__ uint64_t get_nanoseconds() __attribute__ ((always_inline));

struct _hfi_ctrl {
	int32_t fd;		/* device file descriptor */
	/* tidflow valid */
	uint32_t __hfi_tfvalid;
	/* unit id */
	uint32_t __hfi_unit;
	/* port id */
	uint32_t __hfi_port;

	/* number of eager tid entries */
	uint32_t __hfi_tidegrcnt;
	/* number of expected tid entries */
	uint32_t __hfi_tidexpcnt;

	/* effective mtu size, should be <= base_info.mtu */
	uint32_t __hfi_mtusize;
	/* max PIO size, should be <= effective mtu size */
	uint32_t __hfi_piosize;

	/* two struct output from driver. */
	struct hfi1_ctxt_info ctxt_info;
	struct hfi1_base_info base_info;

	/* some local storages in some condition: */
	/* as storage of __hfi_rcvtidflow in hfi_userinit(). */
	__le64 regs[HFI_TF_NFLOWS];

	/* location to which OPA writes the rcvhdrtail register whenever
	   it changes, so that no chip registers are read in the performance
	   path. */
	volatile __le64 *__hfi_rcvtail;

	/* address where ur_rcvhdrtail is written */
	volatile __le64 *__hfi_rcvhdrtail;
	/* address where ur_rcvhdrhead is written */
	volatile __le64 *__hfi_rcvhdrhead;
	/* address where ur_rcvegrindextail is read */
	volatile __le64 *__hfi_rcvegrtail;
	/* address where ur_rcvegrindexhead is written */
	volatile __le64 *__hfi_rcvegrhead;
	/* address where ur_rcvegroffsettail is read */
	volatile __le64 *__hfi_rcvofftail;
	/* address where ur_rcvtidflow is written */
	volatile __le64 *__hfi_rcvtidflow;
};

/* After the device is opened, hfi_userinit() is called to give the driver the
   parameters the user code wants to use, and to get the implementation values,
   etc. back.  0 is returned on success, a positive value is a standard errno,
   and a negative value is reserved for future use.  The first argument is
   the filedescriptor returned by the device open.

   It is allowed to have multiple devices (and of different types)
   simultaneously opened and initialized, although this won't be fully
   implemented initially.  This routine is used by the low level
   hfi protocol code (and any other code that has similar low level
   functionality).
   This is the only routine that takes a file descriptor, rather than an
   struct _hfi_ctrl *.  The struct _hfi_ctrl * used for everything
   else is returned by this routine.
*/

struct _hfi_ctrl *hfi_userinit(int32_t, struct hfi1_user_info_dep *);

/* don't inline these; it's all init code, and not inlining makes the */
/* overall code shorter and easier to debug */
void hfi_touch_mmap(void *, size_t) __attribute__ ((noinline));

/* set the BTH pkey to check for this process. */
/* This is for receive checks, not for sends.  It isn't necessary
   to set the default key, that's always allowed by the hardware.
   If too many pkeys are in use for the hardware to support, this
   will return EAGAIN, and the caller should then fail and exit
   or use the default key and check the pkey in the received packet
   checking. */
int32_t hfi_set_pkey(struct _hfi_ctrl *, uint16_t);

/* flush the eager buffers, by setting the
   eager index head register == eager index tail, if queue is full */
void hfi_flush_egr_bufs(struct _hfi_ctrl *ctrl);

int hfi_wait_for_packet(struct _hfi_ctrl *);

/* stop_start == 0 disables receive on the context, for use in queue overflow
   conditions.  stop_start==1 re-enables, and returns value of tail register,
   to be used to re-init the software copy of the head register */
int hfi_manage_rcvq(struct _hfi_ctrl *ctrl, uint32_t stop_start);

/* ctxt_bp == 0 disables fabric back pressure on the context. */
/* ctxt_bp == 1 enables fabric back pressure on the context. */
int hfi_manage_bp(struct _hfi_ctrl *ctrl, uint8_t ctxt_bp);

/* enable == 1 enables armlaunch (normal), 0 disables (only used */
/* hfi_pkt_test -B at the moment, needed for linda). */
int hfi_armlaunch_ctrl(struct _hfi_ctrl *ctrl, uint32_t enable);

/* force an update of the PIOAvail register to memory */
int hfi_force_pio_avail_update(struct _hfi_ctrl *ctrl);

/* Disarm any send buffers which need disarming. */
int hfi_disarm_bufs(struct _hfi_ctrl *ctrl);

/* New user event mechanism, using spi_sendbuf_status HFI_EVENT_* bits
   obsoletes hfi_disarm_bufs(), and extends it, although old mechanism
   remains for binary compatibility. */
int hfi_event_ack(struct _hfi_ctrl *ctrl, __u64 ackbits);

/* Return send dma's current "in flight counter " */
int hfi_sdma_inflight(struct _hfi_ctrl *ctrl, uint32_t *counter);

/* Return send dma's current "completion counter" */
int hfi_sdma_complete(struct _hfi_ctrl *ctrl, uint32_t *counter);

/* set whether we want an interrupt on all packets, or just urgent ones */
int hfi_poll_type(struct _hfi_ctrl *ctrl, uint16_t poll_type);

/* set send context pkey to verify, error if driver is not configured with */
/* this pkey in its pkey table. */
int hfi_set_pkey(struct _hfi_ctrl *ctrl, uint16_t pkey);

/* reset halted send context, error if context is not halted. */
int hfi_reset_context(struct _hfi_ctrl *ctrl);

/* Statistics maintained by the driver */
const char *hfi_get_next_name(char **names);
uint64_t hfi_get_single_stat(const char *attr, uint64_t *s);
int hfi_get_stats_names_count(void);
/* Counters maintained in the chip, globally, and per-prot */
int hfi_get_ctrs_unit_names_count(int unitno);
int hfi_get_ctrs_port_names_count(int unitno);

uint64_t hfi_get_single_unitctr(int unit, const char *attr, uint64_t *s);
int hfi_get_single_portctr(int unit, int port, const char *attr, uint64_t *c);
void hfi_release_names(char *namep);

/* Syslog wrapper

   level is one of LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING,
   LOG_NOTICE, LOG_INFO, LOG_DEBUG.

   prefix should be a short string to describe which part of the software stack
   is using syslog, i.e. "PSM", "mpi", "mpirun".
*/
void hfi_syslog(const char *prefix, int to_console, int level,
		const char *format, ...)
		__attribute__((format(printf, 4, 5)));

void hfi_vsyslog(const char *prefix, int to_console, int level,
		 const char *format, va_list ap);

/* parameters for PBC for pio write routines, to avoid passing lots
 * of args; we instead pass the structure pointer.  */
struct hfi_pio_params {
	uint16_t length;
	uint8_t vl;
	uint8_t port;
	uint32_t cksum_is_valid;
	uint32_t cksum;
	uint32_t rate;
};

/* write pio buffers.  The hfi_write_pio_force_order() version assumes
   that the processor does not write store buffers to i/o devices in the
   order in which they are writte, and that when flushing partially
   filled store buffers, the words are not ordered either.   The hfi_write_pio()
   form is used when the processor writes store buffers to i/o in the order
   in which they are filled, and writes partially filled buffers in increasing
   address order (assuming they are filled that way).
   The arguments are pio buffer address, payload length, header, and payload
*/
void hfi_write_pio(volatile uint32_t *, const struct hfi_pio_params *,
		   void *, void *);
void hfi_write_pio_force_order(volatile uint32_t *,
			       const struct hfi_pio_params *, void *, void *);

#define HFI_SPECIAL_TRIGGER_MAGIC        0xaebecede
/* IBA7220 can use a "Special" trigger.  We write to the last dword
   in the mapped SendBuf to trigger the launch. */
void hfi_write_pio_special_trigger2k(volatile uint32_t *,
				     const struct hfi_pio_params *, void *,
				     void *);
void hfi_write_pio_special_trigger4k(volatile uint32_t *,
				     const struct hfi_pio_params *, void *,
				     void *);

/*
 * Copy routine that may copy a byte multiple times but optimized for througput
 * This is not safe to use for PIO routines where we want a guarantee that a
 * byte is only copied/moved across the bus once.
 */
void hfi_dwordcpy(volatile uint32_t *dest, const uint32_t *src,
		  uint32_t ndwords);
void hfi_qwordcpy(volatile uint64_t *dest, const uint64_t *src,
		  uint32_t nqwords);

/*
* Safe version of hfi_[d/q]wordcpy that is guaranteed to only copy each byte once.
*/
#if defined(__x86_64__)
void hfi_dwordcpy_safe(volatile uint32_t *dest, const uint32_t *src,
		       uint32_t ndwords);
void hfi_qwordcpy_safe(volatile uint64_t *dest, const uint64_t *src,
		       uint32_t nqwords);
#else
#define hfi_dwordcpy_safe hfi_dwordcpy
#define hfi_qwordcpy_safe hfi_qwordcpy
#endif

/* From here to the end of the file are implementation details that should not
   be used outside this file (other than to call the function), except in the
   one infrastructure file in which they are defined.

   NOTE:  doing paired 32 bit writes to the chip to store 64 bit values (as
   from 32 bit programs) will not work correctly, because there is no sub-qword
   address decode.  Therefore 32 bit programs use only a single 32 bit store;
   the head register values are all less than 32 bits, anyway.   Given that, we
   use only 32 bits even for 64 bit programs, for simplicity.  These functions
   must not be called until after hfi_userinit() is called.  The ctrl argument
   is currently unused, but remains useful for adding debug code.
*/

static __inline__ void hfi_put_rcvegrindexhead(struct _hfi_ctrl *ctrl,
					   uint64_t val)
{
	*ctrl->__hfi_rcvegrhead = __cpu_to_le64(val);
}

static __inline__ void hfi_put_rcvhdrhead(struct _hfi_ctrl *ctrl, uint64_t val)
{
	*ctrl->__hfi_rcvhdrhead = __cpu_to_le64(val);
}

static __inline__ uint64_t hfi_get_rcvhdrtail(struct _hfi_ctrl *ctrl)
{
	uint64_t res = __le64_to_cpu(*ctrl->__hfi_rcvtail);
	ips_rmb();
	return res;
}

static __inline__ void hfi_tidflow_set_entry(struct _hfi_ctrl *ctrl,
					 uint32_t flowid, uint32_t genval,
					 uint32_t seqnum)
{
/* For proper behavior with RSM interception of FECN packets for CCA,
 * the tidflow entry needs the KeepAfterSequenceError bit set.
 * A packet that is converted from expected to eager by RSM will not
 * trigger an update in the tidflow state.  This will cause the tidflow
 * to incorrectly report a sequence error on any non-FECN packets that
 * arrive after the RSM intercepted packets.  If the KeepAfterSequenceError
 * bit is set, PSM can properly detect this "false SeqErr" condition,
 * and recover without dropping packets.
 * Note that if CCA/RSM are not important, this change will slightly
 * increase the CPU load when packets are dropped.  If this is significant,
 * consider hiding this change behind a CCA/RSM environment variable.
 */

	ctrl->__hfi_rcvtidflow[flowid] = __cpu_to_le64(
		((genval & HFI_TF_GENVAL_MASK) << HFI_TF_GENVAL_SHIFT) |
		((seqnum & HFI_TF_SEQNUM_MASK) << HFI_TF_SEQNUM_SHIFT) |
		((uint64_t)ctrl->__hfi_tfvalid << HFI_TF_FLOWVALID_SHIFT) |
		(1ULL << HFI_TF_HDRSUPP_ENABLED_SHIFT) |
		/* KeepAfterSequenceError = 1 -- previously was 0 */
		(1ULL << HFI_TF_KEEP_AFTER_SEQERR_SHIFT) |
		(1ULL << HFI_TF_KEEP_ON_GENERR_SHIFT) |
		/* KeePayloadOnGenErr = 0 */
		(1ULL << HFI_TF_STATUS_SEQMISMATCH_SHIFT) |
		(1ULL << HFI_TF_STATUS_GENMISMATCH_SHIFT));
}

static __inline__ void hfi_tidflow_reset(struct _hfi_ctrl *ctrl,
					 uint32_t flowid, uint32_t genval,
					 uint32_t seqnum)
{
/*
 * If a tidflow table entry is set to "Invalid", we want to drop
 * header if payload is dropped, we want to get a header if the payload
 * is delivered.
 *
 * We set a tidflow table entry "Invalid" by setting FlowValid=1 and
 * GenVal=0x1FFF/0xFFFFF, this is a special generation number and no
 * packet will use this value. We don't care SeqNum but we set it to
 * 0x7FF. So if GenVal does not match, the payload is dropped because
 * KeepPayloadOnGenErr=0; for packet header, KeepOnGenErr=0 make sure
 * header is not generated. But if a packet happens to have the special
 * generation number, the payload is delivered, HdrSuppEnabled=0 make
 * sure header is generated if SeqNUm matches, if SeqNum does not match,
 * KeepAfterSeqErr=1 makes sure the header is generated.
 */
	ctrl->__hfi_rcvtidflow[flowid] = __cpu_to_le64(
		/* genval = 0x1FFF or 0xFFFFF */
		((genval & HFI_TF_GENVAL_MASK) << HFI_TF_GENVAL_SHIFT) |
		/* seqnum = 0x7FF */
		((seqnum & HFI_TF_SEQNUM_MASK) << HFI_TF_SEQNUM_SHIFT) |
		((uint64_t)ctrl->__hfi_tfvalid << HFI_TF_FLOWVALID_SHIFT) |
		/* HdrSuppEnabled = 0 */
		(1ULL << HFI_TF_KEEP_AFTER_SEQERR_SHIFT) |
		/* KeepOnGenErr = 0 */
		/* KeepPayloadOnGenErr = 0 */
		(1ULL << HFI_TF_STATUS_SEQMISMATCH_SHIFT) |
		(1ULL << HFI_TF_STATUS_GENMISMATCH_SHIFT));
}

/*
 * This should only be used for debugging.
 * Normally, we shouldn't read the chip.
 */
static __inline__ uint64_t hfi_tidflow_get(struct _hfi_ctrl *ctrl,
					   uint32_t flowid)
{
	return __le64_to_cpu(ctrl->__hfi_rcvtidflow[flowid]);
}

static __inline__ uint32_t hfi_tidflow_get_seqnum(uint64_t val)
{
	return (val >> HFI_TF_SEQNUM_SHIFT) & HFI_TF_SEQNUM_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_genval(uint64_t val)
{
	return (val >> HFI_TF_GENVAL_SHIFT) & HFI_TF_GENVAL_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_flowvalid(uint64_t val)
{
	return (val >> HFI_TF_FLOWVALID_SHIFT) & HFI_TF_FLOWVALID_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_enabled(uint64_t val)
{
	return (val >> HFI_TF_HDRSUPP_ENABLED_SHIFT) &
	    HFI_TF_HDRSUPP_ENABLED_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_keep_after_seqerr(uint64_t val)
{
	return (val >> HFI_TF_KEEP_AFTER_SEQERR_SHIFT) &
	    HFI_TF_KEEP_AFTER_SEQERR_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_keep_on_generr(uint64_t val)
{
	return (val >> HFI_TF_KEEP_ON_GENERR_SHIFT) &
	    HFI_TF_KEEP_ON_GENERR_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_keep_payload_on_generr(uint64_t val)
{
	return (val >> HFI_TF_KEEP_PAYLOAD_ON_GENERR_SHIFT) &
	    HFI_TF_KEEP_PAYLOAD_ON_GENERR_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_seqmismatch(uint64_t val)
{
	return (val >> HFI_TF_STATUS_SEQMISMATCH_SHIFT) &
	    HFI_TF_STATUS_SEQMISMATCH_MASK;
}

static __inline__ uint32_t hfi_tidflow_get_genmismatch(uint64_t val)
{
	return (val >> HFI_TF_STATUS_GENMISMATCH_SHIFT) &
	    HFI_TF_STATUS_GENMISMATCH_MASK;
}

/*
 * This should only be used by a process to write the eager index into
 * a subcontext's eager header entry.
 */
static __inline__ void hfi_hdrset_use_egrbfr(__le32 *rbuf, uint32_t val)
{
	rbuf[0] =
	    (rbuf[0] &
	     __cpu_to_le32(~(HFI_RHF_USE_EGRBFR_MASK <<
			     HFI_RHF_USE_EGRBFR_SHIFT))) |
	    __cpu_to_le32((val & HFI_RHF_USE_EGRBFR_MASK) <<
			  HFI_RHF_USE_EGRBFR_SHIFT);
}

static __inline__ void hfi_hdrset_egrbfr_index(__le32 *rbuf, uint32_t val)
{
	rbuf[0] =
	    (rbuf[0] &
	     __cpu_to_le32(~(HFI_RHF_EGRBFR_INDEX_MASK <<
			     HFI_RHF_EGRBFR_INDEX_SHIFT))) |
	    __cpu_to_le32((val & HFI_RHF_EGRBFR_INDEX_MASK) <<
			  HFI_RHF_EGRBFR_INDEX_SHIFT);
}

static __inline__ void hfi_hdrset_egrbfr_offset(__le32 *rbuf, uint32_t val)
{
	rbuf[1] =
	    (rbuf[1] &
	     __cpu_to_le32(~(HFI_RHF_EGRBFR_OFFSET_MASK <<
			     HFI_RHF_EGRBFR_OFFSET_SHIFT))) |
	    __cpu_to_le32((val & HFI_RHF_EGRBFR_OFFSET_MASK) <<
			  HFI_RHF_EGRBFR_OFFSET_SHIFT);
}

/*
 * This should only be used by a process to update the receive header
 * error flags.
 */
static __inline__ void hfi_hdrset_err_flags(__le32 *rbuf, uint32_t val)
{
	rbuf[1] |= __cpu_to_le32(val);
}

/*
 * This should only be used by a process to write the rhf seq number into
 * a subcontext's eager header entry.
 */
static __inline__ void hfi_hdrset_seq(__le32 *rbuf, uint32_t val)
{
	rbuf[0] =
	    (rbuf[0] &
	     __cpu_to_le32(~(HFI_RHF_SEQ_MASK <<
			     HFI_RHF_SEQ_SHIFT))) |
	    __cpu_to_le32((val & HFI_RHF_SEQ_MASK) << HFI_RHF_SEQ_SHIFT);
}

/* Manage TID entries.  It is possible that not all entries
   requested may be allocated.  A matching hfi_free_tid() must be
   done for each hfi_update_tid(), because currently no caching or
   reuse of expected tid entries is allowed, to work around malloc/free
   and mmap/munmap issues.  The driver decides which TID entries to allocate.
   If hfi_free_tid is called to free entries in use by a different
   send by the same process, data corruption will probably occur,
   but only within that process, not for other processes.
*/

/* update tidcnt expected TID entries from the array pointed to by tidinfo. */
/* Returns 0 on success, else an errno.  See full description at declaration */
static __inline__ int32_t hfi_update_tid(struct _hfi_ctrl *ctrl,
					 uint64_t vaddr, uint32_t *length,
					 uint64_t tidlist, uint32_t *tidcnt, uint16_t flags)
{
	struct hfi1_cmd cmd;
#ifdef PSM_CUDA
	struct hfi1_tid_info_v2 tidinfo;
#else
	struct hfi1_tid_info tidinfo;
#endif
	int err;

	tidinfo.vaddr = vaddr;		/* base address for this send to map */
	tidinfo.length = *length;	/* length of vaddr */

	tidinfo.tidlist = tidlist;	/* driver copies tids back directly */
	tidinfo.tidcnt = 0;		/* clear to zero */

	cmd.type = PSMI_HFI_CMD_TID_UPDATE;
#ifdef PSM_CUDA
	cmd.type = PSMI_HFI_CMD_TID_UPDATE_V2;

	if (PSMI_IS_DRIVER_GPUDIRECT_ENABLED)
		tidinfo.flags = flags;
	else
		tidinfo.flags = 0;
#endif

	cmd.len = sizeof(tidinfo);
	cmd.addr = (__u64) &tidinfo;

	err = hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd));

	if (err != -1) {
		*length = tidinfo.length;
		*tidcnt = tidinfo.tidcnt;
	}

	return err;
}

static __inline__ int32_t hfi_free_tid(struct _hfi_ctrl *ctrl,
					 uint64_t tidlist, uint32_t tidcnt)
{
	struct hfi1_cmd cmd;
	struct hfi1_tid_info tidinfo;
	int err;

	tidinfo.tidlist = tidlist;	/* input to driver */
	tidinfo.tidcnt = tidcnt;

	cmd.type = PSMI_HFI_CMD_TID_FREE;
	cmd.len = sizeof(tidinfo);
	cmd.addr = (__u64) &tidinfo;

	err = hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd));

	return err;
}

static __inline__ int32_t hfi_get_invalidation(struct _hfi_ctrl *ctrl,
					 uint64_t tidlist, uint32_t *tidcnt)
{
	struct hfi1_cmd cmd;
	struct hfi1_tid_info tidinfo;
	int err;

	tidinfo.tidlist = tidlist;	/* driver copies tids back directly */
	tidinfo.tidcnt = 0;		/* clear to zero */

	cmd.type = PSMI_HFI_CMD_TID_INVAL_READ;
	cmd.len = sizeof(tidinfo);
	cmd.addr = (__u64) &tidinfo;

	err = hfi_cmd_write(ctrl->fd, &cmd, sizeof(cmd));

	if (err != -1)
		*tidcnt = tidinfo.tidcnt;

	return err;
}

extern uint32_t __hfi_pico_per_cycle;	/* only for use in these functions */

/* this is only accurate for reasonably large numbers of cycles (at least tens) */
static __inline__ uint64_t cycles_to_nanosecs(uint64_t cycs)
{
	return (__hfi_pico_per_cycle * cycs) / 1000ULL;
}

/* this is only accurate for reasonably large numbers of nsecs (at least tens) */
static __inline__ uint64_t nanosecs_to_cycles(uint64_t ns)
{
	return (ns * 1000ULL) / __hfi_pico_per_cycle;
}

static __inline__ uint64_t get_nanoseconds()
{
	return cycles_to_nanosecs(get_cycles());
}

/* open the diags device, if supported by driver.  Returns 0 on */
/* success, errno on failure.  Also tells driver that diags */
/* is active, which changes some driver behavior */
int hfi_diag_open(unsigned);	/* unit */
int hfi_diag_close(void);

/* diags chip read and write routines */

int hfid_read32(uint64_t reg_offset, uint32_t *read_valp);
int hfid_write32(uint64_t reg_offset, uint32_t write_val);

int hfid_readmult(uint64_t, unsigned, uint64_t *);	/* chip: offset, cnt, ptr */
int hfid_write(uint64_t, uint64_t);	/* chip: offset, value */

#define HFI_READ_EEPROM 31337
#define HFI_WRITE_EEPROM 101

struct hfi_eeprom_req {
	void *addr;
	uint16_t len;
	uint16_t offset;
};

/*
 * Data layout in I2C flash (for GUID, etc.)
 * All fields are little-endian binary unless otherwise stated
 */
#define HFI_FLASH_VERSION 2
struct hfi_flash {
	/* flash layout version (HFI_FLASH_VERSION) */
	__u8 if_fversion;
	/* checksum protecting if_length bytes */
	__u8 if_csum;
	/*
	 * valid length (in use, protected by if_csum), including
	 * if_fversion and if_csum themselves)
	 */
	__u8 if_length;
	/* the GUID, in network order */
	__u8 if_guid[8];
	/* number of GUIDs to use, starting from if_guid */
	__u8 if_numguid;
	/* the (last 10 characters of) board serial number, in ASCII */
	char if_serial[12];
	/* board mfg date (YYYYMMDD ASCII) */
	char if_mfgdate[8];
	/* last board rework/test date (YYYYMMDD ASCII) */
	char if_testdate[8];
	/* logging of error counts, TBD */
	__u8 if_errcntp[4];
	/* powered on hours, updated at driver unload */
	__u8 if_powerhour[2];
	/* ASCII free-form comment field */
	char if_comment[32];
	/* Backwards compatible prefix for longer QLogic Serial Numbers */
	char if_sprefix[4];
	/* 82 bytes used, min flash size is 128 bytes */
	__u8 if_future[46];
};

int hfid_send_pkt(const void *, unsigned);	/* send a packet for diags */
int hfid_read_i2c(struct hfi_eeprom_req *);	/* diags read i2c flash */

__u8 hfi_flash_csum(struct hfi_flash *, int);

int hfid_reset_hardware(uint32_t);

#endif /* OPA_USER_H */
