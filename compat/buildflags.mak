#
#  This file is provided under a dual BSD/GPLv2 license.  When using or
#  redistributing this file, you may do so under either license.
#
#  GPL LICENSE SUMMARY
#
#  Copyright(c) 2024 Tactical Computing Labs, LLC
#  Copyright(c) 2015 Intel Corporation.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of version 2 of the GNU General Public License as
#  published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  Contact Information:
#  Intel Corporation, www.intel.com
#
#  BSD LICENSE
#
#  Copyright(c) 2015 Intel Corporation.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

ifeq (,$(top_srcdir))
$(error top_srcdir must be set to include makefile fragment)
endif

export os ?= $(shell uname -s | tr '[A-Z]' '[a-z]')
export arch := $(shell uname -m | sed -e 's,\(i[456]86\|athlon$$\),i386,riscv64')
export CCARCH ?= gcc

ifeq (${CCARCH},$(filter ${CCARCH},gcc gcc4 icc clang))
	export CC := ${CCARCH}
else
	anerr := $(error Unknown C compiler arch: ${CCARCH})
endif

BASECFLAGS += $(BASE_FLAGS)
LDFLAGS += $(BASE_FLAGS)
ASFLAGS += $(BASE_FLAGS)

LINKER_SCRIPT_FILE := psm2_compat_linker_script.map
LINKER_SCRIPT := -Wl,--version-script $(LINKER_SCRIPT_FILE)
WERROR := -Werror
INCLUDES := -I$(top_srcdir)/include -I$(top_srcdir)/include/$(os)-$(arch) -I$(top_srcdir)/mpspawn

BASECFLAGS +=-Wall $(WERROR)

BASECFLAGS += -fpic -fPIC

ASFLAGS += -g3 -fpic

ifeq (${CCARCH},icc)
    BASECFLAGS += -O3 -g3
    LDFLAGS += -static-intel
else
	ifeq (${CCARCH},$(filter ${CCARCH},gcc clang))
	    BASECFLAGS += -Wno-strict-aliasing
	else
		ifneq (${CCARCH},gcc4)
			$(error Unknown compiler arch "${CCARCH}")
		endif
	endif
endif
