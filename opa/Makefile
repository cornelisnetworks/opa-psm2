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
#  Copyright (c) 2003-2014 Intel Corporation. All rights reserved.
#

OUTDIR = .

TARGLIB := libopa
MAJOR := $(OPA_LIB_MAJOR)
MINOR := $(OPA_LIB_MINOR)

this_srcdir := $(shell readlink -m .)
top_srcdir := $(this_srcdir)/..

INCLUDES += -I$(top_srcdir) -I$(top_srcdir)/ptl_ips
ifeq (${arch},x86_64)
	PLATFORM_OBJ=opa_dwordcpy-x86_64-fast.o
	BUILD_ARCH=${arch}
else
	PLATFORM_OBJ=opa_dwordcpy-generic.o
	BUILD_ARCH=generic
endif

${TARGLIB}-objs := opa_debug.o opa_time.o \
	opa_service.o opa_utils.o \
	opa_dwordcpy-$(BUILD_ARCH).o opa_sysfs.o opa_syslog.o \
	$(PLATFORM_OBJ)

${TARGLIB}-objs := $(patsubst %.o, $(OUTDIR)/%.o, ${${TARGLIB}-objs})
DEPS := $(${TARGLIB}-objs:.o=.d)

.PHONY: all clean
IGNORE_DEP_TARGETS = clean

all .DEFAULT: ${${TARGLIB}-objs}

install: all
	@echo "Nothing to do for install."

$(OUTDIR)/%.d:  $(this_srcdir)/%.c
	$(CC) $(CFLAGS) $(BASECFLAGS) $(INCLUDES) $< -MM -MF $@ -MQ $(@:.d=.o)

$(OUTDIR)/%.d:  $(this_srcdir)/%.S
	$(CC) $(CFLAGS) $(BASECFLAGS) $(INCLUDES) $< -MM -MF $@ -MQ $(@:.d=.o)

$(OUTDIR)/%.o: $(this_srcdir)/%.c | ${DEPS}
	$(CC) $(CFLAGS) $(BASECFLAGS) $(INCLUDES) -c $< -o $@

$(OUTDIR)/%.o: $(this_srcdir)/%.S | ${DEPS}
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	@rm -f $(OUTDIR)/_revision.c
	@if [ -d $(OUTDIR) ]; then \
		cd $(OUTDIR); \
		rm -f *.o *.d *.gcda *.gcno ${TARGLIB}.*; \
		cd -; \
	fi


#ifeq prevents the deps from being included during clean
#-include line is required to pull in auto-dependecies during 2nd pass
ifeq ($(filter $(IGNORE_DEP_TARGETS), $(MAKECMDGOALS)),)
-include ${DEPS}
endif
