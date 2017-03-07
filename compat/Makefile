#
#  This file is provided under a dual BSD/GPLv2 license.  When using or
#  redistributing this file, you may do so under either license.
#
#  GPL LICENSE SUMMARY
#
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

OUTDIR = .

COMPATLIB := libpsm_infinipath
COMPAT_LIB_TARG := $(INSTALL_LIB_TARG)/psm2-compat
compat_build_dir := $(shell readlink -m .)

MAJOR := $(shell sed -n 's/^\#define.*PSM2_VERNO_COMPAT_MAJOR.*0x0\?\([1-9a-f]\?[0-9a-f]\+\).*/\1/p' ../psm2.h)

top_srcdir := $(compat_build_dir)/..
include $(compat_build_dir)/buildflags.mak
INCLUDES += -I$(top_srcdir)

${COMPATLIB}-objs := psm-compat.o
${COMPATLIB}-objs := $(patsubst %.o, $(OUTDIR)/%.o, ${${COMPATLIB}-objs})

DEPS:= $(${COMPATLIB}-objs:.o=.d)
-include $(DEPS)

all .DEFAULT: ${${COMPATLIB}-objs} $(OUTDIR)/${COMPATLIB}.so.${MAJOR}

install: all
	install -m 0644 -D 40-psm-compat.rules ${DESTDIR}$(UDEVDIR)/rules.d/40-psm-compat.rules
	install -m 0644 -D libpsm2-compat.conf ${DESTDIR}${LIBPSM2_COMPAT_CONF_DIR}/modprobe.d/libpsm2-compat.conf
	install -m 0755 -D libpsm2-compat.cmds ${DESTDIR}/usr/lib/libpsm2/libpsm2-compat.cmds
	install -D ${COMPATLIB}.so.${MAJOR} ${DESTDIR}${COMPAT_LIB_TARG}/${COMPATLIB}.so.${MAJOR}

$(OUTDIR)/%.o: $(compat_build_dir)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -MMD -c $< -o $@

$(OUTDIR)/${COMPATLIB}.so.${MAJOR}: ${${COMPATLIB}-objs}
	$(CC) $(BASECFLAGS) $(LINKER_SCRIPT) $(LDFLAGS) -Wl,-soname=${COMPATLIB}.so.${MAJOR} -shared \
		 -L$(OUTDIR)/.. -lpsm2 -o $@ ${${COMPATLIB}-objs}

clean:
	@if [ -d $(OUTDIR) ]; then \
		cd $(OUTDIR); \
		rm -f *.o *.d *.gcda *.gcno ${COMPATLIB}.*; \
		cd -; \
	fi
