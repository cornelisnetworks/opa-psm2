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
#  Copyright (c) 2003-2014 Intel Corporation. All rights reserved.
#

RPM_NAME := libpsm2

SUBDIRS:= ptl_self ptl_ips ptl_am libuuid opa
export build_dir := .

PSM2_VERNO_MAJOR := $(shell sed -n 's/^\#define.*PSM2_VERNO_MAJOR.*0x0\?\([1-9a-f]\?[0-9a-f]\+\).*/\1/p' $(build_dir)/psm2.h)
PSM2_VERNO_MINOR := $(shell sed -n 's/^\#define.*PSM2_VERNO_MINOR.*0x\([0-9]\?[0-9a-f]\+\).*/\1/p' $(build_dir)/psm2.h)
PSM2_LIB_MAJOR   := $(shell printf "%d" ${PSM2_VERNO_MAJOR})
PSM2_LIB_MINOR   := $(shell printf "%d" `sed -n 's/^\#define.*PSM2_VERNO_MINOR.*\(0x[0-9a-f]\+\).*/\1/p' $(build_dir)/psm2.h`)

OPA_LIB_MAJOR := 4
OPA_LIB_MINOR := 0

export PSM2_VERNO_MAJOR
export PSM2_LIB_MAJOR
export PSM2_VERNO_MINOR
export PSM2_LIB_MINOR
export OPA_LIB_MAJOR
export OPA_LIB_MINOR
export CCARCH ?= gcc
export FCARCH ?= gfortran

top_srcdir := .
include $(top_srcdir)/buildflags.mak
lib_build_dir := $(build_dir)

ifneq (x86_64,$(arch))
   ifneq (i386,$(arch))
      $(error Unsupported architecture $(arch))
   endif
endif

ifndef LIBDIR
   ifeq (${arch},x86_64)
      INSTALL_LIB_TARG=/usr/lib64
   else
      INSTALL_LIB_TARG=/usr/lib
   endif
else
   INSTALL_LIB_TARG=${LIBDIR}
endif
export DESTDIR
export INSTALL_LIB_TARG

TARGLIB := libpsm2
COMPATMAJOR := $(shell sed -n 's/^\#define.*PSM2_VERNO_COMPAT_MAJOR.*0x0\?\([1-9a-f]\?[0-9a-f]\+\).*/\1/p' $(build_dir)/psm2.h)
COMPATLIB := libpsm_infinipath

MAJOR := $(PSM2_LIB_MAJOR)
MINOR := $(PSM2_LIB_MINOR)

nthreads := $(shell echo $$(( `nproc` * 2 )) )

# The following line sets the DISTRO variable to:
#  'rhel' if the host is running RHEL.
#  'suse' if the host is running SUSE.
#  'fedora' if the host is running Fedora.
#
# The DISTRO variable is used subsequently for variable
# behaviors of the 3 distros.

DISTRO := $(shell . /etc/os-release; echo $$ID)

# By defailt the following two variables have the following values:
LIBPSM2_COMPAT_CONF_DIR := /etc
LIBPSM2_COMPAT_SYM_CONF_DIR := /etc
SPEC_FILE_RELEASE_DIST :=#nothing
UDEV_40_PSM_RULES := %{_udevrulesdir}/40-psm.rules

ifeq (fedora,$(DISTRO))
	# On Fedora, we change these two variables to these values:
	LIBPSM2_COMPAT_CONF_DIR := /usr/lib
	LIBPSM2_COMPAT_SYM_CONF_DIR := %{_prefix}/lib
	SPEC_FILE_RELEASE_DIST := %{?dist}
	UDEV_40_PSM_RULES :=#
else ifeq (rhel,${DISTRO})
	# Insert code specific to RHEL here.
else ifeq (sles,${DISTRO})
	# Insert code specific to SLES here.
endif

export 	LIBPSM2_COMPAT_CONF_DIR

# The desired version number comes from the most recent tag starting with "v"
VERSION := $(shell if [ -e .git ] ; then  git  describe --tags --abbrev=0 --match='v*' | sed -e 's/^v//' -e 's/-/_/'; else echo "version" ; fi)
#
# The desired release number comes the git describe following the version which
# is the number of commits since the version tag was planted suffixed by the g<commitid>
RELEASE := $(shell if [ -f RELEASE ]; then cat RELEASE;\
		   elif [ -e .git ] ; then git describe --tags --long --match='v*' | \
				sed -e 's/v[0-9.]*-\(.*\)/\1/' -e 's/-/_/' | \
				sed -e 's/_g.*$$//'; \
		   else echo "release" ; fi)

DIST_SHA := ${shell if [ -e .git ] ; then git log -n1 --pretty=format:%H ; \
		else echo DIST_SHA ; fi}

# Concatenated version and release
VERSION_RELEASE := $(VERSION).$(RELEASE)

LDLIBS := -lrt -lpthread -ldl ${EXTRA_LIBS}

PKG_CONFIG ?= pkg-config

UDEVDIR := $(shell $(PKG_CONFIG) --variable=udevdir udev 2>/dev/null)
ifndef UDEVDIR
	UDEVDIR = /lib/udev
endif

export UDEVDIR

# The DIST variable is a name kernel corresponding to:
# 1. The name of the directory containing the source code distribution
#    (see dist: target below).
# 2. The basename of the filename of the tar file created in the dist:
#    target.
DIST := ${RPM_NAME}-${VERSION_RELEASE}

all: symlinks
	for subdir in $(SUBDIRS); do \
		$(MAKE) -j $(nthreads) -C $$subdir $@ ;\
	done
	$(MAKE) -j $(nthreads) ${TARGLIB}.so
	$(MAKE) -j $(nthreads) -C compat all

clean:
	rm -f _revision.c
	for subdir in $(SUBDIRS) ; do \
		$(MAKE) -j $(nthreads) -C $$subdir $@ ;\
	done
	$(MAKE) -j $(nthreads) -C compat clean
	rm -f *.o *.d *.gcda *.gcno ${TARGLIB}.so*

distclean: cleanlinks clean
	rm -f ${RPM_NAME}.spec
	rm -f ${DIST}.tar.gz
	rm -fr temp.[0-9]*

.PHONY: symlinks
symlinks:
	@[[ -L $(build_dir)/include/linux-x86_64 ]] || \
		ln -sf linux-i386 $(build_dir)/include/linux-x86_64

cleanlinks:
	rm -f $(build_dir)/include/linux-x86_64

install: all
	for subdir in $(SUBDIRS); do \
		$(MAKE) -j $(nthreads) -C $$subdir $@ ;\
	done
	$(MAKE) -j $(nthreads) -C compat install
	install -D ${TARGLIB}.so.${MAJOR}.${MINOR} \
		${DESTDIR}${INSTALL_LIB_TARG}/${TARGLIB}.so.${MAJOR}.${MINOR}
	(cd ${DESTDIR}${INSTALL_LIB_TARG} ; \
		ln -sf ${TARGLIB}.so.${MAJOR}.${MINOR} ${TARGLIB}.so.${MAJOR} ; \
		ln -sf ${TARGLIB}.so.${MAJOR} ${TARGLIB}.so)
	install -m 0644 -D psm2.h ${DESTDIR}/usr/include/psm2.h
	install -m 0644 -D psm2_mq.h ${DESTDIR}/usr/include/psm2_mq.h
	install -m 0644 -D psm2_am.h ${DESTDIR}/usr/include/psm2_am.h
ifneq (fedora,${DISTRO})
	install -m 0644 -D 40-psm.rules ${DESTDIR}$(UDEVDIR)/rules.d/40-psm.rules
endif
	# The following files and dirs were part of the noship rpm:
	mkdir -p ${DESTDIR}/usr/include/hfi1diag
	mkdir -p ${DESTDIR}/usr/include/hfi1diag/linux-x86_64
	mkdir -p ${DESTDIR}/usr/include/hfi1diag/ptl_ips
	install -m 0644 -D ptl_ips/ipserror.h ${DESTDIR}/usr/include/hfi1diag/ptl_ips/ipserror.h
	install -m 0644 -D include/linux-x86_64/bit_ops.h ${DESTDIR}/usr/include/hfi1diag/linux-x86_64/bit_ops.h
	install -m 0644 -D include/linux-x86_64/sysdep.h ${DESTDIR}/usr/include/hfi1diag/linux-x86_64/sysdep.h
	install -m 0644 -D include/opa_udebug.h ${DESTDIR}/usr/include/hfi1diag/opa_udebug.h
	install -m 0644 -D include/opa_debug.h ${DESTDIR}/usr/include/hfi1diag/opa_debug.h
	install -m 0644 -D include/opa_intf.h ${DESTDIR}/usr/include/hfi1diag/opa_intf.h
	install -m 0644 -D include/opa_user.h ${DESTDIR}/usr/include/hfi1diag/opa_user.h
	install -m 0644 -D include/opa_service.h ${DESTDIR}/usr/include/hfi1diag/opa_service.h
	install -m 0644 -D include/opa_common.h ${DESTDIR}/usr/include/hfi1diag/opa_common.h
	install -m 0644 -D include/opa_byteorder.h ${DESTDIR}/usr/include/hfi1diag/opa_byteorder.h
	install -m 0644 -D include/hfi1_deprecated.h ${DESTDIR}/usr/include/hfi1diag/hfi1_deprecated.h

specfile:
	sed -e 's/@VERSION@/'${VERSION_RELEASE}'/g' ${RPM_NAME}.spec.in | \
		sed -e 's/@TARGLIB@/'${TARGLIB}'/g' \
			-e 's/@RPM_NAME@/'${RPM_NAME}'/g' \
			-e 's/@COMPATLIB@/'${COMPATLIB}'/g' \
			-e 's/@COMPATMAJOR@/'${COMPATMAJOR}'/g' \
			-e 's;@UDEVDIR@;'${UDEVDIR}';g' \
			-e 's/@MAJOR@/'${MAJOR}'/g' \
			-e 's/@MINOR@/'${MINOR}'/g' \
			-e 's:@LIBPSM2_COMPAT_CONF_DIR@:'${LIBPSM2_COMPAT_CONF_DIR}':g' \
			-e 's:@LIBPSM2_COMPAT_SYM_CONF_DIR@:'${LIBPSM2_COMPAT_SYM_CONF_DIR}':g' \
			-e 's/@SPEC_FILE_RELEASE_DIST@/'${SPEC_FILE_RELEASE_DIST}'/g'  \
			-e 's;@40_PSM_RULES@;'${UDEV_40_PSM_RULES}';g' \
			-e 's/@DIST_SHA@/'${DIST_SHA}'/g' > \
		${RPM_NAME}.spec

dist: distclean
	mkdir -p ${DIST}
	for x in $$(/usr/bin/find .						\
			-name ".git"                           -prune -o	\
			-name "cscope*"                        -prune -o	\
			-name "${DIST}"                        -prune -o	\
			-name "*.orig"                         -prune -o	\
			-name "*~"                             -prune -o	\
			-name "#*"                             -prune -o	\
			-name ".gitignore"                     -prune -o	\
			-name "doc"                            -prune -o	\
			-name "libcm"                          -prune -o	\
			-name "makesrpm.sh"                    -prune -o	\
			-name "psm.supp"                       -prune -o	\
			-name "test"                           -prune -o	\
			-name "tools"                          -prune -o	\
			-print); do \
		dir=$$(dirname $$x); \
		mkdir -p ${DIST}/$$dir; \
		[ ! -d $$x ] && cp $$x ${DIST}/$$dir; \
	done
	if [ -e .git ] ; then git log -n1 --pretty=format:%H > ${DIST}/COMMIT ; fi
	echo ${RELEASE} > ${DIST}/RELEASE
	tar czvf ${DIST}.tar.gz ${DIST}
	rm -rf ${DIST}

ofeddist:
	$(MAKE) -j $(nthreads) dist

# rebuild the cscope database, skipping sccs files, done once for
# top level
cscope:
	find * -type f ! -name '[ps].*' \( -iname '*.[cfhs]' -o \
	  -iname \\*.cc -o -name \\*.cpp -o -name \\*.f90 \) -print | cscope -bqu -i -

${TARGLIB}-objs := ptl_am/am_reqrep_shmem.o	\
		   ptl_am/am_reqrep.o		\
		   ptl_am/ptl.o			\
		   ptl_am/cmarwu.o		\
		   psm_context.o		\
		   psm_ep.o			\
		   psm_ep_connect.o		\
		   psm_error.o			\
		   psm_utils.o			\
		   psm_sysbuf.o			\
		   psm_timer.o			\
		   psm_am.o			\
		   psm_mq.o			\
		   psm_mq_utils.o		\
		   psm_mq_recv.o		\
		   psm_mpool.o			\
		   psm_stats.o			\
		   psm_memcpy.o			\
		   psm.o			\
		   libuuid/psm_uuid.o		\
		   ptl_ips/ptl.o		\
		   ptl_ips/ptl_rcvthread.o	\
		   ptl_ips/ipserror.o		\
		   ptl_ips/ips_scb.o		\
		   ptl_ips/ips_epstate.o	\
		   ptl_ips/ips_recvq.o		\
		   ptl_ips/ips_recvhdrq.o	\
		   ptl_ips/ips_spio.o		\
		   ptl_ips/ips_proto.o		\
		   ptl_ips/ips_proto_recv.o	\
		   ptl_ips/ips_proto_connect.o  \
		   ptl_ips/ips_proto_expected.o \
		   ptl_ips/ips_tid.o		\
		   ptl_ips/ips_tidcache.o       \
		   ptl_ips/ips_rbtree.o         \
		   ptl_ips/ips_tidflow.o        \
		   ptl_ips/ips_crc32.o 		\
		   ptl_ips/ips_proto_dump.o	\
		   ptl_ips/ips_proto_mq.o       \
		   ptl_ips/ips_proto_am.o       \
		   ptl_ips/ips_subcontext.o	\
		   ptl_ips/ips_path_rec.o       \
		   ptl_ips/ips_opp_path_rec.o   \
		   ptl_ips/ips_writehdrq.o	\
		   ptl_self/ptl.o		\
		   opa/*.o			\
		   psm_diags.o

DEPS:= $(${TARGLIB}-objs:.o=.d)
-include $(DEPS)

${TARGLIB}.so: ${lib_build_dir}/${TARGLIB}.so.${MAJOR}
	ln -fs ${TARGLIB}.so.${MAJOR}.${MINOR} $@

${TARGLIB}.so.${MAJOR}: ${lib_build_dir}/${TARGLIB}.so.${MAJOR}.${MINOR}
	ln -fs ${TARGLIB}.so.${MAJOR}.${MINOR} $@

# when we build the shared library, generate a revision and date
# string in it, for easier id'ing when people may have copied the
# file around.  Generate it such that the ident command can find it
# and strings -a | grep OPA does a reasonable job as well.
${TARGLIB}.so.${MAJOR}.${MINOR}: ${${TARGLIB}-objs}
	date +'char psmi_hfi_revision[] ="$$""Date: %F %R ${rpm_extra_description}HFI $$";' > ${lib_build_dir}/_revision.c
	$(CC) -c $(BASECFLAGS) $(INCLUDES) _revision.c -o _revision.o
	$(CC) $(LDFLAGS) -o $@ -Wl,-soname=${TARGLIB}.so.${MAJOR} -shared \
		${${TARGLIB}-objs} _revision.o -Lopa $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -MMD -c $< -o $@

.PHONY: $(SUBDIRS)

