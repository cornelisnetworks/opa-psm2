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
# Copyright (c) 2014-2015 Intel Corporation. All rights reserved.
#
Summary: Intel PSM Libraries
Name: hfi1-psm
Version: 0.7
Release: 221
License: GPL
Group: System Environment/Libraries
URL: http://www.intel.com/
Source0: %{name}-%{version}-%{release}.tar.gz
Prefix: /usr
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
ExclusiveArch: x86_64
%if 0%{?rhel}
Requires: libuuid
%else
Requires: libuuid1
%endif
BuildRequires: libuuid-devel
Conflicts: opa-libs
Obsoletes: hfi-psm
Obsoletes: hfi-psm-debuginfo

%package devel
Summary: Development files for Intel PSM
Group: System Environment/Development
Requires: %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires: libuuid-devel
Conflicts: opa-devel
Obsoletes: hfi-psm-devel

%package compat
Summary: Development files for Intel PSM
Group: System Environment/Development
Requires: %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Obsoletes: hfi-psm-compat

%description
The PSM Messaging API, or PSM API, is Intel's low-level
user-level communications interface for the Truescale
family of products. PSM users are enabled with mechanisms
necessary to implement higher level communications
interfaces in parallel environments.

%description devel
Development files for the libpsm2 library

%description compat
Support for MPIs linked with PSM versions < 2

%prep
%setup -q -n hfi1-psm-%{version}-%{release}

%build
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
export DESTDIR=$RPM_BUILD_ROOT
%{__make} DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
%post devel -p /sbin/ldconfig
%postun devel -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
/usr/lib64/libpsm2.so.2.1
/usr/lib64/libpsm2.so.2
/usr/lib/udev/rules.d/40-psm.rules

%files devel
%defattr(-,root,root,-)
/usr/lib64/libpsm2.so
/usr/include/psm2.h
/usr/include/psm2_mq.h
/usr/include/psm2_am.h
# The following files were part of the devel-noship and moved to devel:
/usr/include/hfi1diag/ptl_ips/ipserror.h
/usr/include/hfi1diag/linux-x86_64/bit_ops.h
/usr/include/hfi1diag/linux-x86_64/sysdep.h
/usr/include/hfi1diag/opa_udebug.h
/usr/include/hfi1diag/opa_debug.h
/usr/include/hfi1diag/opa_intf.h
/usr/include/hfi1diag/opa_user.h
/usr/include/hfi1diag/opa_service.h
/usr/include/hfi1diag/opa_common.h
/usr/include/hfi1diag/opa_byteorder.h

%files compat
%defattr(-,root,root,-)
/usr/lib64/psm2-compat/libpsm_infinipath.so.1
/usr/lib/udev/rules.d/40-psm-compat.rules
/etc/modprobe.d/hfi1-psm-compat.conf
/usr/sbin/hfi1-psm-compat.cmds
%changelog
* Fri Jan 29 2016 <paul.j.reger@intel.com>
- Fixes another case of write-to-heap-after-free.

* Fri Jan 29 2016 <paul.j.reger@intel.com>
- Fixes case of use-of-heap-allocation-after-free in tid cache code during shutdown.

* Fri Jan 29 2016 <paul.j.reger@intel.com>
- Adds guard to prevent heap overrun.

* Wed Jan 20 2016 <russell.w.mcguire@intel.com>
- Increase HASH_THRESHOLD for message rate benchmark

* Fri Jan 8 2016 <npayyavu@sperf-02.sc.intel.com>
- Fixes handling of link bounce events in PSM

* Fri Jan 8 2016 <paul.j.reger@intel.com>
- Adds guard to prevent calls attempting to free 0 tids and re-factors handling of ENOMEM during DMA completion.

* Mon Dec 21 2015 <npayyavu@sperf-33.sc.intel.com>
- Fixed AMSH file collisions and security issues

* Thu Dec 10 2015 <kyle.liddell@intel.com>
- Eliminate a data race on the completed_q to avoid req->state inconsistency

* Wed Dec 9 2015 <paul.j.reger@intel.com>
- Fixes two more critical problems flagged by KlockWorks.  These two problems are the same as those in sha 4bb697dd7341e176b586a44ff90ef88c411c00a2 but they occur in different sections of code.

* Wed Dec 9 2015 <kyle.liddell@intel.com>
- Fixed the broken outoforder_q list manipulation functions

* Tue Dec 8 2015 <levi.e.dettwyler@intel.com>
- Revert "Optimization: removed 4 bytes from ips_epaddr"

* Tue Dec 8 2015 <levi.e.dettwyler@intel.com>
- Fixed EPID generation for self-only mode

* Mon Dec 7 2015 <paul.j.reger@intel.com>
- Fixes problem with the sources in the dist tar file not able to make child dist tar files that can be built with rpmbuild.

* Mon Dec 7 2015 <paul.j.reger@intel.com>
- Fixes two problems flagged by KlockWorks contained in the three issues: 840, 843 and 844.

* Thu Dec 3 2015 <levi.e.dettwyler@intel.com>
- AM request and reply scbctrls are finalized

* Thu Dec 3 2015 <levi.e.dettwyler@intel.com>
- Fixed a deadlock in AM req/rep communication

* Wed Dec 2 2015 <kyle.liddell@intel.com>
- Implement PSM MQ using hash tables for faster message lookup

* Tue Dec 1 2015 <levi.e.dettwyler@intel.com>
- Revert "Implement PSM MQ using hash tables for faster message lookup"

* Mon Nov 30 2015 <kyle.liddell@intel.com>
- Implement PSM MQ using hash tables for faster message lookup

* Fri Nov 20 2015 <nathan.b.white@intel.com>
- Follow fixes to RAPID CCA

* Thu Nov 19 2015 <levi.e.dettwyler@intel.com>
- Optimization: removed 4 bytes from ips_epaddr

* Thu Nov 19 2015 <levi.e.dettwyler@intel.com>
- Handle return 0 for hfi_cmd_writev in scb_dma_send

* Thu Nov 19 2015 <paul.j.reger@intel.com>
- Fixed problem with an endless loop for reduced ulimit settings.

* Wed Nov 18 2015 <nathan.b.white@intel.com>
- Initial implementation of RAPID CCA

* Fri Nov 13 2015 <levi.e.dettwyler@intel.com>
- Fixed a buffer overflow in AM introduced by 6ca71c

* Thu Nov 12 2015 <paul.j.reger@intel.com>
- Change error handling for failure to lock pages to match driver's change.

* Tue Nov 3 2015 <paul.j.reger@intel.com>
- Improve readability of an obscure expression.  Does not change code.

* Tue Oct 27 2015 <kyle.liddell@intel.com>
- PSM support for handling TID packets intercepted by RSM

* Fri Oct 23 2015 <levi.e.dettwyler@intel.com>
- epaddrs are now freed and NULL'd on disconnect

* Mon Oct 19 2015 <cq.tang@intel.com>
- Fix PSM send/receive buffer over accessing, fix the PSM wire protocol compliance issue.

* Mon Oct 19 2015 <cq.tang@intel.com>
- Improve short message (8B < X <=8K) bandwidth and lower latency.

* Mon Oct 19 2015 <cq.tang@intel.com>
- A new PSM timer operation to reduce latency

* Fri Oct 16 2015 <levi.e.dettwyler@intel.com>
- Fixed a problem with retransmission of last packet

* Tue Oct 13 2015 <paul.j.reger@intel.com>
- Moved PSM2 library major/minor version numbers and build date to PSM2_IDENTIFY

* Fri Oct 9 2015 <russell.w.mcguire@intel.com>
- Exported 3 symbols to fix hfi1_pkt_test link

* Fri Oct 9 2015 <paul.j.reger@intel.com>
- Added PSM2 library major/minor version numbers and build date to trace output.

* Fri Oct 9 2015 <paul.j.reger@intel.com>
- Eliminated annoying error: bc: command not found

* Wed Oct 7 2015 <russell.w.mcguire@intel.com>
- Rename PSM_LOG_MSG to PSM2_LOG_MSG

* Wed Oct 7 2015 <henry.r.estela@intel.com>
- Add UDEVDIR to udev compat rule. 40-psm-compat.rules now installs to the same place prescribed in the spec file.

* Wed Oct 7 2015 <russell.w.mcguire@intel.com>
- Expose hfi_ various symbols for hfidiag builds

* Wed Oct 7 2015 <henry.r.estela@intel.com>
- Clean up compat symbols. Added version script to only export psm_* symbols. Removed extra make flags by creating a lightweight buildflags.mak for compat. Compat shouldn't need extra psm2 buld features such as avx, debug, etc.

* Wed Oct 7 2015 <henry.r.estela@intel.com>
- Rework compat package to not conflict with infinipath-psm Created new compat directory to hold psm1 compat related files. There is a new modprobe.d file that will run a script when ib_qib is added and when it is removed. This will handle the case when hfi1 is loaded before ib_qib.

* Wed Oct 7 2015 <russell.w.mcguire@intel.com>
- Renamed all publicly exposed psm_ symbols to psm2_

* Wed Oct 7 2015 <npayyavu@sperf-29.sc.intel.com>
- Fix for bug relating to incorrect error reporting for uncorrectable errors

* Wed Oct 7 2015 <paul.j.reger@intel.com>
- Revert "A new PSM timer operation to reduce latency"

* Wed Oct 7 2015 <paul.j.reger@intel.com>
- Revert "Improve short message (8B < X <=8K) bandwidth and lower latency."

* Wed Oct 7 2015 <paul.j.reger@intel.com>
- Revert "Fix for PSM blocking send returning early, causing segfault"

* Tue Oct 6 2015 <henry.r.estela@intel.com>
- Add udev path substitution to specfile. The spefcile needs to use the same path that the Makefile installs the udev rules to. '\' was used instead of '/' as an escape character for sed. '/' can't be used because it will confuse sed because '/'s are used in file paths and sed will think they are also escape characters.

* Mon Oct 5 2015 <levi.e.dettwyler@intel.com>
- Revert "Fixed timeout behavior in psm_ep_close()"

* Mon Oct 5 2015 <kyle.liddell@intel.com>
- Fix for PSM blocking send returning early, causing segfault

* Fri Oct 2 2015 <nathan.b.white@intel.com>
- Merge branch 'upstream_master'

* Thu Oct 1 2015 <paul.j.reger@intel.com>
- Added guard for possible NULL FILE pointer.

* Wed Sep 30 2015 <levi.e.dettwyler@intel.com>
- Fixed timeout behavior in psm_ep_close()

* Wed Sep 30 2015 <kyle.liddell@intel.com>
- Latency improvements - remove unnecessary packet header checks

* Wed Sep 30 2015 <paul.j.reger@intel.com>
- Improves error message from psm for failure to open a specific unit/port.

* Tue Sep 29 2015 <kyle.liddell@intel.com>
- Latency improvements - reduce frequency of receive header queue updates

* Thu Sep 24 2015 <levi.e.dettwyler@intel.com>
- Fix a compile error introduced by c44a5bd7

* Thu Sep 24 2015 <levi.e.dettwyler@intel.com>
- Fixed workaround for compiler error about ignoring write return value

* Thu Sep 24 2015 <levi.e.dettwyler@intel.com>
- Fixed an error code leak in ips_proto_mq_isend

* Fri Sep 18 2015 <paul.j.reger@intel.com>
- Removes the tmi tar file.

* Fri Sep 18 2015 <paul.j.reger@intel.com>
- Allows psm to recover from cable pull events that last shorter than 30 seconds.

* Wed Sep 16 2015 <cq.tang@intel.com>
- Improve short message (8B < X <=8K) bandwidth and lower latency.

* Tue Sep 15 2015 <paul.j.reger@intel.com>
- Only adds AVX instructions in psm library when the PSM_AVX env var is set.

* Tue Sep 15 2015 <cq.tang@intel.com>
- A new PSM timer operation to reduce latency

* Mon Sep 14 2015 <npayyavu@sperf-38.sc.intel.com>
- Fixed a bug related to PSM_MULTIRAIL. Seg Faults were detected

* Mon Sep 14 2015 <paul.j.reger@intel.com>
- REVERTS Change for turning _HFI_DEBUGGING off in release builds.

* Thu Sep 10 2015 <paul.j.reger@intel.com>
- Turns 'self cca' off in STL1, and fixes incorrect reading of cca data from driver.

* Tue Sep 8 2015 <alex.estrin@intel.com>
- hfi1-psm: add udev rules for non-root /dev/hfi1 access.

* Fri Sep 4 2015 <paul.j.reger@intel.com>
- Corrects many issues from Klock works static analysis of psm library code.

* Fri Sep 4 2015 <paul.j.reger@intel.com>
- Adds support for building psm library with icc compiler using CCARCH environment variable.

* Thu Sep 3 2015 <cq.tang@intel.com>
- Fix mpi_stress testing segfault.

* Thu Sep 3 2015 <cq.tang@intel.com>
- Fix PSM registration error during mpi_stress test

* Thu Sep 3 2015 <npayyavu@sperf-30.sc.intel.com>
- PSM is no longer hijacking signals and releasing them when the library is unloaded. A destructor has been added for this purpose. JIRA ID: SL-583

* Thu Sep 3 2015 <henry.r.estela@intel.com>
- Add .gitignore ignore o, d, and _revision.c , and so files from compilation.

* Wed Sep 2 2015 <npayyavu@sperf-27.sc.intel.com>
- ignal Handling

* Wed Sep 2 2015 <cq.tang@intel.com>
- remove MTU from epid and compress epid structure

* Tue Sep 1 2015 <paul.j.reger@intel.com>
- Turns _HFI_DEBUGGING off in release builds.

* Tue Sep 1 2015 <cq.tang@intel.com>
- Improve PSM tid packets wire protocol.

* Thu Aug 27 2015 <cq.tang@intel.com>
- Find the best PIO block copying code at compile time and runtime.

* Fri Aug 14 2015 <levi.e.dettwyler@intel.com>
- Adding gcov support to build process

* Fri Aug 14 2015 <cq.tang@intel.com>
- PSM tid registration caching

* Thu Aug 13 2015 <kyle.liddell@intel.com>
- Properly detect if epid is on same host, fix error handler

* Thu Aug 13 2015 <npayyavu@sperf-26.sc.intel.com>
- Changed signal handling to also call old signal handlers.

* Wed Aug 12 2015 <kyle.liddell@intel.com>
- Keep PSM MQ initialized and safe to use until psm_ep_close()

* Mon Aug 10 2015 <kyle.liddell@intel.com>
- Fix ptl_am connect failure and lower system resource consumption

* Mon Aug 10 2015 <levi.e.dettwyler@intel.com>
- Removed "testing" entry from table of contents; not a real section

* Wed Aug 5 2015 <levi.e.dettwyler@intel.com>
- Moving test and libcm content to dedicated repo wfr-psm-test.git

* Fri Jul 31 2015 <levi.e.dettwyler@intel.com>
- Added HFI_MIN_PORT definition

* Thu Jul 30 2015 <paul.j.reger@intel.com>
- Adds backtrace to PSM_LOG functionality.

* Wed Jul 29 2015 <paul.j.reger@intel.com>
- Moved the files that were previously in the devel-noship rpm into the devel rpm.

* Tue Jul 28 2015 <levi.e.dettwyler@intel.com>
- Adding PSM CI scripts used for internal nightly builds

* Tue Jul 28 2015 <paul.j.reger@intel.com>
- Removed the noship rpm from the set of rpm's that psm builds.

* Mon Jul 27 2015 <levi.e.dettwyler@intel.com>
- Fixed a bug where timeout in psm_ep_close is ignored

* Mon Jul 27 2015 <paul.j.reger@intel.com>
- Updates for PSM_LOG capabilities, clean up and finalizes implementation

* Fri Jul 24 2015 <kyle.liddell@intel.com>
- Add a memset() after a posix_memalign() that was originally a calloc()

* Thu Jul 23 2015 <paul.j.reger@intel.com>
- Updates for PSM_LOG capabilities, adds analysis tool

* Thu Jul 23 2015 <paul.j.reger@intel.com>
- Removes README.OLD and test subdirectory from distribution as it is not needed.

* Tue Jul 21 2015 <paul.j.reger@intel.com>
- Updates README file for upstreaming PSM 2 source code.

* Mon Jul 20 2015 <paul.j.reger@intel.com>
- Fixes hang in PSM library.

* Wed Jul 15 2015 <kyle.liddell@intel.com>
- Improvements to ptl_am shm object naming and initialization

* Tue Jul 7 2015 <kyle.liddell@intel.com>
- Remove PSM per-job local process limit, cleanup ptl_am

* Tue Jun 30 2015 <kyle.liddell@intel.com>
- Remove old code path optimizations

* Fri Jun 26 2015 <paul.j.reger@intel.com>
- Removes TODO and NOTPUBLIC_BEGIN ... NOTPUBLIC_END sequences

* Wed Jun 17 2015 <paul.j.reger@intel.com>
- Removes code words and power pc code from PSM library code.

* Tue Jun 16 2015 <cq.tang@intel.com>
- PSM uses two VLs when OPP path query is used.

* Tue Jun 16 2015 <cq.tang@intel.com>
- Avoid PSM to run on VL15 or SC15.

* Fri Jun 12 2015 <cq.tang@intel.com>
- Improve PIO copying performance by copying large blocks.

* Fri Jun 12 2015 <john.fleck@intel.com>
- Change -d reference in makefile to be -e. For STL2, the teamforge repo will host what is in CVS currently. Rather than using an import method to get external repos, we will use git submodules to track external repos. The catch is the .git are files in the submodules. To build, we need to change the makefile to look for the existence of .git (-e) rather than the existence of the directory of .git (-d)

* Mon Jun 8 2015 <paul.j.reger@intel.com>
- Changes copyrights to the dual copyright and removes some files from dist.

* Thu Jun 4 2015 <kyle.liddell@intel.com>
- Improve checking for unknown endpoints in received messages

* Mon Jun 1 2015 <alex.estrin@intel.com>
- hfi-psm: remove extra path to exported hfi1_user.h

* Fri May 29 2015 <kyle.liddell@intel.com>
- Update STL MTU enumeration to match latest STL spec

* Thu May 28 2015 <kyle.liddell@intel.com>
- Rewrite shared memory PTL to support dynamic processes

* Thu May 14 2015 <nathan.b.white@intel.com>
- Removed debug struct from beginning of psmi_malloc

* Mon May 11 2015 <paul.j.reger@intel.com>
- Fix another problem with upstreaming commit.  Symlink should be named ipath not opa.

* Wed May 6 2015 <paul.j.reger@intel.com>
- Revert change that changed the name of compatibility library to libpsm_opa.so

* Tue May 5 2015 <paul.j.reger@intel.com>
- Modified references to about 85 symbols defined in hfi1_user.h.

* Fri May 1 2015 <paul.j.reger@intel.com>
- Rebased with 'master' of ssh://git-amr-2.devtools.intel.com:29418/wfr-psm

* Tue Apr 28 2015 <mike.marciniszyn@intel.com>
- Remove uuid code

* Mon Apr 27 2015 <paul.j.reger@intel.com>
- These changes fix building the test and libcm subdirectories (the test subdirectory depends on the libcm subdirectory).

* Thu Apr 23 2015 <paul.j.reger@intel.com>
- Added bounds check on subctxt_cnt member of user_info and fixed a segv for debug code.

* Wed Apr 22 2015 <kyle.liddell@intel.com>
- Shared memory PTL kernel-assist copy length fix

* Mon Apr 13 2015 <kyle.liddell@intel.com>
- PSM TID session allocation fix for large message bug

* Mon Apr 13 2015 <alex.estrin@intel.com>
- psm: add location path for user-mode exported hfi1_user.h.

* Tue Apr 7 2015 <kyle.liddell@intel.com>
- Fixes for AM over IPS failure and poor performance.

* Thu Apr 2 2015 <cq.tang@intel.com>
- Enhance the expected tid transfer window size.

* Wed Apr 1 2015 <mike.marciniszyn@intel.com>
- correct HFI_EVENT_HFI_FROZEN to match final header

* Wed Apr 1 2015 <cq.tang@intel.com>
- Fix PSM flow CCA divisor/ipd initial value.

* Tue Mar 31 2015 <dennis.dalessandro@intel.com>
- Fix RPM file names to handle hfi rename.

* Mon Mar 30 2015 <cq.tang@intel.com>
- Fix PSM to recover from freeze mode

* Mon Mar 30 2015 <dennis.dalessandro@intel.com>
- Handle hfi device rename.

* Mon Mar 16 2015 <cq.tang@intel.com>
- Fix static rate control setting condition.

* Mon Mar 16 2015 <cq.tang@intel.com>
- Fix Bi-directional Bandwidth dip at 16K/32K

* Mon Mar 9 2015 <todd.rimmer@intel.com>
- psm: add makesrpm.sh to allow simplification of build processes

* Fri Mar 6 2015 <cq.tang@intel.com>
- Minor fix to header file document.

* Wed Mar 4 2015 <cq.tang@intel.com>
- Fix context sharing hanging on large A0 silicon.

* Wed Mar 4 2015 <andrew.friedley@intel.com>
- Backwards compatibility -- override 0x7FFF PKEY

* Tue Mar 3 2015 <cq.tang@intel.com>
- Fix PSM not generate BECN when FECN is received for large message.

* Tue Mar 3 2015 <cq.tang@intel.com>
- improve sdma flow control

* Mon Mar 2 2015 <cq.tang@intel.com>
- Fix sdma completion when scb is to be retransmitted.

* Wed Feb 18 2015 <cq.tang@intel.com>
- Temp fix PSM with RH-7 compiler

* Fri Feb 13 2015 <cq.tang@intel.com>
- Make HFI loopback a runtime selection in PSM

* Mon Feb 9 2015 <kyle.liddell@intel.com>
- Remove PSM buffer over-reads for odd-sized send requests

* Thu Feb 5 2015 <cq.tang@intel.com>
- PSM uses driver defined max subcontext number

* Tue Feb 3 2015 <cq.tang@intel.com>
- Remove unused structure field.

* Tue Feb 3 2015 <cq.tang@intel.com>
- Fix tid protocol sender side descriptor limitation.

* Tue Feb 3 2015 <andrew.friedley@intel.com>
- Remove psm-compat dependency on hfi-utils

* Mon Feb 2 2015 <cq.tang@intel.com>
- Remove unaligned data packet.

* Fri Jan 30 2015 <andrew.friedley@intel.com>
- Add ipath symlink udev rule in hfi-psm-compat

* Thu Jan 29 2015 <cq.tang@intel.com>
- Optimize tidflow index usage

* Thu Jan 29 2015 <cq.tang@intel.com>
- Using static array of receive descriptor

* Thu Jan 29 2015 <cq.tang@intel.com>
- remove tid control packets.

* Thu Jan 29 2015 <cq.tang@intel.com>
- Fix PSM connection index from 64K to 64M

* Thu Jan 29 2015 <cq.tang@intel.com>
- Change PSM/drive API.

* Wed Jan 28 2015 <kyle.liddell@intel.com>
- Modifications to support path record query with libofedplus

* Mon Jan 26 2015 <cq.tang@intel.com>
- Fix context sharing error.

* Mon Jan 26 2015 <cq.tang@intel.com>
- Change IPS_RECVHDRQ_OOO to IPS_RECVHDRQ_REVISIT

* Fri Jan 23 2015 <cq.tang@intel.com>
- Fix the flow->xmit_ack_num usage.

* Wed Jan 14 2015 <kyle.liddell@intel.com>
- Generate and use header dependencies during make process

* Fri Jan 9 2015 <cq.tang@intel.com>
- Change PSM/drive API.

* Thu Jan 8 2015 <cq.tang@intel.com>
- Optimize PSM receiving to reduce code path length.

* Wed Dec 17 2014 <cq.tang@intel.com>
- Reset a send context after it is halted for some reason.

* Tue Dec 16 2014 <cq.tang@intel.com>
- Fix an eager/expected tids splitting problem

* Wed Dec 10 2014 <kyle.liddell@intel.com>
- Remove old memcpy code

* Mon Dec 8 2014 <andrew.friedley@intel.com>
- Remove extra entry in error string table

* Mon Dec 8 2014 <andrew.friedley@intel.com>
- Recognize "ipath" in PSM_DEVICES.

* Thu Dec 4 2014 <mike.marciniszyn@intel.com>
- Fix warning in hfi_sighdlr()

* Tue Dec 2 2014 <andrew.friedley@intel.com>
- Add environment variable to print MQ stats

* Mon Nov 24 2014 <cq.tang@intel.com>
- Fix pthread_spin_init() flag

* Mon Nov 24 2014 <cq.tang@intel.com>
- PSM needs to manage expected tids in group unit.

* Mon Nov 24 2014 <cq.tang@intel.com>
- Add PSM control to disable header suppression while driver enable it

* Fri Nov 21 2014 <cq.tang@intel.com>
- A small code enhancement to deal with chunk processing

* Tue Nov 18 2014 <cq.tang@intel.com>
- A small perfromance improvement.

* Tue Nov 18 2014 <cq.tang@intel.com>
- PSM handle GenErr first and ignore TidErr if any

* Tue Nov 18 2014 <cq.tang@intel.com>
- Improve tid packets receiving logic and NAK sequence.

* Tue Nov 18 2014 <cq.tang@intel.com>
- Improve PSM packets retransmission.

* Mon Nov 17 2014 <arthur.kepner@intel.com>
- psm: add support for CCA on WFR

* Thu Nov 13 2014 <kyle.liddell@intel.com>
- Fix expected rendezvous to use the correct scb buffer

* Thu Nov 13 2014 <kyle.liddell@intel.com>
- Clean up code to cleanly compile on GCC 4.8+

* Wed Nov 12 2014 <andrew.friedley@intel.com>
- Multi-rail support for AM

* Wed Nov 12 2014 <andrew.friedley@intel.com>
- Refactor ips_proto_check_msg_order

* Wed Nov 12 2014 <andrew.friedley@intel.com>
- Refactor sysbuf code

* Tue Nov 11 2014 <kyle.liddell@intel.com>
- Updated PSM ERRCHK timeout defaults to better match FPGA behavior

* Fri Oct 24 2014 <cq.tang@intel.com>
- Fix pure sdma mode with wrong sdma request.

* Fri Oct 24 2014 <andrew.friedley@intel.com>
- Fix typo: svb -> scb

* Fri Oct 24 2014 <andrew.friedley@intel.com>
- Reduce amhdr_len field size to 4 bits

* Wed Oct 22 2014 <cq.tang@intel.com>
- Fix sdma completion queue overrun.

* Mon Oct 13 2014 <cq.tang@intel.com>
- Improve generr and seqerr processing with or without hdrsupp.

* Mon Oct 13 2014 <cq.tang@intel.com>
- Fix the expected tid packet processing in error case

* Mon Oct 13 2014 <cq.tang@intel.com>
- Print the correct header gen/seq for tid packet

* Mon Oct 13 2014 <cq.tang@intel.com>
- Improvement subcontext packet and error message processing.

* Fri Oct 10 2014 <cq.tang@intel.com>
- Allow user to change the eager buffer queue size.

* Thu Oct 9 2014 <cq.tang@intel.com>
- Fix PSM packet header flag bit setting when using SDMA packet generation.

* Thu Oct 2 2014 <andrew.friedley@intel.com>
- Return error on successive calls to psm_ep_open

* Wed Oct 1 2014 <andrew.friedley@intel.com>
- Apply Lindent and checkpatch.pl to code base

* Wed Oct 1 2014 <andrew.friedley@intel.com>
- checkpatch.pl trips on _GETENV_PRINTF

* Thu Sep 25 2014 <cq.tang@intel.com>
- Fix a progression hanging when running context sharing.

* Thu Sep 25 2014 <cq.tang@intel.com>
- Fix context sharing initialization timing bug

* Thu Sep 25 2014 <andrew.friedley@intel.com>
- Switch TIDFLOWDISABLE -> ENABLE

* Tue Sep 23 2014 <cq.tang@intel.com>
- Fix tid-receive generation number truncation.

* Tue Sep 23 2014 <cq.tang@intel.com>
- Fix context sharing for more than 2-way

* Tue Sep 16 2014 <cq.tang@intel.com>
- Remove redundant field ep_hdrq_msg_size in PSM

* Tue Sep 16 2014 <cq.tang@intel.com>
- Remove redundant header suppression checking in PSM

* Tue Sep 16 2014 <cq.tang@intel.com>
- Small enhancement for PSM code.

* Tue Sep 16 2014 <andrew.friedley@intel.com>
- Update status2 fields for isends

* Mon Sep 15 2014 <mike.marciniszyn@intel.com>
- Add back in define to support diag build

* Mon Sep 15 2014 <andrew.friedley@intel.com>
- Make msgctrl/ips_epaddr co-location explicit.

* Mon Sep 15 2014 <andrew.friedley@intel.com>
- Add 'recvfrom' API support.

* Mon Sep 15 2014 <andrew.friedley@intel.com>
- Remove 'prev' linked list link.

* Thu Sep 11 2014 <cq.tang@intel.com>
- Add PSM SDMA functionality using new PSM/driver SDMA API

* Tue Aug 26 2014 <cq.tang@intel.com>
- Add compiling option to support FPGA loopback

* Tue Aug 26 2014 <cq.tang@intel.com>
- Fixing segfault in PSM with big FPGA run

* Tue Aug 26 2014 <cq.tang@intel.com>
- Fix wrong RHF writing order in context sharing.

* Mon Aug 25 2014 <cq.tang@intel.com>
- PSM to support multi-packets per eager buffer.

* Thu Aug 21 2014 <andrew.friedley@intel.com>
- Add Intel copyright notices.

* Thu Aug 14 2014 <cq.tang@intel.com>
- Add PSM processing with SL->SC->SL

* Thu Aug 14 2014 <cq.tang@intel.com>
- Misc enhancement for PSM

* Thu Aug 14 2014 <cq.tang@intel.com>
- Fix PSM behavior on invalid PKEY

* Thu Aug 7 2014 <andrew.friedley@intel.com>
- Revert "Temp workaround of HSD 291213 to make PSM test to pass"

* Thu Aug 7 2014 <cq.tang@intel.com>
- Temp workaround of HSD 291213 to make PSM test to pass

* Fri Aug 1 2014 <andrew.friedley@intel.com>
- PSM/AM epaddr/token changes.

* Wed Jul 30 2014 <cq.tang@intel.com>
- Remove bit field operation for PBC

* Wed Jul 30 2014 <cq.tang@intel.com>
- Fixed bug introduced in previous shared memoru PKEY change.

* Wed Jul 30 2014 <cq.tang@intel.com>
- Fix context sharing hanging with nodma_rtail=1 option

* Wed Jul 30 2014 <cq.tang@intel.com>
- Fix PKEY query problem without IPS device

* Tue Jul 29 2014 <andrew.friedley@intel.com>
- Replace source-ID based PSM2 with 96-bit tag API

* Thu Jul 24 2014 <cq.tang@intel.com>
- Fix the pkey processing during job start without path-query

* Tue Jul 22 2014 <andrew.friedley@intel.com>
- Remove status from testwait_callback.

* Mon Jul 21 2014 <cq.tang@intel.com>
- Small improve to PSM code

* Mon Jul 21 2014 <cq.tang@intel.com>
- Remove KDETH bit operation.

* Tue Jul 8 2014 <cq.tang@intel.com>
- Change PSM startup environment/default-value setting sequence.

* Thu Jun 26 2014 <cq.tang@intel.com>
- This patch fixes the PIO critical path performance issue.

* Wed Jun 18 2014 <andrew.friedley@intel.com>
- Remove bulk PUSH/PULL selection.

* Mon Jun 16 2014 <cq.tang@intel.com>
- HFI_SIZE_OF_CRC and HFI_CRC_SIZE_IN_BYTES are always confusing. This change improve the code readability by removing HFI_SIZE_OF_CRC and only keeping HFI_CRC_SIZE_IN_BYTES. Also changing BYTE2WORD_SHIFT to BYTE2DWORD_SHIFT.

* Mon Jun 16 2014 <andrew.friedley@intel.com>
- Remove rarely used amsh_qpkt_max struct.

* Mon Jun 16 2014 <andrew.friedley@intel.com>
- Remove unused loopback variable.

* Fri Jun 13 2014 <andrew.friedley@intel.com>
- Disable loopback path in PTL AM.

* Thu Jun 12 2014 <andrew.friedley@intel.com>
- Properly set source_id on all EPs.

* Thu Jun 12 2014 <andrew.friedley@intel.com>
- Replace unwanted debug print with assertions.

* Thu Jun 12 2014 <andrew.friedley@intel.com>
- Remove 2kb 'medium' buffers.

* Wed Jun 11 2014 <henry.r.estela@intel.com>
- Restore macros with IPATH references

* Mon Jun 9 2014 <andrew.friedley@intel.com>
- Add matched probe and receive API extension

* Mon Jun 9 2014 <andrew.friedley@intel.com>
- Code cleanup -- remove unnecessary struct/global.

* Mon Jun 2 2014 <andrew.friedley@intel.com>
- Remove PTL AM 'Huge' communication buffers.

* Fri May 23 2014 <mike.marciniszyn@intel.com>
- psm: fix psm1 build with new compat rpms

* Fri May 23 2014 <mike.marciniszyn@intel.com>
- psm: correct build links for in-tree use

* Wed May 21 2014 <mike.marciniszyn@intel.com>
- psm: consolidate libinfinipath in psm2

* Wed May 21 2014 <mike.marciniszyn@intel.com>
- psm: rename main .so and add compat rpm

* Tue May 20 2014 <cq.tang@intel.com>
- Support all MTU supported by STL1 in PSM

* Thu May 15 2014 <andrew.friedley@intel.com>
- PSM2 API implementation.

* Wed May 14 2014 <cq.tang@intel.com>
- Add PSM control over receive context behavior

* Wed May 14 2014 <cq.tang@intel.com>
- Change the context sharing group ID meaning

* Wed May 14 2014 <cq.tang@intel.com>
- PSM to support new job_key managment

* Wed May 14 2014 <cq.tang@intel.com>
- Ignore and retry when driver can't register page.

* Wed May 14 2014 <cq.tang@intel.com>
- Checking link is down before getting real LID

* Wed May 14 2014 <cq.tang@intel.com>
- Print packet header fields for bad packets.

* Wed May 14 2014 <andrew.friedley@intel.com>
- Disable unexpected callbacks.

* Mon May 5 2014 <cq.tang@intel.com>
- This patch fixes the context sharing code with tid-receive

* Mon Apr 28 2014 <mike.marciniszyn@intel.com>
- fix psm build issue

* Tue Apr 22 2014 <andrew.friedley@intel.com>
- Revive PSM Active Messages interface.

* Mon Apr 7 2014 <john.fleck@intel.com>
- Add make install action.

* Fri Mar 28 2014 <andrew.friedley@intel.com>
- Avoid doing a transfer when kassis GET is enabled.

* Wed Mar 26 2014 <cq.tang@intel.com>
- Add WFR expected tid receive support, this includes new tid registration, new tidinfo format and processing, context sharing of tid-array using spin lock, context sharing of tidflow table using spin lock. The shared info among subcontext processes is put in the subcontext register page. This page is structured to have registers, PIO sharing structure, tid sharing structure, and tidflow table sharing structure.

* Tue Mar 18 2014 <andrew.friedley@intel.com>
- Clean up some branching now that CMA is only kassist option.

* Wed Mar 12 2014 <andrew.friedley@intel.com>
- Remove library references from the devel-noship RPM.

* Tue Mar 11 2014 <cq.tang@intel.com>
- Further reduce flow state 'ipsaddr' structure by 8 bytes.

* Tue Mar 11 2014 <cq.tang@intel.com>
- Per Mark's request to add support of max 8:1 context sharing.

* Tue Mar 11 2014 <andrew.friedley@intel.com>
- Remove knem and kcopy.

* Tue Mar 11 2014 <andrew.friedley@intel.com>
- Adding CMA kassist support.

* Mon Mar 10 2014 <cq.tang@intel.com>
- Fix bug in PSM with nodma_rtail=1 driver option, PSM does not pick the packet sequence number from the right location of the header. Also added hfi_hdrget_egrbfr_offset() macro for latest multi- packets per eager buffer use.

* Mon Mar 10 2014 <cq.tang@intel.com>
- Fixed a segfault found by Andrew. The request sequence number is not set to zero. then later when we use 0 as sequence number to search the corresponding request, the returned request is NULL.

* Mon Mar 10 2014 <andrew.friedley@intel.com>
- Add a psm-devel-noship RPM package for use by wfr-diagtools-sw.

* Wed Mar 5 2014 <cq.tang@intel.com>
- This big change is to rework on medium message protocol.

* Mon Mar 3 2014 <cq.tang@intel.com>
- Matching the group size 8 requirement. Both eager array and tid array must be multiple of 8 entries. (Given the total receive array is multiple of 8).

* Mon Mar 3 2014 <cq.tang@intel.com>
- Change the receive array splitting method to allow max configuration. there are max 2048 eager array and 2048 tid array (1024 tid-pairs). But normally eager array is 25% of total receive array.

* Sat Mar 1 2014 <cq.tang@intel.com>
- Fix a segfault during disconnecting stage. A fake ipsaddr is created, but it's field ipsaddr->proto is not initialized, later when code tries to access this field, it causes segfault.

* Wed Feb 26 2014 <cq.tang@intel.com>
- This change further reduce flow-state by 24 bytes. instead of using per flow eager-queue and outoforder-queue, we use such queue on per MQ basis. We hope such queues will be in short length and the earching time is negligible.

* Mon Feb 3 2014 <cq.tang@intel.com>
- remove base_info.context and base_info.subcontext, use ctxt_info.context and ctxt_info.subcontext instead.

* Mon Feb 3 2014 <cq.tang@intel.com>
- Add hfi_qwordcpy(), optimize SPIO block writing code.  This change is for performance and to make sure that PSM only issue qword write to PIO buffer.  This is required by hardware.

* Mon Feb 3 2014 <mike.marciniszyn@intel.com>
- psm: Drop2 changes for psm

* Fri Jan 31 2014 <cq.tang@intel.com>
- driver has progressed to configure the status page flags, but PSM is still having a temp solution to catch any bit in pstatus.  This change is to match the driver code and make both latest PSM and latest driver work together.

* Fri Jan 31 2014 <cq.tang@intel.com>
- This is the context sharing work for PIO.  the PIO blocks control is put in a shared page in uregbase page for subcontexts.

* Thu Jan 30 2014 <cq.tang@intel.com>
- Basically two changes: 1. Using a single page for context sharing uregister base, struct ips_subcontext_ureg has both registers and other control info, this structure is in shared memory. 2. change the epid definition to add MTU and RANK, this is a preparation for connectionless startup at large scale.

* Wed Jan 29 2014 <cq.tang@intel.com>
- Add 31bit PSN and 24bit PSN support in PSM. During startup, driver will tell PSM which mode to use. PSM precalculate a psn_mask for either 31bit PSN or 24bit PSN, and apply the mask to PSN whenever the value is changed.

* Tue Jan 28 2014 <cq.tang@intel.com>
- ips_recvhdrq.c:  remove set but not used variable 'err'

* Wed Jan 8 2014 <cq.tang@intel.com>
- This is big change to make PSM to work on WFR simulator for PIO and Eager receive.

