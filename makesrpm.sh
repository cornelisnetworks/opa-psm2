#!/bin/bash
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

#It makes no sense to have both CUDA and non-CUDA in the same invocation
#as they require different versions of the hfi1_user.h at this point in time.
#Limiting this script to only build CUDA if requested

#default BUILDARG to build source RPM only
BUILDARG=s
RPM_NAME=libpsm2

function usage()
{
    echo "Usage: $0 [OPTION] [OPTION] [OPTION]"
    echo " "
    echo "Creates tar ball of source and source rpms by default."
    echo "Optionally generates binary rpm(s) "
    echo " "
    echo "     s,a,b,p,c,i,l"
    echo "           Optional, default is s (sourcerpm)"
    echo "           Set single extension letter for rpmbuild -b argument"
    echo "     -r <name>, -rpmname <name>"
    echo "           Optional, set the output rpm name"
    echo "     -e <basename ext>, -baseext <basename ext>"
    echo "           Optional, set a base name extension"
    echo "           This only appends an extra string onto the base RPM name"
    echo "           Does not affect supporting RPMs"
    echo "     -c, -cuda"
    echo "           Optional, default is unset"
    echo "           Sets PSM_CUDA=1, creating -cuda based spec and rpms"
    echo "     -d <path>, -dir <path>"
    echo "           Optionally sets output folder for rpmbuild to use"
    echo "     -h <hal_gen>, -hal_gen <hal_gen>"
    echo "           Optional, default is includes all HAL generations"
    echo "           Sets hal generations for rpmbuild to use"
    echo "     Examples:"
    echo "           $0 b"
    echo "           $0 s -cuda"
    echo "           $0 -cuda"
    echo "           $0 -d ./temp"
    echo "           $0 b -cuda -dir output"
    echo "           $0 -h gen1"
    exit 1
}

err=0

# OUTDIR is where the Makefile places its meta-data
OUTDIR=build_release

# Set TEMPDIR first, so user control can override the value
# This is where rpmbuild places rpm(s) and uses its build meta-data.
# It can be set the same as OUTDIR, and work just fine if desired.
TEMPDIR=temp.$$

HAL_GENS=""

while [ "$1" != "" ]; do
    case $1 in
        -d | -dir)      shift
                        if [ -z "$1" ]; then
                            usage
                        fi
                        TEMPDIR=$1
                        ;;
        -c | -cuda)     export PSM_CUDA=1
                        RPM_EXT="-cuda"
                        ;;
        -e | -baseext)  shift
                        if [ -z "$1" ]; then
                            usage
                        fi
                        RPM_NAME_BASEEXT="$1"
                        export RPM_NAME_BASEEXT="$1"
                        ;;
        -h | -halgen)   shift
                        HAL_GENS="$1 $HAL_GENS"
	                ;;
        -r | -rpmname)  shift
                        if [ -z "$1" ]; then
                            usage
                        fi
                        $RPM_NAME="$1"
                        export RPM_NAME="$1"
                        ;;
        s|a|b|p|c|i|l)  BUILDARG=$1
                        ;;
        * )             err=1
                        usage
                        ;;
    esac
    shift
done

if [ "$HAL_GENS" = "" ]; then
    HAL_GENS="*"
fi

# Generic cleanup, build, and tmp folder creation
make distclean OUTDIR=$OUTDIR
make RPM_NAME=$RPM_NAME RPM_NAME_BASEEXT=$RPM_NAME_BASEEXT "PSM_HAL_ENABLE=$HAL_GENS" dist OUTDIR=$OUTDIR
mkdir -p ./$TEMPDIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
# Different paths based on RPM_EXT
cp ${OUTDIR}/$RPM_NAME-*.tar.gz $TEMPDIR/SOURCES
make RPM_NAME=$RPM_NAME RPM_NAME_BASEEXT=$RPM_NAME_BASEEXT specfile OUTDIR=$OUTDIR
cp ${OUTDIR}/$RPM_NAME.spec $TEMPDIR/SPECS
rpmbuild -b$BUILDARG --define "_topdir $PWD/$TEMPDIR" --nodeps $TEMPDIR/SPECS/$RPM_NAME.spec

echo "The SRPM(s) are in $TEMPDIR/SRPMS/`ls $TEMPDIR/SRPMS`"
