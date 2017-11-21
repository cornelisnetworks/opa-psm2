#!/bin/bash
#
#  This file is provided under a dual BSD/GPLv2 license.  When using or
#  redistributing this file, you may do so under either license.
#
#  GPL LICENSE SUMMARY
#
#  Copyright(c) 2017 Intel Corporation.
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
#  Copyright(c) 2017 Intel Corporation.
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

# Stop on error
set -e

BUILD_OPTS="gGbBAS"
BUILD_OPT=
DEB_NAME=libpsm2

# OUT_DIR is where the Makefile places its meta-data
OUT_DIR=build_release

# Set BUILD_DIR first, so user control can override the value
# This is where this script places deb(s) and uses its build meta-data.
# It can be set the same as OUT_DIR, and work just fine if desired.
BUILD_DIR=temp.$$

function literate()
{
    echo $(sed "s/\B/&$2/g" <<< "$1")
}

function usage()
{
    SCRIPT=${0##*/}
    echo "Usage: $SCRIPT [OPTIONS]"
    echo
    echo "Creates tar ball of source and source rpms by default."
    echo "Optionally generates binary rpm(s) "
    echo
    echo "     $(literate $BUILD_OPTS ',')"
    echo "           Optional, default is full build (source and binary)"
    echo "           Set single extension letter for dpkg-buildpackage argument"
    echo "     -r <name>"
    echo "           Optional, set the output deb name"
    echo "     -e <basename ext>"
    echo "           Optional, set a base name extension"
    echo "           This only appends an extra string onto the base DEB name"
    echo "           Does not affect supporting DEBs"
    echo "     -c"
    echo "           Optional, default is unset"
    echo "           Sets PSM_CUDA=1, creating -cuda based manifest and debs"
    echo "     -d <path>"
    echo "           Optionally sets output folder for dpkg-buildpackage to use"
    echo "     -h"
    echo "           Shows this screen"
    echo "     Examples:"
    echo "           $SCRIPT b"
    echo "           $SCRIPT s -c"
    echo "           $SCRIPT -"
    echo "           $SCRIPT -d ./temp"
    echo "           $SCRIPT b -c -d output"
    exit $1
}

while getopts "r:e:cd:h$BUILD_OPTS" OPT; do
    case $OPT in
        r)
            DEB_NAME=$OPTARG
            ;;
        e)
            BASE_EXT=$OPTARG
            ;;
        c)
            export PSM_CUDA=1
            DEB_EXT="-cuda"
            ;;
        d)
            BUILD_DIR=$OPTARG
            ;;
        h)
            usage 0
            ;;
        \?)
            usage 1
            ;;
        *)
            BUILD_OPT=-$OPT
            ;;
    esac
done

# Remove parsed options
shift $((OPTIND-1))

# Check if we have any non-option parameters
test ! $# -eq 0 && usage

# Generic cleanup, build, and tmp folder creation
make distclean OUTDIR=$OUT_DIR

make RPM_NAME=$DEB_NAME RPM_NAME_BASEEXT=$BASE_EXT dist OUTDIR=$OUT_DIR

# Prepare build area
mkdir -p $BUILD_DIR/{build,binary,sources,dists}

# Differnet paths based on DEB_EXT
cp $OUT_DIR/$DEB_NAME-*.tar.gz $BUILD_DIR/dists/

FILE_BASE=$(basename $BUILD_DIR/dists/$DEB_NAME-*.tar.gz .tar.gz)
VERSION=${FILE_BASE##$DEB_NAME-}

echo Building $DEB_NAME version $VERSION...

tar xzf $BUILD_DIR/dists/$DEB_NAME-$VERSION.tar.gz -C $BUILD_DIR/build

(cd $BUILD_DIR/build/$DEB_NAME-$VERSION

# Annotate changelog
mv debian/changelog.in debian/changelog
debchange --newversion=$VERSION "Bump up version to $VERSION"

# Build package
dpkg-buildpackage $BUILD_OPT -us -uc -tc)

mv $BUILD_DIR/build/$DEB_NAME*{.tar.xz,.dsc,.changes} $BUILD_DIR/sources/
mv $BUILD_DIR/build/$DEB_NAME*{.deb,.ddeb} $BUILD_DIR/binary/

echo "The deb package(s) is (are) in $BUILD_DIR/binary/$(ls $BUILD_DIR/binary)"
