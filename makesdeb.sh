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
#  Copyright(c) 2016 Intel Corporation.
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

BUILD_OPTS="gFGbBAS"
BUILD_OPT=F
SIGN_PKG=1

function literate()
{
    echo $(sed "s/\B/&$2/g" <<< "$1")
}

function usage()
{
    echo "Usage: ${0##*/} [-h] [-n] [debuild -($(literate $BUILD_OPTS '|'))]"
	echo "    -n : do not sign package"
    exit $1
}

while getopts "hn$BUILD_OPTS" OPT; do
    case $OPT in
        h)
            usage
                ;;
        \?)
            usage 1
                ;;
		n)
			SIGN_PKG=0
			    ;;
        *)
            BUILD_OPT=$OPT
                ;;
    esac
done

# Remove parsed options
shift $((OPTIND-1))

# Check if we have any non-option parameters
test ! $# -eq 0 && usage

# Annotate changelog
cat debian/changelog.in > debian/changelog

GIT_TAG_PREFIX=PSM2_
GIT_TAG_RELEASE=$(git describe --tags --long --match="$GIT_TAG_PREFIX*")
VERSION=$(sed -e "s/^$GIT_TAG_PREFIX\(.\+\)-\(.\+\)-.\+/\1_\2/" -e 's/_/./g' -e 's/-/./g' <<< "$GIT_TAG_RELEASE")

DEBUILD_OPTS=
if [ $SIGN_PKG -eq 0 ] ; then
	DEBUILD_OPTS="-us -uc"
fi

debchange --newversion=$VERSION "Bump up version to $VERSION"

debchange --release ""

# Build package
debuild -$BUILD_OPT -tc $DEBUILD_OPTS

echo "The deb package(s) is (are) in parent directory"

