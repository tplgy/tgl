#!/bin/bash

#    This file is part of tgl-library
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#    Copyright Vitaly Valtman 2014-2015
#    Copyright Topology LP 2016

SRC_DIR=$1
BUILD_DIR=$2
CC=${3-cc}

if [ ! -d $BUILD_DIR ]; then
    exit 1;
fi

cd $BUILD_DIR
mkdir -p $BUILD_DIR/auto || exit 1

$CC $SRC_DIR/generate/generate.c -o generate || exit 1
$CC $SRC_DIR/tl-parser/tl-parser.c $SRC_DIR/tl-parser/tlc.c -lz -o tl-parser || exit 1

cat $SRC_DIR/auto/scheme.tl $SRC_DIR/auto/encrypted_scheme.tl $SRC_DIR/auto/mtproto.tl $SRC_DIR/auto/append.tl > auto/scheme.tl || exit 1
./tl-parser -E auto/scheme.tl 2> auto/scheme2.tl || exit 1
./tl-parser -e auto/scheme.tlo auto/scheme.tl || exit 1

if [ ! -f auto/constants.h ]; then
    $SRC_DIR/generate/gen_constants_h.py auto/scheme2.tl > auto/constants.h || exit 1
else
    $SRC_DIR/generate/gen_constants_h.py < auto/scheme2.tl > auto/.constants.h || exit 1
    diff auto/constants.h auto/.constants.h &>/dev/null && rm -f auto/.constants.h &>/dev/null || mv auto/.constants.h auto/constants.h
fi

for what in fetch-ds free-ds skip types; do
    if [ ! -f auto/auto-$what.cpp ]; then
        ./generate -g $what auto/scheme.tlo > auto/auto-$what.cpp; \
    else
        ./generate -g $what auto/scheme.tlo > auto/.auto-$what.cpp || exit 1
        diff auto/auto-$what.cpp auto/.auto-$what.cpp &>/dev/null && rm -f auto/.auto-$what.cpp &>/dev/null || mv auto/.auto-$what.cpp auto/auto-$what.cpp
    fi

    if [ ! -f auto/auto-$what.h ]; then
        ./generate -g $what-header auto/scheme.tlo > auto/auto-$what.h; \
    else
        ./generate -g $what-header auto/scheme.tlo > auto/.auto-$what.h || exit 1
        diff auto/auto-$what.h auto/.auto-$what.h &>/dev/null && rm -f auto/.auto-$what.h &>/dev/null || mv auto/.auto-$what.h auto/auto-$what.h
    fi
done
