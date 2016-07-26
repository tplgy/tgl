#!/usr/bin/env python

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
#    Copyright Topology LP 2016

import re
import sys

def transform(pattern):
    if pattern.group(0) == ".":
        return "_"
    return "_" + pattern.group(0).lower()

if len(sys.argv) != 2:
    print("wrong arguemnts")
    sys.exit(1)

f = open(sys.argv[1], "r")

print "#ifndef __TGL_CONSTANTS_H__"
print "#define __TGL_CONSTANTS_H__"

for line in f:
    list = line.strip().split("#")
    if len(list) < 2:
        continue
    code_list = list[1].split()
    if len(code_list) < 1:
        continue
    name = re.sub(r"[A-Z.]+", lambda pattern: transform(pattern), list[0])
    sys.stdout.write("#define CODE_" + name + " 0x")
    print code_list[0]

print "#endif"
