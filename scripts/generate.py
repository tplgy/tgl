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
#    Copyright Vitaly Valtman 2014-2015
#    Copyright Topology LP 2016

import build_lib
import os
import re
import shutil
import subprocess
import sys

def transform(pattern):
    if pattern.group(0) == ".":
        return "_"
    return "_" + pattern.group(0).lower()

def generate_constants_header():
    scheme_file = open(os.path.join("auto", "scheme2.tl"), "w+")

    r = build_lib.run_command_stderr_to_file(os.path.join(".", "tl-parser") + " -E " + os.path.join("auto", "scheme.tl"), scheme_file)
    if r != 0:
        sys.exit(r)

    scheme_file.seek(0, os.SEEK_SET)

    f = open(os.path.join("auto", "constants.h"), "w")
    f.write("#ifndef __TGL_CONSTANTS_H__\n")
    f.write("#define __TGL_CONSTANTS_H__\n")

    for line in scheme_file:
        list = line.strip().split("#")
        if len(list) < 2:
            continue
        code_list = list[1].split()
        if len(code_list) < 1:
            continue
        name = re.sub(r"[A-Z.]+", lambda pattern: transform(pattern), list[0])
        f.write("#define CODE_" + name + " 0x" + code_list[0] + "\n")

    f.write("#endif\n")

def concatenate_small_files(file_names, out_file_name):
    out_file = open(out_file_name, "w")
    for file_name in file_names:
        in_file = open(file_name, "r")
        out_file.write(in_file.read())

def generate_by_name(what, is_header):
    dest_file_name = os.path.join("auto", "auto-" + what + (".h" if is_header else ".cpp"))
    command = os.path.join(".", "generate") + " -g " + what + ("-header " if is_header else " ") + os.path.join("auto", "scheme.tlo")
    f = open(dest_file_name, "w")
    r = build_lib.run_command_stdout_to_file(command, f)
    if r != 0:
        sys.exit(r)

if not (len(sys.argv) == 3 or len(sys.argv) == 4):
    print("wrong arguemnts")
    sys.exit(1)

SRC_DIR = sys.argv[1]
BUILD_DIR = sys.argv[2]
CC = "cc"
if len(sys.argv) == 4:
    CC = sys.argv[3]

if not os.path.isdir(BUILD_DIR) or not os.path.exists(BUILD_DIR):
    print("build directory doesn't exist")
    sys.exit(1)

os.chdir(BUILD_DIR)

if not os.path.exists(os.path.join(BUILD_DIR, "auto")):
    os.mkdir(os.path.join(BUILD_DIR, "auto"))

r = build_lib.run_command(CC + " " + os.path.join(SRC_DIR, "generate", "generate.c") + " -o generate")
if r != 0:
    sys.exit(r)

r = build_lib.run_command(CC + " " + os.path.join(SRC_DIR, "tl-parser", "tl-parser.c") + " " + os.path.join(SRC_DIR, "tl-parser", "tlc.c") + " -lz -o tl-parser")
if r != 0:
    sys.exit(r)

auto_srcs = [os.path.join(SRC_DIR, "auto", "scheme.tl"), \
             os.path.join(SRC_DIR, "auto", "encrypted_scheme.tl"), \
             os.path.join(SRC_DIR, "auto", "mtproto.tl"), \
             os.path.join(SRC_DIR, "auto", "append.tl")]

concatenate_small_files(auto_srcs, os.path.join("auto", "scheme.tl"))

generate_constants_header()

r = build_lib.run_command(os.path.join(".", "tl-parser") + " -e " + os.path.join("auto", "scheme.tlo") + " " + os.path.join("auto", "scheme.tl"))
if r != 0:
    sys.exit(r)

for what in ["fetch-ds", "free-ds", "skip", "types"]:
    generate_by_name(what, is_header=True)
    generate_by_name(what, is_header=False)
