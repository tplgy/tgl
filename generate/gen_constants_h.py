#!/usr/bin/env python

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
