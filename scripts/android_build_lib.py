#
#    Copyright Topology LP 2016
#

import os
import platform
import shutil
import stat
import subprocess
import sys
import time
import build_lib

def get_ndk_dir():
    if "ANDROID_NDK_ROOT" in os.environ:
        ndk_dir = os.environ["ANDROID_NDK_ROOT"]
        if os.path.exists(ndk_dir):
            return ndk_dir

    return get_default_ndk_dir()

def get_default_ndk_dir():
    if "ANDROID_HOME" in os.environ:
        ndk_dir = os.path.join(os.environ["ANDROID_HOME"], "ndk-bundle")
        if os.path.exists(ndk_dir):
            return ndk_dir

    return ""

def get_toolchain_dir(arch):
    return os.path.join(build_lib.get_dev_dir(), "android-toolchain-" + arch)

def get_toolchain_name(arch):
    if arch == "x86":
        return "i686-linux-android"
    elif arch == "x86_64":
        return "x86_64-linux-android"
    elif arch == "arm64":
        return "aarch64-linux-android"
    elif arch == "arm":
        return "arm-linux-androideabi"
    else:
        return None

def get_build_dir(arch, release):
    return os.path.join(build_lib.get_main_dir(), "build-android", "release" if release else "debug", arch)

def get_install_prefix(arch, release):
    return os.path.join(build_lib.get_dev_dir(), "staging-android", "release" if release else "debug", arch)

def get_abi(arch):
    if arch == "arm":
         return "armeabi-v7a"
    elif arch == "arm64":
        return "arm64-v8a"
    else:
        return arch

def get_compiler_flags(arch):
    if arch == "arm":
        return "-march=armv7-a -mfloat-abi=softfp -mfpu=neon"
    elif arch == "arm64":
        return "-march=armv8-a"
    else:
        return ""

def get_link_flags(arch):
    if arch == "arm":
        return "-march=armv7-a -Wl,--fix-cortex-a8"
    elif arch == "arm64":
        return "-march=armv8-a"
    else:
        return ""

def get_cmake_toolchain():
    return os.path.join(build_lib.get_main_dir(), "scripts", "android", "android.toolchain.cmake")

def get_platform(arch):
    return "android-21"

def create_toolchain(arch):
    ndk_dir = get_ndk_dir()
    if not os.path.exists(ndk_dir):
        print "\nAndroid NDK not found. Cannot continue.\n"
        return 1

    toolchain_dir = get_toolchain_dir(arch)

    # Make the standalone toolchain if necessary
    if not os.path.exists(toolchain_dir):
        return build_lib.run_command(os.path.join(ndk_dir, "build", "tools", "make_standalone_toolchain.py") + " --arch " + arch + " --api 21 --stl gnustl --install-dir " + toolchain_dir)

def run_gradle(args):
    host_os = sys.platform
    if host_os is "win32":
        return subprocess.call(["./gradlew.bat"] + args)
    else:
        return subprocess.call(["./gradlew"] + args)
