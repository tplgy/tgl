#
#    Copyright Topology LP 2016
#

import glob
import os
import build_lib

def get_ndk_dir():
    if "ANDROID_NDK_HOME" in os.environ:
        ndk_dir = os.environ["ANDROID_NDK_HOME"]
        if os.path.exists(ndk_dir):
            return ndk_dir

    if "ANDROID_HOME" in os.environ:
        ndk_dir = os.path.join(os.environ["ANDROID_HOME"], "ndk-bundle")
        if os.path.exists(ndk_dir):
            return ndk_dir

    return ""

def cmake_path():
    if "ANDROID_HOME" in os.environ:
        cmake_dir = os.path.join(os.environ["ANDROID_HOME"], "cmake")
        if os.path.exists(cmake_dir):
            cmake_installs = sorted(glob.glob(os.path.join(cmake_dir, "*")))
            if cmake_installs:
                return os.path.join(cmake_installs[-1], "bin", "cmake")

    return "cmake"

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

def get_cmake_toolchain():
    return os.path.join(get_ndk_dir(), "build", "cmake", "android.toolchain.cmake")

def get_platform(arch):
    return "android-21"
