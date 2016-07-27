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
    return os.path.join(build_lib.get_dev_dir(), "android-ndk-r12")

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

def install_ndk():
    os.chdir(build_lib.get_dev_dir())
    ndk_name = "android-ndk-r12"
    install_prefix = "android-toolchain"
    if os.path.exists(ndk_name):
        return 0

    # Fetch the NDK
    host_os_map = { "linux2" : "linux", "darwin" : "darwin", "win32"  : "windows"}
    host_os = host_os_map.get(sys.platform, None)
    if host_os is None:
        return 1

    host_arch = platform.machine()
    ndk_file_prefix = ndk_name + "-" + host_os + "-" + host_arch
    ndk_file = ndk_file_prefix + ".zip"

    # Download and unzip the NDK
    r = build_lib.run_command("wget http://dl.google.com/android/repository/" + ndk_file + " -O " + ndk_file)
    if r != 0:
        return r

    r = build_lib.run_command("unzip " + ndk_file)
    if r != 0:
        return r

    # Remove the zip file
    os.remove(ndk_file)

    # Clean up any standalone toolchains
    if os.path.exists(install_prefix):
        shutil.rmtree(install_prefix)

    return 0

def create_toolchain(arch):
    ndk_dir = get_ndk_dir()
    if not os.path.exists(ndk_dir):
        print "\nAndroid NDK not found. Installing it...\n"
        r = install_ndk()
        if r != 0:
            return r

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
