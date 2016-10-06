#
#    Copyright Topology LP 2016
#

import os
import subprocess
import sys
from multiprocessing import cpu_count

def get_host_os():
    os_map = { "linux2" : "linux", "darwin" : "osx", "win32"  : "win"}
    os = os_map.get(sys.platform)
    if os:
        return os
    return "unknown"

def is_osx_host():
    return "osx" == get_host_os()

def is_linux_host():
    return "linux" == get_host_os()

def is_win_host():
    return "win" == get_host_os()

def get_num_cores():
    return cpu_count()

def get_scripts_dir():
    return os.path.dirname(os.path.abspath(__file__))

def get_main_dir():
    return os.path.abspath(os.path.join(get_scripts_dir(), ".."))

def get_dev_dir():
    return os.path.abspath(os.path.join(get_main_dir(), ".."))

def get_build_dir(release):
    return os.path.abspath(os.path.join(get_main_dir(), "build", "release" if release else "debug"))

def get_host_install_prefix(release):
    return os.path.abspath(os.path.join(get_dev_dir(), "staging", "release" if release else "debug"))

def run_command(command, verbose = True):
    if verbose:
        print "\n___ running \'{}\'' in \'{}\'\n".format(command, os.getcwd())
    return subprocess.call(command, shell=True)

def run_command_stdout_to_file(command, f):
    return subprocess.call(command, shell=True, stdout=f)

def run_command_stderr_to_file(command, f):
    return subprocess.call(command, shell=True, stderr=f)
