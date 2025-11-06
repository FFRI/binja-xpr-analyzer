#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#
import os
import subprocess


def get_target_executable(debugger):
    file_spec = debugger.GetSelectedTarget().GetExecutable()
    directory = file_spec.GetDirectory()
    filename = file_spec.GetFilename()
    full_path = os.path.join(directory, filename)
    return full_path


def get_current_architecture(debugger) -> str:
    triple = debugger.GetSelectedTarget().GetTriple()
    if "x86_64" in triple:
        return "x86_64"
    elif "arm64e" in triple:
        return "arm64e"
    elif "arm64" in triple:
        return "arm64"
    else:
        print(f"Unsupported architecture: {triple}")
        return None


def get_bss_section_info(debugger):
    arch = get_current_architecture(debugger)
    if arch is None:
        return None, None
    cmd = ["/usr/bin/size", "-arch", arch, "-ml", get_target_executable(debugger)]
    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    print(output)
    for l in output.split("\n"):
        if "__bss" in l:
            bss_size = int(l.strip().split(":")[-1].split(" ")[1])
            bss_addr = int(l.strip().split(":")[-1].split(" ")[3], 16)
            return bss_size, bss_addr
    return None, None


def extract(debugger, command, result, internal_dict):
    bss_size, bss_addr = get_bss_section_info(debugger)
    filename = "/tmp/bss_section_dump.bin"
    debugger.HandleCommand(f"memory read --force --binary -c {hex(bss_size)} {hex(bss_addr)} --outfile {filename}")
    debugger.HandleCommand("c")
    os.system(f"strings {filename} > /tmp/config.txt")


def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    print(f"Target executable: {target.GetExecutable()}")
    debugger.HandleCommand("setting set target.max-string-summary-length 10000")
    debugger.HandleCommand("command script add -f extract_config.extract cmd_extract_config")
    debugger.HandleCommand("breakpoint set -n unsetenv -C \"cmd_extract_config\"")
