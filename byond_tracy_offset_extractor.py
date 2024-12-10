"""
@file
@copyright 2024
@author Sovexe (https://github.com/Sovexe)
@license MIT
"""

import lief
import sys
import os
from typing import List, Optional
from dataclasses import dataclass
from colorama import Fore, Style, init

# colorama
init(autoreset=True)
INFO = Fore.CYAN
DEBUG = Fore.MAGENTA
ERROR = Fore.RED
WARN = Fore.YELLOW
RESULTS = Fore.GREEN
RESET = Style.RESET_ALL

# Patterns and Offsets
# PE Base
PE_BASE_PATTERN = bytes.fromhex(
    "4b 8b 34 98 85 f6 74 4f 8b 4e 38 c7 45 fc 00 00 00 00 85 c9"
)
PE_BASE_OFFSETS = {
    "strings": -0xD4,
    "strings_len": -0x4E,
    "miscs": -0xB8,
    "procdefs": -0xF8,
}

# OLD ELF Base for 1643 and lower
OLD_ELF_BASE_PATTERN = bytes.fromhex(
    "8d b4 26 00 00 00 00 8b 46 38 89 47 38 c7 46 38 00 00 00 00 89 34 24"
)
OLD_ELF_BASE_OFFSETS = {
    "strings": -0xF2,
    "strings_len": -0x5D,
    "miscs": -0xD1,
    "procdefs": -0x120,
}

# NEW ELF Base for 1644 and newer
NEW_ELF_BASE_PATTERN = bytes.fromhex(
    "8d b4 26 00 00 00 00 90 83 ec 0c 53 83 c3 01"
)
NEW_ELF_BASE_OFFSETS = {
    "strings": -0x268,
    "strings_len": -0x1D6,
    "miscs": -0x248,
    "procdefs": -0x294,
}

# Function patterns (exec_proc, server_tick, send_maps)
# PE exec_proc
PE_EXEC_PROC_PATTERN = bytes.fromhex("64 a1 00 00 00 00 50 51 53 81 ec 30 0a 00 00")
PE_EXEC_PROC_OFFSETS = {
    "exec_proc": -0x1d
}

# PE server_tick
PE_SERVER_TICK_PATTERN = bytes.fromhex("5f b0 01 5e c3 5f 32 c0 5e c3 cc cc 55")
PE_SERVER_TICK_OFFSETS = {
    "server_tick": 0xC
}

# PE send_maps
PE_SEND_MAPS_PATTERN = bytes.fromhex(
    "89 85 b0 fb ff ff 89 85 90 fb ff ff 8b 86 08 00 00 00 89 95 ac fb ff ff 89 95 8c fb ff ff 89 85 b8 fb ff ff"
)
PE_SEND_MAPS_OFFSETS = {
    "send_maps": -0x5c
}

# OLD ELF exec_proc
OLD_ELF_EXEC_PROC_PATTERN = bytes.fromhex(
    "89 95 24 f8 ff ff c7 45 94 00 00 00 00 c7 45 98 00 00 00 00 c7 45 8c 00 00 00 00 c7 45 90 00 00 00 00 89 85 c4 f7 ff ff 8b 42 18 85 c0"
)
OLD_ELF_EXEC_PROC_OFFSETS = {
    "exec_proc": -0x17
}

# OLD ELF server_tick
OLD_ELF_SERVER_TICK_PATTERN = bytes.fromhex(
    "8b 4d c4 89 55 cc 8b 55 c0 89 45 c8 29 55 c8 19 4d cc 8b 55 c8 8b 4d cc c7 04 24 01 00 00 00"
)
OLD_ELF_SERVER_TICK_OFFSETS = {
    "server_tick": -0xC0
}

# OLD ELF send_maps
OLD_ELF_SEND_MAPS_PATTERN = bytes.fromhex(
    "55 89 e5 57 56 53 81 ec 2c 09 00 00 65 a1 00 00 00 00 89 85 50 f7 ff ff 89 85 4c f7 ff ff 80 78 14 00"
)
OLD_ELF_SEND_MAPS_OFFSETS = {
    "send_maps": 0x000
}

# NEW ELF exec_proc
NEW_ELF_EXEC_PROC_PATTERN = bytes.fromhex(
    "89 95 d8 fc ff ff 89 85 00 fc ff ff 8b 42 18 c7 85 20 fd ff ff 00 00 00 00 c7 85 24 fd ff ff 00 00 00 00 c7 85 28 fd ff ff 00 00 00 00 c7 85 2c fd ff ff 00 00 00 00 85 c0"
)
NEW_ELF_EXEC_PROC_OFFSETS = {
    "exec_proc": -0x17
}

# NEW ELF server_tick
NEW_ELF_SERVER_TICK_PATTERN = bytes.fromhex(
    "66 0f 6e c0 66 0f 6e ca 66 0f 62 c1 66 0f d6 04 24 66 0f 6f d0"
)
NEW_ELF_SERVER_TICK_OFFSETS = {
    "server_tick": -0x2D
}

# NEW ELF send_maps
NEW_ELF_SEND_MAPS_PATTERN = bytes.fromhex(
    "55 89 e5 57 56 53 81 ec ec 08 00 00 65 a1 00 00 00 00 80 78 14 00 89 85 78 f7 ff ff 89 85 54 f7 ff ff"
)
NEW_ELF_SEND_MAPS_OFFSETS = {
    "send_maps": 0x000
}

# Define function names that should be treated as functions
FUNCTION_NAMES = {"exec_proc", "send_maps", "server_tick"}

# 4 bytes as byond is 32bit
POINTER_BYTE_LENGTH = 4

def find_pattern(data, pattern):
    """Search for the byte pattern in the binary data."""
    if not pattern:
        return -1
    index = data.find(pattern)
    if index != -1:
        print(f"{INFO}[INFO] Pattern found at offset: 0x{index:X}{RESET}")
    return index

def find_pattern_with_wildcards(data, pattern, pattern_name):
    """Search for a byte pattern with wildcards (None) in the binary data."""
    pattern_length = len(pattern)
    for i in range(len(data) - pattern_length + 1):
        match = True
        for j in range(pattern_length):
            if pattern[j] is not None and data[i + j] != pattern[j]:
                match = False
                break
        if match:
            print(f"{INFO}[INFO] Wildcard pattern '{pattern_name}' found at offset: 0x{i:X}{RESET}")
            return i
    return -1

def get_section_from_rva(binary, rva, binary_format):
    """Determine which section contains the given RVA."""
    for section in binary.sections:
        sec_va = section.virtual_address
        sec_size = section.size
        if sec_va <= rva < sec_va + sec_size:
            return section
    return None

def get_image_base(binary, binary_format):
    """Retrieve the image base depending on binary format."""
    if binary_format == 'PE':
        return binary.optional_header.imagebase
    elif binary_format == 'ELF':
        print(f"{INFO}[INFO] Listing all LOAD segments:{RESET}")
        for i, segment in enumerate(binary.segments):
            if segment.type == 1:  # PT_LOAD segment
                flags = []
                if segment.flags & 0x1:  # PF_X
                    flags.append('E')
                if segment.flags & 0x2:  # PF_W
                    flags.append('W')
                if segment.flags & 0x4:  # PF_R
                    flags.append('R')
                flags_str = ''.join(flags)
                print(f"  LOAD Segment {i+1}: VA={hex(segment.virtual_address)}, Size={hex(segment.virtual_size)}, Flags={flags_str}")

        # Find the first LOAD segment with execute flag
        for segment in binary.segments:
            if (segment.type == 1 and (segment.flags & 0x1)):  # PF_X
                print(f"{INFO}  [INFO] Selected LOAD segment with EXECUTE flag: VA = {hex(segment.virtual_address)}{RESET}")
                return segment.virtual_address
        # Fallback to first LOAD segment if no EXECUTE flag is found
        first_load = next((seg for seg in binary.segments if seg.type == 1), None)
        if first_load:
            print(f"{WARN}[WARN] No EXECUTE flag found. Using first LOAD segment: VA = {hex(first_load.virtual_address)}{RESET}")
            return first_load.virtual_address
        else:
            print(f"{ERROR}[ERROR] No loadable segment found in ELF binary.{RESET}")
            sys.exit(1)
    else:
        print(f"{ERROR}[ERROR] Unsupported binary format: {binary_format}.{RESET}")
        sys.exit(1)

def read_pointer(binary, rva, POINTER_BYTE_LENGTH, binary_format):
    """Read a pointer of given size from the specified RVA."""
    section = get_section_from_rva(binary, rva, binary_format)
    if section is None:
        print(f"{ERROR}[ERROR] RVA 0x{rva:X} not found in any section.{RESET}")
        return None

    offset_in_section = rva - section.virtual_address
    sec_size = section.size

    if offset_in_section + POINTER_BYTE_LENGTH > sec_size:
        print(f"{ERROR}[ERROR] Attempting to read beyond the section at RVA 0x{rva:X}.{RESET}")
        return None

    try:
        data = binary.get_content_from_virtual_address(rva, POINTER_BYTE_LENGTH)
        if len(data) < POINTER_BYTE_LENGTH:
            print(f"{ERROR}[ERROR] Not enough data to read at RVA 0x{rva:X}.{RESET}")
            return None
        raw_value = int.from_bytes(bytes(data), byteorder="little")
        print(f"{DEBUG}[DEBUG] Read raw value: 0x{raw_value:08X} from RVA: 0x{rva:08X}{RESET}")
        return raw_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Exception while reading pointer at RVA 0x{rva:X}: {e}{RESET}")
        return None

def validate_address(binary, address, POINTER_BYTE_LENGTH, binary_format):
    """Validate if the address points to a valid data section."""
    for section in binary.sections:
        sec_va = section.virtual_address
        sec_size = section.size
        if sec_va <= address < sec_va + sec_size:
            return True
    return False

def compute_addresses(binary, pattern_rva, image_base, POINTER_BYTE_LENGTH, relative_offsets, binary_format):
    addresses = {}
    for name, relative_offset in relative_offsets.items():
        print(f"{INFO}[INFO] Computing address for '{name}':{RESET}")
        pointer_rva = pattern_rva + relative_offset
        print(f"       Pattern RVA: 0x{pattern_rva:X} + Offset: 0x{relative_offset:X} = Pointer RVA: 0x{pointer_rva:X}")

        if name in FUNCTION_NAMES:
            # For functions, compute address as pattern_rva + relative_offset
            adjusted_address = pattern_rva + relative_offset
            addresses[name] = adjusted_address
            print(f"{INFO}       Computed Address for '{name}': 0x{adjusted_address:08X}{RESET}")
        else:
            # For data, read the pointer value
            raw_value = read_pointer(binary, pointer_rva, POINTER_BYTE_LENGTH, binary_format)
            if raw_value is None:
                addresses[name] = None
                print(f"{WARN}[WARN] Could not read pointer for '{name}'.{RESET}")
            else:
                if binary_format == 'PE':  # only adjust address for windows binary
                    adjusted_address = raw_value - image_base
                    print(f"{INFO}       Adjusted Address for '{name}': 0x{adjusted_address:08X}{RESET}")
                else:
                    adjusted_address = raw_value                
                addresses[name] = adjusted_address

    return addresses

@dataclass
class ComplexOffsetPattern:
    name: str
    pattern: List[Optional[int]]
    first_wildcard_pos: int
    second_wildcard_pos: int

# patterns for procdef
PROCDEF_COMPLEX_OFFSET_PATTERNS = {
    "PE": ComplexOffsetPattern(
        name="procdef",
        pattern=[
            0xff, 0x70, None, 0xe8, None, None, None, None, 0x83, 0xc4, 0x04,
            0x85, 0xc0, 0x75, 0x04, 0x33, 0xc9, 0xeb, 0x0a, 0x0f, 0xb7, 0x00,
            0x8d, 0x0c, 0x85, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xf0, 0x83,
            0xc0, None
        ],
        first_wildcard_pos=2,
        second_wildcard_pos=34
    ),
    "ELF_old": ComplexOffsetPattern(
        name="procdef",
        pattern=[
            0x8b, 0x40, None, 0x89, 0x04, 0x24, None, None, None, None, None,
            0x31, 0xd2, 0x85, 0xc0, 0x74, 0x0a, 0x0f, 0xb7, 0x00, 0x8d,
            0x14, 0x85, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xe0, 0x8d,
            0x44, 0x02, None
        ],
        first_wildcard_pos=2,
        second_wildcard_pos=33
    ),
    "ELF_new": ComplexOffsetPattern(
        name="procdef",
        pattern=[
            0xff, 0x70, None, 0xe8, None, None, None, None, 0x83, 0xc4, 0x10,
            0x85, 0xc0, 0x0f, 0x84, 0x1a, 0x05, 0x00, 0x00, 0x0f, 0xb7, 0x00,
            0x8d, 0x14, 0x85, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xc8, 0x8d,
            0x44, 0x02, None
        ],
        first_wildcard_pos=2,
        second_wildcard_pos=35
    )
}

def extract_procdef(data: bytes, base_address: int, procdef_pattern: ComplexOffsetPattern, binary_format: str):
    """Extract the 'procdef' complex offset from a given pattern."""
    pattern_offset = find_pattern_with_wildcards(data, procdef_pattern.pattern, procdef_pattern.name)
    if pattern_offset == -1:
        print(f"{WARN}[WARN] {procdef_pattern.name} pattern not found.{RESET}")
        return None

    pattern_rva = base_address + pattern_offset
    print(f"{INFO}[INFO] {procdef_pattern.name} Pattern RVA: 0x{pattern_rva:08X}{RESET}")

    if procdef_pattern.second_wildcard_pos >= len(procdef_pattern.pattern):
        print(f"{ERROR}[ERROR] Second wildcard position {procdef_pattern.second_wildcard_pos} exceeds pattern length for {procdef_pattern.name}.{RESET}")
        return None

    if pattern_offset + procdef_pattern.second_wildcard_pos >= len(data):
        print(f"{ERROR}[ERROR] Second wildcard position is out of bounds for {procdef_pattern.name}.{RESET}")
        return None

    byte1 = data[pattern_offset + procdef_pattern.first_wildcard_pos]
    byte2 = data[pattern_offset + procdef_pattern.second_wildcard_pos]

    # Format as 0x00??00??, extracting byte1 and byte2
    complex_offset = f"0x00{byte1:02X}00{byte2:02X}"
    print(f"{INFO}[INFO] Extracted {procdef_pattern.name}: {complex_offset}{RESET}")

    return complex_offset

def main():
    args = sys.argv[1:]
    if not args:
        print(f"{ERROR}[ERROR] No arguments provided. Usage: {sys.argv[0]} <binary_path> [--use-old-elf]{RESET}")
        sys.exit(1)
    
    binary_path = None
    use_old_elf = False

    for arg in args:
        if arg == "--use-old-elf":
            use_old_elf = True
        elif binary_path is None:
            binary_path = arg
        else:
            print(f"{ERROR}[ERROR] Unexpected argument: {arg}{RESET}")
            print(f"Usage: {sys.argv[0]} <binary_path> [--use-old-elf]")
            sys.exit(1)

    if binary_path is None:
        print(f"{ERROR}[ERROR] Binary path not provided.{RESET}")
        print(f"Usage: {sys.argv[0]} <binary_path> [--use-old-elf]")
        sys.exit(1)

    _, ext = os.path.splitext(binary_path.lower())
    if ext == '.dll':
        binary_format = 'PE'
    elif ext == '.so':
        binary_format = 'ELF'
    else:
        print(f"{ERROR}[ERROR] Unsupported file extension: {ext}.{RESET}")
        sys.exit(1)

    # Load binary
    binary = lief.parse(binary_path)
    if not binary:
        print(f"{ERROR}[ERROR] Failed to load binary.{RESET}")
        sys.exit(1)
    else:
        print(f"{INFO}[INFO] Successfully loaded binary: {binary_path}{RESET}")

    # Get image base
    image_base = get_image_base(binary, binary_format)
    print(f"{INFO}[INFO] Image Base (l_addr): 0x{image_base:08X}{RESET}")

    # Get .text section
    text_section = binary.get_section(".text")
    if not text_section:
        print(f"{ERROR}[ERROR] .text section not found.{RESET}")
        sys.exit(1)
    else:
        print(f"{INFO}[INFO] .text section found.{RESET}")

    text_data = bytes(text_section.content)
    text_va = text_section.virtual_address

    if binary_format == "PE":
        base_pattern = PE_BASE_PATTERN
        base_offsets = PE_BASE_OFFSETS

        exec_proc_pattern = PE_EXEC_PROC_PATTERN
        exec_proc_offsets = PE_EXEC_PROC_OFFSETS

        server_tick_pattern = PE_SERVER_TICK_PATTERN
        server_tick_offsets = PE_SERVER_TICK_OFFSETS

        send_maps_pattern = PE_SEND_MAPS_PATTERN
        send_maps_offsets = PE_SEND_MAPS_OFFSETS

        procdef_pattern = PROCDEF_COMPLEX_OFFSET_PATTERNS["PE"]
    else:  # ELF
        if use_old_elf:
            base_pattern = OLD_ELF_BASE_PATTERN
            base_offsets = OLD_ELF_BASE_OFFSETS

            exec_proc_pattern = OLD_ELF_EXEC_PROC_PATTERN
            exec_proc_offsets = OLD_ELF_EXEC_PROC_OFFSETS

            server_tick_pattern = OLD_ELF_SERVER_TICK_PATTERN
            server_tick_offsets = OLD_ELF_SERVER_TICK_OFFSETS

            send_maps_pattern = OLD_ELF_SEND_MAPS_PATTERN
            send_maps_offsets = OLD_ELF_SEND_MAPS_OFFSETS

            procdef_pattern = PROCDEF_COMPLEX_OFFSET_PATTERNS["ELF_old"]
        else:
            base_pattern = NEW_ELF_BASE_PATTERN
            base_offsets = NEW_ELF_BASE_OFFSETS

            exec_proc_pattern = NEW_ELF_EXEC_PROC_PATTERN
            exec_proc_offsets = NEW_ELF_EXEC_PROC_OFFSETS

            server_tick_pattern = NEW_ELF_SERVER_TICK_PATTERN
            server_tick_offsets = NEW_ELF_SERVER_TICK_OFFSETS

            send_maps_pattern = NEW_ELF_SEND_MAPS_PATTERN
            send_maps_offsets = NEW_ELF_SEND_MAPS_OFFSETS

            procdef_pattern = PROCDEF_COMPLEX_OFFSET_PATTERNS["ELF_new"]

    all_extracted_addresses = {}

    def try_extract(pattern_name, pattern, offsets):
        if not pattern:
            print(f"{WARN}[WARN] No pattern provided for {pattern_name}. Skipping.{RESET}")
            return
        pattern_offset = find_pattern(text_data, pattern)
        if pattern_offset == -1:
            print(f"{WARN}[WARN] Pattern for {pattern_name} not found in the binary.{RESET}")
            return

        pattern_rva = text_va + pattern_offset
        print(f"{INFO}[INFO] {pattern_name} Pattern RVA: 0x{pattern_rva:08X}{RESET}")

        extracted = compute_addresses(binary, pattern_rva, image_base, POINTER_BYTE_LENGTH, offsets, binary_format)
        all_extracted_addresses.update({k: v for k, v in extracted.items() if v is not None})

    # Extract from all pattern sets
    try_extract("Base", base_pattern, base_offsets)
    try_extract("Exec_Proc", exec_proc_pattern, exec_proc_offsets)
    try_extract("Server_Tick", server_tick_pattern, server_tick_offsets)
    try_extract("Send_Map", send_maps_pattern, send_maps_offsets)

    procdef_offset = extract_procdef(text_data, text_va, procdef_pattern, binary_format)
    if procdef_offset:
        all_extracted_addresses["procdef"] = procdef_offset

    # results
    print(f"\n{RESULTS}[RESULTS] Extracted Addresses:{RESET}")
    final_order = [
        "strings", 
        "strings_len", 
        "miscs", 
        "procdefs",
        "procdef",
        "exec_proc", 
        "server_tick", 
        "send_maps",
    ]

    for name in final_order:
        addr = all_extracted_addresses.get(name, None)
        if addr is not None:
            if name == "procdef":
                print(f"  {RESULTS}{name}: {addr}{RESET}")
            else:
                print(f"  {RESULTS}{name}: 0x{addr:08X}{RESET}")
        else:
            print(f"  {WARN}{name}: Not found{RESET}")

if __name__ == "__main__":
    main()
