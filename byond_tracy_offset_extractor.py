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
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# colorama
init(autoreset=True)
INFO = Fore.CYAN
DEBUG = Fore.MAGENTA
ERROR = Fore.RED
WARN = Fore.YELLOW
RESULTS = Fore.GREEN
RESET = Style.RESET_ALL

# Base Patterns and Offsets
PE_BASE_PATTERN = bytes.fromhex("4b 8b 34 98 85 f6 74 4f 8b 4e 38 c7 45 fc 00 00 00 00 85 c9")
PE_BASE_OFFSETS = {
    "strings": -0xD4,
    "strings_len": -0x4E,
    "miscs": -0xB8,
    "procdefs": -0xF8,
}

OLD_ELF_BASE_PATTERN = bytes.fromhex("8d b4 26 00 00 00 00 8b 46 38 89 47 38 c7 46 38 00 00 00 00 89 34 24")
OLD_ELF_BASE_OFFSETS = {
    "strings": -0xF2,
    "strings_len": -0x5D,
    "miscs": -0xD1,
    "procdefs": -0x120,
}

NEW_ELF_BASE_PATTERN = bytes.fromhex("8d b4 26 00 00 00 00 90 83 ec 0c 53 83 c3 01")
NEW_ELF_BASE_OFFSETS = {
    "strings": -0x268,
    "strings_len": -0x1D6,
    "miscs": -0x248,
    "procdefs": -0x294,
}

FUNC_PATTERNS_AND_OFFSETS = {
    "PE": {
        "exec_proc": {"pattern": bytes.fromhex("64 a1 00 00 00 00 50 51 53 81 ec 30 0a 00 00"), "offset": -0x1D},
        "server_tick": {"pattern": bytes.fromhex("5f b0 01 5e c3 5f 32 c0 5e c3 cc cc 55"), "offset": 0xC},
        "send_maps": {"pattern": bytes.fromhex("89 85 b0 fb ff ff 89 85 90 fb ff ff 8b 86 08 00 00 00 89 95 ac fb ff ff 89 95 8c fb ff ff 89 85 b8 fb ff ff"), "offset": -0x5C},
    },
    "NEW_ELF": {
        "exec_proc": {"pattern": bytes.fromhex("89 95 d8 fc ff ff 89 85 00 fc ff ff 8b 42 18 c7 85 20 fd ff ff 00 00 00 00"), "offset": -0x17},
        "server_tick": {"pattern": bytes.fromhex("66 0f 6e c0 66 0f 6e ca 66 0f 62 c1 66 0f d6 04 24"), "offset": -0x2D},
        "send_maps": {"pattern": bytes.fromhex("55 89 e5 57 56 53 81 ec ec 08 00 00 65 a1 00 00 00 00"), "offset": 0x000},
    },
    "OLD_ELF": {
        "exec_proc": {"pattern": bytes.fromhex("89 95 24 f8 ff ff c7 45 94 00 00 00 00 c7 45 98 00 00 00 00"), "offset": -0x17},
        "server_tick": {"pattern": bytes.fromhex("8b 4d c4 89 55 cc 8b 55 c0 89 45 c8"), "offset": -0xC0},
        "send_maps": {"pattern": bytes.fromhex("55 89 e5 57 56 53 81 ec 2c 09 00 00 65 a1 00 00 00 00"), "offset": 0x000},
    }
}

FUNCTION_NAMES = {"exec_proc", "send_maps", "server_tick"}
POINTER_BYTE_LENGTH = 4

@dataclass
class ComplexOffsetPattern:
    name: str
    pattern: List[Optional[int]]
    first_wildcard_pos: int
    second_wildcard_pos: int

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

def find_pattern(data, pattern):
    if not pattern:
        return -1
    index = data.find(pattern)
    if index != -1:
        print(f"{DEBUG}[DEBUG] Pattern found at offset: 0x{index:08X}{RESET}")
    else:
        print(f"{WARN}[WARN] Pattern not found for a given pattern.{RESET}")
    return index

def find_pattern_with_wildcards(data, pattern, pattern_name):
    pattern_length = len(pattern)
    for i in range(len(data) - pattern_length + 1):
        match = True
        for j in range(pattern_length):
            if pattern[j] is not None and data[i + j] != pattern[j]:
                match = False
                break
        if match:
            print(f"{DEBUG}[DEBUG] Wildcard pattern '{pattern_name}' found at offset: 0x{i:08X}{RESET}")
            return i
    return -1

def get_section_from_rva(binary, rva, binary_format):
    for section in binary.sections:
        sec_va = section.virtual_address
        sec_size = section.size
        if sec_va <= rva < sec_va + sec_size:
            return section
    return None

def read_pointer(binary, rva, binary_format):
    section = get_section_from_rva(binary, rva, binary_format)
    if section is None:
        print(f"{WARN}[WARN] RVA 0x{rva:08X} not found in any section.{RESET}")
        return None

    offset_in_section = rva - section.virtual_address
    sec_size = section.size

    if offset_in_section + POINTER_BYTE_LENGTH > sec_size:
        print(f"{WARN}[WARN] Attempting to read beyond the section at RVA 0x{rva:08X}.{RESET}")
        return None

    try:
        data = binary.get_content_from_virtual_address(rva, POINTER_BYTE_LENGTH)
        if len(data) < POINTER_BYTE_LENGTH:
            print(f"{WARN}[WARN] Not enough data to read at RVA 0x{rva:08X}.{RESET}")
            return None
        raw_value = int.from_bytes(bytes(data), byteorder="little")
        print(f"{DEBUG}[DEBUG] Read raw value: 0x{raw_value:08X} from RVA: 0x{rva:08X}{RESET}")
        return raw_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Exception while reading pointer at RVA 0x{rva:08X}: {e}{RESET}")
        return None

def compute_addresses(binary, pattern_rva, image_base, relative_offsets, binary_format):
    addresses = {}
    for name, relative_offset in relative_offsets.items():
        print(f"{INFO}[INFO] Computing address for '{name}':{RESET}")
        pointer_rva = pattern_rva + relative_offset
        print(f"{DEBUG}[DEBUG] Pattern RVA: 0x{pattern_rva:08X} + Offset: 0x{relative_offset:X} = Pointer RVA: 0x{pointer_rva:08X}")

        if name in FUNCTION_NAMES:
            adjusted_address = pattern_rva + relative_offset
            addresses[name] = adjusted_address
            print(f"{INFO}[INFO]Computed Address for '{name}': 0x{adjusted_address:08X}{RESET}")
        else:
            raw_value = read_pointer(binary, pointer_rva, binary_format)
            if raw_value is None:
                addresses[name] = None
                print(f"{WARN}[WARN] Could not read pointer for '{name}'.{RESET}")
            else:
                if binary_format == 'PE':
                    adjusted_address = raw_value - image_base
                    print(f"{INFO}[INFO]Adjusted Address for '{name}': 0x{adjusted_address:08X}{RESET}")
                else:
                    adjusted_address = raw_value
                addresses[name] = adjusted_address

    return addresses

def calculate_prologue_length(binary, function_rva, min_bytes=5):
    text_section = binary.get_section(".text")
    if not text_section:
        print(f"{ERROR}[ERROR] .text section not found.{RESET}")
        return None

    text_data = bytes(text_section.content)
    text_va = text_section.virtual_address

    offset = function_rva - text_va
    if offset < 0 or offset >= len(text_data):
        print(f"{WARN}[WARN] Function RVA 0x{function_rva:08X} is out of .text section bounds.{RESET}")
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = text_data[offset:]
    total_length = 0
    for insn in md.disasm(code, function_rva):
        total_length += insn.size
        if total_length >= min_bytes:
            break

    return total_length

def calculate_prologue_lengths(binary, offsets):
    prologue_lengths = {}
    for func in ["exec_proc", "server_tick", "send_maps"]:
        if func in offsets and offsets[func] is not None:
            prologue_length = calculate_prologue_length(binary, offsets[func])
            if prologue_length:
                prologue_lengths[func] = prologue_length
                print(f"{INFO}[INFO] Prologue length for {func}: {prologue_length} bytes{RESET}")
            else:
                print(f"{WARN}[WARN] Could not calculate prologue length for {func}.{RESET}")
                prologue_lengths[func] = None
        else:
            print(f"{WARN}[WARN] Skipping {func} as its RVA is None.{RESET}")
            prologue_lengths[func] = None
    return prologue_lengths

def generate_combined_prologue_value(prologue_lengths):
    try:
        exec_proc = prologue_lengths.get("exec_proc", 0) or 0
        server_tick = prologue_lengths.get("server_tick", 0) or 0
        send_maps = prologue_lengths.get("send_maps", 0) or 0
        combined_value = f"0x00{exec_proc:02X}{server_tick:02X}{send_maps:02X}"
        return combined_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Failed to generate combined prologue value: {e}{RESET}")
        return None

def extract_procdef(data: bytes, base_address: int, procdef_pattern: ComplexOffsetPattern, binary_format: str):
    pattern_offset = find_pattern_with_wildcards(data, procdef_pattern.pattern, procdef_pattern.name)
    if pattern_offset == -1:
        print(f"{WARN}[WARN] {procdef_pattern.name} pattern not found.{RESET}")
        return None

    pattern_rva = base_address + pattern_offset
    print(f"{INFO}[INFO] {procdef_pattern.name} Pattern RVA: 0x{pattern_rva:08X}{RESET}")

    if procdef_pattern.second_wildcard_pos >= len(procdef_pattern.pattern):
        print(f"{ERROR}[ERROR] Second wildcard position {procdef_pattern.second_wildcard_pos} exceeds pattern length.{RESET}")
        return None

    if pattern_offset + procdef_pattern.second_wildcard_pos >= len(data):
        print(f"{ERROR}[ERROR] Second wildcard position out of bounds for {procdef_pattern.name}.{RESET}")
        return None

    byte1 = data[pattern_offset + procdef_pattern.first_wildcard_pos]
    byte2 = data[pattern_offset + procdef_pattern.second_wildcard_pos]
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

    binary = lief.parse(binary_path)
    if not binary:
        print(f"{ERROR}[ERROR] Failed to load binary.{RESET}")
        sys.exit(1)
    else:
        print(f"{INFO}[INFO] Successfully loaded binary: {binary_path}{RESET}")

    image_base = binary.imagebase
    print(f"{INFO}[INFO] Image Base (l_addr): 0x{image_base:08X}{RESET}")

    text_section = binary.get_section(".text")
    if not text_section:
        print(f"{ERROR}[ERROR] .text section not found.{RESET}")
        sys.exit(1)
    else:
        print(f"{INFO}[INFO] .text section found.{RESET}")

    text_data = bytes(text_section.content)
    text_va = text_section.virtual_address
    print(f"{DEBUG}[DEBUG] .text section VA: 0x{text_va:08X}, Size: {len(text_data)} bytes{RESET}")

    # Determine format-specific patterns and offsets
    if binary_format == "PE":
        patterns_and_offsets = FUNC_PATTERNS_AND_OFFSETS["PE"]
        procdef_pattern = PROCDEF_COMPLEX_OFFSET_PATTERNS["PE"]
        base_pattern = PE_BASE_PATTERN
        base_offsets = PE_BASE_OFFSETS
    elif use_old_elf:
        patterns_and_offsets = FUNC_PATTERNS_AND_OFFSETS["OLD_ELF"]
        procdef_pattern = PROCDEF_COMPLEX_OFFSET_PATTERNS["ELF_old"]
        base_pattern = OLD_ELF_BASE_PATTERN
        base_offsets = OLD_ELF_BASE_OFFSETS
    else:  # NEW_ELF
        patterns_and_offsets = FUNC_PATTERNS_AND_OFFSETS["NEW_ELF"]
        procdef_pattern = PROCDEF_COMPLEX_OFFSET_PATTERNS["ELF_new"]
        base_pattern = NEW_ELF_BASE_PATTERN
        base_offsets = NEW_ELF_BASE_OFFSETS

    all_extracted_addresses = {}

    # Extract base offsets
    base_pattern_offset = find_pattern(text_data, base_pattern)
    if base_pattern_offset != -1:
        base_rva = text_va + base_pattern_offset
        print(f"{INFO}[INFO] Base pattern found at RVA: 0x{base_rva:08X}{RESET}")
        extracted_base = compute_addresses(binary, base_rva, image_base, base_offsets, binary_format)
        all_extracted_addresses.update({k: v for k, v in extracted_base.items() if v is not None})
    else:
        print(f"{WARN}[WARN] Base pattern not found.{RESET}")

    # Extract procdef
    procdef_offset = extract_procdef(text_data, text_va, procdef_pattern, binary_format)
    if procdef_offset:
        all_extracted_addresses["procdef"] = procdef_offset

    # Extract function RVAs
    offsets = {}
    for func, data in patterns_and_offsets.items():
        pattern_offset = find_pattern(text_data, data["pattern"])
        if pattern_offset != -1:
            final_rva = text_va + pattern_offset + data["offset"]
            offsets[func] = final_rva
            print(f"{INFO}[INFO] {func} RVA: 0x{final_rva:08X}{RESET}")
        else:
            print(f"{WARN}[WARN] Pattern for {func} not found.{RESET}")
            offsets[func] = None

    # Calculate prologue lengths
    prologue_lengths = calculate_prologue_lengths(binary, offsets)

    # Generate combined prologue value
    combined_prologue_value = generate_combined_prologue_value(prologue_lengths)
    if combined_prologue_value:
        all_extracted_addresses["prologue"] = combined_prologue_value

    # Merge function offsets into all_extracted_addresses
    all_extracted_addresses.update({k: v for k, v in offsets.items() if v is not None})

    # Print results
    print(f"\n{RESULTS}Extracted Addresses:{RESET}")
    final_order = [
        "strings", 
        "strings_len", 
        "miscs", 
        "procdefs",
        "procdef",
        "exec_proc", 
        "server_tick", 
        "send_maps",
        "prologue"
    ]

    # Line-by-line printing
    values_list = []
    for name in final_order:
        addr = all_extracted_addresses.get(name, None)
        if name == "procdef" or name == "prologue":
            # procdef and prologue are hex strings
            if addr is not None:
                print(f"  {RESULTS}{name}: {addr}{RESET}")
                values_list.append(addr)
            else:
                print(f"  {WARN}{name}: Not found{RESET}")
                values_list.append("None")
        else:
            if addr is not None:
                val_str = f"0x{addr:08X}"
                print(f"  {RESULTS}{name}: {val_str}{RESET}")
                values_list.append(val_str)
            else:
                print(f"  {WARN}{name}: Not found{RESET}")
                values_list.append("None")

    # Print second time in a single line separated by commas
    print(f"\n{RESULTS}{{{', '.join(values_list)}}}{RESET}")


if __name__ == "__main__":
    main()
