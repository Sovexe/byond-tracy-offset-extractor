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
from colorama import Fore, Style, init
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# Initialize colorama
init(autoreset=True)
INFO = Fore.CYAN
DEBUG = Fore.MAGENTA
ERROR = Fore.RED
WARN = Fore.YELLOW
RESULTS = Fore.GREEN
RESET = Style.RESET_ALL

# Define the Memory Diagnostics Anchor Patterns and Relative Offsets for PE and ELF
PATTERNS_AND_OFFSETS = {
    "PE": {
        "anchor_pattern": bytes.fromhex("8a 01 41 84 c0 75 f9 2b ca 89 4e 18 8b 55 f0"),
        "offsets": {
            "strings_len": 0x19,
            "procdefs_len": -0x96,
            "miscs_len": 0x16F,
        },
        "array_patterns": {
            "strings": {
                "pattern": [
                    0x8b, 0x4d, 0x08, 0x3b, 0x0d, None, None, None, None, 0x73, 
                    0x10, 0xa1, None, None, None, None, 0x8b, None, 0x88
                ],
                "pointer_offset": 12
            },
            "procdefs": {
                "pattern": [
                    0x3b, 0x05, None, None, None, None, 0x72, 0x04, 0x33, 0xc0,
                    0x5d, 0xc3, 0x6b, 0xc0, None, 0x03, 0x05, None, None, None,
                    None
                ],
                "pointer_offset": 17
            },
            "miscs": {
                "pattern": [
                    0x3b, 0x0d, None, None, None, None, 0x72, 0x04, 0x33, 0xc0,
                    0x5d, 0xc3, 0xa1, None, None, None, None, 0x8b, None, 0x88
                ],
                "pointer_offset": 13
            }
        },
        "procdef_pattern": {
            "pattern": [
                0xFF, 0x70, None, 0xE8, None, None, None, None, 0x83, 0xC4, 0x04,
                0x85, 0xC0, 0x75, 0x04, 0x33, 0xC9, 0xEB, 0x0A, 0x0F, 0xB7, 0x00,
                0x8D, 0x0C, 0x85, 0x0C, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xF0, 0x83,
                0xC0, None
            ],
            "wildcard_positions": [2, 34]
        },
        "functions": {
            "exec_proc": {
                "pattern": [
                    0x53, 0x8b, 0xdc, 0x83, 0xec, None, 0x83, 0xe4, 0xf8, 0x83, 0xc4, 
                    None, 0x55, 0x8b, 0x6b, 0x04, 0x89, 0x6c, 0x24, 0x04, 0x8b, 0xec,
                    0x6a, 0xff, 0x68, None, None, None, None, 0x64, 0xa1, 0x00, 0x00, 
                    0x00, 0x00, 0x50, 0x51, 0x53
                ],
            },
            "server_tick": {
                "pattern": [
                    0x55, 0x8b, 0xec, 0x83, 0xec, 0x10, 0x83, 0x3d, None, None, None,
                    None, 0x00, 0x75, 0x06, 0x33, 0xc0, 0x8b, 0xe5, 0x5d, 0xc3
                ],
            },
            "send_maps": {
                "pattern": [
                    0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68, None, None, None, None, 0x64,
                    0xa1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x81, 0xec, None, None, 0x00, 
                    0x00, 0xa1, None, None, None, None, 0x33, 0xc5, 0x89, 0x45, 0xf0, 
                    0x53, 0x56, 0x57, 0x50, 0x8d, 0x45, 0xf4, 0x64, 0xa3, 0x00, 0x00, 
                    0x00, 0x00, 0x64, 0xa1, 0x2c, 0x00, 0x00, 0x00, 0x8b, 0x0d, None, 
                    None, None, None, 0x8b, 0x34, 0x88, 0x8b, 0xbe, None, 0x00, 0x00,
                    0x00
                ],
            },
            "erasure": {
                "pattern": [
                    0X55, 0x8b, 0xec, 0x6a, 0xff, 0x68, None, None, None, None, 0x64,
                    0xa1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x83, 0xec, None, 0x53, 0x56,
                    0x57, 0xa1, None, None, None, None, 0x33, 0xc5, 0x50, 0x8d, 0x45,
                    0xf4, 0x64, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x89, 0x65, 0xf0, 0x8b,
                    0x0d, None, None, None, None, 0xb0
                ],
            },
            "event_io":{
                "pattern": [
                    0x55, 0x8b, 0xec, 0x83, 0xec, 0x08, 0x83, 0x3d, None, None, None,
                    None, 0x00, 0x56, 0x8b, 0xf1, 0x89, 0x75, 0xfc, 0x74, 0x14, 0x68,
                    None, None, None, None, 0xe8, None, None, None, 0xff, 0x83, 0xc4,
                    0x04, 0x5e, 0x8b, 0xe5, 0x5d, 0xc2, 0x08, 0x00
                ]
            },
            "mkstr":{
                "pattern": [
                    0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x83, 0xec, 0x20, 0x53, 0x56,
                    0x8b, 0x35, None, None, None, None, 0x57, 0x85, 0xc0, 0x75, 0x0e,
                    0x68, None, None, None, None, 0xff, 0xd6, 0x83, 0xc4, 0x04, 0xc6,
                    0x45, 0x14, 0x00
                ]
            },
            "rebalance":{
                "pattern":[
                    0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68, None, None, None, None, 0x64,
                    0xa1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x83, 0xec, 0x1c, 0x53, 0x56,
                    0x57, 0xa1, None, None, None, None, 0x33, 0xc5, 0x50, 0x8d, 0x45,
                    0xf4, 0x64, 0xa3, 0x00, 0x00, 0x00, 0x00, 0xa1, None, None, None,
                    None, 0xc1, 0xe0, None, 0x50
                ]
            }
        }
    },
    "OLD_ELF": {
        "anchor_pattern": bytes.fromhex("55 89 e5 57 56 53 81 ec cc 00 00 00 8d 85 60 ff ff ff 89 04 24"),
        "offsets": {
            "strings_len": 0x289,
            "procdefs_len": 0x1C6,
            "miscs_len": 0x470,
        },
        "array_patterns": {
            "strings": {
                "pattern": [
                    0x8b, 0x45, 0x08, 0x39, 0x05, None, None, None, None,
                    0x76, 0x0f, 0x8b, 0x15, None, None, None, None, 0x8b, 
                    None, 0x82
                ],
                "pointer_offset": 13
            },
            "procdefs": {
                "pattern": [
                    0x8b, 0x55, 0x08, 0x39, 0x15, None, None, None, None, 0x76, 
                    0x09, 0x6b, 0xc2, None, 0x03, 0x05, None, None, None, None
                ],
                "pointer_offset": 16
            },
            "miscs": {
                "pattern": [
                    0x8b, 0x55, 0x08, 0x39, 0x15, None, None, None, None, 0x76,
                    0x08, 0xa1, None, None, None, None, 0x8b, None, 0x90
                ],
                "pointer_offset": 12
            }
        },
        "procdef_pattern": {
            "pattern": [
                0x8B, 0x40, None, 0x89, 0x04, 0x24, None, None, None, None, None,
                0x31, 0xD2, 0x85, 0xC0, 0x74, 0x0A, 0x0F, 0xB7, 0x00, 0x8D,
                0x14, 0x85, 0x0C, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xE0, 0x8D,
                0x44, 0x02, None
            ],
            "wildcard_positions": [2, 33]  # Positions to extract bytes for procdef
        },
        "functions": {
            "exec_proc": {
                "pattern": [
                    0x55, 0x89, 0xe5, 0x57, 0x56, 0x53, 0x81, 0xec, None, None, 0x00,
                    0x00, 0x89, None, None, None, 0xff, 0xff, 0xa1, None, None, None, 
                    0x00, 0x89, None, None, None, 0xFF, 0xFF, 0xC7,
                ],
            },
            "server_tick": {
                "pattern": [
                    0x55, 0x89, 0xe5, 0x56, 0x53, 0x83, 0xec, None, 0x8b, 0x15, None,
                    None, None, None, 0x85, 0xd2, 0x0f, None, None, None, None, 0x00
                ],
            },
            "send_maps": {
                "pattern": [
                    0x55, 0x89, 0xE5, 0x57, 0x56, 0x53, 0x81, 0xEC, None, None, 0x00,
                    0x00, 0x65, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x89, None, None, None, 
                    0xff, 0xff, 0x89, None, None, None, 0xff
                ],
            },
        }
    },
    "NEW_ELF": {
        "anchor_pattern": bytes.fromhex("55 89 e5 57 56 8d 45 d4 53 83 ec 58 50"),
        "offsets": {
            "strings_len": 0x2A2,
            "procdefs_len": 0x1EF,
            "miscs_len": 0x3A4,
        },
        "array_patterns": {
            "strings": {
                "pattern": [
                    0x8b, 0x44, 0x24, 0x20, 0x39, 0x05, None, None, None, None, 0x76, 
                    0x17, 0x8b, 0x15, None, None, None, None
                ],
                "pointer_offset": 14
            },
            "procdefs": {
                "pattern": [
                    0x8b, 0x44, 0x24, 0x04, 0x39, 0x05, None, None, None, None, 0x76, 
                    0x14, 0x6b, 0xc0, None, 0x03, 0x05, None, None, None, None
                ],
                "pointer_offset": 17
            },
            "miscs": {
                "pattern": [
                    0x8b, 0x44, 0x24, 0x04, 0x39, 0x05, None, None, None, None, 0x76,
                    0x14, 0x8b, 0x15, None, None, None, None
                ],
                "pointer_offset": 14
            }
        },
        "procdef_pattern": {
            "pattern": [
                0xFF, 0x70, None, 0xE8, None, None, None, None, 0x83, 0xC4, 0x10,
                0x85, 0xC0, 0x0F, None, None, None, None, 0x00, 0x0F, 0xB7, 0x00,
                0x8D, 0x14, 0x85, 0x0C, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xC8, 0x8D,
                0x44, 0x02, None
            ],
            "wildcard_positions": [2, 35]
        },
        "functions": {
            "exec_proc": {
                "pattern": [
                    0x55, 0x89, 0xe5, 0x57, 0x56, 0x53, 0x81, 0xec, None, None, 0x00,
                    0x00, 0x89, None, None, None, None, 0xff, 0xa1, None, None, None,
                    0x00, 0x89, None, None, None, 0xff, 0xff, 0x89, None, None, None,
                    0xff, 0xff
                ],
            },
            "server_tick": {
                "pattern": [
                    0xa1, None, None, None, 0x00, 0x85, 0xc0, 0x0f, 0x84, None, None, 
                    0x00, 0x00, 0x57, 0x56, 0x53, 0x83, 0xec, None, 0x6a, 0x00, 0x68
                ],
            },
            "send_maps": {
                "pattern": [
                    0x55, 0x89, 0xe5, 0x57, 0x56, 0x53, 0x81, 0xec, 0xec, 0x08, 0x00, 0x00,
                    0x65, 0xa1, 0x00, 0x00, 0x00, 0x00
                ],
            },
        }
    }
}

PROLOGUE_FUNCTION_NAMES = {"exec_proc", "send_maps", "server_tick"}
PROLOGUE2_FUNCTION_NAMES = {"erasure", "event_io", "mkstr", "rebalance"}
POINTER_BYTE_LENGTH = 4

def find_pattern(data: bytes, pattern: bytes) -> int:
    if not pattern:
        return -1
    index = data.find(pattern)
    if index != -1:
        print(f"{DEBUG}[DEBUG] Pattern found at offset: 0x{index:08X}{RESET}")
    else:
        print(f"{WARN}[WARN] Pattern not found for a given pattern.{RESET}")
    return index

def find_pattern_with_wildcards(data: bytes, pattern: List[Optional[int]], pattern_name: str) -> int:
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
    print(f"{WARN}[WARN] Wildcard pattern '{pattern_name}' not found.{RESET}")
    return -1

def get_section_from_rva(binary, rva):
    for section in binary.sections:
        sec_va = section.virtual_address
        sec_size = section.size
        if sec_va <= rva < sec_va + sec_size:
            return section
    return None

def read_pointer(binary, rva):
    section = get_section_from_rva(binary, rva)
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

def compute_addresses(binary, pattern_rva, image_base, relative_offsets):
    addresses = {}
    for name, relative_offset in relative_offsets.items():
        print(f"{INFO}[INFO] Computing address for '{name}':{RESET}")
        pointer_rva = pattern_rva + relative_offset
        print(f"{DEBUG}[DEBUG] Pattern RVA: 0x{pattern_rva:08X} + Offset: 0x{relative_offset:X} = Pointer RVA: 0x{pointer_rva:08X}{RESET}")

        raw_value = read_pointer(binary, pointer_rva)
        if raw_value is None:
            addresses[name] = None
            print(f"{WARN}[WARN] Could not read pointer for '{name}'.{RESET}")
        else:
            adjusted_address = raw_value - image_base
            print(f"{INFO}[INFO] Adjusted Address for '{name}': 0x{adjusted_address:08X}{RESET}")
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
    print(f"{DEBUG}[DEBUG] Function RVA: 0x{function_rva:08X}, .text VA: 0x{text_va:08X}, Offset: 0x{offset:08X}{RESET}")
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

def calculate_prologue_lengths(binary, offsets, function_names, min_bytes=5):
    prologue_lengths = {}
    for func in function_names:
        if func in offsets and offsets[func] is not None:
            prologue_length = calculate_prologue_length(binary, offsets[func], min_bytes)
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
        combined_value = f"0x00{send_maps:02X}{server_tick:02X}{exec_proc:02X}"
        return combined_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Failed to generate combined prologue value: {e}{RESET}")
        return None
    
def generate_combined_prologue2_value(prologue2_lengths):
    try:
        erasure = prologue2_lengths.get("erasure", 0) or 0
        event_io = prologue2_lengths.get("event_io", 0) or 0
        mkstr = prologue2_lengths.get("mkstr", 0) or 0
        rebalance = prologue2_lengths.get("rebalance", 0) or 0
        combined_value = f"0x{rebalance:02X}{mkstr:02X}{event_io:02X}{erasure:02X}"
        return combined_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Failed to generate combined prologue2 value: {e}{RESET}")
        return None

def extract_procdef(data: bytes, base_address: int, procdef_info: dict) -> Optional[str]:
    """
    Extracts the procdef complex offset based on the procdef pattern.
    """
    pattern = procdef_info["pattern"]
    wildcard_positions = procdef_info.get("wildcard_positions", [])

    pattern_offset = find_pattern_with_wildcards(data, pattern, "procdef")
    if pattern_offset == -1:
        print(f"{WARN}[WARN] procdef pattern not found.{RESET}")
        return None

    pattern_rva = base_address + pattern_offset
    print(f"{INFO}[INFO] procdef Pattern RVA: 0x{pattern_rva:08X}{RESET}")

    # Extract bytes at the specified wildcard positions
    try:
        if len(wildcard_positions) < 2:
            print(f"{ERROR}[ERROR] Not enough wildcard positions defined for procdef.{RESET}")
            return None
        byte1 = data[pattern_offset + wildcard_positions[0]]
        byte2 = data[pattern_offset + wildcard_positions[1]]
        complex_offset = f"0x00{byte1:02X}00{byte2:02X}"
        print(f"{INFO}[INFO] Extracted procdef: {complex_offset}{RESET}")
        return complex_offset
    except IndexError:
        print(f"{ERROR}[ERROR] procdef extraction failed due to index out of range.{RESET}")
        return None

def get_image_base(binary: lief.Binary, binary_format: str) -> int:
    """
    Retrieve the image base for the binary.
    - For PE, use the image base from the optional header.
    - For ELF, calculate the image base as the minimum virtual address of PT_LOAD segments.
    """
    if binary_format == 'PE':
        image_base = binary.optional_header.imagebase
        print(f"{INFO}[INFO] Image Base (PE): 0x{image_base:08X}{RESET}")
        return image_base
    elif binary_format == 'ELF':
        # Find the minimum virtual address of all PT_LOAD segments
        load_segments = [seg for seg in binary.segments if seg.type == lief.ELF.Segment.TYPE.LOAD]
        if not load_segments:
            print(f"{ERROR}[ERROR] No PT_LOAD segments found in ELF binary.{RESET}")
            sys.exit(1)
        # Calculate the minimum virtual address of all PT_LOAD segments
        image_base = min(seg.virtual_address for seg in load_segments)
        print(f"{INFO}[INFO] Calculated Image Base (ELF): 0x{image_base:08X}{RESET}")
        return image_base
    else:
        print(f"{ERROR}[ERROR] Unsupported binary format: {binary_format}.{RESET}")
        sys.exit(1)

def find_array_pointer(data: bytes, array_name: str, array_len_ptr: int, image_base: int, binary_format_pattern: str) -> Optional[int]:
    """
    Finds the array pointer using the complex pattern defined in PATTERNS_AND_OFFSETS.
    """
    # Retrieve the specific array pattern and pointer_offset
    binary_info = PATTERNS_AND_OFFSETS.get(binary_format_pattern)
    if not binary_info:
        print(f"{ERROR}[ERROR] No patterns defined for binary format: {binary_format_pattern}.{RESET}")
        return None

    array_info = binary_info["array_patterns"].get(array_name)
    if not array_info:
        print(f"{WARN}[WARN] No pattern defined for array '{array_name}' in binary format '{binary_format_pattern}'.{RESET}")
        return None

    pattern = array_info["pattern"]
    pointer_offset = array_info["pointer_offset"]

    array_len_val = array_len_ptr + image_base

    try:
        array_len_bytes = array_len_val.to_bytes(4, byteorder='little')
    except OverflowError:
        print(f"{WARN}[WARN] array_len_val 0x{array_len_val:08X} exceeds 4 bytes for '{array_name}'.{RESET}")
        return None

    # Insert the array_len_val into the pattern
    pattern_with_len = pattern.copy()
    len_inserted = 0
    for i in range(len(pattern_with_len)):
        if pattern_with_len[i] is None and len_inserted < 4:
            pattern_with_len[i] = array_len_bytes[len_inserted]
            len_inserted += 1
        if len_inserted == 4:
            break

    if len_inserted < 4:
        print(f"{WARN}[WARN] Failed to insert array_len_val into pattern for '{array_name}'.{RESET}")
        return None

    print(f"{DEBUG}[DEBUG] Constructed pattern for '{array_name}': {' '.join(['??' if b is None else f'{b:02X}' for b in pattern_with_len])}{RESET}")

    pattern_name = f"{array_name}_pattern"

    # Perform pattern matching with wildcards
    pattern_offset = find_pattern_with_wildcards(data, pattern_with_len, pattern_name)
    if pattern_offset != -1:
        # Extract the array pointer using the pointer_offset
        array_ptr_bytes = data[pattern_offset + pointer_offset : pattern_offset + pointer_offset + POINTER_BYTE_LENGTH]
        if len(array_ptr_bytes) < POINTER_BYTE_LENGTH:
            print(f"{WARN}[WARN] Not enough bytes to extract array pointer for '{array_name}'.{RESET}")
            return None
        array_ptr = int.from_bytes(array_ptr_bytes, byteorder='little')
        array_ptr -= image_base
        print(f"{DEBUG}[DEBUG] Array pointer for '{array_name}' found at offset 0x{pattern_offset:08X}: 0x{array_ptr:08X}{RESET}")
        return array_ptr
    else:
        print(f"{WARN}[WARN] Array pointer for '{array_name}' not found via pattern matching.{RESET}")
        return None

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

    # Setup image_base
    image_base = get_image_base(binary, binary_format)

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
        base_info = PATTERNS_AND_OFFSETS["PE"]
        binary_format_pattern = "PE"
    elif binary_format == "ELF" and use_old_elf:
        base_info = PATTERNS_AND_OFFSETS["OLD_ELF"]
        binary_format_pattern = "OLD_ELF"
    elif binary_format == "ELF" and not use_old_elf:
        base_info = PATTERNS_AND_OFFSETS["NEW_ELF"]
        binary_format_pattern = "NEW_ELF"
    else:
        print(f"{ERROR}[ERROR] Unsupported binary format configuration.{RESET}")
        sys.exit(1)

    all_extracted_addresses = {}

    # Search for the anchor pattern
    print(f"{INFO}[INFO] Searching for Memory Diagnostics Anchor Pattern...{RESET}")
    base_pattern = base_info["anchor_pattern"]
    base_pattern_offset = find_pattern(text_data, base_pattern)
    if base_pattern_offset != -1:
        base_rva = text_va + base_pattern_offset
        print(f"{INFO}[INFO] Memory Diagnostics Anchor found at RVA: 0x{base_rva:08X}{RESET}")
        # Compute addresses based on the new offsets (only lengths)
        extracted_lengths = compute_addresses(binary, base_rva, image_base, base_info["offsets"])
        all_extracted_addresses.update({k: v for k, v in extracted_lengths.items() if v is not None})
    else:
        print(f"{WARN}[WARN] Memory Diagnostics Anchor pattern not found.{RESET}")

    # Extract lengths and array pointers if Memory Diagnostics Anchor was found
    if base_pattern_offset != -1:
        # Read lengths
        strings_len = all_extracted_addresses.get("strings_len", None)
        procdefs_len = all_extracted_addresses.get("procdefs_len", None)
        miscs_len = all_extracted_addresses.get("miscs_len", None)

        # Dynamic Pattern Matching for Array Pointers
        for array_name in ["strings", "procdefs", "miscs"]:
            array_len_ptr = all_extracted_addresses.get(f"{array_name}_len", None)
            if array_len_ptr is not None:
                array_ptr = find_array_pointer(text_data, array_name, array_len_ptr, image_base, binary_format_pattern)
                if array_ptr is not None:
                    all_extracted_addresses[array_name] = array_ptr
            else:
                print(f"{WARN}[WARN] Length pointer for '{array_name}' not available.{RESET}")

    # Extract procdef
    procdef_info = {
        "pattern": base_info["procdef_pattern"]["pattern"],
        "wildcard_positions": base_info["procdef_pattern"]["wildcard_positions"]
    }
    procdef_offset = extract_procdef(text_data, text_va, procdef_info)
    if procdef_offset:
        all_extracted_addresses["procdef"] = procdef_offset

    # Extract function RVAs using wildcard pattern matching
    func_patterns = base_info.get("functions", {})
    offsets = {}
    for func, data in func_patterns.items():
        pattern = data["pattern"]
        pattern_name = f"{func}_pattern"

        pattern_offset = find_pattern_with_wildcards(text_data, pattern, pattern_name)
        if pattern_offset != -1:
            final_rva = text_va + pattern_offset
            offsets[func] = final_rva
            print(f"{INFO}[INFO] {func} RVA: 0x{final_rva:08X}{RESET}")
        else:
            print(f"{WARN}[WARN] Pattern for {func} not found.{RESET}")
            offsets[func] = None

    # Calculate prologue lengths
    prologue_lengths = calculate_prologue_lengths(binary, offsets, PROLOGUE_FUNCTION_NAMES)
    prologue2_lengths = calculate_prologue_lengths(binary, offsets, PROLOGUE2_FUNCTION_NAMES)

    # Generate combined prologue value
    combined_prologue_value = generate_combined_prologue_value(prologue_lengths)
    if combined_prologue_value:
        all_extracted_addresses["prologue"] = combined_prologue_value

    combined_prologue2_value = generate_combined_prologue2_value(prologue2_lengths)
    if combined_prologue2_value:
        all_extracted_addresses["prologue2"] = combined_prologue2_value

    # Merge function offsets into all_extracted_addresses
    all_extracted_addresses.update({k: v for k, v in offsets.items() if v is not None})

    # Print results
    print(f"\n{RESULTS}Extracted Addresses:{RESET}")
    final_order = [
        "strings", 
        "strings_len",
        "miscs",
        "miscs_len",
        "procdefs",
        "procdefs_len",
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
        if name in ["procdef", "prologue"]:
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

    # Print experimental address results
    final_order_experimental = [
        "erasure",
        "event_io",
        "mkstr",
        "rebalance",
        "prologue2"
    ]

    print(f"\n{RESULTS}Experimental Addresses:{RESET}")
    for name in final_order_experimental:
        addr = all_extracted_addresses.get(name, None)
        if name in ["prologue2"]:
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
