"""
@file
@description
Script to extract function and data addresses from both 32-bit PE (.dll and .exe) and 32-bit ELF (.so) binaries using LIEF and Capstone.
Handles only 32-bit architectures.
"""

import lief
import sys
import os
from typing import List, Optional, Union  # Ensure Union is imported
from dataclasses import dataclass
from colorama import Fore, Style, init
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# Initialize colorama for colored terminal output
init(autoreset=True)
INFO = Fore.CYAN
DEBUG = Fore.MAGENTA
ERROR = Fore.RED
WARN = Fore.YELLOW
RESULTS = Fore.GREEN
RESET = Style.RESET_ALL

# Define function patterns and offsets for PE and ELF
PATTERNS_AND_OFFSETS = {
    "PE": {
        "base_pattern": bytes.fromhex("4b 8b 34 98 85 f6 74 4f 8b 4e 38 c7 45 fc 00 00 00 00 85 c9"),
        "base_offsets": {
            "strings": -0xD4,
            "strings_len": -0x4E,
            "miscs": -0xB8,
            "procdefs": -0xF8,
        },
        "func_patterns": {
            "exec_proc": {"pattern": bytes.fromhex("64 a1 00 00 00 00 50 51 53 81 ec 30 0a 00 00"), "offset": -0x1D},
            "server_tick": {"pattern": bytes.fromhex("5f b0 01 5e c3 5f 32 c0 5e c3 cc cc 55"), "offset": 0xC},  # Example fixed pattern
            "send_maps": {"pattern": bytes.fromhex("89 85 b0 fb ff ff 89 85 90 fb ff ff 8b 86 08 00 00 00 89 95 ac fb ff ff 89 95 8c fb ff ff 89 85 b8 fb ff ff"), "offset": -0x5C},
        },
        "procdef_pattern": [
            0xff, 0x70, None, 0xe8, None, None, None, None, 0x83, 0xc4, 0x04,
            0x85, 0xc0, 0x75, 0x04, 0x33, 0xc9, 0xeb, 0x0a, 0x0f, 0xb7, 0x00,
            0x8d, 0x0c, 0x85, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xf0, 0x83,
            0xc0, None
        ],
        "procdef_wildcards": {"first": 2, "second": 34}
    },
    "ELF": {
        "base_patterns": {
            "OLD_ELF": bytes.fromhex("8db426000000008b4638894738c7463800000000893424"),
            "NEW_ELF": bytes.fromhex("8db426000000009083ec0c5383c301")
        },
        "base_offsets": {
            "OLD_ELF": {
                "strings": -0xF2,
                "strings_len": -0x5D,
                "miscs": -0xD1,
                "procdefs": -0x120,
            },
            "NEW_ELF": {
                "strings": -0x268,
                "strings_len": -0x1D6,
                "miscs": -0x248,
                "procdefs": -0x294,
            }
        },
        "func_patterns": {
            "exec_proc": {"pattern": bytes.fromhex("89 95 d8 fc ff ff 89 85 00 fc ff ff 8b 42 18 c7 85 20 fd ff ff 00 00 00 00"), "offset": -0x17},
            "server_tick": {"pattern": bytes.fromhex("66 0f 6e c0 66 0f 6e ca 66 0f 62 c1 66 0f d6 04 24"), "offset": -0x2D},
            "send_maps": {"pattern": bytes.fromhex("55 89 e5 57 56 53 81 ec ec 08 00 00 65 a1 00 00 00 00"), "offset": 0x000},
        },
        "procdef_patterns": {
            "OLD_ELF": {
                "pattern": [
                    0x8b, 0x40, None, 0x89, 0x04, 0x24, None, None, None, None, None,
                    0x31, 0xd2, 0x85, 0xc0, 0x74, 0x0a, 0x0f, 0xb7, 0x00, 0x8d,
                    0x14, 0x85, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xe0, 0x8d,
                    0x44, 0x02, None
                ],
                "wildcards": {"first": 2, "second": 33}
            },
            "NEW_ELF": {
                "pattern": [
                    0xff, 0x70, None, 0xe8, None, None, None, None, 0x83, 0xc4, 0x10,
                    0x85, 0xc0, 0x0f, 0x84, 0x1a, 0x05, 0x00, 0x00, 0x0f, 0xb7, 0x00,
                    0x8d, 0x14, 0x85, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xc8, 0x8d,
                    0x44, 0x02, None
                ],
                "wildcards": {"first": 2, "second": 35}
            }
        }
    }
}

FUNCTION_NAMES = {"exec_proc", "send_maps", "server_tick"}
POINTER_BYTE_LENGTH = 4

@dataclass
class ELFBaseInfo:
    base_pattern: bytes
    base_offsets: dict
    procdef_pattern: List[Optional[int]]
    first_wildcard_pos: int
    second_wildcard_pos: int

def find_pattern(data: bytes, pattern: bytes) -> int:
    """
    Find a specific byte pattern within data.
    """
    if not pattern:
        return -1
    index = data.find(pattern)
    if index != -1:
        print(f"{DEBUG}[DEBUG] Pattern found at offset: 0x{index:08X}{RESET}")
    else:
        print(f"{WARN}[WARN] Pattern not found for a given pattern.{RESET}")
    return index

def find_pattern_with_wildcards(data: bytes, pattern: List[Optional[int]], pattern_name: str, first_wildcard_pos: int, second_wildcard_pos: int) -> int:
    """
    Find a byte pattern with wildcards within data.
    Wildcards are represented by None in the pattern list.
    """
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

def get_segment_containing_section(binary: lief.Binary, section_name: str, binary_format: str) -> Optional[Union[lief.PE.Section, lief.ELF.Segment]]:
    """
    Retrieve the Section (for PE) or Segment (for ELF) that contains the specified section.
    
    :param binary: The parsed binary object.
    :param section_name: The name of the section to locate (e.g., ".text").
    :param binary_format: 'PE' or 'ELF'.
    :return: The Section (for PE) or Segment (for ELF) containing the specified section, or None if not found.
    """
    section = binary.get_section(section_name)
    if not section:
        print(f"{ERROR}[ERROR] {section_name} section not found.{RESET}")
        return None
    
    if binary_format == 'ELF':
        for segment in binary.segments:
            if segment.type == lief.ELF.Segment.TYPE.LOAD:
                seg_start = segment.virtual_address
                seg_end = segment.virtual_address + segment.virtual_size
                if seg_start <= section.virtual_address < seg_end:
                    print(f"{DEBUG}[DEBUG] {section_name} section found in ELF Segment Type: {segment.type}{RESET}")
                    return segment
    elif binary_format == 'PE':
        for section_obj in binary.sections:
            if section_obj.name == section_name:
                print(f"{DEBUG}[DEBUG] {section_name} section found in PE Section: {section_obj.name}{RESET}")
                return section_obj
    print(f"{WARN}[WARN] No Segment or Section contains the {section_name} section.{RESET}")
    return None

def read_pointer(binary: lief.Binary, va: int, binary_format: str) -> Optional[int]:
    """
    Read a pointer value from the binary at the given Virtual Address (VA).
    
    :param binary: The parsed binary object.
    :param va: The Virtual Address to read from.
    :param binary_format: 'PE' or 'ELF'.
    :return: The raw pointer value as an integer, or None if reading fails.
    """
    container = get_segment_containing_section(binary, ".text", binary_format)
    if container is None:
        print(f"{WARN}[WARN] VA 0x{va:08X} not found in any segment/section.{RESET}")
        return None

    if binary_format == 'ELF' and isinstance(container, lief.ELF.Segment):
        offset_in_container = va - container.virtual_address
        seg_size = container.virtual_size
    elif binary_format == 'PE' and isinstance(container, lief.PE.Section):
        offset_in_container = va - container.virtual_address
        seg_size = container.size
    else:
        print(f"{ERROR}[ERROR] Unsupported container type for binary format: {binary_format}.{RESET}")
        return None

    if offset_in_container + POINTER_BYTE_LENGTH > seg_size:
        print(f"{WARN}[WARN] Attempting to read beyond the container at VA 0x{va:08X}.{RESET}")
        return None
    print(f"{offset_in_container:X} {va:X} {container.virtual_address:X}")
    try:
        # PE and ELF handle virtual addresses differently, but LIEF abstracts the content retrieval
        data = binary.get_content_from_virtual_address(va, POINTER_BYTE_LENGTH)
        if len(data) < POINTER_BYTE_LENGTH:
            print(f"{WARN}[WARN] Not enough data to read at VA 0x{va:08X}.{RESET}")
            return None
        raw_value = int.from_bytes(bytes(data), byteorder="little")
        print(f"{DEBUG}[DEBUG] Read raw value: 0x{raw_value:08X} from VA: 0x{va:08X}{RESET}")
        return raw_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Exception while reading pointer at VA 0x{va:08X}: {e}{RESET}")
        return None

def compute_addresses(binary: lief.Binary, base_va: int, image_base: int, relative_offsets: dict, binary_format: str, text_section_start_va: int, text_section_end_va: int) -> dict:
    """
    Compute function and data addresses based on patterns and offsets.
    """
    addresses = {}
    for name, relative_offset in relative_offsets.items():
        print(f"{INFO}[INFO] Computing address for '{name}':{RESET}")
        pointer_va = base_va + relative_offset
        print(f"{DEBUG}[DEBUG] Base VA: 0x{base_va:08X} + Offset: 0x{relative_offset:X} = Pointer VA: 0x{pointer_va:08X}{RESET}")

        if binary_format == 'PE' and name in FUNCTION_NAMES:
            # For PE, RVA = VA - Image Base
            final_rva = pointer_va - image_base
            # Ensure RVA is within 0 to 0xFFFFFFFF
            final_rva &= 0xFFFFFFFF
            # Validate RVA within .text section
            if image_base + final_rva >= text_section_start_va and image_base + final_rva < text_section_end_va:
                addresses[name] = final_rva
                print(f"{INFO}[INFO] Computed RVA for '{name}': 0x{final_rva:08X}{RESET}")
            else:
                print(f"{WARN}[WARN] Computed RVA for '{name}' is outside .text section: 0x{final_rva:08X}{RESET}")
                addresses[name] = None
        elif binary_format == 'ELF' and name in FUNCTION_NAMES:
            # For ELF, VA is absolute
            final_va = pointer_va
            # Validate VA within .text section
            if text_section_start_va <= final_va < text_section_end_va:
                addresses[name] = final_va
                print(f"{INFO}[INFO] Computed VA for '{name}': 0x{final_va:08X}{RESET}")
            else:
                print(f"{WARN}[WARN] Computed VA for '{name}' is outside .text section: 0x{final_va:08X}{RESET}")
                addresses[name] = None
        else:
            # Handle data addresses
            raw_value = read_pointer(binary, pointer_va, binary_format)
            if raw_value is None:
                addresses[name] = None
                print(f"{WARN}[WARN] Could not read pointer for '{name}'.{RESET}")
            else:
                # For data, calculate RVA or VA
                if binary_format == 'PE':
                    adjusted_address = raw_value - image_base
                    adjusted_address &= 0xFFFFFFFF  # Ensure unsigned
                else:  # ELF
                    adjusted_address = raw_value - text_section_start_va  # Treat as absolute VA
                addresses[name] = adjusted_address
                print(f"{INFO}[INFO] Adjusted Address for '{name}': 0x{adjusted_address:08X}{RESET}")
    return addresses

def calculate_prologue_length(binary: lief.Binary, function_va: int, binary_format: str, image_base: int) -> Optional[int]:
    """
    Calculate the length of the prologue of a function using Capstone disassembly.
    """
    section = binary.get_section(".text")
    if not section:
        print(f"{ERROR}[ERROR] .text section not found.{RESET}")
        return None
    else:
        print(f"{INFO}[INFO] .text section found.{RESET}")

    text_data = bytes(section.content)
    text_va = section.virtual_address

    # Calculate offset relative to .text section
    if binary_format in ['PE', 'ELF']:
        offset = function_va - text_va
    else:
        print(f"{ERROR}[ERROR] Unsupported binary format: {binary_format}.{RESET}")
        return None

    if offset < 0 or offset >= len(text_data):
        print(f"{WARN}[WARN] Function VA 0x{function_va:08X} is out of .text section bounds.{RESET}")
        return None

    # Initialize Capstone for 32-bit x86
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    code = text_data[offset:]
    total_length = 0
    for insn in md.disasm(code, function_va):
        total_length += insn.size
        if total_length >= 5:  # Typically, prologue is at least 5 bytes
            break

    print(f"{DEBUG}[DEBUG] Calculated prologue length for VA 0x{function_va:08X}: {total_length} bytes{RESET}")
    return total_length

def calculate_prologue_lengths(binary: lief.Binary, offsets: dict, binary_format: str, image_base: int) -> dict:
    """
    Calculate prologue lengths for all functions.
    """
    prologue_lengths = {}
    for func in ["exec_proc", "server_tick", "send_maps"]:
        if func in offsets and offsets[func] is not None:
            prologue_length = calculate_prologue_length(binary, offsets[func], binary_format, image_base)
            if prologue_length:
                prologue_lengths[func] = prologue_length
                print(f"{INFO}[INFO] Prologue length for {func}: {prologue_length} bytes{RESET}")
            else:
                print(f"{WARN}[WARN] Could not calculate prologue length for {func}.{RESET}")
                prologue_lengths[func] = None
        else:
            print(f"{WARN}[WARN] Skipping {func} as its VA/RVA is None.{RESET}")
            prologue_lengths[func] = None
    return prologue_lengths

def generate_combined_prologue_value(prologue_lengths: dict) -> Optional[str]:
    """
    Generate a combined prologue value based on individual prologue lengths.
    """
    try:
        exec_proc = prologue_lengths.get("exec_proc", 0) or 0
        server_tick = prologue_lengths.get("server_tick", 0) or 0
        send_maps = prologue_lengths.get("send_maps", 0) or 0
        combined_value = f"0x00{send_maps:02X}{server_tick:02X}{exec_proc:02X}"
        return combined_value
    except Exception as e:
        print(f"{ERROR}[ERROR] Failed to generate combined prologue value: {e}{RESET}")
        return None

def extract_procdef(data: bytes, base_va: int, procdef_pattern: List[Optional[int]], binary_format: str, first_wildcard_pos: int, second_wildcard_pos: int) -> Optional[str]:
    """
    Extract procdef by matching complex patterns and calculating the VA/RVA.
    """
    pattern_offset = find_pattern_with_wildcards(data, procdef_pattern, "procdef", first_wildcard_pos, second_wildcard_pos)
    if pattern_offset == -1:
        print(f"{WARN}[WARN] procdef pattern not found.{RESET}")
        return None

    pattern_va = base_va + pattern_offset
    print(f"{INFO}[INFO] procdef Pattern VA: 0x{pattern_va:08X}{RESET}")

    # Assuming procdef is a 2-byte data string
    if pattern_offset + first_wildcard_pos + 2 > len(data):
        print(f"{ERROR}[ERROR] procdef pattern exceeds data length.{RESET}")
        return None

    procdef_bytes = data[pattern_offset + first_wildcard_pos : pattern_offset + first_wildcard_pos + 2]
    if len(procdef_bytes) < 2:
        print(f"{WARN}[WARN] Not enough bytes to read procdef.{RESET}")
        return None

    # Stitch together the two bytes as a data string
    procdef_value = ''.join([f"{byte:02X}" for byte in procdef_bytes])
    print(f"{INFO}[INFO] Extracted procdef: 0x{procdef_value}{RESET}")

    return f"0x{procdef_value}"

def get_image_base(binary: lief.Binary, binary_format: str) -> int:
    """
    Retrieve the image base depending on binary format.
    For ELF, set image_base to the minimum virtual address of LOAD segments.
    For PE, use the image base from the optional header.
    """
    if binary_format == 'PE':
        image_base = binary.optional_header.imagebase
        print(f"{INFO}[INFO] Image Base: 0x{image_base:08X}{RESET}")
        return image_base
    elif binary_format == 'ELF':
        load_segments = [seg for seg in binary.segments if seg.type == lief.ELF.Segment.TYPE.LOAD]
        if not load_segments:
            print(f"{ERROR}[ERROR] No LOAD segments found in ELF binary.{RESET}")
            sys.exit(1)
        image_base = min(seg.virtual_address for seg in load_segments)
        print(f"{INFO}[INFO] Image Base for ELF set to: 0x{image_base:08X}{RESET}")
        return image_base
    else:
        print(f"{ERROR}[ERROR] Unsupported binary format: {binary_format}.{RESET}")
        sys.exit(1)

def main():
    args = sys.argv[1:]
    if not args:
        print(f"{ERROR}[ERROR] No arguments provided. Usage: {sys.argv[0]} <binary_path>{RESET}")
        sys.exit(1)

    binary_path = args[0]

    if not os.path.isfile(binary_path):
        print(f"{ERROR}[ERROR] File not found: {binary_path}{RESET}")
        sys.exit(1)

    _, ext = os.path.splitext(binary_path.lower())
    if ext in ['.dll', '.exe']:
        binary_format = 'PE'
    elif ext == '.so':
        binary_format = 'ELF'
    else:
        print(f"{ERROR}[ERROR] Unsupported file extension: {ext}. Supported extensions are .dll, .exe, and .so.{RESET}")
        sys.exit(1)

    print(f"{DEBUG}[DEBUG] Detected binary format: {binary_format}{RESET}")

    binary = lief.parse(binary_path)
    if not binary:
        print(f"{ERROR}[ERROR] Failed to load binary: {binary_path}{RESET}")
        sys.exit(1)
    else:
        print(f"{INFO}[INFO] Successfully loaded binary: {binary_path}{RESET}")

    image_base = get_image_base(binary, binary_format)

    section = binary.get_section(".text")
    if not section:
        print(f"{ERROR}[ERROR] .text section not found.{RESET}")
        sys.exit(1)
    else:
        print(f"{INFO}[INFO] .text section found.{RESET}")

    text_data = bytes(section.content)
    text_va = section.virtual_address
    print(f"{DEBUG}[DEBUG] .text section VA: 0x{text_va:08X}, Size: {len(text_data)} bytes{RESET}")

    # Calculate .text section boundaries
    if binary_format == 'PE':
        text_section_start_va = image_base + text_va
        text_section_end_va = text_section_start_va + section.size
    elif binary_format == 'ELF':
        text_section_start_va = text_va
        text_section_end_va = text_va + section.size
    else:
        text_section_start_va = 0
        text_section_end_va = 0

    print(f"{DEBUG}[DEBUG] .text section start VA: 0x{text_section_start_va:08X}, end VA: 0x{text_section_end_va:08X}{RESET}")

    all_extracted_addresses = {}

    if binary_format == 'PE':
        # PE Processing
        patterns_and_offsets = PATTERNS_AND_OFFSETS["PE"]
        base_pattern = patterns_and_offsets["base_pattern"]
        base_offsets = patterns_and_offsets["base_offsets"]
        func_patterns = patterns_and_offsets["func_patterns"]
        procdef_pattern = patterns_and_offsets["procdef_pattern"]
        first_wildcard_pos = patterns_and_offsets["procdef_wildcards"]["first"]
        second_wildcard_pos = patterns_and_offsets["procdef_wildcards"]["second"]

        # Extract base offsets
        base_pattern_offset = find_pattern(text_data, base_pattern)
        if base_pattern_offset != -1:
            base_va = text_va + base_pattern_offset
            print(f"{INFO}[INFO] Base pattern found at VA: 0x{base_va:08X}{RESET}")

            extracted_base = compute_addresses(
                binary, 
                base_va, 
                image_base, 
                base_offsets, 
                'PE', 
                text_section_start_va, 
                text_section_end_va
            )
            all_extracted_addresses.update({k: v for k, v in extracted_base.items() if v is not None})
        else:
            print(f"{WARN}[WARN] Base pattern not found.{RESET}")

    elif binary_format == 'ELF':
        # ELF Processing
        # Decide between OLD_ELF and NEW_ELF based on specific patterns or criteria
        # For simplicity, we'll attempt both and proceed with the first match
        elf_types = ["NEW_ELF", "OLD_ELF"]
        selected_elf_type = None
        base_info = None

        for elf_type in elf_types:
            pattern = PATTERNS_AND_OFFSETS["ELF"]["base_patterns"][elf_type]
            pattern_offset = find_pattern(text_data, pattern)
            if pattern_offset != -1:
                selected_elf_type = elf_type
                base_info = {
                    "base_pattern": pattern,
                    "base_offsets": PATTERNS_AND_OFFSETS["ELF"]["base_offsets"][elf_type],
                    "procdef_pattern": PATTERNS_AND_OFFSETS["ELF"]["procdef_patterns"][elf_type]["pattern"],
                    "first_wildcard_pos": PATTERNS_AND_OFFSETS["ELF"]["procdef_patterns"][elf_type]["wildcards"]["first"],
                    "second_wildcard_pos": PATTERNS_AND_OFFSETS["ELF"]["procdef_patterns"][elf_type]["wildcards"]["second"]
                }
                print(f"{INFO}[INFO] Detected ELF type: {elf_type}{RESET}")
                break

        if not selected_elf_type:
            print(f"{WARN}[WARN] No known ELF base patterns found. Exiting.{RESET}")
            sys.exit(1)

        # Correctly calculate base_va as text_va + pattern_offset
        base_va = text_va + pattern_offset
        print(f"{INFO}[INFO] Base pattern found at VA: 0x{base_va:08X}{RESET}")

        extracted_base = compute_addresses(
            binary, 
            base_va, 
            image_base, 
            base_info["base_offsets"], 
            'ELF', 
            text_section_start_va, 
            text_section_end_va
        )
        all_extracted_addresses.update({k: v for k, v in extracted_base.items() if v is not None})

    # Unified Procdef Extraction for Both PE and ELF
    # Define procdef pattern based on binary format
    if binary_format == 'PE':
        procdef_pattern = PATTERNS_AND_OFFSETS["PE"]["procdef_pattern"]
        first_wildcard_pos = PATTERNS_AND_OFFSETS["PE"]["procdef_wildcards"]["first"]
        second_wildcard_pos = PATTERNS_AND_OFFSETS["PE"]["procdef_wildcards"]["second"]
    elif binary_format == 'ELF':
        procdef_pattern = base_info["procdef_pattern"]
        first_wildcard_pos = base_info["first_wildcard_pos"]
        second_wildcard_pos = base_info["second_wildcard_pos"]
    else:
        procdef_pattern = []
        first_wildcard_pos = 0
        second_wildcard_pos = 0

    # Extract procdef
    procdef_offset = find_pattern_with_wildcards(text_data, procdef_pattern, "procdef", first_wildcard_pos, second_wildcard_pos)
    if procdef_offset != -1:
        pattern_va = image_base + procdef_offset
        print(f"{INFO}[INFO] procdef Pattern VA: 0x{pattern_va:08X}{RESET}")

        if second_wildcard_pos >= len(procdef_pattern):
            print(f"{ERROR}[ERROR] Second wildcard position {second_wildcard_pos} exceeds pattern length.{RESET}")
        elif procdef_offset + second_wildcard_pos >= len(text_data):
            print(f"{ERROR}[ERROR] Second wildcard position out of bounds for procdef.{RESET}")
        else:
            byte1 = text_data[procdef_offset + first_wildcard_pos]
            byte2 = text_data[procdef_offset + second_wildcard_pos]
            # Stitch together the two bytes as a data string
            procdef_value = f"0x00{byte1:02X}00{byte2:02X}"
            print(f"{INFO}[INFO] Extracted procdef: {procdef_value}{RESET}")
            all_extracted_addresses["procdef"] = procdef_value

    # Extract function RVAs/VAs with validation
    if binary_format == 'PE':
        func_patterns = PATTERNS_AND_OFFSETS["PE"]["func_patterns"]
    elif binary_format == 'ELF':
        func_patterns = PATTERNS_AND_OFFSETS["ELF"]["func_patterns"]
    else:
        func_patterns = {}

    offsets = {}
    for func, data in func_patterns.items():
        pattern_offset = find_pattern(text_data, data["pattern"])
        if pattern_offset != -1:
            if binary_format == 'PE':
                # For PE, RVA = VA - Image Base
                pointer_va = image_base + text_va + pattern_offset + data["offset"]
                final_rva = pointer_va - image_base
                final_rva &= 0xFFFFFFFF  # Ensure unsigned

                print(f"{INFO}[INFO] {func} VA: 0x{pointer_va:08X}, RVA: 0x{final_rva:08X}{RESET}")

                # Validate RVA within .text section
                if image_base + final_rva >= text_section_start_va and image_base + final_rva < text_section_end_va:
                    offsets[func] = final_rva
                    print(f"{INFO}[INFO] {func} RVA: 0x{final_rva:08X}{RESET}")
                else:
                    print(f"{WARN}[WARN] Computed RVA for '{func}' is outside .text section: 0x{final_rva:08X}{RESET}")
                    offsets[func] = None
            elif binary_format == 'ELF':
                # For ELF, VA is absolute
                pointer_va = text_va + pattern_offset + data["offset"]
                final_va = pointer_va
                print(f"{INFO}[INFO] {func} VA: 0x{final_va:08X}{RESET}")

                # Validate VA within .text section
                if text_section_start_va <= final_va < text_section_end_va:
                    offsets[func] = final_va
                    print(f"{INFO}[INFO] {func} VA: 0x{final_va:08X}{RESET}")
                else:
                    print(f"{WARN}[WARN] Computed VA for '{func}' is outside .text section: 0x{final_va:08X}{RESET}")
                    offsets[func] = None
        else:
            print(f"{WARN}[WARN] Pattern for {func} not found.{RESET}")
            offsets[func] = None

    # Calculate prologue lengths
    prologue_lengths = calculate_prologue_lengths(binary, offsets, binary_format, image_base)

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
            # procdef and prologue are treated differently
            if addr is not None:
                print(f"  {RESULTS}{name}: {addr}{RESET}")
                values_list.append(addr)
            else:
                print(f"  {WARN}{name}: Not found{RESET}")
                values_list.append("None")
        else:
            if addr is not None:
                if binary_format == 'PE' and name in FUNCTION_NAMES:
                    val_str = f"0x{addr:08X} (RVA)"
                elif binary_format == 'ELF' and name in FUNCTION_NAMES:
                    val_str = f"0x{addr:08X} (VA)"
                else:
                    val_str = f"0x{addr:08X}"
                print(f"  {RESULTS}{name}: {val_str}{RESET}")
                values_list.append(val_str)
            else:
                print(f"  {WARN}{name}: Not found{RESET}")
                values_list.append("None")

    # Print all addresses in a single line separated by commas
    print(f"\n{RESULTS}{{{', '.join(values_list)}}}{RESET}")

if __name__ == "__main__":
    main()
