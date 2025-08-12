# BYOND Tracy Offset Extractor

A Python-based tool for analyzing and extracting patterns and addresses from the BYOND PE and ELF binaries for use with [`byond-tracy`](https://github.com/mafemergency/byond-tracy). Script will break if / when Lummox makes compiler changes or if the anchor patterns become misaligned.

---

## Requirements

- **Python 3.12+**
- **Dependencies**: Install the following Python libraries:
  - [`lief`](https://github.com/lief-project/LIEF)
  - [`capstone`](https://github.com/capstone-engine/capstone)
  
  ```bash
  pip install lief
  pip install capstone
  ```

---

## Usage

### Syntax

```bash
python binary_analysis.py <binary_path> [--use-old-elf]
```

### Arguments

- `<binary_path>`: Path to the binary file (`.dll` or `.so`).
- `--use-old-elf`: Optional flag to specify using older ELF patterns (for ELF binaries with version 1643 and lower).

### Example

#### Analyze a PE Binary

```bash
python binary_analysis.py C:\path\to\byondcore.dll
```

#### Analyze an ELF Binary

```bash
python binary_analysis.py /path/to/libbyond.so
```

#### Analyze an ELF Binary (build < 1634)

```bash
python binary_analysis.py /path/to/libbyond.so --use-old-elf
```

---

## Example output

```
[INFO] Successfully loaded binary: .\byondcore1648.dll
[INFO] Image Base (PE): 0x10000000
[INFO] .text section found.
[DEBUG] .text section VA: 0x00001000, Size: 3778058 bytes
[INFO] Searching for Memory Diagnostics Anchor Pattern...
[DEBUG] Pattern found at offset: 0x00116370
[INFO] Memory Diagnostics Anchor found at RVA: 0x00117370
[INFO] Computing address for 'strings_len':
[DEBUG] Pattern RVA: 0x00117370 + Offset: 0x19 = Pointer RVA: 0x00117389
[DEBUG] Read raw value: 0x1042497C from RVA: 0x00117389
[INFO] Adjusted Address for 'strings_len': 0x0042497C
[INFO] Computing address for 'procdefs_len':
[DEBUG] Pattern RVA: 0x00117370 + Offset: 0x-96 = Pointer RVA: 0x001172DA
[DEBUG] Read raw value: 0x1042499C from RVA: 0x001172DA
[INFO] Adjusted Address for 'procdefs_len': 0x0042499C
[INFO] Computing address for 'miscs_len':
[DEBUG] Pattern RVA: 0x00117370 + Offset: 0x16F = Pointer RVA: 0x001174DF
[DEBUG] Read raw value: 0x1042498C from RVA: 0x001174DF
[INFO] Adjusted Address for 'miscs_len': 0x0042498C
[DEBUG] Constructed pattern for 'strings': 8B 4D 08 3B 0D 7C 49 42 10 73 10 A1 ?? ?? ?? ?? 8B ?? 88
[DEBUG] Wildcard pattern 'strings_pattern' found at offset: 0x0021FE33
[DEBUG] Array pointer for 'strings' found at offset 0x0021FE33: 0x00424978
[DEBUG] Constructed pattern for 'procdefs': 3B 05 9C 49 42 10 72 04 33 C0 5D C3 6B C0 ?? 03 05 ?? ?? ?? ??
[DEBUG] Wildcard pattern 'procdefs_pattern' found at offset: 0x0021FE16
[DEBUG] Array pointer for 'procdefs' found at offset 0x0021FE16: 0x00424998
[DEBUG] Constructed pattern for 'miscs': 3B 0D 8C 49 42 10 72 04 33 C0 5D C3 A1 ?? ?? ?? ?? 8B ?? 88
[DEBUG] Wildcard pattern 'miscs_pattern' found at offset: 0x001FC0F6
[DEBUG] Array pointer for 'miscs' found at offset 0x001FC0F6: 0x00424988
[DEBUG] Wildcard pattern 'procdef' found at offset: 0x001162AD
[INFO] procdef Pattern RVA: 0x001172AD
[INFO] Extracted procdef: 0x001C002C
[DEBUG] Wildcard pattern 'exec_proc_pattern' found at offset: 0x00139660
[INFO] exec_proc RVA: 0x0013A660
[DEBUG] Wildcard pattern 'server_tick_pattern' found at offset: 0x00222A60
[INFO] server_tick RVA: 0x00223A60
[DEBUG] Wildcard pattern 'send_maps_pattern' found at offset: 0x001D4DD0
[INFO] send_maps RVA: 0x001D5DD0
[DEBUG] Function RVA: 0x001D5DD0, .text VA: 0x00001000, Offset: 0x001D4DD0
[INFO] Prologue length for send_maps: 5 bytes
[DEBUG] Function RVA: 0x00223A60, .text VA: 0x00001000, Offset: 0x00222A60
[INFO] Prologue length for server_tick: 6 bytes
[DEBUG] Function RVA: 0x0013A660, .text VA: 0x00001000, Offset: 0x00139660
[INFO] Prologue length for exec_proc: 6 bytes

Extracted Addresses:
  strings: 0x00424978
  strings_len: 0x0042497C
  miscs: 0x00424988
  miscs_len: 0x0042498C
  procdefs: 0x00424998
  procdefs_len: 0x0042499C
  procdef: 0x001C002C
  exec_proc: 0x0013A660
  server_tick: 0x00223A60
  send_maps: 0x001D5DD0
  prologue: 0x00050606

{0x00424978, 0x0042497C, 0x00424988, 0x0042498C, 0x00424998, 0x0042499C, 0x001C002C, 0x0013A660, 0x00223A60, 0x001D5DD0, 0x00050606}
```
