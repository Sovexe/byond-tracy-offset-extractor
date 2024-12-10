# BYOND Tracy Offset Extractor

A Python-based tool for analyzing and extracting patterns and addresses from the BYOND PE and ELF binaries for use with [`byond-tracy`](https://github.com/mafemergency/byond-tracy). Script will break if / when Lummox makes compiler changes or if the anchor patterns become misaligned.

---

## Requirements

- **Python 3.12+**
- **Dependencies**: Install the following Python libraries:
  - [`lief`](https://github.com/lief-project/LIEF)
  - [`capstone`](https://github.com/capstone-engine/capstone)
  - [`colorama`](https://github.com/tartley/colorama)
  
  ```bash
  pip install lief
  pip install capstone
  pip install colorma
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
[INFO] Successfully loaded binary: .\libbyond1647.so
[INFO] Listing all LOAD segments:
  LOAD Segment 1: VA=0x0, Size=0x125f3c, Flags=R
  LOAD Segment 2: VA=0x126000, Size=0x4e6204, Flags=ER
  LOAD Segment 3: VA=0x60d000, Size=0x1747e8, Flags=R
  LOAD Segment 4: VA=0x782dbc, Size=0x1b4a0, Flags=WR
  [INFO] Selected LOAD segment with EXECUTE flag: VA = 0x126000
[INFO] Image Base (l_addr): 0x00126000
[INFO] .text section found.
[INFO] Pattern found at offset: 0x1E0FC8
[INFO] Base Pattern RVA: 0x00307018
[INFO] Computing address for 'strings':
       Pattern RVA: 0x307018 + Offset: 0x-268 = Pointer RVA: 0x306DB0
[DEBUG] Read raw value: 0x00787DF0 from RVA: 0x00306DB0
[INFO] Computing address for 'strings_len':
       Pattern RVA: 0x307018 + Offset: 0x-1D6 = Pointer RVA: 0x306E42
[DEBUG] Read raw value: 0x00787DEC from RVA: 0x00306E42
[INFO] Computing address for 'miscs':
       Pattern RVA: 0x307018 + Offset: 0x-248 = Pointer RVA: 0x306DD0
[DEBUG] Read raw value: 0x00787DD8 from RVA: 0x00306DD0
[INFO] Computing address for 'procdefs':
       Pattern RVA: 0x307018 + Offset: 0x-294 = Pointer RVA: 0x306D84
[DEBUG] Read raw value: 0x00787D98 from RVA: 0x00306D84
[INFO] Pattern found at offset: 0x223647
[INFO] Exec_Proc Pattern RVA: 0x00349697
[INFO] Computing address for 'exec_proc':
       Pattern RVA: 0x349697 + Offset: 0x-17 = Pointer RVA: 0x349680
       Computed Address for 'exec_proc': 0x00349680
[INFO] Pattern found at offset: 0x20F3AD
[INFO] Server_Tick Pattern RVA: 0x003353FD
[INFO] Computing address for 'server_tick':
       Pattern RVA: 0x3353FD + Offset: 0x-2D = Pointer RVA: 0x3353D0
       Computed Address for 'server_tick': 0x003353D0
[INFO] Pattern found at offset: 0x1FDAD0
[INFO] Send_Map Pattern RVA: 0x00323B20
[INFO] Computing address for 'send_maps':
       Pattern RVA: 0x323B20 + Offset: 0x0 = Pointer RVA: 0x323B20
       Computed Address for 'send_maps': 0x00323B20
[INFO] Wildcard pattern 'procdef' found at offset: 0x2147A3
[INFO] procdef Pattern RVA: 0x0033A7F3
[INFO] Extracted procdef: 0x001C002C

[RESULTS] Extracted Addresses:
  strings: 0x00787DF0
  strings_len: 0x00787DEC
  miscs: 0x00787DD8
  procdefs: 0x00787D98
  procdef: 0x001C002C
  exec_proc: 0x00349680
  server_tick: 0x003353D0
  send_maps: 0x00323B20
```
