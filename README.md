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
[INFO] Successfully loaded binary: .\byondcore1647.dll
[INFO] Image Base (l_addr): 0x10000000
[INFO] .text section found.
[DEBUG] .text section VA: 0x00001000, Size: 3675722 bytes
[DEBUG] Pattern found at offset: 0x001E28F6
[INFO] Base pattern found at RVA: 0x001E38F6
[INFO] Computing address for 'strings':
[DEBUG] Pattern RVA: 0x001E38F6 + Offset: 0x-D4 = Pointer RVA: 0x001E3822
[DEBUG] Read raw value: 0x1040A6C4 from RVA: 0x001E3822
[INFO]Adjusted Address for 'strings': 0x0040A6C4
[INFO] Computing address for 'strings_len':
[DEBUG] Pattern RVA: 0x001E38F6 + Offset: 0x-4E = Pointer RVA: 0x001E38A8
[DEBUG] Read raw value: 0x1040A6C8 from RVA: 0x001E38A8
[INFO]Adjusted Address for 'strings_len': 0x0040A6C8
[INFO] Computing address for 'miscs':
[DEBUG] Pattern RVA: 0x001E38F6 + Offset: 0x-B8 = Pointer RVA: 0x001E383E
[DEBUG] Read raw value: 0x1040A6D4 from RVA: 0x001E383E
[INFO]Adjusted Address for 'miscs': 0x0040A6D4
[INFO] Computing address for 'procdefs':
[DEBUG] Pattern RVA: 0x001E38F6 + Offset: 0x-F8 = Pointer RVA: 0x001E37FE
[DEBUG] Read raw value: 0x1040A6E4 from RVA: 0x001E37FE
[INFO]Adjusted Address for 'procdefs': 0x0040A6E4
[DEBUG] Wildcard pattern 'procdef' found at offset: 0x0010EF7D
[INFO] procdef Pattern RVA: 0x0010FF7D
[INFO] Extracted procdef: 0x001C002C
[DEBUG] Pattern found at offset: 0x0013027D
[INFO] exec_proc RVA: 0x00131260
[DEBUG] Pattern found at offset: 0x0020B424
[INFO] server_tick RVA: 0x0020C430
[DEBUG] Pattern found at offset: 0x001C32AC
[INFO] send_maps RVA: 0x001C4250
[INFO] Prologue length for exec_proc: 6 bytes
[INFO] Prologue length for server_tick: 6 bytes
[INFO] Prologue length for send_maps: 5 bytes

Extracted Addresses:
  strings: 0x0040A6C4
  strings_len: 0x0040A6C8
  miscs: 0x0040A6D4
  procdefs: 0x0040A6E4
  procdef: 0x001C002C
  exec_proc: 0x00131260
  server_tick: 0x0020C430
  send_maps: 0x001C4250
  prologue: 0x00050606

{0x0040A6C4, 0x0040A6C8, 0x0040A6D4, 0x0040A6E4, 0x001C002C, 0x00131260, 0x0020C430, 0x001C4250, 0x00050606}
```
