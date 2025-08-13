# BYOND Tracy Offset Extractor

A Python-based tool for analyzing and extracting patterns and addresses from the BYOND PE and ELF binaries for use with https://github.com/spacestation13/byond-tracy. Script will break if / when Lummox makes compiler changes or if the anchor patterns become misaligned.

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

### Run via GitHub Actions (recommended)
You can run the extractor entirely from GitHub using the included Extract Signatures workflow.

1. Go to the Actions tab in your fork.
2. Select Extract Signatures from the left sidebar.
3. Click Run workflow.
4. Enter the BYOND version(s) you want to extract, for example: `["515.1590","515.1591"]`
5. Start the workflow - results will be in the run’s summary output.

### Run Locally

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
[INFO] Successfully loaded binary: .\libbyond_516.1666.so
[INFO] Image Base (ELF): 0x00000000
[INFO] .text section found at RVA 0x00133050 (VA 0x00133050), Size: 5412938 bytes
[DEBUG] Searching for Memory Diagnostics Anchor Pattern...
[DEBUG] Pattern found at .text+0x00233080
[INFO] Memory Diagnostics Anchor found at RVA: 0x003660D0

----------------------- Resolving Array Length Variables -----------------------
[DEBUG] Pattern RVA: 0x003660D0 + Offset: 0x2A2 = Pointer RVA: 0x00366372
[DEBUG] Read raw VA: 0x007EA02C from RVA: 0x00366372
[INFO] Resolved strings_len RVA: 0x007EA02C
[DEBUG] Pattern RVA: 0x003660D0 + Offset: 0x1EF = Pointer RVA: 0x003662BF
[DEBUG] Read raw VA: 0x007E9FD4 from RVA: 0x003662BF
[INFO] Resolved procdefs_len RVA: 0x007E9FD4
[DEBUG] Pattern RVA: 0x003660D0 + Offset: 0x3A4 = Pointer RVA: 0x00366474
[DEBUG] Read raw VA: 0x007EA014 from RVA: 0x00366474
[INFO] Resolved miscs_len RVA: 0x007EA014

------------------------------- Resolving Arrays -------------------------------
[DEBUG] Constructed pattern for 'strings': 8B 44 24 20 39 05 2C A0 7E 00 76 17 8B 15 ?? ?? ?? ??
[DEBUG] Wildcard pattern 'strings_pattern' found at .text+0x001AC425
[DEBUG] Read raw VA for 'strings': 0x007EA030 from .text+0x001AC433
[INFO] Resolved strings RVA: 0x007EA030
[DEBUG] Constructed pattern for 'procdefs': 8B 44 24 04 39 05 D4 9F 7E 00 76 14 6B C0 ?? 03 05 ?? ?? ?? ??
[DEBUG] Wildcard pattern 'procdefs_pattern' found at .text+0x001ADC90
[DEBUG] Read raw VA for 'procdefs': 0x007E9FD8 from .text+0x001ADCA1
[INFO] Resolved procdefs RVA: 0x007E9FD8
[DEBUG] Constructed pattern for 'miscs': 8B 44 24 04 39 05 14 A0 7E 00 76 14 8B 15 ?? ?? ?? ??
[DEBUG] Wildcard pattern 'miscs_pattern' found at .text+0x001ADC10
[DEBUG] Read raw VA for 'miscs': 0x007EA018 from .text+0x001ADC1E
[INFO] Resolved miscs RVA: 0x007EA018

------------------------------ Extracting procdef ------------------------------
[DEBUG] Wildcard pattern 'procdef' found at .text+0x00233243
[INFO] procdef Pattern RVA: 0x00366293
[INFO] Extracted procdef: 0x001C002C

------------------------------ Locating Functions ------------------------------
[DEBUG] Wildcard pattern 'exec_proc_pattern' found at .text+0x002431E0
[INFO] Resolved exec_proc RVA: 0x00376230
[DEBUG] Wildcard pattern 'server_tick_pattern' found at .text+0x0022DE10
[INFO] Resolved server_tick RVA: 0x00360E60
[DEBUG] Wildcard pattern 'send_maps_pattern' found at .text+0x0021CA40
[INFO] Resolved send_maps RVA: 0x0034FA90
[DEBUG] Wildcard pattern 'erasure_pattern' found at .text+0x0029F700
[INFO] Resolved erasure RVA: 0x003D2750
[DEBUG] Wildcard pattern 'event_io_pattern' found at .text+0x00357500
[INFO] Resolved event_io RVA: 0x0048A550
[DEBUG] Wildcard pattern 'mkstr_pattern' found at .text+0x001A0B80
[INFO] Resolved mkstr RVA: 0x002D3BD0
[DEBUG] Wildcard pattern 'rebalance_pattern' found at .text+0x0019E8F0
[INFO] Resolved rebalance RVA: 0x002D1940

------------------------- Calculating Prologue Lengths -------------------------
[DEBUG] Function RVA: 0x00376230, .text VA: 0x00133050, Offset: 0x002431E0
[INFO] Prologue length for exec_proc: 5 bytes
[DEBUG] Function RVA: 0x0034FA90, .text VA: 0x00133050, Offset: 0x0021CA40
[INFO] Prologue length for send_maps: 5 bytes
[DEBUG] Function RVA: 0x00360E60, .text VA: 0x00133050, Offset: 0x0022DE10
[INFO] Prologue length for server_tick: 5 bytes
[DEBUG] Function RVA: 0x0048A550, .text VA: 0x00133050, Offset: 0x00357500
[INFO] Prologue length for event_io: 8 bytes
[DEBUG] Function RVA: 0x003D2750, .text VA: 0x00133050, Offset: 0x0029F700
[INFO] Prologue length for erasure: 5 bytes
[DEBUG] Function RVA: 0x002D1940, .text VA: 0x00133050, Offset: 0x0019E8F0
[INFO] Prologue length for rebalance: 5 bytes
[DEBUG] Function RVA: 0x002D3BD0, .text VA: 0x00133050, Offset: 0x001A0B80
[INFO] Prologue length for mkstr: 5 bytes

-------------------------------- Final Results ---------------------------------
Extracted Addresses:
  strings: 0x007EA030
  strings_len: 0x007EA02C
  miscs: 0x007EA018
  miscs_len: 0x007EA014
  procdefs: 0x007E9FD8
  procdefs_len: 0x007E9FD4
  procdef: 0x001C002C
  exec_proc: 0x00376230
  server_tick: 0x00360E60
  send_maps: 0x0034FA90
  prologue: 0x00050505

{0x007EA030, 0x007EA02C, 0x007EA018, 0x007EA014, 0x007E9FD8, 0x007E9FD4, 0x001C002C, 0x00376230, 0x00360E60, 0x0034FA90, 0x00050505}

Experimental Addresses:
  erasure: 0x003D2750
  event_io: 0x0048A550
  mkstr: 0x002D3BD0
  rebalance: 0x002D1940
  prologue2: 0x05050805

{0x007EA030, 0x007EA02C, 0x007EA018, 0x007EA014, 0x007E9FD8, 0x007E9FD4, 0x001C002C, 0x00376230, 0x00360E60, 0x0034FA90, 0x00050505, 0x003D2750, 0x0048A550, 0x002D3BD0, 0x002D1940, 0x05050805}
```



