# XOR ASM Shellcode Toolkit

This repository contains a comprehensive set of tools for developing, encrypting, and testing x64 shellcodes on Linux. The primary goal is to demonstrate shellcode signature hiding techniques using XOR encryption and dynamic decoder stubs for educational and research purposes.

## 🧠 Theory: Modern Shellcode Mechanics

For those returning to this project after a break, here are the core concepts used in the Assembly files:

### 1. The "Null-Byte" Problem
Buffer overflow vulnerabilities often rely on string functions like `strcpy`. These functions stop processing when they hit a **Null Byte (0x00)**.
*   **Bad:** `mov rax, 59` -> Generates `b8 3b 00 00 00` (Contains Nulls).
*   **Good:** `push 59; pop rax` -> Generates `6a 3b 58` (Null-Free).
*   *This is why you see `xor`, `inc`, and `push/pop` used instead of direct `mov`.*

### 2. Stack Strings
Standard programs store strings in the `.data` section. Shellcode is position-independent and cannot rely on hardcoded addresses.
*   **Technique:** We push the string hex value directly onto the stack.
*   **Example:** `"/bin//sh"` is 8 bytes. In hex (little-endian reverse) it is `0x68732f2f6e69622f`.
*   We point the syscall argument to `rsp` (the top of the stack) to use it.

### 3. The `CDQ` Instruction Trick
You will see `cdq` used often before `syscall`.
*   **Purpose:** It extends the sign bit of `EAX` into `EDX`.
*   **Why?**: If `EAX` is positive (which syscall numbers are), `EDX` becomes 0.
*   **Benefit**: `mov rdx, 0` is 7 bytes. `cdq` is **1 byte**. It's a massive space saver for zeroing the 3rd argument register.

### 4. XOR Encoding & Decoders
Security systems (AV/EDR) scan for known byte sequences (signatures).
*   **XOR Property**: `A XOR B = C` and `C XOR B = A`.
*   **Strategy**: We encrypt the shellcode with a key (B). The payload (C) looks like random noise.
*   **The Stub**: A small loop at the start of the payload that iterates over the data and XORs it back to original (A) right before execution.

---

## 📂 Project Structure & Tools

### 1. Payload Generators (`shellcoder.py`, `ReverseShellGen.py`)
Tools designed to generate raw shellcode bytes from various sources.

#### `shellcoder.py` — ELF to Shellcode Extractor
A utility that extracts the executable machine code (`.text` section) from a compiled ELF binary.
- **Functionality**:
  - Parses an ELF executable using `pwntools`.
  - Extracts the raw bytes from the `.text` section.
  - Formats the output as a hexadecimal string.
  - **Safety Check**: Scans for NULL bytes (`0x00`) which can terminate string-based exploits (like `strcpy`).
- **Usage**: `python3 shellcoder.py <binary_path>`

#### `ReverseShellGen.py` — Reverse Shell Generator (IPv4 & IPv6)
An interactive generator for creating custom Reverse Shell payloads (connect-back).
- **Functionality**:
  - Takes a user-defined LHOST (IP) and LPORT.
  - **Auto-Detection**: Identifies if the IP is IPv4 or IPv6.
  - **IPv6 Support**: Generates the 28-byte `sockaddr_in6` structure for modern network environments.
  - **Smart Encoding**: If the IP/Port introduces NULL bytes, it automatically applies a mini-XOR obfuscation routine to the mov instructions to ensure the final payload remains NULL-free.
- **Usage**: Run interactively `python3 ReverseShellGen.py`

#### `IP-ASM-Converter.py` — Manual Assembly Helper
A simple utility for manual assembly coding.
- **Problem**: Manually calculating the hex values for IP addresses and ports to push onto the stack (in correct Endianness) is tedious and error-prone.
- **Solution**: This script takes an IP and Port and prints the exact Assembly instructions (`push 0x...`) needed to embed them in your `.s` file.
- **Usage**: `python3 IP-ASM-Converter.py <IP> <PORT>`

#### `Egghunter-Gen.py` — Buffer Space Stager (New!)
A utility to generate an "Egghunter" stub for small buffer exploits.
- **Concept**: When check buffer is too small for the full payload, you inject a small "Hunter" that scans memory for a specific "Egg" (signature) marking the start of your main payload.
- **Technique**: Uses `access(2)` syscall to safely scan memory pages without crashing.
- **Egg**: Default tag is `PABA` (prepended as `PABAPABA` to the main payload).
- **Usage**: `python3 Egghunter-Gen.py` (Outputs the hunter shellcode).

### 2. Encryption and Obfuscation (`XOR.py`, `XOR-C.py`)
Scripts that transform "clean" shellcode into an encrypted format to bypass static signature detection.

#### `XOR.py` — Stack-Based Encoder (JMP-CALL-POP)
Generates an XOR-encrypted payload with a classic stack-based decoder stub.
- **Technique**: Uses the **JMP-CALL-POP** method to dynamically obtain the address of the encrypted data at runtime.
- **Polymorphism**: Adds a random "Junk Code" prefix (NOPs, increments/decrements) to change the file signature on every generation.
- **Output**: Logs the result to `XOR.txt` for easy tracking.
- **Best for**: Usage in exploits where stack execution is permitted or for learning classic techniques.

#### `XOR-MMX.py` — Advanced MMX Obfuscator (New!) - need to test
A highly advanced generator for evading modern EDRs and static analysis.
- **Anti-Debugging**: Includes a `ptrace` check to detect if the shellcode is being debugged.
- **MMX Encryption**: Uses 64-bit MMX registers (`mm0`-`mm7`) for XOR operations instead of standard general-purpose registers.
- **Alignment**: Automatically pads shellcode to 8-byte boundaries.
- **Usage**: `python3 XOR-MMX.py` (Selects hex and description interactively).

#### `XOR-C.py` — RIP-Relative Encoder (Modern)
A modernized version of the encoder using 64-bit addressing.
- **Technique**: Uses **RIP-Relative Addressing (LEA)** to locate the encrypted data, which is position-independent and does not rely on stack manipulation tricks.
- **C-Harness Generation**: Automatically creates a `test_payload.c` source file.
  - This C file sets up an executable memory segment (`mprotect` with `PROT_EXEC`).
  - Copies the payload and executes it.
- **Best for**: Creating standalone Proof-of-Concept (PoC) executables to test AV/EDR evasion.

### 3. Execution and Analysis (`loader.py`, `Loader-Indirect.c`)
Tools for safely running and verifying shellcode.

#### `loader.py` — In-Memory Loader
A Python script to execute raw hex shellcode directly in memory without compilation.
- **Functionality**:
  - Uses `pwntools` to allocate executable memory.
  - Injects the hex string provided as an argument.
  - Transfers control flow to the shellcode.
- **Usage**: `python3 loader.py <HEX_STRING>`
- **Note**: Useful for verifying that your XOR decoder stub works correctly before embedding it into an exploit.

#### `Loader-Indirect.c` — Stealthy C Loader (New!) - need to test
A compiled C loader that uses **Indirect Syscalls** to bypass EDR hooks.
- **Concept**: Instead of calling `mmap` directly (which EDRs hook), it finds a `syscall` gadget in `libc` and jumps to it.
- **Stealth**: Hides the origin of the system call, making memory allocation look like it came from a legitimate library.
- **Usage**:
  1. Compile: `gcc -o Loader-Indirect Loader-Indirect.c -ldl`
  2. Run: `./Loader-Indirect <HEX_PAYLOAD>`

*(Note: Requires Linux environment/headers to compile)*

---

## ⚡ Advanced Usage: Evasion & Low-Level Tactics

This toolkit goes beyond simple encoding. For complex environments with active EDR/AV monitoring, use these advanced modules:

### 1. 🧬 Polymorphic Egghunter (Stage-0)
When your exploit buffer is too small for a full payload, use the **Egghunter**. It is a tiny (35-byte) robust memory scanner that finds your actual shellcode elsewhere in the process memory by searching for a unique 8-byte "egg" (e.g., `PABAPABA`).
* **Usage**: `python3 Egghunter-Gen.py`
* **Tech**: Uses `sys_access` memory page traversal to avoid segmentation faults.

### 2. 💎 MMX Multimedia Encryption
Standard XOR loops are easily flagged by heuristic emulators. **XOR-MMX.py** utilizes 64-bit MMX registers (`mm0-mm7`) to perform decryption.
* **Benefit**: Most static analyzers do not emulate MMX instructions, allowing the payload to remain "invisible" during the initial scan.
* **Anti-Debugging**: Automatically embeds a `ptrace` trap. If run under a debugger, execution terminates immediately.

### 3. 🛡️ Indirect Syscalls (EDR Bypass)
Modern EDRs hook standard library functions like `mmap` and `mprotect`. **Loader-Indirect.c** bypasses these hooks by:
1. Scanning `libc` for a `syscall` gadget.
2. Executing the system call indirectly via a `call` to that gadget.
This makes the system call appear to originate from a legitimate signed library rather than your shellcode's memory segment.

### 🛠 Quick Start: The "Ghost" Workflow
1. **Generate** your reverse shell: `python3 ReverseShellGen.py`
2. **Encapsulate** with MMX: `python3 XOR-MMX.py` (Add the Egg tag `PABAPABA` manually if needed).
3. **Generate** the hunter: `python3 Egghunter-Gen.py`
4. **Deploy**: Inject the 35-byte Egghunter into the vulnerable buffer.
5. **Execute** via `Loader-Indirect.c` for maximum stealth during testing.

---

## 🚀 Workflow Example

### Step 1: Generate Raw Payload
You can either compile your own ASM or use the generator.

**Option A: Compile from ASM**
```bash
nasm -f elf64 shell.s -o shell.o
ld shell.o -o shell
python3 shellcoder.py shell
# Copy the output HEX
```

**Option B: Generate Reverse Shell**
```bash
python3 ReverseShellGen.py
# Enter IP: 127.0.0.1, Port: 4444
# Copy the output HEX
```

### Step 2: Encrypt Payload
Paste the HEX into `XOR.py` or `XOR-C.py` (in the `my_hex` variable).

```bash
python3 XOR-C.py
# This generates 'test_payload.c' and logs to 'XOR.txt'
```

### Step 3: Test and Verify
Compile the C harness generated by `XOR-C.py`:

```bash
gcc -fno-stack-protector -z execstack test_payload.c -o test_exploit
./test_exploit
```
*Note: Ensure you have a listener running (e.g., `nc -lvnp 4444`) if testing a reverse shell.*

---

## ⚠️ Ethical Usage & Disclaimer

This toolkit is developed solely for **educational and research purposes**. It demonstrates modern techniques used in malware analysis, shellcode development, and red team engagements.

*   **Do not use this code on systems you do not own or have explicit permission to test.**
*   **The authors are not responsible for any misuse of this toolkit.**
*   The goal is to demystify how EDR evasion works so defenders can build better detections.

## ⚠️ Technical Notes
- **Polymorphism**: The "Junk Code" added by the encoders ensures the entry point bytes are different every time, which helps evade simple signature matching.
- **NULL-Free**: All tools strive to avoid `0x00` bytes in the final payload to maximize compatibility with vulnerability classes like buffer overflows.
