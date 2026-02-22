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

### 1. Payload Generators (`shellcoder.py`, `IPHEXGen.py`)
Tools designed to generate raw shellcode bytes from various sources.

#### `shellcoder.py` — ELF to Shellcode Extractor
A utility that extracts the executable machine code (`.text` section) from a compiled ELF binary.
- **Functionality**:
  - Parses an ELF executable using `pwntools`.
  - Extracts the raw bytes from the `.text` section.
  - Formats the output as a hexadecimal string.
  - **Safety Check**: Scans for NULL bytes (`0x00`) which can terminate string-based exploits (like `strcpy`).
- **Usage**: `python3 shellcoder.py <binary_path>`

#### `IPHEXGen.py` — Reverse Shell Generator
An interactive generator for creating custom Reverse Shell payloads (connect-back).
- **Functionality**:
  - Takes a user-defined LHOST (IP) and LPORT.
  - Dynamically constructs the `sockaddr_in` structure in hex.
  - **Smart Encoding**: If the IP/Port introduces NULL bytes, it automatically applies a mini-XOR obfuscation routine to the mov instructions to ensure the final payload remains NULL-free.
- **Usage**: Run interactively `python3 IPHEXGen.py`

### 2. Encryption and Obfuscation (`XOR.py`, `XOR-C.py`)
Scripts that transform "clean" shellcode into an encrypted format to bypass static signature detection.

#### `XOR.py` — Stack-Based Encoder (JMP-CALL-POP)
Generates an XOR-encrypted payload with a classic stack-based decoder stub.
- **Technique**: Uses the **JMP-CALL-POP** method to dynamically obtain the address of the encrypted data at runtime.
- **Polymorphism**: Adds a random "Junk Code" prefix (NOPs, increments/decrements) to change the file signature on every generation.
- **Output**: Logs the result to `XOR.txt` for easy tracking.
- **Best for**: Usage in exploits where stack execution is permitted or for learning classic techniques.

#### `XOR-MMX.py` — Advanced MMX Obfuscator (New!)
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

#### `Loader-Indirect.c` — Stealthy C Loader (New!)
A compiled C loader that uses **Indirect Syscalls** to bypass EDR hooks.
- **Concept**: Instead of calling `mmap` directly (which EDRs hook), it finds a `syscall` gadget in `libc` and jumps to it.
- **Stealth**: Hides the origin of the system call, making memory allocation look like it came from a legitimate library.
- **Usage**:
  1. Compile: `gcc -o Loader-Indirect Loader-Indirect.c -ldl`
  2. Run: `./Loader-Indirect <HEX_PAYLOAD>`

*(Note: Requires Linux environment/headers to compile)*

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
python3 IPHEXGen.py
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

## ⚠️ Technical Notes
- **Polymorphism**: The "Junk Code" added by the encoders ensures the entry point bytes are different every time, which helps evade simple signature matching.
- **NULL-Free**: All tools strive to avoid `0x00` bytes in the final payload to maximize compatibility with vulnerability classes like buffer overflows.
