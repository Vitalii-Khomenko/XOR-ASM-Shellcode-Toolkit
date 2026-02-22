#!/usr/bin/python3
import datetime
import random

def generate_payload(hex_input, description):
    try:
        clean_hex = hex_input.replace(" ", "").replace("\n", "")
        shellcode = bytearray.fromhex(clean_hex)
    except ValueError:
        return None

    # 1. Key generation and encryption (with 0x00 check)
    while True:
        key = random.randint(1, 255)
        encoded = bytearray([b ^ key for b in shellcode])
        if 0 not in encoded: break

    # 2. x64 RIP-Relative Decoder (Modern & Stable)
    # Use LEA to get the start address of data
    key_hex = hex(key)[2:].zfill(2)
    slen_hex = hex(len(shellcode))[2:].zfill(2)
    
    # 488d3d0b000000 -> lea rdi, [rip + 11] (points to start of shellcode)
    # 6aXX           -> push len
    # 59             -> pop rcx
    # 8037XX         -> xor byte [rdi], key
    # 48ffc7         -> inc rdi
    # e2f8           -> loop (back to xor)
    # (followed by encrypted code)
    
    decoder_hex = f"488d3d0b0000006a{slen_hex}598037{key_hex}48ffc7e2f8"

    # --- POLYMORPHIC JUNK GENERATOR ---
    junk_ops = [
        "90",       # NOP
        "48ffc0",   # INC RAX
        "48ffc8",   # DEC RAX
        "48ffc3",   # INC RBX
        "48ffcb",   # DEC RBX
        "fc",       # CLD
        "f8",       # CLC
    ]
    junk_hex = "".join(random.choice(junk_ops) for _ in range(random.randint(1, 5)))
    
    decoder = bytearray.fromhex(junk_hex + decoder_hex)
    
    final_payload = decoder + encoded
    final_hex = final_payload.hex()

    # 3. C code generation and logging
    c_style = ", ".join([f"0x{final_hex[i:i+2]}" for i in range(0, len(final_hex), 2)])
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open("XOR.txt", "a", encoding="utf-8") as f:
        f.write(f"--- {timestamp} ---\nDesc: {description}\nKey: 0x{key_hex.upper()} | Payload: {final_hex}\n\n")

    c_template = f"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned char code[] = {{ {c_style} }};

int main() {{
    long page_size = sysconf(_SC_PAGESIZE);
    void *mem = aligned_alloc(page_size, page_size);
    memcpy(mem, code, sizeof(code));
    mprotect(mem, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    ((void (*)())mem)();
    return 0;
}}
"""
    with open("test_payload.c", "w") as f: f.write(c_template)
    return final_hex

my_hex = "4831db5366bb79215348bb422041636164656d5348bb48656c6c6f204854534889e66a01586a015f6a125a0f056a3c584831ff0f05"
generate_payload(my_hex, "LEA-based XOR Shellcode")
print("[+] Script updated to LEA-decoder. Try rebuilding.")
