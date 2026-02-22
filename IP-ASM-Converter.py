#!/usr/bin/python3
import sys
import socket
import struct

def hex_ip(ip):
    try:
        if ':' in ip:
            # IPv6
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
            # Break into 2 64-bit chunks for easy pushing in ASM
            chunks = []
            for i in range(0, 16, 8):
                val = struct.unpack('<Q', ip_bytes[i:i+8])[0]
                chunks.append(val)
            return ("IPv6", chunks) # Returns list of QWORDs
        else:
            # IPv4
            # inet_aton returns bytes in network order (Big Endian)
            # But x86 is Little Endian.
            ip_bytes = socket.inet_aton(ip)
            val = struct.unpack('<I', ip_bytes)[0]
            # When we push 0x0100007f (127.0.0.1) on x86 stack, it becomes 7f 00 00 01 (Correct network order)
            return ("IPv4", val)
    except OSError:
        print(f"[-] Invalid IP address: {ip}")
        sys.exit(1)

def hex_port(port):
    # Port 4444 (0x115c) -> Network Order (Big Endian) 0x115c
    # x86 Stack (Little Endian): to get 0x115c in memory, we push 0x5c11
    # Check:
    # Port 4444 = 0x115c
    # Pushing 0x5c11 (as a word) puts 11 5c on stack (Low addr: 11, High addr: 5c) -> Correct for network!
    
    # Let's verify with struct.pack('>H', port) -> b'\x11\x5c'
    # To get b'\x11\x5c' in memory on Little Endian, we need the integer 0x5c11.
    val = socket.htons(port) # Host to Network Short? No wait.
    # htons(4444) -> 0x5c11 (on LE machine)
    # The value 0x5c11 (23569)
    # push 0x5c11 -> Memory: 11 5c. Correct.
    return val

def generate_asm(ip, port):
    print(f"\n--- ASM Helper for {ip}:{port} ---\n")
    
    # 1. Port
    p_val = hex_port(port)
    print(f"[PORT] {port}")
    print(f"  Hex Value   : 0x{p_val:04x}")
    print(f"  ASM Command : push word 0x{p_val:04x}   ; Push Port {port} (Network Byte Order)")
    print("")

    # 2. IP
    ip_type, ip_val = hex_ip(ip)
    
    if ip_type == "IPv4":
        print(f"[IPv4] {ip}")
        # Build the full 64-bit value: IP(4) + Port(2) + Family(2)
        # Port is already in Network Order (Big Endian) 0x115c.
        # IP is in Network Order (Big Endian) 0x0100007f (127.0.0.1)
        # We need to construct the 64-bit register value.
        
        # struct sockaddr_in {
        #   short sin_family;   // 2 bytes (AF_INET = 2)
        #   short sin_port;     // 2 bytes (Big Endian)
        #   long  sin_addr;     // 4 bytes (Big Endian)
        #   char  sin_zero[8];  // 8 bytes (Zero padding)
        # }
        
        # In memory (Low -> High):
        # [02 00] [11 5c] [7f 00 00 01]
        
        # But we load a 64-bit register (Little Endian CPU):
        # Byte 0 (Lest Significant): 0x02
        # Byte 1: 0x00
        # Byte 2: 0x11
        # Byte 3: 0x5c
        # Byte 4: 0x7f
        # Byte 5: 0x00
        # Byte 6: 0x00
        # Byte 7 (Most Significant): 0x01
        
        # So the HEX value for 'mov rcx, ...' is: 0x0100007f5c110002
        
        full_val = (ip_val << 32) | (p_val << 16) | 0x0002
        
        print(f"  Result Hex  : 0x{full_val:016x}")
        print(f"  ASM Command : mov rcx, 0x{full_val:016x}")
        print(f"                push rcx")
        print(f"  (Copy this 'mov rcx...' into line 42 of Reverse-shell.s)")
    
    elif ip_type == "IPv6":
        print(f"[IPv6] {ip}")
        print("  Note: IPv6 is 16 bytes (2 x QWORDS). Push in reverse order (High part first).")
        # chunks[1] is high part (bytes 8-15)
        # chunks[0] is low part (bytes 0-7)
        print(f"  Part 1 (High): 0x{ip_val[1]:016x}")
        print(f"  Part 2 (Low) : 0x{ip_val[0]:016x}")
        print(f"  ASM Command  :")
        print(f"    mov rax, 0x{ip_val[1]:016x}")
        print(f"    push rax                  ; IPv6 Part 2")
        print(f"    mov rax, 0x{ip_val[0]:016x}")
        print(f"    push rax                  ; IPv6 Part 1")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <IP> <PORT>")
        # Default prompt if no args
        try:
            u_ip = input("IP: ").strip()
            u_port = int(input("Port: ").strip())
            generate_asm(u_ip, u_port)
        except:
            pass
    else:
        generate_asm(sys.argv[1], int(sys.argv[2]))
