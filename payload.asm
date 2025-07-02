; payload.asm
bits 64
default rel

section .text
 global _start
_start:
    ; MessageBoxA(NULL,"pwnme 2600","pwnme 2600",MB_OK)
    xor     rcx, rcx
    lea     rdx, [rel txt]
    lea     r8,  [rel txt]
    mov     r9d, 0
    sub     rsp, 40
    call    [rel addr_MessageBoxA]
    add     rsp, 40

    ; ExitThread(0)
    xor     rcx, rcx
    call    [rel addr_ExitThread]

section .rdata
 txt:    db "pwnme 2600",0

section .idata
 addr_MessageBoxA:   dq 0
 addr_ExitThread:    dq 0
