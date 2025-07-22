; payload.asm
bits 64
default rel

section .text
 global _start
_start:
    ; First, decode the XOR encoded string
    lea     rsi, [rel encoded_txt]        ; source - encoded string
    lea     rdi, [rel decoded_txt]        ; destination - decoded string  
    mov     rcx, 11                       ; string length including null terminator
    mov     al, 0xAB                      ; XOR key
decode_string:
    mov     bl, [rsi]                     ; load encoded byte
    xor     bl, al                        ; XOR decode
    mov     [rdi], bl                     ; store decoded byte
    inc     rsi                           ; next source
    inc     rdi                           ; next destination
    loop    decode_string                 ; decrement rcx and loop if not zero

    ; Now execute original MessageBox code with decoded string
    ; MessageBoxA(NULL, decoded_txt, decoded_txt, MB_OK)
    xor     rcx, rcx
    lea     rdx, [rel decoded_txt]
    lea     r8,  [rel decoded_txt]
    mov     r9d, 0
    sub     rsp, 40
    call    [rel addr_MessageBoxA]
    add     rsp, 40

    ; ExitThread(0)
    xor     rcx, rcx
    call    [rel addr_ExitThread]

section .rdata
 ; XOR encoded string "pwnme 2600" with key 0xAB
 encoded_txt: db 0x70^0xAB, 0x77^0xAB, 0x6E^0xAB, 0x6D^0xAB, 0x65^0xAB, 0x20^0xAB, 0x32^0xAB, 0x36^0xAB, 0x30^0xAB, 0x30^0xAB, 0x00^0xAB

section .bss
 decoded_txt: resb 11                     ; space for decoded string

section .idata
 addr_MessageBoxA:   dq 0
 addr_ExitThread:    dq 0
