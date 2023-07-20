#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <Tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>

// Function to perform manual mapping
bool ManualMap(HANDLE hProcess, const void* dllBase, DWORD dllSize)
{
    // Step 1: Allocate memory in the target process to store the DLL
    void* remoteDllBase = VirtualAllocEx(hProcess, nullptr, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllBase)
    {
        std::cout << "Failed to allocate memory in the target process!" << std::endl;
        return false;
    }

    // Step 2: Write the DLL data into the target process
    if (!WriteProcessMemory(hProcess, remoteDllBase, dllBase, dllSize, nullptr))
    {
        std::cout << "Failed to write DLL data to the target process!" << std::endl;
        VirtualFreeEx(hProcess, remoteDllBase, 0, MEM_RELEASE);
        return false;
    }

    // Step 3: Get the address of the DLL's entry point function
    FARPROC entryPoint = reinterpret_cast<FARPROC>(reinterpret_cast<ULONGLONG>(remoteDllBase) + /* Offset to the entry point (e.g., from the DLL headers) */);

    // Step 4: Execute the DLL's entry point function in the target process
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entryPoint), nullptr, 0, nullptr);
    if (!hThread)
    {
        std::cout << "Failed to create a remote thread in the target process!" << std::endl;
        VirtualFreeEx(hProcess, remoteDllBase, 0, MEM_RELEASE);
        return false;
    }

    CloseHandle(hThread);
    return true;
}


int main()
{
    const char* targetProcessName = "target_process.exe";
    const char* dllPath = "path/to/your_dll.dll";

    // Find the target process ID
    DWORD targetProcessId = 0;
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hSnapshot, &processEntry))
    {
        do
        {
            if (_stricmp(processEntry.szExeFile, targetProcessName) == 0)
            {
                targetProcessId = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);

    if (targetProcessId == 0)
    {
        std::cout << "Target process not found!" << std::endl;
        return 1;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (!hProcess)
    {
        std::cout << "Failed to open the target process!" << std::endl;
        return 1;
    }

    // Load the DLL from disk
    std::vector<BYTE> dllBuffer;
    std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
    if (!dllFile)
    {
        std::cout << "Failed to open DLL file!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    dllBuffer.resize(dllFile.tellg());
    dllFile.seekg(0, std::ios::beg);
    dllFile.read(reinterpret_cast<char*>(dllBuffer.data()), dllBuffer.size());
    dllFile.close();

    // Inject the DLL into the target process using manual mapping
    if (!ManualMap(hProcess, dllBuffer.data(), static_cast<DWORD>(dllBuffer.size())))
    {
        std::cout << "Failed to inject the DLL!" << std::endl;
    }
    else
    {
        std::cout << "DLL injected successfully!" << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}
