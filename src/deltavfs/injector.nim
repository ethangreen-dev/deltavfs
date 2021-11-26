import os
import osproc
import winim/lean

proc injectDll*(into: string, dllPath: string) = 
    var dllPath = absolutePath(dllPath)
    echo dllPath

    # Start the target process in a suspended state.
    let target = startProcess(into)
    suspend(target)

    let targetHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        false,
        DWORD(target.processId)
    )

    # Allocate and copy dllPath into the target process.
    let remoteDllPath = VirtualAllocEx(
        targetHandle, 
        NULL, 
        cast[SIZE_T](len(dllPath)),
        MEM_COMMIT, 
        PAGE_EXECUTE_READ_WRITE
    )

    echo toHex(cast[uint](remoteDllPath))
    echo toHex(cast[uint](LoadLibraryA))

    WriteProcessMemory(
        targetHandle, 
        remoteDllPath, 
        cstring(dllPath), 
        cast[SIZE_T](len(dllPath)), 
        NULL
    )

    # Spawn a thread to execute LoadLibraryW with the dll
    let loadThread = CreateRemoteThread(
        targetHandle,
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](cast[uint](LoadLibraryA)),
        remoteDllPath,
        0,
        NULL
    )

    resume(target)

    if loadThread != HANDLE(0):
        CloseHandle(loadThread)
