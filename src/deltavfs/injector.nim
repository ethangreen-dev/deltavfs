import os
import osproc
import strutils
import strformat

import ../payload

import stew/endians2
import stew/byteutils

import winim/lean
from winim/inc/psapi import
    EnumProcessModules,
    GetModuleBaseNameA

proc remoteLoadLib(procHandle: HANDLE, moduleName: string): int = 
    var cModuleName = $moduleName
    let moduleNameAddr = VirtualAllocEx(
        procHandle,
        NULL,
        cast[SIZE_T](len(moduleName) + 1),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    WriteProcessMemory(procHandle, moduleNameAddr, LPCVOID(addr cModuleName[0]), SIZE_T(len(moduleName) + 1), NULL)

    echo &"Wrote to {toHex(cast[int](moduleNameAddr))}"

    let loadLibraryAddr = cast[int](LoadLibraryA)
    let resultAddr = VirtualAllocEx(
        procHandle,
        NULL,
        cast[SIZE_T](sizeof(HMODULE)),
        MEM_COMMIT,
        PAGE_READWRITE
    )

    let moduleNameShc = swapBytes(cast[uint64](moduleNameAddr))
    let loadLibraryShc = swapBytes(cast[uint64](loadLibraryAddr))
    let resultShc = swapBytes(cast[uint64](resultAddr))

    echo &"LoadLibraryA: {toHex(cast[int](loadLibraryAddr))}"
    echo &"resultAddr  : {toHex(cast[int](resultAddr))}"

    # Not sure how needed this is -- does nothing based on experimentation.  0x66 0x83 0xE4 0xC0                  ; and sp, 0xFFC0
    let payload = &"""
    0x53                                 ; push rbx
    0x48 0x89 0xE3                       ; mov rbp, rsp
    0x48 0x83 0xEC 0x20                  ; sub rsp, 0x20
    0x48 0xB9 {toHex(moduleNameShc)}     ; mov rcx, <library name>
    0x48 0xBA {toHex(loadLibraryShc)}    ; mov rdx, <addr of LoadLibrary>
    0xFF 0xD2                            ; call rdx
    0x48 0xBA {toHex(resultShc)}         ; movabs rdx, <result ptr>
    0x48 0x89 0x02                       ; mov [rdx], rax
    0x48 0x89 0xDC                       ; pop rsp, rbx
    0x5B                                 ; pop rbx
    0xC3                                 ; ret
    """

    echo payload

    # Some quick formatting to remove comments, additional whitespace, and newlines.
    var resultShellcode = newSeq[byte]()

    for line in splitLines(payload):
        let data = split(line, ";")[0]
            .strip()
            .replace("0x", "")
            .replace(" ", "")
            .hexToSeqByte()

        resultShellcode = resultShellcode & data

    echo resultShellcode

    # Allocate space in executable memory and write the shellcode.
    let shellcodeAddr = VirtualAllocEx(
        procHandle,
        NULL,
        len(resultShellcode),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    WriteProcessMemory(procHandle, shellcodeAddr, LPCVOID(addr resultShellcode[0]), SIZE_T(len(resultShellcode)), NULL)

    echo &"shellcode written to {toHex(cast[int](shellcodeAddr))}"

    let loaderThread = CreateRemoteThread(
        procHandle,
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](shellcodeAddr),
        NULL,
        0,
        NULL
    )

    result = int(0)
    WaitForSingleObject(loaderThread, INFINITE)
    CloseHandle(loaderThread)

    ReadProcessMemory(procHandle, resultAddr, cast[LPVOID](addr result), 8, NULL)

    # Cleanup allocated memory.
    VirtualFree(moduleNameAddr, 0, MEM_RELEASE)
    VirtualFree(resultAddr, 0, MEM_RELEASE)
    VirtualFree(shellcodeAddr, 0, MEM_RELEASE)

    # var moduleHandles: array[1024, HMODULE]
    # var sizeOfHandles: DWORD

    # doAssert EnumProcessModules(procHandle, addr moduleHandles[0], 1024, addr(sizeOfHandles)) != 0

    # let moduleCount = int(int(sizeOfHandles) / sizeof(HMODULE))

    # for i in 0..<moduleCount:
    #     let parsedModName = cast[cstring](create(char, MAX_PATH + 1))
    #     doAssert GetModuleBaseNameA(procHandle, moduleHandles[i], parsedModName, MAX_PATH) != 0

    #     if parsedModName != moduleName:
    #         continue

    #     let test = GetProcAddress(moduleHandles[i], parsedModName)

    #     echo $moduleName
    #     echo toHex(cast[int](test))

    # echo "Hello world!"

proc getLibFuncOffset(moduleName: string, funcName: string): int =
    var cModuleName = $moduleName
    var cFuncName = &funcName

    # Load the module into memory, taking care not to resolve any dependent libraries.
    let moduleHandle = LoadLibraryExA(cast[LPCSTR](addr cModuleName[0]), HANDLE(0), DWORD(DONT_RESOLVE_DLL_REFERENCES))
    let moduleBaseAddr = cast[int](moduleHandle)

    # Determine the local address of the target function, by name.
    let localAddr = GetProcAddress(moduleHandle, cast[LPCSTR](cFuncName))

    echo &"moduleBaseAddr: {toHex(cast[int](moduleBaseAddr))}"
    echo &"localAddr:      {toHex(cast[int](localAddr))}"

    # Compute the delta offset between the module base and the function.
    let localDelta = cast[int](localAddr) - cast[int](moduleBaseAddr)

    localDelta

# proc remoteLoadLib(procHandle: HANDLE, dllPath: string, suspended: bool = false): HANDLE = 
#     var widePath = newWideCSTring(dllPath)
# 
#     let remotePath = VirtualAllocEx(
#         procHandle,
#         NULL,
#         cast[SIZE_T](len widePath) * 2,
#         MEM_COMMIT,
#         PAGE_EXECUTE_READWRITE
#     )
# 
#     WriteProcessMemory(
#         procHandle,
#         remotePath,
#         cast[LPCVOID](addr(widePath[0])),
#         cast[SIZE_T](len widePath) * 2,
#         NULL
#     )
# 
#     echo &"wrote dll path to {toHex(cast[int](remotePath))}"
# 
#     CreateRemoteThread(
#         procHandle,
#         NULL,
#         0,
#         cast[LPTHREAD_START_ROUTINE](cast[uint](LoadLibraryW)),
#         remotePath,
#         if suspended: 4 else: 0,
#         NULL
#     )

proc injectDll*(into: string) = 
    let binDir = currentSourcePath().splitPath().head / "../../bin"

    let capstoneDll = absolutePath(binDir / "capstone.dll")
    let payloadDll = absolutePath(binDir / "payload.dll")

    echo capstoneDll
    echo payloadDll

    # Start the target process in a suspended state.
    let target = startProcess(into)
    suspend(target)

    let targetHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        DWORD(target.processId)
    )

    resume(target)

    discard remoteLoadLib(targetHandle, capstoneDll)
    let payloadBase = remoteLoadLib(targetHandle, payloadDll)

    echo &"payload base address is {toHex(payloadBase)}"

    let localDelta = getLibFuncOffset(payloadDll, "mainThread")
    echo &"local delta: {toHex(localDelta)}"

    let remoteFunc = payloadBase + localDelta

    echo &"target function: {toHex(remoteFunc)}"

    discard readLine(stdin)

    CreateRemoteThread(
        targetHandle,
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](cast[uint](remoteFunc)),
        NULL,
        0,
        NULL
    )

    echo &"spawned mainThread in process {target.processId} with execution at {toHex(cast[int](mainThread))}"

    # Allocate and copy dllPath into the target process.
    # let remoteDllPath = VirtualAllocEx(
    #     targetHandle, 
    #     NULL, 
    #     cast[SIZE_T](len(dllPath)),
    #     MEM_COMMIT, 
    #     PAGE_EXECUTE_READ_WRITE
    # )

    # echo toHex(cast[uint](remoteDllPath))
    # echo toHex(cast[uint](LoadLibraryA))

    # WriteProcessMemory(
    #     targetHandle, 
    #     remoteDllPath, 
    #     cstring(dllPath), 
    #     cast[SIZE_T](len(dllPath)), 
    #     NULL
    # )

    # # Spawn a thread to execute LoadLibraryW with the dll
    # let loadThread = CreateRemoteThread(
    #     targetHandle,
    #     NULL,
    #     0,
    #     cast[LPTHREAD_START_ROUTINE](cast[uint](LoadLibraryA)),
    #     remoteDllPath,
    #     0,
    #     NULL
    # )

   #  if loadThread != HANDLE(0):
   #      CloseHandle(loadThread)


