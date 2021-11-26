# Experimental PE injector.
# Compile with: nim c --gc:arc --passL:-Wl,--dynamicbase .\src\test.nim && .\src\test.exe

import system
import osproc
import bitops
import strutils
import strformat

import ptr_math
import winim/lean

proc NimMain() {.cdecl, importc.}

proc remoteMain() {.stdcall, exportc.} = 
    # NimMain()

    while true:
        echo 5

proc main() =
    # Create and immediately suspend the target.
    let target = startProcess("notepad.exe")
    suspend(target)

    let test5 = readLine(stdin)
    echo test5

    # Get the base address of the current process.
    let localBase = cast[ptr byte](GetModuleHandle(NULL))

    # Get dosHeader and ntHeader.
    let dosHeader = cast[ptr IMAGE_DOS_HEADER](localBase)
    let ntHeader = cast[ptr IMAGE_NT_HEADERS](localBase + int(dosHeader.e_lfanew))

    # Get the size of the current process' image.
    let imageSize = int(ntHeader.OptionalHeader.SizeOfImage)

    # Allocate space in current process for copy of self.
    let localImage = create(byte, imageSize)
    copyMem(localImage, localBase, imageSize)

    # Open target process with RWX priv.
    let targetProcess = OpenProcess(
        MAXIMUM_ALLOWED,
        false,
        DWORD(target.processId)
    )

    # Allocate space in the target process for the local image.
    let destImage = cast[ptr byte](VirtualAllocEx(
        targetProcess,
        NULL,
        imageSize,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    ))

    echo &"local image: {toHex(cast[uint](localImage))}"
    echo &"remot image: {toHex(cast[uint](destImage))}"

    # Determine the delta memory address between the local and destination image.
    let delta = cast[int](destImage) - cast[int](localBase)
    echo delta

    # Get the VirtualAddress of the current process' relocation table.
    let relocVirtualAddr = cast[ptr byte](ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
    var relocTable = cast[ptr IMAGE_BASE_RELOCATION](relocVirtualAddr + cast[int](localBase))

    echo "relocVirtualAddr: ", toHex(cast[uint](relocVirtualAddr))
    echo "relocTableAddr  : ", toHex(cast[uint](relocTable))

    while relocTable.SizeOfBlock > 0:
        let entryCount = int((relocTable.SizeOfBlock - sizeOf(IMAGE_BASE_RELOCATION)) / sizeOf(WORD))
        let relocRva = cast[ptr UncheckedArray[int16]](relocTable + 1)

        for i in 0..entryCount:
            # echo toBin(relocRva[i], 16)
            # echo toBin(bitsliced(relocRva[i], 11..15), 16)

            # let typeOf = uint8(bitsliced(relocRva[i], 0..3))
            # let offset = uint16(bitsliced(relocRva[i], 4..15))

            let typeOf = uint16(bitand(0xF000, relocRva[i]))
            let offset = uint16(bitand(0x0FFF, relocRva[i]))

            # echo &"all   : {toHex(relocRva[i])}"
            # echo &"type  : {toHex(typeOf)}"
            # echo &"offset: {toHex(offset)}"

            # Ignore entries with 0 offset.
            if offset == 0:
                echo &"skipping offset: {toHex(offset)}, type: {toHex(typeOf)}"
                continue

            let relocRvaOffset = cast[uint](relocTable.VirtualAddress) + cast[uint](localImage)

            echo toHex(relocTable.VirtualAddress)
            echo toHex(relocRvaOffset)

            # let newRvaAddr = cast[ptr uint](cast[uint](localImage) + cast[uint](relocVirtualAddr) + uint(offset))
            let newRvaAddr = cast[ptr uint](relocRvaOffset + offset)
            # echo &"test: {toHex(cast[uint](newRvaAddr[]))}"

            let newVal = cast[uint](cast[ptr byte](newRvaAddr[]) + delta)

            echo &"RVA at {toHex(cast[uint](newRvaAddr))}, orig: {toHex(cast[uint](newRvaAddr[]))}    ->    {toHex(cast[uint](newVal))}    |    offset: {toHex(offset)}, type: {toHex(typeOf)}"

            # discard readLine(stdin)

            newRvaAddr[]  = newVal
            # echo &"new rva: {toHex(cast[uint](newRvaAddr[]))}"

        relocTable = cast[ptr IMAGE_BASE_RELOCATION](cast[int](relocTable) + cast[int](relocTable.SizeOfBlock))

    echo "Patch complete."

    # Write the patched localImage into the target process.
    WriteProcessMemory(
        targetProcess,
        destImage,
        localImage,
        imageSize,
        NULL
    )

    let test = cast[uint](cast[int](remoteMain) + delta)
    echo &"{cast[uint](remoteMain)} + {delta} = {test}"

    echo toHex(cast[uint](remoteMain))
    let entryPoint = cast[LPTHREAD_START_ROUTINE](cast[int](remoteMain) + delta)
    echo toHex(cast[uint](entryPoint))

    # Spawn a thread with at entryPoint on the target process.
    CreateRemoteThread(
        targetProcess,
        NULL,
        0,
        entryPoint,
        NULL,
        0,
        NULL
    )

    # resume(target)

    let test2 = readLine(stdin)
    echo test2

when isMainModule:
    main()