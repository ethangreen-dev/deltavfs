import strutils
import strformat

import distorm3
import ptr_math
import winim/core

proc findCave*(targetAddr: ptr byte, caveSize: int): ptr byte = 
    # Search for the start and end of the .text section.
    let imageBase = cast[ptr byte](GetModuleHandle(NULL))
    let ntHeader = cast[ptr IMAGE_NT_HEADERS](imageBase + cast[ptr IMAGE_DOS_HEADER](imageBase).e_lfanew)

    var sectionHeader = cast[ptr IMAGE_SECTION_HEADER](ntHeader + 1)

    for i in 0..int(ntHeader.FileHeader.NumberOfSections):
        sectionHeader = cast[ptr IMAGE_SECTION_HEADER](sectionHeader + i)

        if cast[cstring](addr(sectionHeader.Name)) == ".text":
            break

    let textSection = imageBase + sectionHeader.VirtualAddress

    let sectionAlignment = ntHeader.OptionalHeader.SectionAlignment
    let textSize = ((sectionHeader.Misc.VirtualSize + sectionAlignment - 1) and not(sectionAlignment - 1)) - 1

    echo &"start: {toHex(cast[int](textSection))}  ->  {toHex(cast[int](textSection + textSize))} ({textSize} bytes)"

    # Search for consecutive null bytes within a given delta distance of the target.
    var searchRegion = cast[ptr UncheckedArray[byte]](textSection)

    var consecutive = 0
    for i in 0..textSize: 
        if searchRegion[i] != 0x00:
            consecutive = 0

        elif searchRegion[i] == 0x00:
            consecutive += 1

        if consecutive > caveSize:
            return addr(searchRegion[i]) - consecutive + 1

    # In the event no code caves can be found, allocate memory.
    let newRegion = VirtualAlloc(NULL, caveSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)

    echo &"manually allocated {caveSize} bytes at {toHex(cast[uint](newRegion))}"

    return cast[ptr byte](newRegion)

proc updateOffsets(buffer: var openArray[byte], origOffset: int, newOffset: int) = 
    var
        decodedInstructionsCount = 0'u32
        decodedInsts: array[10, DInst]

        ci = CodeInfo(
            codeOffset: 0x0,
            code: addr(buffer),
            codeLen: len(buffer),
            dt: Decode64Bits,
            features: DF_STOP_ON_RET
        )

    let res = distorm_decompose(addr ci, addr decodedInsts[0], uint32(len(decodedInsts)), addr decodedInstructionsCount)
    assert res == DECRES_SUCCESS

    for i in 0..<decodedInstructionsCount:
        echo repr(decodedInsts[i])