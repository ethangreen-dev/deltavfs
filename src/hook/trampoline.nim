import strutils
import strformat
import typetraits

import assembly
import hookutils

import distorm3
import ptr_math

from winim/core import
    VirtualAlloc,
    GetModuleHandle,
    NULL,
    MEM_COMMIT,
    IMAGE_DOS_HEADER,
    IMAGE_NT_HEADERS,
    IMAGE_SECTION_HEADER,
    PAGE_EXECUTE_READWRITE

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

proc updateOffsets*(buffer: var openArray[byte], origOffset: int, newOffset: int) = 
    echo toHex(buffer)

    let decoded = decodeBuffer(buffer)
    # for instr in decoded:
    #     echo $instr

    echo "OPJADPOKW"

    var
        decodedInstructionsCount = 0'u32
        decodedInsts: array[100, DInst]

        ci = CodeInfo(
            codeOffset: uint(0x1),
            code: addr(buffer),
            codeLen: int(decoded[0].size),
            dt: Decode64Bits,
            features: DF_RETURN_FC_ONLY
        )

    let res = distorm_decompose(addr ci, addr decodedInsts[0], uint32(len(decodedInsts)), addr decodedInstructionsCount)

    echo res
    assert res == DECRES_SUCCESS

    for i in 0..<decodedInstructionsCount:
        if (decodedInsts[i].flags and 0xFFFF) == 0x0000:
           continue

        var test: DecodedInst

        distorm_format(addr ci, addr decodedInsts[i], addr test)

        # echo repr(decodedInsts[i])

        # echo toHex(decodedInsts[i].flags), " ", test.instructionHex, "\t", $test

        # echo &"{decodedInsts[i].opcode} {repr(decodedInsts[i].ops)}"

proc getTrampoline*[T: proc](target: T): ptr T =
    # The address of the trampoline function is stored after the jump shellcode at the target function.
    # Stored as an int64, grab the value and cast it back to T.

    cast[ptr type(T)](cast[uint](target) + JmpSize)