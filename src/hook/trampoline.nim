import strutils
import strformat
import typetraits

import assembly
import hookutils

import ../capstone
import ../capstone/x86

import distorm3
import ptr_math

import winim/core

proc closeAlloc(targetAddr: ptr byte, size: int): int =
    let newRegion = VirtualAlloc(
        cast[LPVOID](targetAddr - int(high(int32) / 2)),
        SIZE_T(size),
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )

    return cast[int](newRegion)

    # let startRegion = cast[int](targetAddr) + low(int32)
    # let endRegion = cast[int](targetAddr) + high(int32)

    # var memoryInfo = new(MEMORY_BASIC_INFORMATION)[]
    # var currentAddr = startRegion

    # var newRegion = LPCVOID(NULL)

    # while VirtualQuery(cast[LPCVOID](addr currentAddr), addr memoryInfo, sizeof(memoryInfo)) != 0:
    #     if currentAddr >= endRegion:
    #         assert 1 == 0

    #     if memoryInfo.State == MEM_FREE:
    #         let newRegion = VirtualAlloc(
    #             memoryInfo.BaseAddress,
    #             SIZE_T(size),
    #             MEM_COMMIT or MEM_RESERVE,
    #             PAGE_EXECUTE_READWRITE
    #         )

    #         if newRegion != NULL:
    #             break

    #     currentAddr += int(memoryInfo.RegionSize)

    # if newRegion == NULL:
    #     newRegion = VirtualAlloc(
    #         cast[LPVOID](targetAddr - int(high(int32))),
    #         SIZE_T(size),
    #         MEM_COMMIT or MEM_RESERVE,
    #         PAGE_EXECUTE_READWRITE
    #     )

    # cast[int](newRegion)

proc findCave*(targetAddr: ptr byte, caveSize: int, useCloseAlloc: bool = true): ptr byte = 
    if useCloseAlloc:
        let newRegion = closeAlloc(targetAddr, caveSize)

        echo &"[:] Allocated trampoline at {toHex(newRegion)}, {toHex(int32(cast[int](targetAddr) - newRegion))} bytes away from the target address."

        return cast[ptr byte](newRegion)

    echo &"[!] WARNING: Using experimental code-cave search algorithm..."

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

    # Determine the starting and stopping addresses for the search.
    # let start = if cast[int](targetAddr) - high(int32) < 0: 0 else: cast[int](targetAddr) - high(int32)
    # let stop = if cast[int](targetAddr) + high(int32) > int(textSize): int(textSize) else: cast[int](targetAddr) + high(int32)

    let offset = int(high(int16) * 2)

    let start = cast[int](targetAddr) - offset
    let stop = cast[int](targetAddr) + offset
 
    echo cast[int](targetAddr) - offset
    echo cast[int](targetAddr) + offset
    echo &"search region: {toHex(start)} to {toHex(stop)}"

    var consecutive = 0
    for i in start..stop:
        # echo toHex(i)

        # while true:
        #     discard "d"

        let currentVal = cast[ptr byte](i)[]

        # If not a null byte, reset the search.
        if currentVal != 0x00:
            consecutive = 0

        elif currentVal == 0x00:
            consecutive += 1

        if consecutive > caveSize:
            return cast[ptr byte](i - consecutive + 1)

    # var consecutive = 0
    # for i in 0..textSize: 
    #     let currentAddr = cast[int](textSection) + i
    #     if abs(cast[int](targetAddr) - currentAddr) >= high(int32):
    #         consecutive = 0
    #         continue
# 
    #     # If not a null byte, reset the search.
    #     if searchRegion[i] != 0x00:
    #         consecutive = 0
# 
    #     elif searchRegion[i] == 0x00:
    #         consecutive += 1
# 
    #     if consecutive > caveSize:
    #         return addr(searchRegion[i]) - consecutive + 1
# 
    # In the event no code caves can be found, allocate memory.
    let newRegion = closeAlloc(targetAddr, caveSize)
    # let newRegion = VirtualAlloc(NULL, caveSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)

    echo &"[:] Allocated trampoline memory at {toHex(newRegion)}"

    return cast[ptr byte](newRegion)

proc updateOffsets*(buffer: var openArray[byte], origOffset: int, newOffset: int) = 
    echo toHex(buffer)

    var handle: Csh

    var instrs: CsInsn = CsInsn()
    var instrsPtr = addr(instrs)

    assert csOpen(ArchX86, Mode64, addr handle) == ErrOk
    csOption(handle, OptDetail, OptOn)

    let instrCount =  csDisasm(handle, addr buffer[0], uint(len(buffer)), uint64(0), 15'u, cast[ptr ptr CsInsn](addr instrsPtr))
    assert instrCount != 0

    # Iterate through each disassembled instruction.
    for i in 0..<int(instrCount):
        var instr = (instrsPtr + i)[]

        # Iterate through each operand in the instruction.
        for j in 0..<8:
            let memBase = instr.detail.x86.operands[j].anoX86297.mem

            # If the base of the operand is not RIP, skip it.
            if memBase.base != X86_REG_RIP:
                continue

            # If the displacement is 0, skip.
            if memBase.disp == 0:
                continue

            echo repr(instr.detail.x86.encoding)
            echo repr(memBase.base), " ", toHex(memBase.disp)

        # Check if the current instruction is relative.
        if instr.detail.x86.disp == 0:
            continue

        # Find the in-address offset and size of the displacement.
        let dispOffset = int(instr.detail.x86.encoding.dispOffset + instr.address)
        let dispSize = instr.detail.x86.encoding.dispSize
        let disp = cast[ptr int32](addr(buffer[dispOffset]))[]

        echo &"instr has displacement {toHex(disp)}"

        let offsetDelta = int32(newOffset - origOffset) + int32(dispOffset)

        assert dispSize == uint8(sizeof(int32))

        echo toHex(newOffset)
        echo toHex(origOffset)
        echo toHex(offsetDelta)

        # echo toHex(buffer[int(dispOffset) .. int(dispOffset + dispSize - 1)])
        echo toHex(disp)
        echo toHex(instr.address), " ", cstring(addr(instr.mnemonic)), " ", cstring(addr(instr.opStr))

        var newDispl = int32((origOffset + disp) - newOffset)

        # var newOffset = offsetDelta + int32(instr.size)

        copyMem(addr buffer[int(dispOffset)], cast[ptr byte](addr newDispl), sizeof(int32))

        echo &"new displacement: {toHex(newDispl)}"

        echo ""

    return

    let decoded = decodeBuffer(buffer)

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

    # cast[ptr type(T)](cast[uint](target) + JmpSize)

    cast[ptr type(T)](cast[int](target - sizeof(int)))