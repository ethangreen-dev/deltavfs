import strutils
import strformat

import hook/assembly
import hook/hookutils
import hook/trampoline

import ptr_math
import stew/arrayops

from winim/core import
    VirtualProtect,
    DWORD,
    LPVOID,
    PAGE_EXECUTE_READWRITE

proc makeHook*[T: proc, U: proc](target: T, destination: U): T =
    var targetAddr = cast[ptr byte](target)
    var destAddr = cast[ptr byte](destination)

    echo toHex(targetAddr[])

    echo &"target:      {repr(pointer targetAddr)}"
    echo &"destination: {repr(pointer destAddr)}"

    # Create shellcode which jumps to the destination. This will be written to the 
    # start of the target function.
    # let destJmp = makeJmp(destAddr)

    # Determine the number of bytes to steal from the target.
    let jmpToDestSize = toBoundedSize(targetAddr, JmpSize + sizeof(int))
    echo &"{jmpToDestSize} bytes will be removed."

    # Create the trampoline shellcode -- this will return execution from the cave back to the target.
    # let jumpBack = makeJmp(targetAddr + instrSize)

    # echo &"JMP to dest: ", toHex(destJmp)
    # echo &"JMP to trgt: ", toHex(jumpBack)

    # Search for a code cave in memory to fit the stolen instructions.
    let caveSize = jmpToDestSize + JmpSize
    let caveAddr = findCave(targetAddr, caveSize)

    echo "found cave at ", repr(caveAddr)

    # Steal bytes from the target function and place into temporary buffer.
    var stolenBytes = newSeq[byte](jmpToDestSize)
    copyMem(addr stolenBytes[0], target, jmpToDestSize)

    # Patch RIP-relative branch instructions to reflect new memory offset.
    updateOffsets(stolenBytes, cast[int](targetAddr), cast[int](caveAddr))

    # Enable READ/WRITE access to the code cave.
    var old: DWORD
    VirtualProtect(cast[LPVOID](caveAddr), caveSize, PAGE_EXECUTE_READWRITE, addr(old))

    # Copy bytes from the start of the target function into the trampoline, in addition to the shellcode which jumps back to the target.
    # iterCopyMem(caveAddr, targetAddr, instrSize)
    iterCopyMem(caveAddr, stolenBytes & makeJmp(targetAddr + jmpToDestSize))

    echo toHex(stolenBytes & makeJmp(targetAddr))

    # Enable write access to the target's memory region.
    VirtualProtect(targetAddr, jmpToDestSize, PAGE_EXECUTE_READWRITE, addr(old))

    # Write destination jmp and caveAddr to start of target function.
    iterCopyMem(targetAddr, makeJmp(destAddr) & toByteSeq(cast[int](caveAddr)))

    # Steal bytes at target and place into temporary buffer.
    # var stolenBytes = newSeq[byte](destJmpSize)
    # copyMem(addr(stolenBytes[0]), target, destJmpSize)

    # Update RIP-relative addressing in the trampoline.
    # updateOffsets(stolenBytes, cast[int](targetAddr), cast[int](caveAddr))

    # Create the shellcode to jump execution from the target to the destination. Append the address of the trampoline
    # so hook functions can execute original behavior without GC pressure.
    # var jumpInto = makeJmp(destAddr) & toByteSeq(cast[int](caveAddr))

    cast[T](caveAddr)
