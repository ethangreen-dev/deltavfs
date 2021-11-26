import strutils
import strformat

import hook/assembly
import hook/hookutils
import hook/trampoline

import ptr_math
import winim/core
import stew/arrayops

proc makeHook*[T: proc, U: proc](target: T, destination: U): T =
    var targetAddr = cast[ptr byte](target)
    var destAddr = cast[ptr byte](destination)

    echo toHex(targetAddr[])

    echo &"target:      {repr(pointer targetAddr)}"
    echo &"destination: {repr(pointer destAddr)}"

    # Create shellcode which jumps into the destination and trampoline.
    let destJmp = makeJmp(destAddr)

    # Determine the number of bytes to steal from the target.
    let instrSize = toBoundedSize(targetAddr, len(destJmp))
    echo &"{instrSize} bytes will be removed."

    # Create the trampoline shellcode -- this will return execution from the cave back to the target.
    let jumpBack = makeJmp(targetAddr + instrSize)
    let caveSize = instrSize + len(jumpBack)

    echo &"JMP to dest: ", toHex(destJmp)
    echo &"JMP to trgt: ", toHex(jumpBack)

    # Search for a code cave in memory to fit the stolen instructions.
    var trampolineAddr = findCave(targetAddr, caveSize)
    echo "found cave at ", repr(trampolineAddr)

    # Enable READ/WRITE access to the code cave.
    var old: DWORD
    VirtualProtect(cast[LPVOID](trampolineAddr), caveSize, PAGE_EXECUTE_READWRITE, addr(old))

    # Steal bytes at target and place into temporary buffer.
    var stolenBytes = newSeq[byte](instrSize)
    copyMem(addr(stolenBytes[0]), target, instrSize)

    # Copy bytes from the start of the target function into the trampoline, in addition to the shellcode which jumps back to the target.
    # iterCopyMem(trampolineAddr, targetAddr, instrSize)
    iterCopyMem(trampolineAddr, stolenBytes & jumpBack)

    # iterCopyMem(trampolineAddr, toOpenArray(cast[ptr UncheckedArray[byte]](targetAddr), 0, instrSize))
    # iterCopyMem(trampolineAddr + instrSize + 1, jumpBack)

    # Enable write access to the target's memory region.
    VirtualProtect(targetAddr, instrSize, PAGE_EXECUTE_READWRITE, addr(old))

    # Create the shellcode to jump execution from the target to the destination.
    var jumpInto = makeJmp(destAddr)

    # Write shellcode to the target function.
    iterCopyMem(targetAddr, jumpInto)

    cast[T](trampolineAddr)
