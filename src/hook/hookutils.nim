import strutils
import strformat

import ptr_math

proc toHex*(value: openArray[byte]): string=
    var outStr: seq[string] = @[]

    for i in value:
        add(outStr, &"0x{toHex(i)}")

    join(outStr, ", ")

proc iterCopyMem*(target: ptr byte, buffer: openArray[byte]) =
    for offset in 0..high(buffer):
        target[offset] = buffer[offset]
        
proc toByteSeq*(value: int): seq[byte] = 
    @cast[array[8, byte]](value)


