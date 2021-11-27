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

# proc iterCopyMem*(target: ptr byte, buffer: ptr byte, number: int) =
#     var temp: seq[byte] = @[]
# 
#     for offset in 0..number:
#         add(temp, buffer[offset])
# 
#         discard readLine(stdin)
# 
#         echo toHex(cast[uint](target + offset)), " set to ", toHex((buffer + offset)[])
#         (target + offset)[] = (buffer + offset)[]
# 
#     echo toHex(temp)

