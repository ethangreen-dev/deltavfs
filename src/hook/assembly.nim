import bitops
import sequtils

import distorm3

const JmpSize64 = 14
const JmpSize32 = 0

const JmpSize* = JmpSize64

proc makeJmp*(destAddr: ptr byte): seq[byte] =
  # In x86_64 ASM you cannot jump to an absolute QWORD address (8 bytes). In order to work around this limitation
  # without trashing registers, the QWORD destAddr will be split into high and low DWORD values.
  let highAddr = cast[uint](destAddr) shr (sizeOf(uint32) * 8)
  let lowAddr = cast[uint](destAddr) and high(uint32)

  # Convert the uint-sized high and low values to byte arrays of length 4.
  let highBytes = cast[array[0..3, byte]](highAddr)
  let lowBytes = cast[array[0..3, byte]](lowAddr)

  # The shellcode will push lowAddr onto the stack, decrement the stack pointer by 4, and then push highAddr. 
  # This is the address to be jumped to with RET.
  var shellcode = @[
    byte 0x68,        # push lowBytes
    0xC7, 0x44, 0x24, 0x04,   # mov qword ptr [rsp + 0x4], highBytes
    0xC3            # ret
  ]

  # Write the high and low bytes into the shellcode buffer.
  insert(shellcode, highBytes, 5)
  insert(shellcode, lowBytes, 1)

  shellcode

proc decodeBuffer*(buffer: var openArray[byte]): seq[DecodedInst] = 
  var instructionCount: uint32 = 0
  var decodedInstructions: array[20, DecodedInst]

  let disasm = distorm_decode(
    codeOffset = 0x0,
    code = addr(buffer[0]),
    codeLen = int32(len(buffer)),
    dt = Decode64Bits,
    maxInstructions = 15,
    res = addr(decodedInstructions[0]),
    usedInstructionsCount = addr(instructionCount)
  )

  assert disasm == DECRES_SUCCESS

  for instr in decodedInstructions:
    if $instr.mnemonic == "":
      continue

    add(result, instr)

proc toBoundedSize*(targetAddr: ptr byte, payloadSize: int): int = 
  var instructionCount: uint32 = 0
  var decodedInstructions: array[20, DecodedInst]

  let disasm = distorm_decode(
    codeOffset = 0x0,
    code = targetAddr,
    codeLen = int32(payloadSize),
    dt = Decode64Bits,
    maxInstructions = 15,
    res = addr(decodedInstructions[0]),
    usedInstructionsCount = addr(instructionCount)
  )

  assert disasm == DECRES_SUCCESS

  for instr in decodedInstructions:
    result += int(instr.size)
    # echo instr.mnemonic, " ", instr.operands

    if result >= payloadSize:
      break