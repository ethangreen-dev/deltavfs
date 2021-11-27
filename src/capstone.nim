import os

import capstone/x86
import nimterop/[build, cimport]

static:
    let currentDir = currentSourcePath().splitPath().head

    let capstoneDir = currentDir / "/capstone/private/"
    let cmakeDefs = @[
        "CAPSTONE_ARCHITECTURE_DEFAULT=OFF",
        "CAPSTONE_X86_SUPPORT=1",
        "CAPSTONE_BUILD_STATIC=1"
    ]
    let cmakeFlags = flagBuild("-D$#", cmakeDefs) & " .."
    let configTarget = "Release"

    cmake(
        capstoneDir / "build", 
        "capstone.sln", 
        cmakeFlags
    )

    cmake(
        capstoneDir / "build", 
        configTarget / "capstone.dll", 
        "--build . --config " & configTarget
    )

    cpFile(capstoneDir / "build" / configTarget / "capstone.dll", currentDir / "../bin/capstone.dll")

const
    CsMnemonicSize = 32

type
    Csh* = csize_t

    CsArch* {.size: sizeof(int16).} = enum
        ArchArm,
        ArchArm64,
        ArchMips,
        ArchX86,
        ArchPPC,
        ArchSparc,
        ArchSysZ,
        ArchXCore,
        ArchM68K,
        ArchTMS320C64x,
        ArchM680X,
        ArchEVM,
        ArchMOS65XX,
        ArchWasm,
        ArchBPF,
        ArchRISCV,
        ArchMax,
        ArchAll = 0xFFFF

    CsMode* {.size: sizeof(int32).} = enum
        ModeLittleEndian = 0,
        # ModeArm = 0,
        Mode16 = 1 shl 1,
        Mode32 = 1 shl 2,
        Mode64 = 1 shl 3,
        ModeBigEndian = 1 shl 31

    CsOptType* = enum
        OptInvalid,
        OptSyntax,
        OptDetail,
        OptMode,
        OptMem,
        OptSkipData,
        OptSkipDataSetup,
        OptMnemonic,
        OptUnsigned

type CsOptValue* = int
const
    OptOff*              = CsOptValue(0)
    OptOn*               = CsOptValue(3)
    OptSyntaxDefault*    = CsOptValue(0)
    OptSyntaxIntel*      = CsOptValue(1)
    OptSyntaxATT*        = CsOptValue(2)
    OptSyntaxNoRegName*  = CsOptValue(3)
    OptSyntaxMASM*       = CsOptValue(4)
    OptSyntaxMotorola*   = CsOptValue(5)

type CsOpType* = int
const
    OpInvalid*           = CsOpType(0)
    OpRegister*          = CsOpType(1)
    OpImmediate*         = CsOpType(2)
    OpMemory*            = CsOpType(3)
    OpFloatingPoint*     = CsOpType(4)
 
type CsAcType* = int
const
    AcInvalid*           = CsAcType(0)
    AcRead*              = CsAcType(1 shl 0)
    AcWrite*             = CsAcType(1 shl 1)

type CsGroupType* = int
const
    GroupInvalid*        = CsGroupType(0)
    GroupJump*           = CsGroupType(1)
    GroupCall*           = CsGroupType(2)
    GroupRet*            = CsGroupType(3)
    GroupInt*            = CsGroupType(4)
    GroupIRet*           = CsGroupType(5)
    GroupPrivilege*      = CsGroupType(6)
    GroupBranchRelative* = CsGroupType(7)

type CsErr* = int
const
    ErrOk*               = CsErr(0)
    ErrMem*              = CsErr(1)
    ErrArch*             = CsErr(2)
    ErrHandle*           = CsErr(3)
    ErrCsh*              = CsErr(4)
    ErrMode*             = CsErr(5)
    ErrOption*           = CsErr(6)
    ErrDetail*           = CsErr(7)
    ErrMemSetup*         = CsErr(8)
    ErrVersion*          = CsErr(9)
    ErrDiet*             = CsErr(10)
    ErrSkipData*         = CsErr(11)
    ErrX86Att*           = CsErr(12)
    ErrX86Intel*         = CsErr(13)
    ErrX86Masm*          = CsErr(14)

type CsDetailArchInfo* {.union.} = object
    x86: cs_x86

type CsDetail* = object
    regsRead: array[16, uint16]
    regsReadCount: uint8

    regsWrite: array[20, uint16]
    regsWriteCount: uint8

    groups: array[8, uint8]
    groupsCount: uint8

    x86: cs_x86

type CsInsn* = object
    id*: uint

    address*: uint64
    size*: uint16

    bytes*: array[24, byte]
    mnemonic*: array[CsMnemonicSize, char]
    opStr*: array[160, char]

    detail*: ptr CsDetail

type CsRegs = array[64, uint16]

proc csVersion*(major: ptr int, minor: ptr int): uint                 {.importc: "cs_version", dynlib: "capstone.dll".}
proc csSupport*(query: int): bool                                     {.importc: "cs_support", dynlib: "capstone.dll".}

proc csOpen*(arch: CsArch, mode: CsMode, handle: ptr Csh): CsErr      {.importc: "cs_open", dynlib: "capstone.dll".}
proc csClose*(handle: ptr Csh)                                        {.importc: "cs_close", dynlib: "capstone.dll".}
proc csOption*(handle: Csh, optType: CsOptType, value: CsOptValue)    {.importc: "cs_option", dynlib: "capstone.dll".}

proc csErrNo*(handle: Csh): CsErr                                     {.importc: "cs_errno", dynlib: "capstone.dll".}
proc csStrErr*(code: CsErr): cstring                                  {.importc: "cs_strerror", dynlib: "capstone.dll".}

proc csDisasm*(
    handle: Csh, 
    code: ptr byte, 
    codeSize: uint,
    address: uint64,
    count: uint,
    insn: ptr ptr CsInsn
): csize_t                                                            {.importc: "cs_disasm", dynlib: "capstone.dll".}

proc csFree*(insn: ptr CsInsn, count: csize_t)                        {.importc: "cs_free", dynlib: "capstone.dll".}
proc csMalloc*(handle: Csh): ptr CsInsn                               {.importc: "cs_malloc", dynlib: "capstone.dll".}

proc csDisasmIter*(
    handle: Csh, 
    code: ptr ptr byte, 
    codeSize: ptr csize_t,
    address: ptr uint64,
    insn: ptr CsInsn
): bool                                                               {.importc: "cs_disasm_iter", dynlib: "capstone.dll".}

proc csRegName*(handle: Csh, regId: uint): cstring                    {.importc: "cs_reg_name", dynlib: "capstone.dll".}
proc csInsnName*(handle: Csh, insnId: uint): cstring                  {.importc: "cs_insn_name", dynlib: "capstone.dll".}
proc csGroupName*(handle: Csh, groupId: uint): cstring                {.importc: "cs_group_name", dynlib: "capstone.dll".}
proc csInsnGroup*(handle: Csh, insn: ptr CsInsn, groupId: uint): bool {.importc: "cs_insn_group", dynlib: "capstone.dll".}

proc csRegRead*(handle: Csh, insn: ptr CsInsn, regId: uint): bool     {.importc: "cs_reg_read", dynlib: "capstone.dll".}
proc csRegWrite*(handle: Csh, insn: ptr CsInsn, regId: uint): bool    {.importc: "cs_reg_write", dynlib: "capstone.dll".}

proc csOpCount*(handle: Csh, insn: ptr CsInsn, opType: uint): bool    {.importc: "cs_op_count", dynlib: "capstone.dll".}
proc csOpIndex*(
    handle: Csh,
    insn: ptr CsInsn,
    opType: uint,
    position: uint
): int                                                                {.importc: "cs_op_index", dynlib: "capstone.dll".}

proc csRegsAccess*(
    handle: Csh,
    insn: ptr CsInsn,
    regsRead: CsRegs,
    regsReadCount: ptr uint8,
    regsWrite: CsRegs,
    regsWriteCount: ptr uint8
): CsErr                                                              {.importc: "cs_regs_access", dynlib: "capstone.dll".}

proc csDisasm*(
    handle: Csh, 
    code: ptr byte, 
    codeSize: uint,
    address: uint64,
    count: uint,
    insn: ptr openArray[CsInsn]
): csize_t = 

    csDisasm(handle, code, codeSize, address, count, cast[ptr ptr CsInsn](addr(insn[0])))
