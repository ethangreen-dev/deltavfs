##  Capstone Disassembly Engine
##  By Axel Souchet & Nguyen Anh Quynh, 2014

## !!!Ignored construct:  # CAPSTONE_PLATFORM_H [NewLine] # CAPSTONE_PLATFORM_H [NewLine]  handle C99 issue (for pre-2013 VisualStudio) # ! defined ( __CYGWIN__ ) && ! defined ( __MINGW32__ ) && ! defined ( __MINGW64__ ) && ( defined ( WIN32 ) || defined ( WIN64 ) || defined ( _WIN32 ) || defined ( _WIN64 ) ) [NewLine]  MSVC  stdbool.h # ( _MSC_VER < 1800 ) || defined ( _KERNEL_MODE ) [NewLine]  this system does not have stdbool.h # __cplusplus [NewLine] typedef unsigned char bool ;
## Error: identifier expected, but got: ;!!!

const
  false* = 0
  true* = 1

##  VisualStudio 2013+ -> C99 is supported

##  not MSVC -> C99 is supported

##  handle C99 issue (for pre-2013 VisualStudio)

## !!!Ignored construct:  # defined ( CAPSTONE_HAS_OSXKERNEL ) || ( defined ( _MSC_VER ) && ( _MSC_VER <= 1700 || defined ( _KERNEL_MODE ) ) ) [NewLine]  this system does not have inttypes.h # defined ( _MSC_VER ) && ( _MSC_VER < 1600 || defined ( _KERNEL_MODE ) ) [NewLine]  this system does not have stdint.h typedef signed char int8_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef signed short int16_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef signed int int32_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef unsigned char uint8_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef unsigned short uint16_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef unsigned int uint32_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef signed long long int64_t ;
## Error: identifier expected, but got: ;!!!

## !!!Ignored construct:  typedef unsigned long long uint64_t ;
## Error: identifier expected, but got: ;!!!

type int64_t* = int64
type int32_t* = int32
type int16_t* = int16
type int8_t* = int8

type uint64_t* = uint64
type uint32_t* = uint32
type uint16_t* = uint16
type uint8_t* = uint8

const
  INT8_MIN* = low(int8)
  INT16_MIN* = low(int16)
  INT32_MIN* = low(int32)
  INT64_MIN* = low(int64)
  INT8_MAX* = high(int8)
  INT16_MAX* = high(int16)
  INT32_MAX* = high(int32)
  INT64_MAX* = high(int64)
  UINT8_MAX* = high(uint8)
  UINT16_MAX* = high(uint16)
  UINT32_MAX* = high(uint32)
  UINT64_MAX* = high(uint64)

const
  PRI_8_LENGTH_MODIFIER* = "hh"
  PRI_64_LENGTH_MODIFIER* = "ll"
  PRId8* = PRI_8_LENGTH_MODIFIER

## !!!Ignored construct:  d [NewLine] # PRIi8 __PRI_8_LENGTH_MODIFIER__ i [NewLine] # PRIo8 __PRI_8_LENGTH_MODIFIER__ o [NewLine] # PRIu8 __PRI_8_LENGTH_MODIFIER__ u [NewLine] # PRIx8 __PRI_8_LENGTH_MODIFIER__ x [NewLine] # PRIX8 __PRI_8_LENGTH_MODIFIER__ X [NewLine] # PRId16 hd [NewLine] # PRIi16 hi [NewLine] # PRIo16 ho [NewLine] # PRIu16 hu [NewLine] # PRIx16 hx [NewLine] # PRIX16 hX [NewLine] # defined ( _MSC_VER ) && _MSC_VER <= 1700 [NewLine] # PRId32 ld [NewLine] # PRIi32 li [NewLine] # PRIo32 lo [NewLine] # PRIu32 lu [NewLine] # PRIx32 lx [NewLine] # PRIX32 lX [NewLine] #  OSX # PRId32 d [NewLine] # PRIi32 i [NewLine] # PRIo32 o [NewLine] # PRIu32 u [NewLine] # PRIx32 x [NewLine] # PRIX32 X [NewLine] # [NewLine] # defined ( _MSC_VER ) && _MSC_VER <= 1700 [NewLine]  redefine functions from inttypes.h used in cstool # strtoull _strtoui64 [NewLine] # [NewLine] # PRId64 __PRI_64_LENGTH_MODIFIER__ d [NewLine] # PRIi64 __PRI_64_LENGTH_MODIFIER__ i [NewLine] # PRIo64 __PRI_64_LENGTH_MODIFIER__ o [NewLine] # PRIu64 __PRI_64_LENGTH_MODIFIER__ u [NewLine] # PRIx64 __PRI_64_LENGTH_MODIFIER__ x [NewLine] # PRIX64 __PRI_64_LENGTH_MODIFIER__ X [NewLine] # [NewLine]  this system has inttypes.h by default # < inttypes . h > [NewLine] # [NewLine] # [NewLine]
## Error: expected ';'!!!
