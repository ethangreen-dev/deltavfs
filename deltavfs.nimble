# Package

version       = "0.1.0"
author        = "metherul"
description   = "A new awesome nimble package"
license       = "MIT"
binDir        = "bin"
srcDir        = "src"
bin           = @["deltavfs"]


# Dependencies

requires "nim >= 1.6.0"

requires "stew"
requires "winim"
requires "ptr_math"
requires "distorm3"

requires "nimterop"

# Build hook subpackage.
after build:
    # exec("nim c --app:lib -d:debug --lineDir:on --debuginfo --debugger:native --embedsrc:on --noMain --gc:arc --outdir:bin/ ./src/payloaood.nim")
    exec("nim c --app:lib --outdir:bin/ src/payload.nim")