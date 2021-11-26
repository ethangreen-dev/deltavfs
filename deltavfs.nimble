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

# Build hook subpackage.
after build:
    exec("nim c --app:lib --noMain --outdir:bin/ ./src/payload.nim")