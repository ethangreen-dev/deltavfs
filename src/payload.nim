import os
import strformat

import hook
import hook/trampoline

import winim/lean
import winim/winstr

const binDir = currentSourcePath().splitPath().head / "../bin"

proc hookMessageBoxA(hWnd: HWND, lpText: LPCTSTR, lpCaption: LPCSTR, uType: UINT): int = 
  return getTrampoline(hookMessageBoxA)[](0, "HOOKED!", "HOOKED!", 0)

proc hookCreateFileW(
  lpFileName: LPCWSTR,
  dwDesiredAccess: DWORD,
  dwShareMode: DWORD,
  lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
  dwCreationDisposition: DWORD,
  dwFlagsAndAttributes: DWORD,
  hTemplateFile: HANDLE 
  ): HANDLE = 

  let newPath = absolutePath(binDir / "test.txt")

  echo &"[H] CreateFileW with lpFileName: '{$lpFileName}'"
  echo &"  - Set lpFileName -> '{newPath}'"

  getTrampoline(hookCreateFileW)[](
    +$newPath,
    dwDesiredAccess,
    dwShareMode,
    lpSecurityAttributes,
    dwCreationDisposition,
    dwFlagsAndAttributes,
    hTemplateFile
  )

proc mainThread*() {.stdcall, exportc: "mainThread", dynlib.} =
  AllocConsole()
  discard stdout.reopen("CONOUT$", fmWrite)
  discard stderr.reopen("CONOUT$", fmWrite)

  echo &"[::] deltaVFS mainThread start."

  # Install hook into MessageBox.

  echo &"[::] Installing hookMessageBoxA"
  discard makeHook(MessageBoxA, hookMessageBoxA)

  echo &"[::] Installing hookCreateFileW"
  discard makeHook(CreateFileW, hookCreateFileW)

  echo &"[::] Initialization complete."

proc testFunction*() {.exportc: "test_function", dynlib.} =
  echo "Calling MessageBoxA"

  discard MessageBoxA(0, "Hello!", "World!", 0)