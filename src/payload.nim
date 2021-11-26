import threadpool

import hook
import winim/lean

proc hookMessageBoxA(hWnd: HWND, lpText: LPCTSTR, lpCaption: LPCSTR, uType: UINT): int = 
    return MessageBoxW(0, "HOOKED YA BINKO", ":)", 0)

proc init() =
    # Install hook into MessageBox.
    discard makeHook(MessageBoxA, hookMessageBoxA)
    MessageBoxA(0, "Hello world!", "From nim :)", 0)

proc main() = 
    spawn(init())

when isMainModule:
    main()