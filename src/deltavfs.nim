import strutils
import typetraits

import hook
import hook/trampoline

import capstone

import deltavfs/injector

import ptr_math
import winim/core

proc hookMessageBox(hWnd: HWND, lpText: LPCTSTR, lpCaption: LPCSTR, uType: UINT): int = 
    echo "I GOCHYA BITCH"

    # Call the trampoline function.
    # let trampoline = getTrampoline(MessageBox)
    let trampoline = cast[ptr type(MessageBox)](cast[uint](MessageBox) + 14)

    echo toHex(cast[uint](trampoline))

    discard readLine(stdin)

    echo OptOn

    return trampoline[](0, "Hooked!", "Hooked by deltavfs", 0)

proc main() =
    let original = makeHook(MessageBox, hookMessageBox)
    discard readLine(stdin)

    MessageBox(0, "Hello", "HA", 0)

    # discard original(0, "Hello world!", "Donkie Kang", 0)

    MessageBox(0, "Hello", "HA", 0)

    # discard original(0, "Trying this again...", "Does this actually work?", 0)

    # let test = original[](0, "Hello world!", "Donkers", 0)
    # MessageBox(0, "Hello world!", "Donkers", 0)

    # injectDll("notepad.exe", "bin/payload.dll")

    discard readLine(stdin)

when isMainModule:
    main()