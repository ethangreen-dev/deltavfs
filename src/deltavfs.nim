import hook
import deltavfs/injector

import winim/core

proc hookMessageBox(hWnd: HWND, lpText: LPCTSTR, lpCaption: LPCSTR, uType: UINT): int = 
    AllocConsole()
    echo "I GOCHYA BITCH"

    return 1

proc main() =
    let original = makeHook(MessageBox, hookMessageBox)
    discard readLine(stdin)

    MessageBox(0, "Hello", "HA", 0)

    discard original(0, "Hello world!", "Donkie Kang", 0)

    # let test = original[](0, "Hello world!", "Donkers", 0)
    # MessageBox(0, "Hello world!", "Donkers", 0)

    # injectDll("notepad.exe", "bin/payload.dll")

    discard readLine(stdin)

when isMainModule:
    main()