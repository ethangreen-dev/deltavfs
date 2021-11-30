import hook
import hook/trampoline

import winim/lean

proc hookMessageBoxA(hWnd: HWND, lpText: LPCTSTR, lpCaption: LPCSTR, uType: UINT): int = 
    # return MessageBoxW(0, "HOOKED YA BINKO", ":)", 0)

    return getTrampoline(hookMessageBoxA)[](0, "HOOKED!", "THOU HATH BEEN HOOKED", 0)

proc mainThread*() {.stdcall, exportc: "mainThread", dynlib.} =
    AllocConsole()
    discard stdout.reopen("CONOUT$", fmWrite)
    discard stderr.reopen("CONOUT$", fmWrite)

    echo "Hello world!"

    # Install hook into MessageBox.
    discard makeHook(MessageBoxA, hookMessageBoxA)
    # MessageBoxA(0, "Hello world!", "From nim :)", 0)
    # echo "Hello world!"

proc testFunction*() {.exportc: "test_function", dynlib.} =
    echo "Calling MessageBoxA"

    discard MessageBoxA(0, "Hello!", "World!", 0)

# proc NimMain() {.cdecl, importc.}

# proc DllMain*(hModule: HINSTANCE, reasonForCall: DWORD, lpReserved: LPVOID): WINBOOL {.exportc, dynlib, stdcall.} =
#     if reasonForCall == DLL_PROCESS_ATTACH:
#         # DisableThreadLibraryCalls(GetModuleHandle("payload.dll"))
#         AllocConsole()
#         discard stdout.reopen("CONOUT$", fmWrite)
# 
#         echo "Hello world!"
#         # NimMain()
#         # CreateThread(NULL, SIZE_T(0), cast[LPTHREAD_START_ROUTINE](mainThread), cast[LPVOID](hModule), 0, NULL)
# 
#     return TRUE