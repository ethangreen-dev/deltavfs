import deltavfs/injector

proc main() =
    injectDll("notepad.exe")

when isMainModule:
    main()