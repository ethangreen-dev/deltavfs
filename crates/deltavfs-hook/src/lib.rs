mod hook;
mod mem_utils;
mod asm_analysis;

use windows::Win32::{System::Console::AllocConsole, Foundation::BOOL};

#[no_mangle]
unsafe extern "stdcall" fn hook_init() {
    match AllocConsole() {
        BOOL(1) => println!("Allocated console."),
        _ => println!("Something broke.")
    }

    println!("Hello from the DLL!");

    hook::install_hook(0x00007FFAE8EC1F10 as usize as _, test as _).unwrap();
}

fn test() -> u32 {
    println!("[!] Hooked CreateFileW.");

    0
}
