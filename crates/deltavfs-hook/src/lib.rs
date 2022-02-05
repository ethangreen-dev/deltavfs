mod asm_analysis;
mod hook;
mod mem_utils;

use widestring::{WideCString};
use windows::Win32::{
    Foundation::{BOOL, HANDLE, PWSTR},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ACCESS_FLAGS, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_SHARE_MODE,
    },
    System::Console::AllocConsole,
};

#[no_mangle]
unsafe extern "stdcall" fn hook_init() {
    match AllocConsole() {
        BOOL(1) => println!("Allocated console."),
        _ => println!("Something broke."),
    }

    println!("Hello from the DLL!");

    hook::install_hook(0x00007FFDE8AA1F10 as usize as _, test as _).unwrap();
}

unsafe fn test(
    file_name: PWSTR,
    desired_access: FILE_ACCESS_FLAGS,
    share_mode: FILE_SHARE_MODE,
    security_attributes: *const SECURITY_ATTRIBUTES,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    template_file: HANDLE,
) -> HANDLE {
    let thing = WideCString::from_ptr_str(file_name.0).to_string().unwrap();

    println!("{}", thing);

    // CreateFileW(
    //     file_name,
    //     desired_access,
    //     share_mode,
    //     security_attributes,
    //     creation_disposition,
    //     flags_and_attributes,
    //     template_file
    // )

    HANDLE(0)
}
