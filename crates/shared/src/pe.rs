use std::path::Path;
use std::ffi::c_void;

use anyhow::anyhow;
use anyhow::Result;

use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::LibraryLoader::GetProcAddress;

pub fn get_func_addr(module: &str, func: &str) -> Result<*const c_void> {
    // If the module is not a path and is instead a win32 name, skip loading.
    if !Path::new(module).exists() {
        println!("Temp code");
    }

    // Get a HANDLE for the module.
    let module_handle = match unsafe {
            GetModuleHandleA(module)
        } {
        HINSTANCE(0) => return Err(anyhow!("Failed to get HANDLE for module '{}'.", module)),
        x => x
    };

    // Get the address of the function from within the module.
    match unsafe {
            GetProcAddress(module_handle, func)
        } {
        Some(x) => Ok(x as *const () as _),
        None => Err(anyhow!("Failed to get address of func '{}' in module '{}'.", func, module)),
    }
}