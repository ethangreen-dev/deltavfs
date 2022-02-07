use shared::pe;

use std::ffi::c_void;
use std::mem::size_of;
use std::{process::Command, ptr};
use std::os::windows::process::CommandExt;

use hex;
use log::*;
use anyhow::{anyhow, Result};

use windows::Win32::Foundation::{HANDLE, HINSTANCE, CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::{WriteProcessMemory, ReadProcessMemory};
use windows::Win32::System::LibraryLoader::{DONT_RESOLVE_DLL_REFERENCES, LoadLibraryExA, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_FREE, VirtualFree};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CreateRemoteThread, WaitForSingleObject};
use windows::Win32::System::{
    Threading::{OpenProcess, PROCESS_ALL_ACCESS}, 
    Memory::VirtualAllocEx
};

pub unsafe fn inject_into(exec_path: &str) -> Result<()> {
    info!("Preparing to inject payload into executable at '{}'", exec_path);

    // Spawn the process in a suspended state.
    let proc = Command::new(exec_path)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()?;

    let proc_handle = OpenProcess(
        PROCESS_ALL_ACCESS,
        false,
        proc.id()
    );

    let library = "C:\\Users\\green\\Dev\\rust\\deltavfs\\target\\debug\\deltavfs_hook.dll";
    let lib_base = remote_loadlib(proc_handle, library)?;

    // Determine the location of the mainThread function within the target.
    let local_delta = get_lib_offset(library, "hook_init\0")?;
    let entry_point = lib_base + local_delta;

    println!("Found remote entry point at: {:x?}", entry_point);

    // Create a thread at mainThread to begin hook installation.
    CreateRemoteThread(
        proc_handle,
        ptr::null_mut(),
        0,
        std::mem::transmute(entry_point),
        ptr::null_mut(),
        0,
        ptr::null_mut()
    );

    Ok(())
}

unsafe fn remote_loadlib(proc_handle: HANDLE, library: &str) -> Result<usize> {
    // Allocate space in the remote process to store the path of the library.
    let lib_path_ptr = VirtualAllocEx(
        proc_handle,
        ptr::null_mut(),
        library.len() + 1,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    println!("{:x?}", lib_path_ptr);

    println!("Remote allocated {} bytes for library path.", library.len() + 1);

    // Allocate space in the remote process to store the result of our LoadLibraryA call.
    let result_ptr = VirtualAllocEx(
        proc_handle,
        ptr::null_mut(),
        size_of::<HINSTANCE>(),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    println!("Remote allocated {} bytes for LoadLibraryA result.", size_of::<HINSTANCE>());

    // Write the path of the library to memory.
    WriteProcessMemory(
        proc_handle,
        lib_path_ptr,
        library.as_bytes().as_ptr() as _,
        library.len(),
        ptr::null_mut()
    );

    let loadlib_ptr = pe::get_func_addr("kernel32", "LoadLibraryA")?;

    // Create the payload string, embed relevant addresses, and convert to byte array.
    let payload_str = format!("      
        0x53
        0x48 0x89 0xE3
        0x48 0x83 0xEC 0x20
        0x48 0xB9 {}
        0x48 0xBA {}
        0xFF 0xD2
        0x48 0xBA {}
        0x48 0x89 0x02
        0x48 0x89 0xDC
        0x5B
        0xC3                                
    ", to_hex(lib_path_ptr), to_hex(loadlib_ptr), to_hex(result_ptr))
        .replace(" ", "")
        .replace("\n", "")
        .replace("0x", "");

    let mut payload = hex::decode(payload_str).unwrap();

    println!("{:X?}", payload);

    // Allocate remote memory for shellcode.
    let shellcode_ptr = VirtualAllocEx(
        proc_handle,
        ptr::null_mut(),
        payload.len(),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    // Write shellcode into process.
    let mut bytes_written: usize = 0;
    WriteProcessMemory(
        proc_handle,
        shellcode_ptr,
        payload.as_mut_ptr() as _,
        payload.len(),
        &mut bytes_written
    );

    println!("Remote LoadLibrary shellcode written to remote process.");
    println!("shellcode ptr: {:x?}", shellcode_ptr);
    println!("result ptr: {:x?}", result_ptr);

    // Spawn a remote thread to execute the payload.
    let loader_thread = CreateRemoteThread(
        proc_handle,
        ptr::null_mut(),
        0,
        Some(std::mem::transmute::<_, unsafe extern "system" fn(lpthreadparameter: *mut c_void) -> u32>(shellcode_ptr)),
        ptr::null_mut(),
        0,
        ptr::null_mut()
    );


    println!("Thread spawned in remote process.");

    WaitForSingleObject(loader_thread, 100000000);
    CloseHandle(loader_thread);

    // Read the remote process' memory for the result.
    let mut result = HINSTANCE::default();
    let mut bytes_read: usize = 0;
    ReadProcessMemory(
        proc_handle, 
        result_ptr, 
        &mut result as *mut HINSTANCE as _, 
        size_of::<HINSTANCE>(), 
        &mut bytes_read
    );

    if bytes_read != size_of::<HINSTANCE>() {
        return Err(anyhow!("Read an invalid number of bytes. Expected {}, got {}.", size_of::<HINSTANCE>(), bytes_read));
    }

    println!("{:x?}", result_ptr);

    // Cleanup remote memory.
    VirtualFree(lib_path_ptr, 0, MEM_FREE);
    VirtualFree(result_ptr, 0, MEM_FREE);
    VirtualFree(shellcode_ptr, 0, MEM_FREE);

    Ok(std::mem::transmute::<_, usize>(result))
}

unsafe fn get_lib_offset(library: &str, func_name: &str) -> Result<usize> {
    let module_handle = LoadLibraryExA(
        library,
        HANDLE(0),
        DONT_RESOLVE_DLL_REFERENCES
    );

    let module_base = std::mem::transmute::<_, *const c_void>(module_handle);

    let local_ptr = match GetProcAddress(module_handle, func_name) {
        Some(x) => x as *const () as *const c_void,
        None => return Err(anyhow!("Unable to find location of func.")),
    };

    let err = GetLastError();
    println!("{:?}", err);

    Ok((local_ptr as usize) - (module_base as usize))
}

fn to_hex(ptr: *const c_void) -> String {
    hex::encode((ptr as usize).to_le_bytes())
}