use std::path::{Path, PathBuf};
use std::ffi::c_void;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::{ptr, thread};
use std::os::windows::process::CommandExt;

use anyhow::{anyhow, Result};
use log::*;

use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES, LOAD_LIBRARY_AS_DATAFILE};
use windows::Win32::System::Threading::{CREATE_SUSPENDED, CreateRemoteThread, IsWow64Process, WaitForSingleObject};
use windows::Win32::System::{
    Threading::{OpenProcess, PROCESS_ALL_ACCESS},
};

use shared::inject::loader::Loader;
use shared::pe::Bitness;

pub unsafe fn inject_into(exec_path: &str, args: &[&str]) -> Result<()> {
    info!(
        "Preparing to inject payload into executable at '{}'",
        exec_path
    );

    // Spawn the process in a suspended state.
    let mut proc = Command::new(exec_path)
        .args(args)
        .creation_flags(CREATE_SUSPENDED)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = proc
        .stdout
        .take()
        .expect("Failed to open stdout of child process.");

    // Open threaded reader to echo child stdout to parent.
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            println!("[~] {}", line.unwrap());
        }
    });

    let proc_handle = OpenProcess(PROCESS_ALL_ACCESS, false, proc.id());

    // Determine the process' bitness.
    let proc_bitness = {
        let mut wow64_flag = BOOL(0);
        if IsWow64Process(proc_handle, &mut wow64_flag) == BOOL(0) {
            return Err(anyhow!("IsWowProcess64 call failed, returned BOOL(0)."))
        };

        match wow64_flag {
            BOOL(0) => Ok(Bitness::X64),
            BOOL(1) => Ok(Bitness::X32),
            _ => Err(anyhow!("IsWow64Process call failed to determine bitness of target process."))
        }
    }?;

    println!("{}", std::env::current_exe().unwrap().to_str().unwrap());

    // Determine the path of the host binary according to proc_bitness.
    let library = std::env::current_exe()?
        .parent()
        .unwrap()
        .join(match proc_bitness {
            Bitness::X32 => "../i686-pc-windows-msvc/debug/deltavfs_host32.dll",
            Bitness::X64 => "deltavfs_host64.dll"
        }).canonicalize()?;

    println!("Using host binary '{}'", library.to_str().unwrap());

    let lib_base = Loader::new(proc_handle, proc_bitness)
        .setup(library.to_str().unwrap())?
        .inject()?;

    let test = std::env::current_exe()?
        .parent()
        .unwrap()
        .join("deltavfs_host64.dll")
        .canonicalize()?;

    println!("Lib base at {:x?}", lib_base);

    // Determine the location of the mainThread function within the target.
    let local_delta = get_lib_offset(test.to_str().unwrap(), "hook_init")?;
    let entry_point = lib_base + local_delta;

    println!("Found remote entry point at: {:x?}", entry_point);

    // Create a thread at mainThread to begin hook installation.
    let hook_thread = CreateRemoteThread(
        proc_handle,
        ptr::null_mut(),
        0,
        std::mem::transmute(entry_point),
        ptr::null_mut(),
        0,
        ptr::null_mut(),
    );

    WaitForSingleObject(hook_thread, 10000);
    CloseHandle(hook_thread);

    println!("deltavfs-host has been successfully injected into the target process.");

    Ok(())
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
        None => return Err(anyhow!("GetProcAddress call failed, unable to determine location of function.")),
    };

    let err = GetLastError();
    println!("{:?}", err);

    Ok((local_ptr as usize) - (module_base as usize))
}
