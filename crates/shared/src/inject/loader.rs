use crate::pe;
use crate::pe::Bitness;

use std::ptr;
use std::mem;
use std::ffi::c_void;

use anyhow::{anyhow, Result};
use iced_x86::code_asm::*;
use widestring::U16CString;

use windows::Win32::Foundation::{
    BOOL,
    HANDLE,
    HINSTANCE,
    CloseHandle
};
use windows::Win32::System::Memory::{
    MEM_COMMIT,
    PAGE_EXECUTE_READWRITE,
    VirtualAllocEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread,
    WaitForSingleObject
};
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory,
    WriteProcessMemory
};

pub struct Loader {
    proc_handle: HANDLE,
    bitness: Bitness,
    result_addr: Option<*mut c_void>,
    lib_path_addr: Option<*mut c_void>,
    shellcode_addr: Option<*mut c_void>,
}

impl Loader {
    pub fn new(proc_handle: HANDLE, bitness: Bitness) -> Loader {
        Loader {
            proc_handle,
            bitness,
            result_addr: None,
            lib_path_addr: None,
            shellcode_addr: None
        }
    }

    pub fn setup(&mut self, lib_path: &str) -> Result<&Loader> {
        // Allocate and write the path of the DLL into the target process.
        let lib_path = U16CString::from_str(lib_path)?;
        let lib_path_size = (lib_path.len() + 1) * 2;

        let lib_path_addr = unsafe {
            VirtualAllocEx(
                self.proc_handle,
                ptr::null(),
                lib_path_size,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            )
        };

        unsafe {
            WriteProcessMemory(
                self.proc_handle,
                lib_path_addr,
                lib_path.as_ptr() as *const _,
                lib_path_size,
                ptr::null_mut()
            )
        };

        // Allocate space in the target process to store the result of LoadLibraryW.
        self.result_addr = Some(unsafe {
            VirtualAllocEx(
                self.proc_handle,
                ptr::null(),
                mem::size_of::<HINSTANCE>(),
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            )
        });

        // Get the relative offset of LoadLibraryW for the current module. This will then be called
        // by following shellcode in the target process -- this works because system modules are,
        // while randomized at boot, loaded at a constant offset in every process.
        let loadlib_addr = pe::get_func_addr("Kernel32", "LoadLibraryW")?;

        // Construct the shellcode that, once injected, will call LoadLibraryW on lib_path_addr.
        // The shellcode can either be 64 or 32 bit, depending on the bitness of the target.
        let mut shellcode = {
            let mut a = CodeAssembler::new(self.bitness.clone() as u32)?;

            match self.bitness {
                Bitness::X32 => {
                    a.push(ebx)?;
                    a.mov(ebx, esp)?;
                    a.sub(esp, 0x20 as u32)?;
                    a.mov(ecx, lib_path_addr as u32)?;
                    a.mov(edx, loadlib_addr as u32)?;
                    a.call(edx)?;
                    a.mov(edx, self.result_addr.unwrap() as u32)?;
                    a.mov(dword_ptr(edx), eax)?;
                    a.mov(esp, ebx)?;
                    a.pop(ebx)?;
                    a.ret()?;
                },
                Bitness::X64 => {
                    a.push(rbx)?;
                    a.mov(rbx, rsp)?;
                    a.sub(rsp, 0x20)?;
                    a.mov(rcx, lib_path_addr as u64)?;
                    a.mov(rdx, loadlib_addr as u64)?;
                    a.call(rdx)?;
                    a.mov(rdx, self.result_addr.unwrap() as u64)?;
                    a.mov(qword_ptr(rdx), rax)?;
                    a.mov(rsp, rbx)?;
                    a.pop(rbx)?;
                    a.ret()?;
                },
            }

            a.assemble(0)
        }?;

        // Allocate space and write the shellcode into the target process.
        let mut bytes_written: usize = 0;
        let shellcode_addr = unsafe {
            VirtualAllocEx(
                self.proc_handle,
                ptr::null(),
                shellcode.len(),
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            )
        };

        unsafe {
            WriteProcessMemory(
                self.proc_handle,
                shellcode_addr,
                shellcode.as_mut_ptr() as *mut _,
                shellcode.len(),
                &mut bytes_written
            )
        };

        self.shellcode_addr = Some(shellcode_addr);

        Ok(self)
    }

    pub fn inject(&self) -> Result<usize> {
        unsafe {
            let loader_thread = CreateRemoteThread(
                self.proc_handle,
                ptr::null(),
                0,
                std::mem::transmute(self.shellcode_addr.unwrap()),
                ptr::null_mut(),
                0,
                ptr::null_mut()
            );

            WaitForSingleObject(loader_thread, u32::MAX);
            CloseHandle(loader_thread);
        };

        let mut result = HINSTANCE::default();
        let mut bytes_read: usize = 0;

        unsafe {
            match ReadProcessMemory(
                self.proc_handle,
                self.result_addr.unwrap(),
                &mut result as *mut HINSTANCE as *mut _,
                mem::size_of::<HINSTANCE>(),
                &mut bytes_read
            ) {
                BOOL(0) => Err(anyhow!("Failed")),
                _ => Ok(mem::transmute::<_, usize>(result))
            }
        }
    }
}
