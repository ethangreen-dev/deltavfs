use std::{ffi::c_void, ptr};

use anyhow::{anyhow, Result};

use windows::Win32::{
    System::{Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        PAGE_PROTECTION_FLAGS,
    }, LibraryLoader::GetModuleHandleA},
};

pub struct WriteGuard {
    target: *const c_void,
    desired_size: usize,
    old_prot: PAGE_PROTECTION_FLAGS,
}

impl WriteGuard {
    pub unsafe fn new(target: *const c_void, desired_size: usize) -> WriteGuard {
        // Grant write permissions to the region of memory.
        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(
            target,
            desired_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot as *mut _,
        );

        WriteGuard {
            target,
            desired_size,
            old_prot,
        }
    }

    pub unsafe fn write(&self, buffer: Vec<u8>) -> Result<()> {
        ptr::copy(buffer.as_ptr(), self.target as _, buffer.len());
        // ptr::write(self.target as _, buffer);

        Ok(())
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        unsafe {
            VirtualProtect(
                self.target,
                self.desired_size,
                self.old_prot,
                ptr::null_mut(),
            );
        }
    }
}

pub unsafe fn get_exec_cave(desired_size: usize, close_to: *const c_void) -> Result<*const c_void> {
    // Determine the size of the module in memory.
    // Find or allocate an executable region in memory with the specified size.
    match VirtualAlloc(
        ptr::null_mut(),
        desired_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as usize
    {
        0 => Err(anyhow!(
            "VirtualAlloc() failed while allocating memory for code cave."
        )),
        x => Ok(x as _),
    }
}
