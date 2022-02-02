use std::ptr;
use std::slice;
use std::ffi::c_void;

use iced_x86::Decoder;
use anyhow::{anyhow, Result};

use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::VirtualAlloc;

pub unsafe fn get_bounded_size(target_ptr: *const c_void, desired_size: usize) -> Result<usize> {
    // Create a view over the region of memory to analyse. The size of the region is set by desired_size + 
    // 15 bytes, which is the largest an x86_64 instruction can be.
    let target_slice = slice::from_raw_parts(target_ptr as *const u8, desired_size + 15);
    let mut decoder = Decoder::new(64, target_slice, 0);

    // Decode instructions one-by-one until the total bytes read is >= desired_size.
    let mut sum = 0;
    for instr in decoder.iter() {
        if sum >= desired_size {
            return Ok(sum);
        }

        sum += instr.len();
    }

    Err(anyhow!("Failed to determine instruction boundaries."))
}

pub unsafe fn get_exec_cave(desired_size: usize) -> Result<*const c_void> {
    // Find or allocate an executable region in memory with the specified size.
    match VirtualAlloc(
            ptr::null_mut(),
            desired_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ) as usize {
        0 => Err(anyhow!("VirtualAlloc() failed while allocating memory for code cave.")),
        x => Ok(x as _)
    }
}
