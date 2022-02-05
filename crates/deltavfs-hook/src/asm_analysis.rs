use std::slice;
use std::ffi::c_void;

use iced_x86::Decoder;
use anyhow::{anyhow, Result};

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

pub fn adjust_offsets(instr_buffer: Vec<u8>) -> Result<()> {
    Ok(())
}