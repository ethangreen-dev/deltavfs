use std::slice;
use std::ffi::c_void;

use iced_x86::{Decoder, Encoder};
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

pub fn adjust_offsets(instr_buffer: Vec<u8>, old_base: usize, new_base: usize) -> Result<Vec<u8>> {
    // Determine the difference between the new and old code bases and create the instr decoder.
    let base_delta = new_base as i64 - old_base as i64;

    let mut encoder = Encoder::new(64);
    let mut decoder = Decoder::new(64, &instr_buffer, 0);
    decoder.set_ip(old_base as _);

    while decoder.can_decode() {
        let mut instr = decoder.decode();

        if !instr.is_ip_rel_memory_operand() {
            continue;
        }

        // Get the RIP offset of the instruction and determine the difference between its current
        // target and the destination.
        let offset = instr.ip_rel_memory_address();
        let target = instr.ip() + offset;

        // Set the new ip rel offset of the instruction.
        let new_offset = (offset as i64 + base_delta) as usize;
        instr.set_memory_displacement64(new_offset as _);

        encoder.encode(&instr, (instr.ip() as i64 + base_delta) as _);
    }

    Ok(encoder.take_buffer())
}