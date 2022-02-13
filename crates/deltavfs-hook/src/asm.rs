use std::{slice, mem, ptr};
use std::ffi::c_void;

use iced_x86::{Decoder, Encoder};
use anyhow::{anyhow, Result};

use crate::hook;

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
    let mut decoder = Decoder::with_ip(64, &instr_buffer, old_base as _, 0);

    while decoder.can_decode() {
        let instr = decoder.decode();

        println!("decoded: {}", instr.clone());

        if !instr.is_ip_rel_memory_operand() {
            encoder.encode(&instr, instr.ip())?;
            continue;
        }

        // Check to ensure that the memory location described by old_ip + base_delta does NOT overflow.
        let old_ip = instr.ip_rel_memory_address();
        let new_ip = (old_ip  as i128) + (base_delta as i128);

        // If it does not overflow, set the IP rel memory address of the current instr to the new offset.
        if new_ip < i32::MAX as _ {
            encoder.encode(&instr, new_ip as _)?;
            continue;
        }

        println!("[!] i64 addition error while taking sum of old IP and base delta.");

        // JMP instructions may reference indirect addresses, which need to be dereferenced before 
        // the new jump can be created.
        if instr.is_jmp_near_indirect() {
            let mut old_ip_buf: [u8; 8] = [0; 8];

            let old_ip = unsafe {
                ptr::copy(old_ip as *const u64 as *const u8, old_ip_buf.as_mut_ptr(), 6);
                u64::from_le_bytes(old_ip_buf)
            };

            // Else, manually insert a jump to destination described by old_ip.
            for byte in hook::make_jmp(old_ip as _)? {
                encoder.write_u8(byte);
            }
        }

    }

    Ok(encoder.take_buffer())
}