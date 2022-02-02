use crate::asm_analysis;
use crate::mem_utils::WriteGuard;

use std::ffi::c_void;
use anyhow::{anyhow, Result};

const JMP_SIZE64: usize = 14;
const JMP_SIZE32: usize = 0;

pub unsafe fn install_hook(target_ptr: *const c_void, dest_ptr: *const c_void) -> Result<()> {
    println!("target_ptr: {:x?}", target_ptr);
    println!("dest:   {:x?}", dest_ptr);

    // Determine the number of bytes to steal from the prologue of the target_ptr function. Note that 
    // partial instructions cannot be left over, so we must first determine instruction boundaries.
    let steal_size = asm_analysis::get_bounded_size(target_ptr, JMP_SIZE64)?;

    println!("{} bytes will be stolen from the target_ptr at {:x?}", steal_size, target_ptr);

    // Find a suitable location for the trampoline, which will both store the stolen bytes and redirect
    // execution back to the target + JMP size offset.
    let trampoline_size = steal_size + JMP_SIZE64;
    let trampoline_ptr = asm_analysis::get_exec_cave(trampoline_size);

    // Steal bytes from the prologue of the target function and create the JMP to target, storing each in a buffer.

    Ok(())
}