use crate::asm;
use crate::mem_utils;
use crate::mem_utils::WriteGuard;

use std::ffi::c_void;

use log::{info, debug};
use anyhow::Result;

const JMP_SIZE: usize = match cfg!(target_pointer_width = "64") {
    true => 14,
    false => 7
};

pub unsafe fn install(
    target_ptr: *const c_void,
    dest_ptr: *const c_void,
) -> Result<*const c_void> {
    info!("installing x64 hook into `{:x?}` -> `{:x?}`", target_ptr, dest_ptr);

    debug!("target_ptr: {:x?}", target_ptr);
    debug!("dest:   {:x?}", dest_ptr);

    // Determine the number of bytes to steal from the prologue of the target_ptr function. Note that
    // partial instructions cannot be left over, so we must first determine instruction boundaries.
    let steal_size = asm::get_bounded_size(target_ptr, JMP_SIZE)?;

    debug!(
        "{} bytes will be stolen from the target_ptr at {:x?}",
        steal_size, target_ptr
    );

    // Find a suitable location for the trampoline, which will both store the stolen bytes and redirect
    // execution back to the target + JMP size offset.
    let trampoline_size = steal_size + JMP_SIZE;
    let trampoline_ptr = mem_utils::get_exec_cave(trampoline_size, target_ptr)?;

    debug!("created executable cave at {:x?}.", trampoline_ptr);

    // Determine the trampoline -> target ptr and create the jmp shellcode.
    let target_jmp_dest = ((target_ptr as usize) + steal_size) as *const c_void;
    let mut target_jmp = asm::make_jmp(target_jmp_dest)?;

    debug!("target_jmp: {:x?}", target_jmp);

    // Copy steal_size bytes from the target function prologue into the stolen_bytes buffer.
    let stolen_bytes = std::slice::from_raw_parts(target_ptr as *const u8, steal_size).to_vec();
    debug!("stolen bytes: {:x?}", stolen_bytes);

    let adjusted_bytes = asm::adjust_offsets(stolen_bytes, target_ptr as _, trampoline_ptr as _)?;
    debug!("patched: {:x?}", adjusted_bytes);

    debug!("jmp -> target created.");

    // Create the trampoline by appending the stolen bytes and JMP shellcode.
    let mut trampoline = adjusted_bytes.clone();
    trampoline.append(&mut target_jmp);

    // Write the trampoline to memory.
    WriteGuard::new(trampoline_ptr, trampoline.len()).write(trampoline)?;

    debug!("trampoline has been written to {:x?}", trampoline_ptr);

    // Write the JMP -> dest_ptr to the prologue of the target.
    let mut dest_jmp = asm::make_jmp(dest_ptr)?;
    dest_jmp.append(&mut vec![0x90 as u8; steal_size - JMP_SIZE]);

    debug!("dest_jmp: {:x?}", dest_jmp);

    WriteGuard::new(target_ptr, dest_jmp.len()).write(dest_jmp)?;

    debug!(
        "jmp -> dest has been written to the target at {:x?}",
        target_ptr
    );

    Ok(trampoline_ptr as _)
}
