use crate::asm_analysis;
use crate::mem_utils;
use crate::mem_utils::WriteGuard;

use std::mem;
use std::ffi::c_void;

use hex;
use anyhow::Result;

const JMP_SIZE64: usize = 14;

pub unsafe fn install_hook(target_ptr: *const c_void, dest_ptr: *const c_void) -> Result<(*const c_void)> {
    println!("target_ptr: {:x?}", target_ptr);
    println!("dest:   {:x?}", dest_ptr);

    // Determine the number of bytes to steal from the prologue of the target_ptr function. Note that 
    // partial instructions cannot be left over, so we must first determine instruction boundaries.
    let steal_size = asm_analysis::get_bounded_size(target_ptr, JMP_SIZE64)?;

    println!("{} bytes will be stolen from the target_ptr at {:x?}", steal_size, target_ptr);

    // Find a suitable location for the trampoline, which will both store the stolen bytes and redirect
    // execution back to the target + JMP size offset.
    let trampoline_size = steal_size + JMP_SIZE64;
    let trampoline_ptr = mem_utils::get_exec_cave(trampoline_size)?;

    println!("created executable cave at {:x?}.", trampoline_ptr);

    // Copy steal_size bytes from the target function prologue into the stolen_bytes buffer.
    let stolen_bytes = std::slice::from_raw_parts(target_ptr as *const u8, steal_size).to_vec();

    // ptr::copy(target_ptr as *const u8, &mut stolen_bytes as *mut _ as *mut u8, steal_size);

    println!("stolen bytes: {:x?}", stolen_bytes);

    let target_jmp_dest = ((target_ptr as usize) + steal_size) as *const c_void;
    let mut target_jmp = make_jmp(target_jmp_dest)?;

    println!("jmp -> target created.");

    // Create the trampoline by appending the stolen bytes and JMP shellcode.
    let mut trampoline = stolen_bytes.clone();
    trampoline.append(&mut target_jmp);

    // Write the trampoline to memory.
    WriteGuard::new(trampoline_ptr, trampoline.len()).write(trampoline)?;

    println!("trampoline has been written to {:x?}", trampoline_ptr);

    // Write the JMP -> dest_ptr to the prologue of the target.
    let mut dest_jmp = make_jmp(dest_ptr)?;
    dest_jmp.append(&mut vec![0x90 as u8; steal_size - JMP_SIZE64]);

    println!("dest_jmp: {:x?}", dest_jmp);

    WriteGuard::new(target_ptr, dest_jmp.len()).write(dest_jmp)?;

    println!("jmp -> dest has been written to the target at {:x?}", target_ptr);

    Ok(trampoline_ptr as _)
}

fn make_jmp(dest_ptr: *const c_void) -> Result<Vec<u8>> {
    // Split the destination ptr into upper and lower 32 bit components.
    let upper = ((dest_ptr as usize) >> (mem::size_of::<u32>() * 8)) as u32;
    let lower = ((dest_ptr as usize) & (u32::MAX as usize)) as u32;

    println!("upper: {:x?}", upper);
    println!("lower: {:x?}", lower);

    // Create the JMP shellcode, embedding the upper and lower byte arrays.
    let jmp_shellcode = format!("
        0x68 {}
        0xC7 0x44 0x24 0x04 {}
        0xC3
    ", hex::encode(lower.to_ne_bytes()), hex::encode(upper.to_ne_bytes()))
        .replace(" ", "")
        .replace("\n", "")
        .replace("0x", "");

    println!("{} {}", jmp_shellcode.len() / 2, jmp_shellcode);

    Ok(hex::decode(jmp_shellcode)?)
}