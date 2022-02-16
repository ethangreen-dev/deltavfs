mod asm;
mod hook;
mod mem_utils;

use macros::hook;
use shared::pe;

use once_cell::sync::OnceCell;

use widestring::WideCString;
use windows::Win32::{
    Foundation::{HANDLE, PWSTR},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_ACCESS_FLAGS, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    },
};
use windows::Win32::Foundation::SIZE;

// static TEST_RECALL: OnceCell<usize> = OnceCell::new();

#[no_mangle]
unsafe extern "stdcall" fn hook_init() {
    println!("Hook initialization.");

    // let target_addr = pe::get_func_addr("kernel32", "CreateFileW").unwrap();
    // let recall = hook::install_hook(target_addr, test as _).unwrap();

    // println!("Got recall value of {:?}", recall);

    // TEST_RECALL.set(recall as _).unwrap();

    test_init();
    map_view_of_file_init();
    create_file_mapping_init();
}

#[hook("kernel32", "CreateFileW")]
unsafe fn test(
    file_name: PWSTR,
    desired_access: FILE_ACCESS_FLAGS,
    share_mode: FILE_SHARE_MODE,
    security_attributes: *const SECURITY_ATTRIBUTES,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    template_file: HANDLE,
) -> HANDLE {
    let thing = WideCString::from_ptr_str(file_name.0).to_string().unwrap();
    println!("[CreateFileW] {}", thing);

    let handle = recall(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file,
    );

    handle
}

#[hook("kernel32", "MapViewOfFile")]
unsafe fn map_view_of_file(
    file_mapping_object: HANDLE,
    desired_access: u32,
    file_offset_high: u32,
    file_offset_low: u32,
    number_of_bytes_to_map: usize
) -> *const usize {
    let ptr = recall(
        file_mapping_object,
        desired_access,
        file_offset_high,
        file_offset_low,
        number_of_bytes_to_map
    );

    println!("[MapViewOfFile] with {} bytes to map. created ptr: {:x?}", number_of_bytes_to_map, ptr);

    ptr
}

#[hook("kernel32", "CreateFileMappingW")]
unsafe fn create_file_mapping(
    file: HANDLE,
    attributes: *const SECURITY_ATTRIBUTES,
    protect: u32,
    max_size_high: u32,
    max_size_low: u32,
    name: *const char
) -> HANDLE {
    println!("[CreateFileMapping] with max_size_high: {}, max_size_low: {}", max_size_high, max_size_low);

    recall(
        file,
        attributes,
        protect,
        max_size_high,
        max_size_low,
        name
    )
}
