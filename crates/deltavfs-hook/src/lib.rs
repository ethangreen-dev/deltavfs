extern crate core;

mod asm;
mod hook;
mod mem_utils;
mod win32;

use macros::define_hook;
use rkyv::ser::Serializer;
use shared::pe;

use shared::ipc::pipe::NamedPipe;
use shared::ipc::models::{
    Request,
    ResolvePathRequest
};

use once_cell::sync::OnceCell;
use rkyv::ser::serializers::AllocSerializer;

use widestring::WideCString;
use windows::Win32::{
    Foundation::{HANDLE, PWSTR},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_ACCESS_FLAGS, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    },
};

const BITNESS: u32 = match cfg!(target_pointer_size = "64") {
    true => 64,
    false => 32
};

static PIPE: OnceCell<NamedPipe> = OnceCell::new();

#[no_mangle]
unsafe extern "stdcall" fn hook_init() {
    println!("Hook initialization.");

    PIPE.set(NamedPipe::new_client(r#"\\.\pipe\deltavfs"#).unwrap()).expect("failed");

    test_init();
    map_view_of_file_init();
    create_file_mapping_init();
}

#[define_hook("kernel32", "CreateFileW")]
unsafe fn test(
    file_name: PWSTR,
    desired_access: FILE_ACCESS_FLAGS,
    share_mode: FILE_SHARE_MODE,
    security_attributes: *const SECURITY_ATTRIBUTES,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    template_file: HANDLE,
) -> HANDLE {
    let path = WideCString::from_ptr_str(file_name.0).to_string().unwrap();
    let req = ResolvePathRequest {
        path
    };

    let mut serializer = AllocSerializer::<256>::default();
    serializer.write(&[Request::ResolvePath as u8]).unwrap();
    serializer.serialize_value(&req).unwrap();

    let payload = serializer.into_serializer().into_inner();

    PIPE.get().unwrap().write(payload.as_slice()).unwrap();

    let handle = recall(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file,
    );

    println!("[CreateFileW] with path '{}' which returned handle {:x?}", "adwadw", handle);

    handle
}

#[define_hook("kernel32", "MapViewOfFile")]
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

    println!("[MapViewOfFile] with handle {:x?} and {} bytes to map. created ptr: {:x?}", file_mapping_object, number_of_bytes_to_map, ptr);

    ptr
}

#[define_hook("kernel32", "CreateFileMappingW")]
unsafe fn create_file_mapping(
    file: HANDLE,
    attributes: *const SECURITY_ATTRIBUTES,
    protect: u32,
    max_size_high: u32,
    max_size_low: u32,
    name: *const char
) -> HANDLE {
    println!("[CreateFileMapping] with handle {:x?}, max_size_high: {}, max_size_low: {}", file, max_size_high, max_size_low);

    recall(
        file,
        attributes,
        protect,
        max_size_high,
        max_size_low,
        name
    )
}
