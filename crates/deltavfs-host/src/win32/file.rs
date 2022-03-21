use macros::define_hook;
use crate::PIPE;

use shared::ipc::models::{
    Request,
    ResolvePathRequest
};

use log::info;
use rkyv::ser::Serializer;
use rkyv::ser::serializers::AllocSerializer;

use widestring::WideCString;
use windows::Win32::{
    Foundation::{HANDLE, PWSTR},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_ACCESS_FLAGS, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, WIN32_FIND_DATAW,
    },
};

#[define_hook("kernel32", "CreateFileW")]
pub unsafe fn test(
    file_name: *const u16,
    desired_access: FILE_ACCESS_FLAGS,
    share_mode: FILE_SHARE_MODE,
    security_attributes: *const SECURITY_ATTRIBUTES,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    template_file: HANDLE,
) -> HANDLE {
    let path = WideCString::from_ptr_str(file_name)
        .to_string()
        .unwrap()
        .replace(r#"C:\GOG Games\Factorio"#, r#"C:\GOG Games\Not Factorio"#)
        .replace(r#"C:\Users\green\AppData\Roaming\Factorio"#, r#"C:\GOG Games\Not Factorio\Roaming"#);

    // let req = ResolvePathRequest {
    //     path
    // };

    // let mut serializer = AllocSerializer::<256>::default();
    // serializer.write(&[Request::ResolvePath as u8]).unwrap();
    // serializer.serialize_value(&req).unwrap();

    // let payload = serializer.into_serializer().into_inner();

    // PIPE.get().unwrap().write(payload.as_slice()).unwrap();

    let handle = recall(
        WideCString::from_str(path.clone()).unwrap().as_ptr(),
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file,
    );

    info!("[CreateFileW] with path '{}' which returned handle {:x?}", path, handle);

    handle
}

#[define_hook("kernel32", "FindFirstFileW")]
pub unsafe fn find_first_filew(
    file_name: PWSTR,
    find_file_data: &mut WIN32_FIND_DATAW
) -> HANDLE {
    info!("[FindFirstFileW] with path '{}'", WideCString::from_ptr_str(file_name.0).to_string().unwrap());

    recall(file_name, find_file_data)
}

#[define_hook("kernel32", "MapViewOfFile")]
pub unsafe fn map_view_of_file(
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
        number_of_bytes_to_map,
    );

    info!("[MapViewOfFile] with handle {:x?} and {} bytes to map. created ptr: {:x?}", file_mapping_object, number_of_bytes_to_map, ptr);

    ptr
}

#[define_hook("kernel32", "CreateFileMappingW")]
pub unsafe fn create_file_mapping(
    file: HANDLE,
    attributes: *const SECURITY_ATTRIBUTES,
    protect: u32,
    max_size_high: u32,
    max_size_low: u32,
    name: *const char
) -> HANDLE {
    info!("[CreateFileMapping] with handle {:x?}, max_size_high: {}, max_size_low: {}", file, max_size_high, max_size_low);

    recall(
        file,
        attributes,
        protect,
        max_size_high,
        max_size_low,
        name
    )
}
