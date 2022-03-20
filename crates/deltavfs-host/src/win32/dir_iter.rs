use std::collections::HashMap;
use macros::define_hook;
use macros::define_hook_test;

use once_cell::sync::{Lazy, OnceCell};
use widestring::{U16CStr, U16CString};

use windows::Win32::Foundation::{BOOL, HANDLE, PWSTR};
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;

// static mut FS_INSTANCE: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
//     let dir_contents = vec![
//         "C:\\Users\\green\\Documents\\Battlefield 2042",
//         "C:\\Users\\green\\Downloads\\SF-Mono-Nerd-Font"
//     ];
//     let mut virtual_dir = VirtualDir::new(dir_contents);
//
//     HashMap::from([
//         ("C:\\Users\\green\\Music\\*", "C:\\Users\\green\\*")
//     ])
// });
//
// pub fn init() {
//     find_first_file_w_init();
//     find_next_file_w_init();
//     find_close_init();
// }
//
// #[define_hook("kernel32", "FindFirstFileW")]
// unsafe fn find_first_file_w(
//     file_name_ffi: PWSTR,
//     find_file_data: &mut WIN32_FIND_DATAW
// ) -> HANDLE {
//     let file_name = U16CStr::from_ptr_str(file_name_ffi.0)
//         .to_string()
//         .unwrap();
//
//     let mut vdir_entry = match FS_INSTANCE.get(file_name.as_str()) {
//         None => return recall(file_name_ffi, find_file_data),
//         Some(x) => x
//     };
//
//     // let new_path = vdir_entry.next().unwrap().to_string();
//     let mut new_path =
//         U16CString::from_str(vdir_entry.to_string())
//         .unwrap();
//
//     println!("[FindFirstFileW] '{:x?}'", new_path);
//
//     let handle = recall(PWSTR(new_path.as_mut_ptr()), find_file_data);
//     // vdir_entry.set_iter(handle);
//
//     handle
// }
//
// #[define_hook("kernel32", "FindNextFileW")]
// unsafe fn find_next_file_w(
//     find_file_handle: HANDLE,
//     find_file_data: &mut WIN32_FIND_DATAW
// ) -> BOOL {
//     let file_name = "C:\\Users\\green\\Downloads\\*";
//
//     let mut vdir_entry = match FS_INSTANCE.get(file_name) {
//         None => return recall(find_file_handle, find_file_data),
//         Some(x) => x
//     };
//     // let new_file = match vdir_entry.next() {
//     //     None => return BOOL(0),
//     //     Some(x) => x
//     // };
//
//     recall(find_file_handle, find_file_data)
// }
//
// #[define_hook("kernel32", "FindClose")]
// unsafe fn find_close(find_file: HANDLE) -> BOOL {
//     recall(find_file)
// }