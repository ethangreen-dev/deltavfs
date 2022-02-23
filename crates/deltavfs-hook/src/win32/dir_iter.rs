use macros::define_hook;

use widestring::WideStr;

use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;

#[define_hook("kernel32", "FindFirstFileW")]
fn find_first_file_w(
    file_name: &WideStr,
    find_file_data: &mut WIN32_FIND_DATAW
) -> HANDLE {
    HANDLE(0)
}

#[define_hook("kernel32", "FindNextFileW")]
fn find_next_file_w(
    find_file: HANDLE,
    find_file_data: &mut WIN32_FIND_DATAW
) -> BOOL {
    BOOL(0)
}