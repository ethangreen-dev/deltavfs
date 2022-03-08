use std::ptr;
use std::marker::PhantomData;

use anyhow::{anyhow, Result};

use windows::Win32::System::Pipes::{
    CreateNamedPipeA,
    ConnectNamedPipe,
    PIPE_WAIT,
    PIPE_TYPE_BYTE,
    PIPE_READMODE_BYTE,
};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    ReadFile,
    WriteFile,
    CreateFileA,
    OPEN_EXISTING,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    PIPE_ACCESS_DUPLEX,
    FILE_ATTRIBUTE_NORMAL
};

#[derive(Debug)]
pub struct NamedPipe {
    name: String,
    handle: HANDLE
}

impl NamedPipe {
    pub fn new_server(name: &str) -> Result<NamedPipe> {
        let name = name.to_string();

        // Create the named pipe with block r/w set to read bytes.
        let handle = unsafe {
            CreateNamedPipeA(
                name.clone(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                100,
                0,
                0,
                1000,
                ptr::null_mut()
            )
        }.ok()?;

        Ok(NamedPipe{
            name,
            handle
        })
    }

    pub fn new_client(name: &str) -> Result<NamedPipe> {
        let name = name.to_string();

        let handle = unsafe {
            CreateFileA(
                name.clone(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE(0)
            )
        }.ok()?;

        Ok(NamedPipe{
            name,
            handle
        })
    }

    pub fn write(&self, buffer: &[u8]) -> Result<()> {
        let buf_ptr = buffer.as_ptr();
        let mut bytes_written = 0u32;

        match unsafe {
            WriteFile(
                self.handle,
                buf_ptr as *const _,
                buffer.len() as _,
                &mut bytes_written,
                ptr::null_mut()
            )
        }.as_bool() {
            true => Ok(()),
            false => Err(anyhow!("Failed to write to named pipe with handle: '{:x?} -- {:x?}'", self.handle, unsafe { GetLastError() }))
        }
    }

    pub fn as_reader(&self) -> Result<PipeReader> {
        unsafe {
            ConnectNamedPipe(self.handle, ptr::null_mut())
        }.expect("Failed to connect to pipe.");

        Ok(PipeReader::new(self.handle))
    }
}

pub struct PipeReader<'a> {
    handle: HANDLE,
    buffer: [u8; 1024],

    _magic: PhantomData<&'a ()>,
}

impl<'a> PipeReader<'a> {
    pub fn new(handle: HANDLE) -> PipeReader<'a> {
        PipeReader{
            handle,
            buffer: [0u8; 1024],
            _magic: PhantomData::default(),
        }
    }

    pub fn read(&'a self) -> Option<&'a [u8]> {
        let buf_ptr = self.buffer.as_ptr();
        let mut bytes_read: u32 = 0;

        match unsafe {
            ReadFile(
                self.handle,
                buf_ptr as *mut _,
                1024,
                &mut bytes_read as *mut _,
                ptr::null_mut()
            )
        }.as_bool() {
            true => Some(&self.buffer[..bytes_read as usize]),
            false => None
        }
    }
}