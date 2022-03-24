extern crate core;

mod asm;
mod hook;
mod mem_utils;
mod win32;

use log;
use log::{Metadata, Record, Level, Log, LevelFilter, info};

use colored::Colorize;
use rkyv::ser::Serializer;
use shared::pe;

use shared::ipc::pipe::NamedPipe;
use shared::ipc::models::{Echo, Magic, ResolvePathRequest};

use once_cell::sync::OnceCell;
use rkyv::ser::serializers::AllocSerializer;
use shared::ipc::dvfs_pipe::ServiceClient;

const BITNESS: u32 = match std::mem::size_of::<usize>() {
    8 => 64,
    4 => 32,
    _ => 0
};

static PIPE: OnceCell<NamedPipe> = OnceCell::new();

struct PipedLogger;
impl Log for PipedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        let pipe = PIPE.get().unwrap();
        let msg = Echo {
            client_id: 0,
            msg: format!("[{}] {}", record.level(), record.args())
        };

        let mut serializer = AllocSerializer::<256>::default();
        serializer.write(&[Magic::Msg as u8]).unwrap();
        serializer.serialize_value(&msg).unwrap();

        let payload = serializer.into_serializer().into_inner();
        pipe.write(payload.as_slice()).unwrap();
    }

    fn flush(&self) { }
}

pub unsafe fn hook_init() {
    PIPE.set(NamedPipe::new_client(r#"\\.\pipe\deltavfs"#).unwrap()).expect("Failed to connect to deltavfs-service.");

    log::set_boxed_logger(Box::new(PipedLogger))
        .map(|()| log::set_max_level(LevelFilter::Debug)).unwrap();

    info!("deltavfs-host start.");

    crate::win32::file::test_init();
    crate::win32::file::find_first_filew_init();
    crate::win32::file::get_module_file_namew_init();

    // crate::win32::file::create_file_mapping_init();
    // crate::win32::file::map_view_of_file_init();

    info!("hook installation complete.")
}
