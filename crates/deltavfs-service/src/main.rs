use shared::ipc::pipe::NamedPipe;

use std::thread;
use std::time::Duration;

use anyhow::Result;
use rkyv::{
    Archive,
    Deserialize,
    Serialize
};
use rkyv::ser::Serializer;
use rkyv::ser::serializers::AllocSerializer;
use shared::ipc::models::ResolvePathRequest;

#[derive(Archive, Deserialize, Serialize, Debug)]
struct TestStruct {
    id: i8,
    name: String,
    some_int: isize,
    another_name: String
}

impl TestStruct {
    pub fn new() -> TestStruct {
        TestStruct {
            id: 12,
            name: "Test String 1".to_string(),
            some_int: 99,
            another_name: "Test String 2".to_string()
        }
    }
}

fn main() {
    loop {
        start_server().unwrap();
    }
}

fn start_server() -> Result<()> {
    let pipe = NamedPipe::new_server(r#"\\.\pipe\deltavfs"#)?;
    let reader = pipe.as_reader()?;

    while let Some(test) = reader.read() {
        let result = unsafe {
            rkyv::util::archived_root::<ResolvePathRequest>(test)
        };

        println!("{}", result.path);
    }

    Ok(())
}