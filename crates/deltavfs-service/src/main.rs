mod handlers;

use std::collections::HashMap;
use shared::ipc::pipe::NamedPipe;

use anyhow::Result;
use rkyv::ser::Serializer;
use rkyv::ser::serializers::AllocSerializer;
use shared::ipc::models::{Echo, RegisterClientResponse, ResolvePathRequest};
use shared::ipc::models::Magic;

static PATH_MAP_TEST: HashMap<String, String> = {


    HashMap::new()
};

static PATH_MAP: HashMap<&str, &str> = HashMap::from([
    (r#"C:\Users\green\AppData\Roaming\Factorio\temp\"#, r#"C:\GOG Games\Not Factorio\Hello Dr Mec"#),
    (r#"C:\GOG Games\Factorio\factorio.exe"#, r#"C:\GOG Games\Factorio\bin\x64\factorio.exe"#)
    (r#"C:\GOG Games\Factorio"#, r#"C:\GOG Games\Not Factorio"#),
]);

fn main() {
    loop {
        println!("[=] deltavfs-service start.");

        start_server().unwrap();
    }
}

fn start_server() -> Result<()> {
    let mut pipe = NamedPipe::new_server(r#"\\.\pipe\deltavfs"#)?;

    loop {
        let buffer = pipe.read();
        if let Err(x) = buffer {
            continue;
        }

        let buffer = buffer.unwrap();
        let magic = Magic::try_from(buffer[0])?;

        match magic {
            Magic::RegisterClientRequest => {
                println!("Got register client request with payload: {:x?}", buffer);
                let response = RegisterClientResponse {
                    client_id: 68
                };

                let mut serializer = AllocSerializer::<256>::default();
                serializer.write(&[Magic::RegisterClientResponse as u8])?;
                serializer.serialize_value(&response)?;

                let payload = serializer.into_serializer().into_inner();
                pipe.write(payload.as_slice())?;
            },
            Magic::Msg => {
                let result = unsafe {
                    rkyv::util::archived_root::<Echo>(buffer)
                };

                println!("[client:{}] {}", result.client_id, result.msg);
            },
            Magic::ResolvePath => {
                println!("Magic::ResolvePath not implemented.");
            },
            Magic::RegisterClientResponse => {
                println!("Magic::RegisterClientResponse type request is invalid.")
            }
        };
    }

    Ok(())
}