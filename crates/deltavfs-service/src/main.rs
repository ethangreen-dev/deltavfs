use shared::ipc::pipe::NamedPipe;

use anyhow::Result;
use shared::ipc::models::Echo;

fn main() {
    loop {
        println!("[=] deltavfs-service start.");

        start_server().unwrap();
    }
}

fn start_server() -> Result<()> {
    let pipe = NamedPipe::new_server(r#"\\.\pipe\deltavfs"#)?;
    let reader = pipe.as_reader()?;

    while let Some(test) = reader.read() {
        let result = unsafe {
            rkyv::util::archived_root::<Echo>(test)
        };

        println!("{}", result.msg);
    }

    Ok(())
}