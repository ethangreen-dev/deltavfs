mod injector;

use env_logger;

fn main() {
    unsafe {
        env_logger::builder().format_timestamp(None).init();

        let path = "E:\\Games\\Steam\\steamapps\\common\\Skyrim Special Edition\\skse64_loader.exe";

        injector::inject_into(path).unwrap();
        println!("Hello, world!");
    }
}
