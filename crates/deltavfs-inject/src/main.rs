mod injector;

use env_logger;

fn main() {
    unsafe {
        env_logger::builder()
            .format_timestamp(None)
            .init();

        injector::inject_into("notepad.exe").unwrap();
        println!("Hello, world!");
    }
}
