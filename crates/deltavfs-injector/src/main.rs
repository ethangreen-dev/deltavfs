mod injector;

use env_logger;

fn main() {
    unsafe {
        env_logger::builder().format_timestamp(None).init();

        // let path = "notepad.exe";
        let path = r#"C:\Program Files (x86)\Steam\steamapps\common\Factorio\bin\x64\factorio.exe"#;

        injector::inject_into(path, &["steam://rungameid/311690"]).unwrap();
        println!("Hello, world!");
    }
}
