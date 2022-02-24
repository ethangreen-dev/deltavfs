mod injector;

use env_logger;

fn main() {
    unsafe {
        env_logger::builder().format_timestamp(None).init();

        let path = r#"C:\Users\green\Dev\rust\IterDirTest\target\debug\IterDirTest.exe"#;

        injector::inject_into(path).unwrap();
        println!("Hello, world!");
    }
}
