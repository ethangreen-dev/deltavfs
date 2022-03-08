mod injector;

use env_logger;

fn main() {
    unsafe {
        env_logger::builder().format_timestamp(None).init();

        // let path = r#"C:\Users\green\Dev\rust\IterDirTest\target\debug\IterDirTest.exe"#;
        let path = r#"C:\Program Files (x86)\Steam\steam.exe"#;

        injector::inject_into(path, &["steam://rungameid/311690"]).unwrap();
        println!("Hello, world!");
    }
}
