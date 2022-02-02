mod injector;

fn main() {
    unsafe {
        injector::inject_into("notepad.exe").unwrap();
        println!("Hello, world!");
    }
}
