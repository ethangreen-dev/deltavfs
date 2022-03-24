mod injector;

use std::env;
use std::str::FromStr;

fn main() {
    unsafe {
        let proc_handle = match env::args().nth(1).unwrap().as_str() {
            "--id" => {
                injector::open_process(env::args().nth(2).unwrap().parse::<u32>().unwrap())
            },
            "--path" => {
                let path = env::args().nth(2).unwrap();

                injector::start_process(path.as_str(), &["test"])
            },
            _ => panic!("Incorrect argument.")
        }.unwrap();

        //let path = "notepad.exe";
        // let path = r#"C:\Program Files (x86)\Steam\steamapps\common\Factorio\bin\x64\factorio.exe"#;

        // let path = r#"C:\Users\green\Downloads\Enter.the.Gungeon.v1.1.3.Hotfix.3\EtG.exe"#;
        let path = r#"C:\GOG Games\Factorio\bin\x64\factorio.exe"#;

        injector::inject_into(proc_handle.clone()).unwrap();
    }
}
