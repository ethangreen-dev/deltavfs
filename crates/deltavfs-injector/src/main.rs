mod injector;

fn main() {
    unsafe {
        //let path = "notepad.exe";
        // let path = r#"C:\Program Files (x86)\Steam\steamapps\common\Factorio\bin\x64\factorio.exe"#;

        // let path = r#"C:\Users\green\Downloads\Enter.the.Gungeon.v1.1.3.Hotfix.3\EtG.exe"#;
        let path = r#"C:\GOG Games\Factorio\bin\x64\factorio.exe"#;

        injector::inject_into(path, &["steam://rungameid/311690"]).unwrap();
    }
}
