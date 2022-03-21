pub mod dir_iter;
pub mod file;

trait TestTrait {
    unsafe fn enable();
    unsafe fn disable();
    unsafe fn initialize();
}

struct TestStruct;
impl TestTrait for TestStruct {
    unsafe fn enable() {
        todo!()
    }

    unsafe fn disable() {
        todo!()
    }

    unsafe fn initialize() {
        todo!()
    }
}

impl TestStruct {
    fn hook() {
        todo!()
    }

    fn call() {
        todo!()
    }
}