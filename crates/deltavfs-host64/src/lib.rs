use deltavfs_host::hook_init as hook_init64;

#[no_mangle]
unsafe extern "stdcall" fn hook_init() {
    hook_init64()
}
