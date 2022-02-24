use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;

pub struct FsController;

impl FsController {
    pub fn new() -> FsController {
        FsController { }
    }
}

pub struct FindFileHandle {
    pattern: String,
    contents: Vec<String>,
    handle: HANDLE,
    find_data: WIN32_FIND_DATAW
}

impl FindFileHandle {
    pub fn new(pattern: String) -> FindFileHandle {
        FindFileHandle {
            pattern,
            contents: Vec::new(),
            handle: HANDLE::default(),
            find_data: WIN32_FIND_DATAW::default()
        }
    }

    pub fn next(&self) -> Option<WIN32_FIND_DATAW> {
        Some(self.find_data)
    }

    pub fn close(&self) {

    }
}

pub struct VirtualDir<'a> {
    iter_index: usize,
    iter_handle: HANDLE,
    contents: Vec<&'a str>
}

impl VirtualDir<'_> {
    pub fn new(contents: Vec<&'static str>) -> Self {
        VirtualDir {
            iter_index: 0,
            iter_handle: HANDLE(0),
            contents
        }
    }

    pub fn set_iter(&mut self, handle: HANDLE) {
        self.iter_handle = handle;
    }

    pub fn next(&mut self) -> Option<&str> {
        if self.contents.len() >= self.iter_index {
            return None;
        }

        self.iter_index += 1;
        Some(self.contents[self.iter_index])
    }
}