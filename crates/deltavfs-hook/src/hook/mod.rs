mod raw_hook64;
mod raw_hook32;

use anyhow::Result;

pub struct Hook {
    target: *const (),
    detour: *const ()
}

impl Hook {
    pub fn new(target: *const (), detour: *const ()) -> Result<Hook> {
        Ok(Hook {
            target,
            detour
        })
    }

    pub fn enable() -> Result<()> {
        Ok(())
    }

    pub fn disable() -> Result<()> {
        Ok(())
    }
}