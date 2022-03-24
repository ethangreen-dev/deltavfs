use crate::ipc::pipe::{NamedPipe, PipeReader};

use anyhow::{anyhow, Result};
use rkyv::{Archive, Serialize, Deserialize, util};
use rkyv::ser::serializers::AllocSerializer;
use crate::ipc::models::{Magic, RegisterClientResponse};

#[derive(Debug)]
pub struct ServiceClient {
    pub id: u16,
    pipe: NamedPipe,
    serializer: AllocSerializer::<256>
}

impl ServiceClient {
    pub fn connect(name: &str) -> Result<ServiceClient> {
        // Connect to the pipe and request a client id from the server.
        let mut pipe = NamedPipe::with_name(name);
        pipe.connect()?;
        pipe.write(&[Magic::RegisterClientRequest as u8])?;

        let reader = PipeReader::new(pipe.handle);
        let buffer = match reader.read() {
            Some(x) => x,
            None => return Err(anyhow!("Failed to read from backing NamedPipe."))
        };

        let response = unsafe {
            util::archived_root::<RegisterClientResponse>(buffer)
        };
        let id = response.client_id;

        Ok(ServiceClient {
            id,
            pipe,
            serializer: AllocSerializer::<256>::default()
        })
    }

    pub fn send<T, Serialize, Deserialize>(self, model: T) -> Result<()> where T: Archive {
        todo!()
    }
}