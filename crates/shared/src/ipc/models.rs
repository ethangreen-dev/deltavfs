use anyhow::anyhow;
use rkyv::{
    Archive,
    Serialize,
    Deserialize
};

#[repr(u8)]
#[derive(Debug)]
pub enum Magic {
    Msg = 0,
    ResolvePath = 1,
    RegisterClientResponse = 254,
    RegisterClientRequest = 255
}

impl TryFrom<u8> for Magic {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Magic::Msg),
            1 => Ok(Magic::ResolvePath),
            254 => Ok(Magic::RegisterClientResponse),
            255 => Ok(Magic::RegisterClientRequest),
            _ => Err(anyhow!("Invalid magic header value."))
        }
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub struct Echo {
    pub client_id: u16,
    pub msg: String
}

#[derive(Archive, Serialize, Deserialize)]
pub struct ResolvePathRequest {
    pub client_id: u16,
    pub path: String
}

#[derive(Archive, Serialize, Deserialize)]
pub struct RegisterClientResponse {
    pub client_id: u16
}
