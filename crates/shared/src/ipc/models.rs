use rkyv::{
    Archive,
    Serialize,
    Deserialize
};

#[repr(u8)]
pub enum Request {
    ResolvePath = 0
}

#[derive(Archive, Serialize, Deserialize)]
pub struct ResolvePathRequest {
    pub path: String
}

#[derive(Archive, Serialize, Deserialize)]
pub struct Echo {
    pub msg: String
}