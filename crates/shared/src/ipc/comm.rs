use crate::ipc::models::Request;

use anyhow::Result;
use rkyv::ser::{serializers::AllocSerializer, Serializer};


// pub fn to_bytes<T>(value: T, kind: Request) -> Result<&'static [u8]> {
//     let mut serializer = AllocSerializer::<256>::default();
//     serializer.write(&[kind as u8])?;
//     serializer.serialize_value(&value)?;
// }