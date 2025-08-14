use std::fmt;
use hmac::digest::typenum::Mod;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
use rusqlite::ToSql;
use uuid::Uuid;
use crate::DatabaseError;

pub enum ModelError {
    ConversionError(String, usize),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ModelError::ConversionError(str,len) => write!(f, "{}- len: {}", str, len),
        }
    }
}


#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct IdentityKey {
    pub uuid: Uuid,
}

impl TryFrom<Vec<u8>> for IdentityKey {
    type Error = ModelError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        identity_key_from_vec(vec)
    }
}

fn identity_key_from_vec(vec: Vec<u8>) -> Result<IdentityKey, ModelError> {
    let len = vec.len();
    if len > 16 {
        return Err(ModelError::ConversionError(
            "Vec Length greater then 16 bytes.".to_string(), len,
        ));
    }

    if len < 16 {
        return Err(ModelError::ConversionError(
            "Vec Length less then 16 bytes.".to_string(), len,
        ));
    }
    
    let bytes: [u8; 16] = vec.try_into().map_err(|_| {
        ModelError::ConversionError("Vec Length greater then 16 bytes.".to_string(), len)
    })?;

    Ok(IdentityKey::from(bytes))
}

impl From<IdentityKey> for Vec<u8> {
    fn from(id: IdentityKey) -> Self {
        id.uuid.as_bytes().to_vec()
    }
}

impl From<[u8; 16]> for IdentityKey {
    fn from(bytes: [u8; 16]) -> IdentityKey {
        Self {
            uuid: Uuid::from_bytes(bytes),
        }
    }
}

impl ToSql for IdentityKey {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.uuid.to_string()))
    }
}

impl FromSql for IdentityKey {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let uuid_str = value.as_str()?;
        // Parse the string into a Uuid
        Uuid::parse_str(uuid_str)
            .map(|uuid| IdentityKey { uuid })
            .map_err(|e| FromSqlError::Other(Box::new(e))) // Convert Uuid parse error
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PublicKeyInternal {
    pub bytes: Vec<u8>,
}
impl From<Vec<u8>> for PublicKeyInternal {
    fn from(bytes: Vec<u8>) -> PublicKeyInternal {
        PublicKeyInternal { bytes }
    }
}

impl From<[u8; 32]> for PublicKeyInternal {
    fn from(bytes: [u8; 32]) -> PublicKeyInternal {
        PublicKeyInternal {
            bytes: bytes.into(),
        }
    }
}

impl ToSql for PublicKeyInternal {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.bytes.as_slice()))
    }
}

impl FromSql for PublicKeyInternal {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let bytes = value.as_bytes()?.to_vec();
        Ok(PublicKeyInternal { bytes })
    }
}

#[derive(Debug, PartialEq)]
pub enum MessageType {
    Sent,
    Received,
    Passing,
}

impl FromSql for MessageType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let message_type = value.as_str()?;
        match message_type {
            "sent" => Ok(MessageType::Sent),
            "received" => Ok(MessageType::Received),
            "passing" => Ok(MessageType::Passing),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

impl ToSql for MessageType {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            MessageType::Sent => Ok(ToSqlOutput::from("sent")),
            MessageType::Received => Ok(ToSqlOutput::from("received")),
            MessageType::Passing => Ok(ToSqlOutput::from("passing")),
        }
    }
}
