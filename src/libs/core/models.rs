use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
use rusqlite::ToSql;
use uuid::Uuid;

enum ModelError {
    ConversionError(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct IdentityKey {
    pub uuid: Uuid,
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
