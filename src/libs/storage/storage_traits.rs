use crate::libs::encryption::double_ratchet::{DoubleRatchet, SymmetricChainState};
use crate::libs::models::{IdentityKey, MessageType};
use crate::libs::storage::records::{MessageRecord, SessionRecord, UserRecord};
use crate::DatabaseError;
use bincode::config::standard;
use bincode::error::EncodeError;
use rusqlite::params;
use std::{fmt, format};
use thiserror::Error;
use x25519_dalek::PublicKey;

pub trait Storage {
    type Transaction<'s>: Transactional + ProtocolStore + 's
    where
        Self: 's;
}

pub trait Transactional {
    fn commit(self) -> Result<(), StoreError>;
    fn rollback(self) -> Result<(), StoreError>;
}

pub trait UserStore {
    fn store_user(&mut self, record: &UserRecord) -> Result<(), StoreError>;
    fn create_user(&mut self, username: String, public_key: [u8; 32]) -> Result<(), StoreError>;
    fn load_user_by_name(&mut self, user_id: &String) -> Result<UserRecord, StoreError>;
    fn load_user_by_id(&mut self, user_id: IdentityKey) -> Result<UserRecord, StoreError>;
}

pub trait SessionStore {
    fn load_sessions(&mut self, message_from: &IdentityKey) -> Result<SessionRecord, StoreError>;

    fn load_active_session(
        &mut self,
        message_from: &IdentityKey,
    ) -> Result<SessionRecord, StoreError>;
    fn create_session(
        &mut self,
        peer_id: &IdentityKey,
        peer_device: &IdentityKey,
        double_ratchet: &DoubleRatchet,
    ) -> std::result::Result<(), StoreError>;
    fn store_session(&mut self, record: &SessionRecord) -> Result<(), StoreError>;
}

pub trait SymmetricChainStore {
    fn store_symmetric_chain_state(
        &mut self,
        session_id: &IdentityKey,
        chain_identifier: &str,
        state: &SymmetricChainState,
    ) -> Result<(), StoreError>;

    fn load_symmetric_chain_state(
        &mut self,
        session_id: &IdentityKey,
        chain_identifier: &str,
    ) -> Result<Option<SymmetricChainState>, StoreError>;
}

pub trait MessageStore {
    fn store_message(
        &mut self,
        peer: &PublicKey,
        message_type: &MessageType,
        content: &str,
    ) -> Result<(), StoreError>;

    fn retrieve_message_for_recipient(
        &mut self,
        peer: &PublicKey,
    ) -> Result<Vec<MessageRecord>, StoreError>;
}

pub trait ProtocolStore: SessionStore + SymmetricChainStore + UserStore + MessageStore {}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Database Error: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("Sqlite Error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("ConnectionPool Error: {0}")]
    ConnectionPoolError(#[from] r2d2::Error),
    #[error("Serialisation Error: {0}")]
    SerialisationError(#[from] EncodeError),
    #[error("Deserialisation Error: {0}")]
    DeserialisationError(String),
    #[error("User Already Exists: {0}")]
    UserAlreadyExists(String),
}
// impl fmt::Display for StoreError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             StoreError::DatabaseError(str) => write!(f, "{}", str),
//             StoreError::SqliteError(str) => write!(f, "Sqlite Error: {}", str),
//             StoreError::SerialisationError(str) => write!(f, "{}", str),
//             StoreError::DeserialisationError(str) => write!(f, "{}", str),
//             StoreError::UserAlreadyExists(str) => write!(f, "{}", str),
//         }
//     }
// }

// impl From<rusqlite::Error> for StoreError {
//     fn from(err: rusqlite::Error) -> StoreError {
//         StoreError::SqliteError(err)
//     }
// }
//
// impl From<DatabaseError> for StoreError {
//     fn from(err: DatabaseError) -> Self {
//         StoreError::DatabaseError(err)
//     }
// }
