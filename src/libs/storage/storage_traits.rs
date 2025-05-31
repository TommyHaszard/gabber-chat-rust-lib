use std::error::Error;
use std::fmt;
use rusqlite::Connection;
use uuid::Uuid;
use crate::DatabaseError;
use crate::libs::chat_initalisation::IdentityKey;
use crate::libs::encryption::double_ratchet::SymmetricChainState;
use crate::libs::storage::records::{SessionRecord, UserRecord};

#[derive(Debug)]
pub enum StoreError {
    DatabaseError(DatabaseError),
    Sqlite(String),
    SerialisationError(String)
}


impl fmt::Display for StoreError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StoreError::DatabaseError(str) => write!(f, "{}", str),
            StoreError::Sqlite(str) => write!(f, "Sqlite Error: {}", str),
            StoreError::SerialisationError(str) => write!(f, "{}", str),

        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> StoreError {
        StoreError::Sqlite(err.to_string())
    }
}

impl From<DatabaseError> for StoreError {
    fn from(err: DatabaseError) -> Self {
        StoreError::DatabaseError(err)
    }
}

pub trait Storage {
    type Transaction<'s>: Transactional + ProtocolStore + 's
    where
        Self: 's;
    fn get_transaction(&self) -> Self::Transaction;
}

pub trait Transactional {
    fn commit(self) -> Result<(), StoreError>;
    fn rollback(self) -> Result<(), StoreError>;
}


pub trait UserStore {
    fn load_user(&mut self, message_from: IdentityKey)-> Result<UserRecord, StoreError>;

    fn store_user(
        &mut self,
        record: &UserRecord,
    ) -> Result<(), StoreError>;
    fn create_user(&mut self, username: String, public_key: [u8; 32]) -> Result<(), StoreError>;
}

pub trait SessionStore {
    fn load_session(&mut self, message_from: IdentityKey)-> Result<SessionRecord, StoreError>;

    fn store_session(
        &mut self,
        record: &SessionRecord,
        message_from: IdentityKey
    ) -> Result<(), StoreError>;
}

pub trait SymmetricChainStore {
    fn store_symmetric_chain_state(
        &mut self,
        session_id: &str,
        chain_identifier: &str,
        state: &SymmetricChainState,
    ) -> Result<(), StoreError>;

    fn load_symmetric_chain_state(
        &mut self,
        session_id: &str,
        chain_identifier: &str,
    ) -> Result<Option<SymmetricChainState>, StoreError>;

}

pub trait ProtocolStore:
SessionStore + SymmetricChainStore + UserStore
{
}
