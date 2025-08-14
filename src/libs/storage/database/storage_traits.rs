use crate::libs::core::models::{IdentityKey, MessageType, PublicKeyInternal};
use crate::libs::encryption::double_ratchet::{DoubleRatchet, SymmetricChainState};
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
    fn create_user(
        &mut self,
        username: String,
        public_key: &PublicKeyInternal,
    ) -> Result<(), StoreError>;
    fn load_user_by_name(&mut self, user_id: &String) -> Result<UserRecord, StoreError>;
    fn load_user_by_id(&mut self, user_id: &IdentityKey) -> Result<UserRecord, StoreError>;
    fn load_user_by_device_id(&mut self, device_id: &IdentityKey)
        -> Result<UserRecord, StoreError>;
    fn load_user_by_pub_key(
        &mut self,
        pub_key: &PublicKeyInternal,
    ) -> Result<UserRecord, StoreError>;
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
    ) -> Result<(), StoreError>;
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
        peer: &PublicKeyInternal,
        message_type: &MessageType,
        content: &str,
    ) -> Result<(), StoreError>;

    fn retrieve_message_for_public_key(
        &mut self,
        peer: &PublicKeyInternal,
    ) -> Result<Vec<MessageRecord>, StoreError>;

    fn load_recent_messages_per_user(&mut self) -> Result<Vec<MessageRecord>, StoreError>;

    fn save_message(&mut self, public_key: &PublicKeyInternal, message: MessageRecord) -> Result<(), StoreError>;
}

pub trait ProtocolStore: SessionStore + SymmetricChainStore + UserStore + MessageStore {}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Database Error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Sqlite Error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("ConnectionPool Error: {0}")]
    ConnectionPool(#[from] r2d2::Error),
    #[error("Serialisation Error: {0}")]
    Serialisation(#[from] EncodeError),
    #[error("Deserialisation Error: {0}")]
    Deserialisation(String),
    #[error("User Already Exists: {0}")]
    UserAlreadyExists(String),
    #[error("Transaction Error: {0}")]
    Transaction(String),
}
