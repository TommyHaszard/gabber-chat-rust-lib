pub mod libs;
use crate::libs::storage::database::database::DATABASE;
use crate::libs::storage::database::storage_sqllite::{SqliteStore, SqliteTransaction};
use crate::libs::storage::database::{database, storage_sqllite};
use libs::storage::database::storage_traits::{Storage, Transactional, UserStore};
use std::error::Error;
use std::fmt;
use crate::libs::storage::lib_sqlite_impl;

uniffi::include_scaffolding!("gabber_chat_lib");

pub fn init_database(path: String) -> Result<(), DatabaseError> {
    lib_sqlite_impl::init_database(path)
}

pub fn load_current_user(device_id: String) -> Result<(), DatabaseError> {
    lib_sqlite_impl::load_current_user(device_id)    
}


pub fn create_user(name: String, public_key: Vec<u8>) -> Result<(), DatabaseError> {
    lib_sqlite_impl::create_user(name, public_key)
}

pub fn send_message(receiver: String, content: String) -> Result<(), DatabaseError> {
    todo!()
}

pub fn sync_with_peer(peer_id: String) -> Vec<String> {
    todo!()
}

pub fn mark_messages_as_seen(message_ids: Vec<String>) -> bool {
    todo!()
}

pub fn initialise_two_friend_nodes() -> bool {
    todo!()
}

#[derive(Debug)]
pub enum DatabaseError {
    InitializationError(String),
    StorageError(String),
    RetrievalError(String),
    SyncError,
    InvalidLength(usize, usize),
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DatabaseError::InitializationError(str) => write!(f, "{}", str),
            DatabaseError::StorageError(str) => write!(f, "{}", str),
            DatabaseError::RetrievalError(str) => write!(f, "{}", str),
            DatabaseError::SyncError => write!(f, "Failed to sync with peer"),
            DatabaseError::InvalidLength(expected, found) => write!(
                f,
                "Invalid length: Expected - {}, Found {}",
                expected, found
            ),
        }
    }
}

impl Error for DatabaseError {}
