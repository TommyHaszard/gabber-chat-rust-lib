pub mod libs;
use crate::libs::storage::database::storage_sqllite::{SqliteStore, SqliteTransaction};
use crate::libs::storage::database::{database, storage_sqllite};
use crate::libs::storage::storage_traits::{Storage, UserStore};
use crate::libs::*;
use rusqlite::Connection;
use std::error::Error;
use std::fmt;
use std::fmt::write;
use crate::libs::storage::database::database::DATABASE;

uniffi::include_scaffolding!("gabber_chat_lib");

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

pub fn init_database(path: String) {
    let _ = database::initialize_database(path);
}

pub fn create_user(name: String, public_key: Vec<u8>) -> Result<(), DatabaseError> {
    let database_pool= DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err))).unwrap();
    // Just verify the connection works
    if public_key.len() != 32 {
        return Err(DatabaseError::InvalidLength(32, public_key.len()));
    }
    sqlite_transaction.create_user( name, public_key.try_into().unwrap())
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;
    Ok(())
}

pub fn send_message(
    receiver: String,
    content: String,
) -> Result<(), DatabaseError> {
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
