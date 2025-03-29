mod libs;

use std::error::Error;
use std::fmt;

use crate::libs::*;

uniffi::include_scaffolding!("gabber_chat_lib");


#[derive(Debug)]
pub enum DatabaseError {
    InitializationError,
    StorageError,
    SyncError,
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DatabaseError::InitializationError => write!(f, "Failed to initialize database"),
            DatabaseError::StorageError => write!(f, "Failed to store data"),
            DatabaseError::SyncError => write!(f, "Failed to sync with peer"),
        }
    }
}

impl Error for DatabaseError {}

pub fn init_database() {
    let _ = database::initialize_database();
}

pub fn create_user(name: String, public_key: String) -> Result<(), DatabaseError> {
    storage::create_user(&name, &public_key)
}

pub fn create_group(name: String, creator_id: String) -> Result<(), DatabaseError> {
    storage::create_group(&name, &creator_id)
}

pub fn send_message(sender: String, receiver: String, content: String) -> Result<(), DatabaseError> {
    storage::store_message(&sender, &receiver, &content)
}

pub fn sync_with_peer(peer_id: String) -> Vec<String> {
    sync::fetch_unsynced_messages(&peer_id)
}

pub fn mark_messages_as_seen(message_ids: Vec<String>) -> bool {
    sync::mark_messages_as_seen(message_ids)
}