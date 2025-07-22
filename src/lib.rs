pub mod libs;

use std::array::TryFromSliceError;
use std::collections::HashMap;
use crate::libs::core::models::{IdentityKey, MessageType, PublicKeyInternal};
use crate::libs::storage::lib_sqlite_impl;
use crate::libs::uniffi::models::{Message, User, UserType};
use libs::storage::database::storage_traits::{Storage, Transactional, UserStore};
use std::error::Error;
use std::fmt;
use bincode::serde::DecodeError::IdentifierNotSupported;

uniffi::include_scaffolding!("gabber_chat_lib");

pub fn init_database(path: String) -> Result<(), DatabaseError> {
    lib_sqlite_impl::init_database(path)
}

pub fn load_current_user(device_id: Vec<u8>) -> Result<User, DatabaseError> {

    if device_id.len() != 16 {
        return Err(DatabaseError::InvalidLength(device_id.len(), 16))
    }

    let device_array: [u8; 16] = device_id
        .as_slice()
        .try_into()
        .map_err(|err: TryFromSliceError| DatabaseError::RetrievalError(err.to_string()))?;
    
    let identity_key = IdentityKey::from(device_array);
    let user_record = lib_sqlite_impl::load_current_user(&identity_key)?;
    Ok(User {
        user_id: user_record.user_id.uuid.as_bytes().to_vec(),
        username: user_record.username,
        user_type: UserType::Current,
    })
}

pub fn load_current_users_and_messages() -> Result<HashMap<User, Message>, DatabaseError> {
    let recent_message_per_user = lib_sqlite_impl::load_recent_message_per_user()?;
    let user_ids = recent_message_per_user
        .iter()
        .map(|message| message.recipient_public_key.clone()).collect();
    
    let user_records = lib_sqlite_impl::load_users(user_ids)?;

    let message_map: HashMap<IdentityKey, Message> = recent_message_per_user
        .into_iter()
        .filter_map(|message_record| {
            let maybe_user = user_records
                .iter()
                .find(|user| user.public_key == message_record.recipient_public_key);

            maybe_user.map(|user| {
                let message = Message {
                    message_id: message_record.message_id.uuid.as_bytes().to_vec(),
                    user_id: user.user_id.clone().uuid.as_bytes().to_vec(),
                    content: message_record.content.clone(),
                    created_at: message_record.created_at.clone(),
                    is_from_user: message_record.message_type == MessageType::Received,
                };
                (user.user_id.clone(), message)
            })
        })
        .collect();    
    
    let result: HashMap<User, Message> = user_records
        .into_iter()
        .filter_map(|user_record| {
            let identity_key = user_record.user_id.clone();
            message_map.get(&identity_key).map(|message| {
                (
                    User {
                        user_id: user_record.user_id.uuid.as_bytes().to_vec(),
                        user_type: UserType::Friend,
                        username: user_record.username,
                    },
                    message.clone(),               
                )
            })
        })
        .collect();
    
    Ok(result)
}

pub fn create_user(name: String, public_key: Vec<u8>) -> Result<(), DatabaseError> {
    let public_key_internal= PublicKeyInternal::from(public_key);
    lib_sqlite_impl::create_user(name, &public_key_internal)
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
