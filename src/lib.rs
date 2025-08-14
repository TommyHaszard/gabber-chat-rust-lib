pub mod libs;

use crate::libs::core::models::{IdentityKey, MessageType, PublicKeyInternal};
use crate::libs::storage::lib_sqlite_impl;
use crate::libs::uniffi::models::{Message, User, UserType};
use libs::storage::database::storage_traits::{Storage, Transactional, UserStore};
use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use crate::libs::storage::records::{MessageRecord, UserRecord};

//uniffi::include_scaffolding!("ChatLib");
uniffi::setup_scaffolding!("ChatLib");

#[uniffi::export]
pub fn init_database(path: String) -> Result<(), DatabaseError> {
    lib_sqlite_impl::init_database(path)
}
#[uniffi::export]
pub fn load_current_user(device_id: Vec<u8>) -> Result<User, DatabaseError> {
    if device_id.len() != 16 {
        return Err(DatabaseError::InvalidLength(device_id.len() as i32, 16));
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

#[uniffi::export]
pub fn load_current_users_and_messages() -> Result<HashMap<User, Message>, DatabaseError> {
    let recent_message_per_user = lib_sqlite_impl::load_recent_message_per_user()?;
    let user_ids = recent_message_per_user
        .iter()
        .map(|message| message.recipient_public_key.clone())
        .collect();

    let user_records = lib_sqlite_impl::load_users(user_ids)?;

    let message_map: HashMap<IdentityKey, Message> = recent_message_per_user
        .into_iter()
        .filter_map(|message_record| {
            let maybe_user = user_records
                .iter()
                .find(|user| user.public_key.eq(&message_record.recipient_public_key));

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
#[uniffi::export]
pub fn create_user(name: String, public_key: Vec<u8>) -> Result<(), DatabaseError> {
    let public_key_internal = PublicKeyInternal::from(public_key);
    lib_sqlite_impl::create_user(name, &public_key_internal)
}

#[uniffi::export]
pub fn send_message(user_id: Vec<u8>, message: Message) -> Result<(), DatabaseError> {
    let user_record = retrieve_user_record_helper(user_id)?;
    let message_id = IdentityKey::try_from(message.message_id)
        .map_err(|err| DatabaseError::RetrievalError(err.to_string()))?;

    let message_record = MessageRecord {
        message_id,
        recipient_public_key: user_record.public_key.clone(),
        message_type: MessageType::Sent,
        content: message.content,
        created_at: message.created_at,
    };
    lib_sqlite_impl::save_message(&user_record.public_key, message_record)
}

#[uniffi::export]
pub fn load_user(user_id: Vec<u8>) -> Result<User, DatabaseError> {
    let user_record = retrieve_user_record_helper(user_id)?;
    Ok(User {
        user_id: user_record.user_id.uuid.as_bytes().to_vec(),
        username: user_record.username,
        user_type: UserType::Friend,
    })
}

#[uniffi::export]
pub fn load_messages_by_user_id(user_id: Vec<u8>) -> Result<Vec<Message>, DatabaseError> {
    let user_record = retrieve_user_record_helper(user_id)?;
    let public_key_internal = PublicKeyInternal::from(user_record.public_key);

    let message_records = lib_sqlite_impl::load_messages_by_public_key(&public_key_internal)?;
    let messages: Vec<Message> = message_records
        .into_iter()
        .filter_map(|message_record| {
            Option::from(Message {
                message_id: message_record.message_id.uuid.as_bytes().to_vec(),
                user_id: user_record.user_id.uuid.as_bytes().to_vec(),
                content: message_record.content.clone(),
                created_at: message_record.created_at.clone(),
                is_from_user: message_record.message_type == MessageType::Received,
            })
        })
        .collect();

    Ok(messages)
}

fn retrieve_user_record_helper(user_id: Vec<u8>) -> Result<UserRecord, DatabaseError> {
    if user_id.len() != 16 {
        return Err(DatabaseError::InvalidLength(user_id.len() as i32, 16));
    }

    let user_id_array: [u8; 16] = user_id
        .as_slice()
        .try_into()
        .map_err(|err| DatabaseError::RetrievalError("Try from Slice Error".to_string()))?;

    let identity_key = IdentityKey::from(user_id_array);

    let user_record = lib_sqlite_impl::load_user_by_id(&identity_key)?;
    Ok(user_record)
}

#[derive(Debug, uniffi::Error)]
pub enum DatabaseError {
    InitializationError(String),
    StorageError(String),
    RetrievalError(String),
    SyncError,
    InvalidLength(i32, i32),
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
