use crate::libs::core::models::{IdentityKey, PublicKeyInternal};
use crate::libs::storage::database::database;
use crate::libs::storage::database::database::DATABASE;
use crate::libs::storage::database::storage_sqllite::SqliteTransaction;
use crate::libs::storage::database::storage_traits::StoreError::Database;
use crate::libs::storage::database::storage_traits::{MessageStore, Transactional, UserStore};
use crate::libs::storage::records::{MessageRecord, UserRecord};
use crate::DatabaseError;
use std::fmt::format;
use x25519_dalek::PublicKey;
use crate::libs::uniffi::models::Message;

pub fn init_database(path: String) -> Result<(), DatabaseError> {
    database::initialize_database(path)
}

pub fn load_current_user(device_id: &IdentityKey) -> Result<UserRecord, DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;
    let user_record = sqlite_transaction
        .load_user_by_device_id(device_id)
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(user_record)
}

pub fn create_user(name: String, public_key: &PublicKeyInternal) -> Result<(), DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    sqlite_transaction
        .create_user(name, public_key)
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(())
}

pub fn load_recent_message_per_user() -> Result<Vec<MessageRecord>, DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    let messages = sqlite_transaction
        .load_recent_messages_per_user()
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(messages)
}

pub fn load_users(user_ids: Vec<PublicKeyInternal>) -> Result<Vec<UserRecord>, DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    let user_results: Vec<Result<UserRecord, DatabaseError>> = user_ids
        .iter()
        .map(|id| {
            sqlite_transaction
                .load_user_by_pub_key(id)
                .map_err(|e| DatabaseError::RetrievalError(e.to_string()))
        })
        .collect();

    let user_records: Vec<UserRecord> = user_results.into_iter().filter_map(Result::ok).collect();

    sqlite_transaction.commit();
    Ok(user_records)
}

pub fn load_user_by_id(user_id: &IdentityKey) -> Result<UserRecord, DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    let user = sqlite_transaction
        .load_user_by_id(user_id)
        .map_err(|e| DatabaseError::RetrievalError(format!("{} {:?}", e.to_string(), user_id)))?;

    sqlite_transaction.commit();
    Ok(user)
}

pub fn load_user_by_public_key(pub_id: &PublicKeyInternal) -> Result<UserRecord, DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    let user = sqlite_transaction
        .load_user_by_pub_key(pub_id)
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(user)
}

pub fn load_messages_by_public_key(
    public_key_internal: &PublicKeyInternal,
) -> Result<Vec<MessageRecord>, DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    let user = sqlite_transaction
        .retrieve_message_for_public_key(&public_key_internal)
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(user)
}

pub fn save_message(public_key: &PublicKeyInternal, message: MessageRecord) -> Result<(), DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;

    sqlite_transaction.save_message(public_key, message).map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;
    sqlite_transaction.commit();
    Ok(())
}
