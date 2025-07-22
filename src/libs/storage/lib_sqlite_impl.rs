use x25519_dalek::PublicKey;
use crate::libs::core::models::{IdentityKey, PublicKeyInternal};
use crate::libs::storage::database::database;
use crate::libs::storage::database::database::DATABASE;
use crate::libs::storage::database::storage_sqllite::SqliteTransaction;
use crate::libs::storage::database::storage_traits::StoreError::Database;
use crate::libs::storage::database::storage_traits::{MessageStore, Transactional, UserStore};
use crate::libs::storage::records::{MessageRecord, UserRecord};
use crate::DatabaseError;

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
        .create_user(name,public_key)
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

    let user_records = user_results
        .into_iter()
        .flat_map(|user| user)
        .collect::<Vec<UserRecord>>();

    sqlite_transaction.commit();
    Ok(user_records)
}
