use crate::DatabaseError;
use crate::libs::storage::database::database;
use crate::libs::storage::database::database::DATABASE;
use crate::libs::storage::database::storage_sqllite::SqliteTransaction;
use crate::libs::storage::database::storage_traits::{Transactional, UserStore};

pub fn init_database(path: String) -> Result<(), DatabaseError> {
    database::initialize_database(path)
}

pub fn load_current_user(device_id: String) -> Result<(), DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;
    sqlite_transaction
        .load_user_by_device_id(device_id.clone())
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(())
}


pub fn create_user(name: String, public_key: Vec<u8>) -> Result<(), DatabaseError> {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let mut sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;
    // Just verify the connection works
    if public_key.len() != 32 {
        return Err(DatabaseError::InvalidLength(32, public_key.len()));
    }
    sqlite_transaction
        .create_user(name, public_key.try_into().unwrap())
        .map_err(|e| DatabaseError::RetrievalError(e.to_string()))?;

    sqlite_transaction.commit();
    Ok(())
}
