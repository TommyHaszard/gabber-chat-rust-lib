use rusqlite::{Connection, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use crate::database::get_db_path;
use crate::DatabaseError;


pub fn store_message(sender: &str, receiver: &str, content: &str) -> Result<(), DatabaseError> {
    let mut conn = Connection::open(get_db_path())
        .map_err(|_| DatabaseError::StorageError)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let message_id = Uuid::now_v7().to_string();

    // First check if both sender and receiver exist - using a closure to limit stmt lifetime
    let (sender_exists, receiver_exists) = {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM Users WHERE id = ?")
            .map_err(|_| DatabaseError::StorageError)?;

        let sender_exists: i64 = stmt.query_row([sender], |row| row.get(0))
            .map_err(|_| DatabaseError::StorageError)?;

        let receiver_exists: i64 = stmt.query_row([receiver], |row| row.get(0))
            .map_err(|_| DatabaseError::StorageError)?;

        (sender_exists, receiver_exists)
    };

    if sender_exists == 0 || receiver_exists == 0 {
        return Err(DatabaseError::StorageError);
    }

    // Start a transaction to ensure data consistency
    let tx = conn.transaction()
        .map_err(|_| DatabaseError::StorageError)?;

    // Insert the message
    tx.execute(
        "INSERT INTO Messages (id, sender_id, receiver_id, group_id, content, timestamp, status)
     VALUES (?1, ?2, ?3, NULL, ?4, ?5, 'pending')",
        [&Uuid::now_v7().to_string(), sender, receiver, content, &timestamp.to_string()],
    ).map_err(|_| DatabaseError::StorageError)?;

    // Log the sync status
    tx.execute(
        "INSERT INTO Message_Sync_Log (id, message_id, peer_id, timestamp, sync_status)
     VALUES (?1, ?2, ?3, ?4, 'sent')",
        [&Uuid::now_v7().to_string(), &message_id, receiver, &timestamp.to_string()],
    ).map_err(|_| DatabaseError::StorageError)?;

    // Commit the transaction
    tx.commit()
        .map_err(|_| DatabaseError::StorageError)?;

    Ok(())
}

// Add a function to create a new user
pub fn create_user(name: &str, public_key: &str) -> Result<(), DatabaseError> {
    let conn = Connection::open(get_db_path())
        .map_err(|_| DatabaseError::StorageError)?;

    conn.execute(
        "INSERT INTO Users (id, name, public_key) VALUES (?1, ?2, ?3)",
        [&Uuid::now_v7().to_string(), name, public_key],
    ).map_err(|_| DatabaseError::StorageError)?;

    Ok(())
}

// Add a function to create a new group
pub fn create_group(name: &str, creator_id: &str) -> Result<(), DatabaseError> {
    let group_id = &Uuid::now_v7().to_string();
    let mut conn = Connection::open(get_db_path())
        .map_err(|_| DatabaseError::StorageError)?;

    let tx = conn.transaction()
        .map_err(|_| DatabaseError::StorageError)?;

    // Insert the group
    tx.execute(
        "INSERT INTO Groups (id, name) VALUES (?1, ?2)",
        [group_id, name],
    ).map_err(|_| DatabaseError::StorageError)?;

    // Add the creator as an admin
    tx.execute(
        "INSERT INTO Group_Members (group_id, user_id, role) VALUES (?1, ?2, 'admin')",
        [group_id, creator_id],
    ).map_err(|_| DatabaseError::StorageError)?;

    tx.commit()
        .map_err(|_| DatabaseError::StorageError)?;

    Ok(())
}