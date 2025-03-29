use rusqlite::{Connection, params};
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::database::get_db_path;

pub fn fetch_unsynced_messages(peer_id: &str) -> Vec<String> {
    let mut conn = match Connection::open(get_db_path()) {
        Ok(conn) => conn,
        Err(_) => return Vec::new(),
    };

    // Find messages that need to be synced with this peer
    // Either sent to this peer or received from this peer but not in the sync log
    let mut stmt = match conn.prepare(
        "SELECT m.id, m.content
     FROM Messages m
     WHERE (m.sender_id = ?1 OR m.receiver_id = ?1)
     AND NOT EXISTS (
         SELECT 1 FROM Message_Sync_Log s
         WHERE s.message_id = m.id AND s.peer_id = ?1
     )"
    ) {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };

    let message_iter = match stmt.query_map(params![peer_id], |row| {
        let id: String = row.get(0)?;
        let content: String = row.get(1)?;
        Ok((id, content))
    }) {
        Ok(iter) => iter,
        Err(_) => return Vec::new(),
    };

    let messages_to_sync: Vec<(_,_)>= message_iter.filter_map(Result::ok).collect();
    let mut messages_to_send = Vec::new();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    drop(stmt); // drop stmt so it drops the borrow on conn so we can open a transaction

    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(_) => return Vec::new(),
    };

    for (message_id, content) in messages_to_sync {
        messages_to_send.push(content);

        // Log that we've synced this message with this peer
        let _ = tx.execute(
            "INSERT INTO Message_Sync_Log (id, message_id, peer_id, timestamp, sync_status)
             VALUES (?1, ?2, ?3, ?4, 'sent')",
            params![
                Uuid::now_v7().to_string(),
                message_id,
                peer_id,
                timestamp.to_string()
            ],
        );

        // Update message status to 'delivered' if it was 'pending'
        let _ = tx.execute(
            "UPDATE Messages SET status = 'delivered'
             WHERE id = ?1 AND status = 'pending'",
            params![message_id],
        );
    }

    let _ = tx.commit();

    messages_to_send
}

// Add a function to mark messages as seen
pub fn mark_messages_as_seen(message_ids: Vec<String>) -> bool {
    let conn = match Connection::open(get_db_path()) {
        Ok(conn) => conn,
        Err(_) => return false,
    };

    if message_ids.is_empty() {
        return true;
    }

    // Create a parameter string with the right number of placeholders
    let params_str: Vec<String> = (0..message_ids.len()).map(|i| format!("?{}", i+1)).collect();
    let query = format!(
        "UPDATE Messages SET status = 'seen' WHERE id IN ({})",
        params_str.join(",")
    );

    // Convert Vec<String> to Vec<&str> for rusqlite params
    let params: Vec<&str> = message_ids.iter().map(|s| s.as_str()).collect();

    match conn.execute(&query, rusqlite::params_from_iter(params.iter())) {
        Ok(_) => true,
        Err(_) => false,
    }
}