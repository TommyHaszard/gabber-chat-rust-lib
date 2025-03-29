use rusqlite::{Connection, Result};
use std::sync::{Mutex, Once};
use once_cell::sync::Lazy;

static INIT: Once = Once::new();
static DB_PATH: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new("messages.db".to_string()));

pub fn get_db_path() -> String {
    DB_PATH.lock().unwrap().clone()
}

pub fn set_db_path(path: &str) {
    let mut db_path = DB_PATH.lock().unwrap();
    *db_path = path.to_string();
}

pub fn initialize_database() -> Result<()> {
    let mut initialized = false;
    INIT.call_once(|| {
        let conn = Connection::open(get_db_path()).expect("Failed to open database");

        // Create Users table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                public_key TEXT UNIQUE
            )",
            [],
        ).expect("Failed to create Users table");

        // Create Groups table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL
            )",
            [],
        ).expect("Failed to create Groups table");

        // Create Group_Members table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Group_Members (
                group_id TEXT,
                user_id TEXT,
                role TEXT CHECK(role IN ('admin', 'member')),
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES Groups(id),
                FOREIGN KEY (user_id) REFERENCES Users(id)
            )",
            [],
        ).expect("Failed to create Group_Members table");

        // Create Messages table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT,
                receiver_id TEXT,
                group_id TEXT,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                status TEXT CHECK(status IN ('pending', 'delivered', 'seen')),
                FOREIGN KEY (sender_id) REFERENCES Users(id),
                FOREIGN KEY (receiver_id) REFERENCES Users(id),
                FOREIGN KEY (group_id) REFERENCES Groups(id)
            )",
            [],
        ).expect("Failed to create Messages table");

        // Create Message_Sync_Log table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Message_Sync_Log (
                id TEXT PRIMARY KEY,
                message_id TEXT,
                peer_id TEXT,
                timestamp INTEGER NOT NULL,
                sync_status TEXT CHECK(sync_status IN ('sent', 'received', 'error')),
                FOREIGN KEY (message_id) REFERENCES Messages(id)
            )",
            [],
        ).expect("Failed to create Message_Sync_Log table");

        // Create indexes for frequent queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sender ON Messages(sender_id)",
            [],
        ).expect("Failed to create sender index");

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_receiver ON Messages(receiver_id)",
            [],
        ).expect("Failed to create receiver index");

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_group ON Messages(group_id)",
            [],
        ).expect("Failed to create group index");

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_log_peer ON Message_Sync_Log(peer_id)",
            [],
        ).expect("Failed to create peer index");

        initialized = true;
    });

    if initialized {
        Ok(())
    } else {
        let conn = Connection::open(get_db_path())?;
        // Just verify the connection works
        conn.execute("SELECT 1", [])?;
        Ok(())
    }
}