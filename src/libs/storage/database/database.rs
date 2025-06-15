use rusqlite::{Connection, Result};
use std::cell::OnceCell;
use std::sync::{Mutex, Once, OnceLock};

use crate::libs::storage::database::storage_sqllite::{SqliteStore, SqliteTransaction};
use crate::libs::storage::storage_traits::{Storage, StoreError, Transactional};
use crate::DatabaseError;

static INIT: Once = Once::new();
pub static DATABASE: OnceLock<SqliteStore> = OnceLock::new();

pub(crate) fn initialize_database(path: String) -> Result<(), DatabaseError> {
    // Now you can get the database instance:
    if let Some(db) = DATABASE.get() {
        // Use the database (e.g., get a transaction, perform queries)
        let database_pool = DATABASE.get().unwrap();
        let mut connection = database_pool.new_connection().unwrap();

        let sqlite_transaction = SqliteTransaction::new(&mut connection)
            .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))?;
        // Just verify the connection works
        sqlite_transaction
            .inner()
            .execute("SELECT 1", [])
            .map_err(|e| DatabaseError::InitializationError(e.to_string()))?;
        println!("Database initialized and ready to use!");
    } else {
        db_migration(path)?;
    }

    Ok(())
}

pub fn db_migration(path: String) -> Result<(), DatabaseError> {
    let db_store = SqliteStore::new(&path);
    DATABASE
        .set(db_store)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))
        .unwrap();

    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();

    let sqlite_transaction = SqliteTransaction::new(&mut connection)
        .map_err(|err| DatabaseError::InitializationError(format!("{:?}", err)))
        .unwrap();

    sqlite_transaction
        .inner()
        .execute("PRAGMA foreign_keys = ON", [])
        .expect("Failed to enforce foreign keys constraints.");

    sqlite_transaction
        .inner()
        .execute(
            "CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                public_key BLOB,
                is_stale BOOLEAN NOT NULL DEFAULT false
        );",
            [],
        )
        .map_err(|e| DatabaseError::InitializationError(e.to_string()))
        .unwrap();

    // messages that have either been decrypted or before they are encrypted and sent
    sqlite_transaction
        .inner()
        .execute(
            "CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT PRIMARY KEY,
            recipient_id BLOB NOT NULL,
            message_type TEXT NOT NULL,
            content BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),

            CHECK (message_type IN ('sent', 'received', 'passing'))
        );",
            [],
        )
        .map_err(|e| DatabaseError::InitializationError(e.to_string()))
        .unwrap();

    sqlite_transaction
        .inner()
        .execute(
            "CREATE TABLE IF NOT EXISTS devices (
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                public_key BLOB,
                bluetooth_id TEXT NOT NULL UNIQUE,
                identity_key_pair BLOB NOT NULL,
                is_stale BOOLEAN NOT NULL DEFAULT false,

                PRIMARY KEY (user_id, device_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );",
            [],
        )
        .map_err(|e| DatabaseError::InitializationError(e.to_string()))
        .unwrap();

    sqlite_transaction.inner().execute(
        "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                remote_device_id TEXT NOT NULL,
                remote_user_id TEXT NOT NULL,
                session_record BLOB,
                is_active_session BOOLEAN NOT NULL DEFAULT false,
                inactive_order INTEGER,
                last_updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),

                --FOREIGN KEY (remote_device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE,
                FOREIGN KEY (remote_user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );",
        [],
    ).map_err(|e| DatabaseError::InitializationError(e.to_string())).unwrap();

    sqlite_transaction
        .inner()
        .execute_batch(
            r#"CREATE TABLE IF NOT EXISTS symmetric_chain_records (
            record_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            chain_identifier TEXT NOT NULL,
            chain_key BLOB NOT NULL,
            message_count INTEGER NOT NULL,
            skipped_keys_data BLOB NOT NULL,
            last_updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),

            FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            );
        "#,
        )
        .map_err(|e| DatabaseError::InitializationError(e.to_string()))?;

    sqlite_transaction
        .inner()
        .execute(
            "CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );",
            [],
        )
        .map_err(|e| DatabaseError::InitializationError(e.to_string()))
        .unwrap();

    sqlite_transaction
        .inner()
        .execute(
            "INSERT INTO app_settings (key, value) VALUES
                ('max_relay_hops', '3'),
                ('bluetooth_discovery_interval', '300'),
                ('message_retention_days', '90'),
                ('app_version', '0.0.1');",
            [],
        )
        .map_err(|e| DatabaseError::InitializationError(e.to_string()))
        .unwrap();

    sqlite_transaction.inner().execute(
        "CREATE TRIGGER IF NOT EXISTS cleanup_old_messages
            AFTER UPDATE ON app_settings
            WHEN NEW.key = 'message_retention_days'
            BEGIN
                DELETE FROM Messages
                WHERE created_at < strftime('%s', 'now') - (NEW.value * 86400)
                AND conversation_id NOT IN (SELECT conversation_id FROM Conversations WHERE is_pinned = 1);
            END;",
        [],
    ).map_err(|e| DatabaseError::InitializationError(e.to_string()))?;

    sqlite_transaction.commit().map_err(|err| {
        DatabaseError::InitializationError("Could not commit inital db.".to_string())
    })?;

    Ok(())
}
