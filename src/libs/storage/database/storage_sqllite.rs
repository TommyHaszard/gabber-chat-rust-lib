use crate::libs::chat_initalisation::IdentityKey;
use crate::libs::encryption::double_ratchet::{KeySecret, MessageId, SymmetricChainState};
use crate::libs::storage::database::database::get_db_path;
use crate::libs::storage::records::{SessionRecord, UserRecord};
use crate::libs::storage::storage_traits::{
    ProtocolStore, SessionStore, StoreError, SymmetricChainStore, UserStore,
};
use crate::DatabaseError;
use bincode::config::standard;
use rusqlite::{params, Connection, OptionalExtension, Result};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct SqliteStore {}

impl ProtocolStore for SqliteStore {}

impl SqliteStore {
    pub fn generate_chain_record_id(session_id: &str, chain_identifier: &str) -> String {
        format!("{}_{}", session_id, chain_identifier)
    }
}

impl UserStore for SqliteStore {
    fn load_user(
        conn: &Connection,
        message_from: IdentityKey,
    ) -> std::result::Result<UserRecord, StoreError> {
        let     conn = Connection::open(get_db_path())
            .map_err(|e| DatabaseError::StorageError(e.to_string()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut stmt = conn.prepare("SELECT data FROM user WHERE userid = ?")?;
        //let sender_exists  = stmt.query_row([message_from.uuid], |row| row.get::<usize, Vec<u8>>(0)).map_err(|_| DatabaseError::StorageError)?;
        todo!()
    }

    fn store_user(conn: &Connection, record: &UserRecord) -> Result<(), StoreError> {
        conn.execute(
            "INSERT INTO Users (id, name, public_key) VALUES (?1, ?2, ?3)",
            params![
                record.user_id.uuid.to_string(),
                record.username,
                record.public_key.as_bytes(),
            ],
        )
        .map_err(|e| DatabaseError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn create_user(
        conn: &Connection,
        username: String,
        public_key: [u8; 32],
    ) -> Result<(), StoreError> {
        // check username already exists and fail

        // let mut stmt = conn.prepare("SELECT data FROM user WHERE userid = ?")?;
        // let sender_exists= stmt.query_row([username], |row| row.get::<usize, Vec<u8>>(0)).map_err(|e| DatabaseError::StorageError(e.to_string()))?;
        // if sender_exists {
        //     return Err(StoreError::)
        // }

        conn.execute(
            "INSERT INTO Users (user_id, username, public_key) VALUES (?1, ?2, ?3)",
            params![Uuid::now_v7().to_string(), username, public_key],
        )
        .map_err(|e| DatabaseError::StorageError(e.to_string()))?;
        Ok(())
    }
}

impl SessionStore for SqliteStore {
    fn load_session(
        conn: &Connection,
        message_from: IdentityKey,
    ) -> std::result::Result<SessionRecord, StoreError> {
        let conn = Connection::open(get_db_path())
            .map_err(|e| DatabaseError::StorageError(e.to_string()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut stmt = conn.prepare("SELECT data FROM user WHERE userid = ?")?;
        todo!()
    }

    fn store_session(
        conn: &Connection,
        record: &SessionRecord,
        message_from: IdentityKey,
    ) -> std::result::Result<(), StoreError> {
        todo!()
    }
}

impl SymmetricChainStore for SqliteStore {
    fn store_symmetric_chain_state(
        conn: &Connection,
        session_id: &str,
        chain_identifier: &str,
        state: &SymmetricChainState,
    ) -> Result<(), StoreError> {
        let record_id = Self::generate_chain_record_id(session_id, chain_identifier);
        let skipped_keys_data = bincode::encode_to_vec(&state.skipped_keys, standard())
            .map_err(|e| StoreError::SerialisationError(e.to_string()))?;

        conn.execute(
            "INSERT OR REPLACE INTO SymmetricChainRecords
         (record_id, session_id, chain_identifier, chain_key, message_count, skipped_keys_data, last_updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%s', 'now'))",
            params![
            record_id,
            session_id,
            chain_identifier,
            state.chain_key.as_slice(),
            state.message_count,
            skipped_keys_data
        ],
        )?;
        Ok(())
    }

    fn load_symmetric_chain_state(
        conn: &Connection,
        session_id: &str,
        chain_identifier: &str,
    ) -> std::result::Result<Option<SymmetricChainState>, StoreError> {
        let record_id = Self::generate_chain_record_id(session_id, chain_identifier);

        let result = conn
            .query_row(
                "SELECT chain_key, message_count, skipped_keys_data
             FROM SymmetricChainRecords
             WHERE record_id = ?1",
                params![record_id],
                |row| {
                    let chain_key_bytes: Vec<u8> = row.get(0)?;
                    let chain_key: KeySecret = chain_key_bytes.try_into().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            "Failed to convert Vec<u8> to KeySecret".into(),
                        )
                    })?;

                    let message_count: u32 = row.get(1)?;
                    let skipped_keys_data: Vec<u8> = row.get(2)?;

                    let (skipped_keys, _len): (HashMap<MessageId, KeySecret>, usize) =
                        bincode::decode_from_slice(&skipped_keys_data, standard()).map_err(
                            |e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    2,
                                    rusqlite::types::Type::Blob,
                                    Box::new(e),
                                )
                            },
                        )?;

                    Ok(SymmetricChainState {
                        chain_key,
                        message_count,
                        skipped_keys,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }
}
