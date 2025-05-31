use crate::libs::chat_initalisation::IdentityKey;
use crate::libs::encryption::double_ratchet::{KeySecret, MessageId, SymmetricChainState};
use crate::libs::storage::records::{SessionRecord, UserRecord};
use crate::libs::storage::storage_traits::{ProtocolStore, SessionStore, Storage, StoreError, SymmetricChainStore, Transactional, UserStore};
use crate::DatabaseError;
use bincode::config::standard;
use rusqlite::{params, Connection, OptionalExtension, Result, Transaction};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use uuid::Uuid;

pub struct SqliteTransaction<'conn> {
    tx: Transaction<'conn>
}

impl<'conn> SqliteTransaction<'conn> {
    pub fn new(conn: &'conn mut PooledConnection<SqliteConnectionManager>) -> Result<Self, StoreError> {
        let trans = conn
            .transaction()
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        Ok(Self { tx: trans })
    }

    pub fn inner(&self) -> &Transaction {
        &self.tx
    }
}

impl<'conn> Transactional for SqliteTransaction<'conn> {
    fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().map_err(|e| StoreError::Sqlite(e.to_string()))
    }

    fn rollback(self) -> Result<(), StoreError> {
        self.tx.rollback().map_err(|e| StoreError::Sqlite(e.to_string()))
    }
}


#[derive(Debug)]
pub struct SqliteStore {
    conn_pool: Pool<SqliteConnectionManager>,
}

impl SqliteStore {
    pub fn new(db_path: &str) -> Self {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::new(manager).unwrap();
        Self { conn_pool: pool }
    }

    pub fn new_connection(&self) -> Result<PooledConnection<SqliteConnectionManager>, StoreError> {
        Ok(self.conn_pool.get().map_err(|err| StoreError::Sqlite(err.to_string()))?)
    }

}

impl Storage for SqliteStore {
    type Transaction<'s> = SqliteTransaction<'s>
    where
        Self: 's;
}


impl<'conn> ProtocolStore for SqliteTransaction<'conn> {

}

impl<'conn> UserStore for SqliteTransaction<'conn> {
    fn load_user(&mut self,
        message_from: IdentityKey,
    ) -> std::result::Result<UserRecord, StoreError> {
        let mut stmt = self.tx.prepare("SELECT data FROM user WHERE userid = ?")?;
        //let sender_exists  = stmt.query_row([message_from.uuid], |row| row.get::<usize, Vec<u8>>(0)).map_err(|_| DatabaseError::StorageError)?;
        todo!()
    }

    fn store_user(&mut self, record: &UserRecord) -> Result<(), StoreError> {
        self.tx.execute(
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
        &mut self,
        username: String,
        public_key: [u8; 32],
    ) -> Result<(), StoreError> {
        // check username already exists and fail

        // let mut stmt = conn.prepare("SELECT data FROM user WHERE userid = ?")?;
        // let sender_exists= stmt.query_row([username], |row| row.get::<usize, Vec<u8>>(0)).map_err(|e| DatabaseError::StorageError(e.to_string()))?;
        // if sender_exists {
        //     return Err(StoreError::)
        // }

        self.tx.execute(
            "INSERT INTO Users (user_id, username, public_key) VALUES (?1, ?2, ?3)",
            params![Uuid::now_v7().to_string(), username, public_key],
        )
        .map_err(|e| DatabaseError::StorageError(e.to_string()))?;
        Ok(())
    }
}

impl<'conn> SessionStore for SqliteTransaction<'conn> {
    fn load_session(
        &mut self,
        message_from: IdentityKey,
    ) -> std::result::Result<SessionRecord, StoreError> {

        let mut stmt = self.tx.prepare("SELECT data FROM user WHERE userid = ?")?;
        todo!()
    }

    fn store_session(&mut self,
        record: &SessionRecord,
        message_from: IdentityKey,
    ) -> std::result::Result<(), StoreError> {
        todo!()
    }
}

impl<'conn> SymmetricChainStore for SqliteTransaction<'conn> {
    fn store_symmetric_chain_state(
        &mut self,
        session_id: &str,
        chain_identifier: &str,
        state: &SymmetricChainState,
    ) -> Result<(), StoreError> {
        let record_id = generate_chain_record_id(session_id, chain_identifier);
        let skipped_keys_data = bincode::encode_to_vec(&state.skipped_keys, standard())
            .map_err(|e| StoreError::SerialisationError(e.to_string()))?;

        self.tx.execute(
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
        &mut self,
        session_id: &str,
        chain_identifier: &str,
    ) -> std::result::Result<Option<SymmetricChainState>, StoreError> {
        let record_id = generate_chain_record_id(session_id, chain_identifier);

        let result = self.tx
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

pub fn generate_chain_record_id(session_id: &str, chain_identifier: &str) -> String {
    format!("{}_{}", session_id, chain_identifier)
}
