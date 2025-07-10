use crate::libs::encryption::double_ratchet::{
    DoubleRatchet, KeySecret, MessageId, SymmetricChainState,
};
use crate::libs::storage::records::{MessageRecord, SessionRecord, UserRecord};
use crate::libs::storage::database::storage_traits::{
    MessageStore, ProtocolStore, SessionStore, Storage, StoreError, SymmetricChainStore,
    Transactional, UserStore,
};
use crate::DatabaseError;
use bincode::config::standard;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{params, Connection, Error, OptionalExtension, Result, Transaction};
use std::collections::HashMap;
use uuid::Uuid;
use x25519_dalek::PublicKey;
use crate::libs::core::models::{IdentityKey, MessageType};

pub struct SqliteTransaction<'conn> {
    tx: Transaction<'conn>,
}

impl<'conn> SqliteTransaction<'conn> {
    pub fn new(
        conn: &'conn mut PooledConnection<SqliteConnectionManager>,
    ) -> Result<Self, StoreError> {
        let trans = conn.transaction()?;
        Ok(Self { tx: trans })
    }

    pub fn inner(&self) -> &Transaction {
        &self.tx
    }
}

impl<'conn> Transactional for SqliteTransaction<'conn> {
    fn commit(self) -> Result<(), StoreError> {
        Ok(self.tx.commit()?)
    }

    fn rollback(self) -> Result<(), StoreError> {
        self.tx.rollback().map_err(StoreError::Sqlite)
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
        Ok(self.conn_pool.get()?)
    }
}

impl Storage for SqliteStore {
    type Transaction<'s>
        = SqliteTransaction<'s>
    where
        Self: 's;
}

impl<'conn> ProtocolStore for SqliteTransaction<'conn> {}

impl<'conn> UserStore for SqliteTransaction<'conn> {
    fn load_user_by_id(&mut self, user_id: IdentityKey) -> Result<UserRecord, StoreError> {
        let mut stmt = self.tx.prepare("SELECT data FROM user WHERE userid = ?")?;
        let user = stmt.query_row([&user_id], |row| {
            let pk_bytes: Vec<u8> = row.get(1)?;
            let public_key_array: [u8; 32] = pk_bytes.try_into().map_err(|_vec_err| {
                rusqlite::Error::FromSqlConversionFailure(
                    1, // Column index
                    rusqlite::types::Type::Blob,
                    "Public key blob was not 32 bytes long.".into(),
                )
            })?;
            let public_key = PublicKey::from(public_key_array);
            Ok(UserRecord {
                user_id: row.get(0)?,
                public_key,
                username: row.get(2)?,
                is_stale: row.get(3)?,
            })
        })?;
        Ok(user)
    }

    fn load_user_by_name(&mut self, user_name: &String) -> Result<UserRecord, StoreError> {
        let mut stmt = self
            .tx
            .prepare("SELECT user_id, username, public_key FROM users WHERE username = ?")?;
        let user = stmt.query_row([&user_name], |row| {
            let pk_bytes: Vec<u8> = row.get(2)?;
            let public_key_array: [u8; 32] = pk_bytes.try_into().map_err(|_vec_err| {
                rusqlite::Error::FromSqlConversionFailure(
                    1, // Column index
                    rusqlite::types::Type::Blob,
                    "Public key blob was not 32 bytes long.".into(),
                )
            })?;
            let public_key = PublicKey::from(public_key_array);
            Ok(UserRecord {
                user_id: row.get(0)?,
                username: row.get(1)?,
                public_key,
                is_stale: false,
            })
        })?;
        Ok(user)
    }

    fn store_user(&mut self, record: &UserRecord) -> Result<(), StoreError> {
        self.tx
            .execute(
                "INSERT INTO users (user_id, username, public_key) VALUES (?1, ?2, ?3)",
                params![
                    record.user_id.uuid.to_string(),
                    record.username,
                    record.public_key.as_bytes(),
                ],
            )
            .map_err(|e| DatabaseError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn create_user(&mut self, username: String, public_key: [u8; 32]) -> Result<(), StoreError> {
        // check username already exists and fail

        let count: i64 = self.tx.query_row(
            "SELECT COUNT(*) FROM users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )?;
        if count > 0 {
            return Err(StoreError::UserAlreadyExists(username));
        }

        self.tx
            .execute(
                "INSERT INTO users (user_id, username, public_key) VALUES (?1, ?2, ?3)",
                params![Uuid::now_v7().to_string(), username, public_key],
            )
            .map_err(|e| DatabaseError::StorageError(e.to_string()))?;

        Ok(())
    }

    fn load_user_by_device_id(&mut self, device_id: String) -> std::result::Result<UserRecord, StoreError> {
        let mut stmt = self
            .tx
            .prepare("SELECT user_id FROM devices WHERE device_id = ?")?;
        let user_identity_key = stmt.query_row([&device_id], |row| {
            let user_id: IdentityKey = row.get(0)?;
            Ok(user_id)
        })?;
        // close this stmt to allow reborrow
        match stmt.finalize() {
            Ok(_) => {
                self.load_user_by_id(user_identity_key)
            },
            Err(stmt_error) => {
                Err(StoreError::Transaction(format!("Failed to close stmt for retrieving User_Id from Device_id from table Device: {}", stmt_error)))
            }
        }
    }
}

impl<'conn> SessionStore for SqliteTransaction<'conn> {
    fn load_sessions(
        &mut self,
        message_from: &IdentityKey,
    ) -> std::result::Result<SessionRecord, StoreError> {
        let mut stmt = self.tx.prepare(
            "SELECT data FROM sessions WHERE remote_user_id = ? and is_active_session = true",
        )?;
        todo!("Return list of all Sessions for the person its from.")
    }

    fn load_active_session(
        &mut self,
        message_from: &IdentityKey,
    ) -> std::result::Result<SessionRecord, StoreError> {
        let mut stmt = self.tx.prepare("SELECT session_id, remote_user_id, remote_device_id, session_record, is_active_session, inactive_order FROM sessions WHERE remote_user_id = ? and is_active_session = true")?;
        Ok(stmt.query_row([&message_from], |row| {
            let dr_data: Vec<u8> = row.get(3)?;
            let (double_ratchet, _len): (DoubleRatchet, usize) =
                bincode::serde::decode_from_slice(&dr_data, standard()).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

            Ok(SessionRecord {
                session_id: row.get(0)?,
                remote_device_id: row.get(1)?,
                remote_user_id: row.get(2)?,
                double_ratchet,
                is_active_session: row.get(4)?,
                inactive_order: row.get(5)?,
            })
        })?)
    }

    fn create_session(
        &mut self,
        peer_id: &IdentityKey,
        peer_device: &IdentityKey,
        double_ratchet: &DoubleRatchet,
    ) -> std::result::Result<(), StoreError> {
        let double_ratchet_data = bincode::serde::encode_to_vec(&double_ratchet, standard())?;

        self.tx.execute(
            "INSERT OR REPLACE INTO sessions
             (session_id, remote_user_id, remote_device_id, session_record, is_active_session, inactive_order, last_updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%s', 'now'))",
            params![
                Uuid::now_v7().to_string(),
                peer_id,
                peer_device,
                double_ratchet_data,
                true,
                0,
            ],
        )?;

        Ok(())
    }

    fn store_session(&mut self, record: &SessionRecord) -> std::result::Result<(), StoreError> {
        let double_ratchet_data =
            bincode::serde::encode_to_vec(&record.double_ratchet, standard())?;

        self.tx.execute(
            "INSERT OR REPLACE INTO sessions
             (session_id, remote_user_id, remote_device_id, session_record, is_active_session, inactive_order, last_updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%s', 'now'))",
            params![
                record.session_id,
                record.remote_user_id,
                record.remote_device_id,
                double_ratchet_data,
                record.is_active_session,
                0,
            ],
        )?;

        Ok(())
    }
}

impl<'conn> SymmetricChainStore for SqliteTransaction<'conn> {
    fn store_symmetric_chain_state(
        &mut self,
        session_id: &IdentityKey,
        chain_identifier: &str,
        state: &SymmetricChainState,
    ) -> Result<(), StoreError> {
        let record_id = generate_chain_record_id(session_id, chain_identifier);
        let skipped_keys_data = bincode::encode_to_vec(&state.skipped_keys, standard())?;

        self.tx.execute(
            "INSERT OR REPLACE INTO symmetric_chain_records
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
        session_id: &IdentityKey,
        chain_identifier: &str,
    ) -> std::result::Result<Option<SymmetricChainState>, StoreError> {
        let record_id = generate_chain_record_id(session_id, chain_identifier);

        let result = self
            .tx
            .query_row(
                "SELECT chain_key, message_count, skipped_keys_data
             FROM symmetric_chain_records
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

impl<'conn> MessageStore for SqliteTransaction<'conn> {
    fn store_message(
        &mut self,
        peer: &PublicKey,
        message_type: &MessageType,
        content: &str,
    ) -> std::result::Result<(), StoreError> {
        self.tx
            .execute(
                "INSERT INTO messages(message_id, recipient_id, message_type, content) VALUES (?1, ?2, ?3, ?4)",
                params![
                    Uuid::now_v7().to_string(),
                    peer.as_bytes(),
                    message_type,
                    content
                ],
            )
            .map_err(|e| DatabaseError::StorageError(e.to_string()))?;

        Ok(())
    }

    fn retrieve_message_for_recipient(
        &mut self,
        peer: &PublicKey,
    ) -> std::result::Result<Vec<MessageRecord>, StoreError> {
        let mut stmt = self.tx.prepare(
            "SELECT message_id, message_type, content
             FROM messages
             WHERE recipient_id = ?",
        )?;

        let rows = stmt.query(params![peer.as_bytes()])?;

        let messages = rows
            .map(|row| {
                Ok(MessageRecord::from_db(
                    row.get(0)?,
                    peer.clone(),
                    MessageType::from(row.get(1)?),
                    row.get(2)?,
                ))
            })
            .collect()?;

        Ok(messages)
    }
}

pub fn generate_chain_record_id(session_id: &IdentityKey, chain_identifier: &str) -> String {
    format!("{}_{}", session_id.uuid, chain_identifier)
}
