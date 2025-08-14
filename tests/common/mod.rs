use rand::rngs::OsRng;
use rand::TryRngCore;
use rusqlite::Connection;
use std::fs;
use std::path::Path;
use std::sync::Once;
use ChatLib::init_database;
use ChatLib::libs::encryption::double_ratchet::{DHKeyGenerator, DoubleRatchet};
use ChatLib::libs::storage::database::database::DATABASE;
use ChatLib::libs::storage::database::storage_sqllite::SqliteTransaction;
use ChatLib::libs::storage::database::storage_traits::Transactional;

pub fn aaa_init(init: &Once, dir: &str, prefix: &str) {
    init.call_once(|| {
        if Path::new(dir).exists() {
            fs::remove_dir_all(dir).expect("Failed to clean up existing test directory");
        }
        fs::create_dir_all(dir).expect("Failed to create test directory");
    });

    // Create a unique database file name for each test
    let db_path = format!(
        "{}/{}_{}.db",
        dir,
        prefix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos()
    );

    init_database(db_path.clone());
    assert!(
        Path::new(&db_path).exists(),
        "Database file should exist after initialization"
    );
}

pub fn cleanup_test_db(sqlite_transaction: SqliteTransaction) {
    sqlite_transaction
        .inner()
        .execute_batch(
            r#"
            DELETE FROM messages;
            DELETE FROM sessions;
            DELETE FROM symmetric_chain_records;
            DELETE FROM devices;
            DELETE FROM users;
            DELETE FROM app_settings;
            "#,
        )
        .expect("Failed to delete from users.");

    sqlite_transaction.commit().unwrap();
}

pub fn ratchet_init<DHKeyGen>(mut real_gen: DHKeyGen) -> (DoubleRatchet, DoubleRatchet)
where
    DHKeyGen: DHKeyGenerator,
{
    let mut shared_key = [0u8; 32];
    OsRng.try_fill_bytes(&mut shared_key);

    let bob_key_pair = real_gen.generate_dh();
    let alice_key_pair = real_gen.generate_dh();

    let alice = DoubleRatchet::initialise_alice(alice_key_pair, shared_key, bob_key_pair.public);
    let bob = DoubleRatchet::initialise_bob(shared_key, bob_key_pair, None);

    (alice, bob)
}
