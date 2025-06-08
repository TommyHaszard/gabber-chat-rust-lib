mod common;

use crate::common::*;
use gabber_chat_lib::libs::encryption::double_ratchet::RealKeyGenerator;
use gabber_chat_lib::libs::models::{IdentityKey, MessageType};
use gabber_chat_lib::libs::storage::database::database::DATABASE;
use gabber_chat_lib::libs::storage::database::storage_sqllite::SqliteTransaction;
use gabber_chat_lib::libs::storage::records::{SessionRecord, UserRecord};
use gabber_chat_lib::libs::storage::storage_traits::{
    MessageStore, SessionStore, Transactional, UserStore,
};
use gabber_chat_lib::*;
use std::sync::Once;

static TEST_DIR: &str = "./tests/test_db_dir";
static INIT: Once = Once::new();
// db_path is global and tests run parallel without cargo test --test-threads=1
// causing db_path issues

// before all -> setup_test_db
// after each clear the db
#[test]
pub fn aaa_db_initalisation() {
    aaa_init(&INIT, TEST_DIR, "database")
}

#[test]
fn test_create_user() {
    let result = create_user("test_user".to_string(), [1; 32].to_vec());
    assert!(result.is_ok(), "Creating a user should succeed");

    // Test duplicate user creation (assuming this should fail)
    let dup_result = create_user("test_user".to_string(), [2; 32].to_vec());
    assert!(dup_result.is_err(), "Creating duplicate user should fail");

    cleanup_test_db()
}

#[test]
fn test_storing_retrieving_session() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let bob_username = "BOB".to_string();
    let bob_device_identity = IdentityKey::from([2; 16]);
    let public_key = [1; 32];

    let mut tx_1 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    tx_1.create_user(bob_username.clone(), public_key.try_into().unwrap())
        .expect("Failed to create BOB");

    tx_1.commit();

    let mut tx_2 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");
    let bob_user = tx_2
        .load_user_by_name(&bob_username)
        .expect("Failed to load Bob from DB");

    assert!(&bob_username.eq(&bob_user.username));

    let alice_ad = b"ALICE_ASSOCIATED_DATA";
    let bob_ad = b"BOB_ASSOCIATED_DATA";
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob_double_ratchet) = ratchet_init(real_gen);

    println!("BobUserId: {:?}", &bob_user.user_id);
    let bob_session = SessionRecord::new(
        &bob_user.user_id.clone(),
        bob_double_ratchet.clone(),
        bob_device_identity,
        true,
    );

    tx_2.store_session(&bob_session)
        .expect("Failed to store Bob Session");
    tx_2.commit();

    let mut tx_3 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");
    let bob_session_retrieved = tx_3
        .load_active_session(&bob_user.user_id)
        .expect("Failed to load Bob Session");
    assert_eq!(bob_session.session_id, bob_session_retrieved.session_id);

    cleanup_test_db()
}

#[test]
fn test_storing_retrieving_message() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let mut tx_1 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let bob_username = "BOB".to_string();
    let public_key = [1; 32];

    tx_1.create_user(bob_username.clone(), public_key.try_into().unwrap())
        .expect("Failed to create BOB");

    tx_1.commit();

    let mut tx_2 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let bob_user = tx_2
        .load_user_by_name(&bob_username)
        .expect("Failed to retrieve User after persisting");

    let message_type = MessageType::Received;
    let message_content = "Test Message 1";

    tx_2.store_message(&bob_user.public_key, &message_type, message_content)
        .expect("Fail to store message.");

    tx_2.commit();

    let mut tx_3 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let messages = tx_3
        .retrieve_message_for_recipient(&bob_user.public_key)
        .expect("Failed to retrieve message");

    assert_eq!(messages.len(), 1);

    let message = messages.get(0).unwrap();

    assert_eq!(message.message_type, message_type);
    assert_eq!(message.content, message_content);
    assert_eq!(
        message.recipient_public_key.as_bytes(),
        message.recipient_public_key.as_bytes()
    )

    //cleanup_test_db()
}

#[test]
fn test_mark_messages_as_seen() {
    let pub_key1 = [1; 32].to_vec();
    let pub_key2 = [2; 32].to_vec();
    // Create users
    create_user("user1".to_string(), pub_key1).unwrap();
    create_user("user2".to_string(), pub_key2).unwrap();
    cleanup_test_db()
}

// #[test]
// pub fn zzz_db_teardown() {
//     if Path::new(TEST_DIR).exists() {
//         fs::remove_dir_all(TEST_DIR).expect("Failed to clean up test directory");
//     }
// }
