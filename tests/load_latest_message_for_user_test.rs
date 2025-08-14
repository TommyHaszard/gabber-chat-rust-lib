use crate::common::*;
use chacha20poly1305::aead::rand_core::RngCore;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rand::Rng;
use std::sync::Once;
use uuid::Uuid;
use ChatLib::libs::core::models::{IdentityKey, MessageType, PublicKeyInternal};
use ChatLib::libs::encryption::double_ratchet::{DHKeyGenerator, DoubleRatchet, RealKeyGenerator};
use ChatLib::libs::storage::database::database::DATABASE;
use ChatLib::libs::storage::database::storage_sqllite::SqliteTransaction;
use ChatLib::libs::storage::database::storage_traits::{
    MessageStore, SessionStore, Transactional, UserStore,
};
use ChatLib::libs::storage::records::SessionRecord;
use ChatLib::libs::storage::records::{MessageRecord, UserRecord};
use ChatLib::load_current_users_and_messages;

mod common;
static TEST_DIR: &str = "./tests/test_db_dir";
static INIT: Once = Once::new();

// Test helper struct to encapsulate common test data
struct TestData {
    bob_username: String,
    bob_device_identity: IdentityKey,
    public_key: PublicKeyInternal,
    alice_ad: &'static [u8],
    bob_ad: &'static [u8],
}

impl TestData {
    fn new(user: String) -> Self {
        let mut random_bytes: [u8; 32] = [0; 32];

        let mut rng = rand::rng();

        rng.fill(&mut random_bytes);

        Self {
            bob_username: user.to_string(),
            bob_device_identity: IdentityKey::from(*Uuid::now_v7().as_bytes()),
            public_key: PublicKeyInternal::from(random_bytes),
            alice_ad: b"ALICE_ASSOCIATED_DATA",
            bob_ad: b"ASSOCIATED_DATA",
        }
    }
}

impl Default for TestData {
    fn default() -> Self {
        Self {
            bob_username: "BOB".to_string(),
            bob_device_identity: IdentityKey::from([2; 16]),
            public_key: PublicKeyInternal::from([1; 32]),
            alice_ad: b"ALICE_ASSOCIATED_DATA",
            bob_ad: b"BOB_ASSOCIATED_DATA",
        }
    }
}

// Helper to create and setup a user in the database
fn setup_user_in_db(
    connection: &mut PooledConnection<SqliteConnectionManager>,
    username: &str,
    public_key: &PublicKeyInternal,
) -> Result<UserRecord, Box<dyn std::error::Error>> {
    let mut tx = SqliteTransaction::new(connection)?;

    tx.create_user(username.to_string(), public_key)?;
    tx.commit();

    let mut tx = SqliteTransaction::new(connection)?;
    let user = tx.load_user_by_name(&username.to_string())?;
    tx.commit();

    Ok(user)
}

// Helper to setup session in database
fn setup_session_in_db(
    connection: &mut PooledConnection<SqliteConnectionManager>,
    user_id: &IdentityKey,
    device_identity: &IdentityKey,
    double_ratchet: &DoubleRatchet,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = SqliteTransaction::new(connection)?;

    tx.create_session(user_id, device_identity, double_ratchet)?;
    tx.commit();

    Ok(())
}

// Helper to store message in database
fn store_message_in_db(
    connection: &mut PooledConnection<SqliteConnectionManager>,
    public_key: &PublicKeyInternal,
    message_type: &MessageType,
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = SqliteTransaction::new(connection)?;

    // SQL: INSERT INTO messages (public_key, message_type, content, created_at)
    //      VALUES (?, ?, ?, ?)
    tx.store_message(public_key, message_type, content);
    tx.commit();

    Ok(())
}

// Helper to retrieve messages from database
fn retrieve_messages_from_db(
    connection: &mut PooledConnection<SqliteConnectionManager>,
    public_key: &PublicKeyInternal,
) -> Result<Vec<MessageRecord>, Box<dyn std::error::Error>> {
    let mut tx = SqliteTransaction::new(connection)?;

    // SQL: SELECT * FROM messages WHERE public_key = ? ORDER BY created_at ASC
    let messages = tx.retrieve_message_for_public_key(public_key)?;
    tx.commit();

    Ok(messages)
}

// Helper to load active session
fn load_active_session_from_db(
    connection: &mut PooledConnection<SqliteConnectionManager>,
    user_id: &IdentityKey,
) -> Result<SessionRecord, Box<dyn std::error::Error>> {
    let mut tx = SqliteTransaction::new(connection)?;

    // SQL: SELECT * FROM sessions WHERE user_id = ? AND is_active = true
    let session = tx.load_active_session(user_id)?;
    tx.commit();

    Ok(session)
}

// Helper to update session in database
fn update_session_in_db(
    connection: &mut PooledConnection<SqliteConnectionManager>,
    session: &SessionRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = SqliteTransaction::new(connection)?;

    // SQL: UPDATE sessions SET double_ratchet_state = ?, updated_at = ?
    //      WHERE session_id = ?
    tx.store_session(session);
    tx.commit();

    Ok(())
}

#[test]
pub fn aaa_db_initialization() {
    aaa_init(&INIT, TEST_DIR, "latest_message_for_user_test")
}

#[test]
pub fn aab_generate_dummy_messages() {
    // --- Configuration ---
    // Here you can define how many users (x) and messages per user (y) to create.
    let num_users_to_create = 10;
    let num_messages_per_user = 20;

    println!(
        "Starting dummy data generation: {} users, {} messages each...",
        num_users_to_create, num_messages_per_user
    );

    // --- Database and RNG Setup ---
    let database_pool = DATABASE.get().expect("Failed to get database pool");
    let mut connection = database_pool
        .new_connection()
        .expect("Failed to get new connection");
    let mut rng = rand::thread_rng();

    // --- Main Generation Loop ---
    for i in 0..num_users_to_create {
        let username = format!("User_{}", i);

        // 1. Generate random user data and initialize a new crypto session for them.
        //    Each user needs their own double ratchet instance with the client.
        let test_data = TestData::new(username.clone());
        let mut real_gen = RealKeyGenerator::new();
        let (_alice, user_double_ratchet) = ratchet_init(real_gen);

        // 2. Create the user in the database.
        let user_record = setup_user_in_db(
            &mut connection,
            &test_data.bob_username, // 'bob_username' is the generic field in TestData
            &test_data.public_key,
        )
        .unwrap_or_else(|e| panic!("Failed to setup user {}: {:?}", username, e));

        // 3. Create a session record for this user.
        setup_session_in_db(
            &mut connection,
            &user_record.user_id,
            &test_data.bob_device_identity,
            &user_double_ratchet,
        )
        .unwrap_or_else(|e| panic!("Failed to setup session for {}: {:?}", username, e));

        // 4. Loop to generate and store messages for the current user.
        for j in 0..num_messages_per_user {
            // Randomly decide if the message was sent by the client or received from the user.
            let message_type = if rng.gen() {
                MessageType::Sent
            } else {
                MessageType::Received
            };

            let message_content = format!("Message #{} for conversation with {}.", j + 1, username);

            // Store the message. We use the user's public key to associate the message
            // with their conversation, regardless of whether it was sent or received.
            store_message_in_db(
                &mut connection,
                &user_record.public_key,
                &message_type,
                &message_content,
            )
            .unwrap_or_else(|e| panic!("Failed to store message {} for {}: {:?}", j, username, e));
        }
        println!(
            "Successfully generated {} messages for {}.",
            num_messages_per_user, username
        );
    }

    println!("\nDummy data generation complete!");

    let hashmap = load_current_users_and_messages().unwrap();
    println!("{:?}", hashmap)
    // In a data generation script, we typically want to keep the data,
    // so the cleanup function is not called.
}

fn test_user_creation_and_session_management() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let test_data = TestData::default();
    let mut real_gen = RealKeyGenerator::new();
    let (alice, bob_double_ratchet) = ratchet_init(real_gen);

    // Test 1: Create user
    let bob_user = setup_user_in_db(
        &mut connection,
        &test_data.bob_username,
        &test_data.public_key,
    )
    .expect("Failed to setup user");

    assert_eq!(test_data.bob_username, bob_user.username);

    // Test 2: Create session
    setup_session_in_db(
        &mut connection,
        &bob_user.user_id,
        &test_data.bob_device_identity,
        &bob_double_ratchet,
    )
    .expect("Failed to setup session");

    // Test 3: Retrieve session
    let bob_session = load_active_session_from_db(&mut connection, &bob_user.user_id)
        .expect("Failed to load active session");

    assert!(!bob_session.session_id.uuid.is_nil());

    cleanup_test_db_connection(&mut connection);
}

fn test_message_storage_and_encryption() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let test_data = TestData::default();
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, bob_double_ratchet) = ratchet_init(real_gen);

    // Setup user and session
    let bob_user = setup_user_in_db(
        &mut connection,
        &test_data.bob_username,
        &test_data.public_key,
    )
    .expect("Failed to setup user");

    setup_session_in_db(
        &mut connection,
        &bob_user.user_id,
        &test_data.bob_device_identity,
        &bob_double_ratchet,
    )
    .expect("Failed to setup session");

    let mut bob_session = load_active_session_from_db(&mut connection, &bob_user.user_id)
        .expect("Failed to load session");

    // Test message flow
    let message1 = "Hi Bob, this is Alice";
    let alice_public_key = PublicKeyInternal::from(alice.dhs.public.to_bytes());

    // Store message
    store_message_in_db(
        &mut connection,
        &alice_public_key,
        &MessageType::Sent,
        message1,
    )
    .expect("Failed to store message");

    // Retrieve messages
    let messages = retrieve_messages_from_db(&mut connection, &alice_public_key)
        .expect("Failed to retrieve messages");

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, message1);

    // Test encryption/decryption
    let (header, cipher) = alice
        .ratchet_encrypt(message1.as_bytes(), test_data.alice_ad, &mut real_gen)
        .unwrap();

    let decrypted = bob_session
        .double_ratchet
        .ratchet_decrypt(header, &cipher, test_data.alice_ad, &mut real_gen)
        .unwrap();

    assert_eq!(decrypted, message1.as_bytes());

    // Update session state
    update_session_in_db(&mut connection, &bob_session).expect("Failed to update session");

    cleanup_test_db_connection(&mut connection);
}

#[test]
fn test_multiple_messages_sequential() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let test_data = TestData::default();
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, bob_double_ratchet) = ratchet_init(real_gen);

    // Setup
    let bob_user = setup_user_in_db(
        &mut connection,
        &test_data.bob_username,
        &test_data.public_key,
    )
    .expect("Failed to setup user");

    setup_session_in_db(
        &mut connection,
        &bob_user.user_id,
        &test_data.bob_device_identity,
        &bob_double_ratchet,
    )
    .expect("Failed to setup session");

    let mut bob_session = load_active_session_from_db(&mut connection, &bob_user.user_id)
        .expect("Failed to load session");

    let alice_public_key = PublicKeyInternal::from(alice.dhs.public.to_bytes());
    let messages_to_send = vec![
        "First message from Alice",
        "Second message from Alice",
        "Third message from Alice",
    ];

    // Test encryption/decryption for each message in order
    for (i, message) in messages_to_send.iter().enumerate() {
        let (header, cipher) = alice
            .ratchet_encrypt(message.as_bytes(), test_data.alice_ad, &mut real_gen)
            .unwrap();

        let decrypted = bob_session
            .double_ratchet
            .ratchet_decrypt(header, &cipher, test_data.alice_ad, &mut real_gen)
            .unwrap();

        assert_eq!(decrypted, message.as_bytes());
    }

    // Store multiple messages
    for message in &messages_to_send {
        store_message_in_db(
            &mut connection,
            &alice_public_key,
            &MessageType::Sent,
            message,
        )
        .expect("Failed to store message");
    }

    // Retrieve all messages
    let retrieved_messages = retrieve_messages_from_db(&mut connection, &alice_public_key)
        .expect("Failed to retrieve messages");

    assert_eq!(retrieved_messages.len(), messages_to_send.len());

    // Test encryption/decryption for each message in order
    for (i, message) in messages_to_send.iter().enumerate() {
        assert_eq!(retrieved_messages[i].content, *message);

        let (header, cipher) = alice
            .ratchet_encrypt(message.as_bytes(), test_data.alice_ad, &mut real_gen)
            .unwrap();

        let decrypted = bob_session
            .double_ratchet
            .ratchet_decrypt(header, &cipher, test_data.alice_ad, &mut real_gen)
            .unwrap();

        assert_eq!(decrypted, message.as_bytes());
    }

    // Update session after all decryptions
    update_session_in_db(&mut connection, &bob_session).expect("Failed to update session");

    // cleanup_test_db_connection(&mut connection);
}

fn test_session_state_persistence() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let test_data = TestData::default();
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, bob_double_ratchet) = ratchet_init(real_gen);

    // Setup
    let bob_user = setup_user_in_db(
        &mut connection,
        &test_data.bob_username,
        &test_data.public_key,
    )
    .expect("Failed to setup user");

    setup_session_in_db(
        &mut connection,
        &bob_user.user_id,
        &test_data.bob_device_identity,
        &bob_double_ratchet,
    )
    .expect("Failed to setup session");

    // Load session, decrypt message, update session
    let mut bob_session_1 = load_active_session_from_db(&mut connection, &bob_user.user_id)
        .expect("Failed to load session");

    let message = "Test message for session state";
    let (header, cipher) = alice
        .ratchet_encrypt(message.as_bytes(), test_data.alice_ad, &mut real_gen)
        .unwrap();

    let decrypted_1 = bob_session_1
        .double_ratchet
        .ratchet_decrypt(header, &cipher, test_data.alice_ad, &mut real_gen)
        .unwrap();

    assert_eq!(decrypted_1, message.as_bytes());

    // Update session state in database
    update_session_in_db(&mut connection, &bob_session_1).expect("Failed to update session");

    // Load session again and verify state is preserved
    let bob_session_2 = load_active_session_from_db(&mut connection, &bob_user.user_id)
        .expect("Failed to load session second time");

    assert_eq!(bob_session_1.session_id, bob_session_2.session_id);
    // Note: You might want to add more specific state comparisons here
    // depending on what DoubleRatchet state should be preserved

    cleanup_test_db_connection(&mut connection);
}

// Helper function for cleanup
fn cleanup_test_db_connection(connection: &mut PooledConnection<SqliteConnectionManager>) {
    let mut tx = SqliteTransaction::new(connection).expect("Failed to create cleanup transaction");

    // SQL: DELETE FROM messages WHERE 1=1
    // SQL: DELETE FROM sessions WHERE 1=1
    // SQL: DELETE FROM users WHERE 1=1
    // (Implement cleanup_test_db method or call existing one)
    cleanup_test_db(tx);
}
