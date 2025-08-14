use crate::common::*;
use chacha20poly1305::aead::rand_core::RngCore;
use std::sync::Once;
use ChatLib::libs::core::models::{IdentityKey, MessageType, PublicKeyInternal};
use ChatLib::libs::encryption::double_ratchet::{DHKeyGenerator, RealKeyGenerator};
use ChatLib::libs::storage::database::database::DATABASE;
use ChatLib::libs::storage::database::storage_sqllite::SqliteTransaction;
use ChatLib::libs::storage::database::storage_traits::{
    MessageStore, SessionStore, Transactional, UserStore,
};
use ChatLib::libs::storage::records::SessionRecord;

mod common;
static TEST_DIR: &str = "./tests/test_db_dir";
static INIT: Once = Once::new();

#[test]
pub fn aaa_db_initalisation() {
    aaa_init(&INIT, TEST_DIR, "integration")
}

#[test]
fn test_happy_path() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let bob_username = "BOB".to_string();
    let bob_device_identity = IdentityKey::from([2; 16]);
    let public_key = PublicKeyInternal::from([1; 32]);

    let mut tx_1 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    tx_1.create_user(bob_username.clone(), &public_key)
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
        &bob_user.user_id,
        bob_double_ratchet.clone(),
        bob_device_identity,
        true,
    );

    tx_2.store_session(&bob_session)
        .expect("Failed to store Bob Session");
    tx_2.commit().expect("Failed to persist code in the db");

    let mut tx_3 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");
    let mut bob_session_retrieved = tx_3
        .load_active_session(&bob_user.user_id)
        .expect("Failed to load Bob Session");
    assert_eq!(bob_session.session_id, bob_session_retrieved.session_id);

    let message1 = b"Hi Bob, this is Alice";
    let (header, cipher) = alice
        .ratchet_encrypt(message1, alice_ad, &mut real_gen)
        .unwrap();

    let plain_text = bob_session_retrieved
        .double_ratchet
        .ratchet_decrypt(header, &cipher, alice_ad, &mut real_gen)
        .unwrap();

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text.clone()),
        String::from_utf8_lossy(&message1.clone())
    );
    cleanup_test_db(tx_3)
}

#[test]
fn messaging_test() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let bob_username = "BOB".to_string();
    let bob_device_identity = IdentityKey::from([2; 16]);
    let public_key = PublicKeyInternal::from([1; 32]);

    let mut tx_1 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    tx_1.create_user(bob_username.clone(), &public_key)
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

    tx_2.create_session(&bob_user.user_id, &bob_device_identity, &bob_double_ratchet)
        .expect("Failed to store Bob Session");
    tx_2.commit().expect("Failed to persist code in the db");

    let mut tx_3 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");
    let mut bob_session_retrieved = tx_3
        .load_active_session(&bob_user.user_id)
        .expect("Failed to load Bob Session");

    let message1 = "Hi Bob, this is Alice";

    let public_key_internal = PublicKeyInternal::from(alice.dhs.public.to_bytes());

    // store and retrieve message from Sender to send to Receiver
    tx_3.store_message(&public_key_internal, &MessageType::Sent, &message1);
    tx_3.commit();

    let mut tx_4 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let messages = tx_4
        .retrieve_message_for_public_key(&public_key_internal)
        .expect("Failed to retrieve messages from db.");

    assert_eq!(messages.len(), 1);

    let message_retrieved = messages.get(0).unwrap();

    let (header, cipher) = alice
        .ratchet_encrypt(
            message_retrieved.content.as_bytes(),
            alice_ad,
            &mut real_gen,
        )
        .unwrap();

    let plain_text = bob_session_retrieved
        .double_ratchet
        .ratchet_decrypt(header, &cipher, alice_ad, &mut real_gen)
        .unwrap();

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text),
        &message1
    );

    assert_eq!(&plain_text, &message1.as_bytes());

    tx_4.store_session(&bob_session_retrieved);
    tx_4.commit();

    let mut tx_5 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let mut bob_session_retrieved2 = tx_5
        .load_active_session(&bob_user.user_id)
        .expect("Failed to load Bob Session");
    assert_eq!(
        bob_session_retrieved2.session_id,
        bob_session_retrieved.session_id
    );

    let message_2 = "Hi Bob, this is Alice_2";

    let public_key_internal = PublicKeyInternal::from(alice.dhs.public.to_bytes());
    // store and retrieve message from Sender to send to Receiver
    tx_5.store_message(&public_key_internal, &MessageType::Sent, &message_2);
    tx_5.commit();

    let mut tx_6 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let messages_retrieved_2 = tx_6
        .retrieve_message_for_public_key(&public_key_internal)
        .expect("Failed to retrieve messages from db.");

    assert_eq!(messages_retrieved_2.len(), 2);

    let message_retrieved = messages_retrieved_2.get(1).unwrap();

    let (header, cipher) = alice
        .ratchet_encrypt(
            message_retrieved.content.as_bytes(),
            alice_ad,
            &mut real_gen,
        )
        .unwrap();

    let plain_text_2 = bob_session_retrieved
        .double_ratchet
        .ratchet_decrypt(header, &cipher, alice_ad, &mut real_gen)
        .unwrap();

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text_2),
        &message_2
    );

    assert_eq!(&plain_text, &message1.as_bytes());
    cleanup_test_db(tx_6)
}

#[test]
fn messaging_test_unordered_message() {
    let database_pool = DATABASE.get().unwrap();
    let mut connection = database_pool.new_connection().unwrap();
    let bob_username = "BOB".to_string();
    let bob_device_identity = IdentityKey::from([2; 16]);
    let public_key = PublicKeyInternal::from([1; 32]);

    let mut tx_1 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    tx_1.create_user(bob_username.clone(), &public_key)
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

    tx_2.create_session(&bob_user.user_id, &bob_device_identity, &bob_double_ratchet)
        .expect("Failed to store Bob Session");
    tx_2.commit().expect("Failed to persist code in the db");

    let mut tx_3 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");
    let mut bob_session_retrieved = tx_3
        .load_active_session(&bob_user.user_id)
        .expect("Failed to load Bob Session");

    let message1 = "Hi Bob, this is Alice";

    // store and retrieve message from Sender to send to Receiver
    let public_key_internal = PublicKeyInternal::from(alice.dhs.public.to_bytes());

    tx_3.store_message(&public_key_internal, &MessageType::Sent, &message1);
    tx_3.commit();

    let mut tx_4 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let messages = tx_4
        .retrieve_message_for_public_key(&public_key_internal)
        .expect("Failed to retrieve messages from db.");

    assert_eq!(messages.len(), 1);

    let message_retrieved = messages.get(0).unwrap();

    let (header, cipher) = alice
        .ratchet_encrypt(
            message_retrieved.content.as_bytes(),
            alice_ad,
            &mut real_gen,
        )
        .unwrap();

    let plain_text = bob_session_retrieved
        .double_ratchet
        .ratchet_decrypt(header, &cipher, alice_ad, &mut real_gen)
        .unwrap();

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text),
        &message1
    );

    assert_eq!(&plain_text, &message1.as_bytes());

    tx_4.store_session(&bob_session_retrieved);
    tx_4.commit();

    let mut tx_5 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let mut bob_session_retrieved2 = tx_5
        .load_active_session(&bob_user.user_id)
        .expect("Failed to load Bob Session");
    assert_eq!(
        bob_session_retrieved2.session_id,
        bob_session_retrieved.session_id
    );

    let message_2 = "Hi Bob, this is Alice_2";

    let public_key_internal = PublicKeyInternal::from(alice.dhs.public.to_bytes());

    // store and retrieve message from Sender to send to Receiver
    tx_5.store_message(&public_key_internal, &MessageType::Sent, &message_2);
    tx_5.commit();

    let mut tx_6 =
        SqliteTransaction::new(&mut connection).expect("Failed to create SQLITE TRANSACTION");

    let messages_retrieved_2 = tx_6
        .retrieve_message_for_public_key(&public_key_internal)
        .expect("Failed to retrieve messages from db.");

    assert_eq!(messages_retrieved_2.len(), 2);

    let message_retrieved = messages_retrieved_2.get(1).unwrap();

    let (header, cipher) = alice
        .ratchet_encrypt(
            message_retrieved.content.as_bytes(),
            alice_ad,
            &mut real_gen,
        )
        .unwrap();

    let plain_text_2 = bob_session_retrieved
        .double_ratchet
        .ratchet_decrypt(header, &cipher, alice_ad, &mut real_gen)
        .unwrap();

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text_2),
        &message_2
    );

    assert_eq!(&plain_text, &message1.as_bytes());
    //cleanup_test_db(tx_6)
}
