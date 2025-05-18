mod common;

use crate::common::*;
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
fn test_message_sending() {
    todo!()
}

#[test]
fn test_sync_with_peer() {

    let pub_key1 = [1; 32].to_vec();
    let pub_key2 = [2; 32].to_vec();
    // Create users
    create_user("user1".to_string(), pub_key1).unwrap();
    create_user("user2".to_string(), pub_key2).unwrap();

    cleanup_test_db()
}

#[test]
fn test_mark_messages_as_seen() {

    let pub_key1 = [1; 32].to_vec();
    let pub_key2 = [2; 32].to_vec();
    // Create users
    create_user("user1".to_string(), pub_key1).unwrap();
    create_user("user2".to_string(),pub_key2).unwrap();
    cleanup_test_db()
}

// #[test]
// pub fn zzz_db_teardown() {
//     if Path::new(TEST_DIR).exists() {
//         fs::remove_dir_all(TEST_DIR).expect("Failed to clean up test directory");
//     }
// }
