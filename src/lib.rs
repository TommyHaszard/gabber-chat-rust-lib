mod libs;

use std::error::Error;
use std::fmt;

use crate::libs::*;

uniffi::include_scaffolding!("gabber_chat_lib");


#[derive(Debug)]
pub enum DatabaseError {
    InitializationError,
    StorageError,
    SyncError,
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DatabaseError::InitializationError => write!(f, "Failed to initialize database"),
            DatabaseError::StorageError => write!(f, "Failed to store data"),
            DatabaseError::SyncError => write!(f, "Failed to sync with peer"),
        }
    }
}

impl Error for DatabaseError {}

pub fn init_database(path: String) {
    let _ = database::initialize_database(path);
}

pub fn create_user(name: String, public_key: String) -> Result<(), DatabaseError> {
    storage::create_user(&name, &public_key)
}

pub fn create_group(name: String, creator_id: String) -> Result<(), DatabaseError> {
    storage::create_group(&name, &creator_id)
}

pub fn send_message(sender: String, receiver: String, content: String) -> Result<(), DatabaseError> {
    storage::store_message(&sender, &receiver, &content)
}

pub fn sync_with_peer(peer_id: String) -> Vec<String> {
    sync::fetch_unsynced_messages(&peer_id)
}

pub fn mark_messages_as_seen(message_ids: Vec<String>) -> bool {
    sync::mark_messages_as_seen(message_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    // Use a static directory for all tests with cleanup at the end
    static TEST_DIR: &str = "./test_db_dir";
    static INIT: Once = Once::new();

    fn setup_test_db() -> String {
        INIT.call_once(|| {
            if Path::new(TEST_DIR).exists() {
                fs::remove_dir_all(TEST_DIR).expect("Failed to clean up existing test directory");
            }
            fs::create_dir_all(TEST_DIR).expect("Failed to create test directory");
        });

        // Create a unique database file name for each test
        let test_name = format!("{}/test_{}.db", TEST_DIR, std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos());

        init_database(test_name.clone());
        test_name
    }

    fn cleanup_test_db(path: &str) {
        if Path::new(path).exists() {
            fs::remove_file(path).expect("Failed to remove test database");
        }
    }

    #[test]
    fn zzz_cleanup() {
        if Path::new(TEST_DIR).exists() {
            fs::remove_dir_all(TEST_DIR).expect("Failed to clean up test directory");
        }
    }

    #[test]
    fn test_database_initialization() {
        let db_path = setup_test_db();
        assert!(Path::new(&db_path).exists(), "Database file should exist after initialization");
        //cleanup_test_db(&db_path);
    }

    #[test]
    fn test_create_user() {
        let db_path = setup_test_db();

        let result = create_user("test_user".to_string(), "test_public_key".to_string());
        assert!(result.is_ok(), "Creating a user should succeed");

        // Test duplicate user creation (assuming this should fail)
        let dup_result = create_user("test_user".to_string(), "different_key".to_string());
        assert!(dup_result.is_err(), "Creating duplicate user should fail");

        cleanup_test_db(&db_path);
    }

    #[test]
    fn test_create_group() {
        let db_path = setup_test_db();

        // First create a user
        let user_result = create_user("group_creator".to_string(), "creator_key".to_string());
        assert!(user_result.is_ok(), "Creating a user should succeed");

        // Then create a group with that user as creator
        let group_result = create_group("test_group".to_string(), "creator_key".to_string());
        assert!(group_result.is_ok(), "Creating a group should succeed");

        cleanup_test_db(&db_path);
    }

    #[test]
    fn test_message_sending() {
        let db_path = setup_test_db();

        // Create sender and receiver
        let sender_result = create_user("sender".to_string(), "sender_key".to_string());
        let receiver_result = create_user("receiver".to_string(), "receiver_key".to_string());
        assert!(sender_result.is_ok() && receiver_result.is_ok(), "Creating users should succeed");

        // Send a message
        let message_result = send_message(
            "sender_key".to_string(),
            "receiver_key".to_string(),
            "Hello, this is a test message".to_string()
        );
        assert!(message_result.is_ok(), "Sending a message should succeed");

        cleanup_test_db(&db_path);
    }

    #[test]
    fn test_sync_with_peer() {
        let db_path = setup_test_db();

        // Create users
        create_user("user1".to_string(), "key1".to_string()).unwrap();
        create_user("user2".to_string(), "key2".to_string()).unwrap();

        // Send messages
        send_message("key1".to_string(), "key2".to_string(), "Message 1".to_string()).unwrap();
        send_message("key1".to_string(), "key2".to_string(), "Message 2".to_string()).unwrap();

        // Fetch unsynced messages
        let messages = sync_with_peer("key2".to_string());
        assert!(!messages.is_empty(), "Should retrieve unsynced messages");

        cleanup_test_db(&db_path);
    }

    #[test]
    fn test_mark_messages_as_seen() {
        let db_path = setup_test_db();

        // Create users
        create_user("user1".to_string(), "key1".to_string()).unwrap();
        create_user("user2".to_string(), "key2".to_string()).unwrap();

        // Send messages
        send_message("key1".to_string(), "key2".to_string(), "Test message".to_string()).unwrap();

        // Fetch messages to get message IDs
        let message_ids = sync_with_peer("key2".to_string());
        assert!(!message_ids.is_empty(), "Should have at least one message");

        // Mark messages as seen
        let result = mark_messages_as_seen(message_ids);
        assert!(result, "Marking messages as seen should succeed");

        // Verify no more unsynced messages
        let unsynced_messages = sync_with_peer("key2".to_string());
        assert!(unsynced_messages.is_empty(), "No messages should be unsynced after marking as seen");

        cleanup_test_db(&db_path);
    }

    #[test]
    fn test_error_handling() {
        let db_path = setup_test_db();

        // Test sending a message with non-existent users
        let result = send_message(
            "nonexistent_sender".to_string(),
            "nonexistent_receiver".to_string(),
            "This should fail".to_string()
        );
        assert!(result.is_err(), "Sending a message with invalid users should fail");

        if let Err(err) = result {
            match err {
                DatabaseError::StorageError => assert!(true),
                _ => assert!(false, "Expected StorageError, got different error type"),
            }
        }

        cleanup_test_db(&db_path);
    }

    #[test]
    fn test_integration() {
        let db_path = setup_test_db();

        // Create users
        create_user("alice".to_string(), "alice_key".to_string()).unwrap();
        create_user("bob".to_string(), "bob_key".to_string()).unwrap();

        // Create a group
        create_group("test_group".to_string(), "alice_key".to_string()).unwrap();

        // Send messages
        send_message("alice_key".to_string(), "bob_key".to_string(), "Hi Bob!".to_string()).unwrap();
        send_message("bob_key".to_string(), "alice_key".to_string(), "Hello Alice!".to_string()).unwrap();

        // Sync messages for Bob
        let bob_messages = sync_with_peer("bob_key".to_string());
        assert_eq!(bob_messages.len(), 1, "Bob should have one unsynced message");

        // Mark Bob's messages as seen
        let mark_result = mark_messages_as_seen(bob_messages);
        assert!(mark_result, "Marking messages as seen should succeed");

        // Sync messages for Alice
        let alice_messages = sync_with_peer("alice_key".to_string());
        assert_eq!(alice_messages.len(), 1, "Alice should have one unsynced message");

        cleanup_test_db(&db_path);
    }
}