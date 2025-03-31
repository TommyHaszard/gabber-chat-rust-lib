use rusqlite::{Connection, Result};
use std::sync::{Mutex, Once, OnceLock};
use once_cell::sync::Lazy;

static INIT: Once = Once::new();
static DB_PATH: OnceLock<String> = OnceLock::new();

pub fn get_db_path() -> &'static str {
    DB_PATH.get().expect("Database path not initialized")
}

pub fn initialize_database(path: String) -> Result<()> {
    let mut initialized = false;
    INIT.call_once(|| {
        DB_PATH.set(path).expect("Database path can only be set once");
        let conn = Connection::open(get_db_path()).expect("Failed to open database");

        conn.execute("PRAGMA foreign_keys = ON", []).expect("Failed to enforce foreign keys constraints.");

        // Create Users table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS LocalUser (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                display_name TEXT,
                profile_picture_path TEXT,
                device_id TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                last_sync_timestamp INTEGER
            )",
            [],
        ).expect("Failed to create LocalUser table");

        // Create Groups table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Contacts (
                contact_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                display_name TEXT,
                profile_picture_path TEXT,
                device_id TEXT,
                bluetooth_id TEXT,
                last_seen INTEGER,
                relationship_status TEXT NOT NULL DEFAULT 'pending',
                is_favorite INTEGER NOT NULL DEFAULT 0,
                discovery_method TEXT NOT NULL DEFAULT 'nearby',

                CHECK (relationship_status IN ('friend', 'pending', 'blocked')),
                CHECK (discovery_method IN ('manual', 'nearby', 'relay')),
                CHECK (is_favorite IN (0, 1))
            );
            CREATE INDEX idx_contacts_bluetooth_id ON Contacts(bluetooth_id);
            CREATE INDEX idx_contacts_last_seen ON Contacts(last_seen);",
            [],
        ).expect("Failed to create Contacts table");

        // Create Group_Members table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Conversations (
                conversation_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                display_name TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                last_message_preview TEXT,
                unread_count INTEGER NOT NULL DEFAULT 0,
                is_pinned INTEGER NOT NULL DEFAULT 0,

                CHECK (type IN ('direct', 'group')),
                CHECK (is_pinned IN (0, 1))
            );
            CREATE INDEX idx_conversations_updated_at ON Conversations(updated_at);",
            [],
        ).expect("Failed to create Converstations table");

        // Create Messages table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Conversation_Members (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                contact_id TEXT,
                role TEXT NOT NULL DEFAULT 'member',
                is_muted INTEGER NOT NULL DEFAULT 0,

                FOREIGN KEY (conversation_id) REFERENCES Conversations(conversation_id) ON DELETE CASCADE,
                FOREIGN KEY (contact_id) REFERENCES Contacts(contact_id) ON DELETE CASCADE,

                CHECK (role IN ('admin', 'member')),
                CHECK (is_muted IN (0, 1))
            );
            CREATE INDEX idx_conversation_members_conversation_id ON Conversation_Members(conversation_id);
            CREATE INDEX idx_conversation_members_contact_id ON Conversation_Members(contact_id);",
            [],
        ).expect("Failed to create Conversation_Members table");

        // Create Messages table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                is_outgoing INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                sent_at INTEGER,
                status TEXT NOT NULL DEFAULT 'draft',
                is_read INTEGER NOT NULL DEFAULT 0,
                delivery_hops INTEGER NOT NULL DEFAULT 0,
                original_message_id TEXT,
                needs_relay INTEGER NOT NULL DEFAULT 0,

                FOREIGN KEY (conversation_id) REFERENCES Conversations(conversation_id) ON DELETE CASCADE,

                CHECK (is_outgoing IN (0, 1)),
                CHECK (content_type IN ('text', 'image', 'audio', 'video', 'location')),
                CHECK (status IN ('draft', 'sending', 'sent', 'delivered', 'failed')),
                CHECK (is_read IN (0, 1)),
                CHECK (needs_relay IN (0, 1))
            );
            CREATE INDEX idx_messages_conversation_id_created_at ON Messages(conversation_id, created_at);
            CREATE INDEX idx_messages_status ON Messages(status);
            CREATE INDEX idx_messages_needs_relay ON Messages(needs_relay);",
            [],
        ).expect("Failed to create Message_Sync_Log table");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Bluetooth_Devices (
                    device_id TEXT PRIMARY KEY,
                    bluetooth_id TEXT NOT NULL UNIQUE,
                    owner_contact_id TEXT,
                    device_name TEXT,
                    last_connected INTEGER,
                    is_trusted INTEGER NOT NULL DEFAULT 0,
                    signal_strength INTEGER,
                    capabilities TEXT,

                    FOREIGN KEY (owner_contact_id) REFERENCES Contacts(contact_id) ON DELETE SET NULL,

                    CHECK (is_trusted IN (0, 1))
                );
                CREATE INDEX idx_bluetooth_devices_bluetooth_id ON Bluetooth_Devices(bluetooth_id);
                CREATE INDEX idx_bluetooth_devices_last_connected ON Bluetooth_Devices(last_connected);",
            [],
        ).expect("Failed to create Bluetooth_Devices");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Delivery_Queue (
                    queue_id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    target_device_id TEXT,
                    target_conversation_id TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    priority TEXT NOT NULL DEFAULT 'normal',
                    next_attempt_at INTEGER NOT NULL,
                    queued_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    via_relay INTEGER NOT NULL DEFAULT 0,

                    FOREIGN KEY (message_id) REFERENCES Messages(message_id) ON DELETE CASCADE,
                    FOREIGN KEY (target_device_id) REFERENCES Bluetooth_Devices(device_id) ON DELETE CASCADE,
                    FOREIGN KEY (target_conversation_id) REFERENCES Conversations(conversation_id) ON DELETE CASCADE,

                    CHECK (priority IN ('high', 'normal', 'low')),
                    CHECK (via_relay IN (0, 1))
                );
                CREATE INDEX idx_delivery_queue_next_attempt_priority ON Delivery_Queue(next_attempt_at, priority);
                CREATE INDEX idx_delivery_queue_message_id ON Delivery_Queue(message_id);
                CREATE INDEX idx_delivery_queue_target_device_id ON Delivery_Queue(target_device_id);",
            [],
        ).expect("Failed to create Delivery_Queue");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Relay_History (
                    id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    relayed_for_device_id TEXT NOT NULL,
                    relayed_to_device_id TEXT NOT NULL,
                    relayed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    success INTEGER NOT NULL DEFAULT 0,

                    FOREIGN KEY (message_id) REFERENCES Messages(message_id) ON DELETE CASCADE,
                    FOREIGN KEY (relayed_for_device_id) REFERENCES Bluetooth_Devices(device_id) ON DELETE CASCADE,
                    FOREIGN KEY (relayed_to_device_id) REFERENCES Bluetooth_Devices(device_id) ON DELETE CASCADE,

                    CHECK (success IN (0, 1))
                );
                CREATE INDEX idx_relay_history_message_id ON Relay_History(message_id);
                CREATE INDEX idx_relay_history_relayed_at ON Relay_History(relayed_at);",
            [],
        ).expect("Failed to create Relay_History");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS AppSettings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                );",
            [],
        ).expect("Failed to create AppSettings");

        conn.execute(
            "INSERT INTO AppSettings (key, value) VALUES
                    ('max_relay_hops', '3'),
                    ('bluetooth_discovery_interval', '300'),
                    ('message_retention_days', '90'),
                    ('app_version', '0.0.1');",
            [],
        ).expect("Failed to init AppSettings");

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS update_conversation_timestamp
                AFTER INSERT ON Messages
                BEGIN
                    UPDATE Conversations
                    SET updated_at = strftime('%s', 'now'),
                        last_message_preview = NEW.content,
                        unread_count = CASE
                                            WHEN NEW.is_outgoing = 0 THEN unread_count + 1
                                            ELSE unread_count
                                        END
                    WHERE conversation_id = NEW.conversation_id;
                END;",
            [],
        ).expect("Failed to create update_conversation_timestamp trigger");


        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS cleanup_old_messages
                AFTER UPDATE ON AppSettings
                WHEN NEW.key = 'message_retention_days'
                BEGIN
                    DELETE FROM Messages
                    WHERE created_at < strftime('%s', 'now') - (NEW.value * 86400)
                    AND conversation_id NOT IN (SELECT conversation_id FROM Conversations WHERE is_pinned = 1);
                END;",
            [],
        ).expect("Failed to create cleanup_old_messages trigger");

        initialized = true;
    });

    if initialized {
        Ok(())
    } else {
        let conn = Connection::open(get_db_path())?;
        // Just verify the connection works
        conn.execute("SELECT 1", [])?;
        Ok(())
    }
}