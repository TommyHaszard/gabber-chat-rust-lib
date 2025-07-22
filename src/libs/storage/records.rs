use crate::libs::core::models::{IdentityKey, MessageType, PublicKeyInternal};
use crate::libs::encryption::double_ratchet::{DHKeyGenerator, DoubleRatchet};
use uuid::Uuid;

pub struct UserRecord {
    pub user_id: IdentityKey,
    pub username: String,
    pub public_key: PublicKeyInternal,
    pub is_stale: bool,
}

impl UserRecord {
    pub fn new(
        user_id: IdentityKey,
        username: String,
        public_key_array: [u8; 32],
        is_stale: bool,
    ) -> Self {
        Self {
            user_id,
            username,
            public_key: PublicKeyInternal::from(public_key_array),
            is_stale,
        }
    }
}

#[derive(Debug)]
pub struct SessionRecord {
    pub session_id: IdentityKey,
    pub remote_device_id: IdentityKey,
    pub remote_user_id: IdentityKey,
    pub double_ratchet: DoubleRatchet,
    pub is_active_session: bool,
    pub inactive_order: u8,
}

impl SessionRecord {
    pub fn new(
        user_identity: &IdentityKey,
        double_ratchet: DoubleRatchet,
        device_id: IdentityKey,
        is_active_session: bool,
    ) -> Self {
        Self {
            session_id: IdentityKey::from(*Uuid::now_v7().as_bytes()),
            remote_device_id: device_id,
            double_ratchet,
            is_active_session,
            remote_user_id: user_identity.clone(),
            inactive_order: 0,
        }
    }
}

#[derive(Debug)]
pub struct MessageRecord {
    pub message_id: IdentityKey,
    pub recipient_public_key: PublicKeyInternal,
    pub message_type: MessageType,
    pub content: String,
    pub created_at: Option<u64>,
}

impl MessageRecord {
    pub fn new(
        recipient_public_key: PublicKeyInternal,
        message_type: MessageType,
        content: String,
    ) -> Self {
        Self {
            message_id: IdentityKey::from(*Uuid::now_v7().as_bytes()),
            recipient_public_key,
            message_type,
            content,
            created_at: None,
        }
    }

    pub fn from_db(
        message_id: IdentityKey,
        recipient_public_key: PublicKeyInternal,
        message_type: MessageType,
        content: String,
        created_at: u64,
    ) -> Self {
        Self {
            message_id,
            recipient_public_key,
            message_type,
            content,
            created_at: Option::from(created_at),
        }
    }
}
