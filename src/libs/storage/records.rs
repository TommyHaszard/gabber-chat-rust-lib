use uuid::Uuid;
use x25519_dalek::PublicKey;
use crate::libs::chat_initalisation::IdentityKey;
use crate::libs::encryption::double_ratchet::{DHKeyGenerator, DoubleRatchet};

pub struct UserRecord {
    pub user_id: IdentityKey,
    pub username: String,
    pub public_key: PublicKey,
    pub is_stale: bool,
}

impl UserRecord {
    pub fn new(user_id: IdentityKey, username: String, public_key_array: [u8; 32], is_stale: bool) -> Self {
        Self {
            user_id,
            username,
            public_key: PublicKey::from(public_key_array),
            is_stale
        }
    }
}

pub struct SessionRecord {
    pub session_id: Uuid,
    pub remote_device_id: IdentityKey,
    pub remote_user_id: IdentityKey,
    pub double_ratchet: DoubleRatchet,
    pub is_active_session: bool,
    pub inactive_order: u8,
}

impl SessionRecord {
    pub fn new(user_identity: IdentityKey, double_ratchet: DoubleRatchet, device_id: IdentityKey, is_active_session: bool) -> Self {
        Self {
            session_id: Uuid::now_v7(),
            remote_device_id: device_id,
            double_ratchet,
            is_active_session,
            remote_user_id: user_identity,
            inactive_order: 0,
        }
    }
}
