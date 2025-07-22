// Rust models for the UDL types that will be used by front-end

use crate::libs::core::models::IdentityKey;

#[derive(Clone, Hash, Eq, PartialEq)]
pub enum UserType {
    Current,
    Friend,
    Other,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct User {
    pub user_id: Vec<u8>,
    pub username: String,
    pub user_type: UserType,
}

#[derive(Clone)]
pub struct Message {
    pub message_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub content: String,
    pub created_at: Option<u64>,
    pub is_from_user: bool
}