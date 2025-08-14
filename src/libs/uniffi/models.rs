// Rust models for the UDL types that will be used by front-end

#[derive(Clone, Hash, Eq, PartialEq, uniffi::Enum, Debug)]
pub enum UserType {
    Current,
    Friend,
    Other,
}

#[derive(Clone, Hash, Eq, PartialEq, uniffi::Record, Debug)]
pub struct User {
    pub user_id: Vec<u8>,
    pub username: String,
    pub user_type: UserType,
}

#[derive(Clone, uniffi::Record, Debug)]
pub struct Message {
    pub message_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub content: String,
    pub created_at: Option<u64>,
    pub is_from_user: bool,
}
