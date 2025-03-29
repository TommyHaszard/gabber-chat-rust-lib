use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub sender_id: String,
    pub receiver_id: Option<String>,
    pub group_id: Option<String>,
    pub content: String,
    pub timestamp: i64,
    pub status: String,
}
