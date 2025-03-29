use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref MESSAGE_QUEUE: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

pub fn send_message_via_bluetooth(message: &str) {
    let mut queue = MESSAGE_QUEUE.lock().unwrap();
    queue.push(message.to_string());
}

pub fn receive_messages_via_bluetooth() -> Vec<String> {
    let mut queue = MESSAGE_QUEUE.lock().unwrap();
    let messages = queue.clone();
    queue.clear();
    messages
}