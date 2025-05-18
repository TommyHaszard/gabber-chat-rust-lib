use crate::common::*;
use chacha20poly1305::aead::rand_core::RngCore;
use gabber_chat_lib::libs::encryption::double_ratchet::{DHKeyGenerator, RealKeyGenerator};
use std::sync::Once;
use rusqlite::types::Type::Real;

mod common;
static TEST_DIR: &str = "./tests/test_db_dir";
static INIT: Once = Once::new();

#[test]
pub fn aaa_db_initalisation() {
    aaa_init(&INIT, TEST_DIR, "integration")
}

#[test]
fn test_happy_path() {
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);


}
