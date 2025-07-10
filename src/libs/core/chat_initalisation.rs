use crate::libs::encryption::double_ratchet::{
    DHKeyGenerator, DHKeyPair, DoubleRatchet, KeySecret,
};
use crate::libs::storage::records::{SessionRecord, UserRecord};
use std::array::TryFromSliceError;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use crate::libs::core::models::IdentityKey;

// Define key size constant
const KEY_SIZE: usize = 32;
const IDENTITY_KEY_SIZE: usize = 16;
const QR_KEYS_EXPECTED_SIZE: usize = KEY_SIZE * 2 + IDENTITY_KEY_SIZE;

#[derive(Debug)]
pub enum ChatInitError {
    InvalidLength { expected: usize, found: usize },
    DeserialiseError(TryFromSliceError),
}

impl From<TryFromSliceError> for ChatInitError {
    fn from(err: TryFromSliceError) -> Self {
        ChatInitError::DeserialiseError(err)
    }
}

fn serialize_keys(key1: &Uuid, key2: &PublicKey) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(key1.as_bytes());
    result.extend_from_slice(key2.as_bytes());
    result
}

fn deserialize_keys(data: &[u8]) -> Result<(IdentityKey, PublicKey, KeySecret), ChatInitError> {
    if data.len() != QR_KEYS_EXPECTED_SIZE {
        return Err(ChatInitError::InvalidLength {
            expected: QR_KEYS_EXPECTED_SIZE,
            found: data.len(),
        });
    }

    let (key1_slice, rest) = data.split_at(IDENTITY_KEY_SIZE);
    let key1_array: [u8; IDENTITY_KEY_SIZE] = key1_slice.try_into()?;
    let key1 = IdentityKey::from(key1_array);

    let (key2_slice, key3_slice) = rest.split_at(KEY_SIZE);
    let key2_array: [u8; KEY_SIZE] = key2_slice.try_into()?;
    let key2 = PublicKey::from(key2_array);

    let key3_array: [u8; KEY_SIZE] = key3_slice.try_into()?;
    let key3 = KeySecret::from(key3_array);

    Ok((key1, key2, key3))
}

// Whoever creates the first QR will provide this data for Alice to init the DoubleRatchet
fn bob_generate_qr_data(
    bob_identity: &IdentityKey,
    dh_key_pair_gen: &mut impl DHKeyGenerator,
) -> (Vec<u8>, DHKeyPair) {
    let bob_setup_keypair = dh_key_pair_gen.generate_dh();
    let qr_data = serialize_keys(&bob_identity.uuid, &bob_setup_keypair.public);
    (qr_data, bob_setup_keypair)
}

// Whoever creates the second QR will provide this data for Bob to init the DoubleRatchet
fn alice_init_from_qr_data<DHKeyGen: DHKeyGenerator>(
    device_id: IdentityKey,
    qr_data: &[u8],
    mut dh_key_pair_gen: &mut DHKeyGen,
) -> Result<SessionRecord, ChatInitError> {
    let (bob_pub_user_id, bob_ratchet_pub_key, shared_root_key) = deserialize_keys(qr_data)?;
    let alice_key_pair = dh_key_pair_gen.generate_dh();
    let mut alice_double_ratchet =
        DoubleRatchet::initialise_alice(alice_key_pair, shared_root_key, bob_ratchet_pub_key);
    let bob_user_record = UserRecord::new(
        bob_pub_user_id.clone(),
        "default".to_string(),
        bob_ratchet_pub_key.to_bytes(),
        false,
    );
    let bob_session_record =
        SessionRecord::new(&bob_pub_user_id, alice_double_ratchet, device_id, true);
    Ok(bob_session_record)
}

fn alice_generate_qr_data<DHKeyGen: DHKeyGenerator>(
    alice_identity: &IdentityKey,
    alice_double_ratchet: &DoubleRatchet,
) -> Vec<u8> {
    serialize_keys(&alice_identity.uuid, &alice_double_ratchet.dhs.public)
}

fn bob_init_from_qr_data<DHKeyGen: DHKeyGenerator>(
    device_id: IdentityKey,
    qr_data: &[u8],
    bob_setup_keypair: DHKeyPair,
) -> Result<SessionRecord, ChatInitError> {
    let (alice_pub_user_id, alice_ratchet_pub_key, shared_root_key) = deserialize_keys(qr_data)?;
    let mut bob_double_ratchet =
        DoubleRatchet::initialise_bob(shared_root_key, bob_setup_keypair, None);
    let alice_user_record = UserRecord::new(
        alice_pub_user_id.clone(),
        "default".to_string(),
        alice_ratchet_pub_key.to_bytes(),
        false,
    );
    let alice_session_record =
        SessionRecord::new(&alice_pub_user_id, bob_double_ratchet, device_id, true);
    Ok(alice_session_record)
}
