use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::ptr::write;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::digest::Key;
// Implementation of Signals Double Ratchet Algorithm with x25519_dalek
// https://signal.org/docs/specifications/doubleratchet

type Counter = u32;

type MessageId = u32;

type KeySecret = [u8; 32];

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Store skipped message keys -> Using the PublicKey and the message number
#[derive(Debug)]
struct KeyStore(HashMap<PublicKey, HashMap<MessageId, SharedSecret>>);

pub const DEFAULT_MAX_SKIP: usize = 1000;
const HKDF_INFO_ROOT_KEY: &[u8] = b"ROOT_KEY";
const HKDF_INFO_CHAIN_KEY: &[u8] = b"CHAIN_KEY";
const HKDF_INFO_HEADER_KEY: &[u8] = b"HEADER_KEY";
// Custom error type for key derivation operations
#[derive(Debug)]
pub enum DoubleRatchetError {
    HmacError(String),
    OutputSizeError(String),
    HkdfError(String)
}

// Using a StaticSecret instead of Ephemeral
#[derive(Clone)]
pub struct DHKeyPair {
    private: StaticSecret,
    public: PublicKey,
}

impl DHKeyPair {
    //GENERATE_DH(): This function is recommended to generate a key pair based on the Curve25519
    // or Curve448 elliptic curves.
    pub fn generate_dh() -> Self {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}

impl fmt::Debug for DHKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DHKeyPair")
            .field("Public", &self.public)
            .field("Private", &"[REDACTED]")
            .finish()
    }
}


#[derive(Debug, Clone)]
struct MessageHeader {
    dh_public_key: PublicKey,
    count: Counter,
    previous_count: Counter,
}

struct DoubleRatchet {
    // Keys
    root_key: KeySecret,
    send_chain_key: Option<KeySecret>,
    recv_chain_key: Option<KeySecret>,

    // Alice's (Self) DH KeyPair
    dhs: DHKeyPair,

    // Bobby's (remote, receiver) Public Key that comes from the Message Header
    dhr: Option<PublicKey>,

    // Message counters
    send_count: Counter,
    recv_count: Counter,

    // Number of messages in previous sending chain
    prev_number: Counter,

    // Stored skipped message keys
    skipped_message_keys: KeyStore,

    // Maximum number of skipped message keys to store
    max_skip: u32,
}

impl DoubleRatchet {
    // Takes an initial shared secrete between two parties, the other parties public key and
    pub fn initialise_alice(shared_root_key: KeySecret, bobby_public_key: PublicKey) {
        let dh_pair = DHKeyPair::generate_dh();
        let dh = dh_pair.private.diffie_hellman(&bobby_public_key);
        let (rk, cks, header_key) = kdf_rk(shared_root_key, &dh).unwrap();

        Self {
            root_key: rk,
            send_chain_key: Some(cks),
            recv_chain_key: None,
            dhs: dh_pair,
            dhr: None,
            send_count: 0,
            recv_count: 0,
            prev_number: 0,
            skipped_message_keys: KeyStore(Default::default()),
            max_skip: 0,
        };
    }

    pub fn initialise_bob(shared_root_key: KeySecret, dh_pair: DHKeyPair, cks: Option<KeySecret>) {
        Self {
            root_key: shared_root_key,
            send_chain_key: cks,
            recv_chain_key: None,
            dhs: dh_pair,
            dhr: None,
            send_count: 0,
            recv_count: 0,
            prev_number: 0,
            skipped_message_keys: KeyStore(Default::default()),
            max_skip: 0,
        };
    }
}

// KDF_RK(rk, dh_out): This function is recommended to be implemented using HKDF
// with SHA-256 or SHA-512, using rk as HKDF salt, dh_out as HKDF input key material,
// and an application-specific byte sequence as HKDF info.
// The info value should be chosen to be distinct from other uses of HKDF in the application.
fn kdf_rk(root_key: KeySecret, dh: &SharedSecret) -> Result<(KeySecret, KeySecret, KeySecret), DoubleRatchetError> {
    // Use HKDF with the root key as salt
    let dh_out = dh.as_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&*root_key), dh_out);

    // Derive the new keys
    let mut new_root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];
    let mut header_key = [0u8; 32];

    // Extract the keys with appropriate context info
    hkdf.expand(HKDF_INFO_ROOT_KEY, &mut new_root_key)
        .map_err(|e| DoubleRatchetError::HkdfError(e.to_string()))?;

    hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut chain_key)
        .map_err(|e| DoubleRatchetError::HkdfError(e.to_string()))?;

    hkdf.expand(HKDF_INFO_HEADER_KEY, &mut header_key)
        .map_err(|e| DoubleRatchetError::HkdfError(e.to_string()))?;

    Ok((new_root_key, chain_key, header_key))
}

// KDF_CK(ck): HMAC [2] with SHA-256 or SHA-512 [8] is recommended, using ck as the HMAC key
// and using separate constants as input (e.g. a single byte 0x01 as input to produce the
// message key, and a single byte 0x02 as input to produce the next chain key).
fn kdf_ck(chain_key: &KeySecret) -> Result<(KeySecret, KeySecret), DoubleRatchetError> {

    let mut message_key: KeySecret = [0u8; KeySecret::LEN];
    let mut next_chain_key: KeySecret = [0u8; KeySecret::LEN];

    // Derive message key using input constant 0x01
    let mut mac = HmacSha256::new_from_slice(chain_key)
        .map_err(|e| DoubleRatchetError::HmacError(e.to_string()))?;
    mac.update(&[0x01]);
    let message_key_result = mac.finalize();

    // Derive next chain key using input constant 0x02
    let mut mac = HmacSha256::new_from_slice(chain_key)
        .map_err(|e| DoubleRatchetError::HmacError(e.to_string()))?;

    mac.update(&[0x02]);
    let next_chain_key_result = mac.finalize();

    message_key.copy_from_slice(&message_key_result.into_bytes()[..KeySecret::LEN]);
    next_chain_key.copy_from_slice(&next_chain_key_result.into_bytes()[..KeySecret::LEN]);

    Ok((message_key, next_chain_key))
}


fn generate_dh_pair() -> DHKeyPair {
    todo!()
}

impl fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DoubleRatchet {{ Alice_Key_Pair: {:?}, Bobby_Public_Key: {:?}, Root_Key: {:?},
            Send_Chain_Key: {:?}, Recv_Chain_Key: {:?}, Send_Count: {:?},
            Recv_Count: {:?}, Prev_Number: {:?}, Skipped_Key_Store: {:?} }}",
            self.dhs,
            self.dhr,
            self.root_key,
            self.send_chain_key,
            self.recv_chain_key,
            self.send_count,
            self.recv_count,
            self.prev_number,
            self.skipped_message_keys,
        )

    }
}




#[cfg(test)]
mod tests {

    #[test]
    fn test_gen_user_key() {
    }
}