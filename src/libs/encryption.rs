use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::ptr::write;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use hmac::digest::{Key, KeyInit};
// Implementation of Signals Double Ratchet Algorithm with x25519_dalek
// https://signal.org/docs/specifications/doubleratchet

type Counter = u32;

type MessageId = u32;

type KeySecret = [u8; 32];

type CipherText = Vec<u8>;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Store skipped message keys -> Using the PublicKey and the message number
struct KeyStore(HashMap<PublicKey, HashMap<MessageId, SharedSecret>>);

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (public_key, messages) in &self.0 {
            let redacted_map: HashMap<_, _> = messages
                .keys()
                .map(|msg_id| (msg_id, "[REDACTED]"))
                .collect();

            map.entry(&public_key, &redacted_map);
        }
        map.finish()
    }
}

pub const DEFAULT_MAX_SKIP: usize = 1000;
const HKDF_INFO_ROOT_KEY: &[u8] = b"ROOT_KEY";
const HKDF_INFO_CHAIN_KEY: &[u8] = b"CHAIN_KEY";
const HKDF_INFO_HEADER_KEY: &[u8] = b"HEADER_KEY";
const HKDF_INFO_ENCRYPTION_KEY: &[u8] = b"ENCRYPTION_KEY";
const KEY_SECRET_LEN: usize = 32;


// Custom error type for key derivation operations

#[derive(Debug)]
pub enum DoubleRatchetError {
    HmacError(String),
    OutputSizeError(String),
    HkdfError(String),
    AeadError(String),
    InvalidLength(String)
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

impl MessageHeader {
    fn init(dh_public_key: PublicKey, count: Counter, previous_count: Counter) -> MessageHeader{
        Self {
            dh_public_key,
            count,
            previous_count
        }
    }
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

    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<(MessageHeader, Vec<u8>), DoubleRatchetError> {
        // cannot run if self is not initialised

        let (new_chain_key, message_key) = kdf_ck(&self.send_chain_key.unwrap())?;
        let header = MessageHeader::init(self.dhs.public.clone(), self.prev_number.clone(), self.send_count.clone());

        self.send_count += 1;

        let cipher_text = encrypt(&message_key, &plaintext, &associated_data)?;

        Ok((header, cipher_text))
    }
}

// KDF_RK(rk, dh_out): This function is recommended to be implemented using HKDF
// with SHA-256 or SHA-512, using rk as HKDF salt, dh_out as HKDF input key material,
// and an application-specific byte sequence as HKDF info.
// The info value should be chosen to be distinct from other uses of HKDF in the application.
fn kdf_rk(root_key: KeySecret, dh: &SharedSecret) -> Result<(KeySecret, KeySecret, KeySecret), DoubleRatchetError> {
    // Use HKDF with the root key as salt
    let dh_out = dh.as_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&root_key), dh_out);

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

    let mut message_key: KeySecret = [0u8; KEY_SECRET_LEN];
    let mut next_chain_key: KeySecret = [0u8; KEY_SECRET_LEN];

    // Derive message key using input constant 0x01
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(chain_key)
        .map_err(|e| DoubleRatchetError::HmacError(e.to_string()))?;
    mac.update(&[0x01]);
    let message_key_result = mac.finalize();

    // Derive next chain key using input constant 0x02
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(chain_key)
        .map_err(|e| DoubleRatchetError::HmacError(e.to_string()))?;

    mac.update(&[0x02]);
    let next_chain_key_result = mac.finalize();

    message_key.copy_from_slice(&message_key_result.into_bytes()[..KEY_SECRET_LEN]);
    next_chain_key.copy_from_slice(&next_chain_key_result.into_bytes()[..KEY_SECRET_LEN]);

    Ok((message_key, next_chain_key))
}

// Encryption function without randomly generating a nonce, so it is not included in the message to
// the receiver. This is safe as the message key is only used once per message, therefore we can
// deterministically regenerate the nonce using the message key without it being unsafe.
fn encrypt(message_key: &KeySecret, plaintext: &[u8], associated_data: &[u8]) -> Result<CipherText, DoubleRatchetError> {
    let (key_bytes, nonce_bytes) = derive_hkdf_key_and_nonce(message_key)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce,
                 Payload {
                    msg: plaintext,
                    aad: associated_data,
                })
        .map_err(|e| DoubleRatchetError::AeadError(e.to_string()))?;

    Ok(ciphertext)
}

fn decrypt(message_key: &KeySecret, cipher_text: &CipherText, associated_data: &[u8]) -> Result<CipherText, DoubleRatchetError> {
    let (key_bytes, nonce_bytes) = derive_hkdf_key_and_nonce(message_key)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plain_text = cipher
        .decrypt(nonce,
                 Payload {
                     msg: cipher_text,
                     aad: associated_data,
                 })
        .map_err(|e| DoubleRatchetError::AeadError(e.to_string()))?;

    Ok(plain_text)
}

fn derive_hkdf_key_and_nonce(message_key: &KeySecret) -> Result<([u8; 32], [u8; 12]), DoubleRatchetError> {
    // Use HKDF to derive encryption key and nonce from message key
    let salt = vec![0u8; Sha256::output_size()];
    let h = Hkdf::<Sha256>::new(Some(&salt), message_key);

    let mut key_bytes = [0u8; 32]; // 256-bit key for ChaCha20Poly1305
    let mut nonce_bytes = [0u8; 12]; // 96-bit nonce
    let mut okm = [0u8; 44]; // 352-bit output key material
    h.expand(HKDF_INFO_ENCRYPTION_KEY, &mut okm).map_err(|e| DoubleRatchetError::InvalidLength(e.to_string()))?;

    key_bytes.copy_from_slice(&okm[..32]);
    nonce_bytes.copy_from_slice(&okm[32..]);
    Ok((key_bytes, nonce_bytes))
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
    use crate::libs::encryption::*;

    #[test]
    fn test_encryption_decryption() {
        let mk = b"super_secret_master_key_32_bytes";
        let plaintext = b"Encrypt this message!";
        let aad = b"metadata";

        let ct = encrypt(mk, plaintext, aad).unwrap();
        println!("Ciphertext: {:?}", ct);

        let pt = decrypt(mk, &ct, aad).unwrap();
        println!("Decrypted: {:?}", String::from_utf8(pt.clone()));
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_gen_user_key() {
    }
}