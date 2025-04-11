use std::collections::HashMap;
use std::fmt;
use std::fmt::{format, Debug, Formatter};
use std::ptr::write;
use chacha20poly1305::aead::{Aead, Buffer, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use hmac::digest::{Key, KeyInit};
use serde::{Deserialize, Serialize};
// Implementation of Signals Double Ratchet Algorithm with x25519_dalek
// https://signal.org/docs/specifications/doubleratchet

type Counter = u32;

type MessageId = u32;

type KeySecret = [u8; 32];

type CipherText = Vec<u8>;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Store skipped message keys -> Using the PublicKey and the message number
struct KeyStore(HashMap<(PublicKey, MessageId), KeySecret>);

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (public_key, messages) in &self.0 {
            let redacted_map = messages
                .map(|msg_id| (msg_id, "[REDACTED]"));

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
    InvalidLength(String),
    KeyNotFoundInKeyStore(String),
    CannotPerformMaxSkip(String),
    InvalidState(String)
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
pub(crate) struct MessageHeader {
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

    fn serialise_header(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(self.dh_public_key.as_bytes());
        result.extend_from_slice(&self.previous_count.to_be_bytes());
        result.extend_from_slice(&self.count.to_be_bytes());
        result
    }
}

pub(crate) struct DoubleRatchet {
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
    pub(crate) fn initialise_alice(shared_root_key: KeySecret, bobby_public_key: PublicKey) -> DoubleRatchet {
        let dh_pair = DHKeyPair::generate_dh();
        let dh = dh_pair.private.diffie_hellman(&bobby_public_key);
        let (rk, cks, _) = kdf_rk(shared_root_key, &dh).unwrap();

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
        }
    }

    pub(crate) fn initialise_bob(shared_root_key: KeySecret, dh_pair: DHKeyPair, cks: Option<KeySecret>) -> DoubleRatchet {
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
        }
    }

    pub(crate) fn ratchet_encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<(MessageHeader, Vec<u8>), DoubleRatchetError> {
        // cannot run if self is not initialised

        let (_, message_key) = kdf_ck(&self.send_chain_key.unwrap())?;
        let header = MessageHeader::init(self.dhs.public, self.prev_number, self.send_count);

        self.send_count += 1;


        let concat_ad = concat_header_and_ad(associated_data, &header);

        let cipher_text = encrypt(&message_key, plaintext, &concat_ad.as_slice())?;

        Ok((header, cipher_text))
    }

    pub(crate) fn ratchet_decrypt(&mut self, header: MessageHeader, cipher_text: &CipherText, associated_data: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
        match self.try_skipped_message_keys(&header, cipher_text, associated_data)? {
            Some(plain_text) => Ok(plain_text),
            None => {
                if Some(&header.dh_public_key) != self.dhr.as_ref() {
                    self.skip_message_keys(header.previous_count);
                    self.dh_ratchet(&header);
                }

                self.skip_message_keys(header.count);
                match self.recv_chain_key {
                    Some(ckr) => {
                        let (_, message_key) = kdf_ck(&ckr)?;

                        self.recv_count += 1;
                        let concat_ad = concat_header_and_ad(associated_data, &header);

                        decrypt(&message_key, cipher_text, &concat_ad.as_slice())
                    }
                    _ => Err(DoubleRatchetError::InvalidState("Receive Chain Key Missing".to_string()))
                }
            }
        }
    }

    fn try_skipped_message_keys(&mut self, header: &MessageHeader, cipher_text: &CipherText, associated_data: &[u8]) -> Result<Option<Vec<u8>>, DoubleRatchetError> {
        match self.skipped_message_keys.0.remove(&(header.dh_public_key, header.count)) {
            Some(mk) => {
                let concat_ad = concat_header_and_ad(associated_data, header);
                let plain_text = decrypt(&mk, cipher_text, concat_ad.as_slice())?;
                Ok(Some(plain_text))
            }
            _ => Ok(None)
        }
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), DoubleRatchetError> {
        if self.recv_count + (DEFAULT_MAX_SKIP as u32) < until {
           return Err(DoubleRatchetError::CannotPerformMaxSkip(format!("{} > {}", self.recv_count+(DEFAULT_MAX_SKIP as u32), until)))
        }
        match self.recv_chain_key {
            Some(ckr) =>
                Ok(while self.recv_count < until {
                    let (new_recv_chain_key, message_key) = kdf_ck(&ckr)?;
                    self.skipped_message_keys.0.insert((self.dhr.unwrap(), self.recv_count), message_key);
                    self.recv_count += 1;
                    self.recv_chain_key = Some(new_recv_chain_key);
                }),
            _ => Err(DoubleRatchetError::InvalidState("Receive Chain Key Missing".to_string()))
        }
    }

    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<(), DoubleRatchetError>{
        self.prev_number = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dhr = Some(header.dh_public_key);

        // calc our DH Ratchet
        let dh_secret = self.dhs.private.diffie_hellman(&header.dh_public_key);
        let (new_rk, new_ckr, _) = kdf_rk(self.root_key, &dh_secret)?;
        self.root_key = new_rk;
        self.recv_chain_key = Some(new_ckr);

        self.dhs = DHKeyPair::generate_dh();

        // calc their DH Ratchet
        let dh_secret = self.dhs.private.diffie_hellman(&header.dh_public_key);

        let (new_rk, new_cks, _) = kdf_rk(self.root_key, &dh_secret)?;
        self.root_key = new_rk;
        self.send_chain_key = Some(new_cks);
        Ok(())
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

fn decrypt(message_key: &KeySecret, cipher_text: &CipherText, associated_data: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
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

fn concat_header_and_ad(associated_data: &[u8], message_header: &MessageHeader) -> Vec<u8>{
    let mut result = Vec::new();
    result.extend_from_slice(associated_data);
    let serialised_header = message_header.serialise_header();
    result.extend_from_slice(&serialised_header);
    result
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
    use chacha20poly1305::aead::OsRng;
    use chacha20poly1305::aead::rand_core::RngCore;
    use super::*;

    fn init() -> (DoubleRatchet, DoubleRatchet){
        let mut shared_key = [0u8; 32];
        OsRng.fill_bytes(&mut shared_key);

        let bob_key_pair = DHKeyPair::generate_dh();

        let alice = DoubleRatchet::initialise_alice(shared_key, bob_key_pair.public);
        let bob = DoubleRatchet::initialise_bob(shared_key, bob_key_pair, None);

        (alice, bob)
    }

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
    fn test_alice_message_one() {

        let associated_data = b"TEST_ASSOCIATED_DATA";
        let (mut alice, mut bob) = init();

        let message1 = b"Hi Bob, this is Alice";
        let (header, cipher) = alice.ratchet_encrypt(message1, associated_data).unwrap();

        let plain_text = bob.ratchet_decrypt(header, &cipher, associated_data).unwrap();

        println!("Decrypted: {:?}, Original: {:?}", String::from_utf8_lossy(&plain_text.clone()), String::from_utf8_lossy(&message1.clone()));
        assert_eq!(plain_text, message1);
    }

    #[test]
    fn test_bob_message_returned() {

        let alice_ad = b"ALICE_ASSOCIATED_DATA";
        let bob_ad = b"BOB_ASSOCIATED_DATA";
        let (mut alice, mut bob) = init();

        let message1 = b"Hi Bob, this is Alice";
        let (header, cipher) = alice.ratchet_encrypt(message1, alice_ad).unwrap();

        let plain_text = bob.ratchet_decrypt(header, &cipher, alice_ad).unwrap();

        println!("Decrypted: {:?}, Original: {:?}", String::from_utf8_lossy(&plain_text.clone()), String::from_utf8_lossy(&message1.clone()));

        let message2 = b"Hey Alice, how have you been?";
        let (header, cipher) = bob.ratchet_encrypt(message2, bob_ad).unwrap();

        let plain_text = alice.ratchet_decrypt(header, &cipher, bob_ad).unwrap();
        println!("Decrypted: {:?}, Original: {:?}", String::from_utf8_lossy(&plain_text.clone()), String::from_utf8_lossy(&message2.clone()));
        assert_eq!(plain_text, message2);
    }

    #[test]
    fn test_alice_out_of_order() {
        // Alice sends three messages
        let alice_ad = b"ALICE_ASSOCIATED_DATA";
        let messages = [
            b"Message A (will arrive in order)",
            b"Message B (will be dlayd aftr c)",
            b"Message C (will arrive before B)"
        ];

        let (mut alice, mut bob) = init();

        let mut headers_and_ciphertexts = Vec::new();

        for msg in messages {
            let (header, ciphertext) = alice.ratchet_encrypt(msg, alice_ad).unwrap();
            headers_and_ciphertexts.push((header, ciphertext));
            println!("Alice encrypted: {}", String::from_utf8_lossy(msg));
        }

        // Bob receives messages in different order (A, C, B)
        let (header_a, ciphertext_a) = &headers_and_ciphertexts[0];
        let plaintext_a = bob.ratchet_decrypt(header_a.clone(), ciphertext_a, alice_ad).unwrap();
        println!("Bob received (1st): {}", String::from_utf8_lossy(&plaintext_a));
        assert_eq!(plaintext_a, messages[0]);

        // Message C arrives before B
        let (header_c, ciphertext_c) = &headers_and_ciphertexts[2];
        let plaintext_c = bob.ratchet_decrypt(header_c.clone(), ciphertext_c, alice_ad).unwrap();
        println!("Bob received (2nd): {}", String::from_utf8_lossy(&plaintext_c));
        assert_eq!(plaintext_c, messages[2]);

        // Finally, message B arrives
        let (header_b, ciphertext_b) = &headers_and_ciphertexts[1];
        let plaintext_b = bob.ratchet_decrypt(header_b.clone(), ciphertext_b, alice_ad).unwrap();
        println!("Bob received (3rd): {}", String::from_utf8_lossy(&plaintext_b));
        assert_eq!(plaintext_b, messages[1]);
    }


    #[test]
    fn test_gen_user_key() {
    }
}