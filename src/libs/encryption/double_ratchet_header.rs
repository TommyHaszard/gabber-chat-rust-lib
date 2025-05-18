use chacha20poly1305::aead::{Aead, Buffer, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::digest::{Key, KeyInit};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{format, Debug, Formatter};
use std::ptr::write;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use crate::libs::encryption::double_ratchet::{concat_header_and_ad, decrypt, derive_hkdf_key_and_nonce, encrypt, kdf_ck, kdf_rk, DHKeyPair, DoubleRatchetError, MessageHeader};
use crate::libs::models::Message;
// Implementation of Signals Double Ratchet Algorithm with x25519_dalek
// https://signal.org/docs/specifications/doubleratchet

type Counter = u32;

type MessageId = u32;

type KeySecret = [u8; 32];

type CipherText = Vec<u8>;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Store skipped message keys -> Using the PublicKey and the message number
#[derive(Clone)]
struct KeyStore(HashMap<(PublicKey, MessageId), KeySecret>);

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (public_key, messages) in &self.0 {
            let redacted_map = messages.map(|msg_id| (msg_id, "[REDACTED]"));

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
const HKDF_INFO_ENCRYPTION_HEADER_KEY: &[u8] = b"ENCRYPTION_HEADER_KEY";
const KEY_SECRET_LEN: usize = 32;

// Custom error type for key derivation operations
#[derive(Clone)]
pub struct DoubleRatchetHE {
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

    header_key_send: Option<KeySecret>,

    header_key_recv: Option<KeySecret>,

    next_header_key_recv: Option<KeySecret>,

    next_header_key_send: Option<KeySecret>

}

impl DoubleRatchetHE {
    // Takes an initial shared secrete between two parties, the other parties public key and
    pub fn initialise_alice_he(shared_root_key: KeySecret, bobby_public_key: PublicKey, shared_hka: KeySecret, shared_nhkb: KeySecret) -> Self {
        let dh_pair = DHKeyPair::generate_dh();
        let dh = dh_pair.private.diffie_hellman(&bobby_public_key);
        let (rk, cks, nhk) = kdf_rk_he(shared_root_key, &dh).unwrap();

        Self {
            root_key: rk,
            send_chain_key: Some(cks),
            recv_chain_key: None,
            dhs: dh_pair,
            dhr: Some(bobby_public_key),
            send_count: 0,
            recv_count: 0,
            prev_number: 0,
            skipped_message_keys: KeyStore(Default::default()),
            header_key_send: Some(shared_hka),
            header_key_recv: None,
            next_header_key_recv: Some(shared_nhkb),
            next_header_key_send: None
        }
    }

    pub fn initialise_bob_he(
        shared_root_key: KeySecret,
        dh_pair: DHKeyPair,
        cks: Option<KeySecret>,
        shared_hka: KeySecret,
        shared_nhkb: KeySecret,
    ) -> Self {
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
            header_key_send: None,
            header_key_recv: None,
            next_header_key_send: Some(shared_nhkb),
            next_header_key_recv: Some(shared_hka)
        }
    }

    pub fn ratchet_encrypt_he(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(CipherText, CipherText), DoubleRatchetError> {
        // cannot run if self is not initialised

        let (_, message_key) = kdf_ck(&self.send_chain_key.unwrap())?;
        let header = MessageHeader::init(self.dhs.public, self.prev_number, self.send_count);
        let enc_header = encrypt_he(&self.header_key_send.unwrap(), header)?;

        self.send_count += 1;

        let concat_ad = concat_header_and_ad(associated_data, &enc_header);

        let cipher_text = encrypt(&message_key, plaintext, &concat_ad.as_slice())?;

        Ok((enc_header, cipher_text))
    }

    pub fn ratchet_decrypt_he(
        &mut self,
        header_enc: CipherText,
        cipher_text: &CipherText,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        match self.try_skipped_message_keys_he(&header_enc, cipher_text, associated_data)? {
            Some(plain_text) => Ok(plain_text),
            None => {
                let (header, check) = self.try_decrypt_he(&header_enc)?;
                if Some(&header.dh_public_key) != self.dhr.as_ref() {
                    self.skip_message_keys_he(header.prev_chain_number);
                    self.dh_ratchet(&header);
                }

                self.skip_message_keys_he(header.message_number);
                match self.recv_chain_key {
                    Some(ckr) => {
                        let (_, message_key) = kdf_ck(&ckr)?;

                        self.recv_count += 1;

                        let header_serialised = header.serialise_header();
                        let concat_ad = concat_header_and_ad(associated_data, header_serialised.as_slice());

                        decrypt(&message_key, cipher_text, &concat_ad.as_slice())
                    }
                    _ => Err(DoubleRatchetError::InvalidState(
                        "Receive Chain Key Missing".to_string(),
                    )),
                }
            }
        }
    }

    fn try_skipped_message_keys_he(
        &mut self,
        header: &CipherText,
        cipher_text: &CipherText,
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>, DoubleRatchetError> {
        todo!()
    }

    fn skip_message_keys_he(&mut self, until: u32) -> Result<(), DoubleRatchetError> {
        if self.recv_count + (DEFAULT_MAX_SKIP as u32) < until {
            return Err(DoubleRatchetError::CannotPerformMaxSkip(format!(
                "{} > {}",
                self.recv_count + (DEFAULT_MAX_SKIP as u32),
                until
            )));
        }
        match self.recv_chain_key {
            Some(ckr) => Ok(while self.recv_count < until {
                let (new_recv_chain_key, message_key) = kdf_ck(&ckr)?;
                self.skipped_message_keys
                    .0
                    .insert((self.dhr.unwrap(), self.recv_count), message_key);
                self.recv_count += 1;
                self.recv_chain_key = Some(new_recv_chain_key);
            }),
            _ => Err(DoubleRatchetError::InvalidState(
                "Receive Chain Key Missing".to_string(),
            )),
        }
    }

    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<(), DoubleRatchetError> {
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


    fn try_decrypt_he(
        &self,
        message_enc: &CipherText,
    ) -> Result<(MessageHeader, bool), DoubleRatchetError> {
        let header = decrypt_he(&self.header_key_recv.unwrap(), message_enc)?;
        if header.is_some(){
            return Ok((header.unwrap(), false));
        }
        let header = decrypt_he(&self.next_header_key_recv.unwrap(), message_enc)?;
        if header.is_some(){
            Ok((header.unwrap(), true))
        } else {
            Err(DoubleRatchetError::DecryptHeaderFailure("Failed to decrypt header".to_string()))
        }
    }
}

// KDF_RK(rk, dh_out): This function is recommended to be implemented using HKDF
// with SHA-256 or SHA-512, using rk as HKDF salt, dh_out as HKDF input key material,
// and an application-specific byte sequence as HKDF info.
// The info value should be chosen to be distinct from other uses of HKDF in the application.
fn kdf_rk_he(
    root_key: KeySecret,
    dh: &SharedSecret,
) -> Result<(KeySecret, KeySecret, KeySecret), DoubleRatchetError> {
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
fn kdf_ck_he(chain_key: &KeySecret) -> Result<(KeySecret, KeySecret), DoubleRatchetError> {
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
fn encrypt_he(
    header_key_send: &KeySecret,
    header: MessageHeader,
) -> Result<CipherText, DoubleRatchetError> {
    let (key_bytes, nonce_bytes) = derive_hkdf_key_and_nonce(header_key_send, HKDF_INFO_ENCRYPTION_HEADER_KEY)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encrypt the plaintext

    let header_seralised = header.serialise_header();

    let ciphertext = cipher
        .encrypt(
            nonce,
            header_seralised.as_slice()
        )
        .map_err(|e| DoubleRatchetError::AeadError(e.to_string()))?;

    Ok(ciphertext)
}

fn decrypt_he(
    header_key_rec: &KeySecret,
    header_enc: &CipherText,
) -> Result<Option<MessageHeader>, DoubleRatchetError> {
    let (key_bytes, nonce_bytes) = derive_hkdf_key_and_nonce(header_key_rec, HKDF_INFO_ENCRYPTION_HEADER_KEY)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher_decrypt_result = cipher
        .decrypt(
            nonce,
            header_enc.as_slice(),
        );

    // Cipher decrypt can fail as the key could be wrong, so it can return None.
    // The deseralise could fail and return deserialise error so we got to return but also
    // return the Optional if it succeeds.

    match cipher_decrypt_result {
        Ok(plaintext) => {
           Ok(Some(deserialize_header(plaintext.as_slice())?))
        }
        Err(_) => {
            Ok(None)
        }
    }
}

fn deserialize_header(data: &[u8]) -> Result<MessageHeader, DoubleRatchetError> {
    if data.len() < 32 + 4 + 4 {
        return Err(DoubleRatchetError::DecryptHeaderFailure("Failed to deserialise Header".to_string()))
    }

    let dh_bytes = &data[0..32];
    let pn_bytes = &data[32..36];
    let n_bytes = &data[36..40];

    let mut dh = [0u8; 32];
    dh.copy_from_slice(dh_bytes);

    let mut pn_buf = [0u8; 4];
    pn_buf.copy_from_slice(pn_bytes);
    let pn = u32::from_be_bytes(pn_buf);

    let mut n_buf = [0u8; 4];
    n_buf.copy_from_slice(n_bytes);
    let n = u32::from_be_bytes(n_buf);

    Ok(MessageHeader {
        dh_public_key: PublicKey::from(dh),
        prev_chain_number: pn,
        message_number: n
    })
}

impl fmt::Debug for DoubleRatchetHE {
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