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
// Implementation of Signals Double Ratchet Algorithm with x25519_dalek
// https://signal.org/docs/specifications/doubleratchet

pub const DEFAULT_MAX_SKIP: usize = 1000;
const HKDF_INFO_ROOT_KEY: &[u8] = b"ROOT_KEY";
const HKDF_INFO_CHAIN_KEY: &[u8] = b"CHAIN_KEY";
const HKDF_INFO_HEADER_KEY: &[u8] = b"HEADER_KEY";
const HKDF_INFO_ENCRYPTION_KEY: &[u8] = b"ENCRYPTION_KEY";
const HKDF_INFO_ENCRYPTION_HEADER_KEY: &[u8] = b"ENCRYPTION_HEADER_KEY";
const KEY_SECRET_LEN: usize = 32;

type Counter = u32;

pub type MessageId = u32;

pub(crate) type KeySecret = [u8; 32];

type CipherText = Vec<u8>;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricChainState {
    pub chain_key: KeySecret,
    pub message_count: u32,
    // Skipped message keys for this specific chain, keyed by their message_number
    pub skipped_keys: HashMap<MessageId, KeySecret>,
}

impl SymmetricChainState {
    pub fn new(initial_chain_key: KeySecret) -> Self {
        Self {
            chain_key: initial_chain_key,
            message_count: 0,
            skipped_keys: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionChainManager {
    // State for our current sending chain.
    pub sending_chain: Option<SymmetricChainState>,

    // Symmetric states for chains on which we are receiving.
    // Keyed by the remote party's DH public key (as [u8; 32]).
    // This key corresponds to `DoubleRatchet.dhr` when a specific receiving chain is active.
    pub receiving_chains: HashMap<[u8; 32], SymmetricChainState>,
}



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
    InvalidState(String),
    DecryptHeaderFailure(String),
    NotInitialized,
}

// Using a StaticSecret instead of Ephemeral
#[derive(Clone)]
pub struct DHKeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl DHKeyPair {
    //GENERATE_DH(): This function is recommended to generate a key pair based on the Curve25519
    // or Curve448 elliptic curves.
    pub(crate) fn generate_dh() -> Self {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}

pub trait DHKeyGenerator {
    fn generate_dh(&mut self) -> DHKeyPair;
}

#[derive(Clone, Copy)]
pub struct RealKeyGenerator {}

impl RealKeyGenerator {
    pub fn new() -> Self {
        Self {}
    }
}

impl DHKeyGenerator for RealKeyGenerator {
    fn generate_dh(&mut self) -> DHKeyPair {
        DHKeyPair::generate_dh()
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
pub struct MessageHeader {
    pub(crate) dh_public_key: PublicKey,
    pub(crate) prev_chain_number: Counter,
    pub(crate) message_number: Counter,
}

impl MessageHeader {
    pub(crate) fn init(
        dh_public_key: PublicKey,
        prev_chain_number: Counter,
        message_number: Counter,
    ) -> Self {
        Self {
            dh_public_key,
            prev_chain_number,
            message_number,
        }
    }

    pub fn serialise_header(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(self.dh_public_key.as_bytes());
        result.extend_from_slice(&self.message_number.to_be_bytes());
        result.extend_from_slice(&self.prev_chain_number.to_be_bytes());
        result
    }
}

#[derive(Clone)]
pub struct DoubleRatchet {
    // Keys
    root_key: KeySecret,

    // Alice's (Self) DH KeyPair
    pub dhs: DHKeyPair,

    // Bob's (remote, receiver) Public Key that comes from the Message Header
    dhr: Option<PublicKey>,

    // Number of messages in previous sending chain
    prev_number: Counter,

    // Store previous chains and messages
    chain_manager: SessionChainManager,

    // Maximum number of skipped message keys to store
    max_skip: u32,
}

impl DoubleRatchet {
    // Takes an initial shared secrete between two parties, the other parties public key and
    pub fn initialise_alice(
        dh_pair: DHKeyPair,
        shared_root_key: KeySecret,
        bobby_public_key: PublicKey,
    ) -> Self {
        let dh = dh_pair.private.diffie_hellman(&bobby_public_key);
        let (rk, cks, ckr) = kdf_rk(shared_root_key, &dh).unwrap();

        let mut chain_manager = SessionChainManager::default();
        chain_manager.sending_chain = Some(SymmetricChainState::new(cks));
        chain_manager.receiving_chains.insert(
            *bobby_public_key.as_bytes(), // Key by Bob's public key
            SymmetricChainState::new(ckr),
        );

        Self {
            root_key: rk,
            dhs: dh_pair,
            dhr: Some(bobby_public_key),
            prev_number: 0,
            chain_manager,
            max_skip: DEFAULT_MAX_SKIP as u32,
        }
    }

    pub fn initialise_bob(
        shared_root_key: KeySecret,
        dh_pair: DHKeyPair,
        cks: Option<KeySecret>,
    ) -> Self {

        let mut chain_manager = SessionChainManager::default();

        Self {
            root_key: shared_root_key,
            dhs: dh_pair,
            dhr: None,
            prev_number: 0,
            chain_manager,
            max_skip: DEFAULT_MAX_SKIP as u32,
        }
    }

    pub fn ratchet_encrypt<DHKeyGen>(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
        dh_key_generator: &mut DHKeyGen,
    ) -> Result<(MessageHeader, CipherText), DoubleRatchetError>
    where
        DHKeyGen: DHKeyGenerator,
    {
        // cannot run if self is not initialised
        if let Some(dhr) = self.dhr {
            if self.chain_manager.sending_chain.is_none() {
                let dh_pair = dh_key_generator.generate_dh();
                let dh = dh_pair.private.diffie_hellman(&self.dhr.unwrap());
                let (rk, cks, _) = kdf_rk(self.root_key, &dh)?;

                self.chain_manager.sending_chain = Some(SymmetricChainState::new(cks));

                self.root_key = rk;
                self.prev_number = 0;
            }
        } else {
            return Err(DoubleRatchetError::NotInitialized);
        }

        let sending_chain_state = self.chain_manager.sending_chain.as_mut().ok_or_else(|| DoubleRatchetError::InvalidState("Sending chain not initialized, but DHR is present.".to_string()))?;

        let (next_cks, message_key) = kdf_ck(&sending_chain_state.chain_key)?;
        sending_chain_state.chain_key = next_cks;
        let header = MessageHeader::init(self.dhs.public, self.prev_number, sending_chain_state.message_count);

        sending_chain_state.message_count += 1;

        let header_serialised = header.serialise_header();
        let concat_ad = concat_header_and_ad(associated_data, header_serialised.as_slice());

        let cipher_text = encrypt(&message_key, plaintext, &concat_ad.as_slice())?;

        Ok((header, cipher_text))
    }

    pub fn ratchet_decrypt<DHKeyGen>(
        &mut self,
        header: MessageHeader,
        cipher_text: &CipherText,
        associated_data: &[u8],
        dh_key_generator: &mut DHKeyGen,
    ) -> Result<Vec<u8>, DoubleRatchetError>
    where
        DHKeyGen: DHKeyGenerator
    {
        if let Some(plain_text) =
            self.try_skipped_message_keys(&header, cipher_text, associated_data)?
        {
            return Ok(plain_text);
        }

        if Some(&header.dh_public_key) != self.dhr.as_ref() {
            if let Some(old_dhr) = self.dhr { // If there was an old DHR
                if let Some(old_recv_chain) =
                    self.chain_manager.receiving_chains.get_mut(old_dhr.as_bytes()) {
                    // This skip is on the *old* chain, before it's replaced by dh_ratchet
                    Self::skip_message_keys_for_chain(self.max_skip, old_recv_chain, header.prev_chain_number, &old_dhr)?;
                }
            }
            self.dh_ratchet(&header, dh_key_generator);
        }

        let current_recv_chain_state =
            self.chain_manager.receiving_chains.get_mut(header.dh_public_key.as_bytes())
            .ok_or_else(|| DoubleRatchetError::InvalidState("Receiving chain not found after DH ratchet.".to_string()))?;

        Self::skip_message_keys_for_chain(self.max_skip, current_recv_chain_state, header.message_number, &header.dh_public_key)?;
        let (next_ckr, message_key) = kdf_ck(&current_recv_chain_state.chain_key)?;
        current_recv_chain_state.chain_key = next_ckr;
        current_recv_chain_state.message_count += 1;

        let header_serialised = header.serialise_header();
        let concat_ad = concat_header_and_ad(associated_data, header_serialised.as_slice());

        decrypt(&message_key, cipher_text, &concat_ad)
    }

    fn skip_message_keys_for_chain(
        max_skip: u32,
        chain_state: &mut SymmetricChainState,
        until_message_number: u32,
        chain_dh_public_key: &PublicKey,
    ) -> Result<(), DoubleRatchetError> {
        if chain_state.message_count.saturating_add(max_skip) < until_message_number {
           return Err(DoubleRatchetError::CannotPerformMaxSkip(format!(
                "Skipping too many messages for chain {:?}: current_count={}, max_skip={}, trying_to_skip_until={}",
                chain_dh_public_key.as_bytes(), // For identification
                chain_state.message_count,
                max_skip,
                until_message_number
            )))
        }
        while chain_state.message_count < until_message_number {
            let (next_chain_key, message_key) = kdf_ck(&chain_state.chain_key)?;
            chain_state.chain_key = next_chain_key;
            chain_state.skipped_keys.insert(chain_state.message_count, message_key);
            chain_state.message_count += 1;
        }
        Ok(())
    }

    fn try_skipped_message_keys(
        &mut self,
        header: &MessageHeader,
        cipher_text: &CipherText,
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>, DoubleRatchetError> {
        let chain_dh_pk_bytes = *header.dh_public_key.as_bytes();

        if let Some(chain_state) = self.chain_manager.receiving_chains.get_mut(&chain_dh_pk_bytes) {
            if let Some(mk) = chain_state.skipped_keys.remove(&header.message_number) {
                let header_serialised = header.serialise_header();
                let concat_ad = concat_header_and_ad(associated_data, header_serialised.as_slice());
                let plain_text = decrypt(&mk, cipher_text, concat_ad.as_slice())?;
                return Ok(Some(plain_text));
            }
        }
        Ok(None)
    }

    fn dh_ratchet<DHKeyGen>(&mut self, header: &MessageHeader, dh_key_generator: &mut DHKeyGen) -> Result<(), DoubleRatchetError>
    where
        DHKeyGen: DHKeyGenerator
    {
        self.prev_number = self
            .chain_manager
            .sending_chain
            .as_ref()
            .map_or(0, |s| s.message_count);
        self.dhr = Some(header.dh_public_key);

        // calc our DH Ratchet
        let dh_secret = self.dhs.private.diffie_hellman(&header.dh_public_key);
        let (new_rk, new_ckr, _) = kdf_rk(self.root_key, &dh_secret)?;
        self.root_key = new_rk;
        self.chain_manager.receiving_chains.insert(
            header.dh_public_key.to_bytes(),
            SymmetricChainState::new(new_ckr), // Create a new state for this chain
        );

        self.dhs = dh_key_generator.generate_dh();

        // calc their DH Ratchet
        let dh_secret = self.dhs.private.diffie_hellman(&header.dh_public_key);

        let (new_rk, new_cks, _) = kdf_rk(self.root_key, &dh_secret)?;
        self.root_key = new_rk;
        self.chain_manager.sending_chain = Some(SymmetricChainState::new(new_cks));
        Ok(())
    }
}

// KDF_RK(rk, dh_out): This function is recommended to be implemented using HKDF
// with SHA-256 or SHA-512, using rk as HKDF salt, dh_out as HKDF input key material,
// and an application-specific byte sequence as HKDF info.
// The info value should be chosen to be distinct from other uses of HKDF in the application.
pub fn kdf_rk(
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
pub fn kdf_ck(chain_key: &KeySecret) -> Result<(KeySecret, KeySecret), DoubleRatchetError> {
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
pub fn encrypt(
    message_key: &KeySecret,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<CipherText, DoubleRatchetError> {
    let (key_bytes, nonce_bytes) =
        derive_hkdf_key_and_nonce(message_key, HKDF_INFO_ENCRYPTION_KEY)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|e| DoubleRatchetError::AeadError(e.to_string()))?;

    Ok(ciphertext)
}

pub fn decrypt(
    message_key: &KeySecret,
    cipher_text: &CipherText,
    associated_data: &[u8],
) -> Result<Vec<u8>, DoubleRatchetError> {
    let (key_bytes, nonce_bytes) =
        derive_hkdf_key_and_nonce(message_key, HKDF_INFO_ENCRYPTION_KEY)?;

    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plain_text = cipher
        .decrypt(
            nonce,
            Payload {
                msg: cipher_text,
                aad: associated_data,
            },
        )
        .map_err(|e| DoubleRatchetError::AeadError(e.to_string()))?;

    Ok(plain_text)
}

pub fn derive_hkdf_key_and_nonce(
    message_key: &KeySecret,
    const_key: &[u8],
) -> Result<([u8; 32], [u8; 12]), DoubleRatchetError> {
    // Use HKDF to derive double_ratchet key and nonce from message key
    let salt = vec![0u8; Sha256::output_size()];
    let h = Hkdf::<Sha256>::new(Some(&salt), message_key);

    let mut key_bytes = [0u8; 32]; // 256-bit key for ChaCha20Poly1305
    let mut nonce_bytes = [0u8; 12]; // 96-bit nonce
    let mut okm = [0u8; 44]; // 352-bit output key material
    h.expand(const_key, &mut okm)
        .map_err(|e| DoubleRatchetError::InvalidLength(e.to_string()))?;

    key_bytes.copy_from_slice(&okm[..32]);
    nonce_bytes.copy_from_slice(&okm[32..]);
    Ok((key_bytes, nonce_bytes))
}

pub fn concat_header_and_ad(associated_data: &[u8], message_header: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(associated_data);
    result.extend_from_slice(message_header);
    result
}

impl fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DoubleRatchet {{ Alice_Key_Pair: {:?}, Bobby_Public_Key: {:?}, Root_Key: {:?},
            Send_Chain_Key: {:?}, Recv_Chain_Key: {:?}}}",
            self.dhs,
            self.dhr,
            self.root_key,
            self.prev_number,
            self.chain_manager,
        )
    }
}
