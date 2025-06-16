mod common;

use crate::common::*;
use crate::libs::encryption::double_ratchet::*;
use gabber_chat_lib::*;
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::path::Path;

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

    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);

    let message1 = b"Hey Alice, how have you been?";

    assert!(matches!(
        bob.ratchet_encrypt(message1, associated_data, &mut real_gen),
        Err(DoubleRatchetError::NotInitialized)
    ));
}

#[test]
fn test_alice_message_fail() {
    let associated_data = b"TEST_ASSOCIATED_DATA";
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);

    let message1 = b"Hi Bob, this is Alice";

    let (header, cipher) = alice
        .ratchet_encrypt(message1, associated_data, &mut real_gen)
        .unwrap();

    let plain_text = bob
        .ratchet_decrypt(header, &cipher, associated_data, &mut real_gen)
        .expect("Decryption should succeed");

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text.clone()),
        String::from_utf8_lossy(&message1.clone())
    );
    assert_eq!(plain_text, message1);
}

#[test]
fn test_bob_message_returned() {
    let alice_ad = b"ALICE_ASSOCIATED_DATA";
    let bob_ad = b"BOB_ASSOCIATED_DATA";
    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);

    let message1 = b"Hi Bob, this is Alice";
    let (header, cipher) = alice
        .ratchet_encrypt(message1, alice_ad, &mut real_gen)
        .unwrap();

    let plain_text = bob
        .ratchet_decrypt(header, &cipher, alice_ad, &mut real_gen)
        .unwrap();

    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text.clone()),
        String::from_utf8_lossy(&message1.clone())
    );

    let message2 = b"Hey Alice, how have you been?";
    let (header, cipher) = bob
        .ratchet_encrypt(message2, bob_ad, &mut real_gen)
        .unwrap();

    let plain_text = alice
        .ratchet_decrypt(header, &cipher, bob_ad, &mut real_gen)
        .unwrap();
    println!(
        "Decrypted: {:?}, Original: {:?}",
        String::from_utf8_lossy(&plain_text.clone()),
        String::from_utf8_lossy(&message2.clone())
    );
    assert_eq!(plain_text, message2);
}

#[test]
fn test_alice_three_in_order() {
    // Alice sends three messages
    let alice_ad = b"ALICE_ASSOCIATED_DATA";
    let messages = [
        b"Message A (will arrive in order)",
        b"Message B (will be dlayd aftr c)",
        b"Message C (will arrive before B)",
    ];

    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);

    let mut headers_and_ciphertexts = Vec::new();

    for msg in messages {
        let (header, ciphertext) = alice.ratchet_encrypt(msg, alice_ad, &mut real_gen).unwrap();
        headers_and_ciphertexts.push((header, ciphertext));
        println!("Alice encrypted: {}", String::from_utf8_lossy(msg));
    }

    // Bob receives messages in different order (A, C, B)
    let (header_a, ciphertext_a) = &headers_and_ciphertexts[0];
    let plaintext_a = bob
        .ratchet_decrypt(header_a.clone(), ciphertext_a, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (1st): {}",
        String::from_utf8_lossy(&plaintext_a)
    );
    assert_eq!(plaintext_a, messages[0]);

    // Message C arrives before B
    let (header_b, ciphertext_b) = &headers_and_ciphertexts[1];
    let plaintext_b = bob
        .ratchet_decrypt(header_b.clone(), ciphertext_b, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (2nd): {}",
        String::from_utf8_lossy(&plaintext_b)
    );
    assert_eq!(plaintext_b, messages[1]);

    // Finally, message B arrives
    let (header_c, ciphertext_c) = &headers_and_ciphertexts[2];
    let plaintext_c = bob
        .ratchet_decrypt(header_c.clone(), ciphertext_c, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (3rd): {}",
        String::from_utf8_lossy(&plaintext_c)
    );
    assert_eq!(plaintext_c, messages[2]);
}

#[test]
fn test_alice_out_of_order() {
    // Alice sends three messages
    let alice_ad = b"ALICE_ASSOCIATED_DATA";
    let messages = [
        b"Message A (will arrive in order)",
        b"Message B (will be dlayd aftr c)",
        b"Message C (will arrive before B)",
    ];

    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);

    let mut headers_and_ciphertexts = Vec::new();

    for msg in messages {
        let (header, ciphertext) = alice.ratchet_encrypt(msg, alice_ad, &mut real_gen).unwrap();
        headers_and_ciphertexts.push((header, ciphertext));
        println!("Alice encrypted: {}", String::from_utf8_lossy(msg));
    }

    // Bob receives messages in different order (A, C, B)
    let (header_a, ciphertext_a) = &headers_and_ciphertexts[0];

    let plaintext_a = bob
        .ratchet_decrypt(header_a.clone(), ciphertext_a, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (1st): {}",
        String::from_utf8_lossy(&plaintext_a)
    );
    assert_eq!(plaintext_a, messages[0]);

    // Message C arrives before B
    let (header_c, ciphertext_c) = &headers_and_ciphertexts[2];
    let plaintext_c = bob
        .ratchet_decrypt(header_c.clone(), ciphertext_c, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (2nd): {}",
        String::from_utf8_lossy(&plaintext_c)
    );
    assert_eq!(plaintext_c, messages[2]);

    // Finally, message B arrives
    let (header_b, ciphertext_b) = &headers_and_ciphertexts[1];
    let plaintext_b = bob
        .ratchet_decrypt(header_b.clone(), ciphertext_b, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (3rd): {}",
        String::from_utf8_lossy(&plaintext_b)
    );
    assert_eq!(plaintext_b, messages[1]);
}
#[test]
fn test_alice_and_bob_out_of_order() {
    // Alice sends three messages
    let alice_ad = b"ALICE_ASSOCIATED_DATA";
    let bob_ad = b"BOB_ASSOCIATED_DATA";
    let messages = [
        b"Message A (will arrive in order)",
        b"Message B (will be dlayd aftr c)",
        b"Message C (will arrive before B)",
    ];

    let mut real_gen = RealKeyGenerator::new();
    let (mut alice, mut bob) = ratchet_init(real_gen);

    let mut headers_and_ciphertexts = Vec::new();

    for msg in messages {
        let (header, ciphertext) = alice.ratchet_encrypt(msg, alice_ad, &mut real_gen).unwrap();
        headers_and_ciphertexts.push((header, ciphertext));
        println!("Alice encrypted: {}", String::from_utf8_lossy(msg));
    }

    // Bob receives messages in different order (A, C, B)
    let (header_a, ciphertext_a) = &headers_and_ciphertexts[0];
    let plaintext_a = bob
        .ratchet_decrypt(header_a.clone(), ciphertext_a, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (1st): {}",
        String::from_utf8_lossy(&plaintext_a)
    );
    assert_eq!(plaintext_a, messages[0]);

    // Message C arrives before B
    let (header_c, ciphertext_c) = &headers_and_ciphertexts[2];
    let plaintext_c = bob
        .ratchet_decrypt(header_c.clone(), ciphertext_c, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (2nd): {}",
        String::from_utf8_lossy(&plaintext_c)
    );
    assert_eq!(plaintext_c, messages[2]);

    let message_bob_to_alice = b"Hey Alice, how have you been?";
    let (header_bob, cipher_bob) = bob
        .ratchet_encrypt(message_bob_to_alice, bob_ad, &mut real_gen)
        .unwrap();
    let plaintext_bob = alice
        .ratchet_decrypt(header_bob.clone(), &cipher_bob, bob_ad, &mut real_gen)
        .unwrap();
    println!(
        "Alice received (1st): {}",
        String::from_utf8_lossy(&plaintext_bob)
    );

    assert_eq!(plaintext_bob, message_bob_to_alice);

    // Finally, message B arrives
    let (header_b, ciphertext_b) = &headers_and_ciphertexts[1];
    let plaintext_b = bob
        .ratchet_decrypt(header_b.clone(), ciphertext_b, alice_ad, &mut real_gen)
        .unwrap();
    println!(
        "Bob received (3rd): {}",
        String::from_utf8_lossy(&plaintext_b)
    );
    assert_eq!(plaintext_b, messages[1]);
}
