//! Криптография: X25519 ECDH + SHA-256 → AES-256-GCM (как в rust_client).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn derive_key(our: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    let shared = our.diffie_hellman(&PublicKey::from(*peer_pub));
    let mut h = Sha256::new();
    h.update(shared.as_bytes());
    let d = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&d);
    key
}

pub fn gcm_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Option<String> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .ok()?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(B64.encode(out))
}

pub fn gcm_decrypt(key: &[u8; 32], encoded: &str, aad: &[u8]) -> Option<String> {
    let data = B64.decode(encoded).ok()?;
    if data.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&data[..12]), Payload { msg: &data[12..], aad })
        .ok()?;
    String::from_utf8(pt).ok()
}

pub fn encrypt_to_peer(
    text: &str,
    peer_pub_b64: &str,
    self_pub_b64: &str,
    our: &StaticSecret,
) -> Option<String> {
    let peer_pub: [u8; 32] = B64.decode(peer_pub_b64).ok()?.try_into().ok()?;
    gcm_encrypt(&derive_key(our, &peer_pub), text.as_bytes(), self_pub_b64.as_bytes())
}

pub fn decrypt_from_peer(encoded: &str, sender_pub_b64: &str, our: &StaticSecret) -> Option<String> {
    let sender_pub: [u8; 32] = B64.decode(sender_pub_b64).ok()?.try_into().ok()?;
    gcm_decrypt(&derive_key(our, &sender_pub), encoded, sender_pub_b64.as_bytes())
}

/// Отпечаток публичного ключа: SHA-256 в формате XX:XX:…
pub fn fingerprint(pub_b64: &str) -> String {
    match B64.decode(pub_b64) {
        Ok(raw) => {
            let d = Sha256::digest(&raw);
            let hexs: String = d.iter().map(|b| format!("{:02x}", b)).collect();
            hexs.as_bytes()
                .chunks(4)
                .map(|c| String::from_utf8_lossy(c).to_uppercase())
                .collect::<Vec<_>>()
                .join(":")
        }
        Err(_) => "?".into(),
    }
}
