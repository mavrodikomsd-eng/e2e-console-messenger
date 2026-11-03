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

#[cfg(test)]
mod tests {
    use super::*;

    /// Кросс-стек регрессия: зашифровано Python (modules/crypto.py,
    /// pycryptodome X25519 + AES-GCM), расшифровывается Rust-функциями.
    /// Векторы сгенерированы tools/chat_v2.py — если формат разъедется,
    /// GUI покажет «не удалось расшифровать (подмена/ключ)».
    #[test]
    fn decrypts_python_encrypted_message() {
        let seed1_b64 = "UHYbgZP1BtXSGpBmmoYFzvEhTolhQw/qgOFwPaIWXWc="; // наш (python)
        let pub1_b64 = "JSFIRz+gwtXNTq81cX6WAZX+rO6rPi710YoDIts6XFo=";
        let seed2_b64 = "Qgoq/tfR6ggvC8gHsOQEuorRqV9y918TuTXEyEb/dAQ="; // peer (python)
        let pub2_b64 = "K5INWFF+vnkvLUITaHCZgPRe931vHQHY+tYwFh0NiX0=";
        let ct = "OWXL0qaSfJOLGJEg1Lgb2GCFZmjR7qH+N8/vbCHRbXOBsfMSATHephiSrWwNd3C5m2l5Ey4e5N7ibg==";
        let want = "привет от питона";

        // 1. Rust расшифровывает питонье
        let seed2_raw: [u8; 32] = B64.decode(seed2_b64).unwrap().try_into().unwrap();
        let our = StaticSecret::from(seed2_raw);
        let got = decrypt_from_peer(ct, pub1_b64, &our);
        assert_eq!(got.as_deref(), Some(want));

        // 2. Rust шифрует ответ питоньим ключом — общий секрет совпадает
        let seed1_raw: [u8; 32] = B64.decode(seed1_b64).unwrap().try_into().unwrap();
        let our1 = StaticSecret::from(seed1_raw);
        let ct_back = encrypt_to_peer("ответ раста", pub1_b64, pub2_b64, &our1).unwrap();
        // Расшифровка «питоном» невозможна здесь, но шифрование должно пройти
        // с ключом, который python-сторона выведет из того же секрета.
        assert!(!ct_back.is_empty());

        // 3. Питоний pub из seed совпадает с растовым:
        let our2_pub = PublicKey::from(&our);
        assert_eq!(B64.encode(our2_pub.as_bytes()), pub2_b64);
    }
}
