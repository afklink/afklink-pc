//! Bytes the protocol signs (protocol spec §1.1): `LP(x)` = the length of `x` in bytes as a `u32`
//! big-endian, then the bytes; a signed message is `LP(domain) ‖ LP(field) ‖ …` with nothing
//! between and nothing after. Only what this module's callers sign or check is here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::KeyId;

/// The domain of a same-device recovery (spec §8.3), signed by the recovery key.
pub const RECOVER_DOMAIN: &str = "AFKLINK-RECOVER-V1";
/// `offer_proof` (spec §3.1), signed by the device key.
pub const OFFER_DOMAIN: &str = "AFKLINK-OFFER-V1";
/// The key card (spec §4), signed by the device key.
pub const KEY_REG_DOMAIN: &str = "AFKLINK-KEY-REG-V1";
/// `first_use` (spec §9), signed by the key being added.
pub const FIRST_USE_DOMAIN: &str = "AFKLINK-FIRST-USE-V1";
/// `endorse` (spec §6.5), signed by the old device's key.
pub const ENDORSE_DOMAIN: &str = "AFKLINK-ENDORSE-V1";
/// The owner's invitation (spec §7), signed by an owner's device key.
pub const INVITE_DOMAIN: &str = "AFKLINK-INVITE-V1";
/// `grant` (spec §7), signed by an owner's device key; it carries the PC's grant token.
pub const GRANT_DOMAIN: &str = "AFKLINK-GRANT-V2";

/// The length of `nonce_pc` (spec §1.2).
pub const NONCE_PC_LEN: usize = 16;
/// The length of `endorse_id`, `grant_id`, `inv_id` (spec §1.2).
pub const GROUND_ID_BYTES: usize = 16;
/// The length of a DTLS fingerprint (spec §3.3).
pub const FINGERPRINT_LEN: usize = 32;
/// The length of a non-empty grant token (spec §7 «Токен выдачи»).
pub const GRANT_TOKEN_BYTES: usize = 16;

/// The PC's grant token (spec §7 «Токен выдачи»): none yet (a new PC: `""` on the wire and in the
/// file), or [`GRANT_TOKEN_BYTES`] random bytes. A grant is accepted only while the token it
/// carries is the current one, byte for byte; every removal the PC learns of replaces it. Not a
/// secret, but never logged: `Debug` says only whether there is one.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct GrantToken(Option<[u8; GRANT_TOKEN_BYTES]>);

impl GrantToken {
    /// Strict: `""`, or exactly [`GRANT_TOKEN_BYTES`] bytes in strict base64url ([`b64url_exact`]).
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() {
            return Some(Self(None));
        }
        b64url_array::<GRANT_TOKEN_BYTES>(text).map(|b| Self(Some(b)))
    }

    /// Fresh random bytes from the system CSPRNG (aws-lc-rs, as the nonce book's). Should it fail,
    /// the bytes are derived from `previous`, the wall clock and a process counter (an `error`
    /// log): the token still changes, so every grant signed over `previous` is refused; only its
    /// unpredictability is weaker. Never `""`.
    pub fn fresh(previous: Self) -> Self {
        let mut bytes = [0u8; GRANT_TOKEN_BYTES];
        let rng = aws_lc_rs::rand::SystemRandom::new();
        if let Err(e) = aws_lc_rs::rand::SecureRandom::fill(&rng, &mut bytes) {
            static DERIVED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = DERIVED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            tracing::error!(
                "viewer keys: the system random generator failed ({e:?}); the grant token is \
                 derived from the previous one, the clock and a counter (it still changes)"
            );
            let digest = super::sha256(&[
                b"AFKLINK-GRANT-TOKEN-FALLBACK",
                previous.as_bytes(),
                &nanos.to_be_bytes(),
                &n.to_be_bytes(),
            ]);
            bytes.copy_from_slice(&digest[..GRANT_TOKEN_BYTES]);
        }
        Self(Some(bytes))
    }

    /// The bytes the grant signs (`LP` of them): empty for none.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref().map_or(&[][..], |b| &b[..])
    }

    /// The wire and file form: `""`, or 22 characters of base64url.
    pub fn to_wire(self) -> String {
        self.0
            .map_or_else(String::new, |b| URL_SAFE_NO_PAD.encode(b))
    }

    /// None yet (`""`).
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl std::fmt::Debug for GrantToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.is_empty() {
            "GrantToken(none)"
        } else {
            "GrantToken(set)"
        })
    }
}

/// Strict base64url (spec §1.2): only `A–Z a–z 0–9 - _`, no `=`, exactly the encoding of `len`
/// bytes, the unused low bits of the last character zero (decoding and encoding again gives the
/// same text). `None` otherwise.
pub fn b64url_exact(text: &str, len: usize) -> Option<Vec<u8>> {
    // The base64url text of `len` bytes, unpadded: ceil(len * 4 / 3) characters.
    let chars = (len * 4).div_ceil(3);
    if text.len() != chars {
        return None;
    }
    // The engine refuses `=`, `+`, `/` and non-zero trailing bits; the length check above makes
    // the decoded length exact.
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (bytes.len() == len).then_some(bytes)
}

/// [`b64url_exact`] into an array.
pub fn b64url_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    b64url_exact(text, N).and_then(|v| <[u8; N]>::try_from(v).ok())
}

/// A number inside `LP`: `u64` big-endian, 8 bytes (spec §1.1: `issued_at`).
pub fn u64_be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// A Telegram user id inside `LP`: decimal ASCII, no sign, no leading zeros (spec §1.1).
pub fn decimal(n: i64) -> String {
    n.to_string()
}

/// `m` of `offer_proof` (spec §3.1).
pub fn offer_message(
    session_id: &str,
    device_id: &str,
    key_id: &KeyId,
    nonce_pc: &[u8; NONCE_PC_LEN],
    fp_viewer: &[u8; FINGERPRINT_LEN],
) -> Vec<u8> {
    lp(&[
        OFFER_DOMAIN.as_bytes(),
        session_id.as_bytes(),
        device_id.as_bytes(),
        key_id.as_bytes(),
        nonce_pc,
        fp_viewer,
    ])
}

/// `reg` of a key card (spec §4): `rpk` is the recovery key's SPKI, or absent (`LP("")`).
pub fn key_reg_message(key_id: &KeyId, kind: &str, platform: &str, rpk: Option<&[u8]>) -> Vec<u8> {
    lp(&[
        KEY_REG_DOMAIN.as_bytes(),
        key_id.as_bytes(),
        kind.as_bytes(),
        platform.as_bytes(),
        rpk.unwrap_or_default(),
    ])
}

/// `f` of `first_use` (spec §9).
pub fn first_use_message(device_id: &str, key_id: &KeyId, uid: i64) -> Vec<u8> {
    lp(&[
        FIRST_USE_DOMAIN.as_bytes(),
        device_id.as_bytes(),
        key_id.as_bytes(),
        decimal(uid).as_bytes(),
    ])
}

/// `e` of `endorse` (spec §6.5).
pub fn endorse_message(
    key_id: &KeyId,
    by: &KeyId,
    endorse_id: &[u8; GROUND_ID_BYTES],
    issued_at: u64,
) -> Vec<u8> {
    lp(&[
        ENDORSE_DOMAIN.as_bytes(),
        key_id.as_bytes(),
        by.as_bytes(),
        endorse_id,
        &u64_be(issued_at),
    ])
}

/// `i` of the owner's invitation (spec §7).
pub fn invite_message(
    device_id: &str,
    inv_id: &[u8; GROUND_ID_BYTES],
    issued_at: u64,
    by: &KeyId,
) -> Vec<u8> {
    lp(&[
        INVITE_DOMAIN.as_bytes(),
        device_id.as_bytes(),
        inv_id,
        &u64_be(issued_at),
        by.as_bytes(),
    ])
}

/// The fields of `g` (spec §7), as the grant carries them.
#[derive(Debug, Clone, Copy)]
pub struct GrantFields<'a> {
    pub device_id: &'a str,
    pub key_id: &'a KeyId,
    pub telegram_user_id: i64,
    /// `null` is `LP("")`.
    pub name: Option<&'a str>,
    /// `null` is `LP("")`.
    pub username: Option<&'a str>,
    /// `null` only on a grant without a signed invitation: `LP("")`.
    pub inv_id: Option<&'a [u8; GROUND_ID_BYTES]>,
    pub grant_id: &'a [u8; GROUND_ID_BYTES],
    pub grant_token: &'a GrantToken,
    pub issued_at: u64,
    pub by: &'a KeyId,
}

/// `g` of a `grant` (spec §7); the role is always `"guest"`.
pub fn grant_message(g: &GrantFields<'_>) -> Vec<u8> {
    lp(&[
        GRANT_DOMAIN.as_bytes(),
        g.device_id.as_bytes(),
        g.key_id.as_bytes(),
        decimal(g.telegram_user_id).as_bytes(),
        g.name.unwrap_or_default().as_bytes(),
        g.username.unwrap_or_default().as_bytes(),
        b"guest",
        g.inv_id.map_or(&[][..], |i| &i[..]),
        g.grant_id,
        g.grant_token.as_bytes(),
        &u64_be(g.issued_at),
        g.by.as_bytes(),
    ])
}

/// `LP(part₀) ‖ LP(part₁) ‖ …` (spec §1.1).
///
/// A part longer than `u32::MAX` bytes cannot reach here (every field comes from a bounded wire
/// frame); if one did, its length would saturate, which gives bytes no honest signer signed, so
/// the check over them fails closed.
pub fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| 4 + p.len()).sum());
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// `r` of a same-device recovery (spec §8.3): `LP("AFKLINK-RECOVER-V1") ‖ LP(device_id) ‖
/// LP(session_id) ‖ LP(key_id_new) ‖ LP(nonce_pc)`. `device_id` is the PC's own, `session_id`
/// the session's, both UTF-8 exactly as on the wire; `key_id_new` its raw 32 bytes; `nonce_pc`
/// its raw 16 bytes.
pub fn recover_message(
    device_id: &str,
    session_id: &str,
    new_key: &KeyId,
    nonce_pc: &[u8; NONCE_PC_LEN],
) -> Vec<u8> {
    lp(&[
        RECOVER_DOMAIN.as_bytes(),
        device_id.as_bytes(),
        session_id.as_bytes(),
        new_key.as_bytes(),
        nonce_pc,
    ])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

    use super::*;
    use crate::viewer_keys::ViewerKey;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Protocol spec, appendix A.7 (recover.json, case main), generated outside Rust (bun,
    // WebCrypto + node:crypto) and copied here byte for byte.
    const DEVICE_ID: &str = "8d3b1f42-6c7a-4e09-b5d8-2a9e7c1f3b64";
    const SESSION_ID: &str = "5f0c6a1e-3b2d-4c8e-9a71-0d2e4f6b8c10";
    /// Key B's `key_id` raw (A.3 and A.7) …
    const KEY_B_HEX: &str = "c6fd4b2c5317b271c905f3dab92fb7fe2e07deed475317bb528ef26cb16f122f";
    /// … and as text (A.3).
    const KEY_B_TEXT: &str = "xv1LLFMXsnHJBfPauS-3_i4H3u1HUxe7Uo7ybLFvEi8";
    /// `nonce_pc` raw (A.1, A.7); `bbnh3oYjcCDYQbDNQTk0Rw` on the wire.
    const NONCE_HEX: &str = "6db9e1de86237020d841b0cd41393447";
    const NONCE_WIRE: &str = "bbnh3oYjcCDYQbDNQTk0Rw";
    /// The full message, 158 bytes (A.7).
    const R_HEX: &str = concat!(
        "0000001241464b4c494e4b2d5245434f5645522d5631",
        "0000002438643362316634322d366337612d346530392d623564382d326139653763316633623634",
        "0000002435663063366131652d336232642d346338652d396137312d306432653466366238633130",
        "00000020c6fd4b2c5317b271c905f3dab92fb7fe2e07deed475317bb528ef26cb16f122f",
        "000000106db9e1de86237020d841b0cd41393447",
    );
    /// The recovery key RK's SPKI (A.2, `rpk` of key A's card).
    const RK_SPKI_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d0301070342000432c70eb024af9b58e123401ecb3c596032a007546e3b6d953765cd8859117e1fb22d49202d109b4cf6f8f70a8cdb7e8af01756211fa2fe0ee0d40b1a1de6a594";
    /// `rsig` of that run (A.7): ECDSA signatures differ per run, so it is checked, not compared.
    const RSIG: &str =
        "Rra7VKYvXJB-4LYSlOG6i9YfoWBW8fP1v8s8BktqgsYns7sZnYyPqXVH1tu9hBal0bINyZDEp0kene6tApszoA";

    fn key_b() -> KeyId {
        KeyId::from_bytes(hex(KEY_B_HEX).try_into().unwrap())
    }

    fn nonce() -> [u8; NONCE_PC_LEN] {
        hex(NONCE_HEX).try_into().unwrap()
    }

    #[test]
    fn lp_is_a_big_endian_length_then_the_bytes() {
        assert_eq!(lp(&[]), Vec::<u8>::new());
        assert_eq!(lp(&[b""]), vec![0, 0, 0, 0]);
        assert_eq!(lp(&[b"ab", b""]), vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0]);
        let long = vec![7u8; 0x0102];
        let out = lp(&[&long]);
        assert_eq!(&out[..4], &[0, 0, 1, 2]);
        assert_eq!(&out[4..], long.as_slice());
    }

    #[test]
    fn recover_message_is_the_spec_vector() {
        // The vector's inputs agree with each other first.
        assert_eq!(key_b().as_str(), KEY_B_TEXT);
        assert_eq!(URL_SAFE_NO_PAD.encode(nonce()), NONCE_WIRE);
        let r = recover_message(DEVICE_ID, SESSION_ID, &key_b(), &nonce());
        assert_eq!(r.len(), 158);
        assert_eq!(r, hex(R_HEX));
    }

    #[test]
    fn the_spec_rsig_verifies_over_the_built_message_and_nothing_else() {
        let rk = ViewerKey::from_spki(&hex(RK_SPKI_HEX)).unwrap();
        let rsig = URL_SAFE_NO_PAD.decode(RSIG).unwrap();
        let r = recover_message(DEVICE_ID, SESSION_ID, &key_b(), &nonce());
        assert_eq!(rk.verify(&r, &rsig), Ok(()));
        // Another session, another PC, another new key, another nonce: refused.
        let mut other_nonce = nonce();
        other_nonce[0] ^= 1;
        for other in [
            recover_message(
                DEVICE_ID,
                "5f0c6a1e-3b2d-4c8e-9a71-0d2e4f6b8c11",
                &key_b(),
                &nonce(),
            ),
            recover_message(
                "8d3b1f42-6c7a-4e09-b5d8-2a9e7c1f3b65",
                SESSION_ID,
                &key_b(),
                &nonce(),
            ),
            recover_message(DEVICE_ID, SESSION_ID, &KeyId::from_bytes([0; 32]), &nonce()),
            recover_message(DEVICE_ID, SESSION_ID, &key_b(), &other_nonce),
            // The field boundary moved: the same bytes in another split.
            lp(&[
                RECOVER_DOMAIN.as_bytes(),
                format!("{DEVICE_ID}5").as_bytes(),
                &SESSION_ID.as_bytes()[1..],
                key_b().as_bytes(),
                &nonce(),
            ]),
        ] {
            assert!(rk.verify(&other, &rsig).is_err());
        }
    }
}
