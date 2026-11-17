//! A viewer's device key (§3): ECDSA P-256 + SHA-256, as WebCrypto makes it, taken only as the
//! canonical 91-byte SPKI; its `key_id`; the check of a 64-byte `r‖s` signature.

use std::fmt;
use std::sync::Arc;

use aws_lc_rs::signature::{ParsedPublicKey, ECDSA_P256_SHA256_FIXED};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::{sha256, VIEWER_KEY_DOMAIN};

/// The only SPKI accepted: 91 bytes.
pub const SPKI_LEN: usize = 91;

/// The SPKI's first 26 bytes, the same for every P-256 key: SEQUENCE { SEQUENCE { id-ecPublicKey,
/// prime256v1 }, BIT STRING of 66 bytes with no unused bits }. An uncompressed point `04 ‖ X ‖ Y`
/// follows.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The first byte of an uncompressed point (SEC 1).
const UNCOMPRESSED: u8 = 0x04;

/// A signature: `r ‖ s`, 32 bytes each (WebCrypto's format), never DER.
pub const SIGNATURE_LEN: usize = 64;

/// A `key_id`: 32 bytes of SHA-256 in base64url without padding.
pub const KEY_ID_LEN: usize = 43;

/// How much of a `key_id` a log line shows ([`KeyId::short`]).
pub const KEY_ID_SHORT_LEN: usize = 8;

/// Why bytes are not a viewer key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("an SPKI of {len} bytes, not {SPKI_LEN}")]
    WrongLength { len: usize },
    #[error("not the canonical SPKI of a P-256 public key (another algorithm, curve or encoding)")]
    NotP256,
    #[error("the point is not in the uncompressed form")]
    NotUncompressed,
    #[error("the point is not on the P-256 curve")]
    NotOnCurve,
}

/// Why a signature does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    #[error("a signature of {len} bytes, not {SIGNATURE_LEN}")]
    WrongLength { len: usize },
    #[error("the signature does not verify")]
    Invalid,
}

/// A `key_id`, as [`KeyId::parse`] accepts it: exactly 43 base64url characters that decode to 32
/// bytes and are their canonical spelling. Both forms are kept: the text for files, logs and
/// `start_param`; the raw 32 bytes for what the protocol signs ([`KeyId::as_bytes`]).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId {
    text: String,
    bytes: [u8; 32],
}

impl KeyId {
    /// Parse a `key_id` strictly. `None` for anything that is not exactly the encoding of 32 bytes.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != KEY_ID_LEN
            || !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        // The engine refuses padding and non-zero trailing bits, so one text per 32 bytes; the
        // re-encoding says so again.
        let decoded = URL_SAFE_NO_PAD.decode(text).ok()?;
        let bytes = <[u8; 32]>::try_from(decoded.as_slice()).ok()?;
        let key_id = Self::from_bytes(bytes);
        (key_id.text == text).then_some(key_id)
    }

    /// The `key_id` whose raw form is `bytes`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            text: URL_SAFE_NO_PAD.encode(bytes),
            bytes,
        }
    }

    /// The `key_id` of `spki` (§3): `base64url(SHA-256(VIEWER_KEY_DOMAIN ‖ spki))`.
    fn of_spki(spki: &[u8]) -> Self {
        Self::from_bytes(sha256(&[VIEWER_KEY_DOMAIN, spki]))
    }

    /// The base64url text (43 characters): for files and the wire, never for a log line.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The first [`KEY_ID_SHORT_LEN`] characters, the only form logs, error texts and damage
    /// details carry (protocol spec §1.4: `kid=AbCd1234`).
    pub fn short(&self) -> &str {
        // The text is 43 ASCII characters by construction.
        self.text.get(..KEY_ID_SHORT_LEN).unwrap_or(&self.text)
    }

    /// The raw 32 bytes: SHA-256 of the domain and the SPKI.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// The full text, as on the wire (`start_param`, files). Logs use [`KeyId::short`] instead.
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl serde::Serialize for KeyId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

/// Only what [`KeyId::parse`] accepts.
impl<'de> serde::Deserialize<'de> for KeyId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("not a canonical key_id"))
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short: `?` in a log line or an error's Debug must not carry a full key_id (§1.4).
        write!(f, "KeyId({}…)", self.short())
    }
}

/// A viewer's public key, parsed and checked on the curve once ([`ViewerKey::from_spki`]).
#[derive(Clone)]
pub struct ViewerKey {
    spki: [u8; SPKI_LEN],
    key_id: KeyId,
    parsed: Arc<ParsedPublicKey>,
}

impl ViewerKey {
    /// Take `spki` as a viewer key: exactly the canonical 91 bytes of a P-256 key with an
    /// uncompressed point that is on the curve. Anything else — another curve or algorithm, a
    /// compressed point, a byte more or less, the point at infinity or off the curve — is refused
    /// here, not at the first signature.
    pub fn from_spki(spki: &[u8]) -> Result<Self, KeyError> {
        match Self::from_spki_quiet(spki) {
            Ok(accepted) => {
                tracing::debug!(kid = %accepted.key_id.short(), "viewer key: accepted");
                Ok(accepted)
            }
            Err(why) => {
                tracing::debug!(len = spki.len(), "viewer key: refused ({why})");
                Err(why)
            }
        }
    }

    /// [`ViewerKey::from_spki`] without a log line: for the store, which re-checks every key of
    /// its list at each load and each save and logs one summary (or the damage) instead.
    pub(super) fn from_spki_quiet(spki: &[u8]) -> Result<Self, KeyError> {
        let Ok(fixed) = <[u8; SPKI_LEN]>::try_from(spki) else {
            return Err(KeyError::WrongLength { len: spki.len() });
        };
        if fixed[..SPKI_PREFIX.len()] != SPKI_PREFIX {
            return Err(KeyError::NotP256);
        }
        if fixed[SPKI_PREFIX.len()] != UNCOMPRESSED {
            return Err(KeyError::NotUncompressed);
        }
        // aws-lc parses the SPKI for P-256 and validates the key (the point on the curve, not the
        // point at infinity) before it is ever used.
        let parsed = ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, fixed)
            .map_err(|_| KeyError::NotOnCurve)?;
        Ok(Self {
            key_id: KeyId::of_spki(&fixed),
            spki: fixed,
            parsed: Arc::new(parsed),
        })
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The canonical SPKI, as stored.
    pub fn spki(&self) -> &[u8; SPKI_LEN] {
        &self.spki
    }

    /// Check `signature` (exactly 64 bytes, `r ‖ s`) over `message` with ECDSA P-256 SHA-256. Which
    /// bytes are signed is the protocol spec's; this is a check over bytes.
    ///
    /// ECDSA signatures are malleable (`(r, s)` and `(r, n − s)` both verify), and anyone holding
    /// the key can make many signatures of one message: replay protection must come from a fresh
    /// PC nonce inside `message`, never from remembering signature bytes.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigError> {
        if signature.len() != SIGNATURE_LEN {
            tracing::debug!(
                kid = %self.key_id.short(),
                len = signature.len(),
                "viewer key: signature refused (wrong length)"
            );
            return Err(SigError::WrongLength {
                len: signature.len(),
            });
        }
        match self.parsed.verify_sig(message, signature) {
            Ok(()) => {
                tracing::debug!(
                    kid = %self.key_id.short(),
                    message_len = message.len(),
                    "viewer key: signature verified"
                );
                Ok(())
            }
            Err(_) => {
                tracing::debug!(
                    kid = %self.key_id.short(),
                    message_len = message.len(),
                    "viewer key: signature refused (does not verify)"
                );
                Err(SigError::Invalid)
            }
        }
    }
}

impl fmt::Debug for ViewerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ViewerKey({}…)", self.key_id.short())
    }
}

impl PartialEq for ViewerKey {
    fn eq(&self, other: &Self) -> bool {
        self.spki == other.spki
    }
}

impl Eq for ViewerKey {}

#[cfg(test)]
pub(super) mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A P-256 key made outside Rust (`openssl ecparam -name prime256v1 -genkey`, then
    /// `openssl ec -pubout -outform DER`), its SPKI in hex.
    pub(in crate::viewer_keys) const OPENSSL_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200044e70c5db7097ff5bdf9dd3be8be35497426abf6cf2c33250209b86ffa4bc68e0e60c4160974ef4d48f6c7465f7070c40745723017cadeec252a15cfde27585fa";

    /// Its `key_id`, computed outside Rust two ways that agreed:
    /// `(printf 'AFKLINK-VIEWER-KEY-V1\0'; cat spki.der) | openssl dgst -sha256 -binary | openssl
    /// base64 -A | tr '+/' '-_' | tr -d '='` and `python3 -I` with `hashlib.sha256` and
    /// `base64.urlsafe_b64encode(...).rstrip(b"=")`.
    const OPENSSL_KEY_ID: &str = "8cc9c5eClTUwMMCSZj0IN_qXAE9sUL3r_vrBkfwYVh8";

    /// The message `openssl dgst -sha256 -sign key.pem` signed with that key …
    const OPENSSL_MESSAGE: &[u8] = b"AFKLink viewer key test vector: offer_proof bytes go here";
    /// … and its signature, the DER's two INTEGERs (`openssl asn1parse`) as `r ‖ s`, 32 bytes each.
    const OPENSSL_SIGNATURE: &str = "7eb340fb520291ff7f6872da1aead33accc7d7f6d0bdf36da9056fb000936e0377f866c3461d7383fea639ba797ae1bb9043cddb2e8191f5d76db0f5c1e85b72";

    /// A fresh key pair and its viewer key, for tests that need a second key or to sign.
    pub(in crate::viewer_keys) fn fresh() -> (EcdsaKeyPair, ViewerKey) {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        let key = ViewerKey::from_spki(&spki).unwrap();
        (pair, key)
    }

    fn openssl_key() -> ViewerKey {
        ViewerKey::from_spki(&hex(OPENSSL_SPKI)).unwrap()
    }

    #[test]
    fn key_id_matches_the_value_computed_outside_rust() {
        let key = openssl_key();
        assert_eq!(key.key_id().as_str(), OPENSSL_KEY_ID);
        assert_eq!(key.key_id().as_str().len(), KEY_ID_LEN);
        // The raw bytes are the SHA-256 the text encodes.
        assert_eq!(
            key.key_id().as_bytes(),
            &sha256(&[VIEWER_KEY_DOMAIN, key.spki()])
        );
        assert_eq!(KeyId::from_bytes(*key.key_id().as_bytes()), *key.key_id());
        assert_eq!(KeyId::parse(OPENSSL_KEY_ID).unwrap(), *key.key_id());
        assert_eq!(key.spki().as_slice(), hex(OPENSSL_SPKI).as_slice());
    }

    #[test]
    fn spki_of_wrong_length_is_refused() {
        let spki = hex(OPENSSL_SPKI);
        assert_eq!(
            ViewerKey::from_spki(&spki[..90]).unwrap_err(),
            KeyError::WrongLength { len: 90 }
        );
        let mut long = spki.clone();
        long.push(0);
        assert_eq!(
            ViewerKey::from_spki(&long).unwrap_err(),
            KeyError::WrongLength { len: 92 }
        );
        assert_eq!(
            ViewerKey::from_spki(&[]).unwrap_err(),
            KeyError::WrongLength { len: 0 }
        );
    }

    #[test]
    fn other_curves_and_algorithms_are_refused() {
        // openssl-made P-384 (120 bytes) and secp256k1 (88 bytes) SPKIs.
        let p384 = hex("3076301006072a8648ce3d020106052b81040022036200043c60c59944d57b28ffdb479de3ed797bf2d2d581a6fd6c6910d4115c843e4adb78139c9e041d1b62e862119eb7ee67217fc2c35d20f3b9200d9129cfcc9e52dab4bb6764d3ac6d098336fcac97638947584b7ef1e67f4ca2457047a79b979f09");
        let k1 = hex("3056301006072a8648ce3d020106052b8104000a03420004f44314d1469110f9105e6abe07c6ea23ac81bc009ea0cf38f2efe6e8980f4aae1b3f1fd6f49b6ede9d6442d611bcfc72c54d9edfffd25d49ce2e0d615241ccc5");
        assert!(matches!(
            ViewerKey::from_spki(&p384),
            Err(KeyError::WrongLength { len: 120 })
        ));
        assert!(matches!(
            ViewerKey::from_spki(&k1),
            Err(KeyError::WrongLength { len: 88 })
        ));
        // 91 bytes with the curve OID's last byte changed (another curve's OID), and with
        // the algorithm OID changed: still refused on the prefix.
        let mut curve = hex(OPENSSL_SPKI);
        curve[22] = 0x04;
        assert_eq!(ViewerKey::from_spki(&curve).unwrap_err(), KeyError::NotP256);
        let mut alg = hex(OPENSSL_SPKI);
        alg[12] = 0x03;
        assert_eq!(ViewerKey::from_spki(&alg).unwrap_err(), KeyError::NotP256);
        // A BIT STRING with unused bits.
        let mut bits = hex(OPENSSL_SPKI);
        bits[25] = 0x01;
        assert_eq!(ViewerKey::from_spki(&bits).unwrap_err(), KeyError::NotP256);
    }

    #[test]
    fn compressed_point_is_refused() {
        // openssl's compressed SPKI of the same key: 59 bytes.
        let compressed = hex("3039301306072a8648ce3d020106082a8648ce3d030107032200024e70c5db7097ff5bdf9dd3be8be35497426abf6cf2c33250209b86ffa4bc68e0");
        assert_eq!(
            ViewerKey::from_spki(&compressed).unwrap_err(),
            KeyError::WrongLength { len: 59 }
        );
        // The 91-byte form with a compressed or hybrid point tag.
        for tag in [0x02, 0x03, 0x06, 0x07, 0x00] {
            let mut spki = hex(OPENSSL_SPKI);
            spki[26] = tag;
            assert_eq!(
                ViewerKey::from_spki(&spki).unwrap_err(),
                KeyError::NotUncompressed,
                "tag {tag:#x}"
            );
        }
    }

    #[test]
    fn off_curve_and_zero_points_are_refused() {
        let mut off = hex(OPENSSL_SPKI);
        off[90] ^= 0x01; // Y changed: not on the curve
        assert_eq!(
            ViewerKey::from_spki(&off).unwrap_err(),
            KeyError::NotOnCurve
        );
        let mut zero = SPKI_PREFIX.to_vec();
        zero.push(UNCOMPRESSED);
        zero.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            ViewerKey::from_spki(&zero).unwrap_err(),
            KeyError::NotOnCurve
        );
        let mut ff = SPKI_PREFIX.to_vec();
        ff.push(UNCOMPRESSED);
        ff.extend_from_slice(&[0xffu8; 64]);
        assert_eq!(ViewerKey::from_spki(&ff).unwrap_err(), KeyError::NotOnCurve);
    }

    #[test]
    fn openssl_signature_verifies() {
        let key = openssl_key();
        assert_eq!(key.verify(OPENSSL_MESSAGE, &hex(OPENSSL_SIGNATURE)), Ok(()));
    }

    #[test]
    fn bad_signatures_are_refused() {
        let key = openssl_key();
        let sig = hex(OPENSSL_SIGNATURE);
        assert_eq!(
            key.verify(OPENSSL_MESSAGE, &sig[..63]),
            Err(SigError::WrongLength { len: 63 })
        );
        let mut long = sig.clone();
        long.push(0);
        assert_eq!(
            key.verify(OPENSSL_MESSAGE, &long),
            Err(SigError::WrongLength { len: 65 })
        );
        assert_eq!(
            key.verify(OPENSSL_MESSAGE, &[0u8; 64]),
            Err(SigError::Invalid)
        );
        assert_eq!(key.verify(b"another message", &sig), Err(SigError::Invalid));
        for bit in [0usize, 100, 300, 511] {
            let mut flipped = sig.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                key.verify(OPENSSL_MESSAGE, &flipped),
                Err(SigError::Invalid),
                "bit {bit}"
            );
        }
        let (_, other) = fresh();
        assert_eq!(other.verify(OPENSSL_MESSAGE, &sig), Err(SigError::Invalid));
    }

    #[test]
    fn own_signatures_round_trip() {
        let (pair, key) = fresh();
        let sig = pair.sign(&SystemRandom::new(), b"nonce").unwrap();
        assert_eq!(key.verify(b"nonce", sig.as_ref()), Ok(()));
        assert_eq!(key.verify(b"nonce2", sig.as_ref()), Err(SigError::Invalid));
    }

    #[test]
    fn key_id_parser_is_strict() {
        assert!(KeyId::parse(OPENSSL_KEY_ID).is_some());
        assert!(KeyId::parse(&OPENSSL_KEY_ID[..42]).is_none());
        assert!(KeyId::parse(&format!("{OPENSSL_KEY_ID}A")).is_none());
        assert!(KeyId::parse(&format!("{OPENSSL_KEY_ID}=")).is_none());
        // Standard-alphabet characters, whitespace.
        assert!(KeyId::parse(&OPENSSL_KEY_ID.replace('_', "/")).is_none());
        assert!(KeyId::parse(&format!(" {}", &OPENSSL_KEY_ID[1..])).is_none());
        // The last character carries 2 spare bits: '8' → '9' sets one, so not canonical.
        let last = &OPENSSL_KEY_ID[..42];
        assert!(KeyId::parse(&format!("{last}8")).is_some());
        assert!(KeyId::parse(&format!("{last}9")).is_none());
        assert!(KeyId::parse("").is_none());
    }

    #[test]
    fn logs_and_debug_name_a_key_by_eight_characters() {
        let key = openssl_key();
        let id = key.key_id();
        assert_eq!(id.short(), &OPENSSL_KEY_ID[..KEY_ID_SHORT_LEN]);
        // Display stays the wire form; Debug (what `?` in a log line prints) is short.
        assert_eq!(id.to_string(), OPENSSL_KEY_ID);
        for debug in [format!("{id:?}"), format!("{key:?}")] {
            assert!(debug.contains(id.short()), "{debug}");
            assert!(!debug.contains(OPENSSL_KEY_ID), "{debug}");
        }
    }
}
