//! Telegram's attestation of a viewer key (§3.1): a Mini App's initData that Telegram signed with
//! its published Ed25519 key (Bot API 8.0, «Validating data for Third-Party Use»), opened through a
//! direct link whose `start_param` is `k_<key_id>`. The PC checks it alone, with the key and the bot
//! id built into the agent: the server, which holds the bot token, cannot make one.
//!
//! The data-check string, as core.telegram.org/bots/webapps gives it:
//! `"<bot_id>:WebAppData" + "\n" + join("\n", sorted("key=value" for every field but hash and
//! signature))`. The fields are read exactly as Telegram and `URLSearchParams` read them — `&`
//! between pairs, the first `=` between key and value, `+` a space, `%XX` a byte, then UTF-8 — and
//! more strictly where that only refuses what Telegram never sends (protocol spec §8.2): a repeated
//! key, an empty key, a pair without `=`, an empty pair, a bad `%` escape, invalid UTF-8, a line
//! break (`\n`, `\r`) in a decoded key or value, or an `=` in a decoded key (each would let two
//! different field lists give one data-check string) is refused. A `hash` field is refused too: the
//! attestation travels without it, and initData carrying it is what the server would take as a
//! login. `auth_date`, `user`, `signature` and `start_param` are required. `user` goes into the
//! string raw, as decoded; it is parsed as JSON only afterwards, for `user.id` (an integer in
//! 1..=2^53−1), the identity (never `receiver` or `chat`). `auth_date`'s value is not looked at:
//! replaying an attestation is worthless without the key's private half.
//!
//! # Which key
//!
//! [`TelegramVerifier::production`] — Telegram's production key, in every build; there is no
//! other key outside tests (test builds will check against a contract vector key, later). A key of
//! all zeros (a placeholder) refuses every attestation.
//!
//! # The bot id
//!
//! The production bot's id is public and built in: [`PROD_TG_BOT_ID`]. [`BOT_ID_VAR`] at build time
//! overrides it only in a build that is not of the release channel (`AFKLINK_BUILD_CHANNEL`, read
//! at compile time and normalised as `crate::build_info` does: trimmed, ASCII case ignored, so
//! ` Release ` is a release here too), for a development bot. A release-channel build with any
//! other value there **does not compile** (a `const` assertion below); the release scripts refuse it
//! before the build too (`agent/scripts/lib/common.ts`, `botIdOverrideRefusal`, which trims the same
//! way). The value is trimmed; an empty one is no override. A development override that is not 1 to
//! 19 digits makes that build refuse every attestation ([`AttestationError::NoBotId`]), said once
//! per process at `error`.

use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use super::{KeyId, START_PARAM_PREFIX};
use crate::person_name::clean_name;

/// The build variable that carries the bot's numeric id (the part of its token before `:`).
pub const BOT_ID_VAR: &str = "AFKLINK_TG_BOT_ID";

/// The bot id as the build gave it (see [`BOT_ID_VAR`]).
const BUILT_BOT_ID: Option<&str> = option_env!("AFKLINK_TG_BOT_ID");

/// The production bot's numeric id (public: the part of its token before `:`, and what every Mini
/// App opened from it signs for). `PROD_TG_BOT_ID` in `agent/scripts/lib/common.ts` says the same
/// (a scripts test reads this line).
pub const PROD_TG_BOT_ID: u64 = 8807488817;

/// [`PROD_TG_BOT_ID`] as the digits a build variable would carry, for the compile-time check.
const PROD_TG_BOT_ID_DIGITS: &str = "8807488817";

/// The build channel as the build gave it (`crate::build_info::CHANNEL_VAR`).
const BUILT_CHANNEL: Option<&str> = option_env!("AFKLINK_BUILD_CHANNEL");

/// Whether this is a release-channel build: `release` trimmed and in any ASCII case, as
/// `crate::build_info::parse_channel` reads it.
const RELEASE_BUILD: bool = is_release_channel(BUILT_CHANNEL);

/// [`RELEASE_BUILD`]'s rule, at compile time.
const fn is_release_channel(raw: Option<&str>) -> bool {
    match raw {
        Some(channel) => eq_ignore_ascii_case(channel.trim_ascii(), "release"),
        None => false,
    }
}

/// ASCII-case-insensitive equality at compile time.
const fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !a[i].eq_ignore_ascii_case(&b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

// A release-channel build checks attestations for the production bot only: an override of the bot
// id there is a build error, not a refusal at run time.
const _: () = assert!(
    override_allowed(RELEASE_BUILD, BUILT_BOT_ID),
    "AFKLINK_TG_BOT_ID differs from the production bot's id in a release-channel build (AFKLINK_BUILD_CHANNEL=release): a release always checks attestations for 8807488817"
);

/// Byte equality at compile time.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether a build of this channel (`release`) may carry `raw` in [`BOT_ID_VAR`]: anything in a
/// development build; in a release, nothing, nothing but blanks, or the production id itself
/// (trimmed).
const fn override_allowed(release: bool, raw: Option<&str>) -> bool {
    match raw {
        _ if !release => true,
        None => true,
        Some(raw) => {
            let raw = raw.trim_ascii();
            raw.is_empty() || str_eq(raw, PROD_TG_BOT_ID_DIGITS)
        }
    }
}

/// Telegram's production Ed25519 key for initData, as published (core.telegram.org/bots/webapps).
pub const PRODUCTION_KEY_HEX: &str =
    "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d";

const PRODUCTION_KEY: [u8; 32] = hex32(PRODUCTION_KEY_HEX);

/// The largest `user.id` taken: 2^53 − 1, the largest integer a JavaScript number holds exactly.
const MAX_USER_ID: i64 = (1 << 53) - 1;

/// The longest initData taken, in bytes: protocol spec §1.2 (`init_data` ≤ 4 KB; Telegram's are
/// about a kilobyte). Longer is refused before any parsing or cryptography.
pub const MAX_INIT_DATA_LEN: usize = 4 * 1024;
/// The most fields taken: Telegram sends about ten.
const MAX_FIELDS: usize = 64;
/// The longest name field returned, in characters (as the journal keeps names).
const NAME_MAX: usize = 64;
/// The longest field name quoted in an error.
const QUOTED_KEY_MAX: usize = 32;

/// 64 hex digits as 32 bytes, at compile time (a typo fails the build).
#[allow(
    clippy::panic,
    reason = "compile time only: a malformed constant fails the build"
)]
const fn hex32(s: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "not 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (digit(b[2 * i]) << 4) | digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Which Telegram key a verifier checks against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramEnvironment {
    Production,
    /// A key a test injected.
    #[cfg(test)]
    Injected,
}

impl TelegramEnvironment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            #[cfg(test)]
            Self::Injected => "injected",
        }
    }
}

/// Why an attestation is refused. Never carries a value from the initData beyond a field's name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("this build has no Telegram bot id ({BOT_ID_VAR}): attestations cannot be checked")]
    NoBotId,
    #[error("the Telegram key is a placeholder of zeros")]
    PlaceholderKey,
    #[error("the Telegram key is not a usable Ed25519 key")]
    UnusableKey,
    #[error("initData of {len} bytes is too long")]
    TooLong { len: usize },
    #[error("initData has more than {MAX_FIELDS} fields")]
    TooManyFields,
    #[error("an empty pair (`&&` or a `&` at an end)")]
    EmptyPair,
    #[error("a pair without `=`")]
    NoEquals,
    #[error("a pair with an empty key")]
    EmptyKey,
    #[error("a bad percent escape")]
    BadPercent,
    #[error("a field that is not UTF-8 once decoded")]
    NotUtf8,
    #[error("the field {0} appears more than once")]
    Duplicate(String),
    #[error("a line feed in a decoded field name or value")]
    LineBreak,
    #[error("a carriage return in a decoded field name or value")]
    CarriageReturn,
    #[error("an `=` in a decoded field name")]
    EqualsInKey,
    #[error("a hash field: an attestation travels without it")]
    HasHash,
    #[error("no auth_date")]
    NoAuthDate,
    #[error("no signature field")]
    NoSignature,
    #[error("the signature is not 64 bytes of base64url")]
    BadSignatureEncoding,
    #[error("the signature is the unsigned stand-in (64 zero bytes)")]
    StandInSignature,
    #[error("the signature does not verify for this bot and key")]
    BadSignature,
    #[error("no start_param")]
    NoStartParam,
    #[error("start_param is not `k_` and this key's id")]
    WrongStartParam,
    #[error("no user field")]
    NoUser,
    #[error("the user field is not the expected JSON object")]
    BadUser,
    #[error("user.id is not an integer in 1..=2^53-1")]
    BadUserId,
}

impl AttestationError {
    /// A stable name for log fields.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoBotId => "no_bot_id",
            Self::PlaceholderKey => "placeholder_key",
            Self::UnusableKey => "unusable_key",
            Self::TooLong { .. } => "too_long",
            Self::TooManyFields => "too_many_fields",
            Self::EmptyPair => "empty_pair",
            Self::NoEquals => "no_equals",
            Self::EmptyKey => "empty_key",
            Self::BadPercent => "bad_percent",
            Self::NotUtf8 => "not_utf8",
            Self::Duplicate(_) => "duplicate",
            Self::LineBreak => "line_break",
            Self::CarriageReturn => "carriage_return",
            Self::EqualsInKey => "equals_in_key",
            Self::HasHash => "has_hash",
            Self::NoAuthDate => "no_auth_date",
            Self::NoSignature => "no_signature",
            Self::BadSignatureEncoding => "bad_signature_encoding",
            Self::StandInSignature => "stand_in_signature",
            Self::BadSignature => "bad_signature",
            Self::NoStartParam => "no_start_param",
            Self::WrongStartParam => "wrong_start_param",
            Self::NoUser => "no_user",
            Self::BadUser => "bad_user",
            Self::BadUserId => "bad_user_id",
        }
    }
}

/// Who Telegram says opened the Mini App: `user.id` is the identity; the names are for display
/// only (cleaned of invisible and control characters, at most 64 characters, `None` when empty).
///
/// It also carries the `key_id` the attestation was checked for ([`TelegramIdentity::attested_key`]).
/// Every field is private and only [`TelegramVerifier::verify_attestation`] fills them, so an
/// identity cannot be built or changed outside this module, and the store binds a recovery to the
/// person and the key Telegram attested ([`super::TrustStore::stage_recover`] refuses any other new
/// key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramIdentity {
    user_id: i64,
    first_name: Option<String>,
    last_name: Option<String>,
    username: Option<String>,
    attested: KeyId,
}

impl TelegramIdentity {
    /// `user.id`: the identity.
    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    /// For display only.
    pub fn first_name(&self) -> Option<&str> {
        self.first_name.as_deref()
    }

    /// For display only.
    pub fn last_name(&self) -> Option<&str> {
        self.last_name.as_deref()
    }

    /// For display only.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The key whose `start_param` (`k_<key_id>`) this attestation was verified for.
    pub fn attested_key(&self) -> &KeyId {
        &self.attested
    }

    /// An identity as if a verifier had attested `attested`, for other modules' tests.
    #[cfg(test)]
    pub(crate) fn for_tests(
        user_id: i64,
        first_name: Option<&str>,
        username: Option<&str>,
        attested: KeyId,
    ) -> Self {
        Self {
            user_id,
            first_name: first_name.map(str::to_string),
            last_name: None,
            username: username.map(str::to_string),
            attested,
        }
    }
}

/// Checks attestations for one bot against one Telegram key.
#[derive(Debug, Clone)]
pub struct TelegramVerifier {
    bot_id: Option<u64>,
    key: [u8; 32],
    environment: TelegramEnvironment,
}

impl TelegramVerifier {
    /// The verifier every shipped build uses: Telegram's production key and the production bot
    /// ([`PROD_TG_BOT_ID`]), or a development build's override ([`BOT_ID_VAR`]). A malformed
    /// override refuses everything ([`AttestationError::NoBotId`]).
    pub fn production() -> Self {
        Self {
            bot_id: built_bot_id(),
            key: PRODUCTION_KEY,
            environment: TelegramEnvironment::Production,
        }
    }

    /// A verifier for `bot_id` with any key, for tests.
    #[cfg(test)]
    pub(crate) fn with_key(
        bot_id: Option<u64>,
        key: [u8; 32],
        environment: TelegramEnvironment,
    ) -> Self {
        Self {
            bot_id,
            key,
            environment,
        }
    }

    pub fn bot_id(&self) -> Option<u64> {
        self.bot_id
    }

    pub fn environment(&self) -> TelegramEnvironment {
        self.environment
    }

    /// Check that `init_data` (the Mini App's raw `initData` without its `hash` pair) is Telegram's
    /// signature for this bot, that its `start_param` is `k_` + `expected`, and return who Telegram
    /// says opened it. Every refusal is logged at `debug` with its reason.
    pub fn verify_attestation(
        &self,
        init_data: &str,
        expected: &KeyId,
    ) -> Result<TelegramIdentity, AttestationError> {
        let result = self.attest(init_data, expected);
        match &result {
            Ok(identity) => tracing::debug!(
                kid = %expected.short(),
                user_id = identity.user_id,
                bot_id = self.bot_id.unwrap_or(0),
                environment = self.environment.as_str(),
                "telegram attestation: verified"
            ),
            Err(e) => tracing::debug!(
                kid = %expected.short(),
                bot_id = self.bot_id.unwrap_or(0),
                environment = self.environment.as_str(),
                len = init_data.len(),
                reason = e.as_str(),
                "telegram attestation: refused ({e})"
            ),
        }
        result
    }

    fn attest(
        &self,
        init_data: &str,
        expected: &KeyId,
    ) -> Result<TelegramIdentity, AttestationError> {
        let fields = parse_init_data(init_data)?;
        // Required fields, before any cryptography (spec §8.2 step 2).
        field(&fields, "auth_date").ok_or(AttestationError::NoAuthDate)?;
        let user = field(&fields, "user").ok_or(AttestationError::NoUser)?;
        field(&fields, "signature").ok_or(AttestationError::NoSignature)?;
        let start_param = field(&fields, "start_param").ok_or(AttestationError::NoStartParam)?;
        self.check_signature(&fields)?;
        let wanted = format!("{START_PARAM_PREFIX}{expected}");
        if start_param != wanted {
            return Err(AttestationError::WrongStartParam);
        }
        identity_of(user, expected)
    }

    /// The signature layer alone: Telegram's Ed25519 signature over the data-check string of
    /// `fields` (sorted, decoded), for this bot.
    fn check_signature(&self, fields: &[(String, String)]) -> Result<(), AttestationError> {
        let bot_id = self.bot_id.ok_or(AttestationError::NoBotId)?;
        // §8.2 step 4, in order: the signature's form, then the key (all zero: refused), then
        // Ed25519.
        let signature = field(fields, "signature").ok_or(AttestationError::NoSignature)?;
        let signature = decode_signature(signature)?;
        if self.key == [0u8; 32] {
            return Err(AttestationError::PlaceholderKey);
        }
        let key = VerifyingKey::from_bytes(&self.key).map_err(|_| AttestationError::UnusableKey)?;
        if signature == [0u8; 64] {
            return Err(AttestationError::StandInSignature);
        }
        let check = data_check_string(bot_id, fields);
        key.verify_strict(check.as_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| AttestationError::BadSignature)
    }
}

/// Where a build's bot id comes from ([`resolve_bot_id`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotIdFrom {
    /// [`PROD_TG_BOT_ID`]: no override, or the production id itself.
    Production,
    /// A development build's [`BOT_ID_VAR`].
    Override,
}

/// The bot id of a build that carries `raw` in [`BOT_ID_VAR`] (`None` or empty: none) and is
/// (`release`) or is not of the release channel. A release takes the production id only (the
/// compile-time check makes anything else unbuildable; this refuses it all the same).
fn resolve_bot_id(raw: Option<&str>, release: bool) -> Result<(u64, BotIdFrom), &'static str> {
    match raw.map(str::trim_ascii).filter(|r| !r.is_empty()) {
        None => Ok((PROD_TG_BOT_ID, BotIdFrom::Production)),
        Some(r) if r == PROD_TG_BOT_ID_DIGITS => Ok((PROD_TG_BOT_ID, BotIdFrom::Production)),
        Some(_) if release => Err("differs from the production bot's in a release build"),
        Some(r) => parse_bot_id(Some(r)).map(|id| (id, BotIdFrom::Override)),
    }
}

/// The bot id of this build, resolved at first use; `None`, said once at `error`, for a malformed
/// override.
fn built_bot_id() -> Option<u64> {
    static PARSED: OnceLock<Option<u64>> = OnceLock::new();
    *PARSED.get_or_init(|| match resolve_bot_id(BUILT_BOT_ID, RELEASE_BUILD) {
        Ok((id, BotIdFrom::Production)) => {
            tracing::debug!(
                bot_id = id,
                release = RELEASE_BUILD,
                "telegram attestation: the production bot's id"
            );
            Some(id)
        }
        Ok((id, BotIdFrom::Override)) => {
            tracing::warn!(
                bot_id = id,
                production = PROD_TG_BOT_ID,
                "telegram attestation: a development build checks attestations for another bot \
                 ({BOT_ID_VAR}); the production bot's are refused"
            );
            Some(id)
        }
        Err(why) => {
            tracing::error!(
                release = RELEASE_BUILD,
                "telegram attestation: this build has no usable bot id ({BOT_ID_VAR} {why}); \
                 every Telegram attestation is refused"
            );
            None
        }
    })
}

fn parse_bot_id(raw: Option<&str>) -> Result<u64, &'static str> {
    let raw = raw.ok_or("was not set at build time")?;
    if raw.is_empty() || raw.len() > 19 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("is not 1 to 19 digits");
    }
    match raw.parse::<u64>() {
        Ok(0) | Err(_) => Err("is not a positive number"),
        Ok(id) => Ok(id),
    }
}

/// A field's decoded value.
fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// `raw` split and decoded as described in the module docs, sorted by key bytes. Each pair is
/// checked in the order of the protocol spec (§8.2 step 1, the vectors' `why`): an `=`, then the
/// `%` escapes of key and value, then their UTF-8, then an empty key, a line break, an `=` in the
/// key, a repeated key; a `hash` field only once every pair parsed. Decoding goes by bytes of the
/// UTF-8 text, so a raw character of any plane stays the same code point, and nothing is trimmed
/// (a value's leading U+FEFF stays: the signature covers it).
fn parse_init_data(raw: &str) -> Result<Vec<(String, String)>, AttestationError> {
    if raw.len() > MAX_INIT_DATA_LEN {
        return Err(AttestationError::TooLong { len: raw.len() });
    }
    let mut fields: Vec<(String, String)> = Vec::new();
    for pair in raw.split('&') {
        if fields.len() == MAX_FIELDS {
            return Err(AttestationError::TooManyFields);
        }
        if pair.is_empty() {
            return Err(AttestationError::EmptyPair);
        }
        let (key, value) = pair.split_once('=').ok_or(AttestationError::NoEquals)?;
        let key = percent_decode(key)?;
        let value = percent_decode(value)?;
        let key = String::from_utf8(key).map_err(|_| AttestationError::NotUtf8)?;
        let value = String::from_utf8(value).map_err(|_| AttestationError::NotUtf8)?;
        if key.is_empty() {
            return Err(AttestationError::EmptyKey);
        }
        // §8.2 step 1: a raw LF first, then a raw CR (the vectors' order: `lf`, then `cr`).
        if key.contains('\n') || value.contains('\n') {
            return Err(AttestationError::LineBreak);
        }
        if key.contains('\r') || value.contains('\r') {
            return Err(AttestationError::CarriageReturn);
        }
        if key.contains('=') {
            return Err(AttestationError::EqualsInKey);
        }
        if fields.iter().any(|(k, _)| *k == key) {
            return Err(AttestationError::Duplicate(quoted(&key)));
        }
        fields.push((key, value));
    }
    if field(&fields, "hash").is_some() {
        return Err(AttestationError::HasHash);
    }
    fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(fields)
}

/// A field name as an error quotes it: cleaned, at most [`QUOTED_KEY_MAX`] characters.
fn quoted(key: &str) -> String {
    let cleaned: String = clean_name(key).chars().take(QUOTED_KEY_MAX).collect();
    format!("{cleaned:?}")
}

/// `application/x-www-form-urlencoded` decoding to bytes: `+` a space, `%XX` a byte (two hex
/// digits, else refused), the rest as is. Not `url::form_urlencoded`, which passes a bad escape
/// through and replaces invalid UTF-8.
fn percent_decode(s: &str) -> Result<Vec<u8>, AttestationError> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = bytes.get(i + 1).copied().and_then(hex);
                let lo = bytes.get(i + 2).copied().and_then(hex);
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(AttestationError::BadPercent);
                };
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `signature` as Telegram writes it: base64url, with or without its `==`, exactly 64 bytes.
fn decode_signature(text: &str) -> Result<[u8; 64], AttestationError> {
    let unpadded = match text.strip_suffix("==") {
        Some(rest) if text.len() == 88 => rest,
        _ => text,
    };
    if unpadded.len() != 86 {
        return Err(AttestationError::BadSignatureEncoding);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(unpadded)
        .map_err(|_| AttestationError::BadSignatureEncoding)?;
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| AttestationError::BadSignatureEncoding)
}

/// The data-check string of the third-party validation: `fields` are sorted already (and hold no
/// `hash`: [`parse_init_data`] refuses one).
fn data_check_string(bot_id: u64, fields: &[(String, String)]) -> String {
    let mut out = format!("{bot_id}:WebAppData");
    for (key, value) in fields {
        if key == "signature" {
            continue;
        }
        out.push('\n');
        out.push_str(key);
        out.push('=');
        out.push_str(value);
    }
    out
}

/// The fields of `user` this module reads. Serde refuses a repeated one.
#[derive(Deserialize)]
struct RawUser {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

/// Who `user` (the raw JSON Telegram signed) names.
fn identity_of(user: &str, attested: &KeyId) -> Result<TelegramIdentity, AttestationError> {
    // An object only: serde's derive would also read a struct from an array (`[7]`).
    if !user.trim_start().starts_with('{') {
        tracing::debug!("telegram attestation: user is not a JSON object");
        return Err(AttestationError::BadUser);
    }
    let raw: RawUser = serde_json::from_str(user).map_err(|e| {
        // Where and what kind, not serde's message: that may quote a value (a name).
        tracing::debug!(
            category = ?e.classify(),
            line = e.line(),
            column = e.column(),
            "telegram attestation: user is not the expected JSON object"
        );
        AttestationError::BadUser
    })?;
    // A JSON integer only: serde_json keeps `7.0` and `7e0` as floats, and `as_i64` is `None` for
    // them, for strings, for null and for integers past `i64::MAX`.
    let user_id = match raw.id.as_ref().and_then(serde_json::Value::as_i64) {
        Some(id) if (1..=MAX_USER_ID).contains(&id) => id,
        _ => return Err(AttestationError::BadUserId),
    };
    Ok(TelegramIdentity {
        user_id,
        first_name: shown(raw.first_name),
        last_name: shown(raw.last_name),
        username: shown(raw.username),
        attested: attested.clone(),
    })
}

/// A name for display: cleaned, trimmed, at most [`NAME_MAX`] characters; `None` when nothing is
/// left.
fn shown(name: Option<String>) -> Option<String> {
    let cleaned = clean_name(&name?);
    let text: String = cleaned.trim().chars().take(NAME_MAX).collect();
    let text = text.trim_end().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

    use super::*;
    use crate::viewer_keys::key::tests::fresh;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// A real initData Telegram signed with its production key, for bot 7342037359 — the public
    /// sample of `validate3rd` (docs.telegram-mini-apps.com), the same one the backend's
    /// `initData.test.ts` checks. Its first name is `Vladislav + - ? \/`: `%2B`, `%20` and a raw
    /// JSON escape. It has no `start_param`, so it checks the signature layer only. Its `hash` pair
    /// is removed (as the Mini App sends an attestation, spec §8.2): `hash` is not covered by the
    /// signature, so the rest still verifies.
    const SAMPLE_BOT: u64 = 7342037359;
    const SAMPLE: &str = concat!(
        "user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%20%2B%20-%20%3F%20%5C%2F%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2F4FPEE4tmP3ATHa57u6MqTDih13LTOiMoKoLDRG4PnSA.svg%22%7D",
        "&chat_instance=8134722200314281151",
        "&chat_type=private",
        "&auth_date=1733584787",
        "&signature=zL-ucjNyREiHDE8aihFwpfR9aggP2xiAo3NSpfe-p7IbCisNlDKlo7Kb6G4D0Ao2mBrSgEk4maLSdv6MLIlADQ",
    );
    /// The sample's `hash` pair, as Telegram sent it.
    const SAMPLE_HASH: &str =
        "hash=2174df5b000556d044f3f020384e879c8efcab55ddea2ced4eb752e93e7080d6";

    fn production(bot_id: u64) -> TelegramVerifier {
        TelegramVerifier::with_key(
            Some(bot_id),
            PRODUCTION_KEY,
            TelegramEnvironment::Production,
        )
    }

    fn signature_layer(v: &TelegramVerifier, raw: &str) -> Result<(), AttestationError> {
        v.check_signature(&parse_init_data(raw)?)
    }

    #[test]
    fn real_sample_verifies_with_the_production_key() {
        assert_eq!(signature_layer(&production(SAMPLE_BOT), SAMPLE), Ok(()));
        // The identity layer reads it too (the start_param rule aside).
        let fields = parse_init_data(SAMPLE).unwrap();
        let id = identity_of(field(&fields, "user").unwrap(), fresh().1.key_id()).unwrap();
        assert_eq!(id.user_id, 279058397);
        assert_eq!(id.first_name.as_deref(), Some("Vladislav + - ? /"));
        assert_eq!(id.username.as_deref(), Some("vdkfrost"));
    }

    #[test]
    fn real_sample_is_refused_by_another_key_another_bot_or_a_change() {
        let other_key = TelegramVerifier::with_key(
            Some(SAMPLE_BOT),
            signer().verifying_key().to_bytes(),
            TelegramEnvironment::Injected,
        );
        assert_eq!(
            signature_layer(&other_key, SAMPLE),
            Err(AttestationError::BadSignature)
        );
        assert_eq!(
            signature_layer(&production(7342037358), SAMPLE),
            Err(AttestationError::BadSignature)
        );
        // Each covered field changed by one character.
        for (from, to) in [
            ("auth_date=1733584787", "auth_date=1733584788"),
            ("chat_type=private", "chat_type=group"),
            (
                "chat_instance=8134722200314281151",
                "chat_instance=8134722200314281152",
            ),
            ("279058397", "279058398"),
            ("Kibenko", "Kibenka"),
        ] {
            let changed = SAMPLE.replacen(from, to, 1);
            assert_ne!(changed, SAMPLE);
            assert_eq!(
                signature_layer(&production(SAMPLE_BOT), &changed),
                Err(AttestationError::BadSignature),
                "{from}"
            );
        }
        // A field added.
        assert_eq!(
            signature_layer(&production(SAMPLE_BOT), &format!("{SAMPLE}&query_id=1")),
            Err(AttestationError::BadSignature)
        );
        // With its `hash` pair, wherever it is, the sample is refused before any signature check.
        for with_hash in [
            format!("{SAMPLE}&{SAMPLE_HASH}"),
            format!("{SAMPLE_HASH}&{SAMPLE}"),
        ] {
            assert_eq!(parse_init_data(&with_hash), Err(AttestationError::HasHash));
            assert_eq!(
                production(SAMPLE_BOT).verify_attestation(&with_hash, fresh().1.key_id()),
                Err(AttestationError::HasHash)
            );
        }
        // `+` for the encoded `%20`s in the name is the same string; `%2B` for a `+` is not.
        let plus = SAMPLE.replacen("Vladislav%20%2B", "Vladislav+%2B", 1);
        assert_ne!(plus, SAMPLE);
        assert_eq!(signature_layer(&production(SAMPLE_BOT), &plus), Ok(()));
        let space = SAMPLE.replacen("Vladislav%20%2B", "Vladislav%20+", 1);
        assert_ne!(space, SAMPLE);
        assert_eq!(
            signature_layer(&production(SAMPLE_BOT), &space),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn signature_padding_is_tolerated() {
        // The signature is the sample's last field.
        assert!(SAMPLE.ends_with("MLIlADQ"));
        let padded = format!("{SAMPLE}==");
        assert_eq!(signature_layer(&production(SAMPLE_BOT), &padded), Ok(()));
        let one = format!("{SAMPLE}=");
        assert_eq!(
            signature_layer(&production(SAMPLE_BOT), &one),
            Err(AttestationError::BadSignatureEncoding)
        );
        let std_alphabet = SAMPLE.replacen("zL-uc", "zL+uc", 1);
        assert_ne!(std_alphabet, SAMPLE);
        assert!(signature_layer(&production(SAMPLE_BOT), &std_alphabet).is_err());
    }

    // --- The full path, with a key the test holds -------------------------------------------

    const BOT: u64 = 123456789;

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn injected() -> TelegramVerifier {
        TelegramVerifier::with_key(
            Some(BOT),
            signer().verifying_key().to_bytes(),
            TelegramEnvironment::Injected,
        )
    }

    /// Percent-encode everything but the unreserved characters (spaces as `%20`).
    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    /// The signature of `fields` (decoded values) for `bot` by `key`, base64url.
    fn sign(fields: &[(&str, &str)], bot: u64, key: &SigningKey) -> String {
        let mut sorted: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        sorted.sort();
        let check = data_check_string(bot, &sorted);
        URL_SAFE_NO_PAD.encode(key.sign(check.as_bytes()).to_bytes())
    }

    fn query(fields: &[(&str, &str)]) -> String {
        fields
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// initData for `fields`, signed for [`BOT`] by [`signer`].
    fn signed(fields: &[(&str, &str)]) -> String {
        let sig = sign(fields, BOT, &signer());
        format!("{}&signature={sig}", query(fields))
    }

    const USER: &str =
        r#"{"id":5551234,"first_name":"Вера + \u2066x","last_name":"","username":"vera_k"}"#;

    fn fields_for(key_id: &KeyId) -> Vec<(&'static str, String)> {
        vec![
            ("user", USER.to_string()),
            ("auth_date", "1731400000".into()),
            ("chat_type", "private".into()),
            ("start_param", format!("k_{key_id}")),
        ]
    }

    fn signed_owned(fields: &[(&str, String)]) -> String {
        let borrowed: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        signed(&borrowed)
    }

    #[test]
    fn full_attestation_verifies_and_names_the_user() {
        let (_, key) = fresh();
        let raw = signed_owned(&fields_for(key.key_id()));
        let id = injected().verify_attestation(&raw, key.key_id()).unwrap();
        assert_eq!(
            id,
            TelegramIdentity {
                user_id: 5551234,
                first_name: Some("Вера + x".into()),
                last_name: None,
                username: Some("vera_k".into()),
                attested: key.key_id().clone(),
            }
        );
        assert_eq!(id.attested_key(), key.key_id());
    }

    #[test]
    fn data_signed_by_another_key_is_refused() {
        let (_, key) = fresh();
        let raw = signed_owned(&fields_for(key.key_id()));
        // Signed by the test's own key: the production verifier refuses it (as it would data the
        // test environment's key signed).
        assert_eq!(
            production(BOT).verify_attestation(&raw, key.key_id()),
            Err(AttestationError::BadSignature)
        );
        // A forged signature: someone else's key.
        let fields = fields_for(key.key_id());
        let borrowed: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let forged = sign(&borrowed, BOT, &SigningKey::from_bytes(&[1u8; 32]));
        let raw = format!("{}&signature={forged}", query(&borrowed));
        assert_eq!(
            injected().verify_attestation(&raw, key.key_id()),
            Err(AttestationError::BadSignature)
        );
        // Right key, another bot.
        let other_bot = sign(&borrowed, BOT + 1, &signer());
        let raw = format!("{}&signature={other_bot}", query(&borrowed));
        assert_eq!(
            injected().verify_attestation(&raw, key.key_id()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn stand_in_and_missing_signatures_are_refused() {
        let (_, key) = fresh();
        let fields = fields_for(key.key_id());
        let borrowed: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let zeros = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let raw = format!("{}&signature={zeros}", query(&borrowed));
        assert_eq!(
            injected().verify_attestation(&raw, key.key_id()),
            Err(AttestationError::StandInSignature)
        );
        assert_eq!(
            injected().verify_attestation(&query(&borrowed), key.key_id()),
            Err(AttestationError::NoSignature)
        );
        let short = URL_SAFE_NO_PAD.encode([1u8; 63]);
        let raw = format!("{}&signature={short}", query(&borrowed));
        assert_eq!(
            injected().verify_attestation(&raw, key.key_id()),
            Err(AttestationError::BadSignatureEncoding)
        );
    }

    #[test]
    fn placeholder_key_and_missing_bot_id_refuse_everything() {
        let (_, key) = fresh();
        let raw = signed_owned(&fields_for(key.key_id()));
        let zero =
            TelegramVerifier::with_key(Some(BOT), [0u8; 32], TelegramEnvironment::Production);
        assert_eq!(
            zero.verify_attestation(&raw, key.key_id()),
            Err(AttestationError::PlaceholderKey)
        );
        let no_bot = TelegramVerifier::with_key(
            None,
            signer().verifying_key().to_bytes(),
            TelegramEnvironment::Injected,
        );
        assert_eq!(
            no_bot.verify_attestation(&raw, key.key_id()),
            Err(AttestationError::NoBotId)
        );
    }

    #[test]
    fn repeated_fields_are_refused() {
        let (_, key) = fresh();
        let good = signed_owned(&fields_for(key.key_id()));
        for extra in [
            "user=%7B%22id%22%3A1%7D".to_string(),
            format!("start_param=k_{}", key.key_id()),
            format!("signature={}", URL_SAFE_NO_PAD.encode([3u8; 64])),
            "auth_date=1".to_string(),
        ] {
            let raw = format!("{good}&{extra}");
            assert!(
                matches!(
                    injected().verify_attestation(&raw, key.key_id()),
                    Err(AttestationError::Duplicate(_))
                ),
                "{extra}"
            );
        }
        // The same key spelled with an escape is the same key.
        let raw = format!("{good}&%75ser=x");
        assert!(matches!(
            injected().verify_attestation(&raw, key.key_id()),
            Err(AttestationError::Duplicate(_))
        ));
    }

    #[test]
    fn start_param_must_be_exactly_this_key() {
        let (_, key) = fresh();
        let (_, other) = fresh();
        let check = |start: Option<String>| {
            let mut fields = fields_for(key.key_id());
            fields.retain(|(k, _)| *k != "start_param");
            if let Some(s) = start {
                fields.push(("start_param", s));
            }
            injected().verify_attestation(&signed_owned(&fields), key.key_id())
        };
        assert!(check(Some(format!("k_{}", key.key_id()))).is_ok());
        assert_eq!(check(None), Err(AttestationError::NoStartParam));
        assert_eq!(
            check(Some(format!("k_{}", other.key_id()))),
            Err(AttestationError::WrongStartParam)
        );
        assert_eq!(
            check(Some(format!("K_{}", key.key_id()))),
            Err(AttestationError::WrongStartParam)
        );
        let swapped: String = key
            .key_id()
            .as_str()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        assert_eq!(
            check(Some(format!("k_{swapped}"))),
            Err(AttestationError::WrongStartParam)
        );
        assert_eq!(
            check(Some(format!("k_{}x", key.key_id()))),
            Err(AttestationError::WrongStartParam)
        );
        assert_eq!(
            check(Some(format!("k_{} ", key.key_id()))),
            Err(AttestationError::WrongStartParam)
        );
        assert_eq!(
            check(Some(key.key_id().to_string())),
            Err(AttestationError::WrongStartParam)
        );
        assert_eq!(
            check(Some(String::new())),
            Err(AttestationError::WrongStartParam)
        );
    }

    #[test]
    fn user_id_must_be_a_positive_integer() {
        let (_, key) = fresh();
        let check = |user: Option<&str>| {
            let mut fields = fields_for(key.key_id());
            fields.retain(|(k, _)| *k != "user");
            if let Some(u) = user {
                fields.push(("user", u.to_string()));
            }
            injected().verify_attestation(&signed_owned(&fields), key.key_id())
        };
        assert_eq!(check(Some(r#"{"id":7}"#)).unwrap().user_id, 7);
        assert_eq!(
            check(Some(r#"{"id":9007199254740991}"#)).unwrap().user_id,
            (1 << 53) - 1
        );
        assert_eq!(check(None), Err(AttestationError::NoUser));
        for bad in [
            r#"{"id":"7"}"#,
            r#"{"id":7.0}"#,
            r#"{"id":7e0}"#,
            r#"{"id":-7}"#,
            r#"{"id":0}"#,
            r#"{"id":9007199254740992}"#,
            r#"{"id":9223372036854775807}"#,
            r#"{"id":9223372036854775808}"#,
            r#"{"id":null}"#,
            r#"{"first_name":"Вера"}"#,
        ] {
            assert_eq!(check(Some(bad)), Err(AttestationError::BadUserId), "{bad}");
        }
        for bad in [
            r#"[7]"#,
            r#"7"#,
            r#"{"id":7"#,
            "",
            r#"{"id":7,"username":5}"#,
            r#"{"id":7,"id":8}"#,
        ] {
            assert!(
                matches!(
                    check(Some(bad)),
                    Err(AttestationError::BadUser | AttestationError::BadUserId)
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn receiver_and_chat_do_not_change_the_identity() {
        let (_, key) = fresh();
        let mut fields = fields_for(key.key_id());
        fields.push(("receiver", r#"{"id":999,"first_name":"Мэллори"}"#.into()));
        fields.push(("chat", r#"{"id":888,"type":"group","title":"x"}"#.into()));
        let id = injected()
            .verify_attestation(&signed_owned(&fields), key.key_id())
            .unwrap();
        assert_eq!(id.user_id, 5551234);
    }

    /// §8.2 step 1: each pair's checks in the spec's order, and a `hash` field only after every
    /// pair parsed — a reordered verifier refuses the same data for another reason (`why`), and
    /// one that stops at `hash` says `attest_has_hash` where the spec says `attest_bad`.
    #[test]
    fn pair_checks_go_in_the_spec_order_and_hash_comes_last() {
        let (_, key) = fresh();
        let good = signed_owned(&fields_for(key.key_id()));
        let cases = [
            // A bad escape in the value before an empty key.
            (format!("{good}&=%zz"), AttestationError::BadPercent),
            // A bad escape in the value before invalid UTF-8 in the key.
            (format!("{good}&%FF=%zz"), AttestationError::BadPercent),
            // Invalid UTF-8 in the value before an empty key.
            (format!("{good}&=%FF"), AttestationError::NotUtf8),
            // A pair that does not parse after `hash`: attest_bad, not attest_has_hash.
            (format!("hash=1&{good}&novalue"), AttestationError::NoEquals),
            (format!("hash=1&{good}&x=%zz"), AttestationError::BadPercent),
            // `hash` twice: a repeated key.
            (
                format!("hash=1&{good}&hash=2"),
                AttestationError::Duplicate("\"hash\"".into()),
            ),
            // `hash` alone among good pairs, anywhere.
            (format!("{good}&hash=1"), AttestationError::HasHash),
        ];
        for (raw, want) in cases {
            assert_eq!(
                injected().verify_attestation(&raw, key.key_id()),
                Err(want.clone()),
                "{want:?}"
            );
        }
    }

    /// §8.2: decoding keeps every code point as sent — a raw character outside the BMP and a
    /// value's leading U+FEFF reach the data-check string unchanged.
    #[test]
    fn raw_astral_characters_and_a_leading_bom_are_kept() {
        let fields = parse_init_data("a=%EF%BB%BFx&b=\u{1F600}y&c=\u{feff}").unwrap();
        assert_eq!(
            fields,
            vec![
                ("a".to_string(), "\u{feff}x".to_string()),
                ("b".to_string(), "\u{1F600}y".to_string()),
                ("c".to_string(), "\u{feff}".to_string()),
            ]
        );
    }

    #[test]
    fn malformed_encodings_are_refused() {
        let (_, key) = fresh();
        let good = signed_owned(&fields_for(key.key_id()));
        let cases = [
            (format!("{good}&x=%G1"), AttestationError::BadPercent),
            (format!("{good}&x=%4"), AttestationError::BadPercent),
            (format!("{good}&x=%"), AttestationError::BadPercent),
            (format!("{good}&x%2=1"), AttestationError::BadPercent),
            (format!("{good}&x=%FF"), AttestationError::NotUtf8),
            (format!("{good}&x=%C3%28"), AttestationError::NotUtf8),
            (format!("{good}&=1"), AttestationError::EmptyKey),
            (format!("{good}&+%20=1"), AttestationError::BadSignature),
            (format!("{good}&novalue"), AttestationError::NoEquals),
            (format!("{good}&&x=1"), AttestationError::EmptyPair),
            (format!("{good}&"), AttestationError::EmptyPair),
            (format!("&{good}"), AttestationError::EmptyPair),
            (String::new(), AttestationError::EmptyPair),
        ];
        for (raw, want) in cases {
            assert_eq!(
                injected().verify_attestation(&raw, key.key_id()),
                Err(want.clone()),
                "{want:?}"
            );
        }
        let long = format!("{good}&x={}", "a".repeat(MAX_INIT_DATA_LEN));
        assert!(matches!(
            injected().verify_attestation(&long, key.key_id()),
            Err(AttestationError::TooLong { .. })
        ));
        // Spec §1.2: `init_data` ≤ 4 KB. Exactly 4096 bytes parse; 4097 are refused unparsed.
        assert_eq!(MAX_INIT_DATA_LEN, 4096);
        let at_limit = format!("a={}", "b".repeat(MAX_INIT_DATA_LEN - 2));
        assert_eq!(at_limit.len(), 4096);
        assert!(parse_init_data(&at_limit).is_ok());
        let over = format!("{at_limit}b");
        assert_eq!(
            parse_init_data(&over),
            Err(AttestationError::TooLong { len: 4097 })
        );
        assert_eq!(
            injected().verify_attestation(&over, key.key_id()),
            Err(AttestationError::TooLong { len: 4097 })
        );
        let many: String = (0..MAX_FIELDS).map(|i| format!("&f{i}=1")).collect();
        assert_eq!(
            injected().verify_attestation(&format!("{good}{many}"), key.key_id()),
            Err(AttestationError::TooManyFields)
        );
    }

    #[test]
    fn a_field_changed_after_signing_is_refused() {
        let (_, key) = fresh();
        let raw = signed_owned(&fields_for(key.key_id()));
        let changed = raw.replacen("auth_date=1731400000", "auth_date=1731400001", 1);
        assert_ne!(changed, raw);
        assert_eq!(
            injected().verify_attestation(&changed, key.key_id()),
            Err(AttestationError::BadSignature)
        );
        let changed = raw.replacen("5551234", "5551235", 1);
        assert_ne!(changed, raw);
        assert_eq!(
            injected().verify_attestation(&changed, key.key_id()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn required_fields_and_hash() {
        let (_, key) = fresh();
        let mut fields = fields_for(key.key_id());
        fields.retain(|(k, _)| *k != "auth_date");
        assert_eq!(
            injected().verify_attestation(&signed_owned(&fields), key.key_id()),
            Err(AttestationError::NoAuthDate)
        );
        // `auth_date`'s value is not looked at.
        let mut fields = fields_for(key.key_id());
        fields.retain(|(k, _)| *k != "auth_date");
        fields.push(("auth_date", "not a time".into()));
        assert!(injected()
            .verify_attestation(&signed_owned(&fields), key.key_id())
            .is_ok());
        // A hash, even one the signature covers (signed with it as an ordinary field), is refused.
        let mut fields = fields_for(key.key_id());
        fields.push(("hash", "00".into()));
        assert_eq!(
            injected().verify_attestation(&signed_owned(&fields), key.key_id()),
            Err(AttestationError::HasHash)
        );
        let good = signed_owned(&fields_for(key.key_id()));
        assert_eq!(
            injected().verify_attestation(&format!("{good}&hash=00"), key.key_id()),
            Err(AttestationError::HasHash)
        );
        assert_eq!(
            injected().verify_attestation(&format!("{good}&%68ash=00"), key.key_id()),
            Err(AttestationError::HasHash)
        );
    }

    #[test]
    fn line_breaks_and_equals_in_keys_are_refused() {
        let (_, key) = fresh();
        let good = signed_owned(&fields_for(key.key_id()));
        for (extra, want) in [
            ("x=a%0Ab", AttestationError::LineBreak),
            ("x=a%0Db", AttestationError::CarriageReturn),
            ("x%0Ay=1", AttestationError::LineBreak),
            ("x%0D=1", AttestationError::CarriageReturn),
            ("x%3Dy=1", AttestationError::EqualsInKey),
        ] {
            assert_eq!(
                injected().verify_attestation(&format!("{good}&{extra}"), key.key_id()),
                Err(want),
                "{extra}"
            );
        }
        // Signed by the right key with the line break inside: still refused (a second field list
        // `x=a` + `b…` would give the same data-check string).
        let mut fields = fields_for(key.key_id());
        fields.push(("x", "a\nchat_type=private".into()));
        assert_eq!(
            injected().verify_attestation(&signed_owned(&fields), key.key_id()),
            Err(AttestationError::LineBreak)
        );
        // An `=` in a value is fine (only the first `=` splits a pair).
        let mut fields = fields_for(key.key_id());
        fields.push(("x", "a=b".into()));
        assert!(injected()
            .verify_attestation(&signed_owned(&fields), key.key_id())
            .is_ok());
    }

    /// `raw` with the first character of its `signature` value changed (still base64url, 64 bytes).
    fn flip_signature(raw: &str) -> String {
        let at = raw.find("signature=").unwrap() + "signature=".len();
        let mut out = raw.to_string();
        let to = if &raw[at..=at] == "A" { "B" } else { "A" };
        out.replace_range(at..=at, to);
        out
    }

    /// The real sample with two adjacent sorted fields spliced into one by a raw line break:
    /// `chat_instance` carries `<v>\nchat_type=private` (sent as `%0A`) and `chat_type` is gone, so
    /// the data-check string — and Telegram's real signature over it — is byte for byte the
    /// sample's. Only the parser's line-break rule, which runs before any signature check, refuses
    /// it; without that rule the same fields verify.
    #[test]
    fn real_sample_spliced_by_a_line_break_is_refused_before_the_signature() {
        let spliced = SAMPLE.replacen(
            "&chat_instance=8134722200314281151&chat_type=private",
            "&chat_instance=8134722200314281151%0Achat_type=private",
            1,
        );
        assert_ne!(spliced, SAMPLE);
        assert_eq!(parse_init_data(&spliced), Err(AttestationError::LineBreak));
        assert_eq!(
            signature_layer(&production(SAMPLE_BOT), &spliced),
            Err(AttestationError::LineBreak)
        );
        assert_eq!(
            production(SAMPLE_BOT).verify_attestation(&spliced, fresh().1.key_id()),
            Err(AttestationError::LineBreak)
        );
        // With a broken signature too: still `LineBreak`, so the rule answers before any check of
        // the signature (which, unspliced, is what refuses it).
        let broken = flip_signature(&spliced);
        assert_eq!(parse_init_data(&broken), Err(AttestationError::LineBreak));
        assert_eq!(
            production(SAMPLE_BOT).verify_attestation(&broken, fresh().1.key_id()),
            Err(AttestationError::LineBreak)
        );
        assert_eq!(
            signature_layer(&production(SAMPLE_BOT), &flip_signature(SAMPLE)),
            Err(AttestationError::BadSignature)
        );
        // The parser rule bypassed: the spliced fields as a parser without it would give them.
        let original = parse_init_data(SAMPLE).unwrap();
        let mut bypassed: Vec<(String, String)> = original
            .iter()
            .filter(|(k, _)| k != "chat_type")
            .cloned()
            .collect();
        for (k, v) in &mut bypassed {
            if k == "chat_instance" {
                v.push_str("\nchat_type=private");
            }
        }
        bypassed.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        assert_eq!(
            data_check_string(SAMPLE_BOT, &bypassed),
            data_check_string(SAMPLE_BOT, &original),
            "the same signed bytes"
        );
        assert_eq!(
            production(SAMPLE_BOT).check_signature(&bypassed),
            Ok(()),
            "Telegram's real signature would verify without the rule"
        );
    }

    /// The `=` splice: `k=v1=v2` read as key `k=v1`, value `v2` gives the same data-check line as
    /// key `k`, value `v1=v2`. No field of the real sample allows it (its signed values hold no
    /// `=`: the line would change), so this one is signed with the test key: a field `x` = `a=b`,
    /// sent as `x=a%3Db`, spliced to `x%3Da=b`. The signed bytes stay identical; only the parser's
    /// rule (an `=` in a decoded key), which runs before any signature check, refuses it.
    #[test]
    fn a_field_spliced_at_an_equals_sign_is_refused_before_the_signature() {
        let (_, key) = fresh();
        let mut fields = fields_for(key.key_id());
        fields.push(("x", "a=b".into()));
        let raw = signed_owned(&fields);
        assert!(raw.contains("&x=a%3Db&"), "{raw}");
        assert!(injected().verify_attestation(&raw, key.key_id()).is_ok());
        let spliced = raw.replacen("&x=a%3Db&", "&x%3Da=b&", 1);
        assert_eq!(
            parse_init_data(&spliced),
            Err(AttestationError::EqualsInKey)
        );
        assert_eq!(
            injected().verify_attestation(&spliced, key.key_id()),
            Err(AttestationError::EqualsInKey)
        );
        // With a broken signature too: still `EqualsInKey` — the rule answers first.
        let broken = flip_signature(&spliced);
        assert_eq!(
            injected().verify_attestation(&broken, key.key_id()),
            Err(AttestationError::EqualsInKey)
        );
        assert_eq!(
            injected().verify_attestation(&flip_signature(&raw), key.key_id()),
            Err(AttestationError::BadSignature)
        );
        // The parser rule bypassed: key `x=a`, value `b`.
        let original = parse_init_data(&raw).unwrap();
        let mut bypassed: Vec<(String, String)> = original
            .iter()
            .map(|(k, v)| {
                if k == "x" {
                    ("x=a".to_string(), "b".to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        bypassed.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        assert_eq!(
            data_check_string(BOT, &bypassed),
            data_check_string(BOT, &original),
            "the same signed bytes"
        );
        assert_eq!(
            injected().check_signature(&bypassed),
            Ok(()),
            "the signature would verify without the rule"
        );
    }

    #[test]
    fn production_verifier_of_this_build() {
        let v = TelegramVerifier::production();
        assert_eq!(v.environment(), TelegramEnvironment::Production);
        let (_, key) = fresh();
        let raw = signed_owned(&fields_for(key.key_id()));
        match BUILT_BOT_ID.filter(|r| !r.is_empty()) {
            // The test build carries no override: the production bot's id.
            None => assert_eq!(v.bot_id(), Some(PROD_TG_BOT_ID)),
            Some(raw) => assert_eq!(v.bot_id(), raw.parse().ok()),
        }
        // Whatever the bot: the production key, which the test's key is not.
        assert_eq!(
            v.verify_attestation(&raw, key.key_id()),
            Err(AttestationError::BadSignature)
        );
    }

    /// A build without the variable checks attestations for the production bot, 8807488817: its
    /// data-check string starts `8807488817:WebAppData`, so data signed for that bot verifies and
    /// data signed for any other does not.
    #[test]
    fn a_build_without_the_variable_verifies_for_the_production_bot() {
        assert_eq!(PROD_TG_BOT_ID, 8807488817);
        assert_eq!(PROD_TG_BOT_ID.to_string(), PROD_TG_BOT_ID_DIGITS);
        for release in [false, true] {
            for raw in [None, Some("")] {
                assert_eq!(
                    resolve_bot_id(raw, release),
                    Ok((PROD_TG_BOT_ID, BotIdFrom::Production)),
                    "{raw:?} release={release}"
                );
            }
        }
        let (bot, _) = resolve_bot_id(None, false).unwrap();
        let v = TelegramVerifier::with_key(
            Some(bot),
            signer().verifying_key().to_bytes(),
            TelegramEnvironment::Injected,
        );
        let (_, key) = fresh();
        let fields = fields_for(key.key_id());
        let borrowed: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let for_prod = format!(
            "{}&signature={}",
            query(&borrowed),
            sign(&borrowed, 8807488817, &signer())
        );
        assert!(v.verify_attestation(&for_prod, key.key_id()).is_ok());
        let for_other = format!(
            "{}&signature={}",
            query(&borrowed),
            sign(&borrowed, 8807488818, &signer())
        );
        assert_eq!(
            v.verify_attestation(&for_other, key.key_id()),
            Err(AttestationError::BadSignature)
        );
    }

    /// A development build may name another bot; a release-channel build may not (a build error,
    /// and refused at run time too); a malformed override refuses everything.
    #[test]
    fn the_override_is_for_development_builds_only() {
        assert_eq!(
            resolve_bot_id(Some("7342037359"), false),
            Ok((7342037359, BotIdFrom::Override))
        );
        assert!(resolve_bot_id(Some("7342037359"), true).is_err());
        assert_eq!(
            resolve_bot_id(Some("8807488817"), true),
            Ok((PROD_TG_BOT_ID, BotIdFrom::Production))
        );
        assert!(resolve_bot_id(Some("12a"), false).is_err());
        assert!(resolve_bot_id(Some("12a"), true).is_err());
        // The compile-time rule.
        assert!(override_allowed(false, Some("7342037359")));
        assert!(override_allowed(true, None));
        assert!(override_allowed(true, Some("")));
        assert!(override_allowed(true, Some("8807488817")));
        assert!(!override_allowed(true, Some("7342037359")));
        assert!(!override_allowed(true, Some("88074888170")));
        assert!(!override_allowed(true, Some("880748881")));
        assert!(str_eq("release", "release") && !str_eq("release", "releasE"));
        // Trimmed, as the scripts trim.
        assert!(override_allowed(true, Some(" 8807488817\n")));
        assert!(override_allowed(true, Some("  ")));
        assert!(!override_allowed(true, Some(" 7342037359 ")));
        assert_eq!(
            resolve_bot_id(Some(" 8807488817 "), true),
            Ok((PROD_TG_BOT_ID, BotIdFrom::Production))
        );
        assert_eq!(
            resolve_bot_id(Some(" 7342037359 "), false),
            Ok((7342037359, BotIdFrom::Override))
        );
        assert_eq!(
            resolve_bot_id(Some("  "), true),
            Ok((PROD_TG_BOT_ID, BotIdFrom::Production))
        );
    }

    /// The channel is read as `build_info::parse_channel` reads it: trimmed, any ASCII case.
    #[test]
    fn the_release_channel_is_normalised_like_build_info() {
        for release in ["release", "Release", " RELEASE ", "release\n", "\treLease"] {
            assert!(is_release_channel(Some(release)), "{release:?}");
        }
        for not in [
            None,
            Some(""),
            Some("dev"),
            Some("releases"),
            Some("re lease"),
        ] {
            assert!(!is_release_channel(not), "{not:?}");
        }
        assert!(eq_ignore_ascii_case("ReLeAsE", "release"));
        assert!(
            !eq_ignore_ascii_case("relеase", "release"),
            "a Cyrillic е is not an e"
        );
    }

    #[test]
    fn bot_id_parsing() {
        assert_eq!(parse_bot_id(Some("7342037359")), Ok(7342037359));
        for bad in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some(" 1"),
            Some("12a"),
            Some("+5"),
            Some("99999999999999999999"),
        ] {
            assert!(parse_bot_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn published_keys_are_the_constants() {
        assert_eq!(PRODUCTION_KEY[0], 0xe7);
        assert_eq!(PRODUCTION_KEY[31], 0x2d);
        assert!(VerifyingKey::from_bytes(&PRODUCTION_KEY).is_ok());
    }
}
