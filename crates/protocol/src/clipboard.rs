//! Clipboard sync between the viewer and the PC: the messages, the limits, and the two helpers both
//! ends need — cutting a text into chunks that each fit one DataChannel message, and joining them
//! back. Text only (`CF_UNICODETEXT` on the PC).
//!
//! Mirrors `packages/protocol/src/clipboard.ts` (the flow, the limits, `splitClipboardText`,
//! `ClipboardJoiner`) and the `cb_*` schemas of `datachannel.ts`; held to them by the fixtures
//! (`tests/fixtures.rs`) and by the same cases here as in `clipboard.test.ts`.
//!
//! Everything rides the reliable `input` channel, both ways:
//!
//! - viewer -> agent: `cb_sync` (the browser's switch, off by default) and `cb_set` (chunks of a
//!   text for the PC's clipboard) — [`crate::InputMessage::ClipboardSync`] and
//!   [`crate::InputMessage::ClipboardSet`];
//! - agent -> viewer: `cb_state` (the answer to every `cb_sync`, and again whenever the PC changes
//!   it), `cb_pc` (chunks of the PC's clipboard after it changed; only while `pc` is `ready`, never
//!   in «Только игра», where the PC says `to_pc_only`) and `cb_ack` (one per `cb_set` text) — the
//!   [`crate::AgentDataMessage`] variants of the same names.
//!
//! The agent's side of the flow — when it reads and writes the clipboard, and why it refuses — is
//! `afklink_core::clipboard`.

use serde::{Deserialize, Serialize};

/// The largest text either side sends or accepts: UTF-8 bytes of the whole text.
/// `CLIPBOARD_MAX_BYTES` in the contract.
pub const CLIPBOARD_MAX_BYTES: usize = 64 * 1024;

/// One chunk's text, JSON-escaped and in UTF-8, is at most this many bytes, so a chunk message
/// always fits [`crate::INPUT_MAX_BYTES`]. `CLIPBOARD_CHUNK_TEXT_BYTES` in the contract.
pub const CLIPBOARD_CHUNK_TEXT_BYTES: usize = 4000;

/// At most this many chunks per text (the largest text, escaped at worst, needs 99).
/// `CLIPBOARD_MAX_CHUNKS` in the contract.
pub const CLIPBOARD_MAX_CHUNKS: u32 = 128;

/// One chunk of a clipboard text: `cb_set` (viewer -> agent) and `cb_pc` (agent -> viewer) both
/// carry it. `id` numbers the text (the sender's own count), `i` is this chunk's place from 0, `n`
/// the text's chunk count; `text` is never empty and never half a character.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardChunk {
    pub id: u32,
    pub i: u32,
    pub n: u32,
    pub text: String,
}

/// Which way the PC allows clipboard sync now (`CLIPBOARD_PC_STATES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardPc {
    /// Both ways; `on` says whether this session syncs.
    Ready,
    /// The PC is in «Только игра»: whoever connects may see the game and nothing else, so nothing
    /// of the PC's clipboard leaves it (never read, no `cb_pc`); the viewer's text still goes to the
    /// PC (`cb_set`, answered as ever).
    ToPcOnly,
    /// Neither: the agent cannot reach this PC's clipboard (its listener did not start).
    Unavailable,
}

impl ClipboardPc {
    /// The wire spelling, for log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ToPcOnly => "to_pc_only",
            Self::Unavailable => "unavailable",
        }
    }

    /// The viewer's text may go to the PC: [`Self::Ready`] and [`Self::ToPcOnly`].
    pub fn takes_text(self) -> bool {
        matches!(self, Self::Ready | Self::ToPcOnly)
    }

    /// The PC's text may go to the viewer: [`Self::Ready`] only.
    pub fn gives_text(self) -> bool {
        self == Self::Ready
    }
}

/// `cb_state`: clipboard sync as the agent has it for this session. `on` only while the PC allows
/// at least one way ([`ClipboardPc::takes_text`]): the viewer's text then goes to the PC, and the
/// PC's to the viewer as well with [`ClipboardPc::Ready`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardState {
    pub on: bool,
    pub pc: ClipboardPc,
}

/// Why a `cb_set` text did not reach the PC's clipboard (`CLIPBOARD_REFUSALS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardRefusal {
    /// Sync is not on in this session.
    Off,
    /// Over [`CLIPBOARD_MAX_BYTES`].
    TooLarge,
    /// Chunks out of order, of another text, or numbered past their count.
    Malformed,
    /// Windows did not take it: the clipboard stayed busy, or the listener is unavailable.
    Failed,
}

impl ClipboardRefusal {
    /// The wire spelling, for log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::Failed => "failed",
        }
    }
}

/// `cb_ack`: the answer to one whole `cb_set` text. `why` only when not `ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardAck {
    pub id: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<ClipboardRefusal>,
}

impl ClipboardAck {
    /// The text `id` is on the PC's clipboard.
    pub fn ok(id: u32) -> Self {
        Self {
            id,
            ok: true,
            why: None,
        }
    }

    /// The text `id` is not, for `why`.
    pub fn refused(id: u32, why: ClipboardRefusal) -> Self {
        Self {
            id,
            ok: false,
            why: Some(why),
        }
    }
}

/// What one character costs inside a JSON string, in UTF-8 bytes — serde_json's escaping, which is
/// JavaScript's `JSON.stringify` for everything a Rust string can hold.
fn json_bytes(c: char) -> usize {
    match c {
        '"' | '\\' => 2,
        '\u{08}' | '\t' | '\n' | '\u{0c}' | '\r' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// `text` cut into chunk texts, in order, each at most [`CLIPBOARD_CHUNK_TEXT_BYTES`] once
/// JSON-escaped, never splitting a character. `None` for an empty text (nothing to send) and for one
/// over [`CLIPBOARD_MAX_BYTES`] (refused, not cut short). `splitClipboardText` in the contract.
pub fn split_text(text: &str) -> Option<Vec<&str>> {
    if text.is_empty() || text.len() > CLIPBOARD_MAX_BYTES {
        return None;
    }
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut size = 0;
    for (at, c) in text.char_indices() {
        let cost = json_bytes(c);
        if size + cost > CLIPBOARD_CHUNK_TEXT_BYTES && at > start {
            pieces.push(&text[start..at]);
            start = at;
            size = 0;
        }
        size += cost;
    }
    pieces.push(&text[start..]);
    Some(pieces)
}

/// `text` as `cb_pc` chunks under `id`, or `None` as [`split_text`] says.
pub fn chunks(id: u32, text: &str) -> Option<Vec<ClipboardChunk>> {
    let pieces = split_text(text)?;
    let n = u32::try_from(pieces.len()).ok()?;
    Some(
        pieces
            .into_iter()
            .zip(0u32..)
            .map(|(piece, i)| ClipboardChunk {
                id,
                i,
                n,
                text: piece.to_string(),
            })
            .collect(),
    )
}

/// What [`Joiner::accept`] made of one chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Joined {
    /// A text is under way and this chunk is in it; more to come.
    Partial,
    /// The last chunk: the whole text.
    Done { id: u32, text: String },
    /// The text `id` is dropped, now, for `why` ([`ClipboardRefusal::TooLarge`] or
    /// [`ClipboardRefusal::Malformed`]); the rest of its chunks will be [`Joined::Ignored`].
    Dropped { id: u32, why: ClipboardRefusal },
    /// A chunk of a text already dropped (or refused by [`Joiner::refuse`]).
    Ignored,
}

/// A text being joined.
#[derive(Debug)]
struct Under {
    id: u32,
    n: u32,
    text: String,
}

/// Joins the chunks of one text at a time: a chunk `i = 0` starts a text (an unfinished one before
/// it is abandoned; an id used again is a new text), anything out of order drops the text as
/// malformed, more than [`CLIPBOARD_MAX_BYTES`] drops it as too large, and the rest of a dropped
/// text is ignored. `ClipboardJoiner` in the contract, held to the same cases.
#[derive(Debug, Default)]
pub struct Joiner {
    current: Option<Under>,
    /// The parts joined so far of `current`, counted.
    parts: u32,
    dropped: Option<u32>,
}

impl Joiner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one chunk.
    pub fn accept(&mut self, chunk: &ClipboardChunk) -> Joined {
        let ClipboardChunk { id, i, n, .. } = *chunk;
        let counted = (1..=CLIPBOARD_MAX_CHUNKS).contains(&n) && i < n;
        if !counted {
            return if self.dropped == Some(id) {
                Joined::Ignored
            } else {
                self.drop(id, ClipboardRefusal::Malformed)
            };
        }
        if i == 0 {
            self.current = Some(Under {
                id,
                n,
                text: String::new(),
            });
            self.parts = 0;
            if self.dropped == Some(id) {
                self.dropped = None;
            }
        } else {
            let in_order = self
                .current
                .as_ref()
                .is_some_and(|u| u.id == id && u.n == n && self.parts == i);
            if !in_order {
                return if self.dropped == Some(id) {
                    Joined::Ignored
                } else {
                    self.drop(id, ClipboardRefusal::Malformed)
                };
            }
        }
        let Some(under) = self.current.as_mut() else {
            return self.drop(id, ClipboardRefusal::Malformed);
        };
        if under.text.len() + chunk.text.len() > CLIPBOARD_MAX_BYTES {
            return self.drop(id, ClipboardRefusal::TooLarge);
        }
        under.text.push_str(&chunk.text);
        self.parts += 1;
        if self.parts < n {
            return Joined::Partial;
        }
        self.parts = 0;
        match self.current.take() {
            Some(done) => Joined::Done {
                id,
                text: done.text,
            },
            None => self.drop(id, ClipboardRefusal::Malformed),
        }
    }

    /// Refuse the text `id` for a reason of the receiver's own (sync off, say): an unfinished text
    /// is dropped and the rest of this one's chunks are [`Joined::Ignored`]. True the first time for
    /// this `id` — the moment to say so, once.
    pub fn refuse(&mut self, id: u32) -> bool {
        let first = self.dropped != Some(id);
        self.current = None;
        self.parts = 0;
        self.dropped = Some(id);
        first
    }

    /// A text is under way: its id, chunks joined and count, for the log.
    pub fn under_way(&self) -> Option<(u32, u32, u32)> {
        self.current.as_ref().map(|u| (u.id, self.parts, u.n))
    }

    fn drop(&mut self, id: u32, why: ClipboardRefusal) -> Joined {
        self.current = None;
        self.parts = 0;
        self.dropped = Some(id);
        Joined::Dropped { id, why }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chunk as a `cb_set` message with the largest id, serialized.
    fn wire(chunk: &ClipboardChunk) -> String {
        let msg = crate::InputMessage::ClipboardSet(ClipboardChunk {
            id: u32::MAX,
            ..chunk.clone()
        });
        serde_json::to_string(&msg).expect("serializes")
    }

    #[test]
    fn every_chunk_of_the_largest_texts_fits_one_message() {
        let cases = [
            "a".repeat(CLIPBOARD_MAX_BYTES),
            "\u{1}".repeat(CLIPBOARD_MAX_BYTES),
            "\"\\".repeat(CLIPBOARD_MAX_BYTES / 2),
            "я".repeat(CLIPBOARD_MAX_BYTES / 2),
            "😀".repeat(CLIPBOARD_MAX_BYTES / 4),
            "line\r\n".repeat(CLIPBOARD_MAX_BYTES / 6),
        ];
        for text in &cases {
            let all = chunks(9, text).expect("fits");
            assert!(all.len() <= CLIPBOARD_MAX_CHUNKS as usize, "{}", all.len());
            for chunk in &all {
                let raw = wire(chunk);
                assert!(raw.len() <= crate::INPUT_MAX_BYTES, "{} bytes", raw.len());
                assert!(!chunk.text.is_empty());
            }
            let joined: String = all.iter().map(|c| c.text.as_str()).collect();
            assert_eq!(&joined, text);
        }
        // The worst escaping, as the contract's test counts it.
        assert_eq!(
            chunks(1, &"\u{1}".repeat(CLIPBOARD_MAX_BYTES))
                .expect("fits")
                .len(),
            99
        );
        assert_eq!(
            chunks(1, &"a".repeat(CLIPBOARD_MAX_BYTES))
                .expect("fits")
                .len(),
            17
        );
    }

    #[test]
    fn a_character_is_never_split() {
        let text = format!("{}😀tail", "x".repeat(CLIPBOARD_CHUNK_TEXT_BYTES - 1));
        let pieces = split_text(&text).expect("fits");
        assert_eq!(
            pieces,
            vec![
                "x".repeat(CLIPBOARD_CHUNK_TEXT_BYTES - 1).as_str(),
                "😀tail"
            ]
        );
    }

    #[test]
    fn an_empty_text_is_nothing_and_one_over_the_limit_is_refused() {
        assert_eq!(split_text(""), None);
        assert_eq!(split_text(&"a".repeat(CLIPBOARD_MAX_BYTES + 1)), None);
        assert_eq!(split_text(&"я".repeat(CLIPBOARD_MAX_BYTES / 2 + 1)), None);
    }

    fn chunk(id: u32, i: u32, n: u32, text: &str) -> ClipboardChunk {
        ClipboardChunk {
            id,
            i,
            n,
            text: text.to_string(),
        }
    }

    #[test]
    fn a_text_comes_back_whole_and_the_joiner_is_ready_for_the_next() {
        let mut joiner = Joiner::new();
        let text = "Привет\n".repeat(2000);
        let all = chunks(5, &text).expect("fits");
        assert!(all.len() > 1);
        for c in &all[..all.len() - 1] {
            assert_eq!(joiner.accept(c), Joined::Partial);
        }
        assert_eq!(
            joiner.under_way(),
            Some((5, all.len() as u32 - 1, all.len() as u32))
        );
        assert_eq!(
            joiner.accept(&all[all.len() - 1]),
            Joined::Done { id: 5, text }
        );
        assert_eq!(
            joiner.accept(&chunk(6, 0, 1, "next")),
            Joined::Done {
                id: 6,
                text: "next".into()
            }
        );
    }

    #[test]
    fn a_chunk_out_of_order_drops_its_text_and_the_rest_is_ignored() {
        use ClipboardRefusal::Malformed;
        let mut joiner = Joiner::new();
        assert_eq!(joiner.accept(&chunk(1, 0, 3, "a")), Joined::Partial);
        assert_eq!(
            joiner.accept(&chunk(1, 2, 3, "c")),
            Joined::Dropped {
                id: 1,
                why: Malformed
            }
        );
        assert_eq!(joiner.accept(&chunk(1, 1, 3, "b")), Joined::Ignored);
        assert_eq!(joiner.accept(&chunk(2, 0, 2, "a")), Joined::Partial);
        let dropped = |id| Joined::Dropped { id, why: Malformed };
        assert_eq!(joiner.accept(&chunk(2, 1, 3, "b")), dropped(2));
        assert_eq!(joiner.accept(&chunk(9, 1, 2, "b")), dropped(9));
        assert_eq!(joiner.accept(&chunk(10, 2, 2, "b")), dropped(10));
        assert_eq!(
            joiner.accept(&chunk(11, 0, CLIPBOARD_MAX_CHUNKS + 1, "b")),
            dropped(11)
        );
    }

    #[test]
    fn a_new_text_abandons_an_unfinished_one_and_an_id_used_again_is_new() {
        let mut joiner = Joiner::new();
        assert_eq!(joiner.accept(&chunk(1, 0, 2, "old")), Joined::Partial);
        assert_eq!(
            joiner.accept(&chunk(2, 0, 1, "new")),
            Joined::Done {
                id: 2,
                text: "new".into()
            }
        );
        assert_eq!(
            joiner.accept(&chunk(1, 1, 2, "late")),
            Joined::Dropped {
                id: 1,
                why: ClipboardRefusal::Malformed
            }
        );
        assert_eq!(
            joiner.accept(&chunk(1, 0, 1, "again")),
            Joined::Done {
                id: 1,
                text: "again".into()
            }
        );
    }

    #[test]
    fn more_than_the_limit_is_dropped_as_too_large() {
        let mut joiner = Joiner::new();
        let piece = "a".repeat(CLIPBOARD_CHUNK_TEXT_BYTES);
        let n = CLIPBOARD_MAX_BYTES.div_ceil(CLIPBOARD_CHUNK_TEXT_BYTES) as u32 + 1;
        let mut last = Joined::Partial;
        for i in 0..n {
            last = joiner.accept(&chunk(4, i, n, &piece));
            if last != Joined::Partial {
                break;
            }
        }
        assert_eq!(
            last,
            Joined::Dropped {
                id: 4,
                why: ClipboardRefusal::TooLarge
            }
        );
        assert_eq!(joiner.accept(&chunk(4, n - 1, n, &piece)), Joined::Ignored);
    }

    #[test]
    fn a_refused_text_is_said_once_and_its_other_chunks_are_ignored() {
        let mut joiner = Joiner::new();
        assert!(joiner.refuse(8));
        assert!(!joiner.refuse(8));
        assert_eq!(joiner.accept(&chunk(8, 1, 2, "b")), Joined::Ignored);
    }

    #[test]
    fn the_wire_spellings_are_the_contracts() {
        let state = crate::AgentDataMessage::ClipboardState(ClipboardState {
            on: true,
            pc: ClipboardPc::ToPcOnly,
        });
        assert_eq!(
            state.to_json().expect("json"),
            r#"{"t":"cb_state","on":true,"pc":"to_pc_only"}"#
        );
        for (pc, wire, takes, gives) in [
            (ClipboardPc::Ready, "ready", true, true),
            (ClipboardPc::ToPcOnly, "to_pc_only", true, false),
            (ClipboardPc::Unavailable, "unavailable", false, false),
        ] {
            assert_eq!(pc.as_str(), wire);
            assert_eq!((pc.takes_text(), pc.gives_text()), (takes, gives), "{wire}");
        }
        // The old «Только игра» word is not the contract's any more.
        assert!(serde_json::from_str::<ClipboardPc>(r#""off_on_pc""#).is_err());
        assert!(serde_json::from_str::<ClipboardRefusal>(r#""off_on_pc""#).is_err());
        let ack = crate::AgentDataMessage::ClipboardAck(ClipboardAck::ok(3));
        assert_eq!(
            ack.to_json().expect("json"),
            r#"{"t":"cb_ack","id":3,"ok":true}"#
        );
        let refused = crate::AgentDataMessage::ClipboardAck(ClipboardAck::refused(
            4,
            ClipboardRefusal::TooLarge,
        ));
        assert_eq!(
            refused.to_json().expect("json"),
            r#"{"t":"cb_ack","id":4,"ok":false,"why":"too_large"}"#
        );
        let pc = crate::AgentDataMessage::ClipboardPc(chunk(7, 0, 1, "a\r\nb"));
        assert_eq!(
            pc.to_json().expect("json"),
            r#"{"t":"cb_pc","id":7,"i":0,"n":1,"text":"a\r\nb"}"#
        );
        for (refusal, wire) in [
            (ClipboardRefusal::Off, "off"),
            (ClipboardRefusal::TooLarge, "too_large"),
            (ClipboardRefusal::Malformed, "malformed"),
            (ClipboardRefusal::Failed, "failed"),
        ] {
            assert_eq!(refusal.as_str(), wire);
        }
        let sync = crate::InputMessage::parse(r#"{"t":"cb_sync","on":true}"#).expect("parses");
        assert_eq!(sync, crate::InputMessage::ClipboardSync { on: true });
        assert!(sync.must_arrive());
        let set = crate::InputMessage::parse(r#"{"t":"cb_set","id":3,"i":1,"n":2,"text":"b"}"#)
            .expect("parses");
        assert_eq!(set, crate::InputMessage::ClipboardSet(chunk(3, 1, 2, "b")));
        assert!(set.must_arrive());
        assert_eq!(set.channel().label(), crate::CHANNEL_INPUT);
    }
}
