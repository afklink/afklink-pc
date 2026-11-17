//! The PC's nonce book (protocol spec §2.2): batches of 16-byte `nonce_pc` the PC gave the server,
//! each valid for [`NONCE_TTL_MS`] from its issue and spent once, bound to the session that spent
//! it. Times are the caller's monotonic milliseconds; on resume from sleep the book is cleared
//! ([`NonceBook::clear`]) because the monotonic clock may not count sleep.

use std::collections::{HashMap, VecDeque};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::wire::NONCE_PC_LEN;

/// A nonce is valid while `now − issued ≤` this (spec §2.2, `NONCE_TTL_MS`).
pub const NONCE_TTL_MS: u64 = 180_000;
/// The book keeps a batch while `now − issued ≤` this, to tell expired from unknown.
pub const NONCE_KEEP_MS: u64 = 360_000;
/// The most batches kept; beyond, the oldest go (`warn`).
pub const MAX_BATCHES: usize = 192;
/// Nonces per batch the agent sends (spec §2.2).
pub const BATCH_SIZE: usize = 4;

/// Why a nonce is refused (`nonce_stale:<detail>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    Unknown,
    Expired,
    Used,
}

impl NonceError {
    pub const fn detail(self) -> &'static str {
        match self {
            Self::Unknown => "nonce_unknown",
            Self::Expired => "nonce_expired",
            Self::Used => "nonce_used",
        }
    }
}

/// A batch to send (`session_nonces`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceBatch {
    pub batch: u32,
    /// Base64url without padding, 22 characters each.
    pub nonces: Vec<String>,
}

#[derive(Debug)]
struct Batch {
    issued_ms: u64,
    nonces: Vec<[u8; NONCE_PC_LEN]>,
}

/// The book. Never logs a nonce.
#[derive(Debug, Default)]
pub struct NonceBook {
    batches: VecDeque<Batch>,
    /// Spent nonces and the session each is bound to.
    spent: HashMap<[u8; NONCE_PC_LEN], String>,
    next_batch: u32,
}

impl NonceBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a batch of [`BATCH_SIZE`] distinct nonces from the system CSPRNG (aws-lc-rs),
    /// record it as issued at `now_ms`, and return it for the server. `None` only if the CSPRNG
    /// fails (`error` logged; nothing recorded).
    pub fn new_batch(&mut self, now_ms: u64) -> Option<NonceBatch> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut nonces: Vec<[u8; NONCE_PC_LEN]> = Vec::with_capacity(BATCH_SIZE);
        while nonces.len() < BATCH_SIZE {
            let mut n = [0u8; NONCE_PC_LEN];
            if let Err(e) = aws_lc_rs::rand::SecureRandom::fill(&rng, &mut n) {
                tracing::error!("nonce book: the system random generator failed ({e:?}); no batch");
                return None;
            }
            if !nonces.contains(&n) {
                nonces.push(n);
            }
        }
        let wire = nonces.iter().map(|n| URL_SAFE_NO_PAD.encode(n)).collect();
        self.next_batch = self.next_batch.wrapping_add(1);
        let batch = self.next_batch;
        self.insert(now_ms, nonces);
        tracing::debug!(batch, now_ms, "nonce book: a new batch issued");
        Some(NonceBatch {
            batch,
            nonces: wire,
        })
    }

    /// Record a batch issued at `issued_ms` (tests and vectors; [`Self::new_batch`] uses it).
    /// Old batches are forgotten at the next check, by its time.
    pub fn insert(&mut self, issued_ms: u64, nonces: Vec<[u8; NONCE_PC_LEN]>) {
        self.batches.push_back(Batch { issued_ms, nonces });
        while self.batches.len() > MAX_BATCHES {
            let forgot = self.drop_oldest();
            tracing::warn!(
                max = MAX_BATCHES,
                spent_forgotten = forgot,
                "nonce book: more batches than it keeps; the oldest dropped with its spends"
            );
        }
    }

    /// Drop the oldest batch and the spends of its nonces — but not of a nonce a batch still
    /// kept holds too (that batch decides it, and its spend must stay). How many spends went.
    fn drop_oldest(&mut self) -> usize {
        let Some(old) = self.batches.pop_front() else {
            return 0;
        };
        let mut forgot = 0;
        for n in &old.nonces {
            if self.batches.iter().any(|b| b.nonces.contains(n)) {
                tracing::debug!(
                    "nonce book: a dropped batch's nonce is in a kept batch too; its spend stays"
                );
                continue;
            }
            if self.spent.remove(n).is_some() {
                forgot += 1;
            }
        }
        forgot
    }

    /// Forget batches older than [`NONCE_KEEP_MS`] (and nonces spent from them).
    fn prune(&mut self, now_ms: u64) {
        while let Some(front) = self.batches.front() {
            if now_ms.saturating_sub(front.issued_ms) <= NONCE_KEEP_MS {
                break;
            }
            let issued_ms = front.issued_ms;
            let forgot = self.drop_oldest();
            tracing::trace!(
                issued_ms,
                spent_forgotten = forgot,
                "nonce book: a batch aged out"
            );
        }
    }

    /// How many spends the book keeps (tests: bounded by the batches it keeps).
    pub fn spent_len(&self) -> usize {
        self.spent.len()
    }

    /// Whether `nonce` is valid now (spec §3.4 step 5): in the book, at most [`NONCE_TTL_MS`]
    /// old, unspent. A spent nonce is `Used` even for the session that spent it. No side effect
    /// beyond forgetting batches past [`NONCE_KEEP_MS`].
    pub fn check(&mut self, nonce: &[u8; NONCE_PC_LEN], now_ms: u64) -> Result<(), NonceError> {
        self.prune(now_ms);
        // The newest batch holding it decides (a duplicate in an older batch cannot extend it).
        let issued = self
            .batches
            .iter()
            .rev()
            .find(|b| b.nonces.contains(nonce))
            .map(|b| b.issued_ms)
            .ok_or(NonceError::Unknown)?;
        if self.spent.contains_key(nonce) {
            return Err(NonceError::Used);
        }
        if now_ms.saturating_sub(issued) > NONCE_TTL_MS {
            return Err(NonceError::Expired);
        }
        Ok(())
    }

    /// Spend `nonce` for `session_id` (spec §3.4 step 9; after a successful check only).
    pub fn spend(&mut self, nonce: &[u8; NONCE_PC_LEN], session_id: &str) {
        self.spent.insert(*nonce, session_id.to_string());
    }

    /// Whether `nonce` is in the newest batch (spec §2.2 (c): a `session_request` with such a
    /// nonce, or none, asks for a new batch).
    pub fn in_newest_batch(&self, nonce: &[u8; NONCE_PC_LEN]) -> bool {
        self.batches
            .back()
            .is_some_and(|b| b.nonces.contains(nonce))
    }

    /// Resume from sleep (spec §2.2): every batch and spend forgotten; the caller sends a new
    /// batch at once.
    pub fn clear(&mut self) {
        tracing::debug!(
            batches = self.batches.len(),
            spent = self.spent.len(),
            "nonce book: cleared (resume from sleep)"
        );
        self.batches.clear();
        self.spent.clear();
    }

    pub fn batches(&self) -> usize {
        self.batches.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    fn nonce(n: u16) -> [u8; NONCE_PC_LEN] {
        let mut b = [0u8; NONCE_PC_LEN];
        b[..2].copy_from_slice(&n.to_be_bytes());
        b
    }

    /// An overflowed batch takes its spends with it: the book's spends stay bounded by the
    /// batches it keeps. A nonce a kept batch holds too stays spent (no replay through a
    /// duplicate).
    #[test]
    fn an_overflowed_batch_drops_its_spends() {
        let mut book = NonceBook::new();
        book.insert(0, vec![nonce(0), nonce(1)]);
        book.spend(&nonce(0), "s0");
        book.spend(&nonce(1), "s1");
        // A later batch holds nonce 1 again (the vectors may; the CSPRNG never does).
        book.insert(0, vec![nonce(1), nonce(2)]);
        for i in 0..MAX_BATCHES {
            if book.batches() == MAX_BATCHES {
                break;
            }
            book.insert(0, vec![nonce(1000 + u16::try_from(i).unwrap())]);
        }
        assert_eq!(book.batches(), MAX_BATCHES);
        assert_eq!(book.spent_len(), 2);
        // One more: the first batch goes; nonce 0's spend with it, nonce 1's stays.
        book.insert(0, vec![nonce(5000)]);
        assert_eq!(book.batches(), MAX_BATCHES);
        assert_eq!(
            book.spent_len(),
            1,
            "the dropped batch's own spend is forgotten"
        );
        assert_eq!(book.check(&nonce(0), 0), Err(NonceError::Unknown));
        assert_eq!(
            book.check(&nonce(1), 0),
            Err(NonceError::Used),
            "a kept batch still holds it: still spent"
        );
        // Spends never outgrow the book: spend everything, overflow everything.
        for i in 0..MAX_BATCHES {
            let n = nonce(20_000 + u16::try_from(i).unwrap());
            book.insert(0, vec![n]);
            book.spend(&n, "s");
        }
        for i in 0..MAX_BATCHES {
            book.insert(0, vec![nonce(40_000 + u16::try_from(i).unwrap())]);
        }
        assert_eq!(book.spent_len(), 0);
    }
}
