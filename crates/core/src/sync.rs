//! Lock helpers for the agent's observable state.
//!
//! Every mutex in this codebase guards plain data that the UI reads and the
//! orchestrator writes — `AgentState`, `Config`, the injector's held-key ledger. None
//! of them carries a cross-field invariant that a panic could leave half-applied, so
//! poisoning has no meaning here: the data is still exactly as valid as it was.
//!
//! That makes `unwrap()` on these locks strictly worse than useless. It does not protect
//! an invariant; it converts one task's panic into *every* task's panic, and the visible
//! result is the agent vanishing from the owner's PC until they walk over and restart it
//! — the one failure mode a remote-access tool cannot afford.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock a state mutex, taking the data even if a previous holder panicked.
///
/// Use this instead of `lock().unwrap()` for any mutex guarding observable state.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn a_poisoned_lock_still_yields_the_data() {
        let m = Arc::new(Mutex::new(7u32));
        let m2 = m.clone();
        // Poison it: panic while holding the guard.
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().expect("fresh lock");
            panic!("poison");
        })
        .join();
        assert!(m.lock().is_err(), "the mutex should be poisoned");
        assert_eq!(*lock(&m), 7, "the value is unchanged and must be readable");
    }
}
