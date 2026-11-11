//! What the long tests share: running one scenario over several seeds.
//!
//! A seed is one draw of the link's jitter and loss and of str0m's ids, and on the thin and
//! braked paths those decide the trajectory: the agent on str0m 0.23 and on 0.24 each pass a
//! single-seed check on some seeds and fail it on others. The
//! tests that ask about such paths ask over seeds, about what every seed must show or how often.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// At most this many simulations at once in one test: the long tests run side by side under
/// `cargo test`, and each simulation is one thread of str0m and OpenH264.
const WORKERS: usize = 4;

/// `run(seed)` for every seed in `seeds`, on up to [`WORKERS`] threads, in seed order. A
/// simulation's panic is the test's.
pub fn over_seeds<T, F>(seeds: impl IntoIterator<Item = u64>, run: F) -> Vec<(u64, T)>
where
    T: Send,
    F: Fn(u64) -> T + Sync,
{
    let seeds: Vec<u64> = seeds.into_iter().collect();
    let workers = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(1, WORKERS)
        .min(seeds.len().max(1));
    let next = AtomicUsize::new(0);
    let done = Mutex::new(Vec::with_capacity(seeds.len()));
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    while let Some(&seed) = seeds.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let out = run(seed);
                        done.lock().unwrap().push((seed, out));
                    }
                })
            })
            .collect();
        for h in handles {
            if let Err(panic) = h.join() {
                std::panic::resume_unwind(panic);
            }
        }
    });
    let mut done = done.into_inner().unwrap();
    done.sort_by_key(|(seed, _)| *seed);
    done
}

/// The median of `values` (the mean of the middle two for an even count).
pub fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    match v.len() {
        0 => f64::NAN,
        n if n % 2 == 1 => v[n / 2],
        n => (v[n / 2 - 1] + v[n / 2]) / 2.0,
    }
}
