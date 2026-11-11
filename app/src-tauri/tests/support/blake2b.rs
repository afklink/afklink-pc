//! BLAKE2b-512, unkeyed (RFC 7693) — for tests only: the digest minisign signs in place of the file
//! for a prehashed (`ED`) signature. No crate in the tree exposes it (minisign keeps its own
//! private), and the tests that need it — a prehashed signature flipped to legacy `Ed` over the
//! digest — check it against RFC 7693's test vector and against minisign itself.
//!
//! Shared by `src/updater/manifest.rs`'s unit tests and `tests/updater_http.rs` (`#[path]`).

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[allow(clippy::many_single_char_names, reason = "RFC 7693's names")]
fn g(v: &mut [u64; 16], (a, b, c, d): (usize, usize, usize, usize), x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *word = u64::from_le_bytes(bytes);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, (0, 4, 8, 12), m[s[0]], m[s[1]]);
        g(&mut v, (1, 5, 9, 13), m[s[2]], m[s[3]]);
        g(&mut v, (2, 6, 10, 14), m[s[4]], m[s[5]]);
        g(&mut v, (3, 7, 11, 15), m[s[6]], m[s[7]]);
        g(&mut v, (0, 5, 10, 15), m[s[8]], m[s[9]]);
        g(&mut v, (1, 6, 11, 12), m[s[10]], m[s[11]]);
        g(&mut v, (2, 7, 8, 13), m[s[12]], m[s[13]]);
        g(&mut v, (3, 4, 9, 14), m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b-512 of `data`.
pub fn blake2b_512(data: &[u8]) -> [u8; 64] {
    let mut h = IV;
    // Parameter block: digest length 64, no key, fanout 1, depth 1.
    h[0] ^= 0x0101_0000 ^ 64;
    if data.is_empty() {
        compress(&mut h, &[0u8; 128], 0, true);
    } else {
        let mut counter: u128 = 0;
        let mut blocks = data.chunks(128).peekable();
        while let Some(chunk) = blocks.next() {
            counter += chunk.len() as u128;
            let mut block = [0u8; 128];
            block[..chunk.len()].copy_from_slice(chunk);
            compress(&mut h, &block, counter, blocks.peek().is_none());
        }
    }
    let mut out = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// RFC 7693 appendix A: BLAKE2b-512("abc").
pub const ABC: &str = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                       7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";

/// `signature` (base64 of a minisign `.sig` file) with its algorithm turned from prehashed `ED` to
/// legacy `Ed` — bytes the global signature does not cover — re-encoded as the manifest carries it.
pub fn flip_to_legacy(signature: &str) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let Ok(raw) = engine.decode(signature.trim()) else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if let Some(line) = lines.get_mut(1) {
        if let Ok(mut bin) = engine.decode(line.trim()) {
            if bin.len() > 2 {
                bin[1] = b'd';
            }
            *line = engine.encode(bin);
        }
    }
    let mut flipped = lines.join("\n");
    flipped.push('\n');
    engine.encode(flipped)
}
