// SPDX-License-Identifier: Apache-2.0
//! Vendored SHA-256 and HMAC-SHA-256 (`docs/event-log.md` §4, `docs/receipts.md`
//! §6).
//!
//! The event-log hash chain (tamper-evidence) and the receipt MAC chain
//! (tamper-resistance) both need a 32-byte hash and a keyed MAC. CrustCore keeps
//! the workspace **std-only and offline-buildable** (`ROADMAP.md` §6.1,
//! `README.md`), so rather than pull `sha2`/`blake3` (which would be the first
//! third-party crates and break offline builds), we vendor SHA-256 here. This is
//! a standard, fixed algorithm — not novel cryptography — and is validated
//! against the published NIST (FIPS 180-4) and RFC 4231 test vectors below.
//!
//! Swapping to the `sha2` crate later is a localized change behind these two
//! functions, gated on the dependency-admission policy (`CLAUDE.md` §6.4).
//!
//! This is tamper-*evidence/resistance* for an audit log, not confidentiality.

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The SHA-256 block size in bytes.
const BLOCK: usize = 64;

/// Computes the SHA-256 digest of `data` (FIPS 180-4).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H0;

    // Pre-processing: append 0x80, pad with zeros to 56 mod 64, then the 64-bit
    // big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 9 + BLOCK);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % BLOCK != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for block in msg.chunks_exact(BLOCK) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let b = i * 4;
            *word = u32::from_be_bytes([block[b], block[b + 1], block[b + 2], block[b + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Computes HMAC-SHA-256 of `msg` under `key` (RFC 2104 / RFC 4231).
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // Reduce an over-long key to its digest, then zero-pad to the block size.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// Constant-time equality for two 32-byte digests (a SHA-256 / HMAC-SHA256 output, or any
/// fixed 32-byte tag/nonce). Visits **every** byte with no early return, so a near-miss
/// cannot be distinguished from a far-miss by timing. This is the comparison every
/// secret/MAC/signature check must use (receipts invariant 10, webhook + Slack signature
/// verification) — the single audited home next to [`sha256`]/[`hmac_sha256`].
#[must_use]
pub fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Decodes a single ASCII hex digit (`0-9`, `a-f`, `A-F`) to its 0–15 value, or `None` for
/// any non-hex byte. The building block for decoding a hex-encoded digest/signature.
#[must_use]
pub fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes exactly 64 ASCII hex chars into the 32-byte digest they encode, or `None` if the
/// length is not 64 or any char is non-hex. The standard decoder for a hex-encoded
/// SHA-256 / HMAC-SHA256 digest or signature (used by the webhook + Slack verifiers).
#[must_use]
pub fn hex32_decode(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // FIPS 180-4 / NIST published SHA-256 vectors.
    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // A multi-block message (> 64 bytes) exercises the padding/length path.
    #[test]
    fn sha256_long_message_spans_blocks() {
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million_a)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // RFC 4231 HMAC-SHA-256 test vectors.
    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        // Test case 1.
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2.
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: key longer than one block (131 bytes of 0xaa).
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn ct_eq_matches_only_identical_digests() {
        let a = sha256(b"alpha");
        assert!(ct_eq(&a, &a));
        assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
        // A single differing byte (anywhere) fails.
        let mut b = a;
        b[31] ^= 0x01;
        assert!(!ct_eq(&a, &b));
        let mut c = a;
        c[0] ^= 0x80;
        assert!(!ct_eq(&a, &c));
    }

    #[test]
    fn hex_val_decodes_every_case_and_rejects_non_hex() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'f'), Some(15));
        assert_eq!(hex_val(b'A'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        for bad in [b'g', b'G', b' ', b'/', b':', b'x', 0u8, 0xff] {
            assert_eq!(hex_val(bad), None, "byte {bad} must not decode");
        }
    }

    #[test]
    fn hex32_decode_round_trips_a_digest_and_rejects_bad_input() {
        let digest = sha256(b"round trip");
        let encoded = hex(&digest); // 64 lowercase hex chars
        assert_eq!(hex32_decode(&encoded), Some(digest));
        // Wrong length and a non-hex char both fail.
        assert_eq!(hex32_decode(&encoded[..63]), None);
        assert_eq!(hex32_decode(&format!("{}zz", &encoded[..62])), None);
        assert_eq!(hex32_decode(""), None);
    }
}
