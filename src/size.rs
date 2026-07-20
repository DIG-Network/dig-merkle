//! The `.dig` store size as a power-of-2 bucket (SPEC §2, CLVM alist key `"sz"`).
//!
//! A `.dig` store's on-chain size hint is quantised to a power-of-2 **bucket** rather than an exact
//! byte count, so it reveals only a coarse magnitude and encodes in a single CLVM byte. The bucket
//! exponent `k ∈ 0..=10` maps to `2^k MB`, where — and this is the canonical unit contract that
//! dig-store must not drift from — **1 MB = 1 MiB = 2^20 bytes**. The ladder is therefore:
//!
//! | k | size |     | k | size |
//! |---|------|-----|---|------|
//! | 0 | 1 MB | | 6 | 64 MB |
//! | 1 | 2 MB | | 7 | 128 MB |
//! | 2 | 4 MB | | 8 | 256 MB |
//! | 3 | 8 MB | | 9 | 512 MB |
//! | 4 | 16 MB | | 10 | 1024 MB = 1 GB |
//! | 5 | 32 MB |
//!
//! [`SizeBucket`] is the CANONICAL source of the ladder AND the byte→bucket mapping
//! ([`SizeBucket::for_byte_len`]) so a consumer (dig-store's SIZE PROOF) never re-derives it and drifts.

use crate::{MerkleError, MerkleResult};

/// The largest bucket exponent: `k = 10` is `2^10 MiB = 1024 MB = 1 GB`, the ceiling a `.dig` store
/// size is quantised into. A byte length above `2^30` (1 GiB) has no bucket and is rejected.
const MAX_EXPONENT: u8 = 10;

/// A `.dig` store size quantised to a power-of-2 bucket: exponent `k ∈ 0..=10` ↔ `2^k MiB`
/// (1 MB..1 GB). See the module docs for the full ladder and the canonical unit (1 MB = 1 MiB).
///
/// A `SizeBucket` is always valid by construction — the only ways to make one
/// ([`from_exponent`](Self::from_exponent), [`for_byte_len`](Self::for_byte_len)) reject an
/// out-of-range value — so `exponent()` is guaranteed to be in `0..=10`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeBucket {
    /// The validated bucket exponent, always in `0..=10`.
    k: u8,
}

impl SizeBucket {
    /// Builds a bucket from its exponent `k`, rejecting `k > 10` (the ladder ceiling).
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::InvalidSize`] if `k > 10` — there is no bucket larger than 1 GB.
    pub fn from_exponent(k: u8) -> MerkleResult<Self> {
        if k > MAX_EXPONENT {
            return Err(MerkleError::InvalidSize(format!(
                "size-bucket exponent {k} exceeds the maximum {MAX_EXPONENT} (1 GB)"
            )));
        }
        Ok(Self { k })
    }

    /// The validated bucket exponent, always in `0..=10`.
    pub fn exponent(&self) -> u8 {
        self.k
    }

    /// The bucket size in megabytes (`2^k`, with 1 MB = 1 MiB): 1, 2, 4, … 1024.
    pub fn megabytes(&self) -> u32 {
        1u32 << self.k
    }

    /// The bucket size in bytes (`2^(k+20)`): the exact byte capacity of this bucket.
    pub fn byte_len(&self) -> u64 {
        1u64 << (u32::from(self.k) + 20)
    }

    /// The CANONICAL byte length → bucket mapping: the SMALLEST `k` whose bucket (`2^(k+20)` bytes)
    /// is at least `bytes`. A store of 0 or 1 byte → `k = 0`; exactly 1 MiB → `k = 0`; 1 MiB + 1 →
    /// `k = 1`; exactly 1 GiB → `k = 10`.
    ///
    /// This is the ergonomics dig-store's SIZE PROOF consumes so the ladder lives in ONE place.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::InvalidSize`] if `bytes > 2^30` (1 GiB) — beyond the ladder ceiling.
    pub fn for_byte_len(bytes: u64) -> MerkleResult<Self> {
        for k in 0..=MAX_EXPONENT {
            // 2^(k+20) is the byte capacity of bucket k; the first that fits `bytes` wins.
            if bytes <= (1u64 << (u32::from(k) + 20)) {
                return Ok(Self { k });
            }
        }
        Err(MerkleError::InvalidSize(format!(
            "size {bytes} bytes exceeds the maximum bucket 2^30 (1 GiB)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exponent→megabytes ladder is exactly the powers of two 1..1024, `k = 10` is 1 GB, and
    /// `byte_len()` is `2^(k+20)` for every bucket (SPEC §2).
    #[test]
    fn exponent_to_megabytes_ladder() {
        let expected_mb = [1u32, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
        for (k, &mb) in expected_mb.iter().enumerate() {
            let bucket = SizeBucket::from_exponent(k as u8).expect("k in range");
            assert_eq!(bucket.megabytes(), mb, "k={k} megabytes");
            assert_eq!(bucket.exponent(), k as u8, "k={k} exponent round-trips");
            assert_eq!(bucket.byte_len(), 1u64 << (k as u32 + 20), "k={k} byte_len");
        }
        // k=10 is a full gigabyte.
        assert_eq!(SizeBucket::from_exponent(10).unwrap().megabytes(), 1024);
        assert_eq!(SizeBucket::from_exponent(10).unwrap().byte_len(), 1 << 30);
    }

    /// `from_exponent` rejects any exponent above the 1 GB ceiling.
    #[test]
    fn from_exponent_rejects_out_of_range() {
        assert!(matches!(
            SizeBucket::from_exponent(11),
            Err(MerkleError::InvalidSize(_))
        ));
        assert!(matches!(
            SizeBucket::from_exponent(255),
            Err(MerkleError::InvalidSize(_))
        ));
    }

    /// The canonical byte→bucket boundaries: the smallest bucket that fits, with 0/1 byte → k0,
    /// exact powers landing in their own bucket, and anything above 1 GiB rejected.
    #[test]
    fn for_byte_len_boundaries() {
        const MIB: u64 = 1 << 20;
        const GIB: u64 = 1 << 30;

        let expect = |bytes: u64, k: u8| {
            assert_eq!(
                SizeBucket::for_byte_len(bytes)
                    .expect("in range")
                    .exponent(),
                k,
                "for_byte_len({bytes}) should be k={k}"
            );
        };

        expect(0, 0);
        expect(1, 0);
        expect(MIB, 0); // exactly 1 MiB fits bucket 0
        expect(MIB + 1, 1); // one byte over → next bucket
        expect(512 * MIB, 9); // 512 MiB == 2^29 fits bucket 9
        expect(512 * MIB + 1, 10);
        expect(GIB, 10); // exactly 1 GiB fits the top bucket
        assert!(
            matches!(
                SizeBucket::for_byte_len(GIB + 1),
                Err(MerkleError::InvalidSize(_))
            ),
            "one byte over 1 GiB has no bucket"
        );
    }
}
