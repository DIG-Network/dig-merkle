//! The DIG DataLayer metadata (SPEC §2) — the SDK's `DataStoreMetadata` shape with the exact-byte
//! `"b"` size REPLACED by a power-of-2 `size_bucket` (`"sz"`), plus the additive `program_hash` (`"p"`).
//!
//! [`DigDataStoreMetadata`] carries `root_hash` + optional `label`/`description`/`size_proof` (the SDK
//! keys `l`/`d`/`sp`), the additive `program_hash` (`"p"`), and the DIG store size as a coarse
//! [`SizeBucket`] (`"sz"`) INSTEAD of the SDK's exact `bytes`/`"b"` count:
//!
//! - **Byte-identity when empty (INV-4, SPEC §5.1).** dig-merkle NEVER emits `"b"`. It appends
//!   `("p" . program_hash)` then `("sz" . exponent)` LAST, each only when `Some`. With both `None` the
//!   bytes are IDENTICAL to the SDK's `DataStoreMetadata` with `bytes == None` (it emits `l`/`d`/`sp`
//!   only) — a plain store is byte-for-byte an ordinary DataLayer store.
//! - **SDK interop.** An SDK-typed reader decoding a DIG store ignores the unknown `"p"`/`"sz"` keys
//!   (same `_ => ()` tolerance), and dig-merkle decoding an SDK store parses `root`/`l`/`d`/`sp` and
//!   ignores the SDK's `"b"` (a foreign `"b"` is not a DIG size-proof) → `size_bucket == None`.
//!
//! ## `program_hash` + `size_bucket` semantics
//!
//! `program_hash` is the CLVM tree-hash (puzzle hash) of the program/puzzle associated with the store
//! or capsule. dig-merkle STORES and ECHOES it only — it never computes it (producers compute it via
//! `clvm_utils::tree_hash` / `ToTreeHash`). `size_bucket` is the store's size quantised to a
//! power-of-2 bucket (`k ∈ 0..=10` ↔ `2^k MiB`, 1 MB..1 GB) — the ONE size field, replacing the exact
//! byte count. dig-merkle round-trips both through the on-chain metadata unchanged.

use chia_protocol::Bytes32;
use chia_wallet_sdk::driver::MetadataWithRootHash;
use clvm_traits::{ClvmDecoder, ClvmEncoder, FromClvm, FromClvmError, Raw, ToClvm, ToClvmError};

use crate::size::SizeBucket;

/// The DIG DataLayer metadata: the SDK's `DataStoreMetadata` shape with the exact byte count
/// (`"b"`) REPLACED by a power-of-2 `size_bucket` (`"sz"`), plus the additive `program_hash` (`"p"`).
///
/// This is the metadata `dig-merkle` curries into a minted store. The DIG store size is expressed as
/// a coarse power-of-2 [`SizeBucket`] rather than an exact byte count — a clean replacement of the
/// SDK's `bytes`/`"b"` field (pre-release: there are NO on-chain DIG stores carrying `"b"`). With
/// `size_bucket == None && program_hash == None` it serializes byte-identically to the SDK's
/// `DataStoreMetadata` with `bytes == None` (it emits `l`/`d`/`sp` only, never `"b"`) — an SDK-typed
/// reader parses it and simply ignores the unknown `"sz"`/`"p"` keys (SPEC §8/§9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DigDataStoreMetadata {
    /// The anchored `.dig` merkle root — always the first metadata atom (SPEC §8).
    pub root_hash: Bytes32,

    /// An optional human-readable store label (CLVM alist key `"l"`).
    pub label: Option<String>,

    /// An optional human-readable store description (CLVM alist key `"d"`).
    pub description: Option<String>,

    /// An optional size-proof string (CLVM alist key `"sp"`).
    pub size_proof: Option<String>,

    /// The optional CLVM tree-hash of the program/puzzle this store is associated with (CLVM alist
    /// key `"p"`, appended after `"sp"`). dig-merkle stores and echoes this value; it never computes it.
    pub program_hash: Option<Bytes32>,

    /// The optional `.dig` store size as a power-of-2 bucket (CLVM alist key `"sz"`, appended LAST —
    /// after `"p"`). This REPLACES the SDK's exact-byte `"b"` field: dig-merkle never emits `"b"`, and
    /// the size is this coarse bucket instead. Encoded on-wire as the minimal 1-byte bucket exponent
    /// `k ∈ 0..=10` (empty atom for `k = 0`), so a `None` size emits no key at all. See [`SizeBucket`].
    pub size_bucket: Option<SizeBucket>,
}

/// Encodes `(root_hash . items)` where `items` pushes `l`/`d`/`sp` (mirroring the SDK, but NEVER the
/// exact-byte `"b"` key), then appends `("p" . program_hash)` and finally `("sz" . exponent)` LAST,
/// each only when `Some`.
///
/// Never emitting `"b"` and appending the DIG keys only when present is the byte-identity guarantee:
/// with `program_hash == None && size_bucket == None` the bytes equal the SDK's `DataStoreMetadata`
/// with `bytes == None` (SPEC §9).
impl<N, E: ClvmEncoder<Node = N>> ToClvm<E> for DigDataStoreMetadata {
    fn to_clvm(&self, encoder: &mut E) -> Result<N, ToClvmError> {
        let mut items: Vec<(&str, Raw<N>)> = Vec::new();

        if let Some(label) = &self.label {
            items.push(("l", Raw(label.to_clvm(encoder)?)));
        }

        if let Some(description) = &self.description {
            items.push(("d", Raw(description.to_clvm(encoder)?)));
        }

        if let Some(size_proof) = &self.size_proof {
            items.push(("sp", Raw(size_proof.to_clvm(encoder)?)));
        }

        // The DIG additions, appended after the SDK keys and each omitted when None → byte-identical
        // to the SDK's metadata for an ordinary store (SPEC §8/§9).
        if let Some(program_hash) = self.program_hash {
            items.push(("p", Raw(program_hash.to_clvm(encoder)?)));
        }

        // The size bucket is appended LAST, its exponent (0..=10) encoded as a minimal CLVM integer
        // (NC-8): the empty atom for k=0, a single byte for k=1..=10.
        if let Some(size_bucket) = self.size_bucket {
            items.push(("sz", Raw(size_bucket.exponent().to_clvm(encoder)?)));
        }

        (self.root_hash, items).to_clvm(encoder)
    }
}

/// Decodes `(root_hash . items)`, reading `l`/`d`/`sp`/`p`/`sz` and IGNORING any other key (the same
/// `_ => ()` tolerance as the SDK).
///
/// There is deliberately NO `"b"` arm. Every DIG capsule store ALWAYS carries `"sz"` (dig-merkle
/// writes it), so `"sz"` is the authoritative size. A foreign SDK DataLayer store's exact-byte `"b"`
/// is NOT a DIG size-proof — fabricating a bucket from it would misrepresent a non-capsule — so `"b"`
/// falls to the unknown-key tolerance and is ignored, and a `sz`-free store decodes honestly with
/// `size_bucket == None`. This does NOT break reading SDK stores: they still DECODE fine (root/l/d/sp
/// parse, `"b"` skipped). A `p`-free store likewise decodes with `program_hash == None` (SPEC §5.1).
impl<N, D: ClvmDecoder<Node = N>> FromClvm<D> for DigDataStoreMetadata {
    fn from_clvm(decoder: &D, node: N) -> Result<Self, FromClvmError> {
        let (root_hash, items) = <(Bytes32, Vec<(String, Raw<N>)>)>::from_clvm(decoder, node)?;
        let mut metadata = Self::root_hash_only(root_hash);

        for (key, Raw(ptr)) in items {
            match key.as_str() {
                "l" => metadata.label = Some(String::from_clvm(decoder, ptr)?),
                "d" => metadata.description = Some(String::from_clvm(decoder, ptr)?),
                "sp" => metadata.size_proof = Some(String::from_clvm(decoder, ptr)?),
                "p" => metadata.program_hash = Some(Bytes32::from_clvm(decoder, ptr)?),
                "sz" => metadata.size_bucket = Some(decode_size_bucket(decoder, ptr)?),
                _ => (),
            }
        }

        Ok(metadata)
    }
}

/// Decodes a `"sz"` value into a [`SizeBucket`], enforcing the CANONICAL minimal encoding (NC-8) and
/// failing CLOSED on anything else: the empty atom is `k = 0`, a single byte `1..=10` is that `k`,
/// and a non-minimal (leading-zero) atom, a byte `> 10`, or a multi-byte atom is REJECTED. This is
/// what makes the on-wire size a canonical form no producer can encode two ways.
fn decode_size_bucket<N, D: ClvmDecoder<Node = N>>(
    decoder: &D,
    ptr: N,
) -> Result<SizeBucket, FromClvmError> {
    const INVALID_SZ: &str = "invalid sz: non-minimal or out-of-range size exponent";

    let atom = decoder.decode_atom(&ptr)?;
    let exponent = match atom.as_ref() {
        [] => 0u8,
        [byte] if (1..=10).contains(byte) => *byte,
        _ => return Err(FromClvmError::Custom(INVALID_SZ.to_string())),
    };

    // The exponent is already validated to 0..=10 above, so this cannot fail; map defensively rather
    // than unwrap so an invariant change surfaces as an error, never a panic.
    SizeBucket::from_exponent(exponent).map_err(|error| FromClvmError::Custom(error.to_string()))
}

/// The SDK's generic `build_datastore`/`from_spend` require this bound to recover the anchored root.
/// `root_hash_only` clears every optional field — including `program_hash` and `size_bucket` — to `None`.
impl MetadataWithRootHash for DigDataStoreMetadata {
    fn root_hash(&self) -> Bytes32 {
        self.root_hash
    }

    fn root_hash_only(root_hash: Bytes32) -> Self {
        Self {
            root_hash,
            label: None,
            description: None,
            size_proof: None,
            program_hash: None,
            size_bucket: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::driver::{DataStoreMetadata, SpendContext};
    use chia_wallet_sdk::prelude::{Allocator, NodePtr};
    use clvm_traits::{FromClvm, ToClvm};

    /// Serializes a value to canonical CLVM bytes via a `chia_protocol::Program` round-trip, so two
    /// encodings can be compared byte-for-byte.
    fn clvm_bytes<T: ToClvm<Allocator>>(value: &T) -> Vec<u8> {
        let mut ctx = SpendContext::new();
        let node = value.to_clvm(&mut *ctx).expect("encode value");
        let program = chia_protocol::Program::from_clvm(&*ctx, node).expect("node to program");
        program.as_ref().to_vec()
    }

    /// The shared non-size fields used across the metadata tests (root, label, description, size_proof).
    fn sample_fields() -> (Bytes32, Option<String>, Option<String>, Option<String>) {
        (
            Bytes32::new([0xcd; 32]),
            Some("site".into()),
            Some("a description".into()),
            Some("size-proof".into()),
        )
    }

    /// The exact raw atom bytes of the `"sz"` value in an encoded metadata, for on-wire assertions.
    fn sz_atom_bytes(metadata: &DigDataStoreMetadata) -> Vec<u8> {
        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");
        let (_root, items) =
            <(Bytes32, Vec<(String, Raw<NodePtr>)>)>::from_clvm(&*ctx, node).expect("decode alist");
        let (_key, Raw(ptr)) = items
            .into_iter()
            .find(|(k, _)| k == "sz")
            .expect("sz key present");
        chia_protocol::Bytes::from_clvm(&*ctx, ptr)
            .expect("sz atom")
            .into_inner()
    }

    /// With `size_bucket == None && program_hash == None`, the CLVM bytes are IDENTICAL to the SDK's
    /// `DataStoreMetadata` with `bytes == None` — the clean-replacement byte-identity (SPEC §8/§9).
    /// dig-merkle emits NO `"b"` key, so the two encodings (l/d/sp) match exactly.
    #[test]
    fn metadata_none_size_bucket_is_byte_identical_to_sdk() {
        let (root, label, description, size_proof) = sample_fields();

        let dig = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            size_proof: size_proof.clone(),
            program_hash: None,
            size_bucket: None,
        };
        let sdk = DataStoreMetadata {
            root_hash: root,
            label,
            description,
            bytes: None,
            size_proof,
        };

        assert_eq!(
            clvm_bytes(&dig),
            clvm_bytes(&sdk),
            "a None size_bucket/program_hash store must serialize byte-identically to the SDK metadata"
        );
    }

    /// SDK-PARSE-COMPAT: a DIG store carrying a `size_bucket` (has `"sz"`, NO `"b"`) parses as a valid
    /// `chia_wallet_sdk::driver::DataStoreMetadata` — the SDK ignores the unknown `"sz"`, and an
    /// absent `"b"` decodes as `bytes == None`.
    #[test]
    fn sdk_reader_parses_size_bucket_store() {
        let (root, label, description, size_proof) = sample_fields();
        let dig = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            size_proof: size_proof.clone(),
            program_hash: None,
            size_bucket: Some(SizeBucket::from_exponent(5).unwrap()),
        };

        let mut ctx = SpendContext::new();
        let node = dig.to_clvm(&mut *ctx).expect("encode dig");
        let sdk = DataStoreMetadata::from_clvm(&*ctx, node).expect("sdk decodes, ignoring sz");

        assert_eq!(sdk.root_hash, root);
        assert_eq!(sdk.label, label);
        assert_eq!(sdk.description, description);
        assert_eq!(sdk.size_proof, size_proof);
        assert_eq!(sdk.bytes, None, "no b key so SDK reads bytes as None");
    }

    /// The on-wire `"sz"` atom is minimally encoded (NC-8): the empty atom for k=0, a single byte
    /// otherwise. Pins the exact bytes for k=0/5/10.
    #[test]
    fn sz_atom_is_minimally_encoded() {
        let with_k = |k: u8| DigDataStoreMetadata {
            root_hash: Bytes32::new([0x01; 32]),
            label: None,
            description: None,
            size_proof: None,
            program_hash: None,
            size_bucket: Some(SizeBucket::from_exponent(k).unwrap()),
        };
        assert_eq!(
            sz_atom_bytes(&with_k(0)),
            Vec::<u8>::new(),
            "k=0 empty atom"
        );
        assert_eq!(sz_atom_bytes(&with_k(5)), vec![0x05], "k=5 single byte");
        assert_eq!(sz_atom_bytes(&with_k(10)), vec![0x0a], "k=10 single byte");
    }

    /// A `Some(SizeBucket)` encodes then decodes unchanged, with every other field preserved.
    #[test]
    fn sz_roundtrips() {
        let (root, label, description, size_proof) = sample_fields();
        let metadata = DigDataStoreMetadata {
            root_hash: root,
            label,
            description,
            size_proof,
            program_hash: Some(Bytes32::new([0x11; 32])),
            size_bucket: Some(SizeBucket::from_exponent(7).unwrap()),
        };
        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");
        let decoded = DigDataStoreMetadata::from_clvm(&*ctx, node).expect("decode");
        assert_eq!(decoded, metadata, "size_bucket and all fields round-trip");
    }

    /// Fail-closed decode: a `"sz"` atom that is non-minimal (`[0x00]`, `[0x00,0x05]`) or out of range
    /// (`[0x0b]` == 11) is REJECTED. Also `SizeBucket::from_exponent(11)` errors.
    #[test]
    fn sz_decode_rejects_non_minimal_and_oversized() {
        let build_with_raw_sz = |raw: Vec<u8>| -> Result<DigDataStoreMetadata, FromClvmError> {
            let mut ctx = SpendContext::new();
            let root = Bytes32::new([0x01; 32]);
            let sz_node = chia_protocol::Bytes::new(raw).to_clvm(&mut *ctx).unwrap();
            let items: Vec<(&str, Raw<NodePtr>)> = vec![("sz", Raw(sz_node))];
            let node = (root, items).to_clvm(&mut *ctx).unwrap();
            DigDataStoreMetadata::from_clvm(&*ctx, node)
        };

        assert!(
            build_with_raw_sz(vec![0x00]).is_err(),
            "leading-zero rejected"
        );
        assert!(
            build_with_raw_sz(vec![0x00, 0x05]).is_err(),
            "multi-byte non-minimal rejected"
        );
        assert!(
            build_with_raw_sz(vec![0x0b]).is_err(),
            "exponent 11 rejected"
        );
        assert!(matches!(
            SizeBucket::from_exponent(11),
            Err(crate::MerkleError::InvalidSize(_))
        ));
    }

    /// With l/d/sp/p/sz all set, the decoded keys are exactly `["l","d","sp","p","sz"]` — `"sz"` is
    /// appended LAST, after `"p"`, and `"b"` is never present.
    #[test]
    fn sz_is_last_key() {
        let metadata = DigDataStoreMetadata {
            root_hash: Bytes32::new([0xab; 32]),
            label: Some("l".into()),
            description: Some("d".into()),
            size_proof: Some("sp".into()),
            program_hash: Some(Bytes32::new([0x01; 32])),
            size_bucket: Some(SizeBucket::from_exponent(3).unwrap()),
        };
        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");
        let (_root, items) =
            <(Bytes32, Vec<(String, Raw<NodePtr>)>)>::from_clvm(&*ctx, node).expect("decode");
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["l", "d", "sp", "p", "sz"],
            "sz is appended last, no b"
        );
    }

    /// §5.1 SDK-store readability + honest None: an SDK `DataStoreMetadata` carrying an exact-byte
    /// `"b"` DECODES successfully (root/l/d/sp parse, `"b"` ignored) with `size_bucket == None` — a
    /// foreign `"b"` is NOT a DIG size-proof, so the honest answer is no bucket. `bytes == None`
    /// likewise decodes to `size_bucket == None`.
    #[test]
    fn sdk_store_with_b_still_decodes() {
        let decode_sdk_bytes = |bytes: Option<u64>| -> DigDataStoreMetadata {
            let mut ctx = SpendContext::new();
            let sdk = DataStoreMetadata {
                root_hash: Bytes32::new([0x02; 32]),
                label: Some("sdk".into()),
                description: None,
                bytes,
                size_proof: Some("sp".into()),
            };
            let node = sdk.to_clvm(&mut *ctx).expect("encode sdk");
            DigDataStoreMetadata::from_clvm(&*ctx, node).expect("decode sdk store")
        };

        let with_b = decode_sdk_bytes(Some(4096));
        assert_eq!(with_b.root_hash, Bytes32::new([0x02; 32]));
        assert_eq!(
            with_b.label,
            Some("sdk".into()),
            "other fields still decode"
        );
        assert_eq!(with_b.size_proof, Some("sp".into()));
        assert_eq!(
            with_b.size_bucket, None,
            "a foreign b is ignored, not read as the size"
        );
        assert_eq!(decode_sdk_bytes(None).size_bucket, None);
    }
}
