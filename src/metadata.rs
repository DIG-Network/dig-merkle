//! The DIG DataLayer metadata superset (SPEC §2) — the SDK's `DataStoreMetadata` plus `program_hash`.
//!
//! [`DigDataStoreMetadata`] carries every field the canonical Chia `DataStoreMetadata` does
//! (`root_hash` + optional `label`/`description`/`bytes`/`size_proof`) and ONE additive field:
//! `program_hash`, the CLVM tree-hash of the program/puzzle a capsule is associated with. It is a
//! strict, backwards-compatible superset:
//!
//! - **Additive on the wire (INV-4, SPEC §5.1).** The CLVM encoding mirrors the SDK's exactly and
//!   appends `("p" . program_hash)` to the metadata alist LAST, and ONLY when `program_hash` is
//!   `Some`. With `program_hash == None` the bytes are IDENTICAL to the SDK's `DataStoreMetadata` —
//!   so a store minted without a program hash is byte-for-byte an ordinary DataLayer store.
//! - **Old readers keep working.** An SDK-typed reader decoding a `program_hash`-bearing store
//!   ignores the unknown `"p"` key (same `_ => ()` tolerance as the SDK), and a new reader decoding
//!   an old (`p`-free) store yields `program_hash == None`. No section id is removed, renumbered, or
//!   repurposed.
//!
//! ## `program_hash` semantics
//!
//! `program_hash` is the CLVM tree-hash (puzzle hash) of the program/puzzle associated with the
//! store or capsule. dig-merkle STORES and ECHOES it only — it never computes it. A producer that
//! wants to anchor a program computes the hash itself (via `clvm_utils::tree_hash` / `ToTreeHash`)
//! and passes it in; dig-merkle round-trips it through the on-chain metadata unchanged.

use chia_protocol::Bytes32;
use chia_wallet_sdk::driver::MetadataWithRootHash;
use clvm_traits::{ClvmDecoder, ClvmEncoder, FromClvm, FromClvmError, Raw, ToClvm, ToClvmError};

use crate::size::SizeBucket;

/// The DIG DataLayer metadata: the canonical `DataStoreMetadata` fields plus an additive
/// `program_hash`.
///
/// This is the metadata `dig-merkle` curries into a minted store. It is a superset of the SDK's
/// `DataStoreMetadata`: with `program_hash == None` it serializes byte-identically, so it is a
/// drop-in that never breaks byte-compatibility with stores already on chain (SPEC §8/§9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DigDataStoreMetadata {
    /// The anchored `.dig` merkle root — always the first metadata atom (SPEC §8).
    pub root_hash: Bytes32,

    /// An optional human-readable store label (CLVM alist key `"l"`).
    pub label: Option<String>,

    /// An optional human-readable store description (CLVM alist key `"d"`).
    pub description: Option<String>,

    /// The optional store size in bytes (CLVM alist key `"b"`).
    pub bytes: Option<u64>,

    /// An optional size-proof string (CLVM alist key `"sp"`).
    pub size_proof: Option<String>,

    /// The optional CLVM tree-hash of the program/puzzle this store is associated with (CLVM alist
    /// key `"p"`, appended after `"sp"`). dig-merkle stores and echoes this value; it never computes it.
    pub program_hash: Option<Bytes32>,

    /// The optional `.dig` store size as a power-of-2 bucket (CLVM alist key `"sz"`, appended LAST —
    /// after `"p"`). Encoded on-wire as the minimal 1-byte bucket exponent `k ∈ 0..=10` (empty atom
    /// for `k = 0`), so a `None` size is byte-identical to a store without the key. See [`SizeBucket`].
    pub size_bucket: Option<SizeBucket>,
}

/// Encodes `(root_hash . items)` where `items` pushes `l`/`d`/`b`/`sp` (mirroring the SDK exactly),
/// then appends `("p" . program_hash)` LAST when `Some`.
///
/// Appending `"p"` after `"sp"` and only when present is the byte-identity guarantee: a `None`
/// `program_hash` yields the exact bytes the SDK's `DataStoreMetadata` produces (SPEC §9).
impl<N, E: ClvmEncoder<Node = N>> ToClvm<E> for DigDataStoreMetadata {
    fn to_clvm(&self, encoder: &mut E) -> Result<N, ToClvmError> {
        let mut items: Vec<(&str, Raw<N>)> = Vec::new();

        if let Some(label) = &self.label {
            items.push(("l", Raw(label.to_clvm(encoder)?)));
        }

        if let Some(description) = &self.description {
            items.push(("d", Raw(description.to_clvm(encoder)?)));
        }

        if let Some(bytes) = self.bytes {
            items.push(("b", Raw(bytes.to_clvm(encoder)?)));
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

/// Decodes `(root_hash . items)`, reading `l`/`d`/`b`/`sp`/`p` and IGNORING any unknown key (the
/// same `_ => ()` tolerance as the SDK), so old (`p`-free) stores decode with `program_hash == None`
/// and any future key is skipped rather than rejected (SPEC §5.1).
impl<N, D: ClvmDecoder<Node = N>> FromClvm<D> for DigDataStoreMetadata {
    fn from_clvm(decoder: &D, node: N) -> Result<Self, FromClvmError> {
        let (root_hash, items) = <(Bytes32, Vec<(String, Raw<N>)>)>::from_clvm(decoder, node)?;
        let mut metadata = Self::root_hash_only(root_hash);

        for (key, Raw(ptr)) in items {
            match key.as_str() {
                "l" => metadata.label = Some(String::from_clvm(decoder, ptr)?),
                "d" => metadata.description = Some(String::from_clvm(decoder, ptr)?),
                "b" => metadata.bytes = Some(u64::from_clvm(decoder, ptr)?),
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
            bytes: None,
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

    fn sample_fields() -> (
        Bytes32,
        Option<String>,
        Option<String>,
        Option<u64>,
        Option<String>,
    ) {
        (
            Bytes32::new([0xcd; 32]),
            Some("site".into()),
            Some("a description".into()),
            Some(4096),
            Some("size-proof".into()),
        )
    }

    /// With `program_hash == None` the CLVM bytes are IDENTICAL to the SDK's `DataStoreMetadata` for
    /// the same fields — the byte-compatibility guarantee (SPEC §8/§9, §5.1).
    #[test]
    fn metadata_none_program_hash_is_byte_identical_to_sdk() {
        let (root, label, description, bytes, size_proof) = sample_fields();

        let dig = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
            program_hash: None,
            size_bucket: None,
        };
        let sdk = DataStoreMetadata {
            root_hash: root,
            label,
            description,
            bytes,
            size_proof,
        };

        assert_eq!(
            clvm_bytes(&dig),
            clvm_bytes(&sdk),
            "None program_hash must serialize byte-identically to the SDK metadata"
        );
    }

    /// A `program_hash` set to `Some` round-trips through CLVM unchanged, and every other field is
    /// preserved.
    #[test]
    fn program_hash_roundtrips() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let program_hash = Some(Bytes32::new([0x7e; 32]));

        let metadata = DigDataStoreMetadata {
            root_hash: root,
            label,
            description,
            bytes,
            size_proof,
            program_hash,
            size_bucket: None,
        };

        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");
        let decoded = DigDataStoreMetadata::from_clvm(&*ctx, node).expect("decode");

        assert_eq!(decoded, metadata, "program_hash and all fields round-trip");
    }

    /// The `root_hash` is the first metadata atom and, when `program_hash` is `Some`, `"p"` is the
    /// LAST alist key (appended after `"sp"`) — the ordering the byte-identity contract pins.
    #[test]
    fn root_is_first_atom_and_p_is_last_alist_key() {
        let metadata = DigDataStoreMetadata {
            root_hash: Bytes32::new([0xab; 32]),
            label: Some("l".into()),
            description: None,
            bytes: None,
            size_proof: Some("sp".into()),
            program_hash: Some(Bytes32::new([0x01; 32])),
            size_bucket: None,
        };

        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");

        // The car is the root; the cdr is the ordered alist of (key, value) pairs.
        let (root, items) =
            <(Bytes32, Vec<(String, Raw<NodePtr>)>)>::from_clvm(&*ctx, node).expect("decode");
        assert_eq!(root, metadata.root_hash, "root is the first atom");

        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["l", "sp", "p"], "p is appended last, after sp");
    }

    /// An SDK-serialized (`p`-free) store decodes losslessly as `DigDataStoreMetadata` with
    /// `program_hash == None` and every other field preserved — old coins keep reading (SPEC §5.1).
    #[test]
    fn old_metadata_without_p_decodes_losslessly() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let sdk = DataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
        };

        let mut ctx = SpendContext::new();
        let node = sdk.to_clvm(&mut *ctx).expect("encode sdk");
        let decoded = DigDataStoreMetadata::from_clvm(&*ctx, node).expect("decode as dig");

        assert_eq!(decoded.root_hash, root);
        assert_eq!(decoded.label, label);
        assert_eq!(decoded.description, description);
        assert_eq!(decoded.bytes, bytes);
        assert_eq!(decoded.size_proof, size_proof);
        assert_eq!(
            decoded.program_hash, None,
            "an old store has no program_hash"
        );
        assert_eq!(decoded.size_bucket, None, "an old store has no size_bucket");
    }

    /// An SDK-typed reader decoding a `program_hash`-bearing store succeeds and simply DROPS the
    /// unknown `"p"` key — proving `"p"` never breaks legacy readers (SPEC §5.1/§8).
    #[test]
    fn sdk_reader_ignores_program_hash() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let dig = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
            program_hash: Some(Bytes32::new([0x9a; 32])),
            size_bucket: None,
        };

        let mut ctx = SpendContext::new();
        let node = dig.to_clvm(&mut *ctx).expect("encode dig");
        let sdk = DataStoreMetadata::from_clvm(&*ctx, node).expect("sdk decodes, ignoring p");

        assert_eq!(sdk.root_hash, root);
        assert_eq!(sdk.label, label);
        assert_eq!(sdk.description, description);
        assert_eq!(sdk.bytes, bytes);
        assert_eq!(sdk.size_proof, size_proof);
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

    /// With BOTH `size_bucket` and `program_hash` `None`, the CLVM bytes are IDENTICAL to the SDK's
    /// `DataStoreMetadata` — adding the `"sz"` field changes nothing when absent (SPEC §5.1).
    #[test]
    fn metadata_none_sz_is_byte_identical_to_sdk() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let dig = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
            program_hash: None,
            size_bucket: None,
        };
        let sdk = DataStoreMetadata {
            root_hash: root,
            label,
            description,
            bytes,
            size_proof,
        };
        assert_eq!(clvm_bytes(&dig), clvm_bytes(&sdk));
    }

    /// With `size_bucket == None` but `program_hash == Some`, the bytes equal the v0.2.0 p-bearing
    /// encoding — proving the new field is invisible on the wire when absent.
    #[test]
    fn sz_absent_leaves_p_encoding_unchanged() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let program_hash = Bytes32::new([0x7e; 32]);

        let with_sz_field = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
            program_hash: Some(program_hash),
            size_bucket: None,
        };
        // The v0.2.0 encoding is exactly the (root, alist) with l/d/b/sp/p and no sz — reconstruct it
        // and compare byte-for-byte.
        let mut ctx = SpendContext::new();
        let items: Vec<(&str, Raw<NodePtr>)> = vec![
            ("l", Raw(label.to_clvm(&mut *ctx).unwrap())),
            ("d", Raw(description.to_clvm(&mut *ctx).unwrap())),
            ("b", Raw(bytes.to_clvm(&mut *ctx).unwrap())),
            ("sp", Raw(size_proof.to_clvm(&mut *ctx).unwrap())),
            ("p", Raw(program_hash.to_clvm(&mut *ctx).unwrap())),
        ];
        let legacy_node = (root, items).to_clvm(&mut *ctx).unwrap();
        let legacy_bytes = chia_protocol::Program::from_clvm(&*ctx, legacy_node)
            .unwrap()
            .as_ref()
            .to_vec();

        assert_eq!(clvm_bytes(&with_sz_field), legacy_bytes);
    }

    /// A v0.2.0/SDK (sz-free) store decodes with `size_bucket == None`, all other fields preserved.
    #[test]
    fn old_metadata_without_sz_decodes_losslessly() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let sdk = DataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
        };
        let mut ctx = SpendContext::new();
        let node = sdk.to_clvm(&mut *ctx).expect("encode sdk");
        let decoded = DigDataStoreMetadata::from_clvm(&*ctx, node).expect("decode as dig");

        assert_eq!(decoded.size_bucket, None);
        assert_eq!(decoded.label, label);
        assert_eq!(decoded.size_proof, size_proof);
    }

    /// An sz-bearing store decoded by the SDK's `DataStoreMetadata` succeeds, ignoring `"sz"`.
    #[test]
    fn sdk_reader_ignores_sz() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let dig = DigDataStoreMetadata {
            root_hash: root,
            label: label.clone(),
            description: description.clone(),
            bytes,
            size_proof: size_proof.clone(),
            program_hash: None,
            size_bucket: Some(SizeBucket::from_exponent(5).unwrap()),
        };
        let mut ctx = SpendContext::new();
        let node = dig.to_clvm(&mut *ctx).expect("encode dig");
        let sdk = DataStoreMetadata::from_clvm(&*ctx, node).expect("sdk decodes, ignoring sz");

        assert_eq!(sdk.root_hash, root);
        assert_eq!(sdk.label, label);
        assert_eq!(sdk.size_proof, size_proof);
    }

    /// A `Some(SizeBucket)` encodes then decodes unchanged, with every other field preserved.
    #[test]
    fn sz_roundtrips() {
        let (root, label, description, bytes, size_proof) = sample_fields();
        let metadata = DigDataStoreMetadata {
            root_hash: root,
            label,
            description,
            bytes,
            size_proof,
            program_hash: Some(Bytes32::new([0x11; 32])),
            size_bucket: Some(SizeBucket::from_exponent(7).unwrap()),
        };
        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");
        let decoded = DigDataStoreMetadata::from_clvm(&*ctx, node).expect("decode");
        assert_eq!(decoded, metadata);
    }

    /// With l/sp/p/sz all set, `"sz"` is the LAST alist key — appended after `"p"`.
    #[test]
    fn sz_is_last_alist_key() {
        let metadata = DigDataStoreMetadata {
            root_hash: Bytes32::new([0xab; 32]),
            label: Some("l".into()),
            description: None,
            bytes: None,
            size_proof: Some("sp".into()),
            program_hash: Some(Bytes32::new([0x01; 32])),
            size_bucket: Some(SizeBucket::from_exponent(3).unwrap()),
        };
        let mut ctx = SpendContext::new();
        let node = metadata.to_clvm(&mut *ctx).expect("encode");
        let (_root, items) =
            <(Bytes32, Vec<(String, Raw<NodePtr>)>)>::from_clvm(&*ctx, node).expect("decode");
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["l", "sp", "p", "sz"], "sz is appended last");
    }

    /// The on-wire `"sz"` atom is minimally encoded (NC-8): empty atom for k=0, a single byte
    /// otherwise. Pins the exact bytes for k=0/5/10.
    #[test]
    fn sz_atom_is_minimally_encoded() {
        let with_k = |k: u8| DigDataStoreMetadata {
            root_hash: Bytes32::new([0x01; 32]),
            label: None,
            description: None,
            bytes: None,
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
}
