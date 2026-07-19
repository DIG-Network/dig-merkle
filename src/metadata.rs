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
    /// key `"p"`, appended LAST). dig-merkle stores and echoes this value; it never computes it.
    pub program_hash: Option<Bytes32>,
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

        // The one DIG addition: appended last, omitted when None → byte-identical to the SDK's
        // metadata for an ordinary store (SPEC §8/§9).
        if let Some(program_hash) = self.program_hash {
            items.push(("p", Raw(program_hash.to_clvm(encoder)?)));
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
                _ => (),
            }
        }

        Ok(metadata)
    }
}

/// The SDK's generic `build_datastore`/`from_spend` require this bound to recover the anchored root.
/// `root_hash_only` clears every optional field — including `program_hash` — to `None`.
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
}
