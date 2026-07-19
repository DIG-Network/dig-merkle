//! The `dig-merkle` error taxonomy (SPEC §6).
//!
//! Every fallible operation in this crate returns [`MerkleError`]. It wraps the underlying
//! chia-wallet-sdk driver/signer error (the byte-source-of-truth for puzzle construction, INV-4)
//! and adds the DataLayer-domain failure modes this crate raises directly — parse failures,
//! fail-closed hydration guards, and delegation-permission checks.

use chia_wallet_sdk::driver::DriverError;
use thiserror::Error;

/// The result type returned by every fallible `dig-merkle` operation.
pub type MerkleResult<T> = Result<T, MerkleError>;

/// Everything that can go wrong while building or parsing a DataLayer-coin spend.
///
/// The variants split into two families: errors *delegated* to the chia-wallet-sdk driver/signer
/// (wrapped verbatim so the underlying cause is never lost), and DataLayer-domain errors this crate
/// raises itself (parse/hydration/permission guards, all fail-closed per SPEC §5).
#[derive(Debug, Error)]
pub enum MerkleError {
    /// A chia-wallet-sdk driver operation failed (puzzle currying, spend construction, CLVM
    /// evaluation). The wrapped [`DriverError`] carries the precise cause.
    #[error("chia driver error: {0}")]
    Driver(#[from] DriverError),

    /// The signing calculator failed to derive the required signatures from the coin spends
    /// (invalid puzzle/solution, an infinity public key in an `AGG_SIG` condition). The message is
    /// the underlying signer error rendered as a string, so this crate does not leak the signer's
    /// error type into its public surface.
    #[error("signature calculation failed: {0}")]
    Signer(String),

    /// A coin/puzzle/solution could not be parsed as the expected shape.
    #[error("failed to parse DataLayer coin: {0}")]
    Parse(String),

    /// The supplied puzzle parsed successfully but is not a DataLayer (DataStore) singleton.
    #[error("coin is not a DataLayer singleton")]
    NotDataStore,

    /// Hydration could not establish the lineage proof required to spend the DataLayer coin
    /// (SPEC §5, fail-closed).
    #[error("missing lineage proof for DataLayer coin")]
    MissingLineage,

    /// A parsed DataLayer coin was missing the owner/delegation hint memo required to recreate its
    /// child (SPEC §5, fail-closed).
    #[error("missing hint on DataLayer coin")]
    MissingHint,

    /// A delegated-puzzle operation was attempted without the permission it requires (e.g. a writer
    /// attempting an admin-only change). The string states the specific violation.
    #[error("delegation permission denied: {0}")]
    Permission(String),

    /// A chain-level precondition was violated (e.g. a supplied coin does not match the expected
    /// launcher). The string states the specific violation.
    #[error("chain precondition failed: {0}")]
    Chain(String),

    /// The injected [`dig_chainsource_interface::ChainSource`] could NOT reliably answer a read
    /// (transport/timeout/malformed/unsupported). Distinct from a genuine absence (`Ok(None)`):
    /// the chain state is UNKNOWN, so every owner-attribution caller MUST fail closed and never
    /// treat this as "no owner" (NC-9, SPEC §3.7). The string is the source's own error rendered
    /// verbatim, so this crate does not leak the source's error type into its public surface.
    #[error("chain source error: {0}")]
    Source(String),

    /// An operation was asked to spend an empty coin set (SPEC §6).
    #[error("no coins supplied to spend")]
    EmptyCoins,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_descriptive() {
        assert_eq!(
            MerkleError::NotDataStore.to_string(),
            "coin is not a DataLayer singleton"
        );
        assert_eq!(
            MerkleError::MissingLineage.to_string(),
            "missing lineage proof for DataLayer coin"
        );
        assert_eq!(
            MerkleError::MissingHint.to_string(),
            "missing hint on DataLayer coin"
        );
        assert_eq!(
            MerkleError::Parse("bad".into()).to_string(),
            "failed to parse DataLayer coin: bad"
        );
        assert_eq!(
            MerkleError::Permission("writer cannot admin".into()).to_string(),
            "delegation permission denied: writer cannot admin"
        );
        assert_eq!(
            MerkleError::Signer("boom".into()).to_string(),
            "signature calculation failed: boom"
        );
        assert_eq!(
            MerkleError::Chain("wrong launcher".into()).to_string(),
            "chain precondition failed: wrong launcher"
        );
        assert_eq!(
            MerkleError::EmptyCoins.to_string(),
            "no coins supplied to spend"
        );
    }

    #[test]
    fn wraps_driver_errors_via_from() {
        let driver = DriverError::InvalidSingletonStruct;
        let err: MerkleError = driver.into();
        assert!(matches!(err, MerkleError::Driver(_)));
        assert!(err.to_string().starts_with("chia driver error:"));
    }
}
