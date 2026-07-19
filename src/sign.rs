//! The signing boundary (SPEC §4) — the load-bearing custody guarantee of `dig-merkle`.
//!
//! dig-merkle holds no key and signs nothing (INV-2). Instead it tells a caller EXACTLY what must
//! be signed: [`required_signatures`] runs each coin spend's puzzle to collect its `AGG_SIG_*`
//! conditions and returns the precise [`RequiredSignature`] set — public key, raw message, appended
//! coin/domain info — for the caller's signer to fulfil. The computation is pure and key-free: it
//! never needs (and this crate never accepts) a secret key.

use chia_wallet_sdk::prelude::{Allocator, CoinSpend};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};

use crate::MerkleError;

/// Computes the exact signatures required to make a set of DataLayer coin spends valid.
///
/// This is the bridge between dig-merkle's unsigned output and a caller's signer. Pass the
/// [`crate::MerkleCoinSpend::coin_spends`] and the network's [`AggSigConstants`] (derived from the
/// `AGG_SIG_ME` additional data, e.g. `AggSigConstants::from(&*MAINNET_CONSTANTS)`); each returned
/// [`RequiredSignature`] names a public key and the message to sign under it. Aggregating the
/// caller's signatures over all of them yields a valid `SpendBundle`.
///
/// The function allocates a private CLVM [`Allocator`] per call and never mutates its inputs, so it
/// is safe to call from any context. It performs NO network I/O and requires NO secret material.
///
/// # Errors
///
/// Returns [`MerkleError::Signer`] if a puzzle fails to evaluate or an `AGG_SIG` condition carries
/// an infinity public key.
pub fn required_signatures(
    coin_spends: &[CoinSpend],
    constants: &AggSigConstants,
) -> Result<Vec<RequiredSignature>, MerkleError> {
    let mut allocator = Allocator::new();
    RequiredSignature::from_coin_spends(&mut allocator, coin_spends, constants)
        .map_err(|error| MerkleError::Signer(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use chia_wallet_sdk::test::Simulator;
    use chia_wallet_sdk::types::Conditions;

    /// A standard single-key coin spend requires exactly one `AGG_SIG_ME` over the spender's
    /// synthetic key. `required_signatures` must surface precisely that.
    #[test]
    fn reports_the_single_agg_sig_me_of_a_standard_spend() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);

        let mut ctx = SpendContext::new();
        let memos = ctx.hint(alice.puzzle_hash).expect("hint allocates");
        alice_p2
            .spend(
                &mut ctx,
                alice.coin,
                Conditions::new().create_coin(alice.puzzle_hash, 1, memos),
            )
            .expect("standard spend should build");
        let coin_spends = ctx.take();
        assert_eq!(coin_spends.len(), 1);

        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = required_signatures(&coin_spends, &constants).expect("signatures compute");

        assert_eq!(required.len(), 1, "one AGG_SIG_ME expected");
        match &required[0] {
            RequiredSignature::Bls(bls) => {
                assert_eq!(bls.public_key, alice.pk, "signed under the spender key");
                assert!(
                    !bls.message().is_empty(),
                    "a non-empty message must be signed"
                );
            }
            RequiredSignature::Secp(_) => panic!("standard spend uses a BLS key, not secp"),
        }
    }

    /// With no coin spends there is nothing to sign — the boundary returns an empty set, never an
    /// error.
    #[test]
    fn no_coin_spends_require_no_signatures() {
        let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
        let required = required_signatures(&[], &constants).expect("empty input is valid");
        assert!(required.is_empty());
    }
}
