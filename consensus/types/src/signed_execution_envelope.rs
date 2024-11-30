use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

// in all likelihood, this will be superstructed so might as well start early eh?
#[superstruct(
    variants(EIP7732, NextFork),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec")
    ),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(
    Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct SignedExecutionEnvelope<E: EthSpec> {
    #[superstruct(only(EIP7732), partial_getter(rename = "message_eip7732"))]
    pub message: ExecutionEnvelopeEIP7732<E>,
    #[superstruct(only(NextFork), partial_getter(rename = "message_next_fork"))]
    pub message: crate::execution_envelope::ExecutionEnvelopeNextFork<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionEnvelope<E> {
    pub fn message(&self) -> ExecutionEnvelopeRef<E> {
        match self {
            SignedExecutionEnvelope::EIP7732(ref signed) => {
                ExecutionEnvelopeRef::EIP7732(&signed.message)
            }
            SignedExecutionEnvelope::NextFork(ref signed) => {
                ExecutionEnvelopeRef::NextFork(&signed.message)
            }
        }
    }

    /// Verify `self.signature`.
    ///
    /// The `parent_state` is the post-state of the beacon block with
    /// block_root = self.message.beacon_block_root
    pub fn verify_signature(
        &self,
        parent_state: &BeaconState<E>,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<bool, BeaconStateError> {
        let domain = spec.get_domain(
            parent_state.current_epoch(),
            Domain::BeaconBuilder,
            &parent_state.fork(),
            genesis_validators_root,
        );
        let pubkey = parent_state
            .validators()
            .get(self.message().builder_index() as usize)
            .and_then(|v| {
                let pk: Option<PublicKey> = v.pubkey.decompress().ok();
                pk
            })
            .ok_or_else(|| {
                BeaconStateError::UnknownValidator(self.message().builder_index() as usize)
            })?;
        let message = self.message().signing_root(domain);

        Ok(self.signature().verify(&pubkey, message))
    }
}
