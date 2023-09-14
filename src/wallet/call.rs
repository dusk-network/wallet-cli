use crate::wallet::Gas;
use crate::wallet::Prover;
use dusk_bls12_381_sign::PublicKey;
use dusk_bls12_381_sign::SecretKey;
use dusk_bls12_381_sign::Signature;
use dusk_bytes::Serializable;
use dusk_pki::SecretSpendKey;
use dusk_pki::StealthAddress;
use dusk_pki::{Ownable, PublicSpendKey, SecretKey as SchnorrKey};

use dusk_plonk::prelude::BlsScalar;
use phoenix_core::transaction::{
    stct_signature_message, Allow, Stake, Unstake, Withdraw,
};
use phoenix_core::Fee;

use dusk_plonk::prelude::JubJubScalar;
use dusk_schnorr::Signature as SchnorrSignature;
use phoenix_core::{Crossover, Note};
use rand::rngs::StdRng;
use rusk_abi::ContractId;

pub struct CallBuilder {
    blinder: JubJubScalar,
    fee: Fee,
    crossover: Crossover,
    stct_signature: SchnorrSignature,
    wtct_signature: (Note, JubJubScalar),
    value: u64,
    proof: Option<Vec<u8>>,
    address: BlsScalar,
    sender: PublicSpendKey,
}

impl CallBuilder {
    pub fn new(
        rng: &mut StdRng,
        refund: PublicSpendKey,
        value: u64,
        contract_id: ContractId,
        sender: SecretSpendKey,
    ) -> Self {
        let blinder = JubJubScalar::random(rng);
        let note = Note::obfuscated(rng, &refund, value, blinder);
        let (fee, crossover) = note
            .try_into()
            .expect("Obfuscated notes should always yield crossovers");

        let address = rusk_abi::contract_to_scalar(&contract_id);

        let contract_id = rusk_abi::contract_to_scalar(&contract_id);

        let stct_message =
            stct_signature_message(&crossover, value, contract_id);
        let stct_message = dusk_poseidon::sponge::hash(&stct_message);

        let sk_r = *sender.sk_r(fee.stealth_address()).as_ref();
        let secret = SchnorrKey::from(sk_r);

        let stct_signature = SchnorrSignature::new(&secret, rng, stct_message);

        let unstake_note =
            Note::transparent(rng, &sender.public_spend_key(), value);
        let unstake_blinder = unstake_note
            .blinding_factor(None)
            .expect("Note is transparent so blinding factor is unencrypted");

        Self {
            blinder,
            fee,
            crossover,
            stct_signature,
            value,
            wtct_signature: (unstake_note, unstake_blinder),
            address,
            proof: None,
            sender: sender.public_spend_key(),
        }
    }

    pub fn gas(mut self, gas: &Gas) -> Self {
        self.fee.gas_limit = gas.limit;
        self.fee.gas_price = gas.price;

        self
    }

    pub async fn prove_stct(mut self, prover: &Prover) -> anyhow::Result<Self> {
        let spend_proof = prover
            .request_stct_proof(
                &self.fee,
                &self.crossover,
                self.value,
                self.blinder,
                self.address,
                self.stct_signature,
            )
            .await?
            .to_bytes()
            .to_vec();

        self.proof = Some(spend_proof);

        Ok(self)
    }

    pub async fn prove_wfct(mut self, prover: &Prover) -> anyhow::Result<Self> {
        let (unstake_note, unstake_blinder) = self.wtct_signature;
        let unstake_note_value = unstake_note.value_commitment().into();

        let spend_proof = prover
            .request_wfct_proof(unstake_note_value, self.value, unstake_blinder)
            .await?
            .to_bytes()
            .to_vec();

        self.proof = Some(spend_proof);

        Ok(self)
    }

    pub fn get_stake(
        self,
        sk: SecretKey,
        pk: PublicKey,
        counter: u64,
    ) -> Stake {
        let signature = stake_sign(&sk, &pk, counter, self.value);

        let spend_proof = self.proof.expect("Proof could not be computed");

        Stake {
            public_key: pk,
            signature,
            value: self.value,
            proof: spend_proof,
        }
    }

    pub fn get_stake_allow(
        self,
        sk: SecretKey,
        pk: PublicKey,
        counter: u64,
        staker: &PublicKey,
    ) -> Allow {
        let signature = allow_sign(&sk, &pk, counter, staker);

        Allow {
            public_key: *staker,
            signature,
            owner: pk,
        }
    }

    pub fn get_unstake(
        self,
        sk: SecretKey,
        pk: PublicKey,
        counter: u64,
    ) -> Unstake {
        let (unstake_note, _) = self.wtct_signature;

        let signature = unstake_sign(&sk, &pk, counter, unstake_note);

        let unstake_proof = self.proof.expect("Proof could not be computed");

        Unstake {
            public_key: pk,
            signature,
            note: unstake_note,
            proof: unstake_proof,
        }
    }

    pub fn get_withdraw(
        self,
        rng: &mut StdRng,
        pk: PublicKey,
        sk: SecretKey,
        counter: u64,
    ) -> Withdraw {
        let sender_psk = self.sender;

        let withdraw_r = JubJubScalar::random(rng);
        let address = sender_psk.gen_stealth_address(&withdraw_r);
        let nonce = BlsScalar::random(rng);

        let signature = withdraw_sign(&sk, &pk, counter, address, nonce);

        Withdraw {
            public_key: pk,
            signature,
            address,
            nonce,
        }
    }
}

/// Creates a signature compatible with what the stake contract expects for a
/// stake transaction.
///
/// The counter is the number of transactions that have been sent to the
/// transfer contract by a given key, and is reported in `StakeInfo`.
fn stake_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    counter: u64,
    value: u64,
) -> Signature {
    let mut msg = Vec::with_capacity(u64::SIZE + u64::SIZE);

    msg.extend(counter.to_bytes());
    msg.extend(value.to_bytes());

    sk.sign(pk, &msg)
}

/// Creates a signature compatible with what the stake contract expects for a
/// unstake transaction.
///
/// The counter is the number of transactions that have been sent to the
/// transfer contract by a given key, and is reported in `StakeInfo`.
fn unstake_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    counter: u64,
    note: Note,
) -> Signature {
    let mut msg = Vec::with_capacity(u64::SIZE + Note::SIZE);

    msg.extend(counter.to_bytes());
    msg.extend(note.to_bytes());

    sk.sign(pk, &msg)
}

/// Creates a signature compatible with what the stake contract expects for a
/// withdraw transaction.
///
/// The counter is the number of transactions that have been sent to the
/// transfer contract by a given key, and is reported in `StakeInfo`.
fn withdraw_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    counter: u64,
    address: StealthAddress,
    nonce: BlsScalar,
) -> Signature {
    let mut msg =
        Vec::with_capacity(u64::SIZE + StealthAddress::SIZE + BlsScalar::SIZE);

    msg.extend(counter.to_bytes());
    msg.extend(address.to_bytes());
    msg.extend(nonce.to_bytes());

    sk.sign(pk, &msg)
}

/// Creates a signature compatible with what the stake contract expects for a
/// ADD_ALLOWLIST transaction.
///
/// The counter is the number of transactions that have been sent to the
/// transfer contract by a given key, and is reported in `StakeInfo`.
fn allow_sign(
    sk: &SecretKey,
    pk: &PublicKey,
    counter: u64,
    staker: &PublicKey,
) -> Signature {
    let mut msg = Vec::with_capacity(u64::SIZE + PublicKey::SIZE);

    msg.extend(counter.to_bytes());
    msg.extend(staker.to_bytes());

    sk.sign(pk, &msg)
}
