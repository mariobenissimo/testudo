use crate::ark_std::One;
use crate::constraints::R1CSVerificationCircuit;
use crate::mipp::MippProof;
use crate::parameters::get_bls12377_fq_params;
use crate::parameters::params_to_base_field;
use crate::r1csproof::R1CSGens;
use crate::r1csproof::R1CSVerifierProof;
use crate::constraints::VerifierConfig;
use crate::{
  math::Math,
  poseidon_transcript::PoseidonTranscript,
  sparse_mlpoly::{SparsePolyEntry, SparsePolynomial},
  unipoly::UniPoly,
};
use ark_crypto_primitives::snark::SNARKGadget;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_groth16::constraints::Groth16VerifierGadget;
use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_crypto_primitives::sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_crypto_primitives::Error;
use ark_ec::pairing::Pairing;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_groth16::PreparedVerifyingKey;
use ark_groth16::constraints::PreparedVerifyingKeyVar;
use ark_poly_commit::multilinear_pc::data_structures::CommitmentG2;
use ark_poly_commit::multilinear_pc::data_structures::ProofG1;
use ark_poly_commit::multilinear_pc::{
  data_structures::{Commitment, CommitterKey, Proof, VerifierKey},
  MultilinearPC,
};
use ark_r1cs_std::groups::bls12::G1Var;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
  alloc::{AllocVar, AllocationMode},
  fields::fp::FpVar,
  prelude::{EqGadget, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::Compress;
use ark_snark::CircuitSpecificSetupSNARK;
use ark_snark::SNARK;
use digest::generic_array::typenum::True;
use rand::CryptoRng;
use rand::Rng;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::{borrow::Borrow, marker::PhantomData};
use ark_groth16;
type BasePrimeField<E> = <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

pub struct VerifierCircuit<E, IV>
where
  E: Pairing,
  IV: PairingVar<E, BasePrimeField<E>>,
{
  // pub inner_circuit: R1CSVerificationCircuit<E::ScalarField>, // circuito Mara

  // pub inner_proof: ark_groth16::Proof<E>, // PROOF DA VERIFICARE
  // pub inner_vk: PreparedVerifyingKey<E>,  // GENS.GC.VK

  pub r: (Vec<E::ScalarField>, Vec<E::ScalarField>),
  pub input:  Vec<E::ScalarField>,
  pub evals: (E::ScalarField,E::ScalarField,E::ScalarField),

  pub transcript: PoseidonTranscript<E::ScalarField>,
  pub gens: R1CSGens<E>,
  pub r1cs_proof: R1CSVerifierProof<E>, // SELF
  pub _iv: PhantomData<IV>,
}

impl<E, IV> VerifierCircuit<E, IV>
where
  E: Pairing,
  IV: PairingVar<E, BasePrimeField<E>>,
{
  pub fn new(
    //config: &VerifierConfig<E>,
    //mut rng: &mut R,
    r: (Vec<E::ScalarField>, Vec<E::ScalarField>),
    input: Vec<E::ScalarField>,
    evals: (E::ScalarField, E::ScalarField, E::ScalarField),
    transcript: PoseidonTranscript<E::ScalarField>,
    gens: R1CSGens<E>,
    r1cs_proof: R1CSVerifierProof<E>,
  ) -> Result<Self, SynthesisError> {
    // let inner_circuit =  crate::constraints::R1CSVerificationCircuit::new(config);
    // let (pk, vk) = Groth16::<E>::setup(inner_circuit.clone(), &mut rng).unwrap();
    // let proof = Groth16::<E>::prove(&pk, inner_circuit.clone(), &mut rng)?;
    // let pvk = Groth16::<E>::process_vk(&vk).unwrap();
    Ok(Self {
      // inner_circuit,
      // inner_proof: proof,
      // inner_vk: pvk,
      r: r,
      input: input.to_vec(),
      evals: evals,
      transcript: transcript,
      gens: gens,
      r1cs_proof,
      _iv: PhantomData,
    })
  }
}
impl<E,IV> ConstraintSynthesizer<BasePrimeField<E>> for VerifierCircuit<E,IV>
where
E: Pairing,
IV: PairingVar<E, BasePrimeField<E>>,

//IV::G1Var: CurveVar<E::G1, E::BaseField>,
// IV::G2Var: CurveVar<E::G2, E::BaseField>,
// IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
{
  fn generate_constraints(self, cs: ConstraintSystemRef<BasePrimeField<E>>) -> ark_relations::r1cs::Result<()> {

    // //STEP 1) ALLOCATE INNER_PROOF AS CIRCUIT VARIABLE

    let (rx, ry) = self.r;
    let (Ar, Br, Cr) = self.evals;
    let mut pubs = vec![self.r1cs_proof.initial_state];
    pubs.extend(self.input.clone());
    pubs.extend(rx.clone());
    pubs.extend(ry.clone());
    pubs.extend(vec![
      self.r1cs_proof.eval_vars_at_ry,
      Ar,
      Br,
      Cr,
      self.r1cs_proof.transcript_sat_state,
    ]);
    // self.transcript.new_from_state(self.r1cs_proof.transcript_sat_state);



    let proof_gadget = <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::ProofVar::new_witness(cs.clone(), || Ok(self.r1cs_proof.circuit_proof)).unwrap();
    let vk_gadget = <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::VerifyingKeyVar::new_witness(cs.clone(), || Ok(self.gens.gens_gc.vk.clone())).unwrap();

    let input_gadget= <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::InputVar::new_input(cs.clone(), || Ok(pubs)).unwrap();
    let ver = <Groth16VerifierGadget<E, IV> as SNARKGadget<E::ScalarField,BasePrimeField<E>,Groth16<E>>>::verify(&vk_gadget, &input_gadget, &proof_gadget).unwrap();
    println!("Verifier groth circuit");
    ver.enforce_equal(&Boolean::constant(true)).unwrap();
    Ok(())
  }
}