use crate::{
  group::{CompressedGroup, Fq, Fr},
  scalar,
  unipoly::UniPoly,
};

use super::scalar::Scalar;
use ark_bls12_377::{constraints::G1Var, G1Projective};
use ark_ff::{BigInteger, PrimeField};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::{
  alloc::AllocVar,
  fields::{fp::FpVar, FieldOpsBounds},
  R1CSVar,
};
use ark_relations::{
  ns,
  r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
// use ark_r1cs_std::prelude::*;
use ark_sponge::{
  absorb_gadget,
  constraints::{AbsorbGadget, CryptographicSpongeVar},
  poseidon::{constraints::PoseidonSpongeVar, PoseidonParameters, PoseidonSponge},
  CryptographicSponge, SpongeExt,
};

#[derive(Clone)]
/// TODO
pub struct PoseidonTranscript {
  sponge: PoseidonSponge<Fq>,
  params: PoseidonParameters<Fq>,
}

impl PoseidonTranscript {
  /// create a new transcript
  pub fn new(params: &PoseidonParameters<Fq>) -> Self {
    let sponge = PoseidonSponge::new(params);
    PoseidonTranscript {
      sponge: sponge,
      params: params.clone(),
    }
  }

  pub fn append_u64(&mut self, x: u64) {
    self.sponge.absorb(&x);
  }

  pub fn absorb_bytes(&mut self, x: &Vec<u8>) {
    self.sponge.absorb(x);
  }

  pub fn append_scalar(&mut self, scalar: &Scalar) {
    let scalar_fq = &Fq::from_repr(<Fq as PrimeField>::BigInt::from_bits_le(
      &scalar.into_repr().to_bits_le(),
    ))
    .unwrap();
    self.sponge.absorb(scalar_fq);
  }

  pub fn append_point(&mut self, point: &CompressedGroup) {
    self.sponge.absorb(&point.0);
  }

  pub fn append_scalar_vector(&mut self, scalars: &Vec<Scalar>) {
    for scalar in scalars.iter() {
      self.append_scalar(&scalar);
    }
  }

  pub fn challenge_scalar(&mut self) -> Scalar {
    let scalar = self.sponge.squeeze_field_elements::<Fr>(1).remove(0);
    self.sponge = PoseidonSponge::new(&self.params);
    self.append_scalar(&scalar);
    scalar
  }

  pub fn challenge_vector(&mut self, len: usize) -> Vec<Scalar> {
    self.sponge.squeeze_field_elements::<Fr>(len)
  }
}

pub trait AppendToPoseidon {
  fn append_to_poseidon(&self, transcript: &mut PoseidonTranscript);
}

impl AppendToPoseidon for CompressedGroup {
  fn append_to_poseidon(&self, transcript: &mut PoseidonTranscript) {
    transcript.append_point(self);
  }
}

pub struct PoseidonTranscripVar {
  pub cs: ConstraintSystemRef<Fq>,
  pub sponge: PoseidonSpongeVar<Fq>,
  pub params: PoseidonParameters<Fq>,
}

impl PoseidonTranscripVar {
  fn new(
    cs: ConstraintSystemRef<Fq>,
    params: &PoseidonParameters<Fq>,
    challenge: Option<Fr>,
  ) -> Self {
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), params);

    if let Some(c) = challenge {
      let c_fq = &Fq::from_repr(<Fq as PrimeField>::BigInt::from_bits_le(
        &c.into_repr().to_bits_le(),
      ))
      .unwrap();
      let c_fq_var =
        FpVar::<Fq>::new_witness(ns!(cs.clone(), "prev_state"), || Ok(c_fq.clone())).unwrap();
      sponge.absorb(&c_fq_var);
    }

    Self {
      cs: cs,
      sponge: sponge,
      params: params.clone(),
    }
  }

  fn append(&mut self, input: &impl AbsorbGadget<Fq>) -> Result<(), SynthesisError> {
    self.sponge.absorb(input)
  }

  fn append_vector(
    &mut self,
    input_vec: &Vec<impl AbsorbGadget<Fq>>,
  ) -> Result<(), SynthesisError> {
    for input in input_vec.iter() {
      self.append(input);
    }
    Ok(())
  }

  fn challenge(&mut self) -> Result<NonNativeFieldVar<Fr, Fq>, SynthesisError> {
    // This is not the right field!!
    let el = self
      .sponge
      .squeeze_nonnative_field_elements::<Fr>(1)
      .unwrap()
      .0
      .remove(0);
    Ok(el)
  }

  fn challenge_vector(
    &mut self,
    len: usize,
  ) -> Result<Vec<NonNativeFieldVar<Fr, Fq>>, SynthesisError> {
    let els = self.sponge.squeeze_nonnative_field_elements(len).unwrap().0;
    Ok(els)
  }
}
