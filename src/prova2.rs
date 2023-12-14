use crate::parameters::params_to_base_field;
use crate::poseidon_transcript::PoseidonTranscript;
use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_crypto_primitives::sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use poseidon_parameters::PoseidonParameters;
use std::marker::PhantomData;
use ark_crypto_primitives::sponge::Absorb;
struct TestudoCommVerifier1<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
{
  g1: E::G1Affine,
  poseidon_params: PoseidonConfig<E::BaseField>,
  _iv: PhantomData<IV>,
}
impl<E, IV> ConstraintSynthesizer<<E as Pairing>::BaseField> for TestudoCommVerifier1<E, IV>
where
  E: Pairing,
  E::G1Affine: Absorb,
  IV: PairingVar<E>,
  IV::G1Var: CurveVar<E::G1, E::BaseField> + AbsorbGadget<E::BaseField>,
{
  fn generate_constraints(
    mut self,
    cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
  ) -> Result<(), SynthesisError> {

    // 
    let mut native_sponge = PoseidonSponge::<E::BaseField>::new(&self.poseidon_params);
    native_sponge.absorb(&self.g1);

    let hash2 : E::ScalarField = native_sponge.squeeze_field_elements(1).remove(0);
    
    println!("hash nativo con gadget absorb {:?}", hash2);

    let g1_var = IV::G1Var::new_input(cs.clone(), || Ok(self.g1))?;

    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_params);

    sponge.absorb(&g1_var);
    let hash = sponge.squeeze_nonnative_field_elements::<E::ScalarField>(1);

    println!("hash circuito con gadget absorb{:?}", hash.unwrap().0.value().unwrap());
    Ok(())
  }
}
struct TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
{
  g1: E::G1Affine,
  poseidon_params: PoseidonConfig<E::BaseField>,
  _iv: PhantomData<IV>,
}

impl<E, IV> ConstraintSynthesizer<<E as Pairing>::BaseField> for TestudoCommVerifier<E, IV>
where
  E: Pairing,
  E::G1Affine: Absorb,
  IV: PairingVar<E>,
  IV::G1Var: CurveVar<E::G1, E::BaseField>,
{
  fn generate_constraints(
    mut self,
    cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
  ) -> Result<(), SynthesisError> {

    let g1_var = IV::G1Var::new_input(cs.clone(), || Ok(self.g1))?;

    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_params);

    let mut buf3 = Vec::new();
    self.g1
      .serialize_with_mode(&mut buf3, Compress::Yes)
      .expect("serialization failed");

    let mut x_var_vec: Vec<UInt8<_>> = Vec::new();
    for x in buf3 {
      x_var_vec.push(UInt8::new_input(cs.clone(), || Ok(x))?);
    }
    sponge.absorb(&x_var_vec);
    let hash = sponge.squeeze_nonnative_field_elements::<E::ScalarField>(1);

    println!("hash {:?}", hash.unwrap().0.value().unwrap());
    // Fp256(BigInteger256([10577417867063568331, 11078737230088386683, 15679987742376005790, 1112270844950899640]))]
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parameters::get_bls12377_fq_params;
  use crate::parameters::get_bw6_fr_params;
  use crate::parameters::poseidon_params;
  use crate::transcript::Transcript;
  use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I};
  use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
  use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
  use ark_ec::bls12::Bls12;
  use ark_ec::pairing::Pairing;
  use ark_ff::{BigInteger, PrimeField};
  use ark_relations::r1cs::ConstraintSystem;
  use ark_std::test_rng;
  use ark_std::UniformRand;

  #[test]
  fn absorb_test() {
    let mut rng = test_rng();
    let cs = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();

    let params = get_bls12377_fq_params();
    let mut native_sponge = PoseidonTranscript::new(&params);
    let mut rng = ark_std::test_rng();
    //let point = ark_bls12_377::G1Affine::rand(&mut rng);
    let g1 = ark_bls12_377::g1::G1Affine::rand(&mut rng);


    native_sponge.append(b"U", &g1);

    let hash = native_sponge.challenge_scalar::<ark_bls12_377::Fr>(b"random_point");

    println!("hash nativo con buffer: {:?}", hash);

    let circuit: TestudoCommVerifier<I, IV> = TestudoCommVerifier {
      g1,
      poseidon_params: get_bls12377_fq_params(),
      _iv: PhantomData,
    };

    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    println!("Num constraint con buffer: {:?}",cs.num_constraints());

    let circuit2: TestudoCommVerifier1<I, IV> = TestudoCommVerifier1 {
      g1,
      poseidon_params: get_bls12377_fq_params(),
      _iv: PhantomData,
    };

    let cs2 = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();

    circuit2.generate_constraints(cs2.clone()).unwrap();
    assert!(cs2.is_satisfied().unwrap());

    println!("Num constraint con gadget: {:?}",cs2.num_constraints());
  }
}
