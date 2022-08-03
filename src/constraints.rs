use std::{borrow::Borrow, fs};

use ark_bls12_377::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_nonnative_field::{NonNativeFieldMulResultVar, NonNativeFieldVar};
use ark_r1cs_std::{
  alloc::{AllocVar, AllocationMode},
  fields::fp::FpVar,
  prelude::{Boolean, EqGadget, FieldVar, UInt8},
  uint8, R1CSVar, ToBitsGadget,
};
use ark_relations::{
  ns,
  r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonParameters},
};

use super::scalar::Scalar;
use crate::{
  errors::ProofVerifyError,
  math::Math,
  sparse_mlpoly::{SparsePolyEntry, SparsePolynomial},
  transcript,
  unipoly::{CompressedUniPoly, UniPoly},
};

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
      let c_fq = Fq::from_repr(<Fq as PrimeField>::BigInt::from_bits_le(
        &c.into_repr().to_bits_le(),
      ))
      .unwrap();
      let c_fq_var = FpVar::new_witness(cs.clone(), || Ok(c_fq)).unwrap();
      sponge.absorb(&c_fq_var);
    }

    Self {
      cs: cs,
      sponge: sponge,
      params: params.clone(),
    }
  }

  fn append(&mut self, input: &FpVar<Fq>) -> Result<(), SynthesisError> {
    self.sponge.absorb(&input)
  }

  fn append_vector(&mut self, input_vec: &Vec<FpVar<Fq>>) -> Result<(), SynthesisError> {
    for input in input_vec.iter() {
      self.append(input)?;
    }
    Ok(())
  }

  // Nice to have: SpongeVar that absorbs a nonnative arithmetic
  // NNA library is archived
  fn checked_append(
    &mut self,
    input_nonnative_var: &NonNativeFieldVar<Fr, Fq>,
    input: &Fr,
  ) -> Result<(), SynthesisError> {
    let input_fq = Fq::from_repr(<Fq as PrimeField>::BigInt::from_bits_le(
      &input.into_repr().to_bits_le(),
    ))
    .unwrap();
    let input_fq_var = FpVar::new_witness(self.cs.clone(), || Ok(input_fq))?;
    self.append(&input_fq_var)?;

    let native_bits = input_fq_var.to_bits_le()?;
    let nonnative_bits = input_nonnative_var.to_bits_le()?;
    for (native, nonnative) in native_bits
      .iter()
      .zip(nonnative_bits.iter())
      .take(Fr::size_in_bits())
    {
      native.enforce_equal(nonnative)?;
    }

    Ok(())
  }

  fn checked_append_vector(
    &mut self,
    inputs_nonnative_vars: &Vec<NonNativeFieldVar<Fr, Fq>>,
    inputs: &Vec<Fr>,
  ) -> Result<(), SynthesisError> {
    for (i_nn, i) in inputs_nonnative_vars.iter().zip(inputs.iter()) {
      self.checked_append(i_nn, i)?;
    }
    Ok(())
  }

  fn challenge(&mut self) -> Result<NonNativeFieldVar<Fr, Fq>, SynthesisError> {
    let c_var = self
      .sponge
      .squeeze_nonnative_field_elements::<Fr>(1)
      .unwrap()
      .0
      .remove(0);

    Ok(c_var)
  }

  fn challenge_vector(
    &mut self,
    len: usize,
  ) -> Result<Vec<NonNativeFieldVar<Fr, Fq>>, SynthesisError> {
    let c_vars = self
      .sponge
      .squeeze_nonnative_field_elements::<Fr>(len)
      .unwrap()
      .0;

    Ok(c_vars)
  }
}

#[derive(Clone)]
pub struct UniPolyVar {
  pub coeffs: Vec<NonNativeFieldVar<Fr, Fq>>,
}

impl AllocVar<UniPoly, Fq> for UniPolyVar {
  fn new_variable<T: Borrow<UniPoly>>(
    cs: impl Into<Namespace<Fq>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|c| {
      let cs = cs.into();
      let cp: &UniPoly = c.borrow();
      let mut coeffs_var = Vec::new();
      for coeff in cp.coeffs.iter() {
        let coeff_var =
          NonNativeFieldVar::<Fr, Fq>::new_variable(cs.clone(), || Ok(coeff.clone()), mode)?;
        coeffs_var.push(coeff_var);
      }
      Ok(Self { coeffs: coeffs_var })
    })
  }
}

impl UniPolyVar {
  pub fn eval_at_zero(&self) -> NonNativeFieldVar<Fr, Fq> {
    self.coeffs[0].clone()
  }

  pub fn eval_at_one(&self) -> NonNativeFieldVar<Fr, Fq> {
    let mut res = self.coeffs[0].clone();
    for i in 1..self.coeffs.len() {
      res = &res + &self.coeffs[i];
    }
    res
  }

  // mul without reduce
  pub fn evaluate(&self, r: &NonNativeFieldVar<Fr, Fq>) -> NonNativeFieldVar<Fr, Fq> {
    let mut eval = NonNativeFieldMulResultVar::<Fr, Fq>::from(&self.coeffs[0]);
    let mut power = r.clone();

    for i in 1..self.coeffs.len() {
      eval += power.mul_without_reduce(&self.coeffs[i]).unwrap();
      power *= r;
    }
    eval.reduce().unwrap()
  }
}

#[derive(Clone)]
pub struct SumcheckVerificationCircuit {
  pub polys: Vec<UniPoly>,
}

impl SumcheckVerificationCircuit {
  fn verifiy_sumcheck(
    &self,
    poly_vars: &Vec<UniPolyVar>,
    claim_var: &NonNativeFieldVar<Fr, Fq>,
    transcript_var: &mut PoseidonTranscripVar,
  ) -> Result<(NonNativeFieldVar<Fr, Fq>, Vec<NonNativeFieldVar<Fr, Fq>>), SynthesisError> {
    let mut e_var = claim_var.clone();
    let mut r_vars: Vec<NonNativeFieldVar<Fr, Fq>> = Vec::new();

    for (poly_var, poly) in poly_vars.iter().zip(self.polys.iter()) {
      let res = poly_var.eval_at_one() + poly_var.eval_at_zero();
      res.enforce_equal(&e_var)?;
      transcript_var.checked_append_vector(&poly_var.coeffs, &poly.coeffs)?;
      let r_i_var = transcript_var.challenge()?;
      r_vars.push(r_i_var.clone());
      e_var = poly_var.evaluate(&r_i_var.clone());
    }

    Ok((e_var, r_vars))
  }
}

#[derive(Clone)]
pub struct SparsePolyEntryVar {
  idx: usize,
  val_var: NonNativeFieldVar<Fr, Fq>,
}

impl AllocVar<SparsePolyEntry, Fq> for SparsePolyEntryVar {
  fn new_variable<T: Borrow<SparsePolyEntry>>(
    cs: impl Into<Namespace<Fq>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|s| {
      let cs = cs.into();
      let spe: &SparsePolyEntry = s.borrow();
      let val_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(spe.val))?;
      Ok(Self {
        idx: spe.idx,
        val_var,
      })
    })
  }
}

#[derive(Clone)]
pub struct SparsePolynomialVar {
  num_vars: usize,
  Z_var: Vec<SparsePolyEntryVar>,
}

impl AllocVar<SparsePolynomial, Fq> for SparsePolynomialVar {
  fn new_variable<T: Borrow<SparsePolynomial>>(
    cs: impl Into<Namespace<Fq>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|s| {
      let cs = cs.into();
      let sp: &SparsePolynomial = s.borrow();
      let mut Z_var = Vec::new();
      for spe in sp.Z.iter() {
        let spe_var = SparsePolyEntryVar::new_variable(cs.clone(), || Ok(spe), mode)?;
        Z_var.push(spe_var);
      }
      Ok(Self {
        num_vars: sp.num_vars,
        Z_var,
      })
    })
  }
}

impl SparsePolynomialVar {
  fn compute_chi(a: &[bool], r_vars: &Vec<NonNativeFieldVar<Fr, Fq>>) -> NonNativeFieldVar<Fr, Fq> {
    let mut chi_i_var = NonNativeFieldVar::<Fr, Fq>::one();
    let one = NonNativeFieldVar::<Fr, Fq>::one();
    for (i, r_var) in r_vars.iter().enumerate() {
      if a[i] {
        chi_i_var *= r_var;
      } else {
        chi_i_var *= &one - r_var;
      }
    }
    chi_i_var
  }

  pub fn evaluate(&self, r_var: &Vec<NonNativeFieldVar<Fr, Fq>>) -> NonNativeFieldVar<Fr, Fq> {
    let mut sum = NonNativeFieldMulResultVar::<Fr, Fq>::zero();
    for spe_var in self.Z_var.iter() {
      // potential problem
      let bits = &spe_var.idx.get_bits(r_var.len());
      sum += SparsePolynomialVar::compute_chi(&bits, r_var)
        .mul_without_reduce(&spe_var.val_var)
        .unwrap();
    }
    sum.reduce().unwrap()
  }
}

#[derive(Clone)]
pub struct R1CSVerificationCircuit {
  pub num_vars: usize,
  pub num_cons: usize,
  pub input: Vec<Fr>,
  pub input_as_sparse_poly: SparsePolynomial,
  pub evals: (Fr, Fr, Fr),
  pub params: PoseidonParameters<Fq>,
  pub prev_challenge: Fr,
  pub claims_phase2: (Scalar, Scalar, Scalar, Scalar),
  pub eval_vars_at_ry: Fr,
  pub sc_phase1: SumcheckVerificationCircuit,
  pub sc_phase2: SumcheckVerificationCircuit,
}

impl ConstraintSynthesizer<Fq> for R1CSVerificationCircuit {
  fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> ark_relations::r1cs::Result<()> {
    let mut transcript_var =
      PoseidonTranscripVar::new(cs.clone(), &self.params, Some(self.prev_challenge));

    let poly_sc1_vars = self
      .sc_phase1
      .polys
      .iter()
      .map(|p| UniPolyVar::new_variable(cs.clone(), || Ok(p), AllocationMode::Witness).unwrap())
      .collect::<Vec<UniPolyVar>>();

    let poly_sc2_vars = self
      .sc_phase2
      .polys
      .iter()
      .map(|p| UniPolyVar::new_variable(cs.clone(), || Ok(p), AllocationMode::Witness).unwrap())
      .collect::<Vec<UniPolyVar>>();

    let input_vars = self
      .input
      .iter()
      .map(|i| NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(i)).unwrap())
      .collect::<Vec<NonNativeFieldVar<Fr, Fq>>>();

    transcript_var.checked_append_vector(&input_vars, &self.input)?;

    let num_rounds_x = self.num_cons.ilog2() as usize;
    let num_rounds_y = (2 * self.num_vars).ilog2() as usize;

    let tau_vars = transcript_var.challenge_vector(num_rounds_x)?;

    let claim_phase1_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(Fr::zero()))?;

    let (claim_post_phase1_var, rx_var) =
      self
        .sc_phase1
        .verifiy_sumcheck(&poly_sc1_vars, &claim_phase1_var, &mut transcript_var)?;

    let (Az_claim, Bz_claim, Cz_claim, prod_Az_Bz_claims) = &self.claims_phase2;

    let Az_claim_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(Az_claim))?;
    let Bz_claim_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(Bz_claim))?;
    let Cz_claim_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(Cz_claim))?;
    let prod_Az_Bz_claim_var =
      NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(prod_Az_Bz_claims))?;
    let one = NonNativeFieldVar::<Fr, Fq>::one();
    let prod_vars: Vec<NonNativeFieldVar<Fr, Fq>> = (0..rx_var.len())
      .map(|i| {
        (&rx_var[i].mul_without_reduce(&tau_vars[i]).unwrap()
          + (&one - &rx_var[i])
            .mul_without_reduce(&(&one - &tau_vars[i]))
            .unwrap())
        .reduce()
        .unwrap()
      })
      .collect();
    let mut taus_bound_rx_var = NonNativeFieldVar::<Fr, Fq>::one();

    for p_var in prod_vars.iter() {
      taus_bound_rx_var *= p_var;
    }

    let expected_claim_post_phase1_var =
      (&prod_Az_Bz_claim_var - &Cz_claim_var) * &taus_bound_rx_var;

    claim_post_phase1_var.enforce_equal(&expected_claim_post_phase1_var)?;

    let r_A_var = transcript_var.challenge()?;
    let r_B_var = transcript_var.challenge()?;
    let r_C_var = transcript_var.challenge()?;

    let claim_phase2_var = &r_A_var.mul_without_reduce(&Az_claim_var).unwrap()
      + &r_B_var.mul_without_reduce(&Bz_claim_var).unwrap()
      + &r_C_var.mul_without_reduce(&Cz_claim_var).unwrap();

    let (claim_post_phase2_var, ry_var) = self.sc_phase2.verifiy_sumcheck(
      &poly_sc2_vars,
      &claim_phase2_var.reduce().unwrap(),
      &mut transcript_var,
    )?;

    let input_as_sparse_poly_var = SparsePolynomialVar::new_variable(
      cs.clone(),
      || Ok(&self.input_as_sparse_poly),
      AllocationMode::Witness,
    )?;

    let poly_input_eval_var = input_as_sparse_poly_var.evaluate(&ry_var[1..].to_vec());

    let eval_vars_at_ry_var =
      NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(&self.eval_vars_at_ry))?;

    let eval_Z_at_ry_var = (NonNativeFieldVar::<Fr, Fq>::one() - &ry_var[0])
      .mul_without_reduce(&eval_vars_at_ry_var)
      .unwrap()
      + &ry_var[0].mul_without_reduce(&poly_input_eval_var).unwrap();

    let (eval_A_r, eval_B_r, eval_C_r) = self.evals;

    let eval_A_r_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(eval_A_r))?;
    let eval_B_r_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(eval_B_r))?;
    let eval_C_r_var = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(eval_C_r))?;

    let scalar_var = &r_A_var.mul_without_reduce(&eval_A_r_var).unwrap()
      + &r_B_var.mul_without_reduce(&eval_B_r_var).unwrap()
      + &r_C_var.mul_without_reduce(&eval_C_r_var).unwrap();

    let expected_claim_post_phase2_var =
      eval_Z_at_ry_var.reduce().unwrap() * scalar_var.reduce().unwrap();

    claim_post_phase2_var.enforce_equal(&expected_claim_post_phase2_var)?;

    Ok(())
  }
}
