use crate::ark_std::Zero;
use crate::{
  math::Math,
  sparse_mlpoly::{SparsePolyEntry, SparsePolynomial},
  unipoly::UniPoly,
};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ec::pairing::Pairing;
use ark_poly_commit::multilinear_pc::data_structures::Commitment;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::AllocationMode;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use std::borrow::Borrow;

pub struct PoseidonTranscripVar<E>
where
  E: Pairing,
{
  pub cs: ConstraintSystemRef<E::ScalarField>,
  pub sponge: PoseidonSpongeVar<E::ScalarField>,
}

impl<E> PoseidonTranscripVar<E>
where
  E: Pairing,
{
  fn new(
    cs: ConstraintSystemRef<E::ScalarField>,
    params: &PoseidonConfig<E::ScalarField>,
    c_var: FpVar<E::ScalarField>,
  ) -> Self {
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &params);

    sponge.absorb(&c_var).unwrap();

    Self { cs, sponge }
  }

  fn append(&mut self, input: &FpVar<E::ScalarField>) -> Result<(), SynthesisError> {
    self.sponge.absorb(&input)
  }

  fn append_vector(&mut self, input_vec: &[FpVar<E::ScalarField>]) -> Result<(), SynthesisError> {
    for input in input_vec.iter() {
      self.append(input)?;
    }
    Ok(())
  }

  fn challenge(&mut self) -> Result<FpVar<E::ScalarField>, SynthesisError> {
    Ok(self.sponge.squeeze_field_elements(1).unwrap().remove(0))
  }

  fn challenge_scalar_vec(
    &mut self,
    len: usize,
  ) -> Result<Vec<FpVar<E::ScalarField>>, SynthesisError> {
    let c_vars = self.sponge.squeeze_field_elements(len).unwrap();
    Ok(c_vars)
  }
}

#[derive(Clone)]
pub struct R1CSVerificationCircuit2<E: Pairing> {
  pub num_vars: usize,
  pub num_cons: usize,
  pub input: Vec<E::ScalarField>,
  pub input_as_sparse_poly: SparsePolynomial<E::ScalarField>,
  pub evals: (E::ScalarField, E::ScalarField, E::ScalarField),
  pub params: PoseidonConfig<E::ScalarField>,
  pub prev_challenge: E::ScalarField,
  pub claims_phase2: (
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
  ),
  pub eval_vars_at_ry: E::ScalarField,
  pub sc_phase1: SumCheckVerificationCircuit<E>,
  pub sc_phase2: SumCheckVerificationCircuit<E>,
  // The point on which the polynomial was evaluated by the prover.
  pub claimed_rx: Vec<E::ScalarField>,
  pub claimed_ry: Vec<E::ScalarField>,
  pub claimed_transcript_sat_state: E::ScalarField,
}

impl<E: Pairing> R1CSVerificationCircuit2<E> {
  pub fn new(config: &VerifierConfig<E>) -> Self {
    Self {
      num_vars: config.num_vars,
      num_cons: config.num_cons,
      input: config.input.clone(),
      input_as_sparse_poly: config.input_as_sparse_poly.clone(),
      evals: config.evals,
      params: config.params.clone(),
      prev_challenge: config.prev_challenge,
      claims_phase2: config.claims_phase2,
      eval_vars_at_ry: config.eval_vars_at_ry,
      sc_phase1: SumCheckVerificationCircuit {
        polys: config.polys_sc1.clone(),
      },
      sc_phase2: SumCheckVerificationCircuit {
        polys: config.polys_sc2.clone(),
      },
      claimed_rx: config.rx.clone(),
      claimed_ry: config.ry.clone(),
      claimed_transcript_sat_state: config.transcript_sat_state,
    }
  }
}
impl<E: Pairing> ConstraintSynthesizer<E::ScalarField> for R1CSVerificationCircuit2<E> {
  fn generate_constraints(
    self,
    cs: ConstraintSystemRef<E::ScalarField>,
  ) -> ark_relations::r1cs::Result<()> {
    let initial_challenge_var =
      FpVar::<E::ScalarField>::new_input(cs.clone(), || Ok(self.prev_challenge))?;
    let mut transcript_var =
      PoseidonTranscripVar::<E>::new(cs.clone(), &self.params, initial_challenge_var);

    let poly_sc1_vars = self
      .sc_phase1
      .polys
      .iter()
      .map(|p| UniPolyVar::new_variable(cs.clone(), || Ok(p), AllocationMode::Witness).unwrap())
      .collect::<Vec<UniPolyVar<E>>>();

    let poly_sc2_vars = self
      .sc_phase2
      .polys
      .iter()
      .map(|p| UniPolyVar::new_variable(cs.clone(), || Ok(p), AllocationMode::Witness).unwrap())
      .collect::<Vec<UniPolyVar<E>>>();

    let input_vars = self
      .input
      .iter()
      .map(|i| {
        FpVar::<E::ScalarField>::new_variable(cs.clone(), || Ok(i), AllocationMode::Input).unwrap()
      })
      .collect::<Vec<FpVar<E::ScalarField>>>();

    let claimed_rx_vars = self
      .claimed_rx
      .iter()
      .map(|r| {
        FpVar::<E::ScalarField>::new_variable(cs.clone(), || Ok(r), AllocationMode::Input).unwrap()
      })
      .collect::<Vec<FpVar<E::ScalarField>>>();

    let claimed_ry_vars = self
      .claimed_ry
      .iter()
      .map(|r| {
        FpVar::<E::ScalarField>::new_variable(cs.clone(), || Ok(r), AllocationMode::Input).unwrap()
      })
      .collect::<Vec<FpVar<E::ScalarField>>>();

    transcript_var.append_vector(&input_vars)?;

    let num_rounds_x = self.num_cons.log_2();
    let _num_rounds_y = (2 * self.num_vars).log_2();

    let tau_vars = transcript_var.challenge_scalar_vec(num_rounds_x)?;

    let claim_phase1_var =
      FpVar::<E::ScalarField>::new_witness(cs.clone(), || Ok(E::ScalarField::zero()))?;

    let (claim_post_phase1_var, rx_var) =
      self
        .sc_phase1
        .verifiy_sumcheck(&poly_sc1_vars, &claim_phase1_var, &mut transcript_var)?;

    // The prover sends (rx, ry) to the verifier for the evaluation proof so
    // the constraints need to ensure it is indeed the result from the first
    // round of sumcheck verification.
    for (i, r) in claimed_rx_vars.iter().enumerate() {
      rx_var[i].enforce_equal(r)?;
    }

    let (Az_claim, Bz_claim, Cz_claim, prod_Az_Bz_claims) = &self.claims_phase2;

    let Az_claim_var = FpVar::<E::ScalarField>::new_witness(cs.clone(), || Ok(Az_claim))?;
    let Bz_claim_var = FpVar::<E::ScalarField>::new_witness(cs.clone(), || Ok(Bz_claim))?;
    let Cz_claim_var = FpVar::<E::ScalarField>::new_witness(cs.clone(), || Ok(Cz_claim))?;
    let prod_Az_Bz_claim_var =
      FpVar::<E::ScalarField>::new_witness(cs.clone(), || Ok(prod_Az_Bz_claims))?;
    let one = FpVar::<E::ScalarField>::one();
    let prod_vars: Vec<FpVar<E::ScalarField>> = (0..rx_var.len())
      .map(|i| (&rx_var[i] * &tau_vars[i]) + (&one - &rx_var[i]) * (&one - &tau_vars[i]))
      .collect();
    let mut taus_bound_rx_var = FpVar::<E::ScalarField>::one();

    for p_var in prod_vars.iter() {
      taus_bound_rx_var *= p_var;
    }

    let expected_claim_post_phase1_var =
      (&prod_Az_Bz_claim_var - &Cz_claim_var) * &taus_bound_rx_var;

    claim_post_phase1_var.enforce_equal(&expected_claim_post_phase1_var)?;

    let r_A_var = transcript_var.challenge()?;
    let r_B_var = transcript_var.challenge()?;
    let r_C_var = transcript_var.challenge()?;

    let claim_phase2_var =
      &r_A_var * &Az_claim_var + &r_B_var * &Bz_claim_var + &r_C_var * &Cz_claim_var;

    let (claim_post_phase2_var, ry_var) =
      self
        .sc_phase2
        .verifiy_sumcheck(&poly_sc2_vars, &claim_phase2_var, &mut transcript_var)?;

    //  Because the verifier checks the commitment opening on point ry outside
    //  the circuit, the prover needs to send ry to the verifier (making the
    //  proof size O(log n)). As this point is normally obtained by the verifier
    //  from the second round of sumcheck, the circuit needs to ensure the
    //  claimed point, coming from the prover, is actually the point derived
    //  inside the circuit. These additional checks will be removed
    //  when the commitment verification is done inside the circuit.
    //  Moreover, (rx, ry) will be used in the evaluation proof.
    for (i, r) in claimed_ry_vars.iter().enumerate() {
      ry_var[i].enforce_equal(r)?;
    }

    let input_as_sparse_poly_var: SparsePolynomialVar<E> = SparsePolynomialVar::new_variable(
      cs.clone(),
      || Ok(&self.input_as_sparse_poly),
      AllocationMode::Witness,
    )?;

    let poly_input_eval_var = input_as_sparse_poly_var.evaluate(&ry_var[1..]);

    let eval_vars_at_ry_var =
      FpVar::<E::ScalarField>::new_input(cs.clone(), || Ok(&self.eval_vars_at_ry))?;

    let eval_Z_at_ry_var = (FpVar::<E::ScalarField>::one() - &ry_var[0]) * &eval_vars_at_ry_var
      + &ry_var[0] * &poly_input_eval_var;

    let (eval_A_r, eval_B_r, eval_C_r) = self.evals;

    let eval_A_r_var = FpVar::<E::ScalarField>::new_input(cs.clone(), || Ok(eval_A_r))?;
    let eval_B_r_var = FpVar::<E::ScalarField>::new_input(cs.clone(), || Ok(eval_B_r))?;
    let eval_C_r_var = FpVar::<E::ScalarField>::new_input(cs.clone(), || Ok(eval_C_r))?;

    let scalar_var = &r_A_var * &eval_A_r_var + &r_B_var * &eval_B_r_var + &r_C_var * &eval_C_r_var;

    let expected_claim_post_phase2_var = eval_Z_at_ry_var * scalar_var;
    claim_post_phase2_var.enforce_equal(&expected_claim_post_phase2_var)?;
    let expected_transcript_state_var = transcript_var.challenge()?;
    let claimed_transcript_state_var =
      FpVar::<E::ScalarField>::new_input(cs, || Ok(self.claimed_transcript_sat_state))?;

    // Ensure that the prover and verifier transcipt views are consistent at
    // the end of the satisfiability proof.
    expected_transcript_state_var.enforce_equal(&claimed_transcript_state_var)?;
    println!("CS MARA MOD");
    Ok(())
  }
}
#[derive(Clone)]
pub struct UniPolyVar<E: Pairing> {
  pub coeffs: Vec<FpVar<E::ScalarField>>,
}
impl<E: Pairing> AllocVar<UniPoly<E::ScalarField>, E::ScalarField> for UniPolyVar<E> {
  fn new_variable<T: Borrow<UniPoly<E::ScalarField>>>(
    cs: impl Into<Namespace<E::ScalarField>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|c| {
      let cs = cs.into();
      let cp: &UniPoly<E::ScalarField> = c.borrow();
      let mut coeffs_var = Vec::new();
      for coeff in cp.coeffs.iter() {
        let coeff_var = FpVar::<E::ScalarField>::new_variable(cs.clone(), || Ok(coeff), mode)?;
        coeffs_var.push(coeff_var);
      }
      Ok(Self { coeffs: coeffs_var })
    })
  }
}
impl<E: Pairing> UniPolyVar<E> {
  pub fn eval_at_zero(&self) -> FpVar<E::ScalarField> {
    self.coeffs[0].clone()
  }

  pub fn eval_at_one(&self) -> FpVar<E::ScalarField> {
    let mut res = self.coeffs[0].clone();
    for i in 1..self.coeffs.len() {
      res = &res + &self.coeffs[i];
    }
    res
  }

  // TODO check if mul without reduce can help
  pub fn evaluate(&self, r: &FpVar<E::ScalarField>) -> FpVar<E::ScalarField> {
    let mut eval = self.coeffs[0].clone();
    let mut power = r.clone();

    for i in 1..self.coeffs.len() {
      eval += &power * &self.coeffs[i];
      power *= r;
    }
    eval
  }
}
#[derive(Clone)]
pub struct SumCheckVerificationCircuit<E: Pairing> {
  pub polys: Vec<UniPoly<E::ScalarField>>,
}
impl<E: Pairing> SumCheckVerificationCircuit<E> {
  fn verifiy_sumcheck(
    &self,
    poly_vars: &[UniPolyVar<E>],
    claim_var: &FpVar<E::ScalarField>,
    transcript_var: &mut PoseidonTranscripVar<E>,
  ) -> Result<(FpVar<E::ScalarField>, Vec<FpVar<E::ScalarField>>), SynthesisError> {
    let mut e_var = claim_var.clone();
    let mut r_vars: Vec<FpVar<E::ScalarField>> = Vec::new();

    for (poly_var, _poly) in poly_vars.iter().zip(self.polys.iter()) {
      let res = poly_var.eval_at_one() + poly_var.eval_at_zero();
      res.enforce_equal(&e_var)?;
      transcript_var.append_vector(&poly_var.coeffs)?;
      let r_i_var = transcript_var.challenge()?;
      r_vars.push(r_i_var.clone());
      e_var = poly_var.evaluate(&r_i_var.clone());
    }

    Ok((e_var, r_vars))
  }
}
#[derive(Clone)]
pub struct SparsePolyEntryVar<E: Pairing> {
  idx: usize,
  val_var: FpVar<E::ScalarField>,
}
impl<E: Pairing> AllocVar<SparsePolyEntry<E::ScalarField>, E::ScalarField>
  for SparsePolyEntryVar<E>
{
  fn new_variable<T: Borrow<SparsePolyEntry<E::ScalarField>>>(
    cs: impl Into<Namespace<E::ScalarField>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    _mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|s| {
      let cs = cs.into();
      let spe: &SparsePolyEntry<E::ScalarField> = s.borrow();
      let val_var = FpVar::<E::ScalarField>::new_witness(cs, || Ok(spe.val))?;
      Ok(Self {
        idx: spe.idx,
        val_var,
      })
    })
  }
}

#[derive(Clone)]
pub struct SparsePolynomialVar<E: Pairing> {
  Z_var: Vec<SparsePolyEntryVar<E>>,
}
impl<E: Pairing> AllocVar<SparsePolynomial<E::ScalarField>, E::ScalarField>
  for SparsePolynomialVar<E>
{
  fn new_variable<T: Borrow<SparsePolynomial<E::ScalarField>>>(
    cs: impl Into<Namespace<E::ScalarField>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|s| {
      let cs = cs.into();
      let sp: &SparsePolynomial<E::ScalarField> = s.borrow();
      let mut Z_var = Vec::new();
      for spe in sp.Z.iter() {
        let spe_var = SparsePolyEntryVar::new_variable(cs.clone(), || Ok(spe), mode)?;
        Z_var.push(spe_var);
      }
      Ok(Self { Z_var })
    })
  }
}
impl<E: Pairing> SparsePolynomialVar<E> {
  fn compute_chi(a: &[bool], r_vars: &[FpVar<E::ScalarField>]) -> FpVar<E::ScalarField> {
    let mut chi_i_var = FpVar::<E::ScalarField>::one();
    let one = FpVar::<E::ScalarField>::one();
    for (i, r_var) in r_vars.iter().enumerate() {
      if a[i] {
        chi_i_var *= r_var;
      } else {
        chi_i_var *= &one - r_var;
      }
    }
    chi_i_var
  }

  pub fn evaluate(&self, r_var: &[FpVar<E::ScalarField>]) -> FpVar<E::ScalarField> {
    let mut sum = FpVar::<E::ScalarField>::zero();
    for spe_var in self.Z_var.iter() {
      // potential problem
      let bits = &spe_var.idx.get_bits(r_var.len());
      sum += Self::compute_chi(bits, r_var) * &spe_var.val_var;
    }
    sum
  }
}
#[derive(Clone)]
pub struct VerifierConfig<E: Pairing> {
  pub comm: Commitment<E>,
  pub num_vars: usize,
  pub num_cons: usize,
  pub input: Vec<E::ScalarField>,
  pub input_as_sparse_poly: SparsePolynomial<E::ScalarField>,
  pub evals: (E::ScalarField, E::ScalarField, E::ScalarField),
  pub params: PoseidonConfig<E::ScalarField>,
  pub prev_challenge: E::ScalarField,
  pub claims_phase2: (
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
  ),
  pub eval_vars_at_ry: E::ScalarField,
  pub polys_sc1: Vec<UniPoly<E::ScalarField>>,
  pub polys_sc2: Vec<UniPoly<E::ScalarField>>,
  pub rx: Vec<E::ScalarField>,
  pub ry: Vec<E::ScalarField>,
  pub transcript_sat_state: E::ScalarField,
}
