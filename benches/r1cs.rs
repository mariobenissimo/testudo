use std::time::SystemTime;

use ark_serialize::CanonicalSerialize;
use libspartan::{
  parameters::POSEIDON_PARAMETERS_377, poseidon_transcript::PoseidonTranscript, Instance, NIZK,
};
use serde::Serialize;

#[derive(Default, Clone, Serialize)]
struct BenchmarkResults {
  r1cs_constraints: usize,
  r1cs_instance_generation_time: u128,
  spartan_proving_time: u128,
  groth16_constaints: usize,
  cons_sat_verification_time: u128,
  groth16_setup: u128,
  groth16_proving: u128,
  groth16_verification: u128,
  groth16_total: u128,
}

fn main() {
  let mut writer = csv::Writer::from_path("testudo.csv").expect("unable to open csv writer");
  for &s in [10, 12, 16, 20, 24, 26, 30].iter() {
    println!("Running for {} inputs", s);
    let mut br = BenchmarkResults::default();
    let num_vars = (2_usize).pow(s as u32);
    let num_cons = num_vars;
    br.r1cs_constraints = num_cons;
    // these are the public io
    let num_inputs = 10;
    let start = SystemTime::now();
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    let end = SystemTime::now();
    let duration = end.duration_since(start).unwrap().as_millis();
    println!(
      "Generating r1cs instance with {} constraints took {} ms",
      num_cons, duration
    );
    br.r1cs_instance_generation_time = duration;
    let mut prover_transcript = PoseidonTranscript::new(&POSEIDON_PARAMETERS_377);
    let start = SystemTime::now();
    let proof = NIZK::prove(&inst, vars, &inputs, &mut prover_transcript);
    let end = SystemTime::now();
    let duration = end.duration_since(start).unwrap().as_millis();
    println!("Proving on  {} inputs took {}", s, duration);
    br.spartan_proving_time = duration;

    let mut verifier_transcript = PoseidonTranscript::new(&POSEIDON_PARAMETERS_377);
    let start = SystemTime::now();
    let res = proof.verify(&inst, &inputs, &mut verifier_transcript);
    let end = SystemTime::now();
    let duration = end.duration_since(start).unwrap().as_millis();
    assert!(res.is_ok());
    println!(
      "verifying constrainsts sat on {} inputs took {}",
      s, duration
    );
    br.groth16_constaints = res.unwrap();
    br.cons_sat_verification_time = duration;

    let mut verifier_transcript = PoseidonTranscript::new(&POSEIDON_PARAMETERS_377);
    let start = SystemTime::now();

    let res = proof.verify_groth16(&inst, &inputs, &mut verifier_transcript);
    assert!(res.is_ok());
    let end = SystemTime::now();
    let duration = end.duration_since(start).unwrap().as_millis();
    assert!(res.is_ok());
    println!("verifying with groth16 on {} inputs took {}", s, duration);
    let (ds, dp, dv) = res.unwrap();
    br.groth16_setup = ds;
    br.groth16_proving = dp;
    br.groth16_verification = dv;
    br.groth16_total = ds + dp + dv;

    writer
      .serialize(br)
      .expect("unable to write results to csv");
    writer.flush().expect("wasn't able to flush");
  }
}
