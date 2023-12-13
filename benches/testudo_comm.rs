use ark_poly_commit::multilinear_pc::MultilinearPC;
use libtestudo::circuit_verifier::TestudoCommVerifier;
use libtestudo::{
  parameters::get_bls12377_fq_params, poseidon_transcript::PoseidonTranscript, sqrt_pst::Polynomial,
};
use ark_std::marker::PhantomData;
use serde::Serialize;
type F = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
use ark_std::UniformRand;
use ark_relations::r1cs::ConstraintSystem;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::ConstraintSynthesizer;

#[derive(Default, Clone, Serialize)]
struct BenchmarkResults {
  power: usize,
  num_constraints: usize,
}
fn main() {
  let params = get_bls12377_fq_params();

  let mut writer = csv::Writer::from_path("sqrt_pst.csv").expect("unable to open csv writer");
  for &s in [4, 5, 20, 27].iter() {
    println!("Running for {} inputs", s);
    let mut rng = ark_std::test_rng();
    let mut br = BenchmarkResults::default();
    br.power = s;
    let num_vars = s;
    let len = 2_usize.pow(num_vars as u32);
    let z: Vec<F> = (0..len).into_iter().map(|_| F::rand(&mut rng)).collect();
    let r: Vec<F> = (0..num_vars)
      .into_iter()
      .map(|_| F::rand(&mut rng))
      .collect();

    let setup_vars = (num_vars as f32 / 2.0).ceil() as usize;
    let gens = MultilinearPC::<E>::setup((num_vars as f32 / 2.0).ceil() as usize, &mut rng);
    let (ck, vk) = MultilinearPC::<E>::trim(&gens, setup_vars);

    let mut pl = Polynomial::from_evaluations(&z.clone());

    let v = pl.eval(&r);

    let (comm_list, t) = pl.commit(&ck);

    let mut prover_transcript = PoseidonTranscript::new(&get_bls12377_fq_params());

    let (u, pst_proof, mipp_proof) = pl.open(&mut prover_transcript, comm_list, &ck, &r, &t);

    let circuit =
      TestudoCommVerifier::<ark_bls12_377::Bls12_377, ark_bls12_377::constraints::PairingVar> {
        &get_bls12377_fq_params(),
        vk,
        U: u,
        point: r,
        v,
        pst_proof,
        mipp_proof,
        T: t,
        _iv: PhantomData,
      };
    let cs = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    br.num_constraints =  cs.num_constraints();

    writer
      .serialize(br)
      .expect("unable to write results to csv");
    writer.flush().expect("wasn't able to flush");
  }
}
