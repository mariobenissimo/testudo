// use ark_ec::pairing::Pairing;
// use ark_relations::r1cs::ConstraintSystemRef;
// use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
// use ark_r1cs_std::fields::fp::FpVar;
// use ark_crypto_primitives::sponge::DuplexSpongeMode;
// use ark_relations::r1cs::SynthesisError;
// use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
// use ark_r1cs_std::fields::FieldVar;
// use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
// use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
// use ark_r1cs_std::uint8::UInt8;
// use ark_r1cs_std::boolean::Boolean;
// use ark_ff::PrimeField;
// use ark_r1cs_std::ToBytesGadget;

// #[derive(Clone)]
// pub struct PoseidonSpongeVar<E: Pairing> {
//   /// Constraint system
//   pub cs: ConstraintSystemRef<E::BaseField>,

//   /// Sponge Parameters
//   pub parameters: PoseidonConfig<E::ScalarField>,

//   // Sponge State
//   /// The sponge's state
//   pub state: Vec<FpVar<E::ScalarField>>,
//   /// The mode
//   pub mode: DuplexSpongeMode,
// }

// impl<E: Pairing> PoseidonSpongeVar<E> {
//   #[tracing::instrument(target = "r1cs", skip(self))]
//   fn apply_s_box(
//       &self,
//       state: &mut [FpVar<E::ScalarField>],
//       is_full_round: bool,
//   ) -> Result<(), SynthesisError> {
//       // Full rounds apply the S Box (x^alpha) to every element of state
//       if is_full_round {
//           for state_item in state.iter_mut() {
//               *state_item = state_item.pow_by_constant(&[self.parameters.alpha])?;
//           }
//       }
//       // Partial rounds apply the S Box (x^alpha) to just the first element of state
//       else {
//           state[0] = state[0].pow_by_constant(&[self.parameters.alpha])?;
//       }

//       Ok(())
//   }

//   #[tracing::instrument(target = "r1cs", skip(self))]
//   fn apply_ark(&self, state: &mut [FpVar<E::ScalarField>], round_number: usize) -> Result<(), SynthesisError> {
//       for (i, mut state_elem) in state.iter_mut().enumerate() {
//           *state_elem += self.parameters.ark[round_number][i];
//       }
//       Ok(())
//   }

//   #[tracing::instrument(target = "r1cs", skip(self))]
//   fn apply_mds(&self, state: &mut [FpVar<E::ScalarField>]) -> Result<(), SynthesisError> {
//       let mut new_state = Vec::new();
//       let zero = FpVar::<E::ScalarField>::zero();
//       for i in 0..state.len() {
//           let mut cur = zero.clone();
//           for (j, state_elem) in state.iter().enumerate() {
//               let term = state_elem * self.parameters.mds[i][j];
//               cur += &term;
//           }
//           new_state.push(cur);
//       }
//       state.clone_from_slice(&new_state[..state.len()]);
//       Ok(())
//   }

//   #[tracing::instrument(target = "r1cs", skip(self))]
//   fn permute(&mut self) -> Result<(), SynthesisError> {
//       let full_rounds_over_2 = self.parameters.full_rounds / 2;
//       let mut state = self.state.clone();
//       for i in 0..full_rounds_over_2 {
//           self.apply_ark(&mut state, i)?;
//           self.apply_s_box(&mut state, true)?;
//           self.apply_mds(&mut state)?;
//       }
//       for i in full_rounds_over_2..(full_rounds_over_2 + self.parameters.partial_rounds) {
//           self.apply_ark(&mut state, i)?;
//           self.apply_s_box(&mut state, false)?;
//           self.apply_mds(&mut state)?;
//       }

//       for i in (full_rounds_over_2 + self.parameters.partial_rounds)
//           ..(self.parameters.partial_rounds + self.parameters.full_rounds)
//       {
//           self.apply_ark(&mut state, i)?;
//           self.apply_s_box(&mut state, true)?;
//           self.apply_mds(&mut state)?;
//       }

//       self.state = state;
//       Ok(())
//   }

//   #[tracing::instrument(target = "r1cs", skip(self))]
//   fn absorb_internal(
//       &mut self,
//       mut rate_start_index: usize,
//       elements: &[FpVar<E::ScalarField>],
//   ) -> Result<(), SynthesisError> {
//       let mut remaining_elements = elements;
//       loop {
//           // if we can finish in this call
//           if rate_start_index + remaining_elements.len() <= self.parameters.rate {
//               for (i, element) in remaining_elements.iter().enumerate() {
//                   self.state[self.parameters.capacity + i + rate_start_index] += element;
//               }
//               self.mode = DuplexSpongeMode::Absorbing {
//                   next_absorb_index: rate_start_index + remaining_elements.len(),
//               };

//               return Ok(());
//           }
//           // otherwise absorb (rate - rate_start_index) elements
//           let num_elements_absorbed = self.parameters.rate - rate_start_index;
//           for (i, element) in remaining_elements
//               .iter()
//               .enumerate()
//               .take(num_elements_absorbed)
//           {
//               self.state[self.parameters.capacity + i + rate_start_index] += element;
//           }
//           self.permute()?;
//           // the input elements got truncated by num elements absorbed
//           remaining_elements = &remaining_elements[num_elements_absorbed..];
//           rate_start_index = 0;
//       }
//   }

//   // Squeeze |output| many elements. This does not end in a squeeze
//   #[tracing::instrument(target = "r1cs", skip(self))]
//   fn squeeze_internal(
//       &mut self,
//       mut rate_start_index: usize,
//       output: &mut [FpVar<E::ScalarField>],
//   ) -> Result<(), SynthesisError> {
//       let mut remaining_output = output;
//       loop {
//           // if we can finish in this call
//           if rate_start_index + remaining_output.len() <= self.parameters.rate {
//               remaining_output.clone_from_slice(
//                   &self.state[self.parameters.capacity + rate_start_index
//                       ..(self.parameters.capacity + remaining_output.len() + rate_start_index)],
//               );
//               self.mode = DuplexSpongeMode::Squeezing {
//                   next_squeeze_index: rate_start_index + remaining_output.len(),
//               };
//               return Ok(());
//           }
//           // otherwise squeeze (rate - rate_start_index) elements
//           let num_elements_squeezed = self.parameters.rate - rate_start_index;
//           remaining_output[..num_elements_squeezed].clone_from_slice(
//               &self.state[self.parameters.capacity + rate_start_index
//                   ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
//           );

//           // Unless we are done with squeezing in this call, permute.
//           if remaining_output.len() != self.parameters.rate {
//               self.permute()?;
//           }
//           // Repeat with updated output slices and rate start index
//           remaining_output = &mut remaining_output[num_elements_squeezed..];
//           rate_start_index = 0;
//       }
//   }
// }

// impl<E: Pairing> CryptographicSpongeVar<E::BaseField, PoseidonSponge<E::BaseField>> for PoseidonSpongeVar<E> {
//   type Parameters = PoseidonConfig<E::ScalarField>;

//   fn new(cs: ConstraintSystemRef<E::BaseField>, parameters: &PoseidonConfig<E::ScalarField>) -> Self {
//       let zero = FpVar::<E::ScalarField>::zero();
//       let state = vec![zero; parameters.rate + parameters.capacity];
//       let mode = DuplexSpongeMode::Absorbing {
//           next_absorb_index: 0,
//       };
//       println!("NEW POSEIDON");
//       Self {
//           cs,
//           parameters: parameters.clone(),
//           state,
//           mode,
//       }
//   }

//   fn cs(&self) -> ConstraintSystemRef<E::BaseField> {
//       self.cs.clone()
//   }

//   fn absorb(&mut self, input: &impl AbsorbGadget<E::ScalarField>) -> Result<(), SynthesisError> {
//       let input = input.to_sponge_field_elements()?;
//       if input.is_empty() {
//           return Ok(());
//       }

//       match self.mode {
//           DuplexSpongeMode::Absorbing { next_absorb_index } => {
//               let mut absorb_index = next_absorb_index;
//               if absorb_index == self.parameters.rate {
//                   self.permute()?;
//                   absorb_index = 0;
//               }
//               self.absorb_internal(absorb_index, input.as_slice())?;
//           }
//           DuplexSpongeMode::Squeezing {
//               next_squeeze_index: _,
//           } => {
//               self.permute()?;
//               self.absorb_internal(0, input.as_slice())?;
//           }
//       };

//       Ok(())
//   }

//   fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<E::ScalarField>>, SynthesisError> {
//       let usable_bytes = ((E::ScalarField::MODULUS_BIT_SIZE - 1) / 8) as usize;

//       let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
//       let src_elements = self.squeeze_field_elements(num_elements)?;

//       let mut bytes: Vec<UInt8<E::ScalarField>> = Vec::with_capacity(usable_bytes * num_elements);
//       for elem in &src_elements {
//           bytes.extend_from_slice(&elem.to_bytes()?[..usable_bytes]);
//       }

//       bytes.truncate(num_bytes);
//       Ok(bytes)
//   }

//   fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<E::ScalarField>>, SynthesisError> {
//       let usable_bits = (E::ScalarField::MODULUS_BIT_SIZE - 1) as usize;

//       let num_elements = (num_bits + usable_bits - 1) / usable_bits;
//       let src_elements = self.squeeze_field_elements(num_elements)?;

//       let mut bits: Vec<Boolean<E::ScalarField>> = Vec::with_capacity(usable_bits * num_elements);
//       for elem in &src_elements {
//           bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
//       }

//       bits.truncate(num_bits);
//       Ok(bits)
//   }

//   fn squeeze_field_elements(
//       &mut self,
//       num_elements: usize,
//   ) -> Result<Vec<FpVar<E::ScalarField>>, SynthesisError> {
//       let zero = FpVar::zero();
//       let mut squeezed_elems = vec![zero; num_elements];
//       match self.mode {
//           DuplexSpongeMode::Absorbing {
//               next_absorb_index: _,
//           } => {
//               self.permute()?;
//               self.squeeze_internal(0, &mut squeezed_elems)?;
//           }
//           DuplexSpongeMode::Squeezing { next_squeeze_index } => {
//               let mut squeeze_index = next_squeeze_index;
//               if squeeze_index == self.parameters.rate {
//                   self.permute()?;
//                   squeeze_index = 0;
//               }
//               self.squeeze_internal(squeeze_index, &mut squeezed_elems)?;
//           }
//       };

//       Ok(squeezed_elems)
//   }
// }
