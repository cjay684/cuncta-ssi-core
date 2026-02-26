pragma circom 2.1.6;

// Poseidon variant must match the JS commitment builder used by the wallet
// (`circomlibjs` buildPoseidon()).
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// age_gte_v1:
// - Holder proves knowledge of (birthdate_days, rand) such that:
//   dob_commitment = Poseidon(domain_tag, birthdate_days, rand)
//   birthdate_days <= current_day - (min_age * 365)
// - Proof is bound to request context by including binding public inputs:
//   nonce_hash, audience_hash, request_hash (field elements derived off-circuit).
//
// Public inputs:
//   dob_commitment, min_age, current_day, nonce_hash, audience_hash, request_hash
// Private inputs:
//   birthdate_days, rand
template AgeGteV1() {
  // private
  signal input birthdate_days;
  signal input rand;

  // public
  signal input dob_commitment;
  signal input min_age;
  signal input current_day;
  signal input nonce_hash;
  signal input audience_hash;
  signal input request_hash;

  // Commitment check
  // Domain separation tag (BN254 field element):
  // sha256("cuncta:age:v1") mod p
  var DOMAIN_TAG = 3805445632897706479387916969139462601971875644687406422943513851068976456195;
  component c = Poseidon(3);
  c.inputs[0] <== DOMAIN_TAG;
  c.inputs[1] <== birthdate_days;
  c.inputs[2] <== rand;
  c.out === dob_commitment;

  // Ensure current_day is reasonably large to avoid trivial underflow tricks:
  // current_day >= min_age*365
  signal age_days;
  age_days <== min_age * 365;
  component ge = LessEqThan(32); // checks a <= b
  ge.in[0] <== age_days;
  ge.in[1] <== current_day;
  ge.out === 1;

  // threshold = current_day - age_days
  signal threshold;
  threshold <== current_day - age_days;
  component le = LessEqThan(32);
  le.in[0] <== birthdate_days;
  le.in[1] <== threshold;
  le.out === 1;

  // Bindings are public inputs; verifier enforces equality to expected derived values.
  // We also include them here so they are part of the proof statement.
  nonce_hash * 1 === nonce_hash;
  audience_hash * 1 === audience_hash;
  request_hash * 1 === request_hash;
}

component main { public [dob_commitment, min_age, current_day, nonce_hash, audience_hash, request_hash] } = AgeGteV1();

