//! Fuzzforge hostile-scenario library for Crucible harnesses.
//!
//! Crucible's `--mutate-accounts` engine already probes owner, signer, PDA,
//! type-tag, duplicate-account and forwarded-CPI checks. This crate covers what
//! it explicitly skips:
//!
//! * [`token2022`]: a matrix of Token-2022 mints with hostile extensions, built
//!   through the real Token-2022 program, plus balance/withheld/frozen readers
//!   that understand extension accounts (`TestContext::token_balance` returns 0
//!   for any Token-2022 account with extensions).
//! * [`invariants`]: reusable ledgers for custody and liveness invariants that
//!   harnesses feed from their actions and assert in `#[invariant_test]`.

pub mod anchor;
pub mod invariants;
pub mod token2022;

pub use invariants::{CustodyLedger, LivenessLog, ShareValueLedger};
pub use token2022::{MintHandle, MintProfile, TokenEnv};
