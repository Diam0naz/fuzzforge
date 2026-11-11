//! Fuzzforge Sentinel: the runtime half of Fuzzforge.
//!
//! The invariants a fuzz campaign validated before launch become the rules a
//! monitor and a pre-signing firewall enforce after it, from one reviewable
//! policy file. See `README.md`.

pub mod check;
pub mod cpswap;
pub mod drill;
pub mod fork;
pub mod monitor;
pub mod policy;
pub mod protocol;
pub mod rpc;
pub mod rules;
pub mod stakepool;
pub mod trace;
pub mod vet;

#[cfg(test)]
mod tests;
