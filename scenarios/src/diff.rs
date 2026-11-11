//! Upgrade-diff fuzzing: the previous build is the oracle.
//!
//! Hand-written invariants only catch what someone thought to write down. When
//! a program is upgraded there is a second, free source of truth: the build
//! that is already deployed. Run every fuzzed step against both builds and any
//! difference in outcome or resulting state is a behaviour change. Each one is
//! either what the release notes promise or a regression, and the fuzzer hands
//! over the shortest action sequence that shows it.
//!
//! A harness in diff mode keeps two `TestContext`s (candidate and reference),
//! applies every step to both, compares success/failure per instruction, and
//! calls [`first_difference`] on the accounts it cares about after each action.

use crucible_test_context::TestContext;
use solana_pubkey::Pubkey;

/// Compare the named accounts in two contexts. Returns a description of the
/// first one that differs in existence, owner, lamports or data.
pub fn first_difference(candidate: &TestContext, reference: &TestContext, accounts: &[(&str, Pubkey)]) -> Option<String> {
    for (name, address) in accounts {
        let a = candidate.svm.get_account(address);
        let b = reference.svm.get_account(address);
        let (a, b) = match (a, b) {
            (None, None) => continue,
            (Some(a), Some(b)) => (a, b),
            (a, _) => {
                let (has, lacks) = if a.is_some() { ("candidate", "reference") } else { ("reference", "candidate") };
                return Some(format!("{name} exists on the {has} build but not on the {lacks} build"));
            }
        };
        if a.owner != b.owner {
            return Some(format!("{name}: owner {} on candidate, {} on reference", a.owner, b.owner));
        }
        if a.data != b.data {
            if a.data.len() != b.data.len() {
                return Some(format!("{name}: data is {} bytes on candidate, {} on reference", a.data.len(), b.data.len()));
            }
            let at = a.data.iter().zip(&b.data).position(|(x, y)| x != y).unwrap_or(0);
            let end = (at + 8).min(a.data.len());
            return Some(format!(
                "{name}: data differs from byte {at}: candidate {:02x?}, reference {:02x?}",
                &a.data[at..end],
                &b.data[at..end]
            ));
        }
        if a.lamports != b.lamports {
            return Some(format!("{name}: {} lamports on candidate, {} on reference", a.lamports, b.lamports));
        }
    }
    None
}

/// Describe an outcome mismatch for one instruction, or `None` when both
/// builds agree on success/failure. Error text is not compared: wording and
/// error codes legitimately change between releases.
pub fn outcome_difference<T, U>(ix: &str, candidate: &Result<T, String>, reference: &Result<U, String>) -> Option<String> {
    let show = |r: Result<(), &String>| match r {
        Ok(()) => "succeeded".to_string(),
        Err(e) => format!("failed ({e})"),
    };
    (candidate.is_ok() != reference.is_ok()).then(|| {
        format!(
            "{ix} {} on the candidate build but {} on the reference build",
            show(candidate.as_ref().map(|_| ())),
            show(reference.as_ref().map(|_| ()))
        )
    })
}
