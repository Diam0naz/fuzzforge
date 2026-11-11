use crate::cpswap::testing::*;
use crate::cpswap::{events, Call, CpIx, Event, PoolView};
use crate::policy::{verdict, Action, Policy};
use crate::rules;
use solana_pubkey::Pubkey;

const PROGRAM: Pubkey = Pubkey::from_str_const("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");

fn policy() -> Policy {
    Policy::load(concat!(env!("CARGO_MANIFEST_DIR"), "/policies/raydium-cp-swap.toml")).unwrap()
}

fn view(r0: u64, r1: u64, lp: u64) -> PoolView {
    PoolView { vault0: r0 + 7, vault1: r1 + 9, fees0: 7, fees1: 9, lp_supply: lp }
}

#[test]
fn shipped_policy_loads_and_hashes() {
    let p = policy();
    assert_eq!(p.allowed.len(), 7);
    assert_eq!(p.sha256.len(), 64);
    assert_eq!(p.describe().len(), 9);
}

#[test]
fn unknown_rule_or_field_fails_the_load() {
    let base = "name = \"x\"\nversion = 1\nprogram = \"CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C\"\n";
    let typo = format!("{base}[rules.solvncy]\naction = \"block\"\nwhy = \"typo\"\n");
    assert!(Policy::parse(&typo).is_err(), "a misspelled rule must not load as 'no rule'");
    let extra = format!("{base}[rules.solvency]\naction = \"block\"\nwhy = \"x\"\nthreshold = 3\n");
    assert!(Policy::parse(&extra).is_err(), "an unknown field must not be ignored");
    let action = format!("{base}[rules.solvency]\naction = \"deny\"\nwhy = \"x\"\n");
    assert!(Policy::parse(&action).is_err());
    assert!(Policy::parse(&format!("{base}[rules]\n")).is_ok());
}

#[test]
fn most_severe_action_decides() {
    use crate::policy::Finding;
    let f = |action| Finding { rule: "solvency", action, detail: String::new() };
    assert_eq!(verdict(&[]), "allow");
    assert_eq!(verdict(&[f(Action::Alert)]), "allow-with-alert");
    assert_eq!(verdict(&[f(Action::Alert), f(Action::Block), f(Action::Hold)]), "block");
}

#[test]
fn share_value_and_solvency_use_the_fuzzed_predicates() {
    let p = policy();
    let mut out = Vec::new();
    // A swap with fee: k grows, nothing fires.
    rules::pool_transition(&p, "pool", Some(view(1_000_000, 1_000_000, 1_000_000)), view(1_100_000, 909_500, 1_000_000), &mut out);
    assert!(out.is_empty(), "{out:?}");
    // A skim of one unit from reserve 0 with nothing else changing.
    rules::pool_transition(&p, "pool", Some(view(1_000_000, 1_000_000, 1_000_000)), view(999_999, 1_000_000, 1_000_000), &mut out);
    assert_eq!(out.iter().map(|f| f.rule).collect::<Vec<_>>(), ["share-value"]);
    out.clear();
    // Vault below booked fees.
    let broke = PoolView { vault0: 5, vault1: 100, fees0: 6, fees1: 0, lp_supply: 10 };
    rules::pool_transition(&p, "pool", None, broke, &mut out);
    assert_eq!(out[0].rule, "solvency");
    assert_eq!(out[0].action, Action::Block);
}

#[test]
fn reserve_outflow_threshold() {
    let p = policy();
    let mut out = Vec::new();
    rules::pool_transition(&p, "pool", Some(view(1_000_000, 1_000_000, 10)), view(2_000_000, 900_001, 10), &mut out);
    assert!(out.is_empty(), "999 bps is under a 1000 bps limit: {out:?}");
    rules::pool_transition(&p, "pool", Some(view(1_000_000, 1_000_000, 10)), view(2_000_000, 899_000, 10), &mut out);
    assert_eq!(out.iter().map(|f| f.rule).collect::<Vec<_>>(), ["reserve-outflow"]);
}

#[test]
fn slippage_measured_on_what_arrives() {
    let p = policy();
    let mut out = Vec::new();
    let swap = |min_out| Call::SwapIn { amount_in: 1_000, min_out };
    // Received 1000, signed min 990: 100 bps of headroom, fine.
    rules::slippage(&p, "s", swap(990), (Some(5_000), Some(0)), (Some(4_000), Some(1_000)), &mut out);
    assert!(out.is_empty());
    // Signed min 0: the whole output is up for grabs.
    rules::slippage(&p, "s", swap(0), (Some(5_000), Some(0)), (Some(4_000), Some(1_000)), &mut out);
    assert_eq!((out[0].rule, out[0].action), ("slippage-headroom", Action::Hold));
    out.clear();
    // Program delivered less than the signed minimum: always block.
    rules::slippage(&p, "s", swap(1_001), (Some(5_000), Some(0)), (Some(4_000), Some(1_000)), &mut out);
    assert_eq!(out[0].action, Action::Block);
    out.clear();
    // Exact-output swap that took more than max_in.
    rules::slippage(&p, "s", Call::SwapOut { max_in: 100, amount_out: 50 }, (Some(1_000), Some(0)), (Some(899), Some(50)), &mut out);
    assert_eq!(out[0].action, Action::Block);
    out.clear();
    // Withdrawal: one side under its minimum.
    rules::slippage(&p, "w", Call::Withdraw { lp: 1, min0: 10, min1: 10 }, (Some(0), Some(0)), (Some(10), Some(9)), &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].action, Action::Block);
}

#[test]
fn allowlist_compute_upgrade_burst() {
    let p = policy();
    let mut out = Vec::new();
    rules::allowlist(&p, &[PROGRAM, Pubkey::from_str_const("11111111111111111111111111111111")], &mut out);
    assert!(out.is_empty());
    rules::allowlist(&p, &[Pubkey::new_unique()], &mut out);
    assert_eq!(out[0].rule, "program-allowlist");
    out.clear();
    rules::compute(&p, 400_000, &mut out);
    assert!(out.is_empty());
    rules::compute(&p, 400_001, &mut out);
    assert_eq!(out.len(), 1);
    out.clear();
    rules::upgrade(&p, "C383E1C5B1F578F3D1BF42F12360FCA67225B9ADDA0F3B6C293AD0D6B966818D", &mut out);
    assert!(out.is_empty(), "hash comparison is case-insensitive");
    rules::upgrade(&p, &"0".repeat(64), &mut out);
    assert_eq!(out[0].rule, "program-upgrade");
    out.clear();
    let mut flags = vec![false; 5];
    flags.extend(vec![true; 15]);
    rules::burst(&p, "pool", &flags, &mut out);
    assert!(out.is_empty(), "15 of 20 is at the limit, not over it");
    flags.push(true);
    rules::burst(&p, "pool", &flags, &mut out);
    assert_eq!(out.len(), 1);
}

#[test]
fn events_decode_and_forgeries_are_ignored() {
    let pool = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let logs = framed(&PROGRAM, vec![swap_log(&pool, &mint, 100, 200, 30), lp_log(&pool, 1_000, 50, 60, (5, 6), true)]);
    let (evs, truncated) = events(&PROGRAM, &logs);
    assert!(!truncated);
    assert_eq!(evs, vec![
        Event::Swap { pool, input_before: 100, output_before: 200, output_amount: 30, input_mint: mint },
        Event::Lp { pool, lp_before: 1_000, r0_before: 50, r1_before: 60, amount0: 5, amount1: 6, withdraw: true },
    ]);

    // Another program logging a CP-Swap-shaped event, even when invoked from
    // inside CP-Swap, is not CP-Swap's event.
    let attacker = Pubkey::new_unique();
    let mut forged = vec![format!("Program {PROGRAM} invoke [1]")];
    forged.extend(framed(&attacker, vec![swap_log(&pool, &mint, 100, 200, 199)]));
    forged.push(format!("Program {PROGRAM} success"));
    forged.extend(framed(&attacker, vec![swap_log(&pool, &mint, 1, 2, 3)]));
    assert!(events(&PROGRAM, &forged).0.is_empty());
    // A program writing "success" in its own log cannot pop its frame.
    let mut popped = framed(&attacker, vec!["Program log: success".into(), swap_log(&pool, &mint, 1, 2, 3)]);
    popped.insert(0, format!("Program {PROGRAM} invoke [1]"));
    assert!(events(&PROGRAM, &popped).0.is_empty());

    // Reserve outflow from the event: 30 of 200 is 1500 bps.
    let p = policy();
    let mut out = Vec::new();
    rules::event_outflow(&p, "pool", &evs[0], &mut out);
    assert_eq!(out.len(), 1);
}

#[test]
fn instruction_decoding() {
    let accounts: Vec<Pubkey> = (0..13).map(|_| Pubkey::new_unique()).collect();
    let ix = CpIx::decode(&ix_data("swap_base_input", &[1_000, 990]), accounts.clone());
    assert_eq!(ix.call, Call::SwapIn { amount_in: 1_000, min_out: 990 });
    assert_eq!(ix.pool(), Some(accounts[3]));
    assert_eq!(ix.user_accounts(), Some((accounts[4], accounts[5])));
    let ix = CpIx::decode(&ix_data("withdraw", &[7, 1, 2]), accounts.clone());
    assert_eq!((ix.call, ix.pool()), (Call::Withdraw { lp: 7, min0: 1, min1: 2 }, Some(accounts[2])));
    assert_eq!(CpIx::decode(&ix_data("update_pool_status", &[]), vec![]).call, Call::Other("update_pool_status"));
    assert_eq!(CpIx::decode(&[1, 2, 3], vec![]).call, Call::Unknown);
    // Truncated arguments are not misread as zero.
    assert_eq!(CpIx::decode(&ix_data("deposit", &[1, 2]), vec![]).call, Call::Unknown);
}
