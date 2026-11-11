use fuzzforge_scenarios::anchor::ix_discriminator;
use fuzzforge_scenarios::ShareValueLedger;

#[test]
fn anchor_discriminator_matches_known_value() {
    // token_vault IDL: "initialize" => afaf6d1f0d989bed
    assert_eq!(ix_discriminator("initialize"), [0xaf, 0xaf, 0x6d, 0x1f, 0x0d, 0x98, 0x9b, 0xed]);
}

#[test]
fn share_value_detects_drop_and_allows_growth() {
    let mut l = ShareValueLedger::default();
    assert!(l.observe("p", 1_000, 1_000, 1_000).is_none());
    // proportional deposit: unchanged value
    assert!(l.observe("p", 2_000, 2_000, 2_000).is_none());
    // swap with fee: k grows
    assert!(l.observe("p", 2_100, 1_910, 2_000).is_none());
    // one unit leaves reserves with no LP burned
    assert!(l.observe("p", 2_099, 1_910, 2_000).is_some());
}

#[test]
fn share_value_handles_256_bit_products() {
    let mut l = ShareValueLedger::default();
    let big = u64::MAX / 2;
    assert!(l.observe("p", big, big, big).is_none());
    assert!(l.observe("p", big, big - 1, big).is_some());
    assert!(l.observe("p", big, big, big).is_none());
}

#[test]
fn deposit_fairness_flags_inflated_share_price() {
    use fuzzforge_scenarios::invariants::deposit_fairness;
    // Fair: 1,000 in for 1,000 of 2,000 shares over a 2,000 reserve.
    assert!(deposit_fairness("v", "token0", 1_000, 1_000, 2_000, 2_000, 1).is_none());
    // One unit of rounding is tolerated.
    assert!(deposit_fairness("v", "token0", 1_000, 999, 2_000, 2_000, 1).is_none());
    // Inflated price: attacker holds 1 share over a 1,000,001 reserve; the
    // victim's 999,999 buys zero shares.
    let msg = deposit_fairness("v", "token0", 999_999, 0, 2_000_000, 1, 1).unwrap();
    assert!(msg.contains("[deposit-fairness]") && msg.contains("lost 999999"), "{msg}");
}

#[test]
fn compute_profile_tracks_high_water_and_limit() {
    use fuzzforge_scenarios::compute;
    assert!(compute::observe("candidate", "t_swap", "lane", 50_000).is_none());
    assert!(compute::observe("candidate", "t_swap", "lane", 40_000).is_none());
    let over = compute::observe("candidate", "t_exit", "lane", compute::limit() + 1).unwrap();
    assert!(over.starts_with("[compute] lane: t_exit used"), "{over}");
    let rows = compute::high_water();
    assert!(rows.iter().any(|r| r.0 == 50_000 && r.2 == "t_swap"));
    assert!(compute::exhausted(&["Program X failed: exceeded CUs meter at BPF instruction".to_string()]));
    assert!(!compute::exhausted(&["Program log: fine".to_string()]));
}

#[test]
fn outcome_difference_ignores_error_wording() {
    use fuzzforge_scenarios::diff::outcome_difference;
    let ok: Result<(), String> = Ok(());
    let e1: Result<(), String> = Err("a".into());
    let e2: Result<(), String> = Err("b".into());
    assert!(outcome_difference("swap", &ok, &ok).is_none());
    assert!(outcome_difference("swap", &e1, &e2).is_none());
    let d = outcome_difference("swap", &ok, &e1).unwrap();
    assert!(d.contains("succeeded on the candidate") && d.contains("failed (a) on the reference"), "{d}");
}

#[test]
fn vault_rate_detects_drop_and_allows_rounding_in_the_vaults_favour() {
    use fuzzforge_scenarios::invariants::vault_rate_fell;
    let (l, s) = (10_235_872_059_163_881u64, 7_808_016_567_176_049u64);
    // Deposit of 1 SOL minting floor(1e9 * s / l) shares: rate cannot fall.
    let minted = (1_000_000_000u128 * s as u128 / l as u128) as u64;
    assert!(!vault_rate_fell((l, s), (l + 1_000_000_000, s + minted)));
    // Minting one share more than that would dilute holders.
    assert!(vault_rate_fell((l, s), (l + 1_000_000_000, s + minted + 1)));
    // Losing one lamport with no shares burnt.
    assert!(vault_rate_fell((l, s), (l - 1, s)));
    assert!(!vault_rate_fell((l, 0), (0, 0)));
}

#[test]
fn supply_inflation_is_one_sided() {
    use fuzzforge_scenarios::invariants::supply_inflated;
    assert!(supply_inflated("p", 100, 100).is_none());
    assert!(supply_inflated("p", 100, 99).is_none(), "a holder burning shares is a donation");
    assert!(supply_inflated("p", 100, 101).is_some());
}
