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
