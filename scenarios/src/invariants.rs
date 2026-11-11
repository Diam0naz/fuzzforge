//! Reusable invariant ledgers.
//!
//! Actions record what *should* have happened; the `#[invariant_test]` compares
//! that against what the SVM shows. Keeping the bookkeeping here means every
//! engagement asserts the same properties with the same wording, which keeps
//! reports comparable across clients.

/// Custody invariant: a custodial account's balance changes only through the
/// program's own authorized flows.
///
/// Feed it the *observed* balance delta after every authorized deposit or
/// withdrawal. Any other movement (a delegate pull, a hook, a CPI side effect)
/// shows up as a mismatch between [`CustodyLedger::expected`] and the real balance.
#[derive(Clone, Debug, Default)]
pub struct CustodyLedger {
    expected: u64,
    pub sent_in: u128,
    pub received_in: u128,
    pub sent_out: u128,
}

impl CustodyLedger {
    /// An authorized inflow: `sent` is the amount the user asked to transfer,
    /// `received` the balance delta the custody account actually saw.
    pub fn credit(&mut self, sent: u64, received: u64) {
        self.expected = self.expected.saturating_add(received);
        self.sent_in += sent as u128;
        self.received_in += received as u128;
    }

    /// An authorized outflow, measured as the custody account's balance delta.
    pub fn debit(&mut self, removed: u64) {
        self.expected = self.expected.saturating_sub(removed);
        self.sent_out += removed as u128;
    }

    /// The account was closed by an authorized flow.
    pub fn reset(&mut self) {
        self.expected = 0;
    }

    pub fn expected(&self) -> u64 {
        self.expected
    }

    /// Value lost between what users sent and what custody received. Non-zero
    /// for fee-on-transfer mints: a program that credits `amount` rather than
    /// the received delta is insolvent by exactly this much.
    pub fn inflow_shortfall(&self) -> u128 {
        self.sent_in.saturating_sub(self.received_in)
    }

    /// `None` when the balance matches, otherwise a human-readable violation.
    pub fn check(&self, label: &str, actual: u64) -> Option<String> {
        (actual != self.expected).then(|| {
            format!(
                "[custody] {label}: balance {actual} != expected {} from authorized flows (third-party movement)",
                self.expected
            )
        })
    }
}

/// Liveness invariant: an operation that the program's own rules say must be
/// possible (the owner exiting a vault, a user withdrawing their position)
/// actually succeeds. Actions push a violation when it does not.
#[derive(Clone, Debug, Default)]
pub struct LivenessLog {
    violations: Vec<String>,
}

impl LivenessLog {
    pub fn fail(&mut self, kind: &str, label: &str, detail: impl AsRef<str>) {
        self.violations.push(format!("[liveness:{kind}] {label}: {}", detail.as_ref()));
    }

    pub fn first(&self) -> Option<&String> {
        self.violations.first()
    }

    pub fn is_empty(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Constant-product AMM invariant: the value of one LP share,
/// `sqrt(reserve_0 * reserve_1) / lp_supply`, never decreases.
///
/// Reserves must exclude fees owed to anyone other than LPs (protocol, fund,
/// creator). Swaps add trade fees to reserves and so raise share value; correct
/// deposit (round up) and withdrawal (round down) never lower it. A drop means
/// some actor extracted LP value: a rounding direction bug, a transfer-fee
/// calculation that leaves the vault short, or accounting that disagrees with
/// the real vault balances.
///
/// Compared exactly: `r0' * r1' * lp^2 >= r0 * r1 * lp'^2` in 256-bit arithmetic.
#[derive(Clone, Debug, Default)]
pub struct ShareValueLedger {
    last: Option<(u64, u64, u64)>,
}

fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    // (hi, lo) of a 256-bit product, schoolbook on 64-bit limbs.
    let (a1, a0) = (a >> 64, a & u64::MAX as u128);
    let (b1, b0) = (b >> 64, b & u64::MAX as u128);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & u64::MAX as u128) + (p10 & u64::MAX as u128);
    let lo = (p00 & u64::MAX as u128) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

/// `true` when one LP share is worth less in `now` than in `prev`. Each state
/// is `(reserve_0, reserve_1, lp_supply)` with reserves net of fees owed to
/// anyone other than LPs. A zero supply on either side is not comparable and
/// returns `false`.
///
/// This is the whole share-value rule. The fuzz harness asserts it after every
/// action and the runtime monitor and firewall in `sentinel/` call the same
/// function on live pool state, so a rule that was fuzzed is the rule enforced.
pub fn share_value_fell(prev: (u64, u64, u64), now: (u64, u64, u64)) -> bool {
    let ((p0, p1, plp), (r0, r1, lp)) = (prev, now);
    if lp == 0 || plp == 0 {
        return false;
    }
    let k_now = r0 as u128 * r1 as u128;
    let k_prev = p0 as u128 * p1 as u128;
    mul_wide(k_now, plp as u128 * plp as u128) < mul_wide(k_prev, lp as u128 * lp as u128)
}

/// Solvency: each vault holds at least the fees booked against it (protocol,
/// fund, creator). `None` when it does, otherwise the violation.
pub fn solvency(label: &str, vaults: (u64, u64), fees: (u64, u64)) -> Option<String> {
    (vaults.0 < fees.0 || vaults.1 < fees.1).then(|| {
        format!(
            "[solvency] {label}: vaults ({}, {}) hold less than booked fees ({}, {})",
            vaults.0, vaults.1, fees.0, fees.1
        )
    })
}

/// Vault invariant: assets per share never fall. `prev` and `now` are
/// `(assets, shares)`. This is the share-value rule for a single-asset vault
/// (a stake pool, a lending reserve's cToken, an ERC-4626-style vault): a
/// correct deposit rounds the shares it mints down and a correct withdrawal
/// rounds the assets it pays down, so neither lowers the rate. Zero shares on
/// either side is not comparable and returns `false`.
pub fn vault_rate_fell(prev: (u64, u64), now: (u64, u64)) -> bool {
    let ((a, s), (a2, s2)) = (prev, now);
    if s == 0 || s2 == 0 {
        return false;
    }
    // a2 / s2 < a / s  <=>  a2 * s < a * s2
    (a2 as u128) * (s as u128) < (a as u128) * (s2 as u128)
}

/// Supply invariant: the share mint's real supply never exceeds the supply
/// the program's own accounting records. Shares minted outside the
/// accounting (an unchecked mint authority, a missed update) dilute every
/// holder. The reverse, a holder burning their own shares, is a donation and
/// is allowed.
pub fn supply_inflated(label: &str, recorded: u64, mint_supply: u64) -> Option<String> {
    (mint_supply > recorded).then(|| {
        format!("[supply] {label}: share mint supply {mint_supply} exceeds the {recorded} the program accounts for ({} unbacked)", mint_supply - recorded)
    })
}

impl ShareValueLedger {
    /// Record the current state and report a violation if share value fell
    /// since the previous call. `lp_supply == 0` resets the baseline.
    pub fn observe(&mut self, label: &str, r0: u64, r1: u64, lp: u64) -> Option<String> {
        let prev = self.last.replace((r0, r1, lp));
        let (p0, p1, plp) = prev?;
        share_value_fell((p0, p1, plp), (r0, r1, lp)).then(|| {
            format!(
                "[share-value] {label}: LP share value decreased: reserves ({p0}, {p1}) / lp {plp} -> ({r0}, {r1}) / lp {lp}"
            )
        })
    }

    pub fn reset(&mut self) {
        self.last = None;
    }
}

/// Deposit fairness: what a depositor could withdraw immediately afterwards is
/// worth what the vault took from them, up to `tolerance` base units of
/// rounding.
///
/// This is the victim's side of the donation (share inflation) attack. Share
/// value never falls in that attack, so [`ShareValueLedger`] stays quiet; the
/// loss is the depositor's, whose shares round down while the attacker's
/// earlier shares absorb the difference.
///
/// `inflow` is what the vault received on one side, `shares` what the
/// depositor was minted, `reserve_after` and `supply_after` the LP-owned
/// reserve on that side and the share supply once the deposit landed.
pub fn deposit_fairness(label: &str, side: &str, inflow: u64, shares: u64, reserve_after: u64, supply_after: u64, tolerance: u64) -> Option<String> {
    if supply_after == 0 {
        return None;
    }
    let claim = (shares as u128 * reserve_after as u128 / supply_after as u128) as u64;
    (claim.saturating_add(tolerance) < inflow).then(|| {
        format!(
            "[deposit-fairness] {label}: deposit put {inflow} of {side} into the vault for {shares} shares that redeem for only {claim} (lost {})",
            inflow - claim
        )
    })
}

/// Pull the most informative line out of a failed transaction's logs.
pub fn summarize_logs(logs: &[String]) -> String {
    logs.iter()
        .rev()
        .find(|l| l.contains("Error") || l.contains("failed") || l.contains("error"))
        .or_else(|| logs.last())
        .cloned()
        .unwrap_or_else(|| "no logs".into())
}
