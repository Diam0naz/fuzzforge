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

impl ShareValueLedger {
    /// Record the current state and report a violation if share value fell
    /// since the previous call. `lp_supply == 0` resets the baseline.
    pub fn observe(&mut self, label: &str, r0: u64, r1: u64, lp: u64) -> Option<String> {
        let prev = self.last.replace((r0, r1, lp));
        let (p0, p1, plp) = prev?;
        if lp == 0 || plp == 0 {
            return None;
        }
        let k_now = r0 as u128 * r1 as u128;
        let k_prev = p0 as u128 * p1 as u128;
        let lhs = mul_wide(k_now, plp as u128 * plp as u128);
        let rhs = mul_wide(k_prev, lp as u128 * lp as u128);
        (lhs < rhs).then(|| {
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
