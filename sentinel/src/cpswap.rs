//! What the monitor and firewall need to know about Raydium CP-Swap: account
//! layouts, instruction arguments and the two events the program logs.
//!
//! This file is the per-protocol adapter. The rules themselves live in
//! `fuzzforge-scenarios` and `rules.rs` and are protocol-agnostic.

use base64::Engine;
use fuzzforge_scenarios::anchor::{account_discriminator, ix_discriminator, read_pubkey, read_u64};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::sync::OnceLock;

pub const POOL_STATE_LEN: usize = 637;

// PoolState is #[repr(C, packed)]; offsets include the 8-byte discriminator.
// The same offsets are used by the fuzz harness in targets/raydium_cp_swap.
const OFF_AMM_CONFIG: usize = 8;
const OFF_VAULT_0: usize = 72;
const OFF_VAULT_1: usize = 104;
const OFF_LP_MINT: usize = 136;
const OFF_MINT_0: usize = 168;
const OFF_MINT_1: usize = 200;
const OFF_PROGRAM_0: usize = 232;
const OFF_PROGRAM_1: usize = 264;
const OFF_OBSERVATION: usize = 296;
const OFF_LP_SUPPLY: usize = 333;
const OFF_PROTOCOL_FEES_0: usize = 341;
const OFF_PROTOCOL_FEES_1: usize = 349;
const OFF_FUND_FEES_0: usize = 357;
const OFF_FUND_FEES_1: usize = 365;
const OFF_CREATOR_FEES_0: usize = 397;
const OFF_CREATOR_FEES_1: usize = 405;

/// The addresses a pool is made of, read from its state account.
#[derive(Clone, Debug)]
pub struct PoolKeys {
    pub state: Pubkey,
    pub amm_config: Pubkey,
    pub vault0: Pubkey,
    pub vault1: Pubkey,
    pub lp_mint: Pubkey,
    pub mint0: Pubkey,
    pub mint1: Pubkey,
    pub program0: Pubkey,
    pub program1: Pubkey,
    pub observation: Pubkey,
}

impl PoolKeys {
    /// `None` unless `data` is a CP-Swap `PoolState`.
    pub fn decode(state: Pubkey, data: &[u8]) -> Option<Self> {
        if data.len() != POOL_STATE_LEN || data[..8] != account_discriminator("PoolState") {
            return None;
        }
        Some(Self {
            state,
            amm_config: read_pubkey(data, OFF_AMM_CONFIG),
            vault0: read_pubkey(data, OFF_VAULT_0),
            vault1: read_pubkey(data, OFF_VAULT_1),
            lp_mint: read_pubkey(data, OFF_LP_MINT),
            mint0: read_pubkey(data, OFF_MINT_0),
            mint1: read_pubkey(data, OFF_MINT_1),
            program0: read_pubkey(data, OFF_PROGRAM_0),
            program1: read_pubkey(data, OFF_PROGRAM_1),
            observation: read_pubkey(data, OFF_OBSERVATION),
        })
    }
}

/// A pool's accounting at one instant: real vault balances, the fees booked
/// against them, and the LP supply the program tracks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolView {
    pub vault0: u64,
    pub vault1: u64,
    pub fees0: u64,
    pub fees1: u64,
    pub lp_supply: u64,
}

impl PoolView {
    pub fn decode(pool: &[u8], vault0: &[u8], vault1: &[u8]) -> Option<Self> {
        if pool.len() != POOL_STATE_LEN {
            return None;
        }
        Some(Self {
            vault0: token_amount(vault0)?,
            vault1: token_amount(vault1)?,
            fees0: read_u64(pool, OFF_PROTOCOL_FEES_0) + read_u64(pool, OFF_FUND_FEES_0) + read_u64(pool, OFF_CREATOR_FEES_0),
            fees1: read_u64(pool, OFF_PROTOCOL_FEES_1) + read_u64(pool, OFF_FUND_FEES_1) + read_u64(pool, OFF_CREATOR_FEES_1),
            lp_supply: read_u64(pool, OFF_LP_SUPPLY),
        })
    }

    /// Reserves owned by LPs: vault balances minus booked fees.
    pub fn reserves(&self) -> (u64, u64) {
        (self.vault0.saturating_sub(self.fees0), self.vault1.saturating_sub(self.fees1))
    }

    pub fn state(&self) -> (u64, u64, u64) {
        let (r0, r1) = self.reserves();
        (r0, r1, self.lp_supply)
    }
}

/// `amount` of an SPL Token or Token-2022 account (same offset in both).
pub fn token_amount(data: &[u8]) -> Option<u64> {
    (data.len() >= 72).then(|| read_u64(data, 64))
}

/// A CP-Swap instruction with the arguments the rules need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    SwapIn { amount_in: u64, min_out: u64 },
    SwapOut { max_in: u64, amount_out: u64 },
    Deposit { lp: u64, max0: u64, max1: u64 },
    Withdraw { lp: u64, min0: u64, min1: u64 },
    /// Any other instruction of the program, by name.
    Other(&'static str),
    Unknown,
}

const OTHER: [&str; 18] = [
    "create_amm_config",
    "update_amm_config",
    "update_pool_status",
    "collect_protocol_fee",
    "collect_fund_fee",
    "collect_creator_fee",
    "collect_creator_fee_permissionless",
    "create_permission_pda",
    "close_permission_pda",
    "create_creator_fee_share",
    "close_creator_fee_share",
    "initialize",
    "initialize_v2",
    "initialize_with_permission",
    "create_support_mint_associated",
    "close_support_mint_associated",
    "collect_excess_lamports",
    "update_creator_fee_share",
];

fn other_table() -> &'static Vec<([u8; 8], &'static str)> {
    static TABLE: OnceLock<Vec<([u8; 8], &'static str)>> = OnceLock::new();
    TABLE.get_or_init(|| OTHER.iter().map(|n| (ix_discriminator(n), *n)).collect())
}

/// One invocation of the program: decoded call plus its accounts in order.
#[derive(Clone, Debug)]
pub struct CpIx {
    pub call: Call,
    pub accounts: Vec<Pubkey>,
}

impl CpIx {
    pub fn decode(data: &[u8], accounts: Vec<Pubkey>) -> Self {
        let arg = |i: usize| data.get(8 + i * 8..16 + i * 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
        let args = |n: usize| (0..n).map(arg).collect::<Option<Vec<u64>>>();
        let disc = data.get(..8);
        let is = |name: &str| disc == Some(&ix_discriminator(name)[..]);
        let call = if is("swap_base_input") {
            args(2).map(|a| Call::SwapIn { amount_in: a[0], min_out: a[1] })
        } else if is("swap_base_output") {
            args(2).map(|a| Call::SwapOut { max_in: a[0], amount_out: a[1] })
        } else if is("deposit") {
            args(3).map(|a| Call::Deposit { lp: a[0], max0: a[1], max1: a[2] })
        } else if is("withdraw") {
            args(3).map(|a| Call::Withdraw { lp: a[0], min0: a[1], min1: a[2] })
        } else {
            other_table().iter().find(|(d, _)| disc == Some(&d[..])).map(|(_, n)| Call::Other(n))
        };
        Self { call: call.unwrap_or(Call::Unknown), accounts }
    }

    /// The pool a swap, deposit or withdrawal acts on.
    pub fn pool(&self) -> Option<Pubkey> {
        match self.call {
            Call::SwapIn { .. } | Call::SwapOut { .. } => self.accounts.get(3).copied(),
            Call::Deposit { .. } | Call::Withdraw { .. } => self.accounts.get(2).copied(),
            _ => None,
        }
    }

    /// The user's token accounts as `(first, second)`: input and output for a
    /// swap, token 0 and token 1 for a deposit or withdrawal.
    pub fn user_accounts(&self) -> Option<(Pubkey, Pubkey)> {
        match self.call {
            Call::Other(_) | Call::Unknown => None,
            _ => Some((*self.accounts.get(4)?, *self.accounts.get(5)?)),
        }
    }

    pub fn emits_event(&self) -> bool {
        !matches!(self.call, Call::Other(_) | Call::Unknown)
    }

    pub fn name(&self) -> &'static str {
        match self.call {
            Call::SwapIn { .. } => "swap_base_input",
            Call::SwapOut { .. } => "swap_base_output",
            Call::Deposit { .. } => "deposit",
            Call::Withdraw { .. } => "withdraw",
            Call::Other(n) => n,
            Call::Unknown => "unknown",
        }
    }
}

/// The two events CP-Swap logs. Reserves are "vault minus booked fees", i.e.
/// exactly the LP-owned reserves the share-value rule is defined on, taken
/// before the instruction's own effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Swap { pool: Pubkey, input_before: u64, output_before: u64, output_amount: u64, input_mint: Pubkey },
    Lp { pool: Pubkey, lp_before: u64, r0_before: u64, r1_before: u64, amount0: u64, amount1: u64, withdraw: bool },
}

impl Event {
    pub fn pool(&self) -> Pubkey {
        match self {
            Event::Swap { pool, .. } | Event::Lp { pool, .. } => *pool,
        }
    }
}

fn event_discriminator(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("event:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn decode_event(bytes: &[u8]) -> Option<Event> {
    let (disc, d) = (bytes.get(..8)?, bytes.get(8..)?);
    if disc == event_discriminator("SwapEvent") && d.len() >= 113 {
        Some(Event::Swap {
            pool: read_pubkey(d, 0),
            input_before: read_u64(d, 32),
            output_before: read_u64(d, 40),
            output_amount: read_u64(d, 56),
            input_mint: read_pubkey(d, 81),
        })
    } else if disc == event_discriminator("LpChangeEvent") && d.len() >= 89 {
        Some(Event::Lp {
            pool: read_pubkey(d, 0),
            lp_before: read_u64(d, 32),
            r0_before: read_u64(d, 40),
            r1_before: read_u64(d, 48),
            amount0: read_u64(d, 56),
            amount1: read_u64(d, 64),
            withdraw: d[88] == 1,
        })
    } else {
        None
    }
}

/// Events logged by `program` itself. Returns the events and whether the log
/// was truncated by the runtime.
///
/// A `Program data:` line is accepted only while `program` is the innermost
/// frame of the invoke stack, so another program in the same transaction
/// cannot forge an event to mislead the monitor.
pub fn events(program: &Pubkey, logs: &[String]) -> (Vec<Event>, bool) {
    let me = program.to_string();
    let mut stack: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    let mut truncated = false;
    for line in logs {
        if line == "Log truncated" {
            truncated = true;
        } else if let Some(rest) = line.strip_prefix("Program data: ") {
            if stack.last() == Some(&me.as_str()) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                    out.extend(decode_event(&bytes));
                }
            }
        } else if let Some(rest) = line.strip_prefix("Program ") {
            let mut parts = rest.splitn(3, ' ');
            let (id, verb) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            // Programs can only write "Program log:" / "Program data:" lines,
            // never one that names a real program id, so frames cannot be faked.
            if id.parse::<Pubkey>().is_err() {
                continue;
            }
            match verb {
                "invoke" => stack.push(id),
                "success" | "failed:" => {
                    stack.pop();
                }
                _ => {}
            }
        }
    }
    (out, truncated)
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub fn swap_log(pool: &Pubkey, input_mint: &Pubkey, input_before: u64, output_before: u64, output_amount: u64) -> String {
        let mut d = event_discriminator("SwapEvent").to_vec();
        d.extend_from_slice(pool.as_ref());
        for v in [input_before, output_before, 0, output_amount, 0, 0] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.push(1);
        d.extend_from_slice(input_mint.as_ref());
        d.extend_from_slice(&[0u8; 32 + 8 + 8 + 1]);
        format!("Program data: {}", base64::engine::general_purpose::STANDARD.encode(d))
    }

    pub fn lp_log(pool: &Pubkey, lp_before: u64, r0: u64, r1: u64, amounts: (u64, u64), withdraw: bool) -> String {
        let mut d = event_discriminator("LpChangeEvent").to_vec();
        d.extend_from_slice(pool.as_ref());
        for v in [lp_before, r0, r1, amounts.0, amounts.1, 0, 0] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.push(withdraw as u8);
        format!("Program data: {}", base64::engine::general_purpose::STANDARD.encode(d))
    }

    pub fn framed(program: &Pubkey, body: Vec<String>) -> Vec<String> {
        let mut logs = vec![format!("Program {program} invoke [1]")];
        logs.extend(body);
        logs.push(format!("Program {program} success"));
        logs
    }

    pub fn ix_data(name: &str, args: &[u64]) -> Vec<u8> {
        let mut d = ix_discriminator(name).to_vec();
        for a in args {
            d.extend_from_slice(&a.to_le_bytes());
        }
        d
    }
}
