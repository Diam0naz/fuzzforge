//! The per-protocol layer. A protocol adapter says which accounts make up a
//! market (a pool, a vault), how to read a [`Snapshot`] from them, and which
//! fuzz-validated predicate decides that value per share fell. Everything
//! else (rules, fork, monitor, policy) is shared.

use crate::cpswap::{self, PoolView};
use crate::stakepool::{mint_supply, StakePool};
use fuzzforge_scenarios::invariants::{share_value_fell, solvency, supply_inflated, vault_rate_fell};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Constant-product AMM: two reserves net of booked fees, LP shares.
    RaydiumCpSwap,
    /// Single-asset share vault: total lamports, pool-token shares.
    SplStakePool,
}

/// One market and the accounts a snapshot of it needs, read together.
#[derive(Clone, Debug)]
pub struct Market {
    pub key: Pubkey,
    pub reads: Vec<Pubkey>,
}

/// What the shared rules see. `reserves` are the assets owned by share
/// holders; `problems` are accounting violations found while decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub reserves: Vec<u64>,
    pub shares: u64,
    pub problems: Vec<String>,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::RaydiumCpSwap => "raydium-cp-swap",
            Protocol::SplStakePool => "spl-stake-pool",
        }
    }

    /// `Some` when `data` is a market account of this protocol.
    pub fn market(&self, key: Pubkey, data: &[u8]) -> Option<Market> {
        match self {
            Protocol::RaydiumCpSwap => cpswap::PoolKeys::decode(key, data).map(|k| Market { key, reads: vec![key, k.vault0, k.vault1] }),
            Protocol::SplStakePool => StakePool::decode(key, data).map(|p| Market { key, reads: vec![key, p.pool_mint] }),
        }
    }

    /// Snapshot from the account data of `market.reads`, in order.
    pub fn snapshot(&self, label: &str, data: &[&[u8]]) -> Option<Snapshot> {
        match self {
            Protocol::RaydiumCpSwap => Some(PoolView::decode(data.first()?, data.get(1)?, data.get(2)?)?.snapshot(label)),
            Protocol::SplStakePool => {
                let pool = StakePool::decode(Pubkey::default(), data.first()?)?;
                let supply = mint_supply(data.get(1)?)?;
                Some(Snapshot {
                    reserves: vec![pool.total_lamports],
                    shares: pool.pool_token_supply,
                    problems: supply_inflated(label, pool.pool_token_supply, supply).into_iter().collect(),
                })
            }
        }
    }

    /// The fuzz-validated "value per share fell" predicate for this shape.
    pub fn value_fell(&self, prev: &Snapshot, now: &Snapshot) -> bool {
        match self {
            Protocol::RaydiumCpSwap => share_value_fell((prev.reserves[0], prev.reserves[1], prev.shares), (now.reserves[0], now.reserves[1], now.shares)),
            Protocol::SplStakePool => vault_rate_fell((prev.reserves[0], prev.shares), (now.reserves[0], now.shares)),
        }
    }
}

impl PoolView {
    pub fn snapshot(&self, label: &str) -> Snapshot {
        let (r0, r1) = self.reserves();
        Snapshot {
            reserves: vec![r0, r1],
            shares: self.lp_supply,
            problems: solvency(label, (self.vault0, self.vault1), (self.fees0, self.fees1)).into_iter().collect(),
        }
    }
}
