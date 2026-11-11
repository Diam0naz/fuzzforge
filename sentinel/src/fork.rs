//! Simulate-before-sign: clone every account a transaction touches from the
//! cluster into a local LiteSVM, run the transaction there, and diff the
//! accounts before and after. Nothing is sent to the cluster.

use crate::rpc::Rpc;
use anyhow::{anyhow, bail, Context, Result};
use crucible_test_context::TestContext;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_clock::Clock;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use std::collections::HashMap;

const UPGRADEABLE_LOADER: Pubkey = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const SYSVAR_CLOCK: Pubkey = Pubkey::from_str_const("SysvarC1ock11111111111111111111111111111111");
const PROGRAMDATA_HEADER: usize = 45;
const LOOKUP_TABLE_HEADER: usize = 56;

pub struct Fork {
    pub ctx: TestContext,
    /// The transaction's full account list, lookup tables resolved.
    pub keys: Vec<Pubkey>,
    /// Accounts as cloned, keyed by address (`None`: did not exist yet).
    pub pre: HashMap<Pubkey, Option<Account>>,
    /// SHA-256 of each cloned upgradeable program's deployed bytes
    /// (programdata after the 45-byte header, as `solana program dump` writes).
    pub program_sha256: HashMap<Pubkey, String>,
    pub slot: u64,
    /// Where the local run may differ from the cluster, for the decision record.
    pub notes: Vec<String>,
}

/// Local changes on top of cloned state, for drills: synthetic accounts, and
/// replacement bytes for a program (an upgrade that has not happened yet).
#[derive(Default)]
pub struct Overlay {
    pub accounts: Vec<(Pubkey, Account)>,
    pub program: Option<(Pubkey, Vec<u8>)>,
}

/// Outcome of the local run.
pub struct Simulation {
    pub ok: bool,
    pub error: Option<String>,
    pub compute_units: u64,
    pub logs: Vec<String>,
}

pub fn decode_tx(wire: &str) -> Result<VersionedTransaction> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(wire.trim())
        .or_else(|_| bs58::decode(wire.trim()).into_vec())
        .context("transaction is neither base64 nor base58")?;
    // wincode reads legacy, v0 and v1 (signatures after the message) layouts.
    wincode::deserialize(&bytes).map_err(|e| anyhow!("not a serialized transaction: {e}"))
}

pub fn encode_tx(tx: &VersionedTransaction) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(wincode::serialize(tx).expect("serializable"))
}

/// The full account list: static keys, then every table's writable entries,
/// then every table's readonly entries (the runtime's order).
pub fn resolve_keys(rpc: &Rpc, tx: &VersionedTransaction) -> Result<(Vec<Pubkey>, Vec<(Pubkey, Account)>)> {
    let mut keys: Vec<Pubkey> = tx.message.static_account_keys().to_vec();
    let Some(lookups) = tx.message.address_table_lookups().filter(|l| !l.is_empty()) else {
        return Ok((keys, Vec::new()));
    };
    let table_keys: Vec<Pubkey> = lookups.iter().map(|l| l.account_key).collect();
    let (_, tables) = rpc.accounts(&table_keys)?;
    let mut entries = Vec::new();
    let mut readonly = Vec::new();
    for (lookup, table) in lookups.iter().zip(tables) {
        let table = table.ok_or_else(|| anyhow!("lookup table {} does not exist", lookup.account_key))?;
        let addresses: Vec<Pubkey> = table.data[LOOKUP_TABLE_HEADER.min(table.data.len())..]
            .chunks_exact(32)
            .map(|c| Pubkey::new_from_array(c.try_into().unwrap()))
            .collect();
        let pick = |i: &u8| addresses.get(*i as usize).copied().ok_or_else(|| anyhow!("lookup index {i} out of range in {}", lookup.account_key));
        for i in &lookup.writable_indexes {
            keys.push(pick(i)?);
        }
        for i in &lookup.readonly_indexes {
            readonly.push(pick(i)?);
        }
        entries.push((lookup.account_key, table));
    }
    keys.extend(readonly);
    Ok((keys, entries))
}

impl Fork {
    /// Clone what `tx` needs. `extra` adds accounts the rules read that the
    /// transaction may not list (a pool's vaults, for instance).
    pub fn build(rpc: &Rpc, tx: &VersionedTransaction, extra: &[Pubkey], overlay: &Overlay) -> Result<Self> {
        let (keys, tables) = resolve_keys(rpc, tx)?;
        let mut notes = Vec::new();
        let mut ctx = TestContext::new();
        // LiteSVM 0.15 reads compute limits only from ComputeBudget
        // instructions; a v1 message carries its limit in the message itself.
        if let solana_message::VersionedMessage::V1(m) = &tx.message {
            let limit = m.config.compute_unit_limit.unwrap_or(200_000);
            ctx = ctx.with_compute_budget(limit as u64);
            notes.push(format!("v1 message: compute limit {limit} applied from the message config"));
            if m.config.heap_size.is_some() {
                notes.push("v1 message: requested heap size is not modelled (32 KiB used)".into());
            }
        }
        let mut pre = HashMap::new();
        let mut program_sha256 = HashMap::new();
        for (k, table) in tables {
            ctx.write_account(&k, table)?;
        }
        let mut wanted: Vec<Pubkey> = Vec::new();
        for k in keys.iter().chain(extra) {
            if wanted.contains(k) || overlay.accounts.iter().any(|(o, _)| o == k) {
                continue;
            }
            // Builtins, sysvars and LiteSVM's bundled SPL programs stay local.
            if let Some(local) = ctx.svm.get_account(k) {
                if local.executable || local.owner == solana_pubkey::pubkey!("Sysvar1111111111111111111111111111111111111") {
                    continue;
                }
            }
            wanted.push(*k);
        }
        wanted.push(SYSVAR_CLOCK);
        let (slot, accounts) = rpc.accounts(&wanted)?;
        for (k, acc) in wanted.iter().zip(accounts) {
            if *k == SYSVAR_CLOCK {
                let d = acc.ok_or_else(|| anyhow!("no clock sysvar"))?.data;
                if d.len() < 40 {
                    bail!("clock sysvar too short");
                }
                let r = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
                let clock = Clock { slot: r(0), epoch_start_timestamp: r(8) as i64, epoch: r(16), leader_schedule_epoch: r(24), unix_timestamp: r(32) as i64 };
                ctx.svm.warp_to_slot(clock.slot);
                ctx.svm.set_sysvar(&clock);
                continue;
            }
            match &acc {
                Some(a) if a.executable && a.owner == UPGRADEABLE_LOADER => {
                    let programdata = Pubkey::new_from_array(a.data.get(4..36).ok_or_else(|| anyhow!("{k}: bad program account"))?.try_into().unwrap());
                    let (_, pd) = rpc.accounts(&[programdata])?;
                    let pd = pd.into_iter().next().flatten().ok_or_else(|| anyhow!("{k}: programdata {programdata} missing"))?;
                    let elf = pd.data.get(PROGRAMDATA_HEADER..).ok_or_else(|| anyhow!("{k}: programdata too short"))?;
                    program_sha256.insert(*k, crate::policy::hex(&Sha256::digest(elf)));
                    ctx.add_program_from_bytes(k, elf).with_context(|| format!("loading program {k}"))?;
                }
                Some(a) if a.executable => ctx.add_program_from_bytes(k, &a.data).with_context(|| format!("loading program {k}"))?,
                Some(a) => ctx.write_account(k, a.clone())?,
                None => {}
            }
            pre.insert(*k, acc);
        }
        if !overlay.accounts.is_empty() {
            notes.push(format!("drill: {} accounts supplied locally (pool snapshot and synthetic user)", overlay.accounts.len()));
        }
        for (k, a) in &overlay.accounts {
            ctx.write_account(k, a.clone())?;
            pre.insert(*k, Some(a.clone()));
        }
        if let Some((program, bytes)) = &overlay.program {
            ctx.add_program_from_bytes(program, bytes).context("loading replacement program")?;
            program_sha256.insert(*program, crate::policy::hex(&Sha256::digest(bytes)));
            notes.push(format!("drill: {program} replaced by local bytes"));
        }
        Ok(Fork { ctx, keys, pre, program_sha256, slot, notes })
    }

    /// Clone more plain (non-program) accounts after the fact.
    pub fn add(&mut self, rpc: &Rpc, keys: &[Pubkey]) -> Result<()> {
        let missing: Vec<Pubkey> = keys.iter().filter(|k| !self.pre.contains_key(k)).copied().collect();
        if missing.is_empty() {
            return Ok(());
        }
        let (_, accounts) = rpc.accounts(&missing)?;
        for (k, acc) in missing.iter().zip(accounts) {
            if let Some(a) = &acc {
                self.ctx.write_account(k, a.clone())?;
            }
            self.pre.insert(*k, acc);
        }
        Ok(())
    }

    pub fn simulate(&mut self, tx: &VersionedTransaction) -> Simulation {
        match self.ctx.svm.send_transaction(tx.clone()) {
            Ok(meta) => Simulation { ok: true, error: None, compute_units: meta.compute_units_consumed, logs: meta.logs },
            Err(f) => Simulation { ok: false, error: Some(f.err.to_string()), compute_units: f.meta.compute_units_consumed, logs: f.meta.logs },
        }
    }

    pub fn pre_data(&self, k: &Pubkey) -> Option<&[u8]> {
        self.pre.get(k)?.as_ref().map(|a| a.data.as_slice())
    }

    pub fn post(&self, k: &Pubkey) -> Option<Account> {
        self.ctx.svm.get_account(k).filter(|a| a.lamports > 0)
    }
}

/// Every program the run invoked, at any depth, in first-seen order.
pub fn invoked_programs(logs: &[String]) -> Vec<Pubkey> {
    let mut out: Vec<Pubkey> = Vec::new();
    for line in logs {
        let Some(rest) = line.strip_prefix("Program ") else { continue };
        let mut parts = rest.split(' ');
        if let (Some(id), Some("invoke")) = (parts.next(), parts.next()) {
            if let Ok(p) = id.parse::<Pubkey>() {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
    out
}
