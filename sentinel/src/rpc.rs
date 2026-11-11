//! Minimal read-only JSON-RPC client. Sentinel never sends a transaction:
//! the firewall simulates locally and the monitor only reads.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::time::Duration;

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

/// One entry of `getSignaturesForAddress`.
#[derive(Clone, Debug)]
pub struct SigInfo {
    pub signature: String,
    pub slot: u64,
    pub failed: bool,
    /// Position in the block, when the RPC reports it.
    pub index: Option<u64>,
}

/// The parts of `getTransaction` the rules use.
#[derive(Clone, Debug)]
pub struct TxInfo {
    pub signature: String,
    pub slot: u64,
    pub failed: bool,
    pub logs: Vec<String>,
    /// base64 of the full wire transaction.
    pub wire: String,
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        let config = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(120))).http_status_as_error(false).build();
        Self { url: url.to_string(), agent: config.into() }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut backoff = 500;
        for attempt in 0..6 {
            let mut resp = self.agent.post(&self.url).send_json(&body).with_context(|| format!("{method}: request failed"))?;
            let status = resp.status().as_u16();
            if status == 429 || status >= 500 {
                if attempt == 5 {
                    bail!("{method}: HTTP {status} after retries");
                }
                std::thread::sleep(Duration::from_millis(backoff));
                backoff *= 2;
                continue;
            }
            let v: Value = resp.body_mut().read_json().with_context(|| format!("{method}: HTTP {status}, body is not JSON"))?;
            if let Some(err) = v.get("error") {
                bail!("{method}: {err}");
            }
            return v.get("result").cloned().ok_or_else(|| anyhow!("{method}: no result"));
        }
        unreachable!()
    }

    /// Accounts at one slot (`getMultipleAccounts` is answered from a single
    /// bank, so the set is consistent). Returns the slot too.
    pub fn accounts(&self, keys: &[Pubkey]) -> Result<(u64, Vec<Option<Account>>)> {
        let mut out = Vec::with_capacity(keys.len());
        let mut slot = 0;
        for chunk in keys.chunks(100) {
            let ks: Vec<String> = chunk.iter().map(|k| k.to_string()).collect();
            let r = self.call("getMultipleAccounts", json!([ks, {"encoding": "base64", "commitment": "confirmed"}]))?;
            slot = slot.max(r["context"]["slot"].as_u64().unwrap_or(0));
            for v in r["value"].as_array().ok_or_else(|| anyhow!("getMultipleAccounts: no value"))? {
                out.push(if v.is_null() { None } else { Some(decode_account(v)?) });
            }
        }
        Ok((slot, out))
    }

    /// The first `len` bytes of an account, without downloading the rest.
    pub fn account_prefix(&self, key: &Pubkey, len: usize) -> Result<Option<Vec<u8>>> {
        let r = self.call(
            "getAccountInfo",
            json!([key.to_string(), {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": len}}]),
        )?;
        if r["value"].is_null() {
            return Ok(None);
        }
        Ok(Some(b64(r["value"]["data"][0].as_str().unwrap_or(""))?))
    }

    /// Newest first, as the RPC returns them.
    pub fn signatures(&self, address: &Pubkey, limit: usize, until: Option<&str>, before: Option<&str>) -> Result<Vec<SigInfo>> {
        let mut cfg = json!({"limit": limit, "commitment": "confirmed"});
        if let Some(u) = until {
            cfg["until"] = json!(u);
        }
        if let Some(b) = before {
            cfg["before"] = json!(b);
        }
        let r = self.call("getSignaturesForAddress", json!([address.to_string(), cfg]))?;
        Ok(r.as_array()
            .ok_or_else(|| anyhow!("getSignaturesForAddress: not an array"))?
            .iter()
            .map(|s| SigInfo {
                signature: s["signature"].as_str().unwrap_or("").to_string(),
                slot: s["slot"].as_u64().unwrap_or(0),
                failed: !s["err"].is_null(),
                index: s["transactionIndex"].as_u64(),
            })
            .collect())
    }

    pub fn transaction(&self, signature: &str) -> Result<Option<TxInfo>> {
        let r = self.call(
            "getTransaction",
            json!([signature, {"encoding": "base64", "commitment": "confirmed", "maxSupportedTransactionVersion": 1}]),
        )?;
        if r.is_null() {
            return Ok(None);
        }
        Ok(Some(TxInfo {
            signature: signature.to_string(),
            slot: r["slot"].as_u64().unwrap_or(0),
            failed: !r["meta"]["err"].is_null(),
            logs: r["meta"]["logMessages"].as_array().map(|a| a.iter().filter_map(|l| l.as_str().map(String::from)).collect()).unwrap_or_default(),
            wire: r["transaction"][0].as_str().unwrap_or("").to_string(),
        }))
    }
}

fn b64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

fn decode_account(v: &Value) -> Result<Account> {
    Ok(Account {
        lamports: v["lamports"].as_u64().unwrap_or(0),
        data: b64(v["data"][0].as_str().unwrap_or(""))?,
        owner: Pubkey::from_str(v["owner"].as_str().unwrap_or(""))?,
        executable: v["executable"].as_bool().unwrap_or(false),
        rent_epoch: 0,
    })
}
