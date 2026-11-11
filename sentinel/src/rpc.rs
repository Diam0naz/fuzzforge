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

/// One account's balance of one asset before and after a transaction.
#[derive(Clone, Debug)]
pub struct Balance {
    /// The wallet: the token account's owner, or the account itself for SOL.
    pub owner: String,
    /// Mint address, or "SOL".
    pub asset: String,
    pub decimals: u8,
    pub pre: u128,
    pub post: u128,
}

/// Balances a transaction moved, from `getTransaction` metadata.
#[derive(Clone, Debug)]
pub struct TxBalances {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub failed: bool,
    pub balances: Vec<Balance>,
}

impl TxBalances {
    pub fn from_json(signature: &str, r: &Value) -> Result<Self> {
        let meta = &r["meta"];
        let mut keys: Vec<String> = r["transaction"]["message"]["accountKeys"]
            .as_array()
            .ok_or_else(|| anyhow!("{signature}: no account keys"))?
            .iter()
            .map(|k| k.as_str().unwrap_or("").to_string())
            .collect();
        for part in ["writable", "readonly"] {
            if let Some(a) = meta["loadedAddresses"][part].as_array() {
                keys.extend(a.iter().map(|k| k.as_str().unwrap_or("").to_string()));
            }
        }
        let lamports = |field: &str| -> Vec<u128> { meta[field].as_array().map(|a| a.iter().map(|v| v.as_u64().unwrap_or(0) as u128).collect()).unwrap_or_default() };
        let (pre, post) = (lamports("preBalances"), lamports("postBalances"));
        let fee = meta["fee"].as_u64().unwrap_or(0) as u128;
        let mut balances = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let (Some(a), Some(b)) = (pre.get(i), post.get(i)) else { continue };
            // The fee is burnt, not sent anywhere: add it back to the payer.
            let b = if i == 0 { b + fee } else { *b };
            if *a != b {
                balances.push(Balance { owner: key.clone(), asset: "SOL".into(), decimals: 9, pre: *a, post: b });
            }
        }
        let tokens = |field: &str| -> Vec<(u64, String, String, u8, u128)> {
            meta[field]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|t| {
                            (
                                t["accountIndex"].as_u64().unwrap_or(u64::MAX),
                                t["mint"].as_str().unwrap_or("").to_string(),
                                t["owner"].as_str().unwrap_or("").to_string(),
                                t["uiTokenAmount"]["decimals"].as_u64().unwrap_or(0) as u8,
                                t["uiTokenAmount"]["amount"].as_str().and_then(|x| x.parse().ok()).unwrap_or(0),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let (tpre, tpost) = (tokens("preTokenBalances"), tokens("postTokenBalances"));
        let mut idx: Vec<u64> = tpre.iter().chain(&tpost).map(|t| t.0).collect();
        idx.sort();
        idx.dedup();
        for i in idx {
            let a = tpre.iter().find(|t| t.0 == i);
            let b = tpost.iter().find(|t| t.0 == i);
            let any = a.or(b).unwrap();
            let (pa, pb) = (a.map(|t| t.4).unwrap_or(0), b.map(|t| t.4).unwrap_or(0));
            if pa != pb {
                balances.push(Balance { owner: any.2.clone(), asset: any.1.clone(), decimals: any.3, pre: pa, post: pb });
            }
        }
        Ok(Self { signature: signature.into(), slot: r["slot"].as_u64().unwrap_or(0), block_time: r["blockTime"].as_i64(), failed: !meta["err"].is_null(), balances })
    }
}

impl Rpc {
    pub fn balances(&self, signature: &str) -> Result<Option<TxBalances>> {
        let r = self.call("getTransaction", json!([signature, {"encoding": "json", "commitment": "confirmed", "maxSupportedTransactionVersion": 1}]))?;
        if r.is_null() {
            return Ok(None);
        }
        TxBalances::from_json(signature, &r).map(Some)
    }

    /// Token accounts `owner` holds of `mint`, with raw amounts.
    pub fn token_holdings(&self, owner: &str, mint: &str) -> Result<Vec<(String, u128)>> {
        let r = self.call("getTokenAccountsByOwner", json!([owner, {"mint": mint}, {"encoding": "jsonParsed", "commitment": "confirmed"}]))?;
        Ok(r["value"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        (
                            v["pubkey"].as_str().unwrap_or("").to_string(),
                            v["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"].as_str().and_then(|x| x.parse().ok()).unwrap_or(0),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}
