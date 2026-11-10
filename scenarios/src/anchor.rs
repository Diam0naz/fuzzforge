//! Build Anchor instructions and accounts without an IDL.
//!
//! Useful when a target's IDL cannot be generated (toolchain mismatch, a
//! pinned Anchor version that will not run locally) or does not exist (native,
//! Pinocchio). Account order must follow the program's `#[derive(Accounts)]`
//! struct exactly; double-check against the source.

use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;

fn sighash(namespace: &str, name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("{namespace}:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// Default Anchor instruction discriminator: `sha256("global:<name>")[..8]`.
pub fn ix_discriminator(name: &str) -> [u8; 8] {
    sighash("global", name)
}

/// Default Anchor account discriminator: `sha256("account:<TypeName>")[..8]`.
pub fn account_discriminator(type_name: &str) -> [u8; 8] {
    sighash("account", type_name)
}

/// Deterministic keypair from a tag. Harness setup must be identical across
/// processes for crash replay; any logic that orders accounts by address (AMM
/// token_0 < token_1) otherwise changes between runs.
pub fn det_keypair(tag: &str) -> Keypair {
    let h = Sha256::digest(format!("fuzzforge:{tag}").as_bytes());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&h);
    Keypair::new_from_array(secret)
}

/// Builder for an Anchor instruction with Borsh-encoded primitive args.
pub struct AnchorIx {
    program_id: Pubkey,
    data: Vec<u8>,
    accounts: Vec<AccountMeta>,
}

impl AnchorIx {
    pub fn new(program_id: Pubkey, name: &str) -> Self {
        Self { program_id, data: ix_discriminator(name).to_vec(), accounts: Vec::new() }
    }

    pub fn u64(mut self, v: u64) -> Self {
        self.data.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u8(mut self, v: u8) -> Self {
        self.data.push(v);
        self
    }

    pub fn bool(self, v: bool) -> Self {
        self.u8(v as u8)
    }

    /// Borsh `Option<T>` tag; append the payload yourself when `some`.
    pub fn option_tag(self, some: bool) -> Self {
        self.u8(some as u8)
    }

    pub fn signer(mut self, k: Pubkey) -> Self {
        self.accounts.push(AccountMeta::new_readonly(k, true));
        self
    }

    pub fn signer_mut(mut self, k: Pubkey) -> Self {
        self.accounts.push(AccountMeta::new(k, true));
        self
    }

    pub fn mutable(mut self, k: Pubkey) -> Self {
        self.accounts.push(AccountMeta::new(k, false));
        self
    }

    pub fn readonly(mut self, k: Pubkey) -> Self {
        self.accounts.push(AccountMeta::new_readonly(k, false));
        self
    }

    pub fn build(self) -> Instruction {
        Instruction { program_id: self.program_id, accounts: self.accounts, data: self.data }
    }
}

/// Little-endian field readers for packed zero-copy accounts.
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

pub fn read_pubkey(data: &[u8], offset: usize) -> Pubkey {
    Pubkey::new_from_array(data[offset..offset + 32].try_into().unwrap())
}
