//! Orca's transfer-hook "counter" program, used as a resolvable Token-2022
//! transfer hook in harnesses. The binary ships in Orca's own test fixtures
//! (`transfer_hook_counter.so`); nothing here builds it. The hook increments a
//! per-mint counter on every transfer and never blocks one, so it is the
//! benign "supported hook" case: it proves a program threads hook accounts
//! correctly, not that it resists a hostile hook.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

/// The counter hook program id (Orca's `TEST_TRANSFER_HOOK_PROGRAM_ID`).
pub const PROGRAM: Pubkey = Pubkey::from_str_const("EBZDYx7599krFc4m2govwBdZcicr4GgepqC78m71nsHS");
const TOKEN_2022: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ATA_PROGRAM: Pubkey = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

/// `InitializeExtraAccountMetaList` discriminator (anchor sighash).
const INIT_EXTRA_METAS: [u8; 8] = [0x5c, 0xc5, 0xae, 0xc5, 0x29, 0x7c, 0x13, 0x03];

/// The validation account the SPL transfer-hook interface reads to resolve the
/// Execute CPI's extra accounts. Seeds: `["extra-account-metas", mint]`.
pub fn extra_metas(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"extra-account-metas", mint.as_ref()], &PROGRAM).0
}

/// The per-mint counter the hook increments. Seeds: `["counter", mint]`.
pub fn counter(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"counter", mint.as_ref()], &PROGRAM).0
}

/// Build the ExtraAccountMetaList and counter for `mint`. Run once per hook
/// mint, after the mint exists.
pub fn init_extra_account_meta_list_ix(payer: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(extra_metas(mint), false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(counter(mint), false),
            AccountMeta::new_readonly(TOKEN_2022, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        data: INIT_EXTRA_METAS.to_vec(),
    }
}

/// The accounts a caller must pass as a hook's "remaining accounts" so the SPL
/// interface can resolve and run the Execute CPI: the validation account, the
/// counter (written by the hook), and the hook program itself. Order does not
/// matter; the resolver indexes by key.
pub fn remaining_accounts(mint: &Pubkey) -> [AccountMeta; 3] {
    [
        AccountMeta::new_readonly(extra_metas(mint), false),
        AccountMeta::new(counter(mint), false),
        AccountMeta::new_readonly(PROGRAM, false),
    ]
}

/// Read the counter's current value (bytes 8..12, little-endian i32) from an
/// account's data, or 0 when absent.
pub fn counter_value(data: &[u8]) -> i32 {
    data.get(8..12).map(|b| i32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}
