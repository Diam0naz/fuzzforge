//! SPL Stake Pool adapter (the program behind JitoSOL and most Solana LSTs).
//!
//! A stake pool is a single-asset share vault: `total_lamports` backs
//! `pool_token_supply` pool tokens. The invariants are the vault templates in
//! `fuzzforge_scenarios::invariants`: the exchange rate never falls
//! (`vault_rate_fell`) and the pool mint never holds more supply than the
//! pool accounts for (`supply_inflated`).

use fuzzforge_scenarios::anchor::{read_pubkey, read_u64};
use solana_pubkey::Pubkey;

pub const PROGRAM: Pubkey = Pubkey::from_str_const("SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy");

/// `StakePool` is Borsh. Everything up to `epoch_fee` has a fixed size; the
/// variable-length tail (optional authorities, future fees) is parsed in order.
const OFF_BUMP: usize = 97;
const OFF_VALIDATOR_LIST: usize = 98;
const OFF_RESERVE: usize = 130;
const OFF_MINT: usize = 162;
const OFF_MANAGER_FEE: usize = 194;
const OFF_TOKEN_PROGRAM: usize = 226;
const OFF_TOTAL_LAMPORTS: usize = 258;
const OFF_SUPPLY: usize = 266;
const OFF_LAST_UPDATE_EPOCH: usize = 274;
const OFF_TAIL: usize = 346;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakePool {
    pub key: Pubkey,
    pub withdraw_bump: u8,
    pub validator_list: Pubkey,
    pub reserve_stake: Pubkey,
    pub pool_mint: Pubkey,
    pub manager_fee_account: Pubkey,
    pub token_program: Pubkey,
    pub total_lamports: u64,
    pub pool_token_supply: u64,
    pub last_update_epoch: u64,
    pub sol_deposit_authority: Option<Pubkey>,
}

impl StakePool {
    pub fn decode(key: Pubkey, d: &[u8]) -> Option<Self> {
        if d.len() < OFF_TAIL || d[0] != 1 {
            return None; // AccountType::StakePool
        }
        let mut o = OFF_TAIL;
        let mut byte = |o: &mut usize| -> Option<u8> {
            let b = *d.get(*o)?;
            *o += 1;
            Some(b)
        };
        // FutureEpoch<Fee>: 0 None, 1 One(Fee), 2 Two(Fee).
        let future_fee = |o: &mut usize, byte: &mut dyn FnMut(&mut usize) -> Option<u8>| -> Option<()> {
            if byte(o)? != 0 {
                *o += 16;
            }
            Some(())
        };
        let option_key = |o: &mut usize, byte: &mut dyn FnMut(&mut usize) -> Option<u8>| -> Option<Option<Pubkey>> {
            if byte(o)? == 0 {
                return Some(None);
            }
            let k = Pubkey::new_from_array(d.get(*o..*o + 32)?.try_into().ok()?);
            *o += 32;
            Some(Some(k))
        };
        future_fee(&mut o, &mut byte)?; // next_epoch_fee
        option_key(&mut o, &mut byte)?; // preferred_deposit_validator
        option_key(&mut o, &mut byte)?; // preferred_withdraw_validator
        o += 32; // stake_deposit_fee, stake_withdrawal_fee
        future_fee(&mut o, &mut byte)?; // next_stake_withdrawal_fee
        o += 1; // stake_referral_fee
        let sol_deposit_authority = option_key(&mut o, &mut byte)?;
        Some(Self {
            key,
            withdraw_bump: d[OFF_BUMP],
            validator_list: read_pubkey(d, OFF_VALIDATOR_LIST),
            reserve_stake: read_pubkey(d, OFF_RESERVE),
            pool_mint: read_pubkey(d, OFF_MINT),
            manager_fee_account: read_pubkey(d, OFF_MANAGER_FEE),
            token_program: read_pubkey(d, OFF_TOKEN_PROGRAM),
            total_lamports: read_u64(d, OFF_TOTAL_LAMPORTS),
            pool_token_supply: read_u64(d, OFF_SUPPLY),
            last_update_epoch: read_u64(d, OFF_LAST_UPDATE_EPOCH),
            sol_deposit_authority,
        })
    }

    pub fn withdraw_authority(&self, program: &Pubkey) -> Pubkey {
        Pubkey::create_program_address(&[self.key.as_ref(), b"withdraw", &[self.withdraw_bump]], program)
            .unwrap_or_else(|_| Pubkey::find_program_address(&[self.key.as_ref(), b"withdraw"], program).0)
    }
}

/// `supply` of an SPL Token / Token-2022 mint.
pub fn mint_supply(data: &[u8]) -> Option<u64> {
    (data.len() >= 44).then(|| read_u64(data, 36))
}
