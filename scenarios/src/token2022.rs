//! Token-2022 hostile mint matrix.
//!
//! Every mint is created with real instructions against the Token-2022 (or
//! classic SPL Token) program loaded in LiteSVM, so extension semantics such as
//! withheld fees, permanent delegates, hooks and freezes are the program's own,
//! not a re-implementation.

use anyhow::{anyhow, Context, Result};
use crucible_test_context::{AccountBuilderBase, TestContext};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_associated_token_account_interface::{
    address::get_associated_token_address_with_program_id,
    instruction::create_associated_token_account_idempotent,
};
use spl_token_2022_interface::{
    extension::{
        transfer_fee::{instruction::initialize_transfer_fee_config, TransferFeeAmount},
        interest_bearing_mint, transfer_hook, BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction as tix,
    state::{Account as TokenAccount, AccountState, Mint},
};

pub const SPL_TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_ID: Pubkey = spl_token_2022_interface::ID;

/// One row of the hostile mint matrix.
///
/// The `attacker` keypair in [`TokenEnv`] holds every privileged authority the
/// profile grants beyond minting: permanent delegate, freeze authority, fee
/// authorities. That models a malicious or compromised mint issuer, which is the
/// realistic threat for any program that accepts arbitrary mints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintProfile {
    /// Classic SPL Token mint. Baseline: every invariant should hold.
    SplToken,
    /// Token-2022 mint with no extensions.
    Plain2022,
    /// 1% transfer fee, withheld in the destination account.
    TransferFee,
    /// Attacker is the permanent delegate: can move tokens out of any account.
    PermanentDelegate,
    /// Transfer hook pointing at a program the caller never passes.
    TransferHook,
    /// Attacker holds the freeze authority.
    FreezeAuthority,
    /// Non-transferable ("soulbound") mint.
    NonTransferable,
    /// 2.5% transfer fee capped at 7 base units: exercises the fee-cap branch
    /// of fee and inverse-fee calculations.
    TransferFeeCapped,
    /// 100% (MAX_FEE_BASIS_POINTS) transfer fee capped at 5,000 base units:
    /// every transfer pays exactly the cap, and amounts at or below it arrive as 0.
    TransferFeeMax,
    /// Interest-bearing mint (UI-only extension; raw amounts are unaffected).
    InterestBearing,
}

impl MintProfile {
    pub const ALL: [MintProfile; 7] = [
        MintProfile::SplToken,
        MintProfile::Plain2022,
        MintProfile::TransferFee,
        MintProfile::PermanentDelegate,
        MintProfile::TransferHook,
        MintProfile::FreezeAuthority,
        MintProfile::NonTransferable,
    ];

    /// Extra profiles for programs that support transfer fees: fee-cap edge
    /// cases and UI-only extensions.
    pub const FEE_EDGES: [MintProfile; 3] = [
        MintProfile::TransferFeeCapped,
        MintProfile::TransferFeeMax,
        MintProfile::InterestBearing,
    ];

    pub fn from_index(i: usize) -> MintProfile {
        Self::ALL[i % Self::ALL.len()]
    }

    pub fn name(self) -> &'static str {
        match self {
            MintProfile::SplToken => "spl-token",
            MintProfile::Plain2022 => "token-2022",
            MintProfile::TransferFee => "token-2022+transfer-fee",
            MintProfile::PermanentDelegate => "token-2022+permanent-delegate",
            MintProfile::TransferHook => "token-2022+transfer-hook",
            MintProfile::FreezeAuthority => "token-2022+freeze-authority",
            MintProfile::NonTransferable => "token-2022+non-transferable",
            MintProfile::TransferFeeCapped => "token-2022+transfer-fee-capped",
            MintProfile::TransferFeeMax => "token-2022+transfer-fee-100pct",
            MintProfile::InterestBearing => "token-2022+interest-bearing",
        }
    }

    pub fn token_program(self) -> Pubkey {
        match self {
            MintProfile::SplToken => SPL_TOKEN_ID,
            _ => TOKEN_2022_ID,
        }
    }

    pub fn transfer_fee_bps(self) -> u16 {
        self.transfer_fee_params().map_or(0, |(bps, _)| bps)
    }

    /// `(basis_points, maximum_fee)` for fee-bearing profiles.
    pub fn transfer_fee_params(self) -> Option<(u16, u64)> {
        match self {
            MintProfile::TransferFee => Some((100, u64::MAX)),
            MintProfile::TransferFeeCapped => Some((250, 7)),
            MintProfile::TransferFeeMax => Some((10_000, 5_000)),
            _ => None,
        }
    }

    fn extensions(self) -> Vec<ExtensionType> {
        match self {
            MintProfile::SplToken | MintProfile::Plain2022 | MintProfile::FreezeAuthority => vec![],
            MintProfile::TransferFee | MintProfile::TransferFeeCapped | MintProfile::TransferFeeMax => {
                vec![ExtensionType::TransferFeeConfig]
            }
            MintProfile::InterestBearing => vec![ExtensionType::InterestBearingConfig],
            MintProfile::PermanentDelegate => vec![ExtensionType::PermanentDelegate],
            MintProfile::TransferHook => vec![ExtensionType::TransferHook],
            MintProfile::NonTransferable => vec![ExtensionType::NonTransferable],
        }
    }
}

/// Program id the TransferHook profile points at. Nothing is deployed there, so
/// any transfer that does not resolve the hook's extra accounts fails, which is
/// how a real hook behaves toward a caller that ignores the hook interface.
pub const UNRESOLVED_HOOK_PROGRAM: Pubkey = Pubkey::new_from_array([0x4b; 32]);

#[derive(Clone, Debug)]
pub struct MintHandle {
    pub profile: MintProfile,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub decimals: u8,
}

impl MintHandle {
    pub fn ata(&self, owner: &Pubkey) -> Pubkey {
        get_associated_token_address_with_program_id(owner, &self.mint, &self.token_program)
    }
}

/// Authorities shared by every mint in the matrix.
pub struct TokenEnv<'a> {
    pub payer: &'a Keypair,
    pub mint_authority: &'a Keypair,
    pub attacker: &'a Keypair,
}

fn send(ctx: &mut TestContext, ix: Instruction, signers: &[&Keypair]) -> Result<()> {
    let label = format!("{:?}", ix.data.first());
    ctx.raw_call(ix)
        .skip_account_mutation()
        .signers(signers)
        .send()
        .with_context(|| format!("send token setup ix {label}"))?
        .into_result()
        .map_err(|e| anyhow!("token setup ix {label} failed: {e:?}"))
}

impl TokenEnv<'_> {
    /// Create a mint for `profile` using real token-program instructions.
    pub fn create_mint(
        &self,
        ctx: &mut TestContext,
        profile: MintProfile,
        mint: &Keypair,
        decimals: u8,
    ) -> Result<MintHandle> {
        let program = profile.token_program();
        let mint_pk = mint.pubkey();
        let space = if program == SPL_TOKEN_ID {
            82
        } else {
            ExtensionType::try_calculate_account_len::<Mint>(&profile.extensions())?
        };

        // Rent-exempt, program-owned, zeroed: equivalent to a system
        // create_account, minus the extra transaction.
        ctx.create_account()
            .pubkey(mint_pk)
            .owner(program)
            .size(space)
            .create()?;

        let attacker = self.attacker.pubkey();
        let payer = self.payer;
        match profile {
            MintProfile::TransferFee | MintProfile::TransferFeeCapped | MintProfile::TransferFeeMax => {
                let (bps, max_fee) = profile.transfer_fee_params().unwrap();
                send(
                    ctx,
                    initialize_transfer_fee_config(&program, &mint_pk, Some(&attacker), Some(&attacker), bps, max_fee)?,
                    &[payer],
                )?
            }
            MintProfile::InterestBearing => send(
                ctx,
                interest_bearing_mint::instruction::initialize(&program, &mint_pk, Some(attacker), 500)?,
                &[payer],
            )?,
            MintProfile::PermanentDelegate => send(
                ctx,
                tix::initialize_permanent_delegate(&program, &mint_pk, &attacker)?,
                &[payer],
            )?,
            MintProfile::TransferHook => send(
                ctx,
                transfer_hook::instruction::initialize(
                    &program,
                    &mint_pk,
                    Some(attacker),
                    Some(UNRESOLVED_HOOK_PROGRAM),
                )?,
                &[payer],
            )?,
            MintProfile::NonTransferable => send(
                ctx,
                tix::initialize_non_transferable_mint(&program, &mint_pk)?,
                &[payer],
            )?,
            _ => {}
        }

        let freeze = (profile == MintProfile::FreezeAuthority).then_some(&attacker);
        send(
            ctx,
            tix::initialize_mint2(&program, &mint_pk, &self.mint_authority.pubkey(), freeze, decimals)?,
            &[payer],
        )?;

        Ok(MintHandle { profile, mint: mint_pk, token_program: program, decimals })
    }

    /// Create (idempotently) the ATA of `owner` and mint `amount` into it.
    pub fn fund(&self, ctx: &mut TestContext, m: &MintHandle, owner: &Pubkey, amount: u64) -> Result<Pubkey> {
        let ata = m.ata(owner);
        send(
            ctx,
            create_associated_token_account_idempotent(&self.payer.pubkey(), owner, &m.mint, &m.token_program),
            &[self.payer],
        )?;
        if amount > 0 {
            send(
                ctx,
                tix::mint_to_checked(
                    &m.token_program,
                    &m.mint,
                    &ata,
                    &self.mint_authority.pubkey(),
                    &[],
                    amount,
                    m.decimals,
                )?,
                &[self.payer, self.mint_authority],
            )?;
        }
        Ok(ata)
    }

    /// Attacker attempt: move `amount` out of `victim` using only the attacker's
    /// own signature. Succeeds only when the mint grants the attacker a delegate
    /// role (PermanentDelegate). Returns whether the transfer succeeded.
    pub fn attacker_pull(&self, ctx: &mut TestContext, m: &MintHandle, victim: &Pubkey, amount: u64) -> bool {
        let dest = match self.fund(ctx, m, &self.attacker.pubkey(), 0) {
            Ok(a) => a,
            Err(_) => return false,
        };
        let ix = match tix::transfer_checked(
            &m.token_program,
            victim,
            &m.mint,
            &dest,
            &self.attacker.pubkey(),
            &[],
            amount,
            m.decimals,
        ) {
            Ok(ix) => ix,
            Err(_) => return false,
        };
        send(ctx, ix, &[self.attacker]).is_ok()
    }

    /// Attacker attempt: freeze `victim`. Succeeds only when the attacker is the
    /// mint's freeze authority.
    pub fn attacker_freeze(&self, ctx: &mut TestContext, m: &MintHandle, victim: &Pubkey) -> bool {
        match tix::freeze_account(&m.token_program, victim, &m.mint, &self.attacker.pubkey(), &[]) {
            Ok(ix) => send(ctx, ix, &[self.attacker]).is_ok(),
            Err(_) => false,
        }
    }
}

/// Extension-aware snapshot of a token account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenAccountView {
    pub exists: bool,
    pub amount: u64,
    pub withheld: u64,
    pub frozen: bool,
}

/// Read a token account owned by either token program, extensions included.
/// Use this instead of `TestContext::token_balance`, which returns 0 for
/// Token-2022 accounts that carry extensions.
pub fn read_token_account(ctx: &TestContext, address: &Pubkey) -> TokenAccountView {
    let Some(acc) = ctx.svm.get_account(address) else {
        return TokenAccountView::default();
    };
    if acc.data.is_empty() || acc.lamports == 0 {
        return TokenAccountView::default();
    }
    match StateWithExtensions::<TokenAccount>::unpack(&acc.data) {
        Ok(state) => TokenAccountView {
            exists: true,
            amount: state.base.amount,
            withheld: state
                .get_extension::<TransferFeeAmount>()
                .map(|e| u64::from(e.withheld_amount))
                .unwrap_or(0),
            frozen: state.base.state == AccountState::Frozen,
        },
        Err(_) => TokenAccountView { exists: true, ..Default::default() },
    }
}
