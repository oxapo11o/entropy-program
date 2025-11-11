use std::str::FromStr;

use clap::{Parser, Subcommand};
use entropy_api::prelude::*;
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    client_error::{
        reqwest::{self, StatusCode},
        ClientErrorKind,
    },
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    rpc_filter::{Memcmp, RpcFilterType},
};
use solana_sdk::{
    address_lookup_table::AddressLookupTableAccount,
    compute_budget::ComputeBudgetInstruction,
    message::{v0::Message, VersionedMessage},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signature, Signer},
    transaction::{Transaction, VersionedTransaction},
};
use solana_sdk::{keccak, pubkey};
use steel::{AccountDeserialize, Clock, Discriminator, Instruction};

const ENTROPY_PROVIDER: Pubkey = pubkey!("apicJTEtH3Q5negrbPKaTfw8at6TmeAo2qW7v8aese1");

#[derive(Parser)]
#[command(name = "entropy-cli")]
#[command(about = "CLI tool for interacting with Entropy protocol", long_about = None)]
struct Cli {
    /// Path to the keypair file
    #[arg(short, long, env = "KEYPAIR")]
    keypair: String,

    /// RPC endpoint URL
    #[arg(short, long, env = "RPC")]
    rpc: String,

    /// Entropy provider base URL
    #[arg(long, env = "ENTROPY_PROVIDER_URL")]
    provider_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Open a new VAR (Verifiable Autonomous Randomness) account
    Open {
        /// The ID for the VAR account
        #[arg(short, long)]
        id: u64,
        /// Commit hex string returned by provider's /open (e.g. e9a1cd66...)
        #[arg(long)]
        commit_hex: Option<String>,
        /// Total samples returned by provider's /open
        #[arg(long)]
        samples: Option<u64>,
        /// Slots from now to set end_at (default 150)
        #[arg(long, default_value_t = 150)]
        end_offset: u64,
        /// Override provider pubkey (defaults to ENTROPY_PROVIDER)
        #[arg(long)]
        provider: Option<String>,
    },
    /// Crank the VAR account (sample and reveal)
    Crank {
        /// The address of the VAR account
        #[arg(short, long, env = "DEFAULT_VAR_ADDRESS")]
        address: String,
    },
    /// Close a VAR account
    Close {
        /// The address of the VAR account to close
        #[arg(short, long, env = "DEFAULT_VAR_ADDRESS")]
        address: String,
    },
    /// Sample the slot hash for a VAR (no reveal)
    Sample {
        /// The address of the VAR account
        #[arg(short, long, env = "DEFAULT_VAR_ADDRESS")]
        address: String,
    },
    /// Advance VAR to next round (sets next end_at = current_slot + offset)
    Next {
        /// The address of the VAR account
        #[arg(short, long, env = "DEFAULT_VAR_ADDRESS")]
        address: String,
        /// Slots from now to set end_at (default 150)
        #[arg(long, default_value_t = 150)]
        end_offset: u64,
    },
    /// Display information about a VAR account
    Var {
        /// The address of the VAR account
        #[arg(short, long, env = "DEFAULT_VAR_ADDRESS")]
        address: String,
    },
    /// End-to-end test: wait -> sample -> fetch seed -> reveal -> verify -> next -> verify
    Test {
        /// The address of the VAR account
        #[arg(short, long, env = "DEFAULT_VAR_ADDRESS")]
        address: String,
    },
}

#[tokio::main]
async fn main() {
    // Load .env file if it exists
    let _ = dotenvy::dotenv();
    
    let cli = Cli::parse();

    // Read keypair from file
    let payer = read_keypair_file(&cli.keypair)
        .unwrap_or_else(|e| panic!("Failed to read keypair from {}: {}", cli.keypair, e));

    // Build RPC client
    let rpc = RpcClient::new(cli.rpc);

    let result = match cli.command {
        Commands::Open {
            id,
            commit_hex,
            samples,
            end_offset,
            provider,
        } => open(&rpc, &payer, id, commit_hex, samples, end_offset, provider).await,
        Commands::Crank { address } => {
            let address = Pubkey::from_str(&address).expect("Invalid address");
            crank(&rpc, &payer, address, &cli.provider_url).await
        }
        Commands::Close { address } => {
            let address = Pubkey::from_str(&address).expect("Invalid address");
            close(&rpc, &payer, address).await
        }
        Commands::Sample { address } => {
            let address = Pubkey::from_str(&address).expect("Invalid address");
            sample_only(&rpc, &payer, address).await
        }
        Commands::Next { address, end_offset } => {
            let address = Pubkey::from_str(&address).expect("Invalid address");
            next_only(&rpc, &payer, address, end_offset).await
        }
        Commands::Var { address } => {
            let address = Pubkey::from_str(&address).expect("Invalid address");
            log_var(&rpc, address).await
        }
        Commands::Test { address } => {
            let address = Pubkey::from_str(&address).expect("Invalid address");
            test_flow(&rpc, &payer, address, &cli.provider_url).await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn close(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    address: Pubkey,
) -> Result<(), anyhow::Error> {
    let ix = entropy_api::sdk::close(payer.pubkey(), address);
    submit_transaction(rpc, payer, &[ix]).await?;
    Ok(())
}

async fn next_only(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    address: Pubkey,
    end_offset: u64,
) -> Result<(), anyhow::Error> {
    let clock = get_clock(rpc).await?;
    let end_at = clock.slot + end_offset;
    let ix = entropy_api::sdk::next(payer.pubkey(), address, end_at);
    submit_transaction(rpc, payer, &[ix]).await?;
    println!("Next submitted with end_at={} (offset={})", end_at, end_offset);
    Ok(())
}

async fn sample_only(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    address: Pubkey,
) -> Result<(), anyhow::Error> {
    let ix = entropy_api::sdk::sample(payer.pubkey(), address);
    submit_transaction(rpc, payer, &[ix]).await?;
    Ok(())
}

async fn open(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    id: u64,
    commit_hex: Option<String>,
    samples: Option<u64>,
    end_offset: u64,
    provider_override: Option<String>,
) -> Result<(), anyhow::Error> {
    let var_address = var_pda(payer.pubkey(), id).0;
    println!("Var address: {:?}", var_address);
    let commit_bytes: [u8; 32] = if let Some(hex_str) = commit_hex {
        parse_commit_hex(&hex_str)?
    } else {
        anyhow::bail!("commit_hex is required. Please provide --commit-hex parameter.");
    };
    let provider_key = if let Some(pk_str) = provider_override {
        Pubkey::from_str(&pk_str)?
    } else {
        ENTROPY_PROVIDER
    };
    let clock = get_clock(rpc).await?;
    let end_at = clock.slot + end_offset;
    let total_samples = samples.unwrap_or(999_998);
    let ix = entropy_api::sdk::open(
        payer.pubkey(),
        payer.pubkey(),
        id,
        provider_key,
        commit_bytes,
        false,
        total_samples,
        end_at,
    );
    println!(
        "Opening VAR id={} provider={} samples={} end_at={} commit_hex={}",
        id,
        provider_key,
        total_samples,
        end_at,
        to_hex_lower(&commit_bytes)
    );
    submit_transaction(rpc, payer, &[ix]).await?;
    println!("VAR={}", var_address);
    Ok(())
}

async fn crank(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    address: Pubkey,
    provider_url: &str,
) -> Result<(), anyhow::Error> {
    // Get var.
    let var = get_var(rpc, address).await?;

    // Get the clock
    let clock = get_clock(rpc).await?;

    // Check if the var is ready to next.
    let buffer_slots = 4;
    if clock.slot < var.end_at + buffer_slots {
        println!(
            "Var seed is not revealed yet. Waiting for {} slots.",
            buffer_slots + (var.end_at - clock.slot)
        );
        return Ok(());
    }

    // Get the seed from the API
    let url = format!("{}/var/{}/seed", provider_url.trim_end_matches('/'), address);
    let response = reqwest::get(&url).await?;
    let seed_response: entropy_types::response::GetSeedResponse = response.json().await?;
    println!("Seed: {:?}", seed_response.seed);

    // Build the instructions
    let sample_ix = entropy_api::sdk::sample(payer.pubkey(), address);
    let reveal_ix = entropy_api::sdk::reveal(payer.pubkey(), address, seed_response.seed);
    // let next_ix = entropy_api::sdk::next(payer.pubkey(), address, clock.slot + 150);
    // submit_transaction(rpc, payer, &[sample_ix, reveal_ix, next_ix]).await?;
    submit_transaction(rpc, payer, &[sample_ix, reveal_ix]).await?;
    Ok(())
}

fn parse_commit_hex(s: &str) -> Result<[u8; 32], anyhow::Error> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        anyhow::bail!("commit hex must be 64 hex chars (32 bytes), got {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = s.as_bytes()[2 * i] as char;
        let lo = s.as_bytes()[2 * i + 1] as char;
        out[i] = (hex_val(hi)? << 4) | hex_val(lo)?;
    }
    Ok(out)
}

fn hex_val(c: char) -> Result<u8, anyhow::Error> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok(10 + (c as u8) - b'a'),
        'A'..='F' => Ok(10 + (c as u8) - b'A'),
        _ => anyhow::bail!("invalid hex char '{}'", c),
    }
}

fn to_hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    s
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

async fn test_flow(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    address: Pubkey,
    provider_url: &str,
) -> Result<(), anyhow::Error> {
    use solana_sdk::keccak;
    use tokio::time::{sleep, Duration};

    // 1) Wait until the var is ready (>= end_at + small buffer)
    {
        let buffer_slots = 4;
        loop {
            let clock = get_clock(rpc).await?;
            let var = get_var(rpc, address).await?;
            if clock.slot >= var.end_at + buffer_slots {
                println!(
                    "Ready: current_slot={} end_at={} (buffer={})",
                    clock.slot, var.end_at, buffer_slots
                );
                break;
            }
            let remaining = (var.end_at + buffer_slots).saturating_sub(clock.slot);
            let est_ms = (remaining.max(1) as u64) * 400;
            let est_s = (est_ms as f64) / 1000.0;
            println!(
                "Waiting for readiness... remaining slots: {} (~{:.1}s)",
                remaining, est_s
            );
            sleep(Duration::from_millis(est_ms.min(10_000))).await;
        }
    }

    // 2) Submit Sample first
    {
        let sample_ix = entropy_api::sdk::sample(payer.pubkey(), address);
        submit_transaction(rpc, payer, &[sample_ix]).await?;
        println!("Sample submitted.");
    }

    // 3) Poll on-chain until slot_hash is recorded
    {
        let mut attempts = 0;
        loop {
            let var = get_var(rpc, address).await?;
            if var.slot_hash != [0; 32] {
                println!("slot_hash recorded.");
                break;
            }
            attempts += 1;
            if attempts > 20 {
                anyhow::bail!("slot_hash not recorded after polling");
            }
            sleep(Duration::from_millis(400)).await;
        }
    }

    // 4) Fetch seed from provider with retry (handles 425 Too Early)
    let seed_bytes: [u8; 32] = {
        let url = format!("{}/var/{}/seed", provider_url.trim_end_matches('/'), address);
        let mut attempts = 0;
        loop {
            let resp = reqwest::get(&url).await?;
            if resp.status().is_success() {
                let seed_response: entropy_types::response::GetSeedResponse = resp.json().await?;
                println!("Fetched seed: {:?}", seed_response.seed);
                break seed_response.seed;
            } else if resp.status().as_u16() == 425 {
                attempts += 1;
                if attempts > 20 {
                    anyhow::bail!("provider not ready to serve seed after retries");
                }
                println!("Provider not ready (425). Retrying...");
                sleep(Duration::from_millis(400)).await;
                continue;
            } else {
                anyhow::bail!("provider error: {}", resp.status());
            }
        }
    };

    // 5) Submit Reveal
    {
        let reveal_ix = entropy_api::sdk::reveal(payer.pubkey(), address, seed_bytes);
        submit_transaction(rpc, payer, &[reveal_ix]).await?;
        println!("Reveal submitted.");
    }

    // 6) Poll until on-chain seed/value are set (finalized)
    let var_after = {
        let mut last: Option<Var> = None;
        let mut attempts = 0;
        loop {
            let v = get_var(rpc, address).await?;
            if v.seed != [0; 32] && v.value != [0; 32] {
                last = Some(v);
                break;
            }
            attempts += 1;
            if attempts > 20 {
                anyhow::bail!("seed/value not recorded after reveal");
            }
            sleep(Duration::from_millis(400)).await;
        }
        last.unwrap()
    };

    // 7) Verify on-chain state and computed value
    if var_after.seed != seed_bytes {
        anyhow::bail!("on-chain seed does not match revealed seed");
    }
    if var_after.slot_hash == [0; 32] {
        anyhow::bail!("slot_hash was not recorded");
    }
    if var_after.value == [0; 32] {
        anyhow::bail!("value was not finalized");
    }
    let commit_from_seed = keccak::hash(&seed_bytes).to_bytes();
    if commit_from_seed != var_after.commit {
        anyhow::bail!("commit mismatch: keccak(seed) != on-chain commit");
    }
    let expected_value =
        keccak::hashv(&[&var_after.slot_hash, &var_after.seed, &var_after.samples.to_le_bytes()])
            .to_bytes();
    if expected_value != var_after.value {
        anyhow::bail!("value mismatch: expected != on-chain");
    }
    println!("Reveal verified: value matches expected computation.");

    Ok(())
}

async fn log_var(rpc: &RpcClient, address: Pubkey) -> Result<(), anyhow::Error> {
    let var = get_var(rpc, address).await?;
    print_var(&var);
    Ok(())
}

fn print_var(var: &Var) {
    println!("Var: {:?}", var);
    println!("  Authority: {:?}", var.authority);
    println!("  Provider: {:?}", var.provider);
    println!(
        "  Commit: {:?}",
        keccak::Hash::new_from_array(var.commit).to_string()
    );
    println!(
        "  Seed: {:?}",
        keccak::Hash::new_from_array(var.seed).to_string()
    );
    println!(
        "  Slot hash: {:?}",
        keccak::Hash::new_from_array(var.slot_hash).to_string()
    );
    println!(
        "  Value: {:?}",
        keccak::Hash::new_from_array(var.value).to_string()
    );
    println!("  Samples: {:?}", var.samples);
    println!("  Is auto: {:?}", var.is_auto);
}

async fn get_clock(rpc: &RpcClient) -> Result<Clock, anyhow::Error> {
    let data = rpc.get_account_data(&solana_sdk::sysvar::clock::ID).await?;
    let clock = bincode::deserialize::<Clock>(&data)?;
    Ok(clock)
}

async fn get_var(rpc: &RpcClient, address: Pubkey) -> Result<Var, anyhow::Error> {
    let account = rpc.get_account(&address).await?;
    let var = Var::try_from_bytes(&account.data)?;
    Ok(*var)
}

#[allow(dead_code)]
async fn simulate_transaction(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
) {
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let x = rpc
        .simulate_transaction(&Transaction::new_signed_with_payer(
            instructions,
            Some(&payer.pubkey()),
            &[payer],
            blockhash,
        ))
        .await;
    println!("Simulation result: {:?}", x);
}

#[allow(dead_code)]
async fn simulate_transaction_with_address_lookup_tables(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
    address_lookup_table_accounts: Vec<AddressLookupTableAccount>,
) {
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let tx = VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::V0(
            Message::try_compile(
                &payer.pubkey(),
                instructions,
                &address_lookup_table_accounts,
                blockhash,
            )
            .unwrap(),
        ),
    };
    let s = tx.sanitize();
    println!("Sanitize result: {:?}", s);
    s.unwrap();
    let x = rpc.simulate_transaction(&tx).await;
    println!("Simulation result: {:?}", x);
}

#[allow(unused)]
async fn submit_transaction_batches(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    mut ixs: Vec<solana_sdk::instruction::Instruction>,
    batch_size: usize,
) -> Result<(), anyhow::Error> {
    // Batch and submit the instructions.
    while !ixs.is_empty() {
        let batch = ixs
            .drain(..std::cmp::min(batch_size, ixs.len()))
            .collect::<Vec<Instruction>>();
        submit_transaction_no_confirm(rpc, payer, &batch).await?;
    }
    Ok(())
}

#[allow(unused)]
async fn simulate_transaction_batches(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    mut ixs: Vec<solana_sdk::instruction::Instruction>,
    batch_size: usize,
) -> Result<(), anyhow::Error> {
    // Batch and submit the instructions.
    while !ixs.is_empty() {
        let batch = ixs
            .drain(..std::cmp::min(batch_size, ixs.len()))
            .collect::<Vec<Instruction>>();
        simulate_transaction(rpc, payer, &batch).await;
    }
    Ok(())
}

async fn submit_transaction(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
) -> Result<solana_sdk::signature::Signature, anyhow::Error> {
    let blockhash = rpc.get_latest_blockhash().await?;
    let mut all_instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ComputeBudgetInstruction::set_compute_unit_price(1_000_000),
    ];
    all_instructions.extend_from_slice(instructions);
    let transaction = Transaction::new_signed_with_payer(
        &all_instructions,
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );

    match rpc.send_and_confirm_transaction(&transaction).await {
        Ok(signature) => {
            println!("Transaction submitted: {:?}", signature);
            Ok(signature)
        }
        Err(e) => {
            println!("Error submitting transaction: {:?}", e);
            Err(e.into())
        }
    }
}

async fn submit_transaction_no_confirm(
    rpc: &RpcClient,
    payer: &solana_sdk::signer::keypair::Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
) -> Result<solana_sdk::signature::Signature, anyhow::Error> {
    let blockhash = rpc.get_latest_blockhash().await?;
    let mut all_instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ComputeBudgetInstruction::set_compute_unit_price(1_000_000),
    ];
    all_instructions.extend_from_slice(instructions);
    let transaction = Transaction::new_signed_with_payer(
        &all_instructions,
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );

    match rpc.send_transaction(&transaction).await {
        Ok(signature) => {
            println!("Transaction submitted: {:?}", signature);
            Ok(signature)
        }
        Err(e) => {
            println!("Error submitting transaction: {:?}", e);
            Err(e.into())
        }
    }
}

pub async fn get_program_accounts<T>(
    client: &RpcClient,
    program_id: Pubkey,
    filters: Vec<RpcFilterType>,
) -> Result<Vec<(Pubkey, T)>, anyhow::Error>
where
    T: AccountDeserialize + Discriminator + Clone,
{
    let mut all_filters = vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
        0,
        &T::discriminator().to_le_bytes(),
    ))];
    all_filters.extend(filters);
    let result = client
        .get_program_accounts_with_config(
            &program_id,
            RpcProgramAccountsConfig {
                filters: Some(all_filters),
                account_config: RpcAccountInfoConfig {
                    encoding: Some(UiAccountEncoding::Base64),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;

    match result {
        Ok(accounts) => {
            let accounts = accounts
                .into_iter()
                .filter_map(|(pubkey, account)| {
                    if let Ok(account) = T::try_from_bytes(&account.data) {
                        Some((pubkey, account.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(accounts)
        }
        Err(err) => match err.kind {
            ClientErrorKind::Reqwest(err) => {
                if let Some(status_code) = err.status() {
                    if status_code == StatusCode::GONE {
                        panic!(
                                "\n{} Your RPC provider does not support the getProgramAccounts endpoint, needed to execute this command. Please use a different RPC provider.\n",
                                "ERROR"
                            );
                    }
                }
                return Err(anyhow::anyhow!("Failed to get program accounts: {}", err));
            }
            _ => return Err(anyhow::anyhow!("Failed to get program accounts: {}", err)),
        },
    }
}
