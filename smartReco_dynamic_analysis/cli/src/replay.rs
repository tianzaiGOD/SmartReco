use clap::Parser;
use smartReco::evm::config::{ReplayConfig, FuzzerTypes, StorageFetchingMode};
use smartReco::evm::contract_utils::ContractLoader;
use smartReco::evm::input::{ConciseEVMInput, EVMInput, EtherscanTransaction};
use smartReco::evm::onchain::endpoints::{Chain, OnChainConfig};
// use smartReco::evm::onchain::flashloan::DummyPriceOracle;

use smartReco::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
use smartReco::evm::vm::EVMState;
use smartReco::fuzzers::revm_fuzzer::evm_fuzzer;
// use smartReco::oracle::{Oracle, Producer};
use smartReco::state::{FuzzState, HasCaller};
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::str::FromStr;
use revm_primitives::{U256, ruint::Uint};

/// CLI for smartReco for EVM smart contracts
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ReplayEvmArgs {
    /// Glob pattern / address to find contracts

    //the function need to run
    #[arg(long)]
    target_function: String,
    
    //the contract need to run
    #[arg(long)]
    target_contract: String,

    #[arg(long, default_value = "false")]
    fetch_tx_data: bool,

    #[arg(long, default_value = "http://localhost:5001/data")]
    proxy_address: String,

    /// Enable onchain
    #[arg(short, long, default_value = "false")]
    onchain: bool,

    /// Onchain - Chain type (ETH, BSC, POLYGON, MUMBAI)
    #[arg(short, long)]
    chain_type: Option<String>,

    /// Onchain - target Block number (Default: 0 / latest)
    #[arg(long)]
    target_onchain_block_number: u64,

    /// Onchain - target Block timestamp (Default: 0 / latest)
    #[arg(long)]
    target_onchain_block_timestamp: u64,

    /// EOA of invoke target tx
    #[arg(long)]
    target_from_address: String,

    /// input of target tx
    #[arg(long)]
    target_tx_input: String,

    /// hash of target tx
    #[arg(long)]
    target_tx_hash: String,

    /// name of target function
    #[arg(long)]
    target_fn_name: String,

    /// value of target tx
    #[arg(long)]
    target_value: String,

    /// is target transaction execute successful
    #[arg(long)]
    target_tx_is_error: u64,

    /// Onchain Customize - Endpoint URL (Default: inferred from chain-type)
    #[arg(long)]
    onchain_url: Option<String>,

    /// Onchain Customize - Chain ID (Default: inferred from chain-type)
    #[arg(long)]
    onchain_chain_id: Option<u32>,

    /// Onchain Customize - Block explorer URL (Default: inferred from chain-type)
    #[arg(long)]
    onchain_explorer_url: Option<String>,

    /// Onchain Customize - Chain name (used as Moralis handle of chain) (Default: inferred from chain-type)
    #[arg(long)]
    onchain_chain_name: Option<String>,

    /// Onchain Etherscan API Key (Default: None)
    #[arg(long)]
    onchain_etherscan_api_key: Option<String>,

    /// Onchain Local Proxy Address (Default: None)
    #[arg(long)]
    onchain_local_proxy_addr: Option<String>,

    /// Onchain which fetching method to use (All, Dump, OneByOne) (Default: OneByOne)
    #[arg(long, default_value = "onebyone")]
    onchain_storage_fetching: String,

    /// Path of work dir, saves corpus, logs, and other stuffs
    #[arg(long, default_value = "work_dir")]
    work_dir: String,

    /// Write contract relationship to files
    #[arg(long, default_value = "false")]
    write_relationship: bool,

    /// random seed
    #[arg(long, default_value = "1667840158231589000")]
    seed: u64,

    /// Only needed when using combined.json (source map info).
    /// This is the base path when running solc compile (--base-path passed to solc).
    /// Also, please convert it to absolute path if you are not sure.
    #[arg(long, default_value = "")]
    base_path: String,

    ///spec id
    #[arg(long, default_value = "Latest")]
    spec_id: String,

    /// target transaction blockhash
    #[arg(long)]
    target_block_hash: String,

}

// enum EVMTargetType {
//     Glob,
//     Address,
// }

pub fn replay_main(args: ReplayEvmArgs) {
    println!("===========================================================================================================");
    println!("===========================================================================================================");
    println!("===========================================================================================================");
    println!("===========================================================================================================");
    println!("                                                 Replay Start!                                                 ");
    println!("===========================================================================================================");
    println!("===========================================================================================================");
    println!("===========================================================================================================");
    println!("===========================================================================================================");

    // let target_type: EVMTargetType = EVMTargetType::Address;

    let target_value: Uint<256, 4> = U256::from_str(&args.target_value).unwrap();

    let target_function_input = EtherscanTransaction {
        blockNumber: args.target_onchain_block_number - 1,
        timeStamp: args.target_onchain_block_timestamp,
        hash: args.target_tx_hash,
        blockHash: args.target_block_hash,
        from: EVMAddress::from_str(&args.target_from_address).unwrap(),
        to: EVMAddress::from_str(&args.target_contract).unwrap(),
        value: target_value,
        input: args.target_tx_input,
        functionName: args.target_fn_name,
        is_success: match args.target_tx_is_error {
            0 => true,
            _ => false,
        },
        
    };
    let victim_block_number: u64 = target_function_input.blockNumber;
    let victim_timestamp: u64 = target_function_input.timeStamp;

    let mut onchain = if args.onchain {
        match args.chain_type {
            Some(chain_str) => {
                let chain = Chain::from_str(&chain_str).expect("Invalid chain type");
                let block_number = victim_block_number;
                Some(OnChainConfig::new(chain, block_number, victim_timestamp))
            }
            None => Some(OnChainConfig::new_raw(
                args.onchain_url
                    .expect("You need to either specify chain type or chain rpc"),
                args.onchain_chain_id
                    .expect("You need to either specify chain type or chain id"),
                victim_block_number,
                victim_timestamp,
                args.onchain_explorer_url
                    .expect("You need to either specify chain type or block explorer url"),
                args.onchain_chain_name
                    .expect("You need to either specify chain type or chain name"),
            )),
        }
    } else {
        None
    };

    // let onchain_clone = onchain.clone();

    if onchain.is_some() && args.onchain_etherscan_api_key.is_some() {
        onchain
            .as_mut()
            .unwrap()
            .etherscan_api_key
            .push(args.onchain_etherscan_api_key.unwrap());
    }

    let mut state_args: EVMFuzzState = FuzzState::new_args(args.seed, args.target_function.clone(), args.target_function);

    // Trick
    state_args.set_victim_function_input(target_function_input.clone());
    state_args.set_target_function_input(target_function_input);
    state_args.set_target_function_address(EVMAddress::from_str(&args.target_contract).unwrap());

    // Add creator to Dapp information from file
    #[cfg(not (feature = "service"))]
    state_args.creator_to_dapp.add_from_file("../data/data.csv").unwrap_or_else(|err| {
        println!("Result is Err: {}", err);
        ()
    });

    let is_onchain = onchain.is_some();

    let contracts = args.target_contract.clone();

    let config = ReplayConfig {
        contract_loader: {
            if onchain.is_none() {
                panic!("Onchain is required for address target type");
            }
            let mut args_target = contracts.clone();

            let addresses: Vec<EVMAddress> = args_target
                .split(",")
                .map(|s| EVMAddress::from_str(s).unwrap())
                .collect();
            ContractLoader::from_address(
                &mut onchain.as_mut().unwrap(),
                HashSet::from_iter(addresses),
                &mut state_args.creator_to_dapp,
            )
        },
        onchain,
        onchain_storage_fetching: if is_onchain {
            Some(
                StorageFetchingMode::from_str(args.onchain_storage_fetching.as_str())
                    .expect("unknown storage fetching mode"),
            )
        } else {
            None
        },
        work_dir: args.work_dir,
        write_relationship: args.write_relationship,
        base_path: args.base_path,
        spec_id: args.spec_id,
        // bytes_pool,
    };
    evm_fuzzer(config, &mut state_args);
}