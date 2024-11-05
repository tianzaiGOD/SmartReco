use std::cell::RefCell;
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;
use std::str::FromStr;

use revm_primitives::B256;

use crate::evm::contract_utils::FIX_DEPLOYER;

use crate::evm::vm::EVMState;

use crate::evm::config::ReplayConfig;
use crate::evm::replay::{replay_host::ReplayFuzzHost, replay_vm::ReplayEVMExecutor, replay_corpus_initializer::ReplayEVMCorpusInitializer};
use crate::evm::input::{ConciseEVMInput, EVMInput, };

use crate::evm::onchain::onchain::OnChain;
use crate::evm::srcmap::parser::BASE_PATH;
use crate::evm::types::{fixed_address, EVMFuzzState,};
use crate::state::HasTargetVictimFunction;
use crate::dapp_utils::CreatorDapp;

pub fn evm_fuzzer(
    config: ReplayConfig,
    state: &mut EVMFuzzState,
) {
    let path = Path::new(config.work_dir.as_str());
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }

    let target_tx = state.get_target_function_tx().clone();
    let deployer = fixed_address(FIX_DEPLOYER);
    let target_transaction_hash = target_tx.hash.clone();
    let target_function_signature = if target_tx.input.len() < 10 {
        "0x00000000".to_string()
    } else {
        format!("0x{}", target_tx.input[2..10].to_string())
    };
    let workdir = format!("record_data/verify/{:?}/unknown", target_tx.to );
    let mut fuzz_host = ReplayFuzzHost::new(workdir, target_transaction_hash, target_tx.to, target_function_signature);
    // push target address to host.origin
    fuzz_host.fuzzhost.origin = config.contract_loader.contracts[0].deployed_address;
    let onchain_clone = config.onchain.unwrap();
    fuzz_host.set_block_timestamp(onchain_clone.block_number.clone(), onchain_clone.timestamp.clone());

    fuzz_host.fuzzhost.current_block_hash = B256::from_str(&state.get_target_function_tx().blockHash).unwrap();
    
    let contracts = config.contract_loader.clone().contracts;
    for contract in contracts {
        let address_to_dapp_info = CreatorDapp::new(contract.deployed_address, contract.creator, contract.dapp);
        fuzz_host.set_contract_dapp_info(contract.deployed_address, address_to_dapp_info);
    }

    let mid = Rc::new(RefCell::new(
        OnChain::<EVMState, EVMInput, EVMFuzzState>::new(
            // scheduler can be cloned because it never uses &mut self
            onchain_clone,
            config.onchain_storage_fetching.unwrap(),
        ),
    ));

    fuzz_host.add_middlewares(mid.clone());


    unsafe {
        BASE_PATH = config.base_path;
    }

    let mut evm_executor: ReplayEVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput> =
        ReplayEVMExecutor::new(fuzz_host, deployer);

    let mut corpus_initializer = ReplayEVMCorpusInitializer::new(
        &mut evm_executor,
        // &mut scheduler,
        // &infant_scheduler,
        state,
        // config.work_dir.clone()
    );
    corpus_initializer.initialize_contract(&mut config.contract_loader.clone());
    evm_executor.host.initialize(state);

    // now evm executor is ready, we can clone it
    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));

    let res = evm_executor_ref.deref().borrow_mut().fast_call(target_tx, state);
}
