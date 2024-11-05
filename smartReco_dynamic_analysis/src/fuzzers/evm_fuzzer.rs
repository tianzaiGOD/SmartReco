use std::cell::RefCell;
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;
use std::str::FromStr;
// use std::sync::Arc;
use revm_primitives::B256;
use crate::state::HasTargetVictimFunction;
use crate::{
    evm::contract_utils::FIX_DEPLOYER, evm::host::FuzzHost, evm::vm::EVMExecutor,

};
use crate::dapp_utils::CreatorDapp;
use crate::evm::host::ACTIVE_MATCH_EXT_CALL;
use crate::evm::vm::EVMState;

use crate::evm::config::Config;
use crate::evm::corpus_initializer::EVMCorpusInitializer;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};
use crate::evm::onchain::onchain::OnChain;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMU256, fixed_address};
use crate::evm::srcmap::parser::BASE_PATH;

pub fn evm_fuzzer(
    config: Config, state: &mut EVMFuzzState
) {
    // create work dir if not exists
    let path = Path::new(config.work_dir.as_str());
    if !path.exists() {
        std::fs::create_dir(path).unwrap();
    }


    let deployer = fixed_address(FIX_DEPLOYER);

    let target_tx = state.get_target_function_tx().clone();
    let victim_tx = state.get_victim_function_tx().clone();
    let workdir = format!("record_data/verify/{:?}/unknown", victim_tx.to );
    let mut fuzz_host = FuzzHost::new(workdir);
    fuzz_host.set_spec_id(config.spec_id);
    fuzz_host.current_block_hash = B256::from_str(&state.get_target_function_tx().blockHash).unwrap();
    let onchain_clone = config.onchain.clone().unwrap();
    fuzz_host.origin = target_tx.to;
    fuzz_host.is_verified = config.is_verified;
    fuzz_host.set_block_timestamp(onchain_clone.block_number, onchain_clone.timestamp);
    let contracts = config.contract_loader.clone().contracts;
    for contract in contracts {
        let address_to_dapp_info = CreatorDapp::new(contract.deployed_address, contract.creator, contract.dapp);
        fuzz_host.set_contract_dapp_info(contract.deployed_address, address_to_dapp_info);
    }
    fuzz_host.target_dependency = hex::decode(&config.related_function_signature[2..10]).expect("Fail");
    fuzz_host.target_dependency_function_name = config.related_function_name;
    match config.onchain.clone() {
        Some(onchain) => {
            Some({
                let mid = Rc::new(RefCell::new(
                    OnChain::<EVMState, EVMInput, EVMFuzzState>::new(
                        onchain,
                        config.onchain_storage_fetching.unwrap(),
                    ),
                ));
                fuzz_host.add_middlewares(mid.clone());
                mid
            })
        }
        None => {
            unsafe {
                ACTIVE_MATCH_EXT_CALL = true;
            }
            None
        }
    };

    unsafe {
        BASE_PATH = config.base_path;
    }

    let mut evm_executor: EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput> =
        EVMExecutor::new(fuzz_host, deployer, victim_tx.to);

    let mut corpus_initializer = EVMCorpusInitializer::new(
        &mut evm_executor,
        state,
    );


    corpus_initializer.initialize_contract(&mut config.contract_loader.clone());

    evm_executor.host.initialize(state);


    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));
    evm_executor_ref.deref().borrow_mut().execute_abi(target_tx, state);
}
