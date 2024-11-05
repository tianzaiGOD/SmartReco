/// Utilities to initialize the corpus
/// Add all potential calls with default args to the corpus
use crate::evm::bytecode_analyzer;
use crate::evm::contract_utils::ContractLoader;
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::types::EVMFuzzState;
use crate::evm::vm::EVMState;
use crate::generic_vm::vm_executor::GenericVM;
use super::replay_vm::ReplayEVMExecutor;
use crate::state::HasCaller;
use revm_primitives::Bytecode;
use bytes::Bytes;

use libafl::schedulers::Scheduler;

pub struct ReplayEVMCorpusInitializer<'a> {
    executor: &'a mut ReplayEVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
    state: &'a mut EVMFuzzState,
}

impl<'a> ReplayEVMCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut ReplayEVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
        state: &'a mut EVMFuzzState,
    ) -> Self {
        Self {
            executor,
            state,
        }
    }

    pub fn initialize_contract(&mut self, loader: &mut ContractLoader) {
        for contract in &mut loader.contracts {
            println!("Deploying contract: {}", contract.name);
            let deployed_address = if !contract.is_code_deployed {
                match self.executor.deploy(
                    Bytecode::new_raw(Bytes::from(contract.code.clone())),
                    Some(Bytes::from(contract.constructor_args.clone())),
                    contract.deployed_address,
                    self.state,
                ) {
                    Some(addr) => addr,
                    None => {
                        println!("Failed to deploy contract: {}", contract.name);
                        // we could also panic here
                        continue;
                    }
                }
            } else {
                // directly set bytecode
                let contract_code = Bytecode::new_raw(Bytes::from(contract.code.clone()));
                bytecode_analyzer::add_analysis_result_to_state(&contract_code, self.state);
                self.executor
                    .host
                    .set_code(contract.deployed_address, contract_code, self.state);
                contract.deployed_address
            };

            contract.deployed_address = deployed_address;
            self.state.add_address(&deployed_address);
        }
    }
}
