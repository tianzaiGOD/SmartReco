/// Utilities to initialize the corpus
/// Add all potential calls with default args to the corpus
use crate::evm::abi::{BoxedABI, get_abi_type_boxed, get_abi_type_boxed_with_state};
use crate::evm::bytecode_analyzer;
use crate::evm::contract_utils::{ABIConfig, ABIInfo, ContractInfo, ContractLoader, extract_sig_from_contract};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputTy};
use crate::evm::types::{fixed_address, EVMFuzzState, EVMAddress, EVMU256, ProjectSourceMapTy, EVMExecutionResult, EVMBytes};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;

use crate::state::HasCaller;
use bytes::Bytes;
use revm_primitives::Bytecode;
#[cfg(feature = "print_txn_corpus")]
use std::collections::{HashMap, HashSet};
use libafl::impl_serdeany;
use serde::{Deserialize, Serialize};

pub struct EVMCorpusInitializer<'a> {
    executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
    state: &'a mut EVMFuzzState,
    #[cfg(feature = "use_presets")]
    presets: Vec<&'a dyn Preset<EVMInput, EVMFuzzState, EVMState>>,
}

pub struct EVMInitializationArtifacts {
    pub address_to_sourcemap: ProjectSourceMapTy,
    pub address_to_abi: HashMap<EVMAddress, Vec<ABIConfig>>,
    pub address_to_abi_object: HashMap<EVMAddress, Vec<BoxedABI>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ABIMap {
    pub signature_to_abi: HashMap<[u8; 4], ABIConfig>,
}

impl_serdeany!(ABIMap);

impl ABIMap {
    pub fn new() -> Self {
        Self {
            signature_to_abi: HashMap::new(),
        }
    }

    pub fn insert(&mut self, abi: ABIConfig) {
        self.signature_to_abi.insert(abi.function.clone(), abi);
    }

    pub fn get(&self, signature: &[u8; 4]) -> Option<&ABIConfig> {
        self.signature_to_abi.get(signature)
    }
}

impl<'a> EVMCorpusInitializer<'a> {
    pub fn new(
        executor: &'a mut EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>,
        state: &'a mut EVMFuzzState,
    ) -> Self {
        Self {
            executor,
            state,
            #[cfg(feature = "use_presets")]
            presets: vec![],
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
