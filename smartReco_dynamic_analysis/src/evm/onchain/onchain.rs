use crate::evm::abi::{get_abi_type_boxed, register_abi_instance};
use crate::evm::bytecode_analyzer;
use crate::evm::config::StorageFetchingMode;
use crate::evm::contract_utils::{ABIConfig, ContractLoader, extract_sig_from_contract};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};

use crate::evm::host::FuzzHost;
use crate::evm::middlewares::middleware::{add_corpus, Middleware, MiddlewareType};
// use crate::evm::mutator::AccessPattern;
use crate::evm::onchain::abi_decompiler::fetch_abi_heimdall;
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::vm::IS_REPLAY_CALL;
use crate::generic_vm::vm_state::VMStateT;
// use crate::handle_contract_insertion;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasAddressToDapp, HasTargetVictimFunction};
use crate::state_input::StagedVMState;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use libafl::corpus::Corpus;
use libafl::prelude::{HasCorpus, HasMetadata, Input};

use libafl::state::{HasRand, State};
use revm_primitives::ruint::Uint;


use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

// use crate::evm::onchain::flashloan::register_borrow_txn;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use itertools::Itertools;
use revm_interpreter::Interpreter;
use revm_primitives::{Bytecode, B256};
use crate::evm::corpus_initializer::ABIMap;
use crate::evm::types::{convert_u256_to_h160, EVMAddress, EVMU256, bytes_to_u64};

pub static mut BLACKLIST_ADDR: Option<HashSet<EVMAddress>> = None;

const UNBOUND_THRESHOLD: usize = 30;

pub struct OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput>,
    S: State,
    VS: VMStateT + Default,
{
    pub loaded_data: HashSet<(EVMAddress, EVMU256)>,
    pub loaded_code: HashSet<EVMAddress>,
    pub loaded_abi: HashSet<EVMAddress>,
    pub calls: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
    pub locs: HashMap<(EVMAddress, usize), HashSet<EVMU256>>,
    pub endpoint: OnChainConfig,
    pub blacklist: HashSet<EVMAddress>,
    pub storage_fetching: StorageFetchingMode,
    pub storage_all: HashMap<EVMAddress, Arc<HashMap<String, EVMU256>>>,
    pub storage_dump: HashMap<EVMAddress, Arc<HashMap<EVMU256, EVMU256>>>,
    pub phantom: std::marker::PhantomData<(I, S, VS)>,
}

impl<VS, I, S> Debug for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput>,
    S: State,
    VS: VMStateT + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnChain")
            .field("loaded_data", &self.loaded_data)
            .field("loaded_code", &self.loaded_code)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl<VS, I, S> OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput>,
    S: State,
    VS: VMStateT + Default,
{
    pub fn new(endpoint: OnChainConfig, storage_fetching: StorageFetchingMode) -> Self {
        unsafe {
            BLACKLIST_ADDR = Some(HashSet::from([
                EVMAddress::zero()
            ]));
        }
        Self {
            loaded_data: Default::default(),
            loaded_code: Default::default(),
            loaded_abi: Default::default(),
            calls: Default::default(),
            locs: Default::default(),
            endpoint,
            blacklist: HashSet::from([
                EVMAddress::zero()
            ]),
            storage_all: Default::default(),
            storage_dump: Default::default(),
            phantom: Default::default(),
            storage_fetching,
        }
    }

    pub fn add_blacklist(&mut self, address: EVMAddress) {
        unsafe {
            BLACKLIST_ADDR.as_mut().unwrap().insert(address);
        }
        self.blacklist.insert(address);
    }
}

pub fn keccak_hex(data: EVMU256) -> String {
    let mut hasher = Sha3::keccak256();
    let mut output = [0u8; 32];
    let mut input: [u8; 32] = data.to_be_bytes();
    hasher.input(input.as_ref());
    hasher.result(&mut output);
    hex::encode(&output).to_string()
}

impl<VS, I, S> Middleware<VS, I, S> for OnChain<VS, I, S>
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        +HasRand
        + Debug
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasMetadata
        + HasAddressToDapp
        + HasTargetVictimFunction
        + Clone
        + 'static,
    VS: VMStateT + Default + 'static,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        let pc = interp.program_counter();
        macro_rules! force_cache {
            ($ty: expr, $target: expr) => {
                false
            };
        }

        match *interp.instruction_pointer {
            0x54 => {
                let address = interp.contract.address;
                let slot_idx = interp.stack.peek(0).unwrap();
                let block_number = if host.is_execute_victim_function {
                    format!("0x{:x}", state.get_victim_function_tx().blockNumber)
                } else {
                    format!("0x{:x}", state.get_target_function_tx().blockNumber)
                };
                // if interp.contract.input.iter().map(|byte| format!("{:02x}", byte)).collect::<String>() == "70a08231000000000000000000000000f64e4ea924228fd94d727d528a5a519c9d2b278f".to_string() {
                //     println!("flag");
                // }
                macro_rules! load_data {
                    ($func: ident, $stor: ident, $key: ident) => {{
                        if !self.$stor.contains_key(&address) {
                            let storage = self.endpoint.$func(address);
                            if storage.is_some() {
                                self.$stor.insert(address, storage.unwrap());
                            }
                        }
                        match self.$stor.get(&address) {
                            Some(v) => v.get(&$key).unwrap_or(&EVMU256::ZERO).clone(),
                            None => self.endpoint.get_contract_slot(
                                address,
                                slot_idx,
                                block_number,
                                force_cache!(self.locs, slot_idx),
                            ),
                        }
                    }};
                    () => {};
                }
                macro_rules! slot_val {
                    () => {{
                        match self.storage_fetching {
                            StorageFetchingMode::Dump => {
                                load_data!(fetch_storage_dump, storage_dump, slot_idx)
                            }
                            StorageFetchingMode::All => {
                                // the key is in keccak256 format
                                let key = keccak_hex(slot_idx);
                                load_data!(fetch_storage_all, storage_all, key)
                            }
                            StorageFetchingMode::OneByOne => self.endpoint.get_contract_slot(
                                address,
                                slot_idx,
                                block_number,
                                false,
                            ),
                        }
                    }};
                }

                host.next_slot = slot_val!();
            }

            0x31 | 0x47 => {
                let address = match *interp.instruction_pointer {
                    // BALANCE
                    0x31 => convert_u256_to_h160(interp.stack.data()[interp.stack.len() - 1]),
                    // SELFBALANCE
                    0x47 => interp.contract.address,
                    _ => unreachable!(),
                };
                let block_number = if host.is_execute_victim_function {
                    format!("0x{:x}", state.get_victim_function_tx().blockNumber)
                } else {
                    format!("0x{:x}", state.get_target_function_tx().blockNumber)
                };
                if !host.address_to_balance.contains_key(&address) {
                    let balance = self.endpoint.get_contract_balance(address, block_number);
                    host.address_to_balance.insert(address, balance);
                }
            }
            // EXTCODEHASH
            0x3f => {
                let contract_address = convert_u256_to_h160(interp.stack.data()[interp.stack.len() - 1]);
                let force_cache = force_cache!(self.calls, contract_address);
                let block_number = if host.is_execute_victim_function {
                    format!("0x{:x}", state.get_victim_function_tx().blockNumber)
                } else {
                    format!("0x{:x}", state.get_target_function_tx().blockNumber)
                };
                match host.code.get(&contract_address) {
                    Some(code) => code.deref().hash(),
                    None => {
                        let contract_code = self.endpoint.get_contract_code(contract_address, force_cache,);
                        if !self.loaded_code.contains(&contract_address) {
                            bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
                            host.set_codedata(contract_address, contract_code.clone());
                            println!("fetching code from {:?} due to EXTCODEHASH by {:?}",
                                     contract_address, interp.contract.address);
                        }
                        contract_code.hash
                    }
                };
            }
            // BLOCKHASH
            0x40 => {
            }
            0xf1 | 0xf2 | 0xf4 | 0xfa | 0x3b | 0x3c => {
                let caller = interp.contract.address;
                let address = match *interp.instruction_pointer {
                    0xf1 | 0xf2 | 0xf4 | 0xfa => interp.stack.peek(1).unwrap(),
                    0x3b | 0x3c => interp.stack.peek(0).unwrap(),
                    _ => {
                        unreachable!()
                    }
                };
                let block_number = if host.is_execute_victim_function {
                    format!("0x{:x}", state.get_victim_function_tx().blockNumber)
                } else {
                    format!("0x{:x}", state.get_target_function_tx().blockNumber)
                };
                let address_h160 = convert_u256_to_h160(address);
                if self.loaded_abi.contains(&address_h160) {
                    return;
                }
                let force_cache = force_cache!(self.calls, address_h160);
                let contract_code = self.endpoint.get_contract_code(address_h160, force_cache, ); // get contract code
                if contract_code.is_empty() || force_cache {
                    self.loaded_code.insert(address_h160);
                    self.loaded_abi.insert(address_h160);
                    return;
                }
                if !self.loaded_code.contains(&address_h160) && !host.code.contains_key(&address_h160) {
                    // bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
                    host.set_codedata(address_h160, contract_code.clone());
                    println!("fetching code from {:?} due to call by {:?}",
                             address_h160, caller);
                }

                // setup abi
                self.loaded_abi.insert(address_h160);
                let is_proxy_call = match *interp.instruction_pointer {
                    0xf2 | 0xf4 => true,
                    _ => false,
                };
                let target = if is_proxy_call {
                    caller
                } else {
                    address_h160
                };
                state.add_address(&target);
                
                // add dapp information to host
                let info = ContractLoader::get_dapp_info(&mut self.endpoint, address_h160, state.get_creator_to_dapp_mut());
                host.set_contract_dapp_info(address_h160, info);

            }
            _ => {}
        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {

    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {}

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OnChain
    }
    unsafe fn on_get_additional_information(
            &mut self,
            interp: &mut Interpreter,
            host: &mut FuzzHost<VS, I, S>,
            state: &mut S,
        ) {
        let from_address = interp.contract.caller;
        let to_address = interp.contract.address;
        let block_number = if host.is_execute_victim_function {
            format!("0x{:x}", state.get_victim_function_tx().blockNumber)
        } else {
            format!("0x{:x}", state.get_target_function_tx().blockNumber)
        };
        match host.address_to_balance.get(&from_address) {
            None => {
                let balance = self.endpoint.get_contract_balance(from_address, block_number.clone());
                host.address_to_balance.insert(from_address, balance);
            },
            _ => (),
        };
        match host.address_to_balance.get(&to_address) {
            None => {
                let balance = self.endpoint.get_contract_balance(to_address, block_number);
                host.address_to_balance.insert(to_address, balance);
            },
            _ => (),
        }
    }
}
