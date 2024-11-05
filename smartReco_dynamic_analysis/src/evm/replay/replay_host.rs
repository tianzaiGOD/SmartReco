use crate::evm::host::{FuzzHost, is_precompile};
use crate::evm::input::{ConciseEVMInput, EVMInputT};
use crate::evm::middlewares::middleware::Middleware;

use bytes::Bytes;
use libafl::prelude::{HasCorpus, HasRand, HasMetadata};
use libafl::state::State;
use revm_interpreter::InstructionResult::Continue;


use std::cell::RefCell;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use revm_interpreter::{BytecodeLocked, CallContext, CallInputs, Contract, CreateInputs, Gas, Host, InstructionResult, Interpreter, SelfDestructResult};
use revm_primitives::{B256, Bytecode, Env, LatestSpec, U256};
use crate::evm::types::{EVMAddress, EVMU256};

use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;

use crate::state::{HasCaller, HasHashToAddress, HasTargetVictimFunction, HasAddressToDapp};
use revm_primitives::{SpecId, FrontierSpec, HomesteadSpec, TangerineSpec, SpuriousDragonSpec, ByzantiumSpec,
                      PetersburgSpec, IstanbulSpec, BerlinSpec, LondonSpec, MergeSpec, ShanghaiSpec};

use crate::dapp_utils::CreatorDapp;
use crate::evm::input::EtherscanTransaction;
use super::replay_record::{DappRecordData, CallGraphNode};
use crate::invoke_middlewares;

pub static mut GLOBAL_CALL_CONTEXT: Option<CallContext> = None;

/// wrap of FuzzHost, in order to reuse middleware
pub struct ReplayFuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    pub fuzzhost: FuzzHost<VS, I, S>,
    pub dapp: String,
    pub same_dapp: bool,
    pub execute_dapp_data: DappRecordData,
    pub tx_hash: String,
    pub call_stack_cache: CallGraphNode,
    pub is_delegate_call: bool,
}

impl<VS, I, S> Debug for ReplayFuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzHost")
            .field("key", &self.dapp)
            .finish()
    }
}

// all clones would not include middlewares and states
impl<VS, I, S> Clone for ReplayFuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    fn clone(&self) -> Self {
        Self {
            fuzzhost: self.fuzzhost.clone(),
            dapp: self.dapp.clone(),
            same_dapp: self.same_dapp,
            tx_hash: self.tx_hash.clone(),
            execute_dapp_data: self.execute_dapp_data.clone(),
            call_stack_cache: self.call_stack_cache.clone(),
            is_delegate_call: false,
        }
    }
}

impl<VS, I, S> ReplayFuzzHost<VS, I, S>
where
    S: State + HasRand + HasCaller<EVMAddress> + Debug + Clone + HasCorpus<I> + HasTargetVictimFunction + HasAddressToDapp + HasMetadata + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
{
    pub fn new(workdir: String, tx_hash: String, root_contract: EVMAddress, function_signature: String) -> Self {
        // let path = tx_hash;
        Self {
            fuzzhost: FuzzHost::new(workdir),
            same_dapp: true,
            dapp: String::new(),
            tx_hash,
            execute_dapp_data: DappRecordData::new(),
            call_stack_cache: CallGraphNode::new(root_contract, "root".to_string(), true, function_signature),
            is_delegate_call: false,
        }
    }

    pub fn init_dapp_name(&mut self, name: &str) {
        self.dapp = name.to_string();
    }

    pub fn set_block_timestamp(&mut self, block_number: String, timestamp: String) {
        self.fuzzhost.set_block_timestamp(block_number, timestamp);
    }

    pub fn set_env(&mut self, tx: &EtherscanTransaction) {
        self.fuzzhost.set_env(tx);
    }

    pub fn change_env(&mut self, from: Option<EVMAddress>, to: EVMAddress, value: U256, data: &Bytes) {
        self.fuzzhost.change_env(from, to, value, data, None, None);
    }

    pub fn set_spec_id(&mut self, spec_id: String) {
        self.fuzzhost.set_spec_id(spec_id);
    }

    pub fn run_inspect(
        &mut self,
        mut interp: &mut Interpreter,
        mut state:  &mut S,
    ) -> InstructionResult {
        match self.fuzzhost.spec_id {
            SpecId::LATEST => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, LatestSpec>(self, state),
            SpecId::FRONTIER => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, FrontierSpec>(self, state),
            SpecId::HOMESTEAD => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, HomesteadSpec>(self, state),
            SpecId::TANGERINE => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, TangerineSpec>(self, state),
            SpecId::SPURIOUS_DRAGON => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, SpuriousDragonSpec>(self, state),
            SpecId::BYZANTIUM => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, ByzantiumSpec>( self, state),
            SpecId::CONSTANTINOPLE | SpecId::PETERSBURG => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, PetersburgSpec>(self, state),
            SpecId::ISTANBUL => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, IstanbulSpec>(self, state),
            SpecId::MUIR_GLACIER | SpecId::BERLIN => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, BerlinSpec>(self, state),
            SpecId::LONDON => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, LondonSpec>(self, state),
            SpecId::MERGE => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, MergeSpec>(self, state),
            SpecId::SHANGHAI => interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, ShanghaiSpec>(self, state),
            _=> interp.run_inspect::<S, ReplayFuzzHost<VS, I, S>, LatestSpec>(self, state),
        }
    }

    pub fn remove_all_middlewares(&mut self) {
        self.fuzzhost.remove_all_middlewares()
    }

    pub fn add_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<VS, I, S>>>) {
        self.fuzzhost.add_middlewares(middlewares)
    }

    pub fn remove_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<VS, I, S>>>) {
        self.fuzzhost.remove_middlewares(middlewares)
    }

    pub fn initialize(&mut self, state: &S)
    where
        S: HasHashToAddress,
    {
        self.fuzzhost.initialize(state)
    }

    pub fn get_contract_dapp_info(&mut self, address: EVMAddress, state: &mut S) -> Option<CreatorDapp> {
        self.fuzzhost.get_contract_dapp_info(address, state)
    }

    pub fn set_contract_dapp_info(&mut self, address: EVMAddress, dapp: CreatorDapp) {
        self.init_dapp_name(&dapp.dapp);
        self.fuzzhost.set_contract_dapp_info(address, dapp)
    }

    pub fn add_call_depth(&mut self) {
        self.fuzzhost.add_call_depth()
    }

    pub fn sub_call_depth(&mut self) {
        self.fuzzhost.sub_call_depth()
    }

    pub fn set_call_to(&mut self, address: EVMAddress) {
        self.fuzzhost.set_call_to(address)
    }

    pub fn get_call_to(&mut self) -> EVMAddress {
        self.fuzzhost.get_call_to()
    }

    pub fn send_balance(&mut self, from_address: EVMAddress, to_address: EVMAddress, transfer_value: U256) -> bool {
        self.fuzzhost.send_balance(from_address, to_address, transfer_value)
    }

    pub fn set_codedata(&mut self, address: EVMAddress, mut code: Bytecode) {
        self.fuzzhost.set_codedata(address, code)
    }

    pub fn clear_codedata(&mut self) {
        self.fuzzhost.clear_codedata()
    }

    pub fn set_code(&mut self, address: EVMAddress, mut code: Bytecode, state: &mut S) {
        self.fuzzhost.set_code(address, code, state)
    }

    pub fn call_precompile(&mut self, input: &mut CallInputs, state: &mut S) -> (InstructionResult, Gas, Bytes) {
        self.fuzzhost.call_precompile(input, state)
    }

    pub fn replay_call(&mut self, input: &mut CallInputs, state: &mut S) -> (InstructionResult, Gas, Bytes) {
        let from = input.context.caller;
        let to = input.context.address;
        
        println!("From host.rs fun divide_call_by_is_same_dapp call depth: {:?}", self.fuzzhost.call_depth);
        println!("From host.rs fun divide_call_by_is_same_dapp call code: {:?}", input.context.scheme);
        println!("From host.rs fun divide_call_by_is_same_dapp from: {:?}", from);
        println!("From host.rs fun divide_call_by_is_same_dapp to: {:?}", to);
        println!("From host.rs fun divide_call_by_is_same_dapp input: 0x{:}", input.input.iter().map(|byte| format!("{:02x}", byte)).collect::<String>());
        let mut old_call_context = None;
        let old_env;
        let mut interp;
        macro_rules! ret_back_ctx {
            () => {
                unsafe {
                    GLOBAL_CALL_CONTEXT = old_call_context;
                }
            };
        }

        unsafe {
            old_call_context = GLOBAL_CALL_CONTEXT.clone();
            old_env = self.fuzzhost.env.clone();
            GLOBAL_CALL_CONTEXT = Some(input.context.clone());
            self.change_env(None, to, input.context.apparent_value, &input.input);
            // if there is code, then call the code
            interp = if let Some(code) = self.fuzzhost.code.get(&input.context.code_address) {
                Interpreter::new(
                    Contract::new_with_context_analyzed(
                        Bytes::from(input.input.to_vec()),
                        code.clone(),
                        &input.context,
                    ),
                    1e10 as u64,
                    false
                )
            } else {
                Interpreter::new(
                    Contract::new_with_context_analyzed(
                        Bytes::from(input.input.to_vec()),
                        Default::default(),
                        &input.context,
                    ),
                    1e10 as u64,
                    false
                )
            };
            let additional_value = input.context.apparent_value;
            if additional_value > U256::ZERO {
                invoke_middlewares!(&mut self.fuzzhost, &mut interp, state, on_get_additional_information);
                match self.send_balance(from, to, input.transfer.value) {
                    false => return (InstructionResult::OutOfFund, Gas::new(0), Bytes::new()),
                    true => ()
                };
            };
        }
        let res = if let Some(_code) = self.fuzzhost.code.get(&input.context.code_address) {
            let ret = self.run_inspect(&mut interp, state);
            (ret, Gas::new(0), interp.return_value())
        } else { // transfer txn and fallback provided
            let input = input.input.to_vec();
            (Continue, Gas::new(0), Bytes::from(input))
        };
        ret_back_ctx!();
        self.fuzzhost.env = old_env;
        res
    }

    pub fn is_from_same_dapp(&mut self, info: CreatorDapp) {
        if info.dapp.contains("unknown") {
            self.same_dapp = false;
            return
        }
        self.same_dapp = info.dapp == self.dapp;
    }

    pub fn extract_function_signature_from_input(&mut self, input: &Bytes) -> Vec<u8> {
        self.fuzzhost.extract_function_signature_from_input(input)
    }
}

impl<VS, I, S> Host<S> for ReplayFuzzHost<VS, I, S>
where
    S: State +HasRand + HasCaller<EVMAddress> + Debug + Clone + HasCorpus<I> + HasMetadata + HasTargetVictimFunction + HasAddressToDapp + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
{
    fn step(&mut self, interp: &mut Interpreter, state: &mut S) -> InstructionResult {
        unsafe {
            invoke_middlewares!(&mut self.fuzzhost, interp, state, on_step);
        }

        let opcode = unsafe {
            *interp.instruction_pointer
        };
        let address = interp.contract.address;
        let input_data = hex::encode(&interp.contract.input);

        unsafe {
            match opcode {
                0x55 => {
                    // SSTORE
                    self.call_stack_cache.add_write();
                }
                0x54 => {
                    // SLOAD
                    self.call_stack_cache.add_read();
                }
                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                    match opcode {
                        // Delegatecall
                        0xf4 => {
                            self.is_delegate_call = true;
                        },
                        _ => ()
                    };
                    
                }
                _ => {}
            }
        }

        return Continue;
    }

    fn step_end(&mut self, _interp: &mut Interpreter, _ret: InstructionResult, _: &mut S) -> InstructionResult {
        return Continue;
    }

    fn env(&mut self) -> &mut Env {
        self.fuzzhost.env()
    }

    fn load_account(&mut self, _address: EVMAddress) -> Option<(bool, bool)> {
        Some((
            true,
            true, // self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, _number: EVMU256) -> Option<B256> {
        self.fuzzhost.block_hash(_number)
    }

    fn balance(&mut self, _address: EVMAddress) -> Option<(EVMU256, bool)> {
        self.fuzzhost.balance(_address)
    }

    fn code(&mut self, address: EVMAddress) -> Option<(Arc<BytecodeLocked>, bool)> {
        self.fuzzhost.code(address)
    }

    fn code_hash(&mut self, _address: EVMAddress) -> Option<(B256, bool)> {
        self.fuzzhost.code_hash(_address)
    }

    fn sload(&mut self, address: EVMAddress, index: EVMU256) -> Option<(EVMU256, bool)> {
        self.fuzzhost.sload(address, index)
    }

    fn sstore(
        &mut self,
        address: EVMAddress,
        index: EVMU256,
        value: EVMU256,
    ) -> Option<(EVMU256, EVMU256, EVMU256, bool)> {
        self.fuzzhost.sstore(address, index, value)
    }

    fn log(&mut self, _address: EVMAddress, _topics: Vec<B256>, _data: Bytes) {
        self.fuzzhost.log(_address, _topics, _data)
    }

    fn selfdestruct(&mut self, _address: EVMAddress, _target: EVMAddress) -> Option<SelfDestructResult> {
        return Some(SelfDestructResult::default());
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
        state: &mut S,
    ) -> (InstructionResult, Option<EVMAddress>, Gas, Bytes) {
        self.fuzzhost.create(inputs, state)
    }

    fn call(&mut self, input: &mut CallInputs, interp: &mut Interpreter, output_info: (usize, usize), state: &mut S) -> (InstructionResult, Gas, Bytes) {
        self.add_call_depth();

        // the call information has alreardy update in input
        let target_address = input.contract;
        let target_function_name = self.extract_function_signature_from_input(&input.input);
        let info = self.get_contract_dapp_info(target_address, state).unwrap();
        self.is_from_same_dapp(info.clone());

        // smartReco think a contract is proxy only if 
        // current function signarture and target function signature are same
        // and is a Deleagatecall
        if self.is_delegate_call {
            let current_function_name = self.extract_function_signature_from_input(&interp.contract.input);
            if current_function_name == target_function_name {
                self.execute_dapp_data.add_dapp_contact(interp.contract.address, target_address);
            }
            self.is_delegate_call = false;
        }
    
        
        let res = if is_precompile(input.contract, self.fuzzhost.precompiles.len()) {
            self.call_precompile(input, state)
        } else {
            if !self.same_dapp {
                self.execute_dapp_data.add_invoke(&info, &format!("0x{:}", hex::encode(target_function_name.clone())));
            }
            let mut node_cache = self.call_stack_cache.clone();
            self.call_stack_cache = CallGraphNode::new(target_address, info.dapp, self.same_dapp, format!("0x{:}", hex::encode(target_function_name.clone())));
            
            let res = self.replay_call(input, state);
            
            node_cache.add_child(self.call_stack_cache.clone());
            self.call_stack_cache = node_cache;
            res
        };
        
        self.sub_call_depth();
        unsafe {
            invoke_middlewares!(&mut self.fuzzhost, interp, state, on_return);
        }
        res
    }
}