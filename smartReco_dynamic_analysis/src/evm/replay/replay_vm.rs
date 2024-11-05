/// EVM executor implementation
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use std::marker::PhantomData;
use std::ops::Deref;

use std::rc::Rc;

use crate::evm::vm::EVMState;
use crate::input::{ConciseSerde, VMInputT};
use bytes::Bytes;

use libafl::prelude::{HasMetadata, HasRand};
use libafl::state::{HasCorpus, State};

use revm_interpreter::{CallContext, CallScheme, Contract, InstructionResult, Interpreter, Gas};
use revm_primitives::{Bytecode, U256};

use crate::evm::bytecode_analyzer;
use super::replay_host::ReplayFuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::types::{EVMAddress, EVMU256};
// use crate::evm::uniswap::generate_uniswap_router_call;
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM};
use crate::generic_vm::vm_state::VMStateT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasTargetVictimFunction, HasAddressToDapp,};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use crate::cache::{Cache, FileSystemCache};
use super::replay_record::{DappRecordData, CallGraphNode};
use crate::evm::input::EtherscanTransaction;
use crate::invoke_middlewares;


/// A post execution constraint
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Constraint {
    Caller(EVMAddress),
    Contract(EVMAddress),
    NoLiquidation
}

/// Is current EVM execution fast call
pub static mut IS_REPLAY_CALL: bool = false;

/// Is current EVM execution fast call (static)
/// - Fast call is a call that does not change the state of the contract
// pub static mut IS_FAST_CALL_STATIC: bool = false;

/// EVM executor, wrapper of revm
#[derive(Debug, Clone)]
pub struct ReplayEVMExecutor<I, S, VS, CI>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT + Default + 'static,
{
    /// Host providing the blockchain environment (e.g., writing/reading storage), needed by revm
    pub host: ReplayFuzzHost<VS, I, S>,
    pub file_cache: FileSystemCache,
    pub verify_file_cache: FileSystemCache,
    /// [Depreciated] Deployer address
    deployer: EVMAddress,
    /// Known arbitrary (caller,pc)
    pub _known_arbitrary: HashSet<(EVMAddress, usize)>,
    phandom: PhantomData<(I, S, VS, CI)>,
}

/// Execution result that may have control leaked
/// Contains raw information of revm output and execution
#[derive(Clone, Debug)]
pub struct IntermediateExecutionResult {
    /// Output of the execution
    pub output: Bytes,
    /// The new state after execution
    pub new_state: EVMState,
    /// Program counter after execution
    pub pc: usize,
    /// Return value after execution
    pub ret: InstructionResult,
    /// Stack after execution
    pub stack: Vec<EVMU256>,
    /// Memory after execution
    pub memory: Vec<u8>,
}

impl<VS, I, S, CI> ReplayEVMExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasTargetVictimFunction
        + HasAddressToDapp
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: Default + VMStateT + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new EVM executor given a host and deployer address
    pub fn new(fuzz_host: ReplayFuzzHost<VS, I, S>, deployer: EVMAddress) -> Self {
        let path = fuzz_host.fuzzhost.origin;
        let hash = fuzz_host.tx_hash.clone();
        Self {
            host: fuzz_host,
            deployer,
            file_cache: FileSystemCache::new(&format!("record_data/cache/{:?}/tx/{:}", path, hash)),
            verify_file_cache: FileSystemCache::new(&format!("record_data/verify/{:?}", path)),
            _known_arbitrary: Default::default(),
            phandom: PhantomData,
        }
    }

    /// Execute from a specific program counter and context
    ///
    /// `call_ctx` is the context of the call (e.g., caller address, callee address, etc.)
    /// `vm_state` is the VM state to execute on
    /// `data` is the input (function hash + serialized ABI args)
    /// `input` is the additional input information (e.g., access pattern, etc.)
    ///     If post execution context exists, then this is the return buffer of the call that leads
    ///     to control leak. This is like we are fuzzing the subsequent execution wrt the return
    ///     buffer of the control leak call.
    /// `post_exec` is the post execution context to use, if any
    ///     If `post_exec` is `None`, then the execution is from the beginning, otherwise it is from
    ///     the post execution context.
    pub fn execute_from_pc(
        &mut self,
        target_tx: &EtherscanTransaction,
        mut state: &mut S,
        // cleanup: bool
    ) -> IntermediateExecutionResult {
        let target_tx_input = hex::decode(&target_tx.input[2..]).expect("Fail");
        let mut data = Bytes::from(target_tx_input);

        let cleanup = true;

        // let caller = input.get_caller();
        let caller = target_tx.from;
        // let value = input.get_txn_value().unwrap_or(EVMU256::ZERO);
        let value = target_tx.value;
        // let contract_address = input.get_contract();
        let contract_address = target_tx.to;
        println!("Target transaction from: {:?}", caller);
        println!("Target transaction to: {:?}", contract_address);
        println!("Target transaction input: 0x{:}", hex::encode(&data));

        // Initial setups
        if cleanup {
            self.host.fuzzhost.coverage_changed = false;
            self.host.fuzzhost.bug_hit = false;
        }

        self.host.fuzzhost.evmstate = Default::default();
        // initialize host origin
        self.host.set_call_to(target_tx.to);
        // set host env
        self.host.set_env(&target_tx);
        self.host.fuzzhost.call_count = 0;
        self.host.fuzzhost.randomness = vec![0];
        // let mut repeats = 1;

        let call_ctx = &CallContext {
            address: contract_address,
            caller,
            code_address: contract_address,
            apparent_value: value,
            scheme: CallScheme::Call,
        };

        // Get the bytecode
        let mut bytecode = match self
            .host
            .fuzzhost
            .code
            .get(&call_ctx.code_address) {
            Some(i) => i.clone(),
            None => {
                println!("no code @ {:?}, did you forget to deploy?", call_ctx.code_address);
                return IntermediateExecutionResult {
                    output: Bytes::new(),
                    new_state: Default::default(),
                    pc: 0,
                    ret: InstructionResult::Revert,
                    stack: Default::default(),
                    memory: Default::default(),
                };
            }
        };

        // Create the interpreter
        let call = Contract::new_with_context_analyzed(data, bytecode, call_ctx);
        let mut interp = Interpreter::new(call, 1e10 as u64, false);

        let additional_value = value;
        let mut r = if additional_value > U256::ZERO {
            unsafe {
                invoke_middlewares!(&mut self.host.fuzzhost, &mut interp, state, on_get_additional_information);
                match self.host.send_balance(caller, contract_address, value) {
                    false => InstructionResult::OutOfFund,
                    true => InstructionResult::Stop
                }
            }
        } else {
            InstructionResult::Stop
        };
        if r == InstructionResult::Stop {
            r = self.host.run_inspect(&mut interp, state);
        }

        // handle and Build the result
        let mut result = IntermediateExecutionResult {
            output: interp.return_value(),
            new_state: self.host.fuzzhost.evmstate.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };

        // remove all concolic hosts
        self.host
            .fuzzhost
            .middlewares
            .deref()
            .borrow_mut()
            .retain(|k, _| *k != MiddlewareType::Concolic);

        result
    }

    /// Conduct a fast call that does not write to the feedback
    pub fn fast_call(
        &mut self,
        target_tx: EtherscanTransaction,
        mut state: &mut S,
    ) -> IntermediateExecutionResult {
        unsafe {
            IS_REPLAY_CALL = true;
        }
        let res = self.execute_from_pc(&target_tx, state);
        unsafe {
            IS_REPLAY_CALL = false;
        }
        // Save the execute result
        let mut result_cache: HashMap<String, String> = HashMap::new();

        let json = serde_json::to_string(&self.host.execute_dapp_data.contract_to_logic_contract.clone()).expect("Replay Mode: fail to serialize data");
        result_cache.insert("delegatecall_record".to_string(), json.clone());

        let json = serde_json::to_string(&self.host.call_stack_cache.to_nested_dict()).expect("Replay Mode: fail to serialize data");;
        result_cache.insert("call_graph".to_string(), json);
        // println!("{:?}", json);

        let result_cache = serde_json::to_string(&result_cache).expect("Replay Mode: fail to serialize data");
        self.file_cache.save(&format!("replay_record_{:}", target_tx.hash, ), &result_cache).unwrap();

        // Save the execute result
        let save_data = match res.ret {
            InstructionResult::Stop | InstructionResult::Return | InstructionResult::SelfDestruct => {
                format!("{:?},{:?},{:?},{:}\n", 
                    true, true, target_tx.is_success, target_tx.hash,  
                )
            },
            _ => { // execute revert
                if target_tx.is_success { // execute error
                    format!("{:?},{:?},{:?},{:}\n", 
                        false, false, target_tx.is_success, target_tx.hash,  
                    )
                } else {
                    format!("{:?},{:?},{:?},{:}\n", 
                        true, false, target_tx.is_success, target_tx.hash,  
                    )
                }
            }
        };

        self.verify_file_cache.save_without_recreate(&format!("{:?}", target_tx.to, ), &save_data).unwrap();

        res
    }
    pub fn reexecute_with_middleware(
        &mut self,
        input: &I,
        state: &mut S,
        middleware: Rc<RefCell<dyn Middleware<VS, I, S>>>,
    ) {
        self.host.add_middlewares(middleware.clone());
        self.execute(input, state);
        self.host.remove_middlewares(middleware);
    }
}

pub static mut IN_DEPLOY: bool = false;

impl<VS, I, S, CI> GenericVM<VS, Bytecode, Bytes, EVMAddress, EVMAddress, EVMU256, Vec<u8>, I, S, CI>
    for ReplayEVMExecutor<I, S, VS, CI>
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasTargetVictimFunction
        + HasAddressToDapp
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    /// Deploy a contract
    fn deploy(
        &mut self,
        code: Bytecode,
        constructor_args: Option<Bytes>,
        deployed_address: EVMAddress,
        state: &mut S,
    ) -> Option<EVMAddress> {
        let deployer = Contract::new(
            constructor_args.unwrap_or(Bytes::new()),
            code,
            deployed_address,
            deployed_address,
            self.deployer,
            EVMU256::from(0),
        );
        // disable middleware for deployment
        unsafe {
            IN_DEPLOY = true;
        }
        let mut interp = Interpreter::new(deployer, 1e10 as u64, false);
        let mut dummy_state = S::default();
        let r = self.host.run_inspect(&mut interp, &mut dummy_state);
        unsafe {
            IN_DEPLOY = false;
        }
        if r != InstructionResult::Return {
            println!("deploy failed: {:?}", r);
            return None;
        }
        println!(
            "deployer = 0x{} contract = {:?}",
            hex::encode(self.deployer),
            hex::encode(interp.return_value())
        );
        let contract_code = Bytecode::new_raw(interp.return_value());
        bytecode_analyzer::add_analysis_result_to_state(&contract_code, state);
        self.host.set_code(deployed_address, contract_code, state);
        Some(deployed_address)
    }

    /// Execute an input (transaction)
    #[cfg(not(feature = "flashloan_v2"))]
    fn execute(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        ExecutionResult::empty_result()

    }

    /// Execute a static call
    fn fast_static_call(
        &mut self,
        data: &Vec<(EVMAddress, Bytes)>,
        vm_state: &VS,
        state: &mut S,
    ) -> Vec<Vec<u8>> {
        unsafe {
            // IS_FAST_CALL_STATIC = true;
            self.host.fuzzhost.evmstate = vm_state
                .as_any()
                .downcast_ref_unchecked::<EVMState>()
                .clone();
            self.host.fuzzhost.bug_hit = false;
            self.host.fuzzhost.call_count = 0;
            // self.host.fuzzhost.current_typed_bug = vec![];
            self.host.fuzzhost.randomness = vec![9];
        }

        let res = data.iter()
            .map(|(address, by)| {
                let ctx = CallContext {
                    address: *address,
                    caller: Default::default(),
                    code_address: *address,
                    apparent_value: Default::default(),
                    scheme: CallScheme::StaticCall,
                };
                let code = self.host.fuzzhost.code.get(&address).expect("no code").clone();
                let call = Contract::new_with_context_analyzed(by.clone(), code.clone(), &ctx);
                let mut interp = Interpreter::new(call, 1e10 as u64, false);
                let ret = self.host.run_inspect(&mut interp, state);
                if ret == InstructionResult::Revert {
                    vec![]
                } else {
                    interp.return_value().to_vec()
                }
            })
            .collect::<Vec<Vec<u8>>>();

        res
    }

    fn state_changed(&self) -> bool {
        false
    }
}
