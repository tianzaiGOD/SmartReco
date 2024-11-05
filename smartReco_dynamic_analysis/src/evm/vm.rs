use std::collections::{HashMap, HashSet};
use revm_primitives::ruint::Uint;

use std::fmt::{Debug, Formatter};

use std::marker::PhantomData;
use std::ops::Deref;
use crate::input::{ConciseSerde, VMInputT};
use bytes::Bytes;

use libafl::prelude::{HasMetadata, HasRand};
use libafl::state::{HasCorpus, State};

use revm_interpreter::{CallContext, CallScheme, Contract, InstructionResult, Interpreter};
use revm_primitives::{Bytecode, LatestSpec, U256};

use crate::evm::bytecode_analyzer;
use crate::evm::host::{
    FuzzHost, CMP_MAP, COVERAGE_NOT_CHANGED, GLOBAL_CALL_CONTEXT, JMP_MAP, READ_MAP,
    RET_OFFSET, RET_SIZE, STATE_CHANGE, WRITE_MAP,
};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy};

use crate::evm::types::{EVMAddress, EVMU256};

use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;

use crate::state::{HasCaller, HasCurrentInputIdx, HasTargetVictimFunction, HasAddressToDapp,};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

use crate::cache::{Cache, FileSystemCache};

use super::input::EtherscanTransaction;
use crate::invoke_middlewares;

/// A post execution constraint
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Constraint {
    Caller(EVMAddress),
    Contract(EVMAddress),
    NoLiquidation
}

/// A post execution context
/// When control is leaked, we dump the current execution context. This context includes
/// all information needed to continue subsequent execution (e.g., stack, pc, memory, etc.)
/// Post execution context is attached to VM state if control is leaked.
///
/// When EVM input has `step` set to true, then we continue execution from the post
/// execution context available. If `step` is false, then we conduct reentrancy
/// (i.e., don't need to continue execution from the post execution context
/// but we execute the input directly
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostExecutionCtx {
    /// Stack snapshot of VM
    pub stack: Vec<EVMU256>,
    /// Memory snapshot of VM
    pub memory: Vec<u8>,

    /// Program counter
    pub pc: usize,
    /// Current offset of the output buffer
    pub output_offset: usize,
    /// Length of the output buffer
    pub output_len: usize,

    /// Call data of the current call
    pub call_data: Bytes,

    /// Call context of the current call
    pub address: EVMAddress,
    pub caller: EVMAddress,
    pub code_address: EVMAddress,
    pub apparent_value: EVMU256,

    pub must_step: bool,
    pub constraints: Vec<Constraint>,
}

impl PostExecutionCtx {
    /// Convert the post execution context to revm [`CallContext`]
    fn get_call_ctx(&self) -> CallContext {
        CallContext {
            address: self.address,
            caller: self.caller,
            apparent_value: self.apparent_value,
            code_address: self.code_address,
            scheme: CallScheme::Call,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EVMState {
    /// State of the EVM, which is mapping of EVMU256 slot to EVMU256 value for each contract
    pub state: HashMap<EVMAddress, HashMap<EVMU256, EVMU256>>,
    pub bug_hit: bool,
}


pub trait EVMStateT {
    fn get_constraints(&self) -> Vec<Constraint>;
}

impl EVMStateT for EVMState {
    fn get_constraints(&self) -> Vec<Constraint> {
        vec![]
    }
}


impl Default for EVMState {
    /// Default VM state, containing empty state, no post execution context,
    /// and no flashloan usage
    fn default() -> Self {
        Self {
            state: HashMap::new(),
            bug_hit: false,
        }
    }
}

impl VMStateT for EVMState {
    /// Calculate the hash of the VM state
    fn get_hash(&self) -> u64 {
        0
    }

    /// Check whether current state has post execution context
    /// This can also used to check whether a state is intermediate state (i.e., not yet
    /// finished execution)
    fn has_post_execution(&self) -> bool {
        false
    }

    /// Get length needed for return data length of the call that leads to control leak
    fn get_post_execution_needed_len(&self) -> usize {
        0
    }

    /// Get the PC of last post execution context
    fn get_post_execution_pc(&self) -> usize {
        0
    }

    /// Get amount of post execution context
    fn get_post_execution_len(&self) -> usize {
        0
    }

    /// Get flashloan information
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String {
        "".to_string()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Get all storage slots of a specific contract
    fn get(&self, address: EVMAddress, block_number: Uint<256, 4>) -> Option<&HashMap<EVMU256, EVMU256>> {
        self.state.get(&address)
    }

    /// Get all storage slots of a specific contract (mutable)
    fn get_mut(&mut self, address: EVMAddress, block_number: Uint<256, 4>) -> Option<&mut HashMap<EVMU256, EVMU256>> {
        self.state.get_mut(&address)
    }

    /// Insert all storage slots of a specific contract
    fn insert(&mut self, address: EVMAddress, storage: HashMap<EVMU256, EVMU256>, block_number: Uint<256, 4>) {
        self.state.insert(address, storage);
    }

    fn new() -> Self {
        Self {
            state: HashMap::new(),
            bug_hit: false,
        }
    }
    
    fn set_bug_hit_mut(&mut self, result: bool) {
        self.bug_hit = result;
    }
}

/// Is current EVM execution fast call
pub static mut IS_REPLAY_CALL: bool = false;

/// EVM executor, wrapper of revm
#[derive(Debug, Clone)]
pub struct EVMExecutor<I, S, VS, CI>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    /// Host providing the blockchain environment (e.g., writing/reading storage), needed by revm
    pub host: FuzzHost<VS, I, S>,
    pub file_cache: FileSystemCache,
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

impl<VS, I, S, CI> EVMExecutor<I, S, VS, CI>
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
    pub fn new(fuzz_host: FuzzHost<VS, I, S>, deployer: EVMAddress, victim_address: EVMAddress) -> Self {
        Self {
            file_cache: FileSystemCache::new(&format!("./record_data/verify/{:?}", victim_address)),
            host: fuzz_host,
            deployer,
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
        target_tx: EtherscanTransaction,
        mut state: &mut S,
        // cleanup: bool
    ) -> IntermediateExecutionResult {
        let target_tx_input = hex::decode(&target_tx.input[2..]).expect("Fail");
        let mut data = Bytes::from(target_tx_input);

        let cleanup = true;

        let caller = target_tx.from;
        let value = target_tx.value;
        let contract_address = target_tx.to;
        println!("Target transaction from: {:?}", caller);
        println!("Target transaction to: {:?}", contract_address);
        println!("Target transaction input: 0x{:}", hex::encode(&data));

        // Initial setups
        if cleanup {
            self.host.coverage_changed = false;
            self.host.bug_hit = false;
            unsafe {
                STATE_CHANGE = false;
            }
        }
        self.host.evmstate = Default::default();
        if !self.host.is_verified {
            self.host.input_record.push(data.clone());
        }
        // initialize host origin
        self.host.set_call_to(target_tx.to);
        // set host env
        self.host.set_env(&target_tx);
        // self.host.env = input.get_vm_env().clone();
        // self.host.access_pattern = input.get_access_pattern().clone();
        self.host.call_count = 0;
        self.host.randomness = vec![0];
        // let mut repeats = 1;

        let call_ctx = &CallContext {
            address: contract_address,
            caller,
            code_address: contract_address,
            apparent_value: value,
            scheme: CallScheme::Call,
        };

        // Ensure that the call context is correct
        unsafe {
            GLOBAL_CALL_CONTEXT = Some(call_ctx.clone());
        }

        // Get the bytecode
        let mut bytecode = match self
            .host
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
                invoke_middlewares!(&mut self.host, &mut interp, state, on_get_additional_information);
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
            new_state: self.host.evmstate.clone(),
            pc: interp.program_counter(),
            ret: r,
            stack: interp.stack.data().clone(),
            memory: interp.memory.data().clone(),
        };

        result
    }

    /// Execute a transaction, wrapper of [`EVMExecutor::execute_from_pc`]
    pub fn execute_abi(
        &mut self,
        // input: &I,
        target_tx: EtherscanTransaction,
        state: &mut S,
    ) {
        let exec_res = self.execute_from_pc(
            target_tx.clone(),
            state,
        );
        let mut r = exec_res;
        println!("Execution Result: {:?}", r.ret);
        // handle return result
        match r.ret {
            InstructionResult::CrossContractControlLeak => {
                println!("\n\n  Find Cross Contract Control Leak! \n\n");
                let victim_tx = state.get_victim_function_tx();
                let save_data = format!(
                    "target_function:{:},victim_function:{:},related_function_name:{:},entry_function_signature:0x{:},target_contract:{:?},victim_contract:{:?},related_function_signature:0x{:},target_tx_hash:{:},victim_tx_hash:{:}\n", 
                    target_tx.functionName, victim_tx.functionName, self.host.target_dependency_function_name, 
                    hex::encode(self.host.entry_function.clone()),target_tx.to, victim_tx.to, hex::encode(self.host.target_dependency.clone()), 
                    target_tx.hash, victim_tx.hash,   
                );
                self.file_cache.save_without_recreate(&format!("{:?}_result", victim_tx.to), &save_data).unwrap();
            }
            _ => {}
        }
    }
}

pub static mut IN_DEPLOY: bool = false;

impl<VS, I, S, CI> GenericVM<VS, Bytecode, Bytes, EVMAddress, EVMAddress, EVMU256, Vec<u8>, I, S, CI>
    for EVMExecutor<I, S, VS, CI>
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
    fn execute(
        &mut self,
        input: &I,
        state: &mut S,
    ) -> ExecutionResult<EVMAddress, EVMAddress, VS, Vec<u8>, CI> {
        // self.execute_abi(input, state)
        let target_tx = state.get_target_function_tx().clone();
        self.execute_abi(target_tx, state);
        ExecutionResult::empty_result()
    }

    /// Execute a static call
    fn fast_static_call(
        &mut self,
        data: &Vec<(EVMAddress, Bytes)>,
        vm_state: &VS,
        state: &mut S,
    ) -> Vec<Vec<u8>> {
        vec![]
    }

    fn state_changed(&self) -> bool {
        unsafe { STATE_CHANGE }
    }
}
