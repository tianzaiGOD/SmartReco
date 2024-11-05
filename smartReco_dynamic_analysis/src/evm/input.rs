use crate::evm::abi::{AEmpty, AUnknown, BoxedABI};
use crate::mutation_utils::byte_mutator;
// use crate::evm::mutator::AccessPattern;
use crate::evm::types::{EVMAddress, EVMExecutionResult, EVMU256, EVMU512};
use crate::evm::vm::EVMState;
use crate::input::{ConciseSerde, VMInputT};
use crate::state::{HasCaller};

use libafl::bolts::HasLen;
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasBytesVec, HasMaxSize, HasMetadata, HasRand, Rand, State};
use primitive_types::U512;
use revm_primitives::Env;
use revm_primitives::U256;
use serde::{Deserialize, Deserializer, Serialize};

use bytes::Bytes;
use std::cell::RefCell;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use crate::generic_vm::vm_executor::ExecutionResult;
use crate::generic_vm::vm_state::VMStateT;


/// EVM Input Types
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum EVMInputTy {
    /// A normal transaction
    ABI,
    /// A flashloan transaction
    Borrow,
    /// An arbitrary external call with same address tx
    ArbitraryCallBoundedAddr,
    /// [Depreciated] A liquidation transaction
    Liquidate,
}

impl Default for EVMInputTy {
    fn default() -> Self {
        EVMInputTy::ABI
    }
}

/// EVM Input Trait
pub trait EVMInputT {
    /// Set the contract and ABI
    fn set_contract_and_abi(&mut self, contract: EVMAddress, abi: Option<BoxedABI>);

    /// Set the caller
    fn set_caller_evm(&mut self, caller: EVMAddress);

    /// Get the ABI encoded input
    fn to_bytes(&self) -> Vec<u8>;

    /// Get revm environment (block, timestamp, etc.)
    fn get_vm_env(&self) -> &Env;

    /// Get revm environment (block, timestamp, etc.) mutably
    fn get_vm_env_mut(&mut self) -> &mut Env;

    /// Get the access pattern of the input, used by the mutator to determine what to mutate
    // fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>>;

    /// Get the transaction value in wei
    fn get_txn_value(&self) -> Option<EVMU256>;

    /// Set the transaction value in wei
    fn set_txn_value(&mut self, v: EVMU256);

    /// Get input type
    #[cfg(feature = "flashloan_v2")]
    fn get_input_type(&self) -> EVMInputTy;

    /// Get additional random bytes for mutator
    fn get_randomness(&self) -> Vec<u8>;

    /// Set additional random bytes for mutator
    fn set_randomness(&mut self, v: Vec<u8>);

    /// Get the percentage of the token amount in all callers' account to liquidate
    #[cfg(feature = "flashloan_v2")]
    fn get_liquidation_percent(&self) -> u8;

    /// Set the percentage of the token amount in all callers' account to liquidate
    #[cfg(feature = "flashloan_v2")]
    fn set_liquidation_percent(&mut self, v: u8);

    fn get_repeat(&self) -> usize;
}


/// EVM Input
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct EVMInput {
    /// Input type
    #[cfg(feature = "flashloan_v2")]
    pub input_type: EVMInputTy,

    /// Caller address
    pub caller: EVMAddress,

    /// Contract address
    pub contract: EVMAddress,

    /// Input data in ABI format
    pub data: Option<BoxedABI>,

    /// Staged VM state index in the corpus
    #[serde(skip_deserializing)]
    pub sstate_idx: usize,

    /// Transaction value in wei
    pub txn_value: Option<EVMU256>,

    /// Whether to resume execution from the last control leak
    pub step: bool,

    /// Environment (block, timestamp, etc.)
    pub env: Env,

    /// Percentage of the token amount in all callers' account to liquidate
    #[cfg(feature = "flashloan_v2")]
    pub liquidation_percent: u8,

    /// If ABI is empty, use direct data, which is the raw input data
    pub direct_data: Bytes,

    /// Additional random bytes for mutator
    pub randomness: Vec<u8>,

    /// Execute the transaction multiple times
    pub repeat: usize,
}

/// etherscan transaction api return struct
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EtherscanTransaction {
    pub blockNumber: u64,
    pub timeStamp: u64,
    pub hash: String,
    pub blockHash: String,
    pub from: EVMAddress,
    pub to: EVMAddress,
    pub value: U256,
    pub input: String,
    pub functionName: String,
    pub is_success: bool,
}

/// EVM Input Minimum for Deserializing
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConciseEVMInput {
    /// Input type
    #[cfg(feature = "flashloan_v2")]
    pub input_type: EVMInputTy,

    /// Caller address
    pub caller: EVMAddress,

    /// Contract address
    pub contract: EVMAddress,

    /// Input data in ABI format
    pub data: Option<BoxedABI>,

    /// Transaction value in wei
    pub txn_value: Option<EVMU256>,

    /// Whether to resume execution from the last control leak
    pub step: bool,

    /// Environment (block, timestamp, etc.)
    pub env: Env,

    /// When to control leak, after `call_leak` number of calls
    pub call_leak: u32,
}


impl ConciseEVMInput {
    pub fn from_input<I, Out>(input: &I, execution_result: &ExecutionResult<EVMAddress, EVMAddress, EVMState, Out, ConciseEVMInput>) -> Self
    where I: VMInputT<EVMState, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    Out: Default
    {
        Self {
            #[cfg(feature = "flashloan_v2")]
            input_type: input.get_input_type(),
            caller: input.get_caller(),
            contract: input.get_contract(),
            data: input.get_data_abi(),
            txn_value: input.get_txn_value(),
            step: input.is_step(),
            env: input.get_vm_env().clone(),
            #[cfg(feature = "flashloan_v2")]
            liquidation_percent: input.get_liquidation_percent(),
            // randomness: input.get_randomness(),
            // repeat: input.get_repeat(),
            // layer: input.get_state().get_post_execution_len(),
            call_leak: match execution_result.additional_info {
                Some(ref info) => info[0] as u32,
                None => u32::MAX
            }
        }
    }

    #[cfg(not(feature = "flashloan_v2"))]
    fn pretty_txn(&self) -> Option<String> {
        match self.data {
            Some(ref d) => Some(format!(
                "{:?} => {:?} {} with {} ETH ({})",
                self.caller, self.contract,
                d.to_string(),
                self.txn_value.unwrap_or(EVMU256::ZERO),
                hex::encode(d.get_bytes())
            )),
            None => Some(format!("{:?} => {:?} transfer {} ETH",
                                 self.caller, self.contract,
                                 self.txn_value.unwrap_or(EVMU256::ZERO),
            )),
        }
    }
}


impl HasLen for EVMInput {
    /// Get the length of the ABI encoded input
    fn len(&self) -> usize {
        match self.data {
            Some(ref d) => d.get_bytes().len(),
            None => 0,
        }
    }
}

impl std::fmt::Debug for EVMInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMInput")
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            // .field("data", &self.data)
            // .field("state", &self.sstate)
            .field("state_idx", &self.sstate_idx)
            .field("txn_value", &self.txn_value)
            .field("step", &self.step)
            .finish()
    }
}

impl EVMInputT for EVMInput {
    fn set_contract_and_abi(&mut self, contract: EVMAddress, abi: Option<BoxedABI>) {
        self.contract = contract;
        self.data = abi;
    }

    fn set_caller_evm(&mut self, caller: EVMAddress) {
        self.caller = caller;
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self.data {
            Some(ref d) => d.get_bytes(),
            None => vec![],
        }
    }

    fn get_vm_env_mut(&mut self) -> &mut Env {
        &mut self.env
    }

    fn get_vm_env(&self) -> &Env {
        &self.env
    }

    // fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>> {
    //     &self.access_pattern
    // }

    fn get_txn_value(&self) -> Option<EVMU256> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: EVMU256) {
        self.txn_value = Some(v);
    }

    #[cfg(feature = "flashloan_v2")]
    fn get_input_type(&self) -> EVMInputTy {
        self.input_type.clone()
    }

    fn get_randomness(&self) -> Vec<u8> {
        self.randomness.clone()
    }

    fn set_randomness(&mut self, v: Vec<u8>) {
        self.randomness = v;
    }

    #[cfg(feature = "flashloan_v2")]
    fn get_liquidation_percent(&self) -> u8 {
        self.liquidation_percent
    }

    #[cfg(feature = "flashloan_v2")]
    fn set_liquidation_percent(&mut self, v: u8) {
        self.liquidation_percent = v;
    }

    fn get_repeat(&self) -> usize {
        self.repeat
    }
}


///
macro_rules! impl_env_mutator_u256 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
        {
            MutationResult::Skipped
        }
    };
}

macro_rules! impl_env_mutator_h160 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<EVMAddress> + HasRand,
        {
            let addr = state_.get_rand_caller();
            if addr == input.get_caller() {
                return MutationResult::Skipped;
            } else {
                input.get_vm_env_mut().$loc.$item = addr;
                MutationResult::Mutated
            }
        }
    };
}

// Wrapper for EVMU256 so that it represents a mutable Input in LibAFL
#[derive(Serialize)]
struct MutatorInput<'a> {
    #[serde(skip_serializing)]
    pub val_vec: &'a mut Vec<u8>,
}

impl<'a, 'de> Deserialize<'de> for MutatorInput<'a> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unreachable!()
    }
}

impl<'a> Clone for MutatorInput<'a> {
    fn clone(&self) -> Self {
        unreachable!()
    }
}

impl<'a> Debug for MutatorInput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutatorInput")
            .field("val_vec", &self.val_vec)
            .finish()
    }
}

impl<'a> MutatorInput<'a> {
    pub fn new(val_vec: &'a mut Vec<u8>) -> Self {
        MutatorInput { val_vec }
    }
}

impl<'a> Input for MutatorInput<'a> {
    fn generate_name(&self, idx: usize) -> String {
        format!("{}_{:?}", idx, self.val_vec)
    }
}

impl<'a> HasBytesVec for MutatorInput<'a> {
    fn bytes(&self) -> &[u8] {
        self.val_vec
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.val_vec
    }
}

impl EVMInput {
    impl_env_mutator_u256!(basefee, block);
    impl_env_mutator_u256!(timestamp, block);
    impl_env_mutator_h160!(coinbase, block);
    impl_env_mutator_u256!(gas_limit, block);
    impl_env_mutator_u256!(number, block);
    impl_env_mutator_u256!(chain_id, cfg);

    pub fn prevrandao<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn gas_price<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn balance<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn caller<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let caller = state_.get_rand_caller();
        if caller == input.get_caller() {
            return MutationResult::Skipped;
        } else {
            input.set_caller(caller);
            MutationResult::Mutated
        }
    }

    pub fn call_value<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        MutationResult::Skipped
    }

}

impl ConciseSerde for ConciseEVMInput {
    fn serialize_concise(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to deserialize concise input")
    }

    fn deserialize_concise(data: &[u8]) -> Self {
        serde_json::from_slice(data)
            .expect("Failed to deserialize concise input")
    }
}

impl VMInputT<EVMState, EVMAddress, EVMAddress, ConciseEVMInput> for EVMInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasCaller<EVMAddress>
            + HasMetadata,
    {
        MutationResult::Skipped
    }

    fn get_caller_mut(&mut self) -> &mut EVMAddress {
        &mut self.caller
    }

    fn get_caller(&self) -> EVMAddress {
        self.caller.clone()
    }

    fn set_caller(&mut self, caller: EVMAddress) {
        self.caller = caller;
    }

    fn get_contract(&self) -> EVMAddress {
        self.contract.clone()
    }

    fn get_state_idx(&self) -> usize {
        self.sstate_idx
    }

    // fn get_staged_state(&self) -> &StagedVMState {
    //     &self.sstate
    // }

    fn set_as_post_exec(&mut self, out_size: usize) {
        self.data = Some(BoxedABI::new(Box::new(AUnknown {
            concrete: BoxedABI::new(Box::new(AEmpty {})),
            size: out_size,
        })));
    }

    fn is_step(&self) -> bool {
        self.step
    }

    fn set_step(&mut self, gate: bool) {
        self.txn_value = None;
        self.step = gate;
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn fav_factor(&self) -> f64 {
        let mut res = 0.0;
        res
    }

    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI> {
        self.data.clone()
    }

    fn get_direct_data(&self) -> Vec<u8> {
        self.direct_data.to_vec()
    }

    #[cfg(feature = "evm")]
    fn get_data_abi_mut(&mut self) -> &mut Option<BoxedABI> {
        &mut self.data
    }

    #[cfg(feature = "evm")]
    fn get_txn_value_temp(&self) -> Option<EVMU256> {
        self.txn_value
    }

    fn get_concise<Out: Default>(&self, exec_res: &ExecutionResult<EVMAddress, EVMAddress, EVMState, Out, ConciseEVMInput>) -> ConciseEVMInput {
        ConciseEVMInput::from_input(self, exec_res)
    }
}

impl Input for EVMInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }

    fn wrapped_as_testcase(&mut self) {
        // todo!()
    }
}
