use crate::evm::input::{ConciseEVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{CallMiddlewareReturn, Middleware, MiddlewareType};
use crate::r#const::ZERO_ADDRESS;

use bytes::Bytes;
// use itertools::Itertools;
use libafl::prelude::{HasCorpus, HasRand, HasMetadata};
use libafl::state::State;
use revm_interpreter::InstructionResult::{Continue, CrossContractControlLeak};
use revm_primitives::ruint::Uint;


use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
// use std::fs::OpenOptions;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Write;
use std::ops::Deref;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
// use hex::FromHex;
use revm::precompile::{Precompile, Precompiles};
use revm_interpreter::{BytecodeLocked, CallContext, CallInputs, CallScheme, Contract, CreateInputs, Gas, Host, InstructionResult, Interpreter, SelfDestructResult};
use revm_interpreter::analysis::to_analysed;
use revm_primitives::{bytecode, AnalysisKind, BlockEnv, Bytecode, CfgEnv, Env, LatestSpec, Spec, TransactTo, TxEnv, B256, U256};
use crate::evm::types::{convert_u256_to_h160, generate_random_address, EVMAddress, EVMU256};

use crate::evm::vm::{EVMState, IN_DEPLOY};
use crate::generic_vm::vm_executor::{ExecutionResult, GenericVM, MAP_SIZE};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;

use crate::state::{HasCaller, HasCurrentInputIdx, HasHashToAddress, HasTargetVictimFunction, HasAddressToDapp};
use revm_primitives::{SpecId, FrontierSpec, HomesteadSpec, TangerineSpec, SpuriousDragonSpec, ByzantiumSpec,
                      PetersburgSpec, IstanbulSpec, BerlinSpec, LondonSpec, MergeSpec, ShanghaiSpec};
use crate::dapp_utils::CreatorDapp;

use super::input::EtherscanTransaction;
use super::super::cache::{Cache, FileSystemCache};

pub static mut JMP_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// dataflow
pub static mut READ_MAP: [bool; MAP_SIZE] = [false; MAP_SIZE];
pub static mut WRITE_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// cmp
pub static mut CMP_MAP: [EVMU256; MAP_SIZE] = [EVMU256::MAX; MAP_SIZE];

pub static mut ABI_MAX_SIZE: [usize; MAP_SIZE] = [0; MAP_SIZE];
pub static mut STATE_CHANGE: bool = false;

pub const RW_SKIPPER_PERCT_IDX: usize = 100;
pub const RW_SKIPPER_AMT: usize = MAP_SIZE - RW_SKIPPER_PERCT_IDX;

// How mant iterations the coverage is the same
pub static mut COVERAGE_NOT_CHANGED: u32 = 0;
pub static mut RET_SIZE: usize = 0;
pub static mut RET_OFFSET: usize = 0;
pub static mut GLOBAL_CALL_CONTEXT: Option<CallContext> = None;
pub static mut GLOBAL_CALL_DATA: Option<CallContext> = None;

pub static mut PANIC_ON_BUG: bool = false;
// for debugging purpose, return ControlLeak when the calls amount exceeds this value
pub static mut CALL_UNTIL: u32 = u32::MAX;

/// Shall we dump the contract calls
pub static mut WRITE_RELATIONSHIPS: bool = false;

const SCRIBBLE_EVENT_HEX: [u8; 32] = [0xb4,0x26,0x04,0xcb,0x10,0x5a,0x16,0xc8,0xf6,0xdb,0x8a,0x41,0xe6,0xb0,0x0c,0x0c,0x1b,0x48,0x26,0x46,0x5e,0x8b,0xc5,0x04,0xb3,0xeb,0x3e,0x88,0xb3,0xe6,0xa4,0xa0];
pub static mut CONCRETE_CREATE: bool = true;

/// Check if address is precompile by having assumption
/// that precompiles are in range of 1 to N.
#[inline(always)]
pub fn is_precompile(address: EVMAddress, num_of_precompiles: usize) -> bool {
    if !address[..18].iter().all(|i| *i == 0) {
        return false;
    }
    let num = u16::from_be_bytes([address[18], address[19]]);
    num.wrapping_sub(1) < num_of_precompiles as u16
}

/// if dapp1 -> dapp2 -> dapp3, dapp1 to dapp2 is delegatecall
pub fn is_from_same_dapp(dapp1: &CreatorDapp, dapp2: &CreatorDapp, dapp3: &CreatorDapp, call_code: CallScheme) -> bool {
    if call_code == CallScheme::DelegateCall {
        if dapp2.dapp.contains("unknown") || dapp3.dapp.contains("unknown") {
            if dapp2.creator == dapp3.creator {
                return true
            }
            return false
            // return true
        }
        if dapp2.dapp == dapp3.dapp {
            return true
        }
    } else {
        if dapp1.dapp.contains("unknown") || dapp2.dapp.contains("unknown") {
            if dapp1.creator == dapp2.creator {
                return true
            }
            return false
            // return true
        }
        if dapp1.dapp == dapp2.dapp {
            return true
        }
    }
    return false
}

#[macro_export]
macro_rules! invoke_middlewares {
    ($host: expr, $interp: expr, $state: expr, $invoke: ident) => {
        if $host.middlewares_enabled {
            if $host.setcode_data.len() > 0 {
                $host.clear_codedata();
            }
            for (_, middleware) in &mut $host.middlewares.clone().deref().borrow_mut().iter_mut()
            {
                middleware
                    .deref()
                    .deref()
                    .borrow_mut()
                    .$invoke($interp, $host, $state);
            }


            if $host.setcode_data.len() > 0 {
                for (address, code) in &$host.setcode_data.clone() {
                    $host.set_code(address.clone(), code.clone(), $state);
                }
            }
        }
    };
}

pub struct FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    pub evmstate: EVMState,
    // these are internal to the host
    pub env: Env,
    pub code: HashMap<EVMAddress, Arc<BytecodeLocked>>,
    pub address_to_hash: HashMap<EVMAddress, Vec<[u8; 4]>>,
    /// it is determined by the local contract execution state. However, 
    /// it is used to verify control flow leak in a global env, quite not rigorous enough
    pub _pc: usize,
    pub pc_to_addresses: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,

    /// information about contract address to (creator, Dapp)
    pub address_to_dapp: HashMap<EVMAddress, Option<CreatorDapp>>,
    /// is interp call to the different dapp
    pub is_diff_dapp: bool,
    /// is interp execute the victim function
    pub is_execute_victim_function: bool,
    /// use for debug
    pub call_depth: usize,

    pub pc_to_call_hash: HashMap<(EVMAddress, usize), HashSet<Vec<u8>>>,
    pub middlewares_enabled: bool,
    pub middlewares: Rc<RefCell<HashMap<MiddlewareType, Rc<RefCell<dyn Middleware<VS, I, S>>>>>>,

    pub coverage_changed: bool,
    pub middlewares_latent_call_actions: Vec<CallMiddlewareReturn>,

    pub origin: EVMAddress,
    pub target_dependency: Vec<u8>,
    pub target_dependency_function_name: String,
    /// store address the call opcode will call to
    pub call_to: EVMAddress,
    pub address_to_balance: HashMap<EVMAddress, U256>,
    pub compare_record: HashSet<EVMAddress>,
    pub sload_record: HashSet<EVMAddress>,
    pub input_record: Vec<Bytes>,
    // controlled by onchain module, if sload cant find the slot, use this value
    pub next_slot: EVMU256,

    pub bug_hit: bool,
    pub call_count: u32,
    pub current_block_hash: B256,
    #[cfg(not (feature = "print_logs"))]
    pub logs: HashSet<u64>,
    pub setcode_data: HashMap<EVMAddress, Bytecode>,
    pub randomness: Vec<u8>,
    pub spec_id: SpecId,
    pub precompiles: Precompiles,
    pub entry_function: Vec<u8>,
    pub no_need_for_test: bool,
    pub unknown_dapp_cache: FileSystemCache,
    pub from_args: bool,
    pub is_verified: bool,
}

impl<VS, I, S> Debug for FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzHost")
            .field("data", &self.evmstate)
            .field("env", &self.env)
            // .field("hash_to_address", &self.hash_to_address)
            .field("address_to_hash", &self.address_to_hash)
            .field("_pc", &self._pc)
            .field("pc_to_addresses", &self.pc_to_addresses)
            .field("pc_to_call_hash", &self.pc_to_call_hash)
            // .field("concolic_enabled", &self.concolic_enabled)
            .field("middlewares_enabled", &self.middlewares_enabled)
            .field("middlewares", &self.middlewares)
            .field(
                "middlewares_latent_call_actions",
                &self.middlewares_latent_call_actions,
            )
            .field("origin", &self.origin)
            .finish()
    }
}

// all clones would not include middlewares and states
impl<VS, I, S> Clone for FuzzHost<VS, I, S>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    fn clone(&self) -> Self {
        Self {
            evmstate: self.evmstate.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            address_to_hash: self.address_to_hash.clone(),
            _pc: self._pc,
            pc_to_addresses: self.pc_to_addresses.clone(),
            pc_to_call_hash: self.pc_to_call_hash.clone(),
            address_to_dapp: self.address_to_dapp.clone(),
            compare_record: self.compare_record.clone(),
            sload_record: self.sload_record.clone(),
            input_record: self.input_record.clone(),
            is_diff_dapp: self.is_diff_dapp,
            is_execute_victim_function: self.is_execute_victim_function,
            call_to: self.call_to.clone(),
            call_depth: self.call_depth.clone(),
            address_to_balance: self.address_to_balance.clone(),
            middlewares_enabled: false,
            middlewares: Rc::new(RefCell::new(HashMap::new())),
            coverage_changed: false,
            middlewares_latent_call_actions: vec![],
            origin: self.origin.clone(),
            target_dependency: self.target_dependency.clone(),
            target_dependency_function_name: self.target_dependency_function_name.clone(),
            next_slot: Default::default(),
            bug_hit: false,
            call_count: 0,
            #[cfg(not (feature = "print_logs"))]
            logs: Default::default(),
            setcode_data:self.setcode_data.clone(),
            randomness: vec![],
            spec_id: self.spec_id.clone(),
            current_block_hash: self.current_block_hash.clone(),
            precompiles: Precompiles::default(),
            entry_function: vec![],
            no_need_for_test: false,
            unknown_dapp_cache: self.unknown_dapp_cache.clone(),
            from_args: self.from_args,
            is_verified: self.is_verified
        }
    }
}

pub static mut ACTIVE_MATCH_EXT_CALL: bool = false;


impl<VS, I, S> FuzzHost<VS, I, S>
where
    S: State + HasRand + HasCaller<EVMAddress> + Debug + Clone + HasCorpus<I> + HasTargetVictimFunction + HasAddressToDapp + HasMetadata + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
{
    pub fn new(workdir: String) -> Self {
        let mut ret = Self {
            evmstate: Default::default(),
            env: Env::default(),
            code: HashMap::new(),
            address_to_hash: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            address_to_dapp: HashMap::new(),
            is_diff_dapp: false,
            is_execute_victim_function: false,
            call_to: Default::default(),
            call_depth: 0,
            address_to_balance: HashMap::new(),
            compare_record: HashSet::new(),
            sload_record: HashSet::new(),
            input_record: vec![],
            middlewares_enabled: false,
            middlewares: Rc::new(RefCell::new(HashMap::new())),
            coverage_changed: false,
            middlewares_latent_call_actions: vec![],
            origin: Default::default(),
            target_dependency: Default::default(),
            target_dependency_function_name: Default::default(),
            next_slot: Default::default(),
            current_block_hash: B256::zero(),
            bug_hit: false,
            call_count: 0,
            #[cfg(not (feature = "print_logs"))]
            logs: Default::default(),
            setcode_data:HashMap::new(),
            randomness: vec![],
            spec_id: SpecId::LATEST,
            precompiles: Default::default(),
            entry_function: vec![],
            no_need_for_test: true,
            unknown_dapp_cache: FileSystemCache::new(&workdir),
            from_args: false,
            is_verified: false,
        };
        ret
    }

    pub fn set_block_timestamp(&mut self, block_number: String, timestamp: String) {
        let b_number: Uint<256, 4> = Uint::from_str(&block_number).unwrap();
        let t_number: Uint<256, 4> = Uint::from_str(&timestamp).unwrap();

        self.env.block.number = b_number;
        self.env.block.timestamp = t_number;
        // self.env.block.timestamp = EVMU256::MAX;
    }

    pub fn set_env(&mut self, tx: &EtherscanTransaction) {
        self.env.block = BlockEnv {
            number: self.env.block.number,
            timestamp: self.env.block.timestamp,
            coinbase: EVMAddress::zero(),
            difficulty: U256::ZERO,
            prevrandao: None,
            basefee: U256::ZERO,
            gas_limit: U256::MAX,
        };
        self.env.tx = TxEnv {
            caller: tx.from,
            gas_limit: u64::MAX,
            gas_price: U256::ZERO,
            gas_priority_fee: None,
            transact_to: TransactTo::Call(tx.to),
            value: tx.value,
            data: Bytes::from(hex::decode(&tx.input[2..]).expect("Fail")),
            chain_id: None,
            nonce: Some(111),
            access_list: Vec::new(),
        };
        self.env.cfg = CfgEnv {
            chain_id: U256::from_str("1").unwrap(),
            spec_id: self.spec_id,
            perf_analyse_created_bytecodes: AnalysisKind::Analyse,
            limit_contract_code_size: Some(usize::MAX)
        };
    }

    pub fn change_env(&mut self, from: Option<EVMAddress>, to: EVMAddress, value: U256, data: &Bytes, block_number: Option<&str>, time_stamp: Option<&str>) {
        self.env.tx.caller = match from {
            Some(address) => address,
            None => self.env.tx.caller
        };
        self.env.tx.transact_to = TransactTo::Call(to);
        self.env.tx.value = value;
        self.env.tx.data = data.clone();
        self.env.block.number = match block_number {
            Some(number) => {
                let b_number: Uint<256, 4> = Uint::from_str(number).unwrap();
                b_number
            },
            None => self.env.block.number
        };
        self.env.block.timestamp = match time_stamp {
            Some(number) => {
                let b_number: Uint<256, 4> = Uint::from_str(number).unwrap();
                b_number
            },
            None => self.env.block.timestamp
        };
    }

    pub fn set_spec_id(&mut self, spec_id: String) {
        self.spec_id = SpecId::from(spec_id.as_str());
    }

    /// custom spec id run_inspect
    pub fn run_inspect(
        &mut self,
        mut interp: &mut Interpreter,
        mut state:  &mut S,
    ) -> InstructionResult {
        match self.spec_id {
            SpecId::LATEST => interp.run_inspect::<S, FuzzHost<VS, I, S>, LatestSpec>(self, state),
            SpecId::FRONTIER => interp.run_inspect::<S, FuzzHost<VS, I, S>, FrontierSpec>(self, state),
            SpecId::HOMESTEAD => interp.run_inspect::<S, FuzzHost<VS, I, S>, HomesteadSpec>(self, state),
            SpecId::TANGERINE => interp.run_inspect::<S, FuzzHost<VS, I, S>, TangerineSpec>(self, state),
            SpecId::SPURIOUS_DRAGON => interp.run_inspect::<S, FuzzHost<VS, I, S>, SpuriousDragonSpec>(self, state),
            SpecId::BYZANTIUM => interp.run_inspect::<S, FuzzHost<VS, I, S>, ByzantiumSpec>( self, state),
            SpecId::CONSTANTINOPLE | SpecId::PETERSBURG => interp.run_inspect::<S, FuzzHost<VS, I, S>, PetersburgSpec>(self, state),
            SpecId::ISTANBUL => interp.run_inspect::<S, FuzzHost<VS, I, S>, IstanbulSpec>(self, state),
            SpecId::MUIR_GLACIER | SpecId::BERLIN => interp.run_inspect::<S, FuzzHost<VS, I, S>, BerlinSpec>(self, state),
            SpecId::LONDON => interp.run_inspect::<S, FuzzHost<VS, I, S>, LondonSpec>(self, state),
            SpecId::MERGE => interp.run_inspect::<S, FuzzHost<VS, I, S>, MergeSpec>(self, state),
            SpecId::SHANGHAI => interp.run_inspect::<S, FuzzHost<VS, I, S>, ShanghaiSpec>(self, state),
            _=> interp.run_inspect::<S, FuzzHost<VS, I, S>, LatestSpec>(self, state),
        }
    }

    pub fn remove_all_middlewares(&mut self) {
        self.middlewares_enabled = false;
        self.middlewares.deref().borrow_mut().clear();
    }

    pub fn add_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<VS, I, S>>>) {
        self.middlewares_enabled = true;
        let ty = middlewares.deref().borrow().get_type();
        self.middlewares
            .deref()
            .borrow_mut()
            .insert(ty, middlewares);
    }

    pub fn remove_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<VS, I, S>>>) {
        let ty = middlewares.deref().borrow().get_type();
        self.middlewares
            .deref()
            .borrow_mut()
            .remove(&ty);
    }

    pub fn remove_middlewares_by_ty(&mut self, ty: &MiddlewareType) {
        self.middlewares
            .deref()
            .borrow_mut()
            .remove(ty);
    }


    pub fn initialize(&mut self, state: &S)
    where
        S: HasHashToAddress,
    {

    }

    pub fn get_contract_dapp_info(&mut self, address: EVMAddress, state: &mut S) -> Option<CreatorDapp> {
        match self.address_to_dapp.get(&address) {
            Some(info) => {
                let dapp_info = info.clone().unwrap();
                if dapp_info.dapp == "unknown"{
                    if dapp_info.creator == EVMAddress::zero() {
                        self.unknown_dapp_cache.save_without_recreate(&state.get_victim_function_tx().hash, &format!("{:?},unknown\n", address)).unwrap();
                    }
                    self.unknown_dapp_cache.save_without_recreate(&state.get_victim_function_tx().hash, &format!("{:?}\n", address)).unwrap();
                }
                info.clone()
            },
            _ =>{ 
                self.unknown_dapp_cache.save_without_recreate(&state.get_victim_function_tx().hash, &format!("{:?},unknown\n", address)).unwrap();
                Some(CreatorDapp::new(address, EVMAddress::zero(), "unknown".to_string()))
            }
        }
    }

    pub fn set_contract_dapp_info(&mut self, address: EVMAddress, dapp: CreatorDapp) {
        match self.address_to_dapp.get(&address) {
            Some(_) => (),
            None => {
                self.address_to_dapp.insert(address, Some(dapp));
            }
        };
    }

    pub fn add_call_depth(&mut self) {
        self.call_depth += 1;
    }

    pub fn sub_call_depth(&mut self) {
        self.call_depth -= 1;
    }

    pub fn set_call_to(&mut self, address: EVMAddress) {
        self.call_to = address;
    }

    pub fn get_call_to(&mut self) -> EVMAddress {
        self.call_to
    }

    pub fn is_input_contain_address(&mut self, current_input: &Bytes, address: EVMAddress, code_address: EVMAddress) -> bool {
        let to = address.as_bytes();
        // if address is from input and has not been verified, we think it is unsafe
        if current_input.windows(to.len()).any(|window| window == to) {
            // check whether address is encoded in bytecode
            if let Some(bytecode) = self.code.get(&code_address) {
                // let bytecode = Bytes::from(bytecode.deref().bytecode().to_vec());
                let bytecode = bytecode.deref().bytecode();
                if bytecode.windows(to.len()).any(|window| window == to) {
                    return false
                }
            };
            for input in &self.input_record.clone() {
                if input.windows(to.len()).any(|window| window == to) {
                    if self.compare_record.contains(&address) || self.sload_record.contains(&address){
                        continue;
                    } else {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn send_balance(&mut self, from_address: EVMAddress, to_address: EVMAddress, transfer_value: U256) -> bool {
        let block_number = self.env.block.number;
        let from_balance = self.address_to_balance.get(&from_address).unwrap();
        let to_balance = self.address_to_balance.get(&to_address).unwrap().clone();
        
        if from_balance - transfer_value < U256::ZERO {
            false
        } else {
            self.address_to_balance.insert(from_address, from_balance - transfer_value);
            self.address_to_balance.insert(to_address, transfer_value + to_balance);
            true
        }
    }

    pub fn set_codedata(&mut self, address: EVMAddress, mut code: Bytecode) {
        self.setcode_data.insert(address, code);
    }

    pub fn clear_codedata(&mut self) {
        self.setcode_data.clear();
    }

    pub fn set_code(&mut self, address: EVMAddress, mut code: Bytecode, state: &mut S) {
        unsafe {
            if self.middlewares_enabled {
                for (_, middleware) in &mut self.middlewares.clone().deref().borrow_mut().iter_mut()
                {
                    middleware
                        .deref()
                        .deref()
                        .borrow_mut()
                        .on_insert(&mut code, address, self, state);
                }
            }
        }
        assert!(self
            .code
            .insert(
                address,
                Arc::new(BytecodeLocked::try_from(to_analysed(code)).unwrap())
            )
            .is_none());
    }

    pub fn find_static_call_read_slot(
        &self,
        address: EVMAddress,
        data: Bytes,
        state: &mut S,
    ) -> Vec<EVMU256> {
        return vec![];
    }

    /// divide logic by whether from and to are same dapp
    fn divide_call_by_is_same_dapp(&mut self, input: &mut CallInputs, state: &mut S) -> (InstructionResult, Gas, Bytes){
        self.call_count += 1;

        let from = input.context.caller;
        let to = input.context.address;
        // handle delegatecall
        let code_address = input.context.code_address;
 
        let from_info = self.get_contract_dapp_info(from, state).unwrap();
        let to_info = self.get_contract_dapp_info(to, state).unwrap();
        let code_address_info = self.get_contract_dapp_info(code_address, state).unwrap();
        if !self.is_execute_victim_function {
            println!("From host.rs fun divide_call_by_is_same_dapp call depth: {:?}", self.call_depth);
            println!("From host.rs fun divide_call_by_is_same_dapp call code: {:?}", input.context.scheme);
            println!("From host.rs fun divide_call_by_is_same_dapp from: {:?}", from);
            println!("From host.rs fun divide_call_by_is_same_dapp to: {:?}", to);
            println!("From host.rs fun divide_call_by_is_same_dapp input: 0x{:}", input.input.iter().map(|byte| format!("{:02x}", byte)).collect::<String>());
        } else {
            println!("Victim contract execution call depth: {:?}", self.call_depth);
            println!("Victim contract execution call code: {:?}", input.context.scheme);
            println!("Victim contract execution from: {:?}", from);
            println!("Victim contract execution to: {:?}", to);
            println!("Victim contract execution input: {:}", input.input.iter().map(|byte| format!("{:02x}", byte)).collect::<String>());
        }
        let mut old_call_context = None;
        let old_env;
        let old_compare_record;
        let old_sload_record;
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
            old_env = self.env.clone();
            old_sload_record = self.sload_record.clone();
            old_compare_record = self.compare_record.clone();
            GLOBAL_CALL_CONTEXT = Some(input.context.clone());
            self.change_env(None, to, input.context.apparent_value, &input.input, None, None);
            self.compare_record = HashSet::new();
            self.sload_record = HashSet::new();
            // if there is code, then call the code
            interp = if let Some(code) = self.code.get(&input.context.code_address) {
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
                invoke_middlewares!(self, &mut interp, state, on_get_additional_information);
                match self.send_balance(from, to, input.transfer.value) {
                    false => return (InstructionResult::OutOfFund, Gas::new(0), Bytes::new()),
                    true => ()
                };
            };
        }
        let is_same = is_from_same_dapp(&from_info, &to_info, &code_address_info, input.context.scheme);
        // if context is in diff dapp mode or is execute same dapp or has already meet implicit bug, no need for diff app mode
        let res = if self.is_diff_dapp || is_same || self.bug_hit {
            // from and to belong to same dapp, dont execute target function, just execute and analysis
            self.call_forbid_control_leak(input, state, &mut interp)
        } else {
            // from and to belong to different dapp, execute target function in to
            if self.from_args {
                // verify whether to execute victim transaction,
                self.no_need_for_test = false;
            }
            let res = self.call_forbid_control_leak_in_diff_dapp(input, state, &mut interp);
            self.is_diff_dapp = false;
            res
        };
        ret_back_ctx!();
        self.env = old_env;
        self.compare_record = old_compare_record;
        self.sload_record = old_sload_record;
        res
    }

    fn call_forbid_control_leak(&mut self, input: &mut CallInputs, state: &mut S, interp: &mut Interpreter) -> (InstructionResult, Gas, Bytes) {
        if let Some(_code) = self.code.get(&input.context.code_address) {
            let ret: InstructionResult = self.run_inspect(interp, state);
            return (ret, Gas::new(0), interp.return_value());
        } else { // transfer txn and fallback provided
            let input = input.input.to_vec();
            return (Continue, Gas::new(0), Bytes::from(input));
        }
    }

    fn call_forbid_control_leak_in_diff_dapp(&mut self, input: &mut CallInputs, state: &mut S, interp: &mut Interpreter) -> (InstructionResult, Gas, Bytes) {
        self.is_diff_dapp = true;
        self.entry_function = self.extract_function_signature_from_input(&interp.contract.input);
        
        let origin_ret = self.run_inspect(interp, state); 
        // execute not success, not cross dapp call or use transfer, no need for verification
        if (origin_ret != InstructionResult::Stop && origin_ret != InstructionResult::Return && origin_ret != InstructionResult::SelfDestruct) || self.no_need_for_test || input.gas_limit == 2300 {
            self.no_need_for_test = true;
            return (origin_ret, Gas::new(0), interp.return_value());
        }
        // execute victim function
        let tx = state.get_victim_function_tx().clone();
        let tx_input = hex::decode(&tx.input[2..]).expect("Fail");

        self.is_execute_victim_function = true;
        let call_context = CallContext {
            address: tx.to,
            caller: tx.from,
            code_address: tx.to,
            apparent_value: tx.value,
            scheme: CallScheme::Call,
        };
        let mut victim_interp = if let Some(code) = self.code.get(&tx.to) {
            Interpreter::new(
                Contract::new_with_context_analyzed(
                    Bytes::from(tx_input.clone()),
                    code.clone(),
                    &call_context
                ),
                1e10 as u64,
                false
            )
        } else {
            Interpreter::new(
                Contract::new_with_context_analyzed(
                    Bytes::from(tx_input.clone()),
                    Default::default(),
                    &call_context
                ),
                1e10 as u64,
                false
            )
        };
        unsafe {
            let additional_value = tx.value;
            if additional_value > U256::ZERO {
                invoke_middlewares!(self, &mut victim_interp, state, on_get_additional_information);
                match self.send_balance(tx.from, tx.to, tx.value) {
                    false => return (InstructionResult::OutOfFund, Gas::new(0), Bytes::new()),
                    true => ()
                };
            };
        }
        println!("Start victim contract execution call code: {:?}", input.context.scheme);
        println!("Start victim contract execution from: {:?}", tx.from);
        println!("Start victim contract execution to: {:?}", tx.to);
        println!("Start victim contract execution input: {:}", tx.input);
        let mut old_call_context;
        let old_env;
        let old_compare_record;
        let old_sload_record;
        let old_address_balance;
        let old_evmstate;
        macro_rules! ret_back_ctx {
            () => {
                unsafe {
                    GLOBAL_CALL_CONTEXT = old_call_context;
                }
            };
        }
        unsafe {
            old_call_context = GLOBAL_CALL_CONTEXT.clone();
            old_env = self.env.clone();
            old_sload_record = self.sload_record.clone();
            old_compare_record = self.compare_record.clone();
            old_address_balance = self.address_to_balance.clone();
            old_evmstate = self.evmstate.clone();
            GLOBAL_CALL_CONTEXT = Some(input.context.clone());
            self.compare_record = HashSet::new();
            self.sload_record = HashSet::new();
            self.address_to_balance = Default::default();
            self.evmstate = Default::default();
        }
        let old_call_depth = self.call_depth;
        self.call_depth = 0;
        self.change_env(Some(tx.from), tx.to, tx.value, &Bytes::from(tx.input.clone()), Some(&format!("0x{:x}", tx.blockNumber)), Some(&format!("0x{:x}", tx.timeStamp)));
        
        let res = if tx_input.len() != 0 {
            let mut ret = self.run_inspect(&mut victim_interp, state);
            if ret != InstructionResult::CrossContractControlLeak {
                ret = origin_ret;
            }
            (ret, Gas::new(0), interp.return_value())
        } else { // transfer txn and fallback provided
            (Continue, Gas::new(0), Bytes::from(tx.input.clone()))
        };
        // recover context
        self.env = old_env;
        self.compare_record = old_compare_record;
        self.sload_record = old_sload_record;
        self.address_to_balance = old_address_balance;
        self.evmstate = old_evmstate;
        self.call_depth = old_call_depth;
        ret_back_ctx!();
        self.is_execute_victim_function = false;
        self.no_need_for_test = true;
        self.from_args = false;
        res
    }    

    pub fn call_precompile(&mut self, input: &mut CallInputs, state: &mut S) -> (InstructionResult, Gas, Bytes) {
        let precompile = self
            .precompiles
            .get(&input.contract)
            .expect("Check for precompile should be already done");
        let out = match precompile {
            Precompile::Standard(fun) => fun(&input.input.to_vec().as_slice(), u64::MAX),
            Precompile::Custom(fun) => fun(&input.input.to_vec().as_slice(), u64::MAX),
        };
        match out {
            Ok((_, data)) => {
                (InstructionResult::Return, Gas::new(0), Bytes::from(data))
            }
            Err(e) => {
                (InstructionResult::PrecompileError, Gas::new(0), Bytes::new())
            }
        }
    }

    pub fn extract_function_signature_from_input(&mut self, input: &Bytes) -> Vec<u8> {
        if input.len() < 4 {
            [0;4].to_vec()
        } else {
            // format!("0x{}", input_data[0..8].to_string())
            input[0..4].to_vec()
        }
    }
}

impl<VS, I, S> Host<S> for FuzzHost<VS, I, S>
where
    S: State +HasRand + HasCaller<EVMAddress> + Debug + Clone + HasCorpus<I> + HasMetadata + HasTargetVictimFunction + HasAddressToDapp + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
{
    // invoke middleware and record important information
    fn step(&mut self, interp: &mut Interpreter, state: &mut S) -> InstructionResult {
        let opcode = unsafe {
            *interp.instruction_pointer
        };
        unsafe {
            invoke_middlewares!(self, interp, state, on_step);

            macro_rules! fast_peek {
                ($idx:expr) => {
                    interp.stack.data()[interp.stack.len() - 1 - $idx]
                };
            }
            match opcode {
                0x55 => {
                    // SSTORE
                    if self.bug_hit && !self.is_diff_dapp {
                        println!("Cross contract reenter hit!");
                        interp.instruction_result = CrossContractControlLeak;
                    }
                }
                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                }
                0x10 | 0x11 | 0x12 | 0x13 | 0x14 => {
                    // record compared value
                    let v1 = fast_peek!(0);
                    let v2 = fast_peek!(1);
                    self.compare_record.insert(convert_u256_to_h160(v1));
                    self.compare_record.insert(convert_u256_to_h160(v2));
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
        return &mut self.env;
    }

    fn load_account(&mut self, _address: EVMAddress) -> Option<(bool, bool)> {
        Some((
            true,
            true, // self.data.contains_key(&address) || self.code.contains_key(&address),
        ))
    }

    fn block_hash(&mut self, _number: EVMU256) -> Option<B256> {
        // not tested, may panic
        if _number > self.env.block.number {
            return Some(
                B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
            )
        }
        Some(self.current_block_hash)
    }

    fn balance(&mut self, _address: EVMAddress) -> Option<(EVMU256, bool)> {
        // println!("balance");
        match self.address_to_balance.get(&_address) {
            Some(balance) => Some((*balance, true)),
            _ => Some((EVMU256::MAX, true))
        }
    }

    fn code(&mut self, address: EVMAddress) -> Option<(Arc<BytecodeLocked>, bool)> {
        // println!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Arc::new(
                BytecodeLocked::default()
            ), true)),
        }
    }

    fn code_hash(&mut self, _address: EVMAddress) -> Option<(B256, bool)> {
        let hash = self.code.get(&_address).unwrap().deref().hash();
        Some((hash, true))
    }

    fn sload(&mut self, address: EVMAddress, index: EVMU256) -> Option<(EVMU256, bool)> {
        let block_number = self.env.block.number;
        if let Some(account) = self.evmstate.get(address, block_number) {            
            if let Some(slot) = account.get(&index) {
                self.sload_record.insert(convert_u256_to_h160(slot.clone()));
                return Some((slot.clone(), true));
            }
        }
        self.sload_record.insert(convert_u256_to_h160(self.next_slot.clone()));
        Some((self.next_slot, true))
    }

    fn sstore(
        &mut self,
        address: EVMAddress,
        index: EVMU256,
        value: EVMU256,
    ) -> Option<(EVMU256, EVMU256, EVMU256, bool)> {
        // println!("0x{:x} sstore for slot {:x} storage: {:}", address, index, value);
        let block_number = self.env.block.number;
        match self.evmstate.get_mut(address, block_number) {
            Some(account) => {
                account.insert(index, value);
            }
            None => {
                let mut account = HashMap::new();
                account.insert(index, value);
                self.evmstate.insert(address, account, block_number);
            }
        };

        Some((EVMU256::from(0), EVMU256::from(0), EVMU256::from(0), true))
    }

    fn log(&mut self, _address: EVMAddress, _topics: Vec<B256>, _data: Bytes) {
        #[cfg(not (feature = "print_logs"))]
        {
            let mut hasher = DefaultHasher::new();
            _data.to_vec().hash(&mut hasher);
            let h = hasher.finish();
            if self.logs.contains(&h) {
                return;
            }
            self.logs.insert(h);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            let timestamp = now.as_nanos();
            println!("log@{} {:?}", timestamp, hex::encode(_data));
        }
    }

    fn selfdestruct(&mut self, _address: EVMAddress, _target: EVMAddress) -> Option<SelfDestructResult> {
        return Some(SelfDestructResult::default());
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
        state: &mut S,
    ) -> (InstructionResult, Option<EVMAddress>, Gas, Bytes) {
        unsafe {
            if unsafe {CONCRETE_CREATE || IN_DEPLOY} {
                // todo: use nonce + hash instead
                let mut r_addr = generate_random_address(state);
                println!("new contract deploy in: {:?}", r_addr);
                let mut interp = Interpreter::new(
                    Contract::new_with_context(
                        Bytes::new(),
                        Bytecode::new_raw(inputs.init_code.clone()),
                        &CallContext {
                            address: r_addr,
                            caller: inputs.caller,
                            code_address: r_addr,
                            apparent_value: inputs.value,
                            scheme: CallScheme::Call,
                        },
                    ),
                    1e10 as u64,
                    false
                );
                let ret = self.run_inspect(&mut interp, state);
                if ret == InstructionResult::Continue {
                    let runtime_code = interp.return_value();
                    self.set_code(
                        r_addr,
                        Bytecode::new_raw(runtime_code.clone()),
                        state
                    );
                    (
                        Continue,
                        Some(r_addr),
                        Gas::new(0),
                        runtime_code,
                    )
                } else {
                    let runtime_code = interp.return_value();
                    self.set_code(
                        r_addr,
                        Bytecode::new_raw(runtime_code.clone()),
                        state
                    );
                    (
                        ret,
                        Some(r_addr),
                        Gas::new(0),
                        Bytes::new(),
                    )
                }
            } else {
                (
                    InstructionResult::Revert,
                    None,
                    Gas::new(0),
                    Bytes::new(),
                )
            }

        }
    }

    fn call(&mut self, input: &mut CallInputs, interp: &mut Interpreter, output_info: (usize, usize), state: &mut S) -> (InstructionResult, Gas, Bytes) {
        let precompile = is_precompile(input.contract, self.precompiles.len());
        if !precompile {
            let to_address = if input.context.scheme == CallScheme::DelegateCall {
                input.context.code_address
            } else {
                input.context.address
            };
            // verify is to address is from input or tx.origin or msg.sender or in arguments
            self.from_args = if (self.call_depth > 0 && self.is_input_contain_address(&interp.contract.input, to_address, interp.contract.code_address)) ||
                to_address == interp.contract.caller || to_address == self.env.tx.caller.into()
            {
                true
            } else {
                false
            };
            if self.is_execute_victim_function && to_address == self.origin {
                let target_function_name = self.extract_function_signature_from_input(&input.input);
                if target_function_name == self.target_dependency {
                    // println!("Cross contract reenter hit!");
                    interp.instruction_result = InstructionResult::ImplicitBugHit;
                    self.bug_hit = true;
                }
            }
        }
        self.add_call_depth();
        let res = if precompile {
            self.call_precompile(input, state)
        } else {
            self.divide_call_by_is_same_dapp(input, state)
        };
        self.sub_call_depth();
        unsafe {
            invoke_middlewares!(self, interp, state, on_return);
        }
        res
    }
}
