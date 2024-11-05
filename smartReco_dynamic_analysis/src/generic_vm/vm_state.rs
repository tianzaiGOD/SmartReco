use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use crate::evm::types::{EVMAddress, EVMU256};
use std::collections::{HashMap, HashSet};
use revm_primitives::ruint::Uint;

pub trait VMStateT: Clone + Debug + Default + Serialize + DeserializeOwned {
    fn get_hash(&self) -> u64;
    fn has_post_execution(&self) -> bool;
    fn get_post_execution_needed_len(&self) -> usize;
    fn get_post_execution_pc(&self) -> usize;
    fn get_post_execution_len(&self) -> usize;
    #[cfg(feature = "full_trace")]
    fn get_flashloan(&self) -> String;
    fn as_any(&self) -> &dyn std::any::Any;
    fn get(&self, address: EVMAddress, block_number: Uint<256, 4>) -> Option<&HashMap<EVMU256, EVMU256>>;
    fn get_mut(&mut self, address: EVMAddress, block_number: Uint<256, 4>) -> Option<&mut HashMap<EVMU256, EVMU256>>;
    fn insert(&mut self, address: EVMAddress, storage: HashMap<EVMU256, EVMU256>, block_number: Uint<256, 4>);
    fn new() -> Self;
    fn set_bug_hit_mut(&mut self, result: bool);
}
