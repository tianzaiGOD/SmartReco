/// Implements wrappers around VMState that can be stored in a corpus.

use libafl::inputs::Input;

use std::fmt::Debug;

use crate::generic_vm::vm_state::VMStateT;

// use crate::tracer::TxnTrace;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use crate::input::ConciseSerde;


/// StagedVMState is a wrapper around a VMState that can be stored in a corpus.
/// It also has stage field that is used to store the stage of the oracle execution on such a VMState.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StagedVMState<VS>
where
    VS: Default + VMStateT, 
{
    #[serde(deserialize_with = "VS::deserialize")]
    pub state: VS,  // VM state
    pub stage: Vec<u64>,  // Stages of each oracle execution
    pub initialized: bool,  // Whether the VMState is initialized, uninitialized VMState will be initialized during mutation
}

impl<VS> StagedVMState<VS>
where
    VS: Default + VMStateT,
{
    /// Create a new StagedVMState with a given VMState
    pub fn new_with_state(state: VS) -> Self {
        Self {
            state,
            stage: vec![],
            initialized: true,
            // trace: TxnTrace::new(),
        }
    }

    /// Create a new uninitialized StagedVMState
    pub fn new_uninitialized() -> Self {
        Self {
            state: Default::default(),
            stage: vec![],
            initialized: false,
            // trace: TxnTrace::new(),
        }
    }
}

impl<VS> Input for StagedVMState<VS>
where
    VS: Default + VMStateT,
{
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{}.state", idx)
    }
}
