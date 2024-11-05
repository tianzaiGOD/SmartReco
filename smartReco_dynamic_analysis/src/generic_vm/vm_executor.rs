use crate::generic_vm::vm_state::VMStateT;

use crate::state_input::StagedVMState;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use crate::input::ConciseSerde;

use revm_interpreter::{InstructionResult};

pub const MAP_SIZE: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult<Loc, Addr, VS, Out, CI>
where
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug,
    Loc: Serialize + DeserializeOwned + Debug,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    pub output: Out,
    pub reverted: bool,
    #[serde(deserialize_with = "StagedVMState::deserialize")]
    pub new_state: StagedVMState<VS>,
    pub additional_info: Option<Vec<u8>>,
    pub instruction_result: InstructionResult,
    pub phantom: std::marker::PhantomData<(Loc, Addr, VS, CI)>,
}

impl<Loc, Addr, VS, Out, CI> ExecutionResult<Loc, Addr, VS, Out, CI>
where
    VS: Default + VMStateT + 'static,
    Addr: Serialize + DeserializeOwned + Debug,
    Loc: Serialize + DeserializeOwned + Debug,
    Out: Default,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    pub fn empty_result() -> Self {
        Self {
            output: Out::default(),
            reverted: false,
            new_state: StagedVMState::new_uninitialized(),
            additional_info: None,
            instruction_result: InstructionResult::Stop,
            phantom: Default::default(),
        }
    }
}

pub trait GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI> {
    fn deploy(
        &mut self,
        code: Code,
        constructor_args: Option<By>,
        deployed_address: Addr,
        state: &mut S,
    ) -> Option<Addr>;
    fn execute(&mut self, input: &I, state: &mut S) -> ExecutionResult<Loc, Addr, VS, Out, CI>
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Loc: Serialize + DeserializeOwned + Debug,
        Out: Default,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde;

    fn fast_static_call(&mut self, data: &Vec<(Addr, By)>, vm_state: &VS, state: &mut S) -> Vec<Out>
    where
        VS: VMStateT,
        Addr: Serialize + DeserializeOwned + Debug,
        Loc: Serialize + DeserializeOwned + Debug,
        Out: Default;

    fn state_changed(&self) -> bool;
}
