/// Definition of ABI types and their encoding, decoding, mutating methods

use crate::evm::abi::ABILossyType::{TArray, TDynamic, TEmpty, TUnknown, T256};
use crate::mutation_utils::{byte_mutator, byte_mutator_with_expansion};
use crate::generic_vm::vm_state::VMStateT;
use crate::state::{HasCaller};
use bytes::Bytes;
use itertools::Itertools;
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::MutationResult;
use libafl::prelude::{HasMetadata, Mutator, Rand};
use libafl::state::{HasMaxSize, HasRand, State};
use once_cell::sync::Lazy;
use rand::random;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Write};
use std::ops::{Deref, DerefMut};
use libafl::impl_serdeany;
use crate::evm::types::{EVMAddress, EVMU256, EVMBytes, EVMFuzzState};
use crate::input::ConciseSerde;


/// Mapping from known signature to function name
static mut FUNCTION_SIG: Lazy<HashMap<[u8; 4], String>> = Lazy::new(|| HashMap::new());

/// Convert a vector of bytes to hex string
fn vec_to_hex(v: &Vec<u8>) -> String {
    let mut s = String::new();
    s.push_str("0x");
    for i in v {
        s.push_str(&format!("{:02x}", i));
    }
    s
}

/// Calculate the smallest multiple of [`multiplier`] that is larger than or equal to [`x`] (round up)
fn roundup(x: usize, multiplier: usize) -> usize {
    (x + multiplier - 1) / multiplier * multiplier
}

/// Set the first 32 bytes of [`bytes`] to be [`len`] (LSB)
///
/// E.g. if len = 0x1234,
/// then bytes is set to 0x00000000000000000000000000000000000000000000001234
fn set_size(bytes: *mut u8, len: usize) {
    let mut rem: usize = len;
    unsafe {
        for i in 0..32 {
            *bytes.add(31 - i) = (rem & 0xff) as u8;
            rem >>= 8;
        }
    }
}

fn get_size(bytes: &Vec<u8>) -> usize {
    let mut size: usize = 0;
    for i in 0..32 {
        size <<= 8;
        size += bytes[i] as usize;
    }
    size
}

/// ABI instance map from address
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ABIAddressToInstanceMap {
    /// Mapping from address to ABI instance
    pub map: HashMap<EVMAddress, Vec<BoxedABI>>,
}

impl_serdeany!(ABIAddressToInstanceMap);

impl ABIAddressToInstanceMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Add an ABI instance to the map
    pub fn add(&mut self, address: EVMAddress, abi: BoxedABI) {
        if !self.map.contains_key(&address) {
            self.map.insert(address, Vec::new());
        }
        self.map.get_mut(&address).unwrap().push(abi);
    }
}

pub fn register_abi_instance<S: HasMetadata>(
    address: EVMAddress,
    abi: BoxedABI,
    state: &mut S
) {
    let mut abi_map = state.metadata_mut().get_mut::<ABIAddressToInstanceMap>().expect("ABIAddressToInstanceMap not found");
    abi_map.add(address, abi);
}

/// ABI types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ABILossyType {
    /// All 256-bit types (uint8, uint16, uint32, uint64, uint128, uint256, address...)
    T256,
    /// All array types (X[], X[n], (X,Y,Z))
    TArray,
    /// All dynamic types (string, bytes...)
    TDynamic,
    /// Empty type (nothing)
    TEmpty,
    /// Unknown type (e.g., those we don't know ABI, it can be any type)
    TUnknown,
}

/// Traits of ABI types (encoding, decoding, etc.)
pub trait ABI: CloneABI + serde_traitobject::Serialize + serde_traitobject::Deserialize {
    /// Is the args static (i.e., fixed size)
    fn is_static(&self) -> bool;
    /// Get the ABI-encoded bytes of args
    fn get_bytes(&self) -> Vec<u8>;
    /// Get the ABI type of args
    fn get_type(&self) -> ABILossyType;
    /// Set the bytes to args, used for decoding
    fn set_bytes(&mut self, bytes: Vec<u8>);
    /// Convert args to string (for debugging)
    fn to_string(&self) -> String;
    fn as_any(&mut self) -> &mut dyn Any;
    /// Get the size of args
    fn get_size(&self) -> usize;
}

impl Debug for dyn ABI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ABI")
            .field("is_static", &self.is_static())
            .field("get_bytes", &self.get_bytes())
            .finish()
    }
}

/// Cloneable trait object, to support serde serialization
pub trait CloneABI {
    fn clone_box(&self) -> Box<dyn ABI>;
}

impl<T> CloneABI for T
where
    T: ABI + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn ABI> {
        Box::new(self.clone())
    }
}

/// ABI wrapper + function hash, to support serde serialization
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BoxedABI {
    /// ABI wrapper
    #[serde(with = "serde_traitobject")]
    pub b: Box<dyn ABI>,
    /// Function hash, if it is 0x00000000, it means the function hash is not set or
    /// this is to resume execution from a previous control leak
    pub function: [u8; 4],
}

impl BoxedABI {
    /// Create a new ABI wrapper with function hash = 0x00000000
    pub fn new(b: Box<dyn ABI>) -> Self {
        Self {
            b,
            function: [0; 4],
        }
    }

    /// Get the args in ABI form (unencoded)
    pub fn get(&self) -> &Box<dyn ABI> {
        &self.b
    }

    /// Get the args in ABI form (unencoded) mutably
    pub fn get_mut(&mut self) -> &mut Box<dyn ABI> {
        &mut self.b
    }

    /// Get the function hash + encoded args (transaction data)
    pub fn get_bytes(&self) -> Vec<u8> {
        [Vec::from(self.function), self.b.get_bytes()].concat()
    }

    /// Get the function hash + encoded args (transaction data)
    pub fn get_bytes_vec(&self) -> Vec<u8> {
        self.b.get_bytes()
    }

    /// Determine if the args is static (i.e., fixed size)
    pub fn is_static(&self) -> bool {
        self.b.is_static()
    }

    /// Get the ABI type of args.
    /// If the function has more than one args, it will return Array type (tuple of args)
    pub fn get_type(&self) -> ABILossyType {
        self.b.get_type()
    }

    /// Get the ABI type of args in string format
    pub fn get_type_str(&self) -> String {
        match self.b.get_type() {
            T256 => "A256".to_string(),
            TArray => "AArray".to_string(),
            TDynamic => "ADynamic".to_string(),
            TEmpty => "AEmpty".to_string(),
            TUnknown => "AUnknown".to_string(),
        }
    }

    /// Set the function hash
    pub fn set_func(&mut self, function: [u8; 4]) {
        self.function = function;
    }

    /// Set the function hash with function name, so that we can print the function name instead of hash
    pub fn set_func_with_name(&mut self, function: [u8; 4], function_name: String) {
        self.function = function;
        unsafe {
            FUNCTION_SIG.insert(function, function_name);
        }
    }

    /// Convert function hash and args to string (for debugging)
    pub fn to_string(&self) -> String {
        if self.function == [0; 4] {
            // format!("Stepping with return: {}", hex::encode(self.b.to_string()))
            format!("Stepping with return: {}", self.b.to_string())
        } else {
            let function_name = unsafe {
                FUNCTION_SIG
                    .get(&self.function)
                    .unwrap_or(&hex::encode(self.function))
                    .clone()
            };
            format!("{}{}", function_name, self.b.to_string())
        }
    }

    /// Set the bytes to args, used for decoding
    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.b.set_bytes(bytes[4..].to_vec());
    }
}


/// Randomly sample an args with any type with size `size`
fn sample_abi<Loc, Addr, VS, S, CI>(state: &mut S, size: usize) -> BoxedABI
where
    S: State + HasRand + HasMaxSize + HasCaller<EVMAddress>,
    VS: VMStateT + Default,
    Loc: Clone + Debug + Serialize + DeserializeOwned,
    Addr: Clone + Debug + Serialize + DeserializeOwned,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
{
    // TODO(@shou): use a better sampling strategy
    if size == 32 {
        // sample a static type
        match state.rand_mut().below(100) % 2 {
            0 => BoxedABI::new(Box::new(A256 {
                data: vec![0; 32],
                is_address: false,
                dont_mutate: false,
            })),
            1 => BoxedABI::new(Box::new(A256 {
                data: state.get_rand_address().0.into(),
                is_address: true,
                dont_mutate: false,
            })),
            _ => unreachable!(),
        }
    } else {
        // sample a dynamic type
        let max_size = state.max_size();
        let vec_size = state.rand_mut().below(max_size as u64) as usize;
        match state.rand_mut().below(100) % 4 {
            // dynamic
            0 => BoxedABI::new(Box::new(ADynamic {
                data: vec![state.rand_mut().below(255) as u8; vec_size],
                multiplier: 32,
                data_type: "string".to_string(),
            })),
            // tuple
            1 => BoxedABI::new(Box::new(AArray {
                data: vec![sample_abi::<Loc, Addr, VS, S, CI>(state, 32); vec_size],
                dynamic_size: false,
            })),
            // array[]
            2 => {
                let abi = sample_abi::<Loc, Addr, VS, S, CI>(state, 32);
                BoxedABI::new(Box::new(AArray {
                    data: vec![abi; vec_size],
                    dynamic_size: false,
                }))
            }
            // array[...]
            3 => {
                let abi = sample_abi::<Loc, Addr, VS, S, CI>(state, 32);
                BoxedABI::new(Box::new(AArray {
                    data: vec![abi; vec_size],
                    dynamic_size: true,
                }))
            }
            _ => unreachable!(),
        }
    }
}

impl BoxedABI {
    /// Mutate the args
    pub fn mutate<Loc, Addr, VS, S, CI>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            // + HasItyState<Loc, Addr, VS, CI>
            + HasCaller<EVMAddress>
            + HasMetadata,
        VS: VMStateT + Default,
        Loc: Clone + Debug + Serialize + DeserializeOwned,
        Addr: Clone + Debug + Serialize + DeserializeOwned,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
    {
        self.mutate_with_vm_slots::<Loc, Addr, VS, S, CI>(state, None)
    }

    /// Mutate the args and crossover with slots in the VM state
    ///
    /// Check [`VMStateHintedMutator`] for more details
    pub fn mutate_with_vm_slots<Loc, Addr, VS, S, CI>(
        &mut self,
        state: &mut S,
        vm_slots: Option<HashMap<EVMU256, EVMU256>>,
    ) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            // + HasItyState<Loc, Addr, VS, CI>
            + HasCaller<EVMAddress>
            + HasMetadata,
        VS: VMStateT + Default,
        Loc: Clone + Debug + Serialize + DeserializeOwned,
        Addr: Clone + Debug + Serialize + DeserializeOwned,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde
    {
        match self.get_type() {
            // no need to mutate empty args
            TEmpty => MutationResult::Skipped,
            // mutate static args
            T256 => {
                let v = self.b.deref_mut().as_any();
                let a256 = v.downcast_mut::<A256>().unwrap();
                if a256.dont_mutate {
                    return MutationResult::Skipped;
                }
                if a256.is_address {
                    a256.data = state.get_rand_address().0.to_vec();
                    MutationResult::Mutated
                } else {
                    byte_mutator(state, a256, vm_slots)
                }
            }
            // mutate dynamic args
            TDynamic => {               
                let adyn = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<ADynamic>()
                    .unwrap();
                byte_mutator_with_expansion(state, adyn, vm_slots)
            }
            // mutate tuple/array args
            TArray => {
                let aarray = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<AArray>()
                    .unwrap();

                let data_len = aarray.data.len();
                if data_len == 0 {
                    return MutationResult::Skipped;
                }
                if aarray.dynamic_size {
                    match state.rand_mut().below(100) {
                        0..=80 => {
                            let index: usize = state.rand_mut().next() as usize % data_len;
                            let result = aarray.data[index].mutate_with_vm_slots::<Loc, Addr, VS, S, CI>(state, vm_slots);
                            return result;
                        }
                        81..=90 => {
                            // increase size
                            if state.max_size() <= aarray.data.len() {
                                return MutationResult::Skipped;
                            }
                            for _ in 0..state.rand_mut().next() as usize % state.max_size() {
                                aarray.data.push(aarray.data[0].clone());
                            }
                        }
                        91..=100 => {
                            // decrease size
                            if aarray.data.len() < 1 {
                                return MutationResult::Skipped;
                            }
                            let index: usize = state.rand_mut().next() as usize % data_len;
                            aarray.data.remove(index);
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                } else {
                    let index: usize = state.rand_mut().next() as usize % data_len;
                    return aarray.data[index].mutate_with_vm_slots::<Loc, Addr, VS, S, CI>(state, vm_slots);
                }
                MutationResult::Mutated
            }
            // mutate unknown args, may change the type
            TUnknown => {
                let a_unknown = self
                    .b
                    .deref_mut()
                    .as_any()
                    .downcast_mut::<AUnknown>()
                    .unwrap();
                unsafe {
                    if a_unknown.size == 0 {
                        a_unknown.concrete = BoxedABI::new(Box::new(AEmpty {}));
                        return MutationResult::Skipped;
                    }
                    if (state.rand_mut().below(100)) < 80 {
                        a_unknown
                            .concrete
                            .mutate_with_vm_slots::<Loc, Addr, VS, S, CI>(state, vm_slots)
                    } else {
                        a_unknown.concrete = sample_abi::<Loc, Addr, VS, S, CI>(state, a_unknown.size);
                        MutationResult::Mutated
                    }
                }
            }
        }
    }
}

impl Clone for Box<dyn ABI> {
    fn clone(&self) -> Box<dyn ABI> {
        self.clone_box()
    }
}

/// AEmpty is used to represent empty args
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AEmpty {}

impl Input for AEmpty {
    fn generate_name(&self, idx: usize) -> String {
        format!("AEmpty_{}", idx)
    }
}

impl ABI for AEmpty {
    fn is_static(&self) -> bool {
        true
    }

    fn get_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    fn get_type(&self) -> ABILossyType {
        TEmpty
    }

    fn set_bytes(&mut self, bytes: Vec<u8>) {
        assert!(bytes.len() == 0);
    }

    fn to_string(&self) -> String {
        "".to_string()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn get_size(&self) -> usize {
        0
    }
}

/// [`A256`] is used to represent 256-bit args
/// (including uint8, uint16... as they are all 256-bit behind the scene)
///
/// For address type, we need to distinguish between it and rest so that we can mutate correctly.
/// Instead of mutating address as a 256-bit integer, we mutate it to known address or zero address.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct A256 {
    /// 256-bit or less data representing the arg
    pub data: Vec<u8>,
    /// whether this arg is an address
    pub is_address: bool,
    /// whether this arg should not be mutated
    pub dont_mutate: bool,
}

impl Input for A256 {
    fn generate_name(&self, idx: usize) -> String {
        format!("A256_{}", idx)
    }
}

impl HasBytesVec for A256 {
    fn bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.data.as_mut()
    }
}

impl ABI for A256 {
    fn is_static(&self) -> bool {
        // 256-bit args are always static
        true
    }

    fn get_bytes(&self) -> Vec<u8> {
        // pad self.data to 32 bytes with 0s on the left
        let mut bytes = vec![0; 32];
        let data_len = self.data.len();
        unsafe {
            let mut ptr = bytes.as_mut_ptr();
            ptr = ptr.add(32 - data_len);
            for i in 0..data_len {
                *ptr.add(i) = self.data[i];
            }
        }
        bytes
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn get_type(&self) -> ABILossyType {
        T256
    }

    fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.data = bytes;
    }

    fn to_string(&self) -> String {
        vec_to_hex(&self.data)
    }

    fn get_size(&self) -> usize {
        32
    }
}


/// [`ADynamic`] is used to represent dynamic args
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ADynamic {
    /// data representing the arg
    data: Vec<u8>,
    /// multiplier used to round up the size of the data
    multiplier: usize,
    /// the type: string, bytes, or default value: unknown
    data_type: String,
}

impl Input for ADynamic {
    fn generate_name(&self, idx: usize) -> String {
        format!("ADynamic_{}", idx)
    }
}

impl HasBytesVec for ADynamic {
    fn bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.data.as_mut()
    }
}

impl ABI for ADynamic {
    fn is_static(&self) -> bool {
        false
    }

    fn get_bytes(&self) -> Vec<u8> {
        // pad self.data to K bytes with 0s on the left
        // where K is the smallest multiple of self.multiplier that is larger than self.data.len()
        let new_len: usize = roundup(self.data.len(), self.multiplier);
        let mut bytes = vec![0; new_len + 32];
        unsafe {
            let ptr = bytes.as_mut_ptr();
            set_size(ptr, self.data.len());
            // set data
            for i in 0..self.data.len() {
                *ptr.add(i + 32) = self.data[i];
            }
        }
        bytes
    }

    fn get_type(&self) -> ABILossyType {
        TDynamic
    }

    fn to_string(&self) -> String {
        vec_to_hex(&self.data)
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.data = bytes;
    }

    fn get_size(&self) -> usize {
        self.data.len() + 32
    }
}


/// [`AArray`] is used to represent array or tuple
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AArray {
    /// vector of ABI objects in the array / tuple
    pub(crate) data: Vec<BoxedABI>,
    /// whether the size of the array is dynamic (i.e., is it dynamic size array)
    pub(crate) dynamic_size: bool,
}

impl Input for AArray {
    fn generate_name(&self, idx: usize) -> String {
        format!("AArray_{}", idx)
    }
}

impl ABI for AArray {
    fn is_static(&self) -> bool {
        if self.dynamic_size {
            false
        } else {
            self.data.iter().all(|x| x.is_static())
        }
    }

    fn get_bytes(&self) -> Vec<u8> {
        // check Solidity spec for encoding of arrays
        let mut tail_data: Vec<Vec<u8>> = Vec::new();
        let mut tails_offset: Vec<usize> = Vec::new();
        let mut head: Vec<Vec<u8>> = Vec::new();
        let mut head_data: Vec<Vec<u8>> = Vec::new();
        let mut head_size: usize = 0;
        let dummy_bytes: Vec<u8> = vec![0; 0];
        for i in 0..self.data.len() {
            if self.data[i].is_static() {
                let encoded = self.data[i].get_bytes_vec();
                head_size += encoded.len();
                head.push(encoded);
                tail_data.push(dummy_bytes.clone());
            } else {
                tail_data.push(self.data[i].get_bytes_vec());
                head.push(dummy_bytes.clone());
                head_size += 32;
            }
        }
        let mut content_size: usize = 0;
        tails_offset.push(0);
        let mut head_data_size: usize = 0;
        let mut tail_data_size: usize = 0;
        if tail_data.len() > 0 {
            for i in 0..tail_data.len() - 1 {
                content_size += tail_data[i].len();
                tails_offset.push(content_size);
            }
            for i in 0..tails_offset.len() {
                if head[i].len() == 0 {
                    head_data.push(vec![0; 32]);
                    head_data_size += 32;
                    set_size(head_data[i].as_mut_ptr(), tails_offset[i] + head_size);
                } else {
                    head_data.push(head[i].clone());
                    head_data_size += head[i].len();
                }
            }
            tail_data_size = content_size + tail_data[tail_data.len() - 1].len();
        }
        let mut bytes =
            vec![0; head_data_size + tail_data_size + if self.dynamic_size { 32 } else { 0 }];

        if self.dynamic_size {
            set_size(bytes.as_mut_ptr(), self.data.len());
        }
        let mut offset: usize = if self.dynamic_size { 32 } else { 0 };
        for i in 0..head_data.len() {
            bytes[offset..offset + head_data[i].len()]
                .copy_from_slice(head_data[i].to_vec().as_slice());
            offset += head_data[i].len();
        }
        for i in 0..tail_data.len() {
            bytes[offset..offset + tail_data[i].len()]
                .copy_from_slice(tail_data[i].to_vec().as_slice());
            offset += tail_data[i].len();
        }
        bytes
    }

    fn get_type(&self) -> ABILossyType {
        TArray
    }

    fn to_string(&self) -> String {
        format!(
            "({})",
            self.data.iter().map(|x| x.b.deref().to_string()).join(",")
        )
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    // Input: packed concrete bytes produced by get_concolic
    // Set the bytes in self.data accordingly
    fn set_bytes(&mut self, bytes: Vec<u8>) {
        // TODO: here we need to able to perform
        // the inverse of get_bytes

        if self.dynamic_size {
            // to usize
            let size: usize = bytes[0..32]
                .iter()
                .fold(0, |acc, x| (acc << 8) + *x as usize);
            if size != self.data.len() {
                unreachable!("Array size mismatch");
            }
        }

        let mut offset = if self.dynamic_size { 32 } else { 0 };
        //let mut heads_offset: Vec<usize> = Vec::new();
        let mut tails_offset: Vec<usize> = Vec::new();
        let mut head_size: usize = offset;
        let mut index = 0;

        // get old data size
        for i in 0..self.data.len() {
            if !self.data[i].is_static() {
                let tail_offset = get_size(&bytes[head_size..head_size + 32].to_vec());
                tails_offset.push(tail_offset);
                head_size += 32;
            }
        }

        for mut item in self.data.iter_mut() {
            if item.is_static() {
                let len = item.b.get_size();
                let mut new_bytes = vec![0; len];
                new_bytes.copy_from_slice(&bytes[offset..offset + len]);
                //println!("static {} set: {}", item.get_type_str(), hex::encode(new_bytes.clone()));
                item.b.set_bytes(new_bytes);
                offset += len;
            } else {
                let tail_offset = tails_offset[index]+offset;
                let tail_size = if index == tails_offset.len() - 1 {
                    bytes.len() - tail_offset
                } else {
                    tails_offset[index + 1] - tail_offset+offset
                };
                index += 1;
                let mut new_bytes = vec![0; tail_size];
                new_bytes.copy_from_slice(&bytes[tail_offset..tail_offset+tail_size]);
                //println!("dynamic {} set: {}", item.get_type_str(), hex::encode(new_bytes.clone()));
                item.b.set_bytes(new_bytes);
            }
        }
    }

    fn get_size(&self) -> usize {
        let data_size = self.data.iter().map(|x| x.b.get_size()).sum::<usize>();
        if self.dynamic_size {
            32 + data_size
        } else {
            data_size
        }
    }
}

/// [`AUnknown`] represents arg with no known types (can be any type)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AUnknown {
    /// Current concrete arg
    pub concrete: BoxedABI,
    /// Size constraint
    pub size: usize,
}

impl Input for AUnknown {
    fn generate_name(&self, idx: usize) -> String {
        format!("AUnknown_{}", idx)
    }
}

impl ABI for AUnknown {
    fn is_static(&self) -> bool {
        self.concrete.is_static()
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.concrete.b.get_bytes()
    }

    fn get_type(&self) -> ABILossyType {
        TUnknown
    }

    fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.concrete.b.set_bytes(bytes);
    }

    fn to_string(&self) -> String {
        self.concrete.b.to_string()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn get_size(&self) -> usize {
        self.concrete.b.get_size()
    }
}

/// Create a [`BoxedABI`] with default arg given the ABI type in string
pub fn get_abi_type_boxed(abi_name: &String) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type(abi_name, &None),
        function: [0; 4],
    };
}

/// Create a [`BoxedABI`] with default arg given the ABI type in string and address
/// todo: remove this function
pub fn get_abi_type_boxed_with_address(abi_name: &String, address: Vec<u8>) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type(abi_name, &Some(address)),
        function: [0; 4],
    };
}

/// Create a [`BoxedABI`] with default arg given the ABI type in string, address and bytes
/// todo: remove this function
pub fn get_abi_type_boxed_with_state(abi_name: &String, state: &mut EVMFuzzState) -> BoxedABI {
    return BoxedABI {
        b: get_abi_type_with_state(abi_name, state),
        function: [0; 4],
    };
}

pub fn split_with_parenthesis(s: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut current: String = String::new();
    let mut parenthesis: i32 = 0;
    for c in s.chars() {
        if c == '(' {
            parenthesis += 1;
        } else if c == ')' {
            parenthesis -= 1;
        }
        if c == ',' && parenthesis == 0 {
            result.push(current);
            current = String::new();
        } else {
            current.push(c);
        }
    }
    result.push(current);
    result
}

pub fn get_abi_type(abi_name: &String, with_address: &Option<Vec<u8>>) -> Box<dyn ABI> {
    let abi_name_str = abi_name.as_str();
    // tuple
    if abi_name_str == "()" {
        return Box::new(AEmpty {});
    }
    if abi_name_str.starts_with("(") && abi_name_str.ends_with(")") {
        return Box::new(AArray {
            data: split_with_parenthesis(&abi_name_str[1..abi_name_str.len() - 1])
                .iter()
                .map(|x| BoxedABI {
                    b: get_abi_type(&String::from(x), with_address),
                    function: [0; 4],
                })
                .collect(),
            dynamic_size: false,
        });
    }
    if abi_name_str.ends_with("[]") {
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type(
                        &abi_name[..abi_name_str.len() - 2].to_string(),
                        with_address
                    ),
                    function: [0; 4]
                };
                1
            ],
            dynamic_size: true,
        });
    } else if abi_name_str.ends_with("]") && abi_name_str.contains("[") {
        let split = abi_name_str.rsplit_once('[').unwrap();
        let name = split.0;
        let len = split
            .1
            .split(']')
            .next()
            .unwrap()
            .parse::<usize>()
            .expect("invalid array length");
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type(&String::from(name), with_address),
                    function: [0; 4]
                };
                len
            ],
            dynamic_size: false,
        });
    }
    get_abi_type_basic(abi_name.as_str(), 32, with_address)
}

/// Get the arg with default value given the ABI type in string
pub fn get_abi_type_with_state(abi_name: &String, state: &mut EVMFuzzState) -> Box<dyn ABI> {
    let abi_name_str = abi_name.as_str();
    // tuple
    if abi_name_str == "()" {
        return Box::new(AEmpty {});
    }
    if abi_name_str.starts_with("(") && abi_name_str.ends_with(")") {
        return Box::new(AArray {
            data: split_with_parenthesis(&abi_name_str[1..abi_name_str.len() - 1])
                .iter()
                .map(|x| BoxedABI {
                    b: get_abi_type_with_state(&String::from(x), state),
                    function: [0; 4],
                })
                .collect(),
            dynamic_size: false,
        });
    }
    if abi_name_str.ends_with("[]") {
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type_with_state(
                        &abi_name[..abi_name_str.len() - 2].to_string(),
                        state
                    ),
                    function: [0; 4]
                };
                1
            ],
            dynamic_size: true,
        });
    } else if abi_name_str.ends_with("]") && abi_name_str.contains("[") {
        let split = abi_name_str.rsplit_once('[').unwrap();
        let name = split.0;
        let len = split
            .1
            .split(']')
            .next()
            .unwrap()
            .parse::<usize>()
            .expect("invalid array length");
        return Box::new(AArray {
            data: vec![
                BoxedABI {
                    b: get_abi_type_with_state(&String::from(name), state),
                    function: [0; 4]
                };
                len
            ],
            dynamic_size: false,
        });
    }
    get_abi_type_basic_with_state(abi_name.as_str(), 32, state)
}

/// Get the arg with default value given the ABI type in string.
/// Only support basic types.
fn get_abi_type_basic_with_state(
    abi_name: &str,
    abi_bs: usize,
    state: &mut EVMFuzzState
) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(A256 {
            data: vec![0; abi_bs],
            is_address: false,
            dont_mutate: false,
        }),
        "address" => Box::new(A256 {
            data: {
                let address = state.get_rand_address().0;
                println!("{:#?}", address);
                Vec::from(address)
            },
            is_address: true,
            dont_mutate: false,
        }),
        "bool" => Box::new(A256 {
            data: vec![0; 1],
            is_address: false,
            dont_mutate: false,
        }),
        "bytes" => Box::new(ADynamic {
            data: Vec::new(), //with_bytes.to_owned().unwrap_or(Vec::new()),
            multiplier: 32,
            data_type: "bytes".to_string(),
        }),
        "string" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
            data_type: "string".to_string(),
        }),
        _ => {
            if abi_name.starts_with("uint") {
                let len = abi_name[4..].parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic_with_state("uint", len / 8, state);
            } else if abi_name.starts_with("int") {
                let len = abi_name[3..].parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic_with_state("int", len / 8, state);
            } else if abi_name == "unknown" {
                return Box::new(AUnknown {
                    concrete: BoxedABI {
                        b: get_abi_type_basic_with_state("uint", 32, state),
                        function: [0; 4],
                    },
                    size: 1,
                });
            } else if abi_name.starts_with("bytes") {
                let len = abi_name[5..].parse::<usize>().unwrap();
                return Box::new(A256 {
                    data: vec![0; len], //with_bytes.to_owned().unwrap_or(vec![0; len]),
                    is_address: false,
                    dont_mutate: false,
                });
                
            } else if abi_name.len() == 0 {
                return Box::new(AEmpty {});
            } else {
                panic!("unknown abi type {}", abi_name);
            }
        }
    }
}

/// Get the arg with default value given the ABI type in string.
/// Only support basic types.
fn get_abi_type_basic(
    abi_name: &str,
    abi_bs: usize,
    with_address: &Option<Vec<u8>>,
) -> Box<dyn ABI> {
    match abi_name {
        "uint" | "int" => Box::new(A256 {
            data: vec![0; abi_bs],
            is_address: false,
            dont_mutate: false,
        }),
        "address" => Box::new(A256 {
            data: with_address.to_owned().unwrap_or(vec![0; 20]),
            is_address: true,
            dont_mutate: false,
        }),
        "bool" => Box::new(A256 {
            data: vec![0; 1],
            is_address: false,
            dont_mutate: false,
        }),
        "bytes" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
            data_type: "bytes".to_string(),
        }),
        "string" => Box::new(ADynamic {
            data: Vec::new(),
            multiplier: 32,
            data_type: "string".to_string(),
        }),
        _ => {
            if abi_name.starts_with("uint") {
                let len = abi_name[4..].parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic("uint", len / 8, with_address);
            } else if abi_name.starts_with("int") {
                let len = abi_name[3..].parse::<usize>().unwrap();
                assert!(len % 8 == 0 && len >= 8);
                return get_abi_type_basic("int", len / 8, with_address);
            } else if abi_name == "unknown" {
                return Box::new(AUnknown {
                    concrete: BoxedABI {
                        b: get_abi_type_basic("uint", 32, with_address),
                        function: [0; 4],
                    },
                    size: 1,
                });
            } else if abi_name.starts_with("bytes") {
                let len = abi_name[5..].parse::<usize>().unwrap();
                return Box::new(A256 {
                    data: vec![0; len],
                    is_address: false,
                    dont_mutate: false,
                });
                
            } else if abi_name.len() == 0 {
                return Box::new(AEmpty {});
            } else {
                panic!("unknown abi type {}", abi_name);
            }
        }
    }
}
