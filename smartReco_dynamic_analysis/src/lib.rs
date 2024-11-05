#![feature(downcast_unchecked)]
#![feature(let_chains)]
#![feature(unchecked_math)]
#![feature(trait_alias)]

extern crate core;

pub mod cache;
pub mod r#const;
pub mod evm;
pub mod executor;
pub mod fuzzers;
pub mod generic_vm;
pub mod input;
pub mod state;
pub mod state_input;
pub mod mutation_utils;

pub mod dapp_utils;