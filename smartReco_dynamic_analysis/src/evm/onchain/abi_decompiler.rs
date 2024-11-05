use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use crate::evm::contract_utils::ABIConfig;
use heimdall::decompile::decompile_with_bytecode;
use heimdall::decompile::out::solidity::ABIStructure;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use crate::cache::{Cache, FileSystemCache};

pub fn fetch_abi_heimdall(bytecode: String) -> Vec<ABIConfig> {
    let mut hasher = DefaultHasher::new();
    bytecode.hash(&mut hasher);
    let bytecode_hash = hasher.finish();
    let cache_key = format!("{}.json", bytecode_hash);
    let cache = FileSystemCache::new("record_data/cache/heimdall");
    match cache.load(cache_key.as_str()) {
        Ok(res) => {
            println!("using cached result of decompiling contract");
            return serde_json::from_str(res.as_str()).unwrap();
        }
        Err(_) => {}
    }
    let heimdall_result = decompile_with_bytecode(bytecode, "".to_string());
    let mut result = vec![];
    for heimdall_abi in heimdall_result {
        match heimdall_abi {
            ABIStructure::Function(func) => {
                let mut inputs = vec![];
                for input in func.inputs {
                    let ty = input.type_;
                    if ty == "bytes" {
                        inputs.push("unknown".to_string());
                    } else {
                        inputs.push(ty);
                    }
                }

                let name = func.name.replace("Unresolved_", "");
                let mut abi_config = ABIConfig {
                    abi: format!("({})", inputs.join(",")),
                    function: [0; 4],
                    function_name: name.clone(),
                    is_static: func.state_mutability == "view",
                    is_payable: func.state_mutability == "payable",
                    is_constructor: false,
                };
                abi_config
                    .function
                    .copy_from_slice(hex::decode(name).unwrap().as_slice());
                result.push(abi_config)
            }
            _ => {
                continue;
            }
        }
    }
    FileSystemCache::new("record_data/cache/heimdall").save(
        cache_key.as_str(),
        serde_json::to_string(&result).unwrap().as_str(),
    ).expect("unable to save cache");
    result
}
