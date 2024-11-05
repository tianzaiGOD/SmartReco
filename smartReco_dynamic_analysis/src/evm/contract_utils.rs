use crate::evm::types::{
    fixed_address, generate_random_address, EVMAddress, EVMFuzzState,
};
/// Load contract from file system or remote
use glob::glob;
// use revm::EVM;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::str::FromStr;

// use crate::state::FuzzState;
use itertools::Itertools;
use std::io::Read;
use std::path::Path;
extern crate crypto;

use crate::evm::abi::get_abi_type_boxed_with_address;
use crate::evm::onchain::endpoints::{ContractCreateInfo, OnChainConfig};
use crate::evm::srcmap::parser::{decode_instructions, SourceMapLocation};
use crate::r#const::ZERO_ADDRESS;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
// use hex::encode;
// use regex::Regex;
use serde::{Serialize, Deserialize};
// use crate::evm::onchain::abi_decompiler::fetch_abi_heimdall;
use crate::dapp_utils::{DappInfo, CreatorDapp};

// to use this address, call rand_utils::fixed_address(FIX_DEPLOYER)
pub static FIX_DEPLOYER: &str = "8b21e662154b4bbc1ec0754d0238875fe3d22fa6";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIConfig {
    pub abi: String,
    pub function: [u8; 4],
    pub function_name: String,
    pub is_static: bool,
    pub is_payable: bool,
    pub is_constructor: bool,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub name: String,
    pub code: Vec<u8>,
    pub abi: Vec<ABIConfig>,
    pub is_code_deployed: bool,
    pub constructor_args: Vec<u8>,
    pub deployed_address: EVMAddress,
    pub source_map: Option<HashMap<usize, SourceMapLocation>>,
    pub dapp: String,
    pub creator: EVMAddress,
}

#[derive(Debug, Clone)]
pub struct ABIInfo {
    pub source: String,
    pub abi: Vec<ABIConfig>,
}

#[derive(Debug, Clone)]
pub struct ContractLoader {
    pub contracts: Vec<ContractInfo>,
    pub abis: Vec<ABIInfo>,
}

pub fn set_hash(name: &str, out: &mut [u8]) {
    let mut hasher = Sha3::keccak256();
    hasher.input_str(name);
    hasher.result(out)
}

impl ContractLoader {
    fn parse_abi(path: &Path) -> Vec<ABIConfig> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data)
            .expect("failed to read abis file");
        return Self::parse_abi_str(&data);
    }

    fn process_input(ty: String, input: &Value) -> String {
        if let Some(slot) = input.get("components") {
            if ty == "tuple" {
                let v = slot
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Self::process_input(v["type"].as_str().unwrap().to_string(), v))
                    .collect::<Vec<String>>()
                    .join(",");
                return format!("({})", v);
            } else if ty.ends_with("[]") {
                return format!(
                    "{}[]",
                    Self::process_input(ty[..ty.len() - 2].to_string(), input)
                );
            }
            panic!("unknown type: {}", ty);
        } else {
            ty
        }
    }

    pub fn parse_abi_str(data: &String) -> Vec<ABIConfig> {
        let json: Vec<Value> = serde_json::from_str(&data).expect("failed to parse abis file");
        json.iter()
            .flat_map(|abi| {
                if abi["type"] == "function" || abi["type"] == "constructor" {
                    let name = if abi["type"] == "function" {
                        abi["name"].as_str().expect("failed to parse abis name")
                    } else {
                        "constructor"
                    };
                    let mut abi_name: Vec<String> = vec![];
                    abi["inputs"]
                        .as_array()
                        .expect("failed to parse abis inputs")
                        .iter()
                        .for_each(|input| {
                            abi_name.push(Self::process_input(
                                input["type"].as_str().unwrap().to_string(),
                                input,
                            ));
                        });
                    let mut abi_config = ABIConfig {
                        abi: format!("({})", abi_name.join(",")),
                        function: [0; 4],
                        function_name: name.to_string(),
                        is_static: abi["stateMutability"].as_str().unwrap_or_default() == "view",
                        is_payable: abi["stateMutability"].as_str().unwrap_or_default() == "payable",
                        is_constructor: abi["type"] == "constructor",
                    };
                    let function_to_hash = format!("{}({})", name, abi_name.join(","));
                    // print name and abi_name
                    // println!("{}({})", name, abi_name.join(","));

                    set_hash(function_to_hash.as_str(), &mut abi_config.function);
                    Some(abi_config)
                } else {
                    None
                }
            })
            .collect()
    }

    /// get dapp information based on contract address
    pub fn get_dapp_info(onchain: &mut OnChainConfig, addr: EVMAddress, address_to_dapp: &mut DappInfo) -> CreatorDapp {
        if onchain.is_contract(addr) {
            let contract_creator = Self::get_contract_creator(onchain, addr);
            println!("contract_creator: {}", contract_creator);
            let contract_creator = if contract_creator == "0x" {
                EVMAddress::zero()
            } else {
                EVMAddress::from_str(&contract_creator).unwrap()
            };
            let dapp = match address_to_dapp.search_by_address(contract_creator) {
                Some(name) => name,
                _ => "unknown".to_string()
            };
            CreatorDapp::new(addr, contract_creator, dapp)
        } else {
           CreatorDapp::new(addr, EVMAddress::zero(), "unknown".to_string())
        }
    }

    pub fn get_contract_creator(onchain: &mut OnChainConfig, address: EVMAddress) -> String {
        let mut contract_creat_info = onchain.fetch_tx(address).unwrap();
        let mut txhash = &contract_creat_info.0;
        let mut address = address;
        // ADD: make sure when address is not a contract, just return not_dapp
        for _i in 0..5 {       
            // let txhash_creator = Self::parse_txhash_str(&contract_creat_info.unwrap());
            let to_address = onchain.fetch_creator_data(txhash, address);
            if let Some(to) = to_address {
                address = EVMAddress::from_str(&to).unwrap();
                contract_creat_info = onchain.fetch_tx(address).unwrap();
                txhash = &contract_creat_info.0;
            } else {
                return contract_creat_info.1.clone()
            };
        }
        println!("Error!");
        return "not Dapp".to_string();
    }

    fn parse_hex_file(path: &Path) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        hex::decode(data).expect("Failed to parse hex file")
    }

    fn constructor_args_encode(constructor_args: &Vec<String>) -> Vec<u8> {
        constructor_args
            .iter()
            .flat_map(|arg| {
                let arg = if arg.starts_with("0x") {
                    &arg[2..]
                } else {
                    arg
                };
                let arg = if arg.len() % 2 == 1 {
                    format!("0{}", arg)
                } else {
                    arg.to_string()
                };
                let mut decoded = hex::decode(arg).unwrap();
                let len = decoded.len();
                if len < 32 {
                    let mut padding = vec![0; 32 - len]; // Create a vector of zeros
                    padding.append(&mut decoded); // Append the original vector to it
                    padding
                } else {
                    decoded
                }
            })
            .collect()
    }

    pub fn from_prefix(
        prefix: &str,
        state: &mut EVMFuzzState,
        source_map_info: Option<ContractsSourceMapInfo>,
        proxy_deploy_codes: &Vec<String>,
        constructor_args: &Vec<String>,
    ) -> Self {
        let contract_name = prefix.split("/").last().unwrap().replace("*", "");

        // get constructor args
        let constructor_args_in_bytes: Vec<u8> = Self::constructor_args_encode(constructor_args);

        // create dummy contract info
        let mut contract_result = ContractInfo {
            name: prefix.to_string(),
            code: vec![],
            abi: vec![],
            is_code_deployed: false,
            constructor_args: constructor_args_in_bytes,
            deployed_address: generate_random_address(state),
            source_map: source_map_info.map(|info| {
                info.get(contract_name.as_str())
                    .expect(format!("combined.json provided but contract ({:?}) not found", contract_name).as_str())
                    .clone()
            }),
            dapp: "unknown".to_string(),
            creator: EVMAddress::from_str(ZERO_ADDRESS).unwrap(),
        };
        let mut abi_result = ABIInfo {
            source: prefix.to_string(),
            abi: vec![],
        };

        println!("Loading contract {}", prefix);

        // Load contract, ABI, and address from file
        for i in glob(prefix).expect("not such path for prefix") {
            match i {
                Ok(path) => {
                    if path.to_str().unwrap().ends_with(".abi") {
                        // this is an ABI file
                        abi_result.abi = Self::parse_abi(&path);
                        contract_result.abi = abi_result.abi.clone();
                        // println!("ABI: {:?}", result.abis);
                    } else if path.to_str().unwrap().ends_with(".bin") {
                        // this is an BIN file
                        contract_result.code = Self::parse_hex_file(&path);
                    } else if path.to_str().unwrap().ends_with(".address") {
                        // this is deployed address
                        contract_result
                            .deployed_address
                            .0
                            .clone_from_slice(Self::parse_hex_file(&path).as_slice());
                    } else {
                        println!("Found unknown file: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }

        if let Some(abi) = abi_result.abi.iter().find(|abi| abi.is_constructor) {
            let mut abi_instance =
                get_abi_type_boxed_with_address(&abi.abi, fixed_address(FIX_DEPLOYER).0.to_vec());
            abi_instance.set_func_with_name(abi.function, abi.function_name.clone());
            if contract_result.constructor_args.len() == 0 {
                println!("No constructor args found, using default constructor args");
                contract_result.constructor_args = abi_instance.get().get_bytes();
            }
            // println!("Constructor args: {:?}", result.constructor_args);
            contract_result.code.extend(contract_result.constructor_args.clone());
        } else {
            println!("No constructor in ABI found, skipping");
        }

        // now check if contract is deployed through proxy by checking function signatures
        // if it is, then we use the new bytecode from proxy
        let current_code = hex::encode(&contract_result.code);
        for deployed_code in proxy_deploy_codes {
            // if deploy_code startwiths '0x' then remove it
            let deployed_code_cleaned = if deployed_code.starts_with("0x") {
                &deployed_code[2..]
            } else {
                deployed_code
            };

            // match all function signatures, compare sigs between our code and deployed code from proxy
            let deployed_code_sig: Vec<[u8;4]> = extract_sig_from_contract(deployed_code_cleaned);
            let current_code_sig: Vec<[u8;4]> = extract_sig_from_contract(&current_code);

            // compare deployed_code_sig and current_code_sig
            if deployed_code_sig.len() == current_code_sig.len() {
                let mut is_match = true;
                for i in 0..deployed_code_sig.len() {
                    if deployed_code_sig[i] != current_code_sig[i] {
                        is_match = false;
                        break;
                    }
                }
                if is_match {
                    contract_result.code = hex::decode(deployed_code_cleaned)
                        .expect("Failed to parse deploy code");
                }
            }
        }
        return Self {
            contracts: if contract_result.code.len() > 0 {
                vec![contract_result]
            } else {
                vec![]
            },
            abis: vec![abi_result],
        };
    }

    pub fn from_address(onchain: &mut OnChainConfig, address: HashSet<EVMAddress>, address_to_dapp: &mut DappInfo) -> Self {
        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];
        for addr in address {
            // let abi = onchain.fetch_abi(addr);
            let contract_code = onchain.get_contract_code(addr, false);
            
            let dapp_info = Self::get_dapp_info(onchain, addr, address_to_dapp);
            
            contracts.push(ContractInfo {
                name: addr.to_string(),
                code: contract_code.bytes().to_vec(),
                abi: vec![],
                is_code_deployed: true,
                constructor_args: vec![], // todo: fill this
                deployed_address: addr,
                source_map: None,
                dapp: dapp_info.dapp,
                creator: dapp_info.creator,
            });
            abis.push(ABIInfo {
                source: addr.to_string(),
                abi: vec![],
            });
        }
        Self { contracts, abis }
    }
}

// type ContractSourceMap = HashMap<usize, SourceMapLocation>;
type ContractsSourceMapInfo = HashMap<String, HashMap<usize, SourceMapLocation>>;

pub fn parse_combined_json(json: String) -> ContractsSourceMapInfo {
    let map_json = serde_json::from_str::<serde_json::Value>(&json).unwrap();

    let contracts = map_json["contracts"]
        .as_object()
        .expect("contracts not found");
    let file_list = map_json["sourceList"]
        .as_array()
        .expect("sourceList not found")
        .iter()
        .map(|x| x.as_str().expect("sourceList is not string").to_string())
        .collect::<Vec<String>>();

    let mut result = ContractsSourceMapInfo::new();

    for (contract_name, contract_info) in contracts {
        let splitter = contract_name.split(':').collect::<Vec<&str>>();
        let file_name = splitter.iter().take(splitter.len() - 1).join(":");
        let contract_name = splitter.last().unwrap().to_string();

        let bin_runtime = contract_info["bin-runtime"]
            .as_str()
            .expect("bin-runtime not found");
        let bin_runtime_bytes = hex::decode(bin_runtime).expect("bin-runtime is not hex");

        let srcmap_runtime = contract_info["srcmap-runtime"]
            .as_str()
            .expect("srcmap-runtime not found");

        result.insert(
            contract_name.clone(),
            decode_instructions(bin_runtime_bytes, srcmap_runtime.to_string(), &file_list),
        );
    }
    result
}

pub fn extract_sig_from_contract(code: &str) -> Vec<[u8;4]> {
    let mut i = 0;
    let bytes = hex::decode(code).expect("failed to decode contract code");
    let mut code_sig = vec![];

    while i < bytes.len() {
        let op = *bytes.get(i).unwrap();
        i += 1;

        // PUSH4
        if op == 0x63 {
            // peak forward

            // ensure we have enough bytes
            if i + 4 + 2 >= bytes.len() {
                break;
            }

            // Solidity: check whether next ops is EQ
            // Vyper: check whether next 2 ops contain XOR
            if bytes[i + 4] == 0x14 || bytes[i + 5] == 0x18 || bytes[i + 4] == 0x18 {
                let mut sig_bytes = vec![];
                for j in 0..4 {
                    sig_bytes.push(*bytes.get(i + j).unwrap());
                }
                code_sig.push(sig_bytes.try_into().unwrap());
            }
        }
        /// skip off the PUSH XXXxxxxxxXXX instruction
        if op >= 0x60 && op <= 0x7f {
            i += op as usize - 0x5f;
            continue;
        }
    }
    code_sig
}

