/// Configuration for the EVM fuzzer
use crate::evm::contract_utils::{ContractInfo, ContractLoader};
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
}

pub enum StorageFetchingMode {
    Dump,
    All,
    OneByOne,
}

impl StorageFetchingMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dump" => Some(StorageFetchingMode::Dump),
            "all" => Some(StorageFetchingMode::All),
            "onebyone" => Some(StorageFetchingMode::OneByOne),
            _ => None,
        }
    }
}

impl FuzzerTypes {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "cmp" => Ok(FuzzerTypes::CMP),
            "dataflow" => Ok(FuzzerTypes::DATAFLOW),
            "basic" => Ok(FuzzerTypes::BASIC),
            _ => Err(format!("Unknown fuzzer type: {}", s)),
        }
    }
}

pub struct Config {
    pub onchain: Option<OnChainConfig>,
    pub onchain_storage_fetching: Option<StorageFetchingMode>,
    pub fuzzer_type: FuzzerTypes,
    pub contract_loader: ContractLoader, 
    pub work_dir: String,
    pub base_path: String,
    pub spec_id: String,
    pub related_function_signature: String,
    pub related_function_name: String,
    pub is_verified: bool,
}

pub struct ReplayConfig {
    pub onchain: Option<OnChainConfig>,
    pub onchain_storage_fetching: Option<StorageFetchingMode>,
    pub contract_loader: ContractLoader, 
    pub work_dir: String,
    pub write_relationship: bool,
    pub base_path: String,

    pub spec_id: String,
}
