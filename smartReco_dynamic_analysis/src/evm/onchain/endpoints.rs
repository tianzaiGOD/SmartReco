use crate::cache::{Cache, FileSystemCache};
use bytes::Bytes;
use reqwest::header::HeaderMap;
use retry::OperationResult;
use retry::{delay::Fixed, retry_with_index};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fmt::{Debug, format};
use std::panic;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use revm_interpreter::analysis::to_analysed;
use revm_primitives::{Bytecode, LatestSpec};
use crate::evm::types::{EVMAddress, EVMU256};

const MAX_HOPS: u32 = 2; // Assuming the value of MAX_HOPS

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub enum Chain {
    ETH,
    GOERLI,
    SEPOLIA,
    BSC,
    CHAPEL,
    POLYGON,
    MUMBAI,
    FANTOM,
    AVALANCHE,
    OPTIMISM,
    ARBITRUM,
    GNOSIS,
    BASE,
    CELO,
    ZKEVM,
    ZKEVM_TESTNET,
    LOCAL,
}

pub trait PriceOracle: Debug {
    // ret0: price = int(original_price x 10^5)
    // ret1: decimals of the token
    fn fetch_token_price(&mut self, token_address: EVMAddress) -> Option<(u32, u32)>;
}

impl Chain {
    pub fn from_str(s: &String) -> Option<Self> {
        match s.as_str() {
            "ETH" | "eth" => Some(Self::ETH),
            "GOERLI" | "goerli" => Some(Self::GOERLI),
            "SEPOLIA" | "sepolia" => Some(Self::SEPOLIA),
            "BSC" | "bsc" => Some(Self::BSC),
            "CHAPEL" | "chapel" => Some(Self::CHAPEL),
            "POLYGON" | "polygon" => Some(Self::POLYGON),
            "MUMBAI" | "mumbai" => Some(Self::MUMBAI),
            "FANTOM" | "fantom" => Some(Self::FANTOM),
            "AVALANCHE" | "avalanche" => Some(Self::AVALANCHE),
            "OPTIMISM" | "optimism" => Some(Self::OPTIMISM),
            "ARBITRUM" | "arbitrum" => Some(Self::ARBITRUM),
            "GNOSIS" | "gnosis" => Some(Self::GNOSIS),
            "BASE" | "base" => Some(Self::BASE),
            "CELO" | "celo" => Some(Self::CELO),
            "ZKEVM" | "zkevm" => Some(Self::ZKEVM),
            "ZKEVM_TESTNET" | "zkevm_testnet" => Some(Self::ZKEVM_TESTNET),
            "LOCAL" | "local" => Some(Self::LOCAL),
            _ => None,
        }
    }

    pub fn get_chain_id(&self) -> u32 {
        match self {
            Chain::ETH => 1,
            Chain::GOERLI => 5,
            Chain::SEPOLIA => 11155111,
            Chain::BSC => 56,
            Chain::CHAPEL => 97,
            Chain::POLYGON => 137,
            Chain::MUMBAI => 80001,
            Chain::FANTOM => 250,
            Chain::AVALANCHE => 43114,
            Chain::OPTIMISM => 10,
            Chain::ARBITRUM => 42161,
            Chain::GNOSIS => 100,
            Chain::BASE => 8453,
            Chain::CELO => 42220,
            Chain::ZKEVM => 1101,
            Chain::ZKEVM_TESTNET => 1442,
            Chain::LOCAL => 31337,
        }
    }

    pub fn to_lowercase(&self) -> String {
        match self {
            Chain::ETH => "eth",
            Chain::GOERLI => "goerli",
            Chain::SEPOLIA => "sepolia",
            Chain::BSC => "bsc",
            Chain::CHAPEL => "chapel",
            Chain::POLYGON => "polygon",
            Chain::MUMBAI => "mumbai",
            Chain::FANTOM => "fantom",
            Chain::AVALANCHE => "avalanche",
            Chain::OPTIMISM => "optimism",
            Chain::ARBITRUM => "arbitrum",
            Chain::GNOSIS => "gnosis",
            Chain::BASE => "base",
            Chain::CELO => "celo",
            Chain::ZKEVM => "zkevm",
            Chain::ZKEVM_TESTNET => "zkevm_testnet",
            Chain::LOCAL => "local",
        }
        .to_string()
    }

    pub fn get_chain_rpc(&self) -> String {
        match self {
            Chain::ETH => "https://eth.llamarpc.com",
            Chain::GOERLI => "https://rpc.ankr.com/eth_goerli",
            Chain::SEPOLIA => "https://rpc.ankr.com/eth_sepolia",
            Chain::BSC => "https://rpc.ankr.com/bsc",
            Chain::CHAPEL => "https://rpc.ankr.com/bsc_testnet_chapel",
            Chain::POLYGON => "https://polygon.llamarpc.com",
            Chain::MUMBAI => "https://rpc-mumbai.maticvigil.com/",
            Chain::FANTOM => "https://rpc.ankr.com/fantom",
            Chain::AVALANCHE => "https://rpc.ankr.com/avalanche",
            Chain::OPTIMISM => "https://rpc.ankr.com/optimism",
            Chain::ARBITRUM => "https://rpc.ankr.com/arbitrum",
            Chain::GNOSIS => "https://rpc.ankr.com/gnosis",
            Chain::BASE => "https://developer-access-mainnet.base.org",
            Chain::CELO => "https://rpc.ankr.com/celo",
            Chain::ZKEVM => "https://rpc.ankr.com/polygon_zkevm",
            Chain::ZKEVM_TESTNET => "https://rpc.ankr.com/polygon_zkevm_testnet",
            Chain::LOCAL => "http://localhost:8545",
        }
        .to_string()
    }

    pub fn get_chain_etherscan_base(&self) -> String {
        match self {
            Chain::ETH => "https://api.etherscan.io/api",
            Chain::GOERLI => "https://api-goerli.etherscan.io/api",
            Chain::SEPOLIA => "https://api-sepolia.etherscan.io/api",
            Chain::BSC => "https://api.bscscan.com/api",
            Chain::CHAPEL => "https://api-testnet.bscscan.com/api",
            Chain::POLYGON => "https://api.polygonscan.com/api",
            Chain::MUMBAI => "https://mumbai.polygonscan.com/api",
            Chain::FANTOM => "https://api.ftmscan.com/api",
            Chain::AVALANCHE => "https://api.snowtrace.io/api",
            Chain::OPTIMISM => "https://api-optimistic.etherscan.io/api",
            Chain::ARBITRUM => "https://api.arbiscan.io/api",
            Chain::GNOSIS => "https://api.gnosisscan.io/api",
            Chain::BASE => "https://api.basescan.org/api",
            Chain::CELO => "https://api.celoscan.io/api",
            Chain::ZKEVM => "https://api-zkevm.polygonscan.com/api",
            Chain::ZKEVM_TESTNET => "https://api-testnet-zkevm.polygonscan.com/api",
            Chain::LOCAL => "http://localhost:8080/abi/",
        }
        .to_string()
    }
}

#[derive(Deserialize)]
pub struct GetPairResponse {
    pub data: GetPairResponseData,
}

#[derive(Deserialize)]
pub struct GetPairResponseData {
    pub p0: Vec<GetPairResponseDataPair>,
    pub p1: Vec<GetPairResponseDataPair>,
}

#[derive(Deserialize)]
pub struct GetPairResponseDataPair {
    pub id: String,
    pub token0: GetPairResponseDataPairToken,
    pub token1: GetPairResponseDataPairToken,
}

#[derive(Deserialize)]
pub struct GetPairResponseDataPairToken {
    pub decimals: String,
    pub id: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContractCreateInfo {
    pub contractAddress: String,
    pub contractCreator: String,
    pub txHash: String,
}

#[derive(Serialize, Deserialize)]
struct Response {
    status: String,
    message: String,
    result: Vec<ContractCreateInfo>,
}

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub blockNumber: String,
    pub timeStamp: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub contractAddress: String,
    pub input: String,
    pub r#type: String,
    pub gas: String,
    pub gasUsed: String,
    pub isError: String,
    pub errCode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxRes {
    pub jsonrpc: String,
    pub id: u32,
    pub result: TxResDetail,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxResDetail {
    pub blockNumber: String,
    pub from: String,
    pub gas: String,
    pub gasPrice: String,
    pub maxFeePerGas: Option<String>,
    pub maxPriorityFeePerGas: Option<String>,
    pub hash: String,
    pub input: String,
    pub nonce: String,
    pub to: Option<String>,
    pub transactionIndex: String,
    pub value: String,
    #[serde(rename = "type")]
    pub tx_type: String,
    // accessList: Option<Vec<String>>,
    pub chainId: String,
    pub v: String,
    pub r: String,
    pub s: String,
}
#[derive(Serialize, Deserialize)]
struct IsContractRes {
    jsonrpc: String,
    id: String,
    result: String,
}

#[derive(Clone, Debug)]
pub struct OnChainConfig {
    pub endpoint_url: String,
    // pub cache_len: usize,
    //
    // code_cache: HashMap<EVMAddress, Bytecode>,
    // slot_cache: HashMap<(EVMAddress, EVMU256), EVMU256>,
    pub client: reqwest::blocking::Client,
    pub chain_id: u32,
    pub block_number: String, // 0x123456
    pub block_hash: Option<String>,

    pub etherscan_api_key: Vec<String>,
    pub etherscan_base: String,
    pub local_etherscan_base: String,
    pub timestamp: String,
    pub chain_name: String,

    slot_cache: HashMap<(EVMAddress, EVMU256), EVMU256>,
    code_cache: HashMap<EVMAddress, Bytecode>,
    // price_cache: HashMap<EVMAddress, Option<(u32, u32)>>,
    abi_cache: HashMap<EVMAddress, Option<String>>,
    storage_all_cache: HashMap<EVMAddress, Option<Arc<HashMap<String, EVMU256>>>>,
    storage_dump_cache: HashMap<EVMAddress, Option<Arc<HashMap<EVMU256, EVMU256>>>>,
    // uniswap_path_cache: HashMap<EVMAddress, TokenContext>,
    rpc_cache: FileSystemCache,
    creator_cache: HashMap<(String, EVMAddress), Option<String>>,
    /// HashMap<contract_address, (txhash, from)>
    tx_cache: HashMap<EVMAddress, Option<(String, String)>>, 
    is_contract_cache: HashMap<EVMAddress, bool>,
}

impl OnChainConfig {
    pub fn new(chain: Chain, block_number: u64, timestamp: u64) -> Self {
        Self::new_raw(
            chain.get_chain_rpc(),
            chain.get_chain_id(),
            block_number,
            timestamp,
            chain.get_chain_etherscan_base(),
            chain.to_lowercase(),
        )
    }

    pub fn new_raw(
        endpoint_url: String,
        chain_id: u32,
        block_number: u64,
        timestamp: u64,
        etherscan_base: String,
        chain_name: String,
    ) -> Self {
        Self {
            endpoint_url,
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .expect("build client failed"),
            chain_id,
            block_number: if block_number == 0 {
                "latest".to_string()
            } else {
                format!("0x{:x}", block_number)
            },
            block_hash: None,
            etherscan_api_key: vec![],
            etherscan_base,
            local_etherscan_base: "http://127.0.0.1:5003".to_string(),
            chain_name: chain_name,
            slot_cache: Default::default(),
            code_cache: Default::default(),
            // price_cache: Default::default(),
            abi_cache: Default::default(),

            storage_all_cache: Default::default(),
            storage_dump_cache: Default::default(),
            // uniswap_path_cache: Default::default(),
            rpc_cache: FileSystemCache::new("record_data/cache"),
            creator_cache: Default::default(),
            tx_cache: Default::default(),
            is_contract_cache: Default::default(),
            timestamp: format!("0x{:x}", timestamp),
        }
    }

    fn get(&self, url: String, file_name: String, address: EVMAddress) -> Option<String> {
        let path = format!("record_data/cache/{:?}", address).to_lowercase();
        if !fs::metadata(&path).is_ok() {
            fs::create_dir_all(&path).expect("Failed to create directory");
        };
        match self.rpc_cache.load(&file_name) {
            Ok(t) => {
                if !t.is_empty() && !t.contains("error") {
                    return Some(t);
                }
            }
            Err(_) => {}
        }
        match retry_with_index(Fixed::from_millis(1000), |current_try| {
            if current_try > 5 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self
                .client
                .get(url.to_string())
                // .header("Content-Type", "application/json")
                .headers(get_header())
                .send()
            {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => {
                            if t.contains("Max rate limit reached") {
                                println!("Etherscan max rate limit reached, retrying...");
                                return OperationResult::Retry("Rate limit reached".to_string());
                            } else {
                                return OperationResult::Ok(t);
                            }
                        }
                        Err(e) => {
                            println!("{:?}", e);
                            return OperationResult::Retry("failed to parse response".to_string());
                        }
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return OperationResult::Retry("failed to send request".to_string());
                }
            }
        }) {
            Ok(t) => {
                if !t.contains("error") {
                    self.rpc_cache.save(&file_name.as_str(), t.as_str()).unwrap();
                }

                Some(t)
            }
            Err(e) => {
                println!("Error: {}", e);
                None
            }
        }
    }

    fn post(&self, url: String, data: String, file_name: String, path: String) -> Option<String> {
        if !fs::metadata(&path.to_lowercase()).is_ok() {
            fs::create_dir_all(&path).expect("Failed to create directory");
        };
        match self.rpc_cache.load(&file_name.as_str()) {
            Ok(t) => {
                return Some(t);
            }
            Err(_) => {}
        }
        match retry_with_index(Fixed::from_millis(100), |current_try| {
            if current_try > 3 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self
                .client
                .post(url.to_string())
                .header("Content-Type", "application/json")
                .headers(get_header())
                .body(data.to_string())
                .send()
            {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => {
                            return OperationResult::Ok(t);
                        }
                        Err(e) => {
                            println!("{:?}", e);
                            return OperationResult::Retry("failed to parse response".to_string());
                        }
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return OperationResult::Retry("failed to send request".to_string());
                }
            }
        }) {
            Ok(t) => {
                if !t.contains("error") {
                    self.rpc_cache.save(&file_name.as_str(), t.as_str()).unwrap();
                }
                Some(t)
            }
            Err(e) => {
                println!("Error: {}", e);
                None
            }
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn fetch_storage_all(&mut self, address: EVMAddress) -> Option<Arc<HashMap<String, EVMU256>>> {
        if let Some(storage) = self.storage_all_cache.get(&address) {
            return storage.clone();
        } else {
            let storage = self.fetch_storage_all_uncached(address);
            self.storage_all_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_all_uncached(&self, address: EVMAddress) -> Option<Arc<HashMap<String, EVMU256>>> {
        assert_eq!(
            self.block_number, "latest",
            "fetch_full_storage only works with latest block"
        );
        let target_path = format!("{:?}/{:}", address, self.block_number);
        let path = format!("record_data/cache/{:}", target_path);
        let file_name = format!("{:}/storage_all_{}_{:}", target_path, self.chain_name, address);
        let resp = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push_str("]");
            self._request("eth_getStorageAll".to_string(), params, file_name, path)
        };

        match resp {
            Some(resp) => {
                let mut map = HashMap::new();
                for (k, v) in resp.as_object()
                    .expect("failed to convert resp to array, are you using a node that supports eth_getStorageAll?")
                    .iter()
                {
                    map.insert(
                        k.trim_start_matches("0x").to_string(),
                        EVMU256::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
                    );
                }
                Some(Arc::new(map))
            }
            None => None,
        }
    }

    pub fn fetch_blk_hash(&mut self) -> &String {
        if self.block_hash == None {
            let target_path = format!("block_hash/{:}", self.block_number);
            let path = format!("record_data/cache/{:}", target_path);
            let file_name = format!("{:}/{}_{:}", target_path, self.chain_name, self.block_number);

            self.block_hash = {
                let mut params = String::from("[");
                params.push_str(&format!("\"0x{}\",false", self.block_number));
                params.push_str("]");
                let res = self._request("eth_getBlockByNumber".to_string(), params, file_name, path);
                match res {
                    Some(res) => {
                        let blk_hash = res["hash"]
                            .as_str()
                            .expect("fail to find block hash")
                            .to_string();
                        Some(blk_hash)
                    }
                    None => panic!("fail to get block hash"),
                }
            }
        }
        return self.block_hash.as_ref().unwrap();
    }

    pub fn fetch_storage_dump(&mut self, address: EVMAddress) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        if let Some(storage) = self.storage_dump_cache.get(&address) {
            return storage.clone();
        } else {
            let storage = self.fetch_storage_dump_uncached(address);
            self.storage_dump_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_dump_uncached(
        &mut self,
        address: EVMAddress,
    ) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        let resp = {
            let blk_hash = self.fetch_blk_hash().clone();
            let target_path = format!("{:?}/{:?}", address, blk_hash);
            let path = format!("record_data/cache/{:}", target_path);
            let file_name = format!("{:}/storage_dump_{}_{:}", target_path, self.chain_name, address);
            let mut params = String::from("[");
            params.push_str(&format!("\"{}\",", blk_hash));
            params.push_str("0,");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str("\"\",");
            params.push_str(&format!("1000000000000000"));
            params.push_str("]");
            self._request("debug_storageRangeAt".to_string(), params, file_name, path)
        };

        match resp {
            Some(resp) => {
                let mut map = HashMap::new();
                let kvs = resp["storage"]
                    .as_object()
                    .expect("failed to convert resp to array");
                if kvs.len() == 0 {
                    return None;
                }
                for (_, v) in kvs.iter() {
                    let key = v["key"].as_str().expect("fail to find key");
                    let value = v["value"].as_str().expect("fail to find value");

                    map.insert(
                        EVMU256::from_str_radix(key.trim_start_matches("0x"), 16).unwrap(),
                        EVMU256::from_str_radix(value.trim_start_matches("0x"), 16).unwrap(),
                    );
                }
                Some(Arc::new(map))
            }
            None => None,
        }
    }

    pub fn fetch_abi_uncached(&self, address: EVMAddress) -> Option<String> {
        let endpoint = format!(
            "{}/abi/{}/{:?}/{}",
            self.local_etherscan_base, self.chain_name, address, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
        );
        let file_name = format!("{:?}/abi_{}_{:?}", address, self.chain_name, address);
        println!("fetching abi from {}", endpoint);
        match self.get(endpoint.clone(), file_name, address) {
            Some(resp) => {
                let json = serde_json::from_str::<Value>(&resp);
                match json {
                    Ok(json) => {
                        let result_parsed = json["result"].as_str();
                        match result_parsed {
                            Some(result) => {
                                if result == "Contract source code not verified" {
                                    None
                                } else {
                                    Some(result.to_string())
                                }
                            }
                            _ => None,
                        }
                    }
                    Err(_) => None,
                }
            }
            None => {
                println!("failed to fetch abi from {}", endpoint);
                return None;
            }
        }
    }

    pub fn fetch_abi(&mut self, address: EVMAddress) -> Option<String> {
        if self.abi_cache.contains_key(&address) {
            return self.abi_cache.get(&address).unwrap().clone();
        }
        let abi = self.fetch_abi_uncached(address);
        self.abi_cache.insert(address, abi.clone());
        abi
    }

    pub fn fetch_creator_data(&mut self, tx_hash: &str, address: EVMAddress) -> Option<String> {
        if self.creator_cache.contains_key(&(tx_hash.to_string(), address)) {
            return self.creator_cache.get(&(tx_hash.to_string(), address)).unwrap().clone();
        }
        let creator = match self.fetch_creator_data_uncache(tx_hash, address) {
            Some(tx) => {
                Some(tx.from)
            },
            None => None,
        };
        self.creator_cache.insert((tx_hash.to_string(), address), creator.clone());
        creator
    }

    pub fn fetch_creator_data_uncache(&self, tx_hash: &str, address: EVMAddress) -> Option<Transaction>{
        let endpoint = format!(
            "{}/creator/{}/{:}/{}",
            self.local_etherscan_base, self.chain_name, tx_hash, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
        );
        let file_name = format!("{:?}/{}_internal_tx_of_{}", address, self.chain_name, tx_hash);
        println!("verify contract creator");
        match self.get(endpoint.clone(), file_name, address) {
            Some(resp) => {

                let data: Value = serde_json::from_str(&resp).unwrap();
                let result = data["result"].as_array();

                if let Some(result_array) = result {
                    if !result_array.is_empty() {
                        let mut res = None;
                        for item in result_array {
                            let transaction: Transaction = serde_json::from_value(item.clone()).unwrap();
                            if (transaction.r#type =="create" || transaction.r#type =="create2") && EVMAddress::from_str(&transaction.contractAddress).unwrap() == address {
                                res = Some(transaction);
                                break;
                            }
                            // println!("{:?}", transaction);
                        }
                        return res;
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            None => {
                println!("failed to check transaction");
                return None;
            }
        }
    }

    /// EVMAddress -> Some((txHash, from))
    pub fn fetch_tx(&mut self, address: EVMAddress) -> Option<(String, String)> {
        if self.tx_cache.contains_key(&address) {
            return self.tx_cache.get(&address).unwrap().clone();
        }
        let tx_data = match self.fetch_tx_uncached(address) {
            Some(data) => Some((data[0].txHash.clone(), data[0].contractCreator.clone())),
            _ => Some(("0x".to_string(), "0x".to_string()))
        };
        self.tx_cache.insert(address, tx_data.clone());
        tx_data
    }

    pub fn fetch_tx_uncached(&self, address: EVMAddress) -> Option<Vec<ContractCreateInfo>> {
        let endpoint = format!(
            "{}/tx/{}/{:?}/{}",
            self.local_etherscan_base, self.chain_name, address, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
        );
        
        let file_name = format!("{:?}/create_tx_{}_{:?}", address, self.chain_name, address);
        println!("fetching contract creator for {} from {}", hex::encode(address), endpoint);
        match self.get(endpoint.clone(), file_name, address) {
            Some(resp) => {
                let json: Result<Response, serde_json::Error> = serde_json::from_str(&resp);
                match json {
                    Ok(json) => {
                        Some(json.result)
                    }
                    Err(_) => {
                        println!("{:?} is not a contract!", address);
                        return None
                    },
                }
            }
            None => {
                println!("failed to fetch creator from {}", endpoint);
                return None;
            }
        }
    }

    /// Verify given address is an EOA or not
    pub fn is_contract(&mut self, address: EVMAddress) -> bool {
        if self.is_contract_cache.contains_key(&address) {
            return self.is_contract_cache.get(&address).unwrap().clone();
        }
        let is_contract = self.is_contract_uncached(address);
        self.is_contract_cache.insert(address, is_contract);
        is_contract
    }
    
    pub fn is_contract_uncached(&self, address: EVMAddress) -> bool {
        let target_path = format!("{:?}", address);
        let path = format!("record_data/cache/{:}", target_path);
        let file_name = format!("{:}/code_{}_{:?}", target_path, self.chain_name, address);
        let res = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"latest\""));
            params.push_str("]");
            let endpoint = format!(
                "{}/bytecode/{}/{:?}/latest/{}",
                self.local_etherscan_base, self.chain_name, address, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
            );
            self.get(endpoint, file_name, address).unwrap()
            // self._request("eth_getCode".to_string(), params, file_name, path)
        };
        let res = if res.contains("jsonrpc") {
            // let resp = self._request("eth_getCode".to_string(), params, file_name, path);
            let json: Result<Value, _> = serde_json::from_str(&res);

            let res = match json {
                Ok(json) => {
                    json.get("result").cloned()
                }
                Err(e) => {
                    println!("{:?}", e);
                    None
                }
            };
            match res {
                Some(resp) => {
                    resp.as_str().unwrap().to_string()
                    
                }
                None => "".to_string(),
            }
        } else {res};

        if res == "0x" {
            return false
        } else {
            return true
        }
    }

    fn _request(&self, method: String, params: String, file_name: String, path: String) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, self.chain_id
        );

        match self.post(self.endpoint_url.clone(), data, file_name, path) {
            Some(resp) => {
                let json: Result<Value, _> = serde_json::from_str(&resp);

                match json {
                    Ok(json) => {
                        return json.get("result").cloned();
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        return None;
                    }
                }
            }

            None => {
                println!("failed to fetch from {}", self.endpoint_url);
                return None;
            }
        }
    }

    pub fn get_contract_code(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode {
        if self.code_cache.contains_key(&address) {
            return self.code_cache[&address].clone();
        }
        if force_cache {
            return Bytecode::default();
        }
        println!("fetching code from {}", hex::encode(address));

        let target_path = format!("{:?}", address);
        let path = format!("record_data/cache/{:}", target_path);
        let file_name = format!("{:}/code_{}_{:?}", target_path, self.chain_name, address);

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", "latest"));
            params.push_str("]");
            let endpoint = format!(
                "{}/bytecode/{}/{:?}/latest/{}",
                self.local_etherscan_base, self.chain_name, address, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
            );
            let resp = self.get(endpoint, file_name, address).unwrap();
            let resp = if resp.contains("jsonrpc") {
                // let resp = self._request("eth_getCode".to_string(), params, file_name, path);
                let json: Result<Value, _> = serde_json::from_str(&resp);

                let res = match json {
                    Ok(json) => {
                        json.get("result").cloned()
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                };
                match res {
                    Some(resp) => {
                        resp.as_str().unwrap().to_string()
                        
                    }
                    None => "".to_string(),
                }
            } else {resp};
            
            resp
        };
        let code = resp_string.trim_start_matches("0x");
        if code.len() == 0 {
            self.is_contract_cache.insert(address, false);
            self.code_cache.insert(address, Bytecode::new());
            return Bytecode::new();
        } else {
            self.is_contract_cache.insert(address, true);
        }
        let code = hex::decode(code).unwrap();
        let bytes = to_analysed(Bytecode::new_raw(Bytes::from(code)));
        self.code_cache.insert(address, bytes.clone());
        return bytes;
    }

    pub fn get_contract_balance(&mut self, address: EVMAddress, block_number: String,) -> EVMU256 {

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", block_number));
            params.push_str("]");

            let target_path = format!("{:?}/balance/{:}", address, block_number);

            let path = format!("record_data/cache/{:}/balance", target_path);
            if !fs::metadata(&path.to_lowercase()).is_ok() {
                fs::create_dir_all(&path).expect("Failed to create directory");
            };
            let file_name = format!("{:}/balance_{}_{:?}", target_path, self.chain_name, address);

            let endpoint = format!(
                "{}/balance/{}/{:?}/{}/{}",
                self.local_etherscan_base, self.chain_name, address, block_number, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
            );
            let resp = self.get(endpoint, file_name, address).unwrap();
            let resp = if resp.contains("jsonrpc") {
                let json: Result<Value, _> = serde_json::from_str(&resp);

                let res = match json {
                    Ok(json) => {
                        json.get("result").cloned()
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                };
                match res {
                    Some(resp) => {
                        resp.as_str().unwrap().to_string()
                        
                    }
                    None => "".to_string(),
                }
            } else {resp};
            
            resp
        };
        let balance_suffix = resp_string.trim_start_matches("0x");
        let balance_suffix =  if balance_suffix.len() % 2 != 0 {
            format!("0{}", balance_suffix)
        } else {
            balance_suffix.to_string()
        };
        let balance_value: EVMU256 = EVMU256::try_from_be_slice(&hex::decode(balance_suffix).unwrap()).unwrap();
        return balance_value;
    }
    
    pub fn get_contract_slot(&mut self, address: EVMAddress, slot: EVMU256, block_number: String, force_cache: bool) -> EVMU256 {
        if self.slot_cache.contains_key(&(address, slot)) {
            return self.slot_cache[&(address, slot)];
        }
        if force_cache {
            return EVMU256::ZERO;
        }
        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"0x{:x}\",", slot));
            params.push_str(&format!("\"{}\"", block_number));
            params.push_str("]");

            let target_path = format!("{:?}/slot/{:}", address, block_number);

            let path = format!("record_data/cache/{:}/slot", target_path);
            if !fs::metadata(&path.to_lowercase()).is_ok() {
                fs::create_dir_all(&path).expect("Failed to create directory");
            };
            let file_name = format!("{:}/slot_{}_{:x}", target_path, self.chain_name, slot);
            let endpoint = format!(
                "{}/slot/{}/{:?}/0x{:x}/{}/{}",
                self.local_etherscan_base, self.chain_name, address, slot, block_number, self.etherscan_api_key[rand::thread_rng().gen_range(0..self.etherscan_api_key.len())]
            );
            let resp = self.get(endpoint, file_name, address).unwrap();
            // let resp = self._request("eth_getStorageAt".to_string(), params, file_name, path);
            let resp = if resp.contains("jsonrpc") {
                // let resp = self._request("eth_getCode".to_string(), params, file_name, path);
                let json: Result<Value, _> = serde_json::from_str(&resp);

                let res = match json {
                    Ok(json) => {
                        json.get("result").cloned()
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                };
                match res {
                    Some(resp) => {
                        resp.as_str().unwrap().to_string()
                        
                    }
                    None => "".to_string(),
                }
            } else {resp};
            
            resp
        };

        let slot_suffix = resp_string.trim_start_matches("0x");

        if slot_suffix.len() == 0 {
            self.slot_cache.insert((address, slot), EVMU256::ZERO);
            return EVMU256::ZERO;
        }
        let slot_value = EVMU256::try_from_be_slice(&hex::decode(slot_suffix).unwrap()).unwrap();
        self.slot_cache.insert((address, slot), slot_value);
        return slot_value;
    }
}

fn get_header() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authority", "etherscan.io".parse().unwrap());
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap());
    headers.insert(
        "accept-language",
        "zh-CN,zh;q=0.9,en;q=0.8".parse().unwrap(),
    );
    headers.insert("cache-control", "max-age=0".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Not?A_Brand\";v=\"24\", \"Chromium\";v=\"116\", \"Google Chrome\";v=\"116\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"macOS\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers
}