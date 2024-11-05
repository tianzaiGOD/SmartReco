use std::collections::{HashMap, HashSet};
use crate::{evm::types::EVMAddress, dapp_utils::CreatorDapp};
// use crate::cache::{Cache, FileSystemCache};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize, Default)] 
pub struct CallGraphNode {
    pub contract_address: EVMAddress,
    // record is contract_address same dapp with root contract
    pub is_same: bool,
    pub called_function_signature: String,
    pub children: Vec<CallGraphNode>,
    pub write: usize,
    pub read: usize,
    pub invoke: usize,
    pub dapp_name: String,
}

impl CallGraphNode {
    pub fn new(contract_address: EVMAddress, dapp_name: String, is_same: bool, called_function_signature: String) -> Self{
        CallGraphNode { 
            contract_address, 
            is_same,
            called_function_signature,
            children: Vec::new(),
            write: 0,
            read: 0,
            invoke: 1,
            dapp_name,
        }
    }

    pub fn add_child(&mut self, child: CallGraphNode) {
        self.children.push(child);
    }

    pub fn add_write(&mut self) {
        self.write += 1;
    }

    pub fn add_read(&mut self) {
        self.read += 1;
    }

    pub fn print_tree(&self, level: usize)  -> String{
        // let mut total_str = "".to_string();
        let indent = " ".repeat(level);
        let line = format!("{}{:?}\n", indent, self.contract_address);
        let mut total_str = line;
        for child in &self.children {
            total_str = total_str + &child.print_tree(level + 1);
        }
        total_str
    }

    pub fn to_nested_dict(&self) -> Value
    {
        let mut nested_dict = json!({
            "contract_address": format!("{:?}", self.contract_address),
            "is_same": self.is_same,
            "called_function_signature": self.called_function_signature,
            "children": [],
            "write": self.write,
            "read": self.read,
            "invoke": self.invoke,
            "dapp_name": self.dapp_name,
        });

        let mut children = vec![];
        for child in &self.children {
            children.push(child.to_nested_dict());
        }
        nested_dict["children"] = Value::Array(children);

        nested_dict
    }
}

#[derive(Clone, Serialize, Deserialize)] 
/// (Dapp, Contract, Function) => Count
pub struct DappRecordData {
    pub dapp_read_count: HashMap<(String, EVMAddress, String), usize>,
    pub dapp_write_count: HashMap<(String, EVMAddress, String), usize>,
    pub dapp_invoke_count: HashMap<(String, EVMAddress, String), usize>,
    /// record the logic/storage contract, as contract may be a proxy
    pub contract_to_logic_contract: HashMap<EVMAddress, EVMAddress>,
    pub logic_to_storage_contract: HashMap<EVMAddress, EVMAddress>,
    // file_system: FileSystemCache,
}

impl DappRecordData {
    pub fn new() -> Self {
        Self {
            dapp_read_count: HashMap::new(),
            dapp_write_count: HashMap::new(),
            dapp_invoke_count: HashMap::new(),
            contract_to_logic_contract: HashMap::new(),
            logic_to_storage_contract: HashMap::new(),
            // file_system: FileSystemCache::new(&path)
        }
    }

    pub fn add_read(&mut self, info: &CreatorDapp, function_name: &str) {
        match self.dapp_read_count.get_mut(&(info.dapp.clone(), info.contract, function_name.to_string())) {
            Some(info) => {
                *info += 1;
            },
            None => {
                self.dapp_read_count.insert((info.dapp.clone(), info.contract, function_name.to_string()), 1);
            }
        }
    }

    pub fn add_write(&mut self, info: &CreatorDapp, function_name: &str) {
        match self.dapp_write_count.get_mut(&(info.dapp.clone(), info.contract, function_name.to_string())) {
            Some(info) => {
                *info += 1;
            },
            None => {
                self.dapp_write_count.insert((info.dapp.clone(), info.contract, function_name.to_string()), 1); 
            }
        }
    }

    pub fn add_invoke(&mut self, info: &CreatorDapp, function_name: &str) {
        let dapp_name = if info.dapp.contains("unknown") {
            format!("{:}{:}", info.contract, info.dapp.clone())
        } else {
            info.dapp.clone()
        };
        match self.dapp_invoke_count.get_mut(&(dapp_name.clone(), info.contract, function_name.to_string())) {
            Some(info) => {
                *info += 1;
            },
            None => {
                self.dapp_invoke_count.insert((dapp_name, info.contract, function_name.to_string()), 1);  
            }
        }
    }

    pub fn add_dapp_contact(&mut self, from: EVMAddress, to: EVMAddress) {
        self.contract_to_logic_contract.insert(from, to);
        self.logic_to_storage_contract.insert(to, from);
    }

    pub fn convert_hashmap<K, V, T>(hashmap: HashMap<(K, T, K), V>)  -> HashMap<String, V>
    where
        K: std::string::ToString,
        T: std::fmt::Debug + std::fmt::Display,
    {
        hashmap
            .into_iter()
            .map(|((key1, key2, key3), value)| (format!("{}_{:?}_{}", key1.to_string(), key2, key3.to_string()), value))
            .collect()
    }

}