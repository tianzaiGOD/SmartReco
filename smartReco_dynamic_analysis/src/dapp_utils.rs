use csv::Reader;
use std::error::Error;
use std::fs::File;
use crate::evm::types::{EVMAddress};
use std::str::FromStr;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// use crate::evm::contract_utils::ContractLoader;
/// struct to store creator and dapp information
#[derive(Clone, Debug)]
pub struct CreatorDapp {
    pub contract: EVMAddress,
    pub creator: EVMAddress,
    pub dapp: String,
}

impl CreatorDapp {
    pub fn new(contract: EVMAddress, creator: EVMAddress, dapp: String) -> Self {
        Self {
            contract,
            creator,
            dapp,
        }
    }
}

/// record information about creator address to Dapp name
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DappInfo {
    pub address_to_name: HashMap<EVMAddress, String>
}

impl DappInfo {
    pub fn new() -> Self {
        let ret = Self {
            address_to_name: HashMap::new(),
        };
        ret
    }

    pub fn add_from_file(&mut self, filename: &str) -> Result<(), Box<dyn Error>> {
        let file = File::open(filename)?;
        let mut csv_reader = Reader::from_reader(file);
    
        for result in csv_reader.records() {
            let record = result?;
            if let (Some(hex_value), Some(string_value)) = (record.get(0), record.get(1)) {
                let address = EVMAddress::from_str(hex_value).unwrap();
                self.address_to_name.insert(address, string_value.to_string());
            }
        }
        Ok(())
    }

    pub fn search_by_address(&mut self, address: EVMAddress) -> Option<String> {
        if self.address_to_name.contains_key(&address) {
            Some(self.address_to_name[&address].clone())
        } else {
            None
        }
    }

    pub fn is_from_same_dapp(&mut self, address1: EVMAddress, address2: EVMAddress) -> bool {
        let dapp1 = match self.search_by_address(address1) {
            Some(dapp) => dapp,
            None => return false
        };
        let dapp2 = match self.search_by_address(address2) {
            Some(dapp) => dapp,
            None => return false
        };
        return dapp1 == dapp2;

    }
}