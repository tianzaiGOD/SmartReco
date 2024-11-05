import requests
import random
import os
import json
from .util import *
from .globl_variables import eth_key, endpoint
import time

USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
    "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
    "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
    "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
    "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
]
headers = {
    'authority': 'etherscan.io',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
              'application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/108.0.0.0 Safari/537.36',
}

# Change url, add your own key here
def get_endpoint(network="ETH"):
    if network == "ETH":
        return "https://api.etherscan.io/api"
    elif network == "BSC":
        return "https://api.bscscan.com/api"
    elif network =="ARBITRUM":
        return "https://api.arbiscan.io/api"
    elif network == "ZKEVM":
        return "https://api-era.zksync.network/api"
    elif network == "POLYGON":
        return "https://api.polygonscan.com/api"
    else:
        raise Exception("Unknown network")

def fetch_tx_list(contract_address, tx_number, end_block_number, start_block_number=0, sort="desc"):
    index = random.randint(1, 100) % len(eth_key)
    transaction_list_url = f"{endpoint[-1]}?module=account&action=txlist&address={contract_address}&startblock={start_block_number}&endblock={end_block_number}&page=1&offset={tx_number}&sort={sort}&apikey={eth_key[index]}"
    time.sleep(0.2)
    random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
    headers["user-agent"] = random_agent
    response = requests.get(transaction_list_url, headers=headers)
    response_json = response.json()
    return response_json["result"]

def get_tx_list(network, contract_address, store_path, end_block_number, tx_number, start_block_number=0, sort="desc"):
    file_name = f"tx_list_{contract_address}_{network}_{start_block_number}_{end_block_number}_{tx_number}"
    tx_store_path = f"{store_path}/{file_name}"
    file_list = check_files_with_prefix(store_path, file_name)
    create_folder_if_not_exists(store_path)
    if len(file_list) > 0:
        with open(tx_store_path, "r") as file:
            tx_list = json.load(file)
            if not 'Max rate limit reached' in tx_list:
                return tx_list
    tx_list = fetch_tx_list(contract_address, tx_number, end_block_number, start_block_number, sort)
    with open(tx_store_path, "w") as file:
        file.write(json.dumps(tx_list))
    return tx_list


def fetch_source_code_of_contract(contract_address, store_path):
    index = random.randint(1, 100) % len(eth_key)
    url = f"{endpoint[-1]}?module=contract&action=getsourcecode&address={contract_address}&apikey={eth_key[index]}"
    time.sleep(0.2)
    random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
    headers["user-agent"] = random_agent
    response = requests.get(url, headers=headers)
    response_json = response.json()["result"][0]
    return response_json

def get_contract_online_info(contract_address, store_path):
    file_list = check_files_with_prefix(store_path, f'source_code_eth_{contract_address}')
    type_info_path = f'{store_path}/type_info_{contract_address}'
    compile_version_path = f'{store_path}/compile_version_{contract_address}'
    abi_path = f'{store_path}/abi_eth_{contract_address}'
    source_code_path = f'{store_path}/source_code_eth_{contract_address}'

    if len(file_list) > 0:
        with open(abi_path, "r") as file:
            if "no source code" in file.readline():
                return [False, f"Contract {contract_address} is not a contract"]
        with open(type_info_path, 'r') as file:
            contract_type = file.readline()
        with open(compile_version_path, 'r') as file:
            compile_version = file.readline()
        return [True, contract_type, compile_version, source_code_path]
    else:
        try:
            response_json = fetch_source_code_of_contract(contract_address, store_path)

            contract_version = response_json["CompilerVersion"]
            contract_codes = response_json["SourceCode"]
            contract_abis = response_json["ABI"]
            # source_code_folder = f"{store_path}/source_code"
            os.makedirs(store_path, exist_ok=True)

            if not contract_codes:
                with open(abi_path, "w") as file:
                    file.write("no source code\n")
                err_info = f"Fail to analyze contract {contract_address} due to no source code"
                return [False, err_info]
            
            [contract_type, compile_version] = get_contract_type_version(contract_version)

            abi_data = handle_abi_data(contract_abis)

            with open(source_code_path, "w") as file:
                file.write(contract_codes)
            with open(type_info_path, "w") as file:
                file.write(contract_type)
            with open(compile_version_path, "w") as file:
                file.write(compile_version)
            with open(abi_path, "w") as file:
                json.dump(abi_data, file)
        except Exception as e:
            err_info = f"Fail to analyze contract {contract_address} due to {e}"
            return [False, err_info]
    
    return [True, contract_type, compile_version, source_code_path]
        
def get_creator_info(address, file_path, base_path):
    contract_folder = f"{base_path}/{address}"
    create_folder_if_not_exists(contract_folder)

    store_creator_key = "create_tx_eth_"
    creator_cache_url = f"{contract_folder}/{store_creator_key}{address}"

    if os.path.exists(creator_cache_url): 
        with open(creator_cache_url, 'r') as data:
            response_json = json.load(data)
        if response_json["status"] != 0:
            return response_json
    index = random.randint(1, 100) % len(eth_key)
    creator_url = f"{endpoint[-1]}?module=contract&action=getcontractcreation&contractaddresses={address}&format=json&apikey={eth_key[index]}"
    time.sleep(0.2)
    random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
    headers["user-agent"] = random_agent
    response = requests.get(creator_url, headers=headers)
    response_json = response.json()
    with open(creator_cache_url, 'w') as cache:
        cache.write(json.dumps(response_json))
    return response_json

def get_internal_tx_info(response_json, file_path, address, base_path):
    contract_creat_info = response_json["result"][0]
    txHash = contract_creat_info["txHash"]
    contract_folder = f"{base_path}/{address}"
    create_folder_if_not_exists(contract_folder)
    
    store_internal_tx_key = 'internal_tx_of_'
    internal_tx_cache_url = f"{contract_folder}/{store_internal_tx_key}{txHash}"

    if not os.path.exists(internal_tx_cache_url):
        index = random.randint(1, 100) % len(eth_key)
        txhash_url = f"{endpoint[-1]}?module=account&action=txlistinternal&txhash={txHash}&format=json&apikey={eth_key[index]}"
        time.sleep(0.2)
        random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
        headers["user-agent"] = random_agent
        response = requests.get(txhash_url, headers=headers)
        response_json = response.json()
        with open(internal_tx_cache_url, 'w') as cache:
            cache.write(json.dumps(response_json))
    else:
        with open(internal_tx_cache_url) as data:
            response_json = json.load(data)
        if response_json["status"] != "1" and response_json["message"] != "No transactions found":
            index = random.randint(1, 100) % len(eth_key)
            txhash_url = f"{endpoint[-1]}?module=account&action=txlistinternal&txhash={txHash}&format=json&apikey={eth_key[index]}"
            time.sleep(0.2)
            random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
            headers["user-agent"] = random_agent
            response = requests.get(txhash_url, headers=headers)
            response_json = response.json()
            with open(internal_tx_cache_url, 'w') as cache:
                cache.write(json.dumps(response_json))
    
    internal_tx_arr = response_json["result"]
    for i in range(len(internal_tx_arr)):
        internal_tx = internal_tx_arr[i]
        if internal_tx["type"] == "create" and internal_tx["contractAddress"].lower() == address.lower() and internal_tx["to"] == '':
            # contract create tx is from internal tx
            return (True, (internal_tx['from'], '0x') )
    # contract create tx is not from internal tx
    return (False, (contract_creat_info["contractCreator"], file_path["dapp_name"]))

def get_tx_info(tx_hash, base_path):
    file_path = f"{base_path}/{tx_hash}"
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            response_json = json.load(file)
        if "result" in response_json:
            return response_json["result"]
    index = random.randint(1, 100) % len(eth_key)
    txhash_url = f"{endpoint[-1]}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&format=json&apikey={eth_key[index]}"
    time.sleep(0.1 + random.random())
    random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
    headers["user-agent"] = random_agent
    response = requests.get(txhash_url, headers=headers)
    response_json = response.json()
    with open(file_path, "w") as file:
        file.write(json.dumps(response_json))
    tx_detail = response_json["result"]
    return tx_detail
    
def fetch_internal_tx_list(base_path, contract_address, tx_number, end_block, start_block=0, sort="desc"):
    file_name = f"internaltx_list_{contract_address}_{start_block}_{end_block}_{tx_number}"
    store_path = f"{base_path}/{contract_address}"
    tx_store_path = f"{store_path}/{file_name}"
    file_list = check_files_with_prefix(store_path, file_name)
    if len(file_list) > 0:
        with open(tx_store_path, "r") as file:
            response_json = json.load(file)
    else:
        index = random.randint(1, 100) % len(eth_key)
        time.sleep(0.2)
        url = f"{endpoint[-1]}?module=account&action=txlistinternal&address={contract_address}&startblock={start_block}&endblock={end_block}&page=1&offset={tx_number}&sort={sort}&apikey={eth_key[index]}"
        random_agent =  USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]
        headers["user-agent"] = random_agent
        response = requests.get(url, headers=headers)
        response_json = response.json()
        with open(tx_store_path, 'w') as cache:
            cache.write(json.dumps(response_json))
    return response_json["result"]