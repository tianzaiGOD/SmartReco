import functools
import json
import re
import flask
import requests
from retry import retry
from ratelimit import limits
import time
import os
import random


################### CONFIG ###################

USE_ETHERSCAN_API = False
ETHERSCAN_API_KEY = {
    "ETH": "",
    "BSC": "",
    "POLYGON": "",
    "MUMBAI": "",
}
QUOTING_METHOD = {
    "ETH": "subgraph",
    "BSC": "fuzzland_api",
    "POLYGON": "subgraph",
    "MUMBAI": "subgraph"
}
execute_env = os.environ.get("ENV")
##############################################


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


def get_endpoint(network):
    if network == "eth":
        return "https://api.etherscan.io/api"
    # TODO: Change url
    elif network == "bsc":
        return "https://api.bscscan.com/api"
    elif network =="arbitrum":
        return "https://api.arbiscan.io/api"
    elif network=="zkevm":
        return "https://api-era.zksync.network/api"
    elif network == "polygon":
        return "https://polygonscan.com"
    elif network == "mumbai":
        return "https://mumbai.polygonscan.com"
    else:
        raise Exception("Unknown network")


def get_rpc(network):
    if network == "eth":
        return os.getenv("ETH_RPC", "https://eth.merkle.io")
    elif network == "bsc":
        return os.getenv("BSC_RPC", "https://bsc.llamarpc.com")
    elif network == "polygon":
        return os.getenv("POLYGON_RPC", "https://polygon.llamarpc.com")
    elif network == "mumbai":
        return os.getenv("MUMBAI_RPC", "https://rpc-mumbai.maticvigil.com")
    elif network == "arbitrum":
        return os.getenv("ARBI_RPC", "https://arbitrum.llamarpc.com")
    else:
        raise Exception("Unknown network")

data = '{  p0: pairs(block:{number:%s},first:10,where :{token0 : \"%s\"}) { \n    id\n    token0 {\n      decimals\n      id\n    }\n    token1 {\n      decimals\n      id\n    }\n  }\n  \n   p1: pairs(block:{number:%s},first:10, where :{token1 : \"%s\"}) { \n    id\n    token0 {\n      decimals\n      id\n    }\n    token1 {\n      decimals\n      id\n    }\n  }\n}'
data_peg = '{  p0: pairs(block:{number:%s},first:10,where :{token0 : \"%s\", token1: \"%s\"}) { \n    id\n    token0 {\n      decimals\n      id\n    }\n    token1 {\n      decimals\n      id\n    }\n  }\n\n   p1: pairs(block:{number:%s},first:10, where :{token1 : \"%s\", token0: \"%s\"}) { \n    id\n    token0 {\n      decimals\n      id\n    }\n    token1 {\n      decimals\n      id\n    }\n  }\n  }'


@retry(tries=100, delay=1, backoff=1)
@limits(calls=4, period=2)
def etherscan_get(url, ):
    print(url)
    return requests.get(url, headers=headers)


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def fetch_reserve(pair, network, block):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": pair,
            "data": "0x0902f1ac"
        }, block],
        "id": 1
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    result = response.json()["result"]

    return result[2:66], result[66:130]


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def fetch_rpc_balance(network, address, block, eth_key):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, block],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    result = response.json()["result"]
    return result


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def get_latest_block(network):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()["result"]

# max 1 hops
MAX_HOPS = 0

def add_reserve_info(pair_data, network, block):
    if pair_data["src"] == "pegged_weth":
        return
    reserves = fetch_reserve(pair_data["pair"], network, block)
    pair_data["initial_reserves_0"] = reserves[0]
    pair_data["initial_reserves_1"] = reserves[1]

def scale(price, decimals):
    # scale price to 18 decimals
    price = int(price, 16)
    if int(decimals) > 18:
        return float(price) / (10 ** (int(decimals) - 18))
    else:
        return float(price) * (10 ** (18 - int(decimals)))

@functools.lru_cache(maxsize=10240)
def fetch_etherscan_token_holder(network, token_address):
    slot = re.compile("<tbody(.*?)>(.+?)</tbody>")
    td_finder = re.compile("<tr>(.+?)</tr>")
    finder = re.compile("/token/" + token_address + "\?a=0x[0-9a-f]{40}'")
    url = f"{get_endpoint(network)}/token/generic-tokenholders2?a={token_address}"
    response = etherscan_get(url)
    response.raise_for_status()
    ret = []
    tds = td_finder.findall(slot.findall(response.text.replace("\n", ""))[0][1])
    if len(tds) < 10:
        return []
    for i in tds:
        holder = finder.findall(i)[0].split("?a=")[1][:-1]
        is_contract = "Contract" in i
        if not is_contract:
            ret.append(holder)
    return ret


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_contract_abi(network, token_address, eth_key):
    url = f"{get_endpoint(network)}?module=contract&action=getabi&address={token_address}&format=json&apikey={eth_key}"
    time.sleep(0.5)
    response = etherscan_get(url)
    print(response.status_code)
    if response.status_code == 200:
        return response.json()
    return []

# ADD
@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_tx_info(network, txhash, eth_key):
    url = f"{get_endpoint(network)}?module=account&action=txlistinternal&txhash={txhash}&format=json&apikey={eth_key}"
    time.sleep(0.5)
    response = etherscan_get(url)
    if response.status_code == 200:
        return response.json()
    return []

# ADD
@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_create_info(network, address, eth_key):
    url = f"{get_endpoint(network)}?module=contract&action=getcontractcreation&contractaddresses={address}&format=json&apikey={eth_key}"
    time.sleep(0.5)
    response = etherscan_get(url)
    if response.status_code == 200:
        return response.json()
    return []

def get_major_symbol(network):
    if network == "eth":
        return "ETH"
    elif network == "bsc":
        return "BNB"
    elif network == "polygon" or network == "mumbai":
        return "MATIC"
    else:
        raise Exception("Unknown network")

@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_rpc_slot(network, token_address, slot, block, eth_key):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [token_address, slot, block],
        "id": 1
    }
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    print(response.json())
    return response.json()["result"]


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_rpc_byte_code(network, address, block, eth_key):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, block],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    print(response.json())
    return response.json()["result"]


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_blk_hash(network, num):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [num, False],
        "id": 1
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()["result"]["hash"]


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def fetch_rpc_storage_dump(network, address, block, offset="", amt=0):
    print(f"fetching {address} {block} {offset}")
    if amt > 1:
        return "defer"
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_storageRangeAt",
        "params": [fetch_blk_hash(network, block), 0, address, offset, 100000],
        "id": 1
    }

    response = requests.post(url, json=payload, timeout=15)
    try:
        response.raise_for_status()
    except Exception as e:
        print(response.text)
        raise e

    j = response.json()
    if "result" not in j:
        print(j)
        raise Exception("invalid response")

    res = {}
    if "nextKey" in j["result"] and j["result"]["nextKey"]:
        res = fetch_rpc_storage_dump(network, address, block, offset=j["result"]["nextKey"], amt=amt+1)
    if res == "defer":
        return {}
    # this rpc is likely going to fail for a few times
    return {**res, **j["result"]["storage"]}


@functools.lru_cache(maxsize=10240)
@retry(tries=10, delay=0.5, backoff=0.3)
def fetch_rpc_storage_all(network, address, block):
    url = f"{get_rpc(network)}"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAll",
        "params": [address, block],
        "id": 1
    }

    response = requests.post(url, json=payload, timeout=7)
    response.raise_for_status()

    return response.json()["result"]


app = flask.Flask(__name__)


@app.route("/holders/<network>/<token_address>", methods=["GET"])
def holders(network, token_address):
    return flask.jsonify(fetch_etherscan_token_holder(network, token_address))


@app.route("/abi/<network>/<token_address>/<eth_key>", methods=["GET"])
def abi(network, token_address, eth_key):
    return flask.jsonify(fetch_etherscan_contract_abi(network, token_address, eth_key))

# ADD
@app.route("/creator/<network>/<txhash>/<eth_key>", methods=["GET"])
def creator(network, txhash, eth_key):
    return flask.jsonify(fetch_etherscan_tx_info(network, txhash, eth_key))
# ADD
@app.route("/tx/<network>/<address>/<eth_key>", methods=["GET"])
def tx(network, address, eth_key):
    return flask.jsonify(fetch_etherscan_create_info(network, address, eth_key))

@app.route("/slot/<network>/<token_address>/<slot>/<block>/<eth_key>", methods=["GET"])
def slot(network, token_address, slot, block, eth_key):
    return fetch_rpc_slot(network, token_address, slot, block, eth_key)


@app.route("/bytecode/<network>/<address>/<block>/<eth_key>", methods=["GET"])
def bytecode(network, address, block, eth_key):
    return fetch_rpc_byte_code(network, address, block, eth_key)

@app.route("/balance/<network>/<address>/<block>/<eth_key>", methods=["GET"])
def balance(network, address, block, eth_key):
    return fetch_rpc_balance(network, address, block, eth_key)


@app.route("/storage_dump/<network>/<address>/<block>", methods=["GET"])
def storage_dump(network, address, block):
    # use debug_storageRangeAt to dump the storage
    # this requires RPC endpoint enabling debug & archive node
    return {"storage": fetch_rpc_storage_dump(network, address, block)}


@app.route("/storage_all/<network>/<address>/<block>", methods=["GET"])
def storage_all(network, address, block):
    # use eth_getStorageAll to dump the storage
    # this requires running a modified geth
    return fetch_rpc_storage_all(network, address, block)

if __name__ == "__main__":
    app.run(port=5003)