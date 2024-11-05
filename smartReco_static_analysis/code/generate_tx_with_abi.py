# use abi to generate transaction input
import json
import web3
import eth_abi
from lib.generate import *
from lib.util import extract_function_name
from lib.onchain_tool import *
from lib.printer import *

def analysis_tx_data(tx_data, type):
    return {
        "blockNumber": tx_data["blockNumber"],
        "blockHash": tx_data["blockHash"],
        "timeStamp": tx_data["timeStamp"],
        "hash": tx_data["hash"],
        "from": tx_data["from"],
        "to": tx_data["to"],
        "value": tx_data["value"],
        "input": tx_data["input"],
        "functionName": tx_data["functionName"],
        "isError": tx_data["isError"],
        "functionSign": tx_data["methodId"] if "methodId" in tx_data else "0x00000000",
        "type": type
    }

def get_function_signature_and_types(func):
    name = func["name"]
    types = []
    for input in func["inputs"]:
        input_type = input["type"]
        # handle "tuple", if we use "tuple" will get wrong signature
        if "tuple" in input_type:
            args = []
            for arg in input["components"]:
                args.append(arg["type"])
            args_str = "(" + ",".join(args) + ")"
            if input_type.endswith("[]"):
                args_str += "[]"
            types.append(args_str)
        else:
            types.append(input_type)

    signature = '{}({})'.format(name,','.join(types))
    return signature, types

def get_function_abis(output_path, contract_address):
    with open(f"{output_path}/abi_eth_{contract_address}", "r") as file:
        abi = json.loads(json.load(file)["result"])
    # handle function overload
    function_abis = {}
    for func in [obj for obj in abi if obj['type'] == 'function']:
        [signature, _] = get_function_signature_and_types(func)
        function_abis[web3.Web3.keccak(text=signature)[:4].hex()] = signature
    return function_abis, abi

def get_target_function_abi(abi, signature):
    function_name = extract_function_name(signature)
    for func in [obj for obj in abi if obj['type'] == 'function']:
        name = func['name']
        if name != function_name:
            continue
        return func
    return {}


def get_function_hash_and_args_types(func):
    signature, types = get_function_signature_and_types(func)
    return [web3.Web3.keccak(text=signature)[:4].hex(), types]

def generate_input_with_abi(function_hash, args_types, address_array=[]):
    args_value = []
    for args_type in args_types:
        args_value.extend(gen_input(args_type, address_array))
    return function_hash + eth_abi.encode(args_types, args_value).hex()

def generate_value(func):
    if "payable" in func and func["payable"]:
        return str(gen_value())
    return "0"

def filter_tx_with_function_hash(tx_list, function_signature):
    related_tx_cache = []
    for tx in tx_list:
        if tx["to"] == None:
            continue
        tx_function_signature = tx["functionName"].split("(")[0] if "methodId" in tx else "0x00000000"
        if tx_function_signature == function_signature and tx["isError"] != '1':
            related_tx_cache.append(tx)
    return related_tx_cache

def generate_tx_with_abi(output_path, contract_address, storage_address, function_name, tx_data, random_choice, total_abi):
    target_func_abi = get_target_function_abi(total_abi, function_name)
    if random_choice:
        implicit_tx_list = [analysis_tx_data(random_choice, "origin")]
        if ("payable" in target_func_abi and target_func_abi["payable"]) or ("stateMutability" in target_func_abi and target_func_abi["stateMutability"] == "payable"):
            new_tx = random_choice.copy()
            new_tx["value"] = str(int(new_tx["value"]) + random.randint(1, 100000000))
            implicit_tx_list.append(analysis_tx_data(new_tx, "payable"))
        if len(random_choice) > 10:
            new_tx = random_choice.copy()
            new_tx["input"] = random_change(new_tx["input"])
            implicit_tx_list.append(analysis_tx_data(new_tx, "random"))
        return implicit_tx_list
    else:
        info(f"Can not find related transaction for function: {function_name}, random generate input with abi")
        [function_hash, args_types] = get_function_hash_and_args_types(target_func_abi)
        tx_input = generate_input_with_abi(function_hash, args_types, [tx_data["from"], tx_data["to"], contract_address])
        
        return [{
            "blockNumber": tx_data["blockNumber"],
            "timeStamp": tx_data["timeStamp"],
            "hash": tx_data["hash"],
            "from": tx_data["from"],
            "to": storage_address,
            "value": generate_value(target_func_abi),
            "input": tx_input,
            "functionName": function_name,
            "isError": 0,
            "functionSign": web3.Web3.keccak(text=function_name)[:4].hex(),
            "blockHash": tx_data["blockHash"],
            "type": "without_input"
        }]
