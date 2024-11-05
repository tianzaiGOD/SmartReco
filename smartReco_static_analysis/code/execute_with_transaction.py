# operation about execute/replay transaction
import json
import re
import subprocess
from analysis_slither import *
from lib.onchain_tool import *
from generate_tx_with_abi import get_function_abis
from lib.globl_variables import contract_abi_cache, eth_key

program_path = '../smartReco_dynamic_analysis/cli/target/debug/cli'

def analysis_tx_data(tx_data):
    return {
        "block_number": tx_data["blockNumber"],
        "block_hash": tx_data["blockHash"],
        "timestamp": tx_data["timeStamp"],
        "hash_data": tx_data["hash"],
        "from_address": tx_data["from"],
        "to_address": tx_data["to"],
        "value": tx_data["value"],
        "input_data": tx_data["input"],
        "function_name": tx_data["functionName"],
        "function_is_error": tx_data["isError"],
        "function_sign": tx_data["functionSign"] if "functionSign" in tx_data else "0x00000000"
    }

def replay_with_tx(tx, network="ETH"):
    tx_args = analysis_tx_data(tx)
    replay_arr = [program_path]
    replay_arr.extend(["replay", "-o", "--target-contract", tx_args['to_address'], "--target-function", "server", "-c", network, "--onchain-etherscan-api-key", ",".join(eth_key), "--target-from-address", tx_args['from_address'], "--target-tx-input", tx_args['input_data'], "--target-tx-hash", tx_args['hash_data'], "--target-fn-name", tx_args['function_name'], "--target-value", tx_args['value'], "--target-onchain-block-number", tx_args['block_number'], "--target-onchain-block-timestamp", tx_args['timestamp'],"--target-tx-is-error",tx_args["function_is_error"], "--target-block-hash", tx_args["block_hash"]])
    try:
        result = subprocess.run(replay_arr, timeout=300, stdout=subprocess.PIPE)
        return {
            "returncode": result.returncode,
            "err_info": result.stderr,
            "stdout": result.stdout.decode("utf-8"),
            "args": replay_arr
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": 1,
            "err_info": f"tx {tx['hash']} exectuion timeout"
        }

def verify_with_implicit_tx_list(contract_address, implicit_tx_list, tx, candidate_function, candidate_function_name, verify_path, network, is_verify=0):
    for implicit_tx in implicit_tx_list:
        result = verify_with_target_and_victim_tx(implicit_tx, tx, candidate_function["function_name"], candidate_function_name, is_verify, network)
        if result["returncode"] == 0 and "Find Cross Contract Control Leak!" in result["stdout"]:
            with open(f"{verify_path}/{contract_address}_args", "a") as file:
                res = '["' + implicit_tx["type"] + '","' + '","'.join(result["args"][1:]) + '"]'
                print(res)
                file.write(f'{res}\n')
                with open(f"{verify_path}/{contract_address}_implicit_tx", "a") as file1:
                    file1.write(f"{implicit_tx}\n")

def verify_with_target_and_victim_tx(target_tx, victim_tx, related_function_signature, related_function_name, is_verify, network="ETH"):
    target_tx_args = analysis_tx_data(target_tx)
    victim_tx_args = analysis_tx_data(victim_tx)
    # verify_arr = [program_path]
    verify_arr = [program_path, "evm", "-o", "--target-contract", target_tx_args['to_address'], "--victim-contract", victim_tx_args["to_address"], "--target-function", target_tx_args["function_name"], "--victim-function", victim_tx_args["function_name"], "-c", network, "--onchain-etherscan-api-key", ",".join(eth_key), "--target-from-address", target_tx_args['from_address'], "--target-tx-input", target_tx_args['input_data'], "--target-tx-hash", target_tx_args['hash_data'], "--target-fn-name", target_tx_args['function_name'], "--target-value", str(target_tx_args['value']), "--target-onchain-block-number", target_tx_args['block_number'], "--target-onchain-block-timestamp", target_tx_args['timestamp'], 
        "--target-tx-is-error",str(target_tx_args["function_is_error"]),"--victim-from-address", victim_tx_args["from_address"], "--victim-tx-input", victim_tx_args["input_data"], "--victim-tx-hash", victim_tx_args["hash_data"], "--victim-fn-name", victim_tx_args["function_name"], "--victim-value", victim_tx_args["value"], "--victim-onchain-block-number", victim_tx_args["block_number"], "--victim-onchain-block-timestamp", victim_tx_args["timestamp"],"--victim-tx-is-error",victim_tx_args["function_is_error"], "--related-function-signature", related_function_signature, "--related-function-name", related_function_name, "--target-block-hash", target_tx_args["block_hash"], "--victim-block-hash", victim_tx_args["block_hash"]]
    if is_verify:
        verify_arr.append("--is-verified")
    
    try:
        result = subprocess.run(verify_arr, timeout=300, stdout=subprocess.PIPE)
        return {
            "returncode": result.returncode,
            "stdout": result.stdout.decode("utf-8"),
            "err_info": result.stderr,
            "args": verify_arr
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": 1,
            "err_info": f"tx {target_tx['hash']} exectuion timeout",
            "stdout": "Error"
        }

def split_str_by_pattern(string):
    pattern = r'(0x[0-9a-fA-F]{40})'
    matches = re.findall(pattern, string)

    contract_address = matches[0]
    parts = string.split(contract_address)
    return [parts[0][0:-1], contract_address, parts[1][1:]]

def organize_in_order(objs, operation, record):
    temp_obj = record
    for obj in objs:
        [dapp, contract_address, invoke_function] = split_str_by_pattern(obj)
        if dapp not in temp_obj:
            temp_obj[dapp] = {}
        if contract_address not in temp_obj[dapp]:
            temp_obj[dapp][contract_address] = {}
        if invoke_function not in temp_obj[dapp][contract_address]:
            temp_obj[dapp][contract_address][invoke_function] = {}
        if operation not in temp_obj[dapp][contract_address][invoke_function]:
            temp_obj[dapp][contract_address][invoke_function][operation] = objs[obj]
        else:
            temp_obj[dapp][contract_address][invoke_function][operation] += objs[obj]
    return temp_obj

def organize_in_order_with_callgraph(objs, operation, record):
    temp_obj = record
    unknown_contract_cache = {}
    unknown_count = 0
    for obj in objs:
        if len(obj["children"]) > 0:
            temp_obj = organize_in_order_with_callgraph(obj["children"], operation, temp_obj)
        if obj["is_same"]:
            continue
        dapp = obj["dapp_name"]
        contract_address = obj["contract_address"]
        invoke_function = obj["called_function_signature"]
        if dapp not in temp_obj:
            if "unknown" in dapp:
                continue
            temp_obj[dapp] = {}
        if contract_address not in temp_obj[dapp]:
            temp_obj[dapp][contract_address] = {}
        if invoke_function not in temp_obj[dapp][contract_address]:
            temp_obj[dapp][contract_address][invoke_function] = {}
        if operation not in temp_obj[dapp][contract_address][invoke_function]:
            temp_obj[dapp][contract_address][invoke_function][operation] = obj[operation]
        else:
            temp_obj[dapp][contract_address][invoke_function][operation] += obj[operation]
    return temp_obj

def organize_in_order_with_callgraph_for_leaf(obj, operation, record):
    temp_obj = record
    dapp = obj["dapp_name"]
    contract_address = obj["contract_address"]
    invoke_function = obj["called_function_signature"]
    if obj["is_same"]:
        return temp_obj
    if dapp not in temp_obj:
        if "unknown" in dapp:
            return temp_obj
        # else:
        temp_obj[dapp] = {}
    if contract_address not in temp_obj[dapp]:
        temp_obj[dapp][contract_address] = {}
    if invoke_function not in temp_obj[dapp][contract_address]:
        temp_obj[dapp][contract_address][invoke_function] = {}
    if operation not in temp_obj[dapp][contract_address][invoke_function]:
        temp_obj[dapp][contract_address][invoke_function][operation] = obj[operation]
    else:
        temp_obj[dapp][contract_address][invoke_function][operation] += obj[operation]
    return temp_obj
        
def get_replay_record(tx, tx_cache_path, base_output_path):
    hash = tx["hash"]
    cache_path = f"{tx_cache_path}/{hash}/replay_record_{hash}"
    dapp_contract_functions_info = {}
    dapp_contract_functions_info_with_callgraph = {}

    with open(cache_path, "r") as file:
        operates = json.load(file)
        for operate in operates:
            if operate == "delegatecall_record":
                storage_logic_contracts = json.loads(operates[operate])
            elif operate == "call_graph":
                call_graph = json.loads(operates[operate])    
    dapp_contract_functions_info_with_callgraph = filter_ignore_contract_with_callgraph(call_graph, storage_logic_contracts, base_output_path)
    
    return [dapp_contract_functions_info_with_callgraph, storage_logic_contracts, call_graph]

def filter_ignore_contract_with_callgraph(callgraph, storage_logic_contracts, base_output_path):
    root_contract = callgraph if callgraph["contract_address"] not in storage_logic_contracts else callgraph["children"][0]
    function_abi_cache = {}
    dapp_contract_functions_info = {}
    operations = ["read", "write", "invoke"]
    for leaf in root_contract["children"]:
        if not leaf["is_same"]:
            for operation in operations:
                dapp_contract_functions_info = organize_in_order_with_callgraph_for_leaf(leaf, operation, dapp_contract_functions_info)
                dapp_contract_functions_info = organize_in_order_with_callgraph(leaf["children"], operation, dapp_contract_functions_info)
        else:
            storage_address = leaf["contract_address"]
            logic_address = storage_address if storage_address not in storage_logic_contracts else storage_logic_contracts[storage_address]
            called_function_signature = leaf["called_function_signature"]
            output_path = f"{base_output_path}/cache/{logic_address}"
        
            result = get_contract_online_info(logic_address, output_path)
            if not result[0]:
                for operation in operations:
                    dapp_contract_functions_info = organize_in_order_with_callgraph_for_leaf(leaf, operation, dapp_contract_functions_info)
                    dapp_contract_functions_info = organize_in_order_with_callgraph(leaf["children"], operation, dapp_contract_functions_info)
                err_info = result[1]
                handle_err(err_info, base_output_path, callgraph["contract_address"], storage_address)
                continue 

            if logic_address in contract_abi_cache:
                function_abis = contract_abi_cache[logic_address]["function_abis"]
            else:
                contract_abi_cache[logic_address] = {}
                function_abis, total_abi = get_function_abis(output_path, logic_address)
                contract_abi_cache[logic_address]["function_abis"] = function_abis
                contract_abi_cache[logic_address]["total_abi"] = total_abi

            res = analysis_with_slither(base_output_path, output_path, logic_address, root_contract["contract_address"]) if result[1] != ".vy" \
                else analysis_with_slither(base_output_path, output_path, logic_address, root_contract["contract_address"], contract_type=result[1], compile_version=result[2], vyper_storage_path=result[3])
            if not res:
                for operation in operations:
                    dapp_contract_functions_info = organize_in_order_with_callgraph_for_leaf(leaf, operation, dapp_contract_functions_info)
                    dapp_contract_functions_info = organize_in_order_with_callgraph(leaf["children"], operation, dapp_contract_functions_info)
                continue
            
            if called_function_signature in function_abis and is_only_owner_function(logic_address, function_abis[called_function_signature], output_path):
                # no need for record
                continue
            else:
                for operation in operations:
                    dapp_contract_functions_info = organize_in_order_with_callgraph_for_leaf(leaf, operation, dapp_contract_functions_info)
                    dapp_contract_functions_info = organize_in_order_with_callgraph(leaf["children"], operation, dapp_contract_functions_info)
    return dapp_contract_functions_info

def sort_with_importance(dapp_contract_functions_info):
    dapp_list = []
    for dapp_name, contracts in dapp_contract_functions_info.items():
        contract_list = []
        dapp_importance = 0
        for contract_address, functions in contracts.items():
            function_list = []
            contract_importance = 0
            for function_name, items in functions.items():
                function_importance = 0
                for value in items.values():
                    function_importance += value
                    contract_importance += value
                    dapp_importance += value
                function_list.append({
                    "function_name": function_name,
                    "importance": function_importance,
                    **items
                })
            function_list.sort(key=custom_sort)
            contract_list.append({
                "contract_address": contract_address,
                "importance": contract_importance,
                "function_list": function_list
            })
        contract_list.sort(key=custom_sort)
        dapp_list.append({
            "dapp_name": dapp_name,
            "importance": dapp_importance,
            "contract_list": contract_list
        })
    dapp_list.sort(key=custom_sort)
    return dapp_list

def custom_sort(obj):
    # desc
    return -obj["importance"]