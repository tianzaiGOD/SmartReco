import argparse
from lib import *
from analysis_slither import *
from execute_with_transaction import *
from generate_tx_with_abi import *
from datetime import datetime

def main(network, tx, contract_address, base_output_path, tx_length, block_number, max_round, max_test, max_check_count, tx_round, tx_count, count=0):
    try:
        contract_address = contract_address.lower()
        output_path = f"{base_output_path}/cache/{contract_address}"
        tx_cache_path = f"{output_path}/tx"
        function_count = {}
        # ignore the create tx of contract or tx with error
        if tx["to"] == "" or tx["isError"] == "1":
            return
        info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_round}: Start replay for {tx_count + count}th tx function name: {tx['functionName']} of {contract_address}")
        result = replay_with_tx(tx, network)
        if result["returncode"] != 0:
            err_info = result["err_info"]
            handle_err(err_info, base_output_path, contract_address, contract_address)
            return
        [dapp_contract_functions_info, storage_logic_contracts, call_graph] = get_replay_record(tx, tx_cache_path, base_output_path)
        sorted_list = sort_with_importance(dapp_contract_functions_info)
        
        # handle if victim contract is a proxy
        target_logic_address = contract_address if contract_address not in storage_logic_contracts else storage_logic_contracts[contract_address]
        output_path = f"{base_output_path}/cache/{target_logic_address}"
        result = get_contract_online_info(target_logic_address, output_path)

        # analysis for victim transaction
        if not result[0]:
            res = False
        else:
            res = analysis_with_slither(base_output_path, output_path, target_logic_address, contract_address) if result[1] != ".vy"\
                else analysis_with_slither(base_output_path, output_path, target_logic_address, contract_address, contract_type=result[1], compile_version=result[2], vyper_storage_path=result[3])
            if target_logic_address in contract_abi_cache:
                function_abis = contract_abi_cache[target_logic_address]["function_abis"]
                total_abi = contract_abi_cache[target_logic_address]["total_abi"]
                
            if res:
                function_abis, total_abi = get_function_abis(output_path, target_logic_address)
                contract_abi_cache[target_logic_address] = {}
                contract_abi_cache[target_logic_address]["function_abis"] = function_abis
                contract_abi_cache[target_logic_address]["total_abi"] = total_abi
                called_function_signature = tx["methodId"]
                
                if called_function_signature not in function_count:
                    function_count[called_function_signature] = 0
                function_count[called_function_signature] += 1
                if function_count[called_function_signature] > max_test:
                    info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_count}: Has already analyzed {tx['functionName']} over {max_test} time!")
                    return
                
                if called_function_signature in function_abis and is_only_owner_function(target_logic_address, function_abis[called_function_signature], output_path):
                    # victim function is protected by only_owner, no need for test
                    return

        info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_count}: Start verify for {count + tx_count}th tx of {contract_address}")
        for dapp in sorted_list:
            for contracts in dapp["contract_list"]:
                # handle proxy
                storage_address = contracts["contract_address"]
                logic_address = storage_address\
                    if storage_address not in storage_logic_contracts\
                        else storage_logic_contracts[storage_address]
                output_path = f"{base_output_path}/cache/{logic_address}"
                verify_path = f"{base_output_path}/verify/{contract_address}"
                result = get_contract_online_info(logic_address, output_path)
                if not result[0]:
                    err_info = result[1]
                    handle_err(err_info, base_output_path, contract_address, storage_address)
                    continue 

                if logic_address in contract_abi_cache:
                    function_abis = contract_abi_cache[logic_address]["function_abis"]
                    total_abi = contract_abi_cache[logic_address]["total_abi"]
                else:
                    function_abis, total_abi = get_function_abis(output_path, logic_address)
                    contract_abi_cache[logic_address] = {}
                    contract_abi_cache[logic_address]["function_abis"] = function_abis
                    contract_abi_cache[logic_address]["total_abi"] = total_abi
                res = analysis_with_slither(base_output_path, output_path, logic_address, contract_address) if result[1] != ".vy"\
                    else analysis_with_slither(base_output_path, output_path, logic_address, contract_address, contract_type=result[1], compile_version=result[2], vyper_storage_path=result[3])
                if not res:
                    continue
                
                for candidate_function in contracts["function_list"]:
                    implicit_dependency, candidate_function_name = find_implicit_dependency(logic_address, candidate_function["function_name"], output_path, function_abis, base_output_path)
                    for implicit_function in implicit_dependency:
                        check_count = 0
                        check_count_round = 0 
                        onchain_tx_list = get_tx_list(network, storage_address, output_path, "latest", 1000)
                        is_verify = is_verified_input(logic_address, implicit_function, output_path, function_abis, base_output_path)
                        while check_count < max_check_count:
                            random_choice = None
                            filtered_related_tx = filter_tx_with_function_hash(onchain_tx_list, implicit_function.split("(")[0])
                            if len(filtered_related_tx) == 0:
                                # no related tx, random generate
                                for i in range(50):
                                    info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_round}: Tx: {count} Test Count: {check_count + i} in victim contract: {contract_address} for implicit dependency function: {implicit_function}, candidate_function: {candidate_function_name}")
                                    implicit_tx_list = generate_tx_with_abi(output_path, logic_address, storage_address, implicit_function, tx, random_choice, total_abi)
                                    verify_with_implicit_tx_list(contract_address, implicit_tx_list, tx, candidate_function, candidate_function_name, verify_path, network, is_verify)
                                check_count += 50
                            for i in range(len(filtered_related_tx)):
                                random_choice = filtered_related_tx[i]
                                # contain at most 3 tx: [normal, update_value, update_input]
                                implicit_tx_list = generate_tx_with_abi(output_path, logic_address, storage_address, implicit_function, tx, random_choice, total_abi)
                                info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_round}: Tx: {count} Test Count: {check_count + i} in victim contract: {contract_address} for implicit dependency function: {implicit_function}, candidate_function: {candidate_function_name}")
                                verify_with_implicit_tx_list(contract_address, implicit_tx_list, tx, candidate_function, candidate_function_name, verify_path, network, is_verify)
                            check_count += len(filtered_related_tx)
                            check_count_round += 1
                            if check_count_round > max_round:
                                onchain_tx_list = []
                            elif len(onchain_tx_list) > 0:
                                end_block = int(onchain_tx_list[-1]["blockNumber"])
                                onchain_tx_list = get_tx_list(network, storage_address, output_path, end_block - 1, 1000)
                                
        info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_round}: Finish verify for {count + tx_count}th tx of {contract_address}")
    except Exception as e:
        err_info = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error {e} for implicity contract {storage_address}"
        handle_err(err_info, base_output_path, contract_address, storage_address)
        traceback.print_exc()
        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyzes smart contracts for read-only reenterancy issues")
    parser.add_argument("--target-address", "-t", required=True, help="Address of contract")
    parser.add_argument("--output-dir", "-o", help="path to the output directory")
    parser.add_argument("--tx-length", nargs="?", type=int, help="transaction length per round, MAX_TEST= max_round * tx_length")
    parser.add_argument("--block-number", "-b", nargs="?", type=int, help="max block number, default='latest' ")
    parser.add_argument("--max-round", nargs="?", type=int, help="max target address test round, MAX_TEST= max_round * tx_length")
    parser.add_argument("--max-test", nargs="?", type=int, help="max test count per function")
    parser.add_argument("--max-check-count", nargs="?", type=int, help="max test count per implicit function")
    parser.add_argument("--network", "-n", nargs="?", help="which blockchain you want to explore, e.g. eth(default) bsc arbitrum")
    parser.add_argument("--etherscan-key", nargs="?", help="provide a key to get stable access, use ',' to split key if more than one key provide")
    args = parser.parse_args()

    contract_address = args.target_address.lower()
    tx_length = args.tx_length if args.tx_length else 1000
    block_number = args.block_number if args.block_number else "latest"
    base_output_path = args.output_dir if args.output_dir else "record_data"
    max_round = args.max_round if args.max_round else 10
    max_test = args.max_test if args.max_test else 100
    max_check_count = args.max_check_count if args.max_check_count else 50
    network = args.network if args.network else "ETH"
    endpoint.append(get_endpoint(network))
    if args.etherscan_key:
        keys = args.etherscan_key.split(",")
        eth_key.extend(keys)
    else:
        warn("No etherscan key found, analysis may fail!")
    create_folder_if_not_exists("record_data")
    info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SmartReco start analyze for {contract_address} top {tx_length} transactions until block: {block_number}!")
    output_path = f"{base_output_path}/cache/{contract_address}"
    tx_list = get_tx_list(network, contract_address, output_path, block_number, tx_length)  
    tx_round = 0
    tx_count = 0
    while len(tx_list) > 0 and tx_round < max_round:
        info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Round {tx_round}: SmartReco actually find {len(tx_list)} txs for {contract_address}")
        for count in range(len(tx_list)):
            main(network, tx_list[count], contract_address, base_output_path, tx_length, block_number, max_round, max_test, max_check_count, tx_round, tx_count, count)
        tx_round += 1
        tx_count += len(tx_list)
        contract_address_end_block = int(tx_list[-1]["blockNumber"])
        tx_list = get_tx_list(network, contract_address, output_path, contract_address_end_block - 1, tx_length)  
    info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Finish analyze for contract {contract_address}")