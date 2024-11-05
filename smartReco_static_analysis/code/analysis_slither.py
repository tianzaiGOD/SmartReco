import random
import sys
sys.path.append("..")
import argparse
import os
import sys
import json
import traceback
from lib.util import *
from lib.printer import *
# from lib.onchain_tool import get_contract_online_info
from lib.globl_variables import eth_key, endpoint
import vvm
from slither.slither import Slither
from slither.core.declarations import SolidityFunction
from slither.slithir.operations import SolidityCall
function_visibility = ['public', 'external']
def split_str_get_sign(variable):
    # contract.property/function_name
    return variable.split('.')[1]

def is_nonReentrant(target_object):
    if hasattr(target_object, "is_reentrant") and not target_object.is_reentrant:
        return True
    if hasattr(target_object, "internal_calls"):
        for internal_call in target_object.internal_calls:
            if is_nonReentrant(internal_call):
                return True
    return False

def find_read_write_variable_in_internal_calls(internal_calls, storage_read, storage_write, state_in_contract, origin_function):
    total_function_read = []
    total_function_write = []
    for internal_call in internal_calls:
        res = find_read_write_variable(internal_call, storage_read, storage_write, state_in_contract, origin_function)
        total_function_read.extend(res[0])
        total_function_write.extend(res[1])
        if hasattr(internal_call, "internal_calls"):
            res = find_read_write_variable_in_internal_calls(internal_call.internal_calls, storage_read, storage_write, state_in_contract, origin_function)
            total_function_read.extend(res[0])
            total_function_write.extend(res[1])
    return [total_function_read, total_function_write]

def find_read_write_variable(function, storage_read, storage_write, state_in_contract, origin_function=None):
    temp_function_read = []
    temp_function_write = []

    if hasattr(function, 'state_variables_read'):
        read = function.state_variables_read
    else: 
        info(f'function {function.name} has no attribute state_variables_read')
        read = []
    if hasattr(function, 'state_variables_written'):
        write = function.state_variables_written
    else: 
        info(f'function {function.name} has no attribute state_variables_written')
        write = []
    
    for read_variable in read:
        if read_variable.is_constant or read_variable.is_immutable:
            info(f'Read: variable {read_variable} is constant or immutable')
            continue
        if read_variable not in state_in_contract:
            info(f'SmartReco right now not support for cross contract analysis')
            continue
        read_variable_str = read_variable.name

        if not read_variable_str in storage_read:
            storage_read[read_variable_str] = []

        temp_function_read.append(read_variable)
        if origin_function:
            if is_function_need_record(origin_function):
                storage_read[read_variable_str].append(origin_function)
        else:
            if is_function_need_record(function):
                storage_read[read_variable_str].append(function)
    for write_variable in write:
        if write_variable.is_constant or write_variable.is_immutable:
            info(f'Write: variable {write_variable} is constant or immutable')
            continue
        if write_variable not in state_in_contract:
            info(f'SmartReco right now not support for cross contract analysis')
            continue
        write_variable_str = write_variable.name
        if not write_variable_str in storage_write:
            storage_write[write_variable_str] = []
        temp_function_write.append(write_variable)   
        if origin_function: 
            if is_function_need_record(origin_function):
                storage_write[write_variable_str].append(origin_function)
        else:
            if is_function_need_record(function):
                storage_write[write_variable_str].append(function)
    return [temp_function_read, temp_function_write]

def is_function_need_record(function):
    if function.is_empty == None:
        info(f'function {function.canonical_name} is empty')
        return False
    if function.visibility not in function_visibility:
        info(f'function {function.canonical_name} is not visible')
        return False
    if function.pure:
        info(f'function {function.canonical_name} is pure')
        return False
    if function.is_constructor:
        info(f'function {function.canonical_name} is constructor')
        return False
    if function.is_fallback:
        info(f'function {function.canonical_name} is fallback')
        return False
    return True

def is_contract_need_record(contract):
    if contract.contract_kind == "interface" or contract.contract_kind == "library":
        info('contract %s is library or interface' % contract.name)
        return False
    return True

def class_dict_to_str_dict(class_dict):
    temp_dict = {}
    for key_sign in class_dict:
        # key_sign = split_str_get_sign(key)
        temp_dict[key_sign] = []
        for item in class_dict[key_sign]:
            if type(item).__name__ == "StateVariable":
                temp_dict[key_sign].append(item.name)
            else:
                temp_dict[key_sign].append(item.solidity_signature)
        temp_dict[key_sign] = list(set(temp_dict[key_sign]))
    return temp_dict    

def unique_storage_record(storage):
    unique_dict_list = {}
    for key in storage:
        unique_names = set()
        for item in storage[key]:
            if key not in unique_dict_list:
                unique_dict_list[key] = []
            name = item.name
            if name not in unique_names:
                unique_dict_list[key].append(item)
                unique_names.add(name)
    return unique_dict_list

def contain_only_owner_modifier(function, only_owner_modifiers):
    contain_modifier = []
    for modifier in function.modifiers:
        if modifier.solidity_signature in only_owner_modifiers:
            contain_modifier.append(modifier)
    for internal_call in function.internal_calls:
        if type(internal_call).__name__ == 'FunctionContract':
            contain_modifier.extend(contain_only_owner_modifier(internal_call, only_owner_modifiers))
    return contain_modifier

def analysis_modifier_variable(variable):
    try:
        if str(variable.type) == "address":
            return True
        # refer to AChecker
        if type(variable.type).__name__ == 'MappingType':
            from_type = variable.type.type_from
            to_type = variable.type.type_to
            if str(from_type.type) == "address" and str(to_type.type) == "bool":
                return True
            elif str(to_type.type) == "address":
                return True
        return False
    except:
        if type(to_type).__name__ == "MappingType":
            if str(to_type.type_from) == "address" and str(to_type.type_to) == "bool":
                return True
            elif str(to_type.type_to) == "address":
                return True
        return False

def use_msgSender_compare_with_state(expression):
    use_msg_sender_compare = False
    msg_sender_with_local_variable = False
    if str(expression.expression_left) == "msg.sender":
        use_msg_sender_compare = True
        if hasattr(expression.expression_right, "value") and ((type(expression.expression_right.value).__name__ == "LocalVariable" and expression.expression_right.value.location == "memory") or\
            str(expression.expression_left.value) == "tx.origin"):
            msg_sender_with_local_variable = True
            return [use_msg_sender_compare, msg_sender_with_local_variable]
    elif str(expression.expression_right) == "msg.sender":
        use_msg_sender_compare = True
        if hasattr(expression.expression_left, "value") and ((type(expression.expression_left.value).__name__ == "LocalVariable" and expression.expression_left.value.location == "memory") or \
            (type(expression.expression_left).__name__ == "CallExpression") or str(expression.expression_left.value) == "tx.origin"):
            msg_sender_with_local_variable = True
            return [use_msg_sender_compare, msg_sender_with_local_variable]
    return [use_msg_sender_compare, msg_sender_with_local_variable]
def is_only_owner_modifier(modifier):
    contain_msg_sender = False
    contain_state_variable = False
    msg_sender_with_local_variable = False
    # [contain_msg_sender, contain_state_variable]
    res = [False, False, False]
    for read_variable in modifier.variables_read:
        if type(read_variable).__name__ == "StateVariable":
            contain_state_variable = analysis_modifier_variable(read_variable)
        elif str(read_variable) == "msg.sender":
            use_msg_sender_compare = False
            for node in modifier.nodes:
                # when msg.sender is used to compare with local variable, it is not dapp access control
                if type(node.expression).__name__ == "BinaryOperation":
                    [use_msg_sender_compare, msg_sender_with_local_variable] = use_msgSender_compare_with_state(node.expression)
                elif type(node.expression).__name__ == "CallExpression":
                    for argument in node.expression.arguments:
                        if type(argument).__name__ == "BinaryOperation":
                            [use_msg_sender_compare, msg_sender_with_local_variable] = use_msgSender_compare_with_state(argument)
            if use_msg_sender_compare:
                contain_msg_sender = True
    for internal_call in modifier.internal_calls:
        if type(internal_call).__name__ == "SolidityFunction":
            continue
        if type(internal_call).__name__ == "FunctionContract":
            res = is_only_owner_modifier(internal_call)
            contain_msg_sender = contain_msg_sender or res[0]
            contain_state_variable = contain_state_variable or res[1]
            msg_sender_with_local_variable = msg_sender_with_local_variable or res[2]
    if len(modifier.external_calls_as_expressions) > 0:
        contain_state_variable = True
    return [contain_msg_sender, contain_state_variable, msg_sender_with_local_variable]

def find_target_contract(target_contract_name, contracts):
    for contract in contracts:
        if contract.name == target_contract_name:
            return contract
    raise ValueError(f"Can not find {target_contract_name}")

def is_input_verify(function):
    require_or_assert = [
        SolidityFunction("assert(bool)"),
        SolidityFunction("require(bool)"),
        SolidityFunction("require(bool,string)"),
    ]
    require = function.all_slithir_operations()
    require = [
        ir
        for ir in require
        if isinstance(ir, SolidityCall) and ir.function in require_or_assert
    ]
    require = [ir.node for ir in require]
    expressions = [str(m.expression) for m in set(require)]
    parameters = [function.parameters[i] for i in range(len(function.parameters))]
    verified = 0
    need_verified = 0
    for parameter in parameters:
        type_str = str(parameter.type)
        if "int" not in type_str and "bool" not in type_str and "string" not in type_str:
            need_verified += 1
        else:
            continue
        for expression in expressions:
            if str(parameter) in expression:
                verified += 1
                break
    if verified == need_verified:
        return 1
    else:
        return 0

def analyze_contracts(contract_path, address, output_dir, base_output_path, version, origin_contract, vyper_path=""):
    try:
        info("Slither: Analysing start: %s" % address)

        file_path = f"{output_dir}/static_analysis_{address}.json"
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                content = file.readlines()
                if "no source code" in content[0]:
                    return False
            info("Contract %s is already analyzed" % address)
            return True       

        os.makedirs(output_dir, exist_ok=True)

        # Initialize Slither
        index = random.randint(1, 100) % len(eth_key)
        if "bscscan" in endpoint[-1]:
            slither_obj = Slither("bsc:" + address, bscan_api_key=eth_key[index], etherscan_only_source_code=True) if vyper_path == "" else\
            Slither(contract_path, bscan_api_key=eth_key[index], compile_force_framework="vyper", vyper=vyper_path, etherscan_only_source_code=True)
        elif "arbiscan" in endpoint[-1]:
            slither_obj = Slither("arbi:" + address, arbiscan_api_key=eth_key[index], etherscan_only_source_code=True) if vyper_path == "" else\
            Slither(contract_path, arbiscan_api_key=eth_key[index], compile_force_framework="vyper", vyper=vyper_path, etherscan_only_source_code=True)
        else:
            slither_obj = Slither(address, etherscan_api_key=eth_key[index], etherscan_only_source_code=True) if vyper_path == "" else\
            Slither(contract_path, etherscan_api_key=eth_key[index], compile_force_framework="vyper", vyper=vyper_path, etherscan_only_source_code=True)

        # get the contract name, as there may be more than one contract in a source code
        keys = list(slither_obj.crytic_compile.compilation_units.keys())
        if vyper_path == "":
            # solidity
            target_contract_name = keys[0] if len(keys) == 1 else slither_obj.contracts[-1].name
        else:
            # as vyper has only one contract, no need to analyze
            target_contract_name = slither_obj.contracts[-1].name
        target_contract = find_target_contract(target_contract_name, slither_obj.contracts)
        function_read = {}
        storage_read = {}
        function_write = {}
        storage_write = {}
        only_owner_modifiers = {}
        only_owner_function = {}
        nonReentrant = {}
        verify_input = {}

        for modifier in target_contract.modifiers:
            modifier_str = str(modifier.solidity_signature)
            if modifier_str in only_owner_modifiers:
                continue
            result = is_only_owner_modifier(modifier)

            if result[0] and result[1] and not result[2]:
                only_owner_modifiers[modifier_str] = [modifier]
        for function in target_contract.functions:
            if not is_function_need_record(function):
                continue
            function_str = str(function.solidity_signature)

            function_read[function_str] = []
            function_write[function_str] = []
            only_owner_function[function_str] = []

            # if input is verified
            verify_input[function_str] = is_input_verify(function)

            # if function contains only owner modifier
            only_owner_function[function_str].extend(contain_only_owner_modifier(function, only_owner_modifiers))            
            
            [function_read[function_str], function_write[function_str]] = find_read_write_variable(function, storage_read, storage_write, target_contract.state_variables_ordered)
            [internal_read, internal_write] = find_read_write_variable_in_internal_calls(function.internal_calls, storage_read, storage_write, target_contract.state_variables_ordered, function)
            for internal_read_variable in internal_read:
                function_read[function_str].append(internal_read_variable)
            for internal_write_variable in internal_write:
                function_write[function_str].append(internal_write_variable)
            function_read[function_str] = list(set(function_read[function_str]))
            function_write[function_str] = list(set(function_write[function_str]))
            nonReentrant[function_str] = 1 if is_nonReentrant(function) else 0

        storage_read_unique = unique_storage_record(storage_read)
        storage_write_unique = unique_storage_record(storage_write)

        total_storage = {}
        total_storage['function_read'] = class_dict_to_str_dict(function_read)
        total_storage['function_write'] = class_dict_to_str_dict(function_write)
        total_storage['storage_read_unique'] = class_dict_to_str_dict(storage_read_unique)
        total_storage['storage_write_unique'] = class_dict_to_str_dict(storage_write_unique)
        total_storage['only_owner_function'] = class_dict_to_str_dict(only_owner_function)
        total_storage['only_owner_modifiers'] = class_dict_to_str_dict(only_owner_modifiers)
        total_storage['non_Reentrant'] = nonReentrant
        total_storage["verified_input"] = verify_input
        with open(file_path, 'w') as file:
            json.dump(total_storage, file)
        return True
    except Exception as e:
        err_info = f"Contract {address} analyzed failed due to {e}\n"
        if "Contract has no public source code" in err_info:
            info(err_info)
            with open(file_path, 'w') as file:
                json.dump({"error": "no source code"}, file)
                return False
        handle_err(err_info, base_output_path, origin_contract, address)
        traceback.print_exc()
        return False

def solidity_analysis(base_output_path, output_path, contract_address, solc_version, origin_contract):
    contract_path = f"{output_path}/source_code"
    return analyze_contracts(contract_path, contract_address, output_path, base_output_path, solc_version, origin_contract)

def vyper_analysis(base_output_path, output_path, contract_address, vyper_version, origin_contract, vyper_storage_path):
    # use vvm to set right vyper_version
    vvm.set_vyper_version(vyper_version)
    executable_path = str(vvm.install.get_executable())
    return analyze_contracts(vyper_storage_path, contract_address, output_path, base_output_path, vyper_version, origin_contract, executable_path)

def analysis_with_slither(base_output_path, output_path, contract_address, origin_contract, compile_version="", contract_type=".sol", vyper_storage_path=""):
    if contract_type == '.sol':
        return solidity_analysis(base_output_path, output_path, contract_address, compile_version, origin_contract)
    else:
        return vyper_analysis(base_output_path, output_path, contract_address, compile_version, origin_contract, vyper_storage_path)

def is_only_owner_function(contract_address, fun_name, output_dir):
    static_cache_path = f"{output_dir}/static_analysis_{contract_address}.json"
    with open(static_cache_path, "r") as file:
        static_result = json.load(file)
    if fun_name in static_result["only_owner_function"] and len(static_result["only_owner_function"][fun_name]) > 0:
            return True
    else:
        return False
def is_verified_input(contract_address, function_name, output_dir, function_abis, base_output_path):
    static_cache_path = f"{output_dir}/static_analysis_{contract_address}.json"
    with open(static_cache_path, "r") as file:
        static_result = json.load(file)
    verified_input = static_result["verified_input"]
    if function_name in verified_input:
            return verified_input[function_name]
    else:
        # case: 0x97a49f8eec63c0dfeb9db4c791229477962dc692 
        # getReservePoolBps() is in abi but actually is not initialized
        return 0

def find_implicit_dependency(contract_address, fun_sign, output_dir, function_abis, base_output_path):
    static_cache_path = f"{output_dir}/static_analysis_{contract_address}.json"
    with open(static_cache_path, "r") as file:
        static_result = json.load(file)
    function_read = static_result["function_read"]
    # function_write = static_result["function_write"]
    # storage_read = static_result["storage_read_unique"]
    storage_write = static_result["storage_write_unique"]
    only_owner_function = static_result["only_owner_function"]
    non_Reentrancy = static_result["non_Reentrant"]

    if fun_sign in function_abis:
        function_name = function_abis[fun_sign]
        if function_name in function_read:
            target_strorages = function_read[function_name]
        else:
            # case: 0x97a49f8eec63c0dfeb9db4c791229477962dc692 
            # getReservePoolBps() is in abi but actually is not initialized
            return [], function_name
    else:
        # transfer, and fun_sign=0x00000000
        # function_name = "fallback()"
        return [], "fallback"
    implicit_dependency = []

    for storage in target_strorages:
        if storage not in storage_write:
            # e.g., storage is set in constructor and never changed
            continue
        for write_fun in storage_write[storage]:
            # it is protected by modifier
            if only_owner_function[write_fun]:
                continue
            # or if target function and implicit function both have nonReentrant, it is no need for test
            if (non_Reentrancy[write_fun] and non_Reentrancy[function_name]) or write_fun == function_name:
                continue
            implicit_dependency.append(write_fun)
    
    return list(set(implicit_dependency)), function_name