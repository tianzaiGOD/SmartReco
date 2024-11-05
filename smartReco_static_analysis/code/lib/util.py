import os
import re
import time

def is_ir_call(ir):
    if ir == 'LowLevelCall':
        return True
    elif ir == 'HighLevelCall':
        return True
    elif ir == 'InternalCall':
        return True
    elif ir == 'LibraryCall':
        return True
    elif ir == 'EventCall':
        return True
    elif ir == 'Send':
        return True
    elif ir == 'Transfer':
        return True
    else:
        return False

def extract_parameter_types(signature):
    pattern = r"(.*)\((.*?)\)"
    matches = re.search(pattern, signature)
    if matches:
        parameters = matches.group(2)
        parameter_list = parameters.split(", ")
        parameter_types = []
        for parameter in parameter_list:
            parameter_type = parameter.split(" ")[0]
            parameter_types.append(parameter_type)
        return parameter_types
    else:
        return []
    
def extract_function_name(signature):
    pattern = r"(\w+)\("
    matches = re.search(pattern, signature)
    if matches:
        return matches.group(1)
    return ""

def extract_function_signature(fun_name):
    function_name = extract_function_name(fun_name)
    parameter_types = extract_parameter_types(fun_name)
    return '{}({})'.format(function_name,','.join(parameter_types))


def check_files_with_prefix(directory, prefix):
    if not os.path.exists(directory):
        return []
    file_list = [file for file in os.listdir(directory) if file == prefix]
    return file_list

# change abi data struct to meet expectaions
def handle_abi_data(abi):
    abi_struct = {}
    abi_struct["message"] = "OK"
    abi_struct["result"] = abi
    return abi_struct

def get_contract_type_version(version):
    pattern = r'v\d+\.\d+\.\d+'
    if version.startswith("vyper"):
        contract_type = '.vy'
        compile_version = version.split(':')[1]
    else:
        contract_type = '.sol'
        match = re.search(pattern, version)
        compile_version = match.group() if match else 'latest'
    return [contract_type, compile_version]

def handle_err(err_info, base_path, origin_contract, contract_address):
    folder = f"{base_path}/err_info/{origin_contract}"
    make_dir(folder)
    err_info = err_info if err_info else "None"
    with open(f'{folder}/err_{contract_address}.txt', 'a') as file:
        file.write(err_info)
        file.write("\n")

def create_folder_if_not_exists(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

def make_dir(path):
    folders = []
    while not os.path.isdir(path):
        path, suffix = os.path.split(path)
        folders.append(suffix)
    for folder in folders[::-1]:
        path = os.path.join(path, folder)
        os.mkdir(path)

def make_file(path):
    file = os.path.exists(path)
    if not file:
        suffix, filename = os.path.split(path)
        # print(suffix, filename)
        make_dir(suffix)
        os.mknod(path)

def calculate_run_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        run_time = end_time - start_time
        print(f"Function {func.__name__} execute time: {run_time}s")
        return result
    return wrapper