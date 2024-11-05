# analyze and collect the dapp infomation
import csv
from lib import *

def get_file_path(folder_path):
    files_info = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file != "address.txt":
                continue
            file_path = os.path.join(root, file)
            file_info = {
                'file_path': file_path,
                'dapp_name': root.replace('./dataset/collect_dapp_address/', ''),
            }
            files_info.append(file_info)
    return files_info

# creator may belong to more than one dapp, as dapp can have many versions
# we need to hanle this situation
def unique_dapp_information(dapp_set):
    creator_to_dapp = {}
    dapp_to_creator = {}
    dapp_to_new_name = {}
    unique_creator_to_dapp = set()
    for i in range(len(dapp_set)):
        creator = dapp_set[i][0]
        dapp = dapp_set[i][1]

        if creator in creator_to_dapp:
            creator_to_dapp[creator].append(dapp)
        else:
            creator_to_dapp[creator] = [dapp]
        if dapp in dapp_to_creator:
            dapp_to_creator[dapp].append(creator)
        else:
            dapp_to_creator[dapp] = [creator]
    for creator, dapps in creator_to_dapp.items():
        dapps.sort()    
        temp_store_creator = []
        compose_dapp_name = "&".join(dapps)
        for dapp in dapps:
            if dapp in dapp_to_new_name:
                old_compose_dapp_name = dapp_to_new_name[dapp]
                dapps.extend(old_compose_dapp_name.split("&"))
                dapps = list(set(dapps))
                dapps.sort()
                compose_dapp_name = "&".join(dapps)
                temp_store_creator = dapp_to_creator[old_compose_dapp_name]
                del dapp_to_creator[old_compose_dapp_name]
                break
        for dapp in dapps:
            if dapp in dapp_to_creator:
                temp_store_creator.extend(dapp_to_creator[dapp])
                if len(dapps) > 1:
                    dapp_to_new_name[dapp] = compose_dapp_name
                del dapp_to_creator[dapp]

        if len(temp_store_creator) > 0:
            dapp_to_creator[compose_dapp_name] = list(set(temp_store_creator))
    for dapp, creators in dapp_to_creator.items():
        for creator in creators:
            unique_creator_to_dapp.add((creator, dapp))
    return unique_creator_to_dapp


if __name__ == "__main__":
    folder_path = '../data/collect_dapp_address'
    base_path = "./record_data/cache"
    network = "ETH"
    endpoint.append(get_endpoint(network))

    files_path = get_file_path(folder_path)
    dapp_set = set()
    i = 0
    count = 0
    total_address = []
    for file_path in files_path:
        with open(file_path["file_path"], 'r') as file:
            line = file.readline()
            while line:
                address = line.strip().lower()
                total_address.append(address)
                count += 1
                print(count)
                print(address, file_path['dapp_name'].split("/")[-1])

                response_json = get_creator_info(address, file_path, base_path)
                i = 0     
                for i in range(0, 5): 
                    if response_json["result"] == None:
                        print(f'Error: {line.strip()}')
                        dapp_set.add((line.strip(), file_path['dapp_name'].split("/")[-1]))
                        break
                    res = get_internal_tx_info(response_json, file_path, address, base_path)

                    if not res[0]:
                        dapp_set.add(res[1])
                        break
                    else:
                        address = res[1][0]
                        response_json = get_creator_info(address, file_path, base_path)
                if i == 5:
                    print("Error!")
                line = file.readline()
    dapp_set = list(dapp_set)
    print(f"total count: {count}")
    with open("../data/data_unique.csv", 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['creatorAddress', 'dappName'])
        writer.writerows(dapp_set)
    dapp_set = unique_dapp_information(dapp_set)
    dapp_set = sorted(list(dapp_set), key=lambda x: x[1])
    with open("../data/data.csv", 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['creatorAddress', 'dappName'])
        writer.writerows(dapp_set)