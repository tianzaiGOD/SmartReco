# generate input with type
import random
import string
from web3 import Web3
import eth_abi

def gen_bool():
    options = [True, True, False]
    return random.choice(options)


def gen_uint(length):
    value = 0
    if length == 0 or length == 256:
        value = random.randint(0, 2**256)
    elif length == 128:
        value = random.randint(0, 2**128)
    elif length == 64:
        value = random.randint(0, 2**64)
    elif length == 32:
        value = random.randint(0, 2**32)
    else:
        value = random.randint(0, 2**length-1)
    return random.choice([0, value, value])


def gen_int(length):
    value = 0
    if length == 0 or length == 256:
        value = random.randint(-2**255, 2**255)
    elif length == 128:
        value = random.randint(-2**127, 2**127)
    elif length == 64:
        value = random.randint(-2**63, 2**63)
    elif length == 32:
        value = random.randint(-2**31, 2**31)
    else:
        value = random.randint(-2**(length-1)-1, 2**(length-1)-1)
    return random.choice([0, value, value])

def gen_bytes(length):
    value = ""
    if length == 0:
        length = random.randrange(1,30,1)
    options = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    for i in range(length*2):
        Nullbytes = random.choice([True, False, False])
        if Nullbytes:
            value = value + '0'
        else:
            value = value + (random.choice(options))
    return bytes.fromhex(value)

def gen_address(addressArray):
    options = addressArray
    if len(addressArray) == 0:
        options = ['0x96780224CB07A07C1449563C5dfc8500fFa0Ea2A', '0xf97DdC7b1836c7bb14cD907EF9845A6c028428f4']
    choice = random.choice(options)
    # return Web3.toChecksumAddress(choice)
    return choice


def gen_array(type, length, addressArray):
    array = []
    if length == 0:
        length = random.randint(2, 10)

    data_type = ''
    data_length = ''

    for i in range(len(type)):
        if type[i].isdigit():
            data_length = data_length + type[i]
        else:
            data_type = data_type + type[i]
    #print(data_type)
    #print(int(data_length))

    #data_length = int(data_length)

    if data_length == '':
        data_length = 256
    else:
        data_length = int(data_length)

    for i in range(length):
        if data_type == 'uint':
            array.append(gen_uint(data_length))

        elif data_type == 'int':
            array.append(gen_int(data_length))

        elif data_type == 'bool':
            array.append(gen_bool())

        elif data_type == 'address':
            array.append(gen_address(addressArray))

        elif data_type == 'bytes':
            array.append(gen_bytes(data_length))

    return array


def gen_string():
    #if length == 0:
    length = random.randint(1, 10)
    letters = string.ascii_letters
    toReturn = ''.join(random.choice(letters) for i in range(length))
    returnthis = random.choice(["", "", toReturn])
    return returnthis

def gen_value():
    return random.randint(10000000000000000000, 100000000000000000000)

def gen_tuple(input_type, addressArray):
    actual_input_types = input_type[1:-1].split(",")
    input_seq = []
    internal_tuple = "("
    for actual_input_type in actual_input_types:
        if actual_input_type.startswith("("):
            internal_tuple  = internal_tuple + actual_input_type[1:] + "," 
        elif len(internal_tuple) > 1:
            if actual_input_type[-1] == ")":
                internal_tuple  = internal_tuple + actual_input_type 
                input_seq.extend(gen_input(internal_tuple, addressArray))
                internal_tuple = "("
            elif actual_input_type.endswith(")[]"):
                internal_tuple  = internal_tuple + actual_input_type 
                array_length = random.randint(1, 5)
                for i in range(array_length):
                    input_seq.append(gen_tuple(internal_tuple, addressArray))
                internal_tuple = "("
            else:
                internal_tuple  = internal_tuple + actual_input_type + ","
        else:
            input_seq.extend(gen_input(actual_input_type, addressArray))
    return input_seq

def gen_input(input_type, addressArray):
    input_seq = []
    if input_type[0] == "(" and input_type.endswith(")[]"):
        array_length = random.randint(1, 5)
        cache = []
        for i in range(array_length):
            cache.append(gen_tuple(input_type[:-2], addressArray))
        input_seq.append(cache)
    elif input_type[0] == "(" and input_type[-1] == ")":
        input_seq.append(gen_tuple(input_type, addressArray))
    else:
        data_type = ''
        data_length = ''

        inp = input_type.split('[')[0]
        array_length = 0

        try:
            #print(inp)
            if input_type[-1] == ']':
                array_length = input_type.split('[')[1]
                if array_length == ']':
                    array_length = random.randint(1, 5)
                else:
                    array_length = int(array_length[:-1])
                #print(array_length)
        except Exception as e:
            print(e)

        for i in range(len(inp)):
            if inp[i].isdigit():
                data_length = data_length + inp[i]
            else:
                data_type = data_type + inp[i]
        if array_length == 0:
            if data_length == '':
                data_length = 0
            else:
                data_length = int(data_length)

            if data_type == 'uint':
                input_seq.append(gen_uint(data_length))

            elif data_type == 'int':
                input_seq.append(gen_int(data_length))

            elif data_type == 'bool':
                input_seq.append(gen_bool())

            elif data_type == 'address':
                input_seq.append(gen_address(addressArray))

            elif data_type == 'string':
                input_seq.append(gen_string())

            elif data_type == 'bytes':
                input_seq.append(gen_bytes(data_length))
        else:
            input_seq.append(gen_array(inp,array_length, addressArray))
    return input_seq

def random_change(input):
    if len(input) <= 10:
        # no args
        return input
    options = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    new_input = input[:10]

    for i in range(len(input) - 10):
        if input[i + 10] == '0':
            new_input += input[i + 10]
        elif random.random() <= 0.5:
            new_input += random.choice(options)
        else:
            new_input += input[i + 10]
    return new_input