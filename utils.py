import re

from electroncash.address import UnknownAddress
from electroncash import transaction, token, bitcoin


def extract_hex_from_libauth_extended_json_string(s):
    hex_regex = r'0x[0-9a-f-A-F]+'

    match = re.search(hex_regex, s)
    if match:
        return match.group(0)

def extract_bigint_from_libauth_extended_json_string(s):
    bigint_regex = r'[0-9]+'

    match = re.search(bigint_regex, s)
    if match:
        return match.group(0)


def generate_electron_cash_tx_from_libauth_format(tx_data, wallet):

    transaction_data = tx_data['transaction']
    source_outputs_data = tx_data['sourceOutputs']

    ec_inputs = list()
    ec_inputs_bytes = list()
    for index, item in enumerate(transaction_data['inputs']):
        prevout_hash = extract_hex_from_libauth_extended_json_string(item['outpointTransactionHash'])
        prevout_hash = prevout_hash[2:] if prevout_hash.startswith('0x') else prevout_hash
        script_sig = extract_hex_from_libauth_extended_json_string(item['unlockingBytecode'])


        address = None
        locking_byte_code = extract_hex_from_libauth_extended_json_string(
            source_outputs_data[index]['lockingBytecode'])
        locking_byte_code = locking_byte_code[2:] if locking_byte_code.startswith('0x') else locking_byte_code
        type, possible_address = transaction.get_address_from_output_script(bytes.fromhex(locking_byte_code))
        if type in [bitcoin.TYPE_ADDRESS, bitcoin.TYPE_PUBKEY]:
            address = possible_address

        if script_sig:
            script_sig = script_sig[2:] if script_sig.startswith('0x') else script_sig
        else:
            script_sig = None
        ec_input = {
            'prevout_n': item['outpointIndex'],
            'prevout_hash': prevout_hash,
            'sequence': item['sequenceNumber'],
            'scriptSig': script_sig,
            'address':  address if address else UnknownAddress(),
            'type': 'unknown',
            'x_pubkeys': [],
            'pubkeys': [],
            'signatures': {},
        }

        if script_sig:
            try:
                script_sig_data = {}
                transaction.parse_scriptSig(script_sig_data, bytes.fromhex(script_sig))
                ec_input['type'] = script_sig_data['type']
                ec_input['signatures'] = script_sig_data['signatures']
                ec_input['num_sig'] = script_sig_data['num_sig']
            except Exception as e:
                ec_input['num_sig'] = 0
                print(e)
                print("could not parse script sig index:", index)
        if not script_sig:
            wallet.add_input_sig_info(ec_input, ec_input['address'])
            ec_input['pubkeys'] = wallet.get_public_keys(ec_input['address'])
            ec_input['type'] = wallet.get_txin_type(ec_input['address'])

        ec_inputs.append(ec_input)

        input_bytes = b''

        prevout_hash_arr = bytearray.fromhex(prevout_hash)
        prevout_hash_arr.reverse()
        prevout_hash_byte = bytes(prevout_hash_arr)
        # input_bytes += bytes.fromhex(prevout_hash)
        input_bytes += prevout_hash_byte

        input_bytes += bitcoin.int_to_bytes(item['outpointIndex'], 4)
        input_bytes += bitcoin.var_int_bytes(len(bytes.fromhex(script_sig if script_sig else '')))
        input_bytes += bytes.fromhex(script_sig if script_sig else '')
        input_bytes += bitcoin.int_to_bytes(item['sequenceNumber'], 4)

        ec_inputs_bytes.append(input_bytes)

    ec_outputs = list()
    ec_outputs_bytes = list()
    token_data_list = list()
    for item in transaction_data['outputs']:
        locking_bytecode = extract_hex_from_libauth_extended_json_string(item['lockingBytecode'])
        locking_bytecode = locking_bytecode[2:] if locking_bytecode.startswith('0x') else locking_bytecode

        item['valueSatoshis'] = extract_bigint_from_libauth_extended_json_string(item['valueSatoshis'])
        value = int(item['valueSatoshis'][:-1]) if item['valueSatoshis'].endswith('n') else int(item['valueSatoshis'])

        address = transaction.get_address_from_output_script(bytes.fromhex(locking_bytecode))
        ec_output = address + (value,)
        ec_outputs.append(ec_output)

        output_bytes = b''
        output_bytes += bitcoin.int_to_bytes(value, 8)

        amount = None
        if 'token' in item.keys():
            item['token']['category'] = extract_hex_from_libauth_extended_json_string(item['token']['category'])
            category_id = item['token']['category']
            category_id = category_id[2:] if category_id.startswith('0x') else category_id
            category_id_arr = bytearray.fromhex(category_id)
            category_id_arr.reverse()
            category_id = bytes(category_id_arr)

            bitfield = 0
            if 'amount' in item['token'].keys():
                item['token']['amount'] = extract_bigint_from_libauth_extended_json_string(item['token']['amount'])
                amount = item['token']['amount']
                amount = int(amount) if amount.endswith('n') else int(amount)
                if amount and amount > 0:
                    bitfield |= token.Structure.HasAmount

            commitment = b''
            if 'nft' in item['token'].keys():
                bitfield |= token.Structure.HasNFT
                commitment = item['token']['nft'].get('commitment')
                commitment = commitment.encode() if commitment else b''

                capability = item['token']['nft'].get('capability')

                if not capability or capability == 'none':
                    bitfield |= token.Capability.NoCapability
                elif capability == 'mutable':
                    bitfield |= token.Capability.Mutable
                elif capability == 'minting':
                    bitfield |= token.Capability.Minting

                if commitment and len(commitment) > 0:
                    bitfield |= token.Structure.HasCommitmentLength

            token_output_data = token.OutputData(category_id, amount, commitment, bitfield)
            token_data_list.append(token_output_data)

            wrapped_locking_bytecode = token.wrap_spk(token_output_data, bytes.fromhex(locking_bytecode))
            output_bytes += bitcoin.var_int_bytes(len(wrapped_locking_bytecode))
            output_bytes += wrapped_locking_bytecode
        else:
            token_data_list.append(None)
            output_bytes += bitcoin.var_int_bytes(len(bytes.fromhex(locking_bytecode)))
            output_bytes += bytes.fromhex(locking_bytecode)
        ec_outputs_bytes.append(output_bytes)

    # for index, input_item in enumerate(source_outputs_data['inputs']):
    #     outpoint_transaction_hash = input_item['outpointTransactionHash']
    #     unlocking_bytecode = input_item['unlockingBytecode']
    #     locking_bytecode = input_item['lockingBytecode']
    #     value_satoshis = input_item['valueSatoshis']
    #
    #     token_amount = input_item['token']['amount']
    #     token_category = input_item['token']['category']


    locktime = transaction_data['locktime']
    version = transaction_data['version']

    ec_tx_bytes = b''
    ec_tx_bytes += bitcoin.int_to_bytes(version, 4)
    ec_tx_bytes += bitcoin.var_int_bytes(len(ec_inputs_bytes))
    for tx_input in ec_inputs_bytes:
        # b_arr = bytearray(tx_input)
        # b_arr.reverse()
        # ec_tx_bytes += bytes(b_arr)
        ec_tx_bytes += bytes(tx_input)
    ec_tx_bytes += bitcoin.var_int_bytes(len(ec_outputs_bytes))
    for tx_output in ec_outputs_bytes:
        # b_arr = bytearray(tx_output)
        # b_arr.reverse()
        # ec_tx_bytes += bytes(b_arr)
        ec_tx_bytes += bytes(tx_output)
    ec_tx_bytes += bitcoin.int_to_bytes(locktime, 4)

    print("generated raw tx: ", ec_tx_bytes.hex())

    ec_tx = transaction.Transaction.from_io(
        inputs=ec_inputs, outputs=ec_outputs, locktime=locktime, token_datas=token_data_list, version=version)
    ec_tx._sign_schnorr = True
    return ec_tx
