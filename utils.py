import re

from electroncash.address import UnknownAddress, Address
from electroncash import transaction, token, bitcoin, util

from .transaction import TransactionWithSighashUTXOS


def extract_hex_from_libauth_extended_json_string(s):
    hex_regex = r'0x[0-9a-f-A-F]+'

    match = re.search(hex_regex, s)
    if match:
        group = match.group(0)
        group = group[2:] if group.startswith('0x') else group
        return group

def extract_bigint_from_libauth_extended_json_string(s):
    bigint_regex = r'[0-9]+'

    match = re.search(bigint_regex, s)
    if match:
        group = match.group(0)
        group = group[:-1] if group.endswith('n') else group
        return group

def generate_electron_cash_tx_from_libauth_format(tx_data, wallet, wallet_connect_address, password):

    transaction_data = tx_data['transaction']
    source_outputs_data = tx_data['sourceOutputs']

    ec_inputs = list()
    ec_inputs_bytes = list()
    for index, item in enumerate(transaction_data['inputs']):
        prevout_hash = extract_hex_from_libauth_extended_json_string(item['outpointTransactionHash'])
        script_sig = extract_hex_from_libauth_extended_json_string(item['unlockingBytecode'])

        # in case of empty script_sig, first check if it's a contract and the contract contains the script_sig
        if not script_sig and ('contract' in source_outputs_data[index].keys() and
                source_outputs_data[index]['contract']['artifact']['contractName']):
            script_sig = extract_hex_from_libauth_extended_json_string(source_outputs_data[index]['unlockingBytecode'])


        address = None
        locking_bytecode = extract_hex_from_libauth_extended_json_string(
            source_outputs_data[index]['lockingBytecode'])
        type, possible_address = transaction.get_address_from_output_script(bytes.fromhex(locking_bytecode))
        if type in [bitcoin.TYPE_ADDRESS, bitcoin.TYPE_PUBKEY]:
            address = possible_address

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
            'walletconnect_locking_bytecode': locking_bytecode
        }

        token_output_data = None
        if 'token' in source_outputs_data[index].keys():
            token_output_data = generate_token_data_output_from_token_dict(source_outputs_data[index]['token'])
            ec_input['token_data'] = token_output_data
        ec_input['walletconnect_locking_bytecode'] = token.wrap_spk(
                token_output_data, bytes.fromhex(locking_bytecode)).hex()

        value = extract_bigint_from_libauth_extended_json_string(source_outputs_data[index]['valueSatoshis'])
        value = int(value)
        ec_input['value'] = value

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

        item['valueSatoshis'] = extract_bigint_from_libauth_extended_json_string(item['valueSatoshis'])
        value = int(item['valueSatoshis'])

        address = transaction.get_address_from_output_script(bytes.fromhex(locking_bytecode))
        ec_output = address + (value,)
        ec_outputs.append(ec_output)

        output_bytes = b''
        output_bytes += bitcoin.int_to_bytes(value, 8)

        if 'token' in item.keys():
            token_output_data = generate_token_data_output_from_token_dict(item['token'])
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

    for index, input in enumerate(ec_tx.inputs()):
        sig_placeholder = "41" + bytearray(65).hex()
        pubkey_placeholder = "21" + bytearray(33).hex()

        address = Address.from_string(wallet_connect_address)
        priv_key = wallet.export_private_key(address, password)
        if input['scriptSig'] and input['scriptSig'].find(sig_placeholder) != -1:
            source_output = source_outputs_data[index]
            assert "contract" in source_output.keys()
            assert "redeemScript" in source_output['contract'].keys()
            redeem_script = source_output['contract']['redeemScript']
            redeem_script = extract_hex_from_libauth_extended_json_string(redeem_script)
            input['scriptCode'] = redeem_script

            ec_tx.__class__ = TransactionWithSighashUTXOS
            hash_type = 0x1 | 0x40 | 0x20 # SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS # Consistency
            type, priv_key, _ = bitcoin.deserialize_privkey(priv_key)
            pre_hash = bitcoin.Hash(ec_tx.serialize_preimage_bytes(index, hash_type))
            sig = ec_tx._schnorr_sign(bitcoin.public_key_from_private_key(priv_key, True), priv_key, pre_hash)
            sig = '41' + util.bh2u(sig + bytes((hash_type & 0xff,)))
            input['scriptSig'] = input['scriptSig'].replace(sig_placeholder, sig)
            ec_tx.__class__ = transaction.Transaction

        if input['scriptSig'] and input['scriptSig'].find(pubkey_placeholder) != -1:
            pubkey = '21' + bitcoin.public_key_from_private_key(priv_key, True)
            input['scriptSig'] = input['scriptSig'].replace(pubkey_placeholder, pubkey)

    return ec_tx



def generate_token_data_output_from_token_dict(token_dict):
    token_dict['category'] = extract_hex_from_libauth_extended_json_string(token_dict['category'])
    category_id = token_dict['category']
    category_id_arr = bytearray.fromhex(category_id)
    category_id_arr.reverse()
    category_id = bytes(category_id_arr)

    amount = None
    bitfield = 0
    if 'amount' in token_dict.keys():
        token_dict['amount'] = extract_bigint_from_libauth_extended_json_string(token_dict['amount'])
        amount = int(token_dict['amount'])
        if amount and amount > 0:
            bitfield |= token.Structure.HasAmount

    commitment = b''
    if 'nft' in token_dict.keys():
        bitfield |= token.Structure.HasNFT
        commitment = token_dict['nft'].get('commitment')
        commitment = extract_hex_from_libauth_extended_json_string(commitment) if commitment else None
        commitment = bytes.fromhex(commitment) if commitment else b''

        capability = token_dict['nft'].get('capability')

        if not capability or capability == 'none':
            bitfield |= token.Capability.NoCapability
        elif capability == 'mutable':
            bitfield |= token.Capability.Mutable
        elif capability == 'minting':
            bitfield |= token.Capability.Minting

        if commitment and len(commitment) > 0:
            bitfield |= token.Structure.HasCommitmentLength

    token_output_data = token.OutputData(category_id, amount, commitment, bitfield)

    return token_output_data