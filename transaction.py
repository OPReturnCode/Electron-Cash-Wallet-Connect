from electroncash import token
from electroncash.util import *
from electroncash.bitcoin import *
from electroncash.transaction import Transaction, InputValueMissing


# The EC Transaction class does not support SIGHASH_UTXOS
class TransactionWithSighashUTXOS(Transaction):

    def get_hash_utxos(self):
        buf = b''
        for i in self.inputs():
            script_bytes = bfh(i['walletconnect_locking_bytecode'])
            buf += int_to_bytes(i['value'], 8)
            buf += var_int_bytes(len(script_bytes))
            buf += script_bytes
        return Hash(buf)

    # This method is taken and edited from electroncash/transaction.py from the official Electron Cash project repo at
    # https://github.com/Electron-Cash/Electron-Cash
    def serialize_preimage_bytes(self, i, nHashType=0x00000041, use_cache=False) -> bytes:
        """ See `.calc_common_sighash` for explanation of use_cache feature """

        if (nHashType & 0xff) != 0x61:
            raise ValueError("other hashtypes not supported.")

        nVersion = int_to_bytes(self.version, 4)
        nHashType = int_to_bytes(nHashType, 4)
        nLocktime = int_to_bytes(self.locktime, 4)

        txin = self.inputs()[i]
        outpoint = self.serialize_outpoint_bytes(txin)
        preimage_script = bfh(self.get_preimage_script(txin))
        input_token = txin.get('token_data')
        if input_token is not None:
            serInputToken = token.PREFIX_BYTE + input_token.serialize()
        else:
            serInputToken = b''
        scriptCode = var_int_bytes(len(preimage_script)) + preimage_script
        try:
            amount = int_to_bytes(txin['value'], 8)
        except KeyError:
            raise InputValueMissing
        nSequence = int_to_bytes(txin.get('sequence', 0xffffffff - 1), 4)

        hashPrevouts, hashSequence, hashOutputs = self.calc_common_sighash(use_cache=use_cache)
        hashUtxos = self.get_hash_utxos()

        preimage = (nVersion + hashPrevouts + hashUtxos + hashSequence + outpoint + serInputToken + scriptCode + amount + nSequence
                    + hashOutputs + nLocktime + nHashType)
        print("preimage: ", nVersion.hex(), hashPrevouts.hex(), hashUtxos.hex(), hashSequence.hex(), outpoint.hex(),
              serInputToken.hex(), scriptCode.hex(), amount.hex(), nSequence.hex(), hashOutputs.hex(), nLocktime.hex(),
              nHashType.hex())
        return preimage