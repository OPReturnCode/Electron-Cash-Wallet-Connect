import time
import queue
import threading

from pywalletconnect.client import WCClient

from . import utils

WALLET_CONNECT_PROJECT_ID = "2aec5e29ba5caf7514434791e1da60ad"
WALLET_CONNECT_CHAIN_ID = "bitcoincash"
WALLET_CONNECT_NAMESPACE = "bch"

WALLET_CONNECT_METADATA = {
    "name": "Electron Cash Wallet",
    "description": "A Bitcoin Cash SPV Wallet",
    "link": "https://electroncash.org/",
    "icons": [
        "https://raw.githubusercontent.com/Electron-Cash/Electron-Cash/master/icons/electron-cash.svg"
    ]
}


WALLET_CONNECT_SESSION_REQUEST = "wc_sessionRequest"
WALLET_CONNECT_SESSION_EVENT = "wc_sessionEvent"
WALLET_CONNECT_SESSION_DELETE = "wc_sessionDelete"
WALLET_CONNECT_SESSION_PING = "wc_sessionPing"

WALLET_CONNECT_GET_ADDRESSES = "bch_getAddresses"
WALLET_CONNECT_SIGN_TRANSACTION = "bch_signTransaction"
WALLET_CONNECT_SIGN_MESSAGE = "bch_signMessage"

WCClient.set_project_id(WALLET_CONNECT_PROJECT_ID)
WCClient.set_wallet_metadata(WALLET_CONNECT_METADATA)


class WalletConnect:
    def __init__(self, wallet_connect_uri, wallet_address, wallet, proxy_opts):
        # assert proxy_opts is not None

        self.session_data = None
        self.connection_closed = False

        self.wallet_connect_uri = wallet_connect_uri
        self.wallet_address = wallet_address
        self.wallet = wallet
        self.proxy_opts = proxy_opts

        self.wc_client = WCClient.from_wc_uri(self.wallet_connect_uri, socks_opts=self.proxy_opts)
        self.wc_client.wallet_namespace = WALLET_CONNECT_NAMESPACE

        self.task_queue = queue.Queue()
        self.thread = threading.Thread(target=self.get_message)
        self.thread.daemon = True

    def open_session(self):
        print("Connecting to the dApp...")
        self.session_data = self.wc_client.open_session()
        # GET approval from the user for the session after this.
        print(f"Wallet Connect pairing request: {self.session_data}, do you approve?")
        return self.session_data

    def approve_session(self):
        print("You accepted!, sending your address to the server.")
        print(self.wc_client.reply_session_request(self.session_data[0], WALLET_CONNECT_CHAIN_ID, self.wallet_address))
        print("Connected. We're now listening to dApp requests.")
        self.thread.start()

    def get_message(self):
        while not self.connection_closed:
            message_id, method, params = self.wc_client.get_message()

            if message_id is not None:
                print(message_id, method, params)
                # {'request': {'method': 'bch_getAddresses', 'params': {}}, 'chainId': 'bch:bitcoincash'}
                if method == WALLET_CONNECT_SESSION_DELETE:
                    # user requested disconnect
                    print("user requested disconnect")
                    task_data = {
                        "type": WALLET_CONNECT_SESSION_DELETE,
                        "params": params
                    }
                    self.task_queue.put(task_data)
                    self.close_session()
                    break

                elif method == WALLET_CONNECT_SESSION_REQUEST:
                    if params["request"]["method"] == WALLET_CONNECT_GET_ADDRESSES:
                        print(self.wallet_address)
                        self.wc_client.reply(message_id, ["bitcoincash:" + self.wallet_address])

                    elif params["request"]["method"] == WALLET_CONNECT_SIGN_TRANSACTION:
                        tx_data = params['request']['params']
                        ec_tx = utils.generate_electron_cash_tx_from_libauth_format(tx_data, self.wallet)
                        task_data = {
                            "type": WALLET_CONNECT_SIGN_TRANSACTION,
                            "message_id": message_id,
                            "electroncash_tx": ec_tx,
                            "params": params,
                        }
                        self.task_queue.put(task_data)

                    elif params["request"]["method"] == WALLET_CONNECT_SIGN_MESSAGE:
                        task_data = {
                            "type": WALLET_CONNECT_SIGN_MESSAGE,
                            "message_id": message_id,
                            "params": params,
                        }
                        self.task_queue.put(task_data)
            time.sleep(1)

    def send_reply(self, message_id, data):
        self.wc_client.reply(message_id, data)

    def close_session(self):
        self.wc_client.websock.close()
        self.connection_closed = True
