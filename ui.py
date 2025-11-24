import time
from datetime import datetime

import socks
import base64
import traceback

from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5.QtWidgets import QDialog, QMenu, QAction

from electroncash.i18n import _
from electroncash import util, address
from electroncash_gui.qt import address_dialog
from electroncash_gui.qt.password_dialog import PasswordDialog
from electroncash_gui.qt.util import WindowModalDialog, CloseButton, OkButton, CancelButton, Buttons, ButtonsLineEdit

from . import w_connect2


class WalletConnectDialog(WindowModalDialog):

    def __init__(self, parent, plugin):

        super().__init__(parent, _("Wallet Connect"))
        self.plugin = plugin
        self.parent = parent
        self.wallet = self.parent.wallet
        self.address = None
        self.password = None

        self.proxy_opts = None

        self.wallet_connect_threads = []

        proxy = self.parent.network.proxy
        if proxy and (proxy["mode"] == "socks5" or proxy["mode"] == "socks4"):
            proxy_type = socks.SOCKS5 if proxy["mode"] == "socks5" else socks.SOCKS4
            # TODO add proxy user and password too
            self.proxy_opts = dict(
                proxy_type=proxy_type, proxy_addr=proxy["host"], proxy_port=int(proxy["port"]), proxy_rdns=True)
        print("Proxy is: ", self.proxy_opts)

        self.init_wallet_connect_history()

        self.layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)

        self.new_connection_layout = QtWidgets.QHBoxLayout()
        wallet_connect_uri_label = QtWidgets.QLabel(_("Wallet Connect URI:"))
        wallet_connect_uri_label.setFont(bold_font)
        self.wallet_connect_uri_text_edit = QtWidgets.QLineEdit()
        self.connect_btn = QtWidgets.QPushButton(_("Connect New dApp"))
        self.new_connection_layout.addWidget(wallet_connect_uri_label)
        self.new_connection_layout.addWidget(self.wallet_connect_uri_text_edit)
        self.new_connection_layout.addWidget(self.connect_btn)

        # add new connection layout to the main layout
        self.layout.addLayout(self.new_connection_layout)


        self.sessions_layout = QtWidgets.QVBoxLayout()
        wallet_connect_sessions_label = QtWidgets.QLabel(_("Wallet Connect Sessions:"))
        wallet_connect_sessions_label.setFont(bold_font)

        self.sessions_layout.addWidget(wallet_connect_sessions_label)

        self.history_btn = QtWidgets.QPushButton(_("Show History"))
        self.sessions_layout.addWidget(self.history_btn)

        self.active_sessions = QtWidgets.QTreeWidget()
        self.active_sessions.setHeaderLabels([_("Name"), _("URL"), _("Description")])
        self.active_sessions.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.active_sessions.header().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.active_sessions.header().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.active_sessions.setMinimumSize(200, 150)

        self.sessions_layout.addWidget(self.active_sessions)

        # add sessions layout to the main layout
        self.layout.addLayout(self.sessions_layout)

        self.proxy_layout = QtWidgets.QHBoxLayout()
        proxy_label = QtWidgets.QLabel("Proxy Info: ")
        proxy_label.setFont(bold_font)
        self.proxy_layout.addWidget(proxy_label)

        proxy_info_label_text = 'No proxy is in use.'
        if self.proxy_opts is not None:
            proxy_info_label_text = f'Using {proxy["mode"]} at {self.proxy_opts["proxy_addr"]}:{self.proxy_opts["proxy_port"]}'
        proxy_info_label = QtWidgets.QLabel(proxy_info_label_text)
        self.proxy_layout.addWidget(proxy_info_label)
        self.proxy_layout.addStretch()
        self.layout.addLayout(self.proxy_layout)

        self.address_layout = QtWidgets.QHBoxLayout()
        wallet_connect_address_label = QtWidgets.QLabel(_("Wallet Connect Address:"))
        self.wallet_connect_address_line_edit = ButtonsLineEdit()

        self.wallet_connect_address_line_edit.addCopyButton()
        # self.wallet_connect_address_line_edit.setReadOnly(True)

        self.address_layout.addWidget(wallet_connect_address_label)
        self.address_layout.addWidget(self.wallet_connect_address_line_edit)

        self.default_address_btn = QtWidgets.QPushButton(_("Default Address"))
        self.address_layout.addWidget(self.default_address_btn)
        self.put_default_wallet_address()

        self.layout.addLayout(self.address_layout)

        cbtn = CloseButton(self)
        cbtn.setDefault(False)
        self.layout.addLayout(Buttons(cbtn))

        self.resize(QtCore.QSize(int(self.parent.width()/2), self.height()))

        self.connect_btn.clicked.connect(self.on_connect_btn)
        self.wallet_connect_uri_text_edit.returnPressed.connect(self.on_connect_btn)
        self.default_address_btn.clicked.connect(self.put_default_wallet_address)
        self.history_btn.clicked.connect(self.on_history_btn)

    def init_wallet_connect_history(self):
        wallet_history = self.wallet.storage.get("wallet_connect_history")
        if wallet_history is None:
            self.wallet.storage.put("wallet_connect_history", dict())
            self.wallet.storage.write()

    def append_wallet_connect_history(self, url, address_str):
        wallet_history = self.wallet.storage.get("wallet_connect_history")
        assert wallet_history is not None

        history_record = {'address': address_str, 'last_connected_timestamp': time.time()}
        if url not in wallet_history.keys():
            wallet_history[url] = [history_record]
        elif wallet_history[url][-1]['address'] == address_str:
            # Only update the timestamp
            wallet_history[url][-1] = history_record
        else:
            wallet_history[url].append(history_record)

        # TODO check for race conditions
        self.wallet.storage.put("wallet_connect_history", wallet_history)
        self.wallet.storage.write()

    def get_wallet_connect_history(self):
        wallet_history = self.wallet.storage.get("wallet_connect_history")
        return wallet_history

    def on_error(self, exc_info):
        print(exc_info[2])
        self.window.show_error(str(exc_info[1]))

    def on_connect_btn(self):
        if self.wallet.is_watching_only():
            self.parent.show_warning(_(
                "This wallet is watching-only."
                "This means you are not able to sign transactions or messages or spend BCH in any way."
                "And you might experience odd behavior and crashes due to private keys not existing."))
            return

        try:
            if self.wallet.has_password():
                pd = PasswordDialog()
                password = pd.run()
                self.wallet.check_password(password)
                self.password = password
                del pd

            addr = self.get_wallet_address()
            address_str = addr.to_token_string()
            wallet_connect = w_connect2.WalletConnect(
                self.wallet_connect_uri_text_edit.text(), address_str,
                self.wallet, self.password, self.proxy_opts)

            session_data = wallet_connect.open_session()
            data = session_data[2]
            for existing_thread in self.wallet_connect_threads:
                if existing_thread.url == data['url']:
                    raise Exception(f"You already have an open connection to {data['url']}")
            else:
                icons = "\n".join(data['icons'])
                pairing_msg = (f"Name: {data['name']}\n"
                               f"Url: {data['url']}\n"
                               f"Description: {data['description']}\n"
                               f"Icons: {icons}")

                approved = self.parent.question(
                    title=f"Approve Wallet Connect Pairing Request?", msg=pairing_msg)

                if approved:
                    wallet_connect.approve_session()

                    self.append_wallet_connect_history(data['url'], addr.to_cashaddr())

                    thread = WalletConnectThread(parent=self, wallet_connect=wallet_connect, url=data['url'])
                    self.wallet_connect_threads.append(thread)

                    thread.start()
                    self.wallet_connect_uri_text_edit.clear()
                    self.active_sessions.addTopLevelItem(
                        QtWidgets.QTreeWidgetItem([data["name"], data["url"], data["description"]])
                    )
        except Exception as e:
            print(traceback.format_exc())
            self.parent.show_warning(str(e))

    def on_history_btn(self):
        history_dialog = WalletConnectHistoryDialog(self)
        history_dialog.show()

    def _on_session_disconnected(self, url):
        for index in range(self.active_sessions.topLevelItemCount()):
            item = self.active_sessions.topLevelItem(index)
            if item.text(1) == url:
                self.active_sessions.takeTopLevelItem(index)
                for thread_index in range(len(self.wallet_connect_threads)):
                    if self.wallet_connect_threads[thread_index].url == url:
                        thread = self.wallet_connect_threads.pop(thread_index)
                        thread.quit()
                        thread.wait()
                        break
                return True
        return False
        # self.active_sessions.clear()

    def on_session_disconnected(self, url):
        if self._on_session_disconnected(url):
            self.parent.show_message(f"{url}: {_('Wallet Connect disconnected due to user request.')}")

    def on_session_connection_lost(self, url):
        if self._on_session_disconnected(url):
            self.parent.show_message(f"{url}: {_('Wallet Connect connection lost.')}")

    def send_reply(self, wallet_connect, message_id, data):
        # TODO maybe remove this function?
        wallet_connect.send_reply(message_id, data)

    def approve_transaction_sign(self):
        pass

    def put_default_wallet_address(self):

        # For backward compatibility, check if an address is stored in the incorrect location and fix it.
        # This section can be removed in future iterations, as it is only relevant to users of the initial version.
        address_str = self.parent.config.get("wallet_connect_address")
        if address_str:
            if not self.wallet.is_mine(address.Address.from_string(address_str)):
                raise Exception("Error: The address entered does not belong to this wallet.")
            self.wallet.storage.put("wallet_connect_address", address_str)
            self.wallet.storage.write()
            self.parent.config.set_key("wallet_connect_address", None)

        address_str = self.wallet.storage.get("wallet_connect_address")
        if address_str:
            self.address = address.Address.from_string(address_str)
        else:
            self.address = self.wallet.get_unused_address(frozen_ok=False)
            self.wallet.storage.put("wallet_connect_address", self.address.to_cashaddr())
            self.wallet.storage.write()
        self.wallet.set_frozen_state([self.address], True)

        self.wallet_connect_address_line_edit.setText(self.address.to_cashaddr())

        return self.address

    def get_wallet_address(self):
        address_str = self.wallet_connect_address_line_edit.text()
        # Always make sure the address in the input belongs to the wallet
        addr = address.Address.from_string(address_str)
        if not self.wallet.is_mine(addr):
            raise Exception("Error: The address entered does not belong to this wallet.")
        self.wallet.set_frozen_state([addr], True)

        return addr


class WalletConnectHistoryDialog(QtWidgets.QDialog):
    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle("Wallet Connect History")
        self.activateWindow()
        self.parent = parent

        self.layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)

        self.previous_sessions_layout = QtWidgets.QVBoxLayout()
        previous_sessions_label = QtWidgets.QLabel(_("Wallet Connect History:"))
        previous_sessions_label.setFont(bold_font)

        self.previous_sessions = QtWidgets.QTreeWidget()
        self.previous_sessions.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.previous_sessions.customContextMenuRequested.connect(self.show_context_menu)


        self.previous_sessions.setHeaderLabels([_("URL"), _("Address"), _("Last Used")])
        self.previous_sessions.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.previous_sessions.header().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.previous_sessions.header().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.previous_sessions.setMinimumSize(400, 150)

        self.previous_sessions_layout.addWidget(self.previous_sessions)

        self.layout.addLayout(self.previous_sessions_layout)

        cbtn = CloseButton(self)
        cbtn.setDefault(False)
        self.layout.addLayout(Buttons(cbtn))


        history = self.parent.get_wallet_connect_history()
        for url, records in history.items():
            for record in records:
                address_str = record["address"]
                last_connected = datetime.fromtimestamp(record["last_connected_timestamp"]).strftime('%Y-%m-%d %H:%M')
                self.previous_sessions.addTopLevelItem(
                    QtWidgets.QTreeWidgetItem([url, address_str, last_connected])
                )

    def show_context_menu(self, position):
        item = self.previous_sessions.itemAt(position)
        if item:
            record_menu = QMenu()

            show_address_history_action = QAction(_("Show address history"))
            show_address_history_action.triggered.connect(lambda: self.show_address_dialog(item.text(1)) )
            record_menu.addAction(show_address_history_action)

            copy_address = QAction(_("Copy address"))
            copy_address.triggered.connect(lambda: self.copy_to_clipboard(item.text(1)) )
            record_menu.addAction(copy_address)

            copy_url = QAction(_("Copy URL"))
            copy_url.triggered.connect(lambda: self.copy_to_clipboard(item.text(0)) )
            record_menu.addAction(copy_url)

            record_menu.exec_(self.previous_sessions.viewport().mapToGlobal(position))

    def show_address_dialog(self, address_str):
        addr = address.Address.from_string(address_str)
        addr_dialog = address_dialog.AddressDialog(self.parent.parent, addr)
        addr_dialog.exec_()

    def copy_to_clipboard(self, text):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(text)

class WalletConnectSignTxApprovalDialog(QtWidgets.QDialog):
    def __init__(self, parent, wallet_connect, msg, tx, message_id, broadcast):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle("Approve Wallet Connect Transaction Sign")
        self.activateWindow()

        self.wallet_connect = wallet_connect
        self.tx = tx
        self.message_id = message_id
        self.broadcast = broadcast
        self.parent = parent

        # The following line is for debug only.
        # self.parent.parent.w_tx = tx

        self.layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)

        self.message_label = QtWidgets.QLabel(msg)
        self.show_tx_btn = QtWidgets.QPushButton(_("Show Transaction"))
        ok_btn = OkButton(self)
        ok_btn.setText(_("Approve"))
        cancel_btn = CancelButton(self)

        self.show_tx_btn.clicked.connect(self.on_show_tx_btn)
        ok_btn.clicked.connect(self.approve_tx)


        self.layout.addWidget(self.message_label)
        self.layout.addLayout(Buttons(cancel_btn, self.show_tx_btn, ok_btn))


    def on_show_tx_btn(self):
        self.parent.parent.show_transaction(self.tx)

    def approve_tx(self):
        window = self.parent.parent

        def sign_done(success):
            if success:
                if self.broadcast:
                    window.broadcast_transaction(self.tx, "")
                # send back result through wallet connect
                self.parent.send_reply(self.wallet_connect, self.message_id ,{
                    'signedTransaction': self.tx.serialize(),
                    'signedTransactionHash': self.tx.txid()
                })
        window.sign_tx(self.tx, sign_done)


class WalletConnectSignMessageApprovalDialog(QtWidgets.QDialog):
    def __init__(self, parent, wallet_connect, user_msg, message_to_sign, message_id):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle("Approve Wallet Connect Message Sign Request")
        self.activateWindow()

        self.wallet_connect = wallet_connect
        self.message_to_sign = message_to_sign
        self.message_id = message_id
        self.parent = parent


        self.layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)

        self.message_label = QtWidgets.QLabel(user_msg)
        ok_btn = OkButton(self)
        ok_btn.setText(_("Approve"))
        cancel_btn = CancelButton(self)
        ok_btn.clicked.connect(self.approve_message_sign)

        self.layout.addWidget(self.message_label)
        self.layout.addLayout(Buttons(cancel_btn, ok_btn))


    def approve_message_sign(self):
        window = self.parent.parent
        wallet = window.wallet

        addr = address.Address.from_string(self.wallet_connect.wallet_address)
        password = None
        if wallet.has_password():
            pd = PasswordDialog()
            password = pd.run()
            del pd
        sig = wallet.sign_message(addr, self.message_to_sign, password)
        sig = base64.b64encode(sig).decode('ascii')
        del password

        # send back result through wallet connect
        self.parent.send_reply(self.wallet_connect, self.message_id , sig)


class WalletConnectThread(QtCore.QThread):
    error_raised = QtCore.pyqtSignal(str)

    def __init__(self, parent, wallet_connect, url):
        super(WalletConnectThread, self).__init__(None)
        self.parent = parent
        self.wallet_connect = wallet_connect
        self.url = url

    def sign_tx_approval(self, task, url):
        tx = task['electroncash_tx']
        output_value = tx.output_value()
        user_prompt = task['params']['request']["params"]["userPrompt"]
        broadcast = task['params']['request']["params"].get('broadcast')

        prompt = (f"A transaction trying to spend {output_value} satoshis was received from {url}."
                  f"\nWebsite description: {user_prompt}")

        message_id = task['message_id']

        approval_dialog = WalletConnectSignTxApprovalDialog(
            self.parent, self.wallet_connect, prompt, tx, message_id, broadcast)
        approval_dialog.show()

    def sign_message_approval(self, task, url):
        message = task['params']['request']["params"]["message"]
        user_prompt = task['params']['request']["params"].get("userPrompt")

        prompt = (f"A request to sign the following message was received from {url}. Message: {message}"
                  f"\nWebsite description: {user_prompt}")

        message_id = task['message_id']

        approval_dialog = WalletConnectSignMessageApprovalDialog(
            self.parent, self.wallet_connect, prompt, message, message_id)
        approval_dialog.show()

    def disconnect(self):
        util.do_in_main_thread(self.parent.on_session_disconnected, self.url)
        self.quit()

    def connection_lost(self):
        util.do_in_main_thread(self.parent.on_session_connection_lost, self.url)
        self.quit()

    def run(self):
        while True:
            try:
                if not self.wallet_connect.thread.is_alive():
                    time.sleep(3) # sometimes is_alive returns a false positive.
                    if not self.wallet_connect.thread.is_alive():
                        self.connection_lost()
                        break


                task = self.wallet_connect.task_queue.get(timeout=3)
                print("got a task!", task)

                if task['type'] == w_connect2.WALLET_CONNECT_SESSION_DELETE:
                    # emit a signal instead of directly calling the method
                    self.disconnect()
                    break

                if task['type'] == w_connect2.WALLET_CONNECT_SIGN_TRANSACTION:
                    util.do_in_main_thread( self.sign_tx_approval, task, self.url)
                    # util.do_in_main_thread(self.parent.parent.show_transaction, task['electroncash_tx'])

                if task['type'] == w_connect2.WALLET_CONNECT_SIGN_MESSAGE:
                    util.do_in_main_thread( self.sign_message_approval, task, self.url)
            except Exception as e:
                if str(e) != "":
                    print("DEBUG:", e)
                self.error_raised.emit(e.__class__.__name__ + ' ' + str(e))
