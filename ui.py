import socks
import base64
import traceback

from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5.QtWidgets import QDialog

from electroncash.i18n import _
from electroncash import util, address
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

        self.wallet_connect = None
        self.proxy_opts = None

        self.wallet_connect_thread = WalletConnectThread(parent=self, wallet_connect=self.wallet_connect)

        proxy = self.parent.network.proxy
        if proxy and (proxy["mode"] == "socks5" or proxy["mode"] == "socks4"):
            proxy_type = socks.SOCKS5 if proxy["mode"] == "socks5" else socks.SOCKS4
            # TODO add proxy user and password too
            self.proxy_opts = dict(
                proxy_type=proxy_type, proxy_addr=proxy["host"], proxy_port=int(proxy["port"]), proxy_rdns=True)
        print("Proxy is: ", self.proxy_opts)


        self.get_wallet_address()

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
        self.wallet_connect_address_line_edit.setText(self.get_wallet_address().to_cashaddr())
        self.wallet_connect_address_line_edit.addCopyButton()
        self.wallet_connect_address_line_edit.setReadOnly(True)

        self.address_layout.addWidget(wallet_connect_address_label)
        self.address_layout.addWidget(self.wallet_connect_address_line_edit)
        self.layout.addLayout(self.address_layout)

        cbtn = CloseButton(self)
        cbtn.setDefault(False)
        self.layout.addLayout(Buttons(cbtn))

        self.resize(QtCore.QSize(int(self.parent.width()/2), self.height()))

        self.connect_btn.clicked.connect(self.on_connect_btn)
        self.wallet_connect_uri_text_edit.returnPressed.connect(self.on_connect_btn)

    def on_error(self, exc_info):
        print(exc_info[2])
        self.window.show_error(str(exc_info[1]))

    def on_connect_btn(self):
        # TODO: remove this once we support multiple sessions.
        if self.wallet_connect:
            self.wallet_connect.close_session()
            self.active_sessions.clear()

        if self.wallet.is_watching_only():
            self.parent.show_warning(_(
                "This wallet is watching-only."
                "This means you are not able to sign transactions or messages. Or spend BCH in any way."))
            return

        try:
            if self.wallet.has_password():
                pd = PasswordDialog()
                password = pd.run()
                self.wallet.check_password(password)
                self.password = password
                del pd

            self.wallet_connect = w_connect2.WalletConnect(
                self.wallet_connect_uri_text_edit.text(), self.address.to_token_string(),
                self.wallet, self.password, self.proxy_opts)

            session_data = self.wallet_connect.open_session()

            data = session_data[2]
            icons = "\n".join(data['icons'])
            pairing_msg = (f"Name: {data['name']}\n"
                           f"Url: {data['url']}\n"
                           f"Description: {data['description']}\n"
                           f"Icons: {icons}")

            approved = self.parent.question(
                title=f"Approve Wallet Connect Pairing Request?", msg=pairing_msg)

            if approved:
                self.wallet_connect.approve_session()
                self.wallet_connect_thread.wallet_connect = self.wallet_connect
                self.wallet_connect_thread.start()
                self.wallet_connect_uri_text_edit.clear()
                self.active_sessions.addTopLevelItem(
                    QtWidgets.QTreeWidgetItem([data["name"], data["url"], data["description"]])
                )
        except Exception as e:
            print(traceback.format_exc())
            self.parent.show_warning(str(e))

    def on_session_disconnected(self):
        self.parent.show_message(f"{_('Wallet Connect disconnected due to user request.')}")
        self.active_sessions.clear()

    def send_reply(self, message_id, data):
        self.wallet_connect.send_reply(message_id, data)

    def approve_transaction_sign(self):
        pass

    def get_wallet_address(self):

        # For backward compatibility, check if an address is stored in the incorrect location and fix it.
        # This section can be removed in future iterations, as it is only relevant to users of the initial version.
        address_str = self.parent.config.get("wallet_connect_address")
        if address_str:
            self.wallet.is_mine(address.Address.from_string(address_str))
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

        return self.address


class WalletConnectSignTxApprovalDialog(QtWidgets.QDialog):
    def __init__(self, parent, msg, tx, message_id, broadcast):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle("Approve Wallet Connect Transaction Sign")
        self.activateWindow()

        self.tx = tx
        self.message_id = message_id
        self.broadcast = broadcast
        self.parent = parent

        # TODO TODO remove the following line. Debug only.
        self.parent.parent.w_tx = tx

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
                self.parent.send_reply(self.message_id ,{
                    'signedTransaction': self.tx.serialize(),
                    'signedTransactionHash': self.tx.txid()
                })
        window.sign_tx(self.tx, sign_done)


class WalletConnectSignMessageApprovalDialog(QtWidgets.QDialog):
    def __init__(self, parent, user_msg, message_to_sign, message_id):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle("Approve Wallet Connect Message Sign Request")
        self.activateWindow()

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

        addr = self.parent.get_wallet_address()
        password = None
        if wallet.has_password():
            pd = PasswordDialog()
            password = pd.run()
            del pd
        sig = wallet.sign_message(addr, self.message_to_sign, password)
        sig = base64.b64encode(sig).decode('ascii')
        del password

        # send back result through wallet connect
        self.parent.send_reply(self.message_id , sig)


class WalletConnectThread(QtCore.QThread):
    error_raised = QtCore.pyqtSignal(str)

    def __init__(self, parent, wallet_connect):
        super(WalletConnectThread, self).__init__(None)
        self.parent = parent
        self.wallet_connect = wallet_connect

    def sign_tx_approval(self, task):
        tx = task['electroncash_tx']
        output_value = tx.output_value()
        user_prompt = task['params']['request']["params"]["userPrompt"]
        broadcast = task['params']['request']["params"].get('broadcast')

        prompt = f"A transaction trying to spend {output_value} satoshis was received.\nWebsite description: {user_prompt}"

        message_id = task['message_id']

        approval_dialog = WalletConnectSignTxApprovalDialog(
            self.parent, prompt, tx, message_id, broadcast)
        approval_dialog.show()

    def sign_message_approval(self, task):
        message = task['params']['request']["params"]["message"]
        user_prompt = task['params']['request']["params"].get("userPrompt")

        prompt = (f"A request to sign the following message was received. Message: {message}"
                  f"\nWebsite description: {user_prompt}")

        message_id = task['message_id']

        approval_dialog = WalletConnectSignMessageApprovalDialog(
            self.parent, prompt, message, message_id)
        approval_dialog.show()

    def run(self):
        while True:
            try:
                task = self.wallet_connect.task_queue.get(timeout=3)
                print("got a task!", task)

                if task['type'] == w_connect2.WALLET_CONNECT_SESSION_DELETE:
                    # todo emit a signal instead of directly calling the method
                    self.parent.on_session_disconnected()
                    break

                if task['type'] == w_connect2.WALLET_CONNECT_SIGN_TRANSACTION:
                    util.do_in_main_thread( self.sign_tx_approval, task)
                    # util.do_in_main_thread(self.parent.parent.show_transaction, task['electroncash_tx'])

                if task['type'] == w_connect2.WALLET_CONNECT_SIGN_MESSAGE:
                    util.do_in_main_thread( self.sign_message_approval, task)
            except Exception as e:
                if str(e) != "":
                    print(e)
                self.error_raised.emit(e.__class__.__name__ + ' ' + str(e))
