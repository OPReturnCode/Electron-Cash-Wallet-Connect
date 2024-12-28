import weakref

from PyQt5 import QtGui

from electroncash.plugins import BasePlugin, hook
from electroncash_gui.qt.main_window import StatusBarButton
from . import ui


class Plugin(BasePlugin):

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            dialog = ui.WalletConnectDialog(window, self)
            sbbtn = StatusBarButton(self.icon(), "Wallet Connect", dialog.show)
            sb = window.statusBar()
            sb.insertPermanentWidget(3, sbbtn)
            window._wallet_connect_btn = weakref.ref(sbbtn)

    @hook
    def on_new_window(self, window):
        dialog =ui.WalletConnectDialog(window, self)
        sbbtn = StatusBarButton(self.icon(), "Wallet Connect", dialog.show)
        sb = window.statusBar()
        sb.insertPermanentWidget(3, sbbtn)
        window._wallet_connect_btn = weakref.ref(sbbtn)

    def icon(self):
        from .resources import qInitResources # lazy importing
        return QtGui.QIcon(":walletconnect/assets/Icon.svg")
