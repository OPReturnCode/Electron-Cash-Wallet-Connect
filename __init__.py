fullname = "Wallet-Connect2"
available_for = ["qt"]
description = "Wallet Connect V2 protocol implementation for Electron-Cash"

default_on = True

# TODO where to move these?
import sys
import os

plugin_path = os.path.abspath('') + '/electroncash_plugins/walletconnect/bundled_deps/'
print("plugin_path: ", plugin_path)

# sys.path.insert(0, plugin_path + 'cryptography-43.0.1')
sys.path.insert(0, plugin_path + 'wsproto-1.2.0/src')
sys.path.insert(0, plugin_path + 'h11-0.14.0')
sys.path.insert(0, plugin_path + 'pyWalletConnect')
