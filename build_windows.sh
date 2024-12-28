#!/bin/bash

mkdir "tmp"
mkdir "build" 2> /dev/null;

cp -r "bundled_deps/pyWalletConnect/pywalletconnect" "tmp";
cp "bundled_deps/pyWalletConnect/LICENSE" "tmp/pywalletconnect";
cp -r "bundled_deps/wsproto-1.2.0/src/wsproto" "tmp/pywalletconnect";
cp "bundled_deps/wsproto-1.2.0/LICENSE" "tmp/pywalletconnect/wsproto";
cp -r "bundled_deps/h11-0.14.0/h11" "tmp/pywalletconnect/wsproto";
cp "bundled_deps/h11-0.14.0/LICENSE.txt" "tmp/pywalletconnect/wsproto/h11";
cp -r "bundled_deps/cryptography/" "tmp";
cp *.py "tmp"

# patch imports
find ./tmp/pywalletconnect -type f -name "*.py" -exec sed -i "s/from wsproto/from .wsproto/g" {} \;
find ./tmp/pywalletconnect/wsproto -type f -name "*.py" -exec sed -i "s/from h11._headers/from .h11._headers/g" {} \;
find ./tmp/pywalletconnect/wsproto -type f -name "*.py" -exec sed -i "s/import h11/from . import h11/g" {} \;
find ./tmp/pywalletconnect/wsproto/h11 -type f -name "*.py" -exec sed -i "s/from h11./from ./g" {} \;
find ./tmp/ -maxdepth 1 -type f -name "*.py" -exec sed -i "s/from pywalletconnect/from .pywalletconnect/g" {} \;

find ./tmp/ -type d -name "__pycache__" -exec rm -r {} \;
find ./tmp/pywalletconnect -type f -name "log" -exec rm {} \;

mkdir "tmp/walletconnect"
mv tmp/pywalletconnect "tmp/walletconnect"
unzip tmp/cryptography/cryptography-43.0.1-cp39-abi3-win32.whl -d tmp/cryptography/

find ./tmp/cryptography/cryptography -mindepth 1 -maxdepth 1 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography import/from . import/g" {} \;
find ./tmp/cryptography/cryptography -maxdepth 1 -maxdepth 1 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography./from ./g" {} \;
find ./tmp/cryptography/cryptography -mindepth 2 -maxdepth 2 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography import/from .. import/g" {} \;
find ./tmp/cryptography/cryptography -mindepth 2 -maxdepth 2 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography./from ../g" {} \;
find ./tmp/cryptography/cryptography -mindepth 3 -maxdepth 3 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography import/from ... import/g" {} \;
find ./tmp/cryptography/cryptography -mindepth 3 -maxdepth 3 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography./from .../g" {} \;
find ./tmp/cryptography/cryptography -mindepth 4 -maxdepth 4 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography import/from .... import/g" {} \;
find ./tmp/cryptography/cryptography -mindepth 4 -maxdepth 4 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography./from ..../g" {} \;
find ./tmp/cryptography/cryptography -mindepth 5 -maxdepth 5 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography import/from ..... import/g" {} \;
find ./tmp/cryptography/cryptography -mindepth 5 -maxdepth 5 -type f -name "*.py*" -exec sed -i "/_rust/!s/from cryptography./from ...../g" {} \;

# Make sure pyWalletConnect uses the local cryptography dependency since EC windows binaries do not fully pack it.
find ./tmp -type f -name "enc_tunnel.py" -exec sed -i "/serialization/!s/from cryptography./from .cryptography./g" {} \;
find ./tmp -type f -name "enc_tunnel.py" -exec sed -i "s/from cryptography.hazmat.primitives import hashes, hmac, serialization/from .cryptography.hazmat.primitives import hmac/g" {} \;
find ./tmp -type f -name "enc_tunnel.py" -exec sed -i "/from .cryptography.hazmat.primitives import hmac/a from cryptography.hazmat.primitives import hashes, serialization" {} \;
find ./tmp -type f -name "ws_auth.py" -exec sed -i "/serialization/!s/from cryptography./from .cryptography./g" {} \;

d=$(date +"%G %b %d")
find ./tmp -type f -name "enc_tunnel.py" -exec sed -i "1 i # This file was edited by walletconnect build script. $d" {} \;
find ./tmp -type f -name "ws_auth.py" -exec sed -i "1 i # This file was edited by walletconnect build script. $d" {} \;
find ./tmp -type f -name "websocket.py" -exec sed -i "1 i # This file was edited by walletconnect build script. $d" {} \;

mv tmp/cryptography/cryptography "tmp/walletconnect/pywalletconnect"
mv tmp/*.py "tmp/walletconnect"
cp "manifest.json" "tmp"
cp "LICENSE" "tmp"

cd tmp
zip -r "walletconnect_win.zip" "walletconnect/" "manifest.json"
cd ..

cp tmp/walletconnect_win.zip build
rm -r tmp