#!/bin/bash

mkdir "tmp";
mkdir "build" 2> /dev/null;

cp -r "bundled_deps/pyWalletConnect/pywalletconnect" "tmp";
cp "bundled_deps/pyWalletConnect/LICENSE" "tmp/pywalletconnect";
cp -r "bundled_deps/wsproto-1.2.0/src/wsproto" "tmp/pywalletconnect";
cp "bundled_deps/wsproto-1.2.0/LICENSE" "tmp/pywalletconnect/wsproto";
cp -r "bundled_deps/h11-0.14.0/h11" "tmp/pywalletconnect/wsproto";
cp "bundled_deps/h11-0.14.0/LICENSE.txt" "tmp/pywalletconnect/wsproto/h11";
cp *.py "tmp"

# patch imports
find ./tmp/pywalletconnect -type f -name "*.py" -exec sed -i "s/from wsproto/from .wsproto/g" {} \;
find ./tmp/pywalletconnect/wsproto -type f -name "*.py" -exec sed -i "s/from h11._headers/from .h11._headers/g" {} \;
find ./tmp/pywalletconnect/wsproto -type f -name "*.py" -exec sed -i "s/import h11/from . import h11/g" {} \;
find ./tmp/pywalletconnect/wsproto/h11 -type f -name "*.py" -exec sed -i "s/from h11./from ./g" {} \;
find ./tmp/ -maxdepth 1 -type f -name "*.py" -exec sed -i "s/from pywalletconnect/from .pywalletconnect/g" {} \;

d=$(date +"%G %b %d")
find ./tmp -type f -name "websocket.py" -exec sed -i "1 i # This file was edited by walletconnect build script. $d" {} \;

find ./tmp/ -type d -name "__pycache__" -exec rm -r {} \;
find ./tmp/pywalletconnect -type f -name "log" -exec rm {} \;

mkdir "tmp/walletconnect"
mv tmp/pywalletconnect "tmp/walletconnect"
mv tmp/*.py "tmp/walletconnect"
cp "manifest.json" "tmp"
cp "LICENSE" "tmp"

cd tmp
zip -r "walletconnect_linux.zip" "walletconnect/" "manifest.json"
cd ..

cp tmp/walletconnect_linux.zip build
rm -r tmp