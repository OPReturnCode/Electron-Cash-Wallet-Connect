#!/bin/bash

./build_linux.sh
./build_windows.sh
./build_macosx.sh

cd build
sha256sum *.zip > sha256sums.txt
cd ..

ls ./build
cat ./build/sha256sums.txt