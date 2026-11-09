#!/bin/sh
# Build slinky.dll with clang-cl + lld-link + Ninja (LLVM for Windows).
# No Windows SDK is needed: the import libraries are generated from cmake/imports/*.def.
set -e
cd "$(dirname "$0")"
cmake -S . -B build/cmake -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-clang-cl.cmake
cmake --build build/cmake
echo "built: $(pwd)/build/cmake/slinky.dll"
