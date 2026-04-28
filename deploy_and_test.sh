#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v cmake >/dev/null 2>&1; then
  echo "CMake was not found. Install CMake and rerun this script." >&2
  exit 1
fi

if ! command -v c++ >/dev/null 2>&1 && ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
  echo "No C++ compiler was found. Install a C++17 compiler and rerun this script." >&2
  exit 1
fi

cmake -S . -B build -DPRAG_FETCH_SEAL=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release

if [ -x build/prag_demo ]; then
  DEMO=build/prag_demo
else
  DEMO=build/Release/prag_demo
fi

"$DEMO" --mode prag-i
"$DEMO" --mode prag-ii
"$DEMO" --update
