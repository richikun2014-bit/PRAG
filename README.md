# PRAG

Privacy-preserving Approximate Nearest Neighbor Retrieval and Update (PRAG) — a prototype implementation using homomorphic encryption.

This repository contains a C++ implementation that uses Microsoft SEAL (CKKS) and demonstrates two related approaches:

- **PRAG-I** — Server-side scoring of encrypted vectors using Chebyshev polynomial approximations, allowing the server to compute scores without learning comparison results.
- **PRAG-II** — Integrates HNSW local candidate scoring, where a trusted client-side callback decrypts and selects indices; only the selected indices are revealed to the server.

Key modules (directory overview):

- `src/common/`: configuration, protocol types, Chebyshev approximation, and runtime mode switching.
- `src/client/`: key descriptors, vector/query encryption, result decryption, and PRAG-II client callbacks.
- `src/server/`: encrypted index storage, homomorphic operations, PRAG-I/PRAG-II retrieval logic, and secure update engines.
- `apps/`: demo application (`prag_demo`) demonstrating retrieval and update flows.
- `tests/`: a self-contained C++ test executable (no external test framework required).

The project uses CMake for building. The repository includes support to fetch and build Microsoft SEAL as a subproject; the provided scripts can download SEAL automatically if needed.

Quick navigation:

- One-command deploy & test (Linux / PowerShell): `./deploy_and_test.sh` / `./deploy_and_test.ps1`
- Manual CMake build: use `-DPRAG_FETCH_SEAL=ON` to let CMake automatically fetch SEAL
- Built binaries: `build/prag_demo` (Linux) or `build\\Release\\prag_demo.exe` (Windows)

--

Quick Start

Below are minimal, platform-specific steps to install, build and run the project on Linux and Windows. Run the commands from the repository root unless noted otherwise.

Linux (recommended)

Prerequisites (Ubuntu/Debian example):

```bash
sudo apt update
sudo apt install -y build-essential cmake git pkg-config wget
```

Build and run quickly:

```bash
# clone if you haven't already
git clone <repository-url>
cd P-RAG

# configure and build (Release)
cmake -S . -B build -DPRAG_FETCH_SEAL=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j$(nproc)

# run tests (optional)
ctest --test-dir build --output-on-failure -C Release

# run demos
./build/prag_demo --mode prag-i
./build/prag_demo --mode prag-ii
./build/prag_demo --update

# convenience script (configures, builds, tests, runs demos)
./deploy_and_test.sh
```

Notes:
- If your machine cannot download SEAL (network restrictions), prepare SEAL sources on another machine and place them under `_deps/seal-src/`, or install SEAL system-wide and configure CMake to use the installed package (see CMake options or the `-UseInstalledSeal` flag in the PowerShell script).

Windows (Visual Studio / PowerShell)

Prerequisites:

- Visual Studio with "Desktop development with C++" workload or Visual Studio Build Tools
- CMake (available on the PATH)
- Git

In Developer PowerShell or an x64 Native Tools prompt:

```powershell
# clone and enter repo
git clone <repository-url>
cd P-RAG

# configure (CMake will select an appropriate Visual Studio generator)
cmake -S . -B build -A x64 -DPRAG_FETCH_SEAL=ON

# build (Release)
cmake --build build --config Release

# run tests
ctest --test-dir build -C Release --output-on-failure

# run demo (path depends on generator/config)
.\build\Release\prag_demo.exe --mode prag-i

# or use the convenience script
.\deploy_and_test.ps1
```

If you prefer the Visual Studio GUI, open the generated solution in the `build` directory, select `Release|x64`, build and run `prag_demo`.

--

Common options

- `-DPRAG_FETCH_SEAL=ON`: instructs CMake to fetch and build Microsoft SEAL as a subproject during configuration.
- `./deploy_and_test.sh` / `./deploy_and_test.ps1`: convenience scripts that configure, build, run CTest and execute demo flows; the PowerShell script supports flags like `-InstallToolchain` and `-UseInstalledSeal`.

Example run flow

1. After a successful build, run `prag_demo --mode prag-i` to execute the PRAG-I demo; use `--mode prag-ii` for PRAG-II; use `--update` to run the update demo.
2. To run only the unit tests: `ctest --test-dir build -C Release --output-on-failure`.

Troubleshooting

- If CMake fails to fetch SEAL or other external dependencies, check network/proxy settings. As a workaround, populate the `_deps/` directory manually before configuring.
- On Windows, if the compiler or SDK cannot be found, ensure Visual Studio's C++ workload is installed and run CMake from an appropriate Developer command prompt.



---

