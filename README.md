# PRAG

This directory contains a C++17 implementation of the PRAG system structure described in the paper draft and prompt notes.

Implemented modules:

- `common/`: configuration, protocol data types, Chebyshev approximation, and runtime mode switching.
- `client/`: key descriptors, vector/query encryption, result decryption, and PRAG-II comparison callbacks.
- `server/`: encrypted index storage, homomorphic operations, PRAG-I/PRAG-II retrieval, and secure update engines.
- `apps/`: runnable demo for retrieval and update flows.
- `tests/`: self-contained C++ test executable with no third-party test framework.

The arithmetic backend uses Microsoft SEAL CKKS through `seal::CKKSEncoder`, `seal::Encryptor`, `seal::Evaluator`, and `seal::Decryptor`. PRAG-I evaluates encrypted Chebyshev polynomial scores without revealing comparison results to the server. PRAG-II performs real HNSW graph-path ANN by sending encrypted local candidate scores to the trusted client callback, which returns only selected indices.

## One-command build and test

PowerShell:

```powershell
.\deploy_and_test.ps1
```

Bash:

```bash
./deploy_and_test.sh
```

Both scripts configure CMake, build the project, run the test executable through CTest, then run PRAG-I, PRAG-II, and update demos. The code depends on Microsoft SEAL; by default the scripts ask CMake to fetch SEAL v4.1.2 from the official Microsoft repository.

On a clean Windows machine, the PowerShell script supports optional toolchain installation through winget:

```powershell
.\deploy_and_test.ps1 -InstallToolchain
```

If Microsoft SEAL is already installed through vcpkg or a system package, use the installed package instead of fetching it:

```powershell
.\deploy_and_test.ps1 -UseInstalledSeal
```

## Manual build

```bash
cmake -S . -B build -DPRAG_FETCH_SEAL=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
./build/prag_demo --mode prag-i
./build/prag_demo --mode prag-ii
./build/prag_demo --update
```

On multi-config generators such as Visual Studio, keep the `--config Release` and `-C Release` arguments.
