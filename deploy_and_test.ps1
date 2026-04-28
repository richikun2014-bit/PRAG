param(
    [switch]$InstallToolchain,
    [switch]$UseInstalledSeal
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-Command($Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command "cmake")) {
    if ($InstallToolchain -and (Test-Command "winget")) {
        winget install --id Kitware.CMake -e --silent
    } else {
        throw "CMake was not found. Install CMake or rerun with -InstallToolchain on a machine with winget."
    }
}

$hasCompiler = (Test-Command "cl") -or (Test-Command "g++") -or (Test-Command "clang++")
if (-not $hasCompiler) {
    if ($InstallToolchain -and (Test-Command "winget")) {
        winget install --id Microsoft.VisualStudio.2022.BuildTools -e --silent --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        throw "The C++ build tools were installed. Open a new Developer PowerShell and run this script again."
    }
    throw "No C++ compiler was found. Install MSVC Build Tools, MinGW g++, or clang++, then rerun this script."
}

if ($UseInstalledSeal) {
    cmake -S . -B build -DPRAG_FETCH_SEAL=OFF
} else {
    cmake -S . -B build -DPRAG_FETCH_SEAL=ON
}
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release

$demo = Join-Path $PSScriptRoot "build\Release\prag_demo.exe"
if (-not (Test-Path $demo)) {
    $demo = Join-Path $PSScriptRoot "build\prag_demo.exe"
}
& $demo --mode prag-i
& $demo --mode prag-ii
& $demo --update
