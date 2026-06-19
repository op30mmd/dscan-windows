# dscan

Windows command-line C++ application that scans for corrupted files using multiple independent detection methods.

## Features
- Recursive disk scanning
- Multiple detection methods: size, magic, io, struct (PNG, GZIP, ZIP, JPEG, PDF), manifest
- Multithreaded producer/consumer pipeline
- Hardware-accelerated CRC32C
- Interactive review and deletion UI (Recycle Bin support)

## Build Instructions

### Windows (MSVC)
1. Open Developer PowerShell for VS 2022.
2. `cmake -S . -B build`
3. `cmake --build build --config Release`

### Linux (Cross-compilation for Windows)
Required: `mingw-w64`
1. `cmake -S . -B build -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++`
2. `cmake --build build`

## Usage
`dscan C:\ [options]`

See `dscan --help` for all flags.
