# dscan

Windows command-line C++ application that scans for corrupted files using multiple independent detection methods.

## Features
- Recursive disk scanning
- Multiple detection methods: size, magic, io, struct (PNG, GZIP, ZIP, JPEG, PDF), manifest
- Multithreaded producer/consumer pipeline
- Hardware-accelerated CRC32C
- Interactive review and deletion UI (Recycle Bin support)

## Build Instructions
1. Open Developer PowerShell for VS 2022.
2. `cmake -S . -B build -G "Visual Studio 17 2022" -A x64`
3. `cmake --build build --config Release`

## Usage
`dscan C:\ [options]`

See `dscan --help` for all flags.
