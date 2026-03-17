# Canary DLL (C++)

This DLL is copied by PEcheck into the target application directory with each tested DLL name. When the executable loads it (from the app directory), the canary writes a marker file so PEcheck can record that the DLL name is hijackable.

## Build

**Visual Studio:** Open `canary.sln`. Build **Release | x86** to get `canary32.dll`, and **Release | x64** to get `canary64.dll`. Both output to this folder. (Solution uses platform toolset v143; for VS 2019 edit the project and set toolset to v142.)

**Command line:** Use `build_canary.bat` if you prefer. You need a DLL for the same architecture as the target executable (x86 or x64). Source: `canary.cpp`.

### Visual Studio (Developer Command Prompt)

```bat
:: x64 (for 64-bit targets)
cl /LD /EHsc /O2 canary.cpp /Fe:canary64.dll kernel32.lib

:: x86 (for 32-bit targets)
cl /LD /EHsc /O2 canary.cpp /Fe:canary32.dll kernel32.lib
```

### MinGW / G++

```bat
:: x64
g++ -shared -o canary64.dll canary.cpp -s -static-libgcc

:: x86 (use -m32 and a 32-bit toolchain)
g++ -shared -m32 -o canary32.dll canary.cpp -s -static-libgcc
```

Place `canary32.dll` and/or `canary64.dll` in this directory (or point PEcheck at it with `--canary-dir`).

**MSVC:** The batch script looks for `vcvarsall.bat` and calls it with `x64` then `x86` so `canary64.dll` is really 64-bit and `canary32.dll` is 32-bit. If you were building from the default Developer Command Prompt (x86), both DLLs used to be 32-bit; the script now fixes that. If `vcvarsall` is not found (e.g. different VS path), run `build_canary.bat` from **x64 Native Tools Command Prompt** to get `canary64.dll`, then from **x86 Native Tools Command Prompt** to get `canary32.dll`.

## Behavior

- On `DLL_PROCESS_ATTACH`, the canary reads `PECHECK_MARKER` (a file path) from the environment, creates that file, and writes `"loaded"` into it. The host polls for the file to detect that the canary was loaded.
- **DllMain must stay minimal**: no AllocConsole, no printf, no LoadLibrary. The loader holds a lock during DllMain; doing more can deadlock or crash the process.
