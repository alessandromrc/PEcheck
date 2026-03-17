# PEcheck

Probe-based **DLL hijacking** checker for Windows. It finds which DLLs used by an executable can be loaded from the application directory (hijackable) by actually testing each one with a canary DLL that pings back when loaded.

## How it works

1. **Parse the target executable** – Reads the PE import table (and delay-load imports) to get every DLL name the exe depends on.
2. **Test each DLL name** – For each name (e.g. `version.dll`, `kernel32.dll`):
   - Copies a **canary DLL** (that signals the host when loaded) into the target’s application directory with that name.
   - Launches the target executable (from that directory).
   - If the canary is loaded, it sets a named event; PEcheck waits on that event.
   - If the event is set within the timeout → that DLL is **hijackable** (the loader took it from the app directory).
3. **Report** – Lists which DLL names were confirmed hijackable.

So you get a real “does it load from the app folder?” result per DLL, not just a static list.

## Requirements

- **Windows**
- **Python 3.x** with `pefile`: `pip install pefile`
- **Canary DLL** built for the same architecture as the target (x86 → `canary32.dll`, x64 → `canary64.dll`)

## 1. Build the canary DLL

The canary is a small DLL that, when loaded, signals PEcheck via a named event. You must build it and place it where PEcheck can find it.

```bat
cd canary
build_canary.bat
```

This produces `canary32.dll` and `canary64.dll` in the `canary` folder (needs Visual Studio `cl` or MinGW `gcc` in PATH). See `canary/README.md` for manual build commands.

## 2. Run PEcheck

```bash
python pecheck.py "C:\Path\To\target.exe"
```

Options:

- `--canary-dir DIR` – Folder containing `canary32.dll` / `canary64.dll` (default: `canary` next to the script).
- `--timeout SEC` – Seconds to wait for the canary to load per DLL (default: 5).
- `--list-only` – Only print the list of imported DLL names; do not run the probe.

Example output:

```
Target: C:\MyApp\app.exe
Imported DLLs to test: 12
  - kernel32.dll
  - version.dll
  ...
Canary: ...\canary\canary64.dll
  [1/12] kernel32.dll -> not loaded from app dir
  [2/12] version.dll -> HIJACKABLE
  ...
--- Result ---
Hijackable (canary loaded from app directory): 2
  version.dll
  someother.dll
```

## Notes

- The target is started once per DLL under test; each run uses a single canary copy with the current DLL name, then the process is terminated and the canary is removed.
- Delay-loaded DLLs are only loaded when first used; if the app doesn’t hit that code path within `--timeout`, they may be reported as not hijackable even if they would be in real use. Increase `--timeout` or trigger the relevant feature if needed.
- Build the canary for the same architecture as the target (32-bit exe → `canary32.dll`, 64-bit → `canary64.dll`).
