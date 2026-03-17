#!/usr/bin/env python3
"""
PEcheck - Probe-based DLL hijacking checker for Windows.

1. Runs the target executable and enumerates all DLLs it actually loads at runtime.
2. For each loaded DLL name: places a canary DLL (that pings back when loaded) in the app directory,
   launches the target exe again, and checks if the canary was loaded. If so, that DLL is hijackable.

Usage:
  python pecheck.py <path_to_exe> [--canary-dir DIR] [--timeout SEC] [--gather-wait SEC]
  Build the canary first: see canary/README or run build_canary.bat

Requires: Windows, pefile (for arch only), and a built canary DLL (canary32.dll / canary64.dll).
"""

import argparse
import os
import sys
import time
import ctypes
from ctypes import wintypes
import subprocess
import uuid

if sys.platform != "win32":
    sys.exit("This tool runs only on Windows.")

try:
    import pefile
except ImportError:
    sys.exit("Install pefile: pip install pefile")

# --- Windows API (ctypes) ---
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

# Event sync
kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.SetEvent.restype = wintypes.BOOL
kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
kernel32.ResetEvent.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

# Process / module enumeration
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
LIST_MODULES_ALL = 0x03
MAX_PATH = 260
WAIT_OBJECT_0 = 0

psapi.GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD
]
psapi.GetModuleFileNameExW.restype = wintypes.DWORD
psapi.EnumProcessModules.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]
psapi.EnumProcessModules.restype = wintypes.BOOL
try:
    psapi.EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD
    ]
    psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    _HAS_ENUM_EX = True
except Exception:
    _HAS_ENUM_EX = False


def open_process(pid: int):
    """Open process with rights to query modules; fallback to limited if needed."""
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    return h


def get_loaded_module_names(pid: int):
    """
    Enumerate all loaded modules (exe + DLLs) in the process; return list of (base_name, full_path).
    Returns (list, None) or (None, error_string).
    """
    h_process = open_process(pid)
    if not h_process:
        return None, "OpenProcess failed (run as same user or elevated)"

    try:
        cb_needed = wintypes.DWORD()
        if _HAS_ENUM_EX:
            ok = psapi.EnumProcessModulesEx(h_process, None, 0, ctypes.byref(cb_needed), LIST_MODULES_ALL)
        else:
            ok = psapi.EnumProcessModules(h_process, None, 0, ctypes.byref(cb_needed))
        if not ok or cb_needed.value == 0:
            return None, "EnumProcessModules failed (32/64 bit mismatch?)"

        hmods = (wintypes.HMODULE * (cb_needed.value // ctypes.sizeof(wintypes.HMODULE)))()
        if _HAS_ENUM_EX:
            ok = psapi.EnumProcessModulesEx(h_process, hmods, cb_needed, ctypes.byref(cb_needed), LIST_MODULES_ALL)
        else:
            ok = psapi.EnumProcessModules(h_process, hmods, cb_needed, ctypes.byref(cb_needed))
        if not ok:
            return None, "EnumProcessModules failed"

        count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
        result = []
        buf = ctypes.create_unicode_buffer(MAX_PATH)
        for i in range(count):
            path_len = psapi.GetModuleFileNameExW(h_process, hmods[i], buf, MAX_PATH)
            if path_len:
                path = buf.value[:path_len].replace("/", "\\").lower()
                name = os.path.basename(path)
                result.append((name, path))
        return result, None
    finally:
        kernel32.CloseHandle(h_process)


def run_and_gather_loaded_dlls(exe_path: str, app_dir: str, wait_sec: float):
    """
    Launch the exe, wait wait_sec, enumerate all loaded modules, then terminate.
    Return (sorted list of DLL names only, excluding exe), or (None, error).
    """
    try:
        proc = subprocess.Popen(
            [exe_path],
            cwd=app_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,
        )
    except Exception as e:
        return None, str(e)

    time.sleep(max(0.5, wait_sec))
    modules, err = get_loaded_module_names(proc.pid)
    if proc.poll() is None:
        try:
            hproc = kernel32.OpenProcess(PROCESS_TERMINATE, False, proc.pid)
            if hproc:
                kernel32.TerminateProcess(hproc, 0)
                kernel32.CloseHandle(hproc)
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass

    if err:
        return None, err
    if not modules:
        return None, "No modules enumerated"

    # First module is the exe; rest are DLLs. Return unique DLL names (lowercase), sorted.
    exe_name = os.path.basename(exe_path).lower()
    dll_names = sorted({name for name, _path in modules[1:] if name.lower() != exe_name})
    return dll_names, None


def get_pe_architecture(pe_path: str):
    """Return 'x64' or 'x86' for the PE, or None on error."""
    try:
        pe = pefile.PE(pe_path, fast_load=True)
        m = pe.FILE_HEADER.Machine
        pe.close()
        if m == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return "x64"
        if m == 0x14c:  # IMAGE_FILE_MACHINE_I386
            return "x86"
        return None
    except Exception:
        return None


def find_canary_dll(canary_dir: str, arch: str, debug: bool = False):
    """Return path to canary DLL for the given architecture (x86 or x64), or None."""
    name = "canary64.dll" if arch == "x64" else "canary32.dll"
    _resolve = getattr(os.path, "realpath", os.path.abspath)
    script_dir = os.path.normpath(os.path.dirname(_resolve(__file__)))
    cwd = os.path.normpath(os.getcwd())
    canary_sub = os.path.join(script_dir, "canary")
    bases = [script_dir, cwd, canary_dir, canary_sub]
    # Dedupe while preserving order (cwd might equal script_dir)
    seen = set()
    for base in bases:
        if not base or base in seen:
            continue
        seen.add(base)
        path = os.path.normpath(os.path.join(base, name))
        if debug:
            print(f"  [debug] trying {path} -> exists={os.path.isfile(path)}", file=sys.stderr)
        if os.path.isfile(path):
            return path
    return None


def test_one_dll(
    exe_path: str,
    app_dir: str,
    dll_name: str,
    canary_path: str,
    marker_path: str,
    timeout_sec: float,
):
    """
    Deploy canary as app_dir\\dll_name, launch exe with PECHECK_MARKER set.
    Canary writes the marker file when loaded. Poll for file appearance.
    Returns (hijackable: bool, error_message or None).
    """
    target_dll = os.path.join(app_dir, dll_name)
    if os.path.isfile(target_dll):
        return False, "DLL already exists in app dir (remove it to test)"
    try:
        import shutil
        shutil.copy2(canary_path, target_dll)
    except Exception as e:
        return False, str(e)

    # Remove stale marker from a previous run
    if os.path.isfile(marker_path):
        try:
            os.remove(marker_path)
        except Exception:
            pass

    env = os.environ.copy()
    env["PECHECK_MARKER"] = marker_path

    try:
        proc = subprocess.Popen(
            [exe_path],
            cwd=app_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except Exception as e:
        try:
            os.remove(target_dll)
        except Exception:
            pass
        return False, str(e)

    # Poll for canary to create the marker file (more reliable than named event)
    step = 0.05
    elapsed = 0.0
    signaled = False
    while elapsed < timeout_sec:
        if os.path.isfile(marker_path):
            signaled = True
            break
        time.sleep(step)
        elapsed += step

    # Cleanup: remove canary and marker, kill process if still running
    try:
        os.remove(target_dll)
    except Exception:
        pass
    try:
        if os.path.isfile(marker_path):
            os.remove(marker_path)
    except Exception:
        pass
    if proc.poll() is None:
        try:
            hproc = kernel32.OpenProcess(PROCESS_TERMINATE, False, proc.pid)
            if hproc:
                kernel32.TerminateProcess(hproc, 0)
                kernel32.CloseHandle(hproc)
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass

    return signaled, None


def main():
    parser = argparse.ArgumentParser(
        description="Test which DLLs of a target executable can be hijacked (loaded from app directory) using a canary DLL."
    )
    parser.add_argument("exe", help="Path to the executable to test")
    parser.add_argument(
        "--canary-dir",
        default=None,
        metavar="DIR",
        help="Directory containing canary32.dll and canary64.dll (default: script dir/canary)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Seconds to wait for canary load per DLL (default: 5)",
    )
    parser.add_argument(
        "--gather-wait",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Seconds to let the app run before enumerating loaded DLLs (default: 3)",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only run the app, list loaded DLLs, and exit (no canary probe)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print marker file path and other debug info",
    )
    args = parser.parse_args()

    exe_path = os.path.abspath(args.exe)
    if not os.path.isfile(exe_path):
        print(f"Error: not a file: {exe_path}", file=sys.stderr)
        sys.exit(1)

    app_dir = os.path.dirname(exe_path)
    print(f"Target: {exe_path}")
    print("Running app to gather loaded DLLs...")
    dll_names, err = run_and_gather_loaded_dlls(exe_path, app_dir, args.gather_wait)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    if not dll_names:
        print("No DLLs enumerated (app may have exited too quickly). Try --gather-wait.", file=sys.stderr)
        sys.exit(0)

    print(f"Loaded DLLs to test: {len(dll_names)}")
    for n in dll_names:
        print(f"  - {n}")
    if args.list_only:
        return

    print("Testing each DLL with canary...")
    arch = get_pe_architecture(exe_path)
    if not arch:
        print("Error: could not determine PE architecture (x86/x64).", file=sys.stderr)
        sys.exit(1)
    canary_dir = args.canary_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary")
    canary_path = find_canary_dll(canary_dir, arch, debug=args.debug)
    if not canary_path:
        print("Error: canary DLL not found.", file=sys.stderr)
        print("  Run with --debug to see which paths were checked.", file=sys.stderr)
        print("  Put canary64.dll or canary32.dll next to pecheck.py or in the canary folder.", file=sys.stderr)
        sys.exit(1)
    print(f"Canary: {canary_path}")
    import tempfile
    marker_path = os.path.join(tempfile.gettempdir(), "pecheck_canary_" + str(uuid.uuid4()).replace("-", "")[:12] + ".marker")
    if args.debug:
        print(f"Debug: marker path = {marker_path}")
        print("       (canary will write this file when loaded; check if it appears)")
    hijackable = []
    for i, dll_name in enumerate(dll_names):
        ok, err_msg = test_one_dll(exe_path, app_dir, dll_name, canary_path, marker_path, args.timeout)
        if ok:
            hijackable.append(dll_name)
            print(f"  [{i+1}/{len(dll_names)}] {dll_name} -> HIJACKABLE")
        else:
            print(f"  [{i+1}/{len(dll_names)}] {dll_name} -> not loaded from app dir" + (f" ({err_msg})" if err_msg else ""))
    try:
        if os.path.isfile(marker_path):
            os.remove(marker_path)
    except Exception:
        pass
    print()
    print("--- Result ---")
    print(f"Hijackable (canary loaded from app directory): {len(hijackable)}")
    for n in hijackable:
        print(f"  {n}")
    if not hijackable:
        print("  (none)")


if __name__ == "__main__":
    main()
