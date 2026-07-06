#!/usr/bin/env python3
"""
flash_board.py – Mate firmware flasher for atom-lite-c25_21
Chip: esp32 | Flash: 4MB | Mode: dio @ 40m

Auto-installs esptool and pyserial into a local .venv if needed.
Flashes with a full erase by default (reliable across board/partition
changes); pass --no-erase for a faster same-board reflash.
Usage:
  python flash_board.py              # auto-detect port, full erase + flash
  python flash_board.py --port COM3
  python flash_board.py --no-erase   # skip erase (faster; same board only)
  python flash_board.py --monitor    # open serial monitor after flash
"""
import os
import sys
import time
import subprocess
import argparse
try:
    from importlib import metadata as importlib_metadata
except ImportError:
    importlib_metadata = None

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

BOARD         = "atom-lite-c25_21"
CHIP          = "esp32"
FLASH_SIZE    = "4MB"
FLASH_MODE    = "dio"
FLASH_FREQ    = "40m"
DEFAULT_BAUD  = 115200
DEFAULT_NO_STUB = True
MIN_ESPTOOL   = "5.2.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR   = os.environ.get("FLASH_BOARD_VENV", os.path.join(SCRIPT_DIR, ".venv"))

FILES = {
    "bootloader":      ("0x1000",   "bootloader-atom-lite-c25_21.bin"),
    "partition-table": ("0x8000", "partition-table-atom-lite-c25_21.bin"),
    "app":             ("0x10000",    "mate-atom-lite-c25_21.bin"),
    "storage":         ("0x1D0000", "storage-atom-lite-c25_21.bin"),
}

# ---------------------------------------------------------------------------

def parse_version(v):
    parts, pre = [], False
    for p in v.split("."):
        d = ""
        for c in p:
            if c.isdigit():
                d += c
            else:
                pre = True; break
        parts.append(int(d or 0))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3]), pre

def version_ok(installed, required):
    it, ip = parse_version(installed)
    rt, _  = parse_version(required)
    return it > rt or (it == rt and not ip)

def in_venv():
    return (getattr(sys, "base_prefix", sys.prefix) != sys.prefix
            or getattr(sys, "real_prefix", None) is not None)

def venv_python(venv_dir=VENV_DIR):
    return os.path.join(venv_dir, "Scripts" if os.name == "nt" else "bin", "python" + (".exe" if os.name == "nt" else ""))

def ensure_venv():
    p = venv_python()
    if not os.path.exists(p):
        print(f"{YELLOW}Creating .venv at {VENV_DIR}{RESET}")
        try:
            subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
        except subprocess.CalledProcessError:
            print(f"{RED}Failed to create venv. Install python3-venv and retry.{RESET}")
            sys.exit(1)
    return p

def install(python_exe, pkgs):
    subprocess.check_call([python_exe, "-m", "pip", "install", "--upgrade"] + pkgs)

def bootstrap():
    missing = []
    try:
        import serial.tools.list_ports  # noqa
    except ImportError:
        missing.append("pyserial")
    try:
        import esptool
        ver = None
        if importlib_metadata:
            try: ver = importlib_metadata.version("esptool")
            except Exception: pass
        ver = ver or getattr(esptool, "__version__", None)
        if not ver or not version_ok(ver, MIN_ESPTOOL):
            missing.append(f"esptool>={MIN_ESPTOOL}")
    except ImportError:
        missing.append(f"esptool>={MIN_ESPTOOL}")
    if missing:
        py = sys.executable if in_venv() else ensure_venv()
        install(py, missing)
        os.execv(py, [py] + sys.argv)

bootstrap()

import serial
import serial.tools.list_ports

# ---------------------------------------------------------------------------

def check_files():
    missing = [n for n, (_, f) in FILES.items() if not os.path.exists(os.path.join(SCRIPT_DIR, f))]
    if missing:
        print(f"{RED}Missing: {', '.join(missing)}{RESET}")
        sys.exit(1)
    print(f"{GREEN}All files present.{RESET}")

def list_ports():
    return {p.device for p in serial.tools.list_ports.comports()}

def flash_size_bytes():
    s = FLASH_SIZE.strip().upper()
    if s.endswith("MB"):
        return int(s[:-2]) * 1024 * 1024
    if s.endswith("M"):
        return int(s[:-1]) * 1024 * 1024
    if s.endswith("KB"):
        return int(s[:-2]) * 1024
    if s.endswith("K"):
        return int(s[:-1]) * 1024
    return int(s, 0)

def wait_for_port(before, timeout=30.0):
    print(f"{CYAN}Hold BOOT and connect the board (or press BOOT + RESET).{RESET}")
    sp = ["|", "/", "-", "\\"]
    t0, i = time.time(), 0
    while time.time() - t0 < timeout:
        new = list_ports() - before
        sys.stdout.write(f"\r{sp[i % 4]} "); sys.stdout.flush()
        i += 1
        if new:
            sys.stdout.write("\r"); sys.stdout.flush()
            return new.pop()
        time.sleep(0.15)
    print(f"\n{RED}Timeout — no new port detected.{RESET}")
    sys.exit(1)

def erase(port, baud, no_stub=False):
    cmd = [sys.executable, "-m", "esptool",
           "-p", port, "-b", str(baud),
           "--chip", CHIP, "--before", "default-reset", "--after", "no-reset"]
    if no_stub:
        cmd.append("--no-stub")
        size = flash_size_bytes()
        cmd += ["erase-region", "0x0", hex(size)]
        mode = " (--no-stub erase-region 0x0..0x%X @ %d)" % (size, baud)
    else:
        cmd.append("erase-flash")
        mode = " (@ %d)" % baud
    print(f"{CYAN}Erasing flash{mode}...{RESET}")
    return subprocess.run(cmd).returncode

def flash(port, baud, no_stub=False):
    cmd = [sys.executable, "-m", "esptool",
           "-p", port, "-b", str(baud),
           "--chip", CHIP,
           "--before", "default-reset", "--after", "hard-reset"]
    if no_stub:
        cmd.append("--no-stub")
    cmd += ["write-flash",
            "--flash-mode", FLASH_MODE,
            "--flash-freq", FLASH_FREQ,
            "--flash-size", FLASH_SIZE]
    for _, (offset, fname) in FILES.items():
        full = os.path.join(SCRIPT_DIR, fname)
        if os.path.exists(full):
            cmd += [offset, full]
    mode = " (--no-stub @ %d)" % baud if no_stub else ""
    print(f"{CYAN}Flashing atom-lite-c25_21{mode}...{RESET}")
    return subprocess.run(cmd).returncode

def reset_to_app(port):
    try:
        with serial.Serial(port, 115200, timeout=0.1) as s:
            s.dtr = False; time.sleep(0.05)
            s.rts = True;  time.sleep(0.05)
            s.rts = False
        print(f"{GREEN}Reset sent.{RESET}")
    except Exception as e:
        print(f"{YELLOW}RTS/DTR reset failed: {e} — press RESET manually.{RESET}")

def monitor(port, baud):
    print(f"{CYAN}Monitor on {port} @ {baud} (Ctrl+C to exit)...{RESET}")
    time.sleep(0.3)
    try:
        with serial.Serial(port, baud, timeout=0.2) as s:
            while True:
                try:
                    d = s.read(1024)
                    if d:
                        sys.stdout.write(d.decode(errors="replace")); sys.stdout.flush()
                except KeyboardInterrupt:
                    break
    except Exception as e:
        print(f"{RED}Monitor error: {e}{RESET}")

def main():
    ap = argparse.ArgumentParser(description=f"Mate flasher – {BOARD}")
    ap.add_argument("--port",    help="Serial port (e.g. COM3 or /dev/ttyUSB0)")
    ap.add_argument("--baud",    type=int, default=DEFAULT_BAUD)
    ap.add_argument("--no-erase", action="store_true", help="Skip the full erase (faster; same-board reflash only)")
    ap.add_argument("--monitor", action="store_true", help="Serial monitor after flash")
    ap.add_argument("--no-stub", action="store_true", default=DEFAULT_NO_STUB,
                    help="Flash without the stub (slower, robust for finicky ESP32 modules)")
    ap.add_argument("--stub", action="store_false", dest="no_stub",
                    help="Use the RAM stub flasher even on boards that default to --no-stub")
    args = ap.parse_args()

    check_files()
    print(f"{CYAN}Mate flasher | board: {BOARD} | chip: {CHIP} | flash: {FLASH_SIZE}{RESET}")

    port = args.port
    if not port:
        before = list_ports()
        port   = wait_for_port(before)
    print(f"{GREEN}Port: {port}{RESET}")

    if not args.no_erase:
        rc = erase(port, args.baud, no_stub=args.no_stub)
        if rc and (not args.no_stub or args.baud != 115200):
            print(f"{YELLOW}Erase failed at {args.baud} baud — retrying with --no-stub @ 115200...{RESET}")
            rc = erase(port, 115200, no_stub=True)
        if rc:
            print(f"{RED}Erase failed ({rc}).{RESET}")
            sys.exit(rc)

    rc = flash(port, args.baud, no_stub=args.no_stub)
    if rc and not args.no_stub:
        # Some ESP32 modules (e.g. ESP32-PICO-D4 on Atom Lite) drop the stub
        # when the baud is bumped. Fall back to a robust no-stub @ 115200 pass.
        print(f"{YELLOW}Flash failed at {args.baud} baud — retrying with --no-stub @ 115200 (slower but robust)...{RESET}")
        rc = flash(port, 115200, no_stub=True)
    if rc:
        print(f"{RED}Flash failed ({rc}).{RESET}")
        sys.exit(rc)
    reset_to_app(port)

    if args.monitor:
        monitor(port, args.baud)

if __name__ == "__main__":
    main()
