#!/usr/bin/env python3
"""
flash_board.py – Mate firmware flasher for atoms3-lite
Chip: esp32s3 | Flash: 8MB | Mode: dio @ 80m

Auto-installs esptool and pyserial into a local .venv if needed.
Usage:
  python flash_board.py              # auto-detect port
  python flash_board.py --port COM3
  python flash_board.py --erase      # full erase before flash
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

BOARD         = "atoms3-lite"
CHIP          = "esp32s3"
FLASH_SIZE    = "8MB"
FLASH_MODE    = "dio"
FLASH_FREQ    = "80m"
DEFAULT_BAUD  = 460800
MIN_ESPTOOL   = "5.2.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR   = os.environ.get("FLASH_BOARD_VENV", os.path.join(SCRIPT_DIR, ".venv"))

FILES = {
    "bootloader":      ("0x0",   "bootloader-atoms3-lite.bin"),
    "partition-table": ("0x8000", "partition-table-atoms3-lite.bin"),
    "app":             ("0x10000",    "mate-atoms3-lite.bin"),
    "storage":         ("0x3D0000", "storage-atoms3-lite.bin"),
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

def erase(port, baud):
    cmd = [sys.executable, "-m", "esptool",
           "-p", port, "-b", str(baud),
           "--chip", CHIP, "--before", "default-reset", "--after", "no_reset",
           "erase_flash"]
    print(f"{CYAN}Erasing flash...{RESET}")
    r = subprocess.run(cmd)
    if r.returncode:
        print(f"{RED}Erase failed ({r.returncode}).{RESET}")
        sys.exit(r.returncode)

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
    print(f"{CYAN}Flashing atoms3-lite{mode}...{RESET}")
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
    ap.add_argument("--erase",   action="store_true", help="Full erase before flashing")
    ap.add_argument("--monitor", action="store_true", help="Serial monitor after flash")
    ap.add_argument("--no-stub", action="store_true", help="Flash without the stub (slower, robust for finicky ESP32 modules)")
    args = ap.parse_args()

    check_files()
    print(f"{CYAN}Mate flasher | board: {BOARD} | chip: {CHIP} | flash: {FLASH_SIZE}{RESET}")

    port = args.port
    if not port:
        before = list_ports()
        port   = wait_for_port(before)
    print(f"{GREEN}Port: {port}{RESET}")

    if args.erase:
        erase(port, args.baud)

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
