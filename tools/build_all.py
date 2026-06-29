#!/usr/bin/env python3
"""
build_all.py – build all board permutations of janos-web-client locally,
mirroring the GitHub Actions workflow (espressif/idf:release-v6.0).

Calls Docker directly from Python (no bash wrapper) to avoid MSYS path
conversion issues on Windows. This script is the single source of truth for
the board build matrix, mirrored into CI via --print-matrix.

Output layout:
  binaries/
    xiao-c6/
      mate-xiao-c6.bin
      bootloader-xiao-c6.bin
      partition-table-xiao-c6.bin
      storage-xiao-c6.bin
      flash_board.py          ← board-specific flasher
    cores3/ ...
    atoms3r/ ...
    stickc-plus2/ ...
    sticks3/ ...
    atom-lite/ ...

Usage:
  python tools/build_all.py [--targets xiao-c6,cores3] [--keep-build]
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Build matrix – mirrors .github/workflows/build.yml
# ---------------------------------------------------------------------------

BOARDS = {
    "xiao-c6": {
        "idf_target":         "esp32c6",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.esp32c6",
        "chip":               "esp32c6",
        "flash_size":         "4MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x1D0000",  # 0x10000 + 0x1C0000 (partitions_4mb.csv)
    },
    "nanoc6": {
        "idf_target":         "esp32c6",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.nanoc6",
        "chip":               "esp32c6",
        "flash_size":         "4MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x1D0000",  # 0x10000 + 0x1C0000 (partitions_4mb.csv)
    },
    "cores3": {
        "idf_target":         "esp32s3",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.cores3",
        "chip":               "esp32s3",
        "flash_size":         "16MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x7D0000",  # 0x10000 + 0x7C0000 (partitions_16mb.csv)
    },
    "atoms3r": {
        "idf_target":         "esp32s3",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.atoms3r",
        "chip":               "esp32s3",
        "flash_size":         "8MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x3D0000",  # 0x10000 + 0x3C0000 (partitions_8mb.csv)
    },
    "atoms3": {
        "idf_target":         "esp32s3",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.atoms3",
        "chip":               "esp32s3",
        "flash_size":         "8MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x3D0000",  # 0x10000 + 0x3C0000 (partitions_8mb.csv)
    },
    "atoms3-lite": {
        "idf_target":         "esp32s3",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.atoms3-lite",
        "chip":               "esp32s3",
        "flash_size":         "8MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x3D0000",  # 0x10000 + 0x3C0000 (partitions_8mb.csv)
    },
    "stickc-plus2": {
        "idf_target":         "esp32",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.esp32",
        "chip":               "esp32",
        "flash_size":         "8MB",
        "flash_mode":         "dio",
        "flash_freq":         "40m",
        "boot_offset":        "0x1000",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x3D0000",  # 0x10000 + 0x3C0000 (partitions_8mb.csv)
    },
    "sticks3": {
        "idf_target":         "esp32s3",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.sticks3",
        "chip":               "esp32s3",
        "flash_size":         "8MB",
        "flash_mode":         "dio",
        "flash_freq":         "80m",
        "boot_offset":        "0x0",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x3D0000",  # 0x10000 + 0x3C0000 (partitions_8mb.csv)
    },
    "atom-lite": {
        "idf_target":         "esp32",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.atom-lite",
        "chip":               "esp32",
        "flash_size":         "4MB",
        "flash_mode":         "dio",
        "flash_freq":         "40m",
        "boot_offset":        "0x1000",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x1D0000",  # 0x10000 + 0x1C0000 (partitions_4mb.csv)
    },
    "atom-matrix": {
        "idf_target":         "esp32",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.atom-matrix",
        "chip":               "esp32",
        "flash_size":         "4MB",
        "flash_mode":         "dio",
        "flash_freq":         "40m",
        "boot_offset":        "0x1000",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x1D0000",  # 0x10000 + 0x1C0000 (partitions_4mb.csv)
    },
    "coreink": {
        "idf_target":         "esp32",
        "sdkconfig_defaults": "sdkconfig.defaults;sdkconfig.defaults.coreink",
        "chip":               "esp32",
        "flash_size":         "4MB",
        "flash_mode":         "dio",
        "flash_freq":         "40m",
        "boot_offset":        "0x1000",
        "ptable_offset":      "0x8000",
        "app_offset":         "0x10000",
        "spiffs_offset":      "0x1D0000",  # 0x10000 + 0x1C0000 (partitions_4mb.csv)
    },
}

IMAGE        = "espressif/idf:release-v6.0"
REPO_ROOT    = Path(__file__).resolve().parent.parent
BINARIES_DIR = REPO_ROOT / "binaries"
CACHE_DIR    = REPO_ROOT / ".espressif"

# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[build_all] {msg}", flush=True)


def run(cmd: list, cwd: Optional[Path] = None) -> None:
    log("$ " + " ".join(str(c) for c in cmd))
    result = subprocess.run(cmd, cwd=cwd or REPO_ROOT)
    if result.returncode != 0:
        sys.exit(f"Command failed with exit code {result.returncode}")


def docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def build_board(board: str, keep_build: bool, out_root: Path, use_docker: bool = True) -> None:
    cfg       = BOARDS[board]
    build_dir = REPO_ROOT / f"build-{board}"
    out_dir   = out_root / board

    log(f"=== Building {board} (target={cfg['idf_target']}) ===")
    out_dir.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(exist_ok=True)

    # Remove stale files that cause idf.py set-target / fullclean to fail
    for f in (REPO_ROOT / "sdkconfig", REPO_ROOT / "sdkconfig.old"):
        f.unlink(missing_ok=True)
    for stale in (REPO_ROOT / "build", build_dir):
        shutil.rmtree(stale, ignore_errors=True)

    # Apply the board's sdkconfig.defaults authoritatively via -D (not just the
    # env var) and use a single per-board build dir for BOTH set-target and
    # build. This guarantees the generated sdkconfig is rebuilt from THIS
    # board's defaults every time, so nothing (e.g. PSRAM from a prior board)
    # can bleed across builds. Single-quote the value to protect the ';'.
    defaults = cfg["sdkconfig_defaults"]
    idf_cmd = (
        ". /opt/esp/idf/export.sh >/dev/null 2>&1"
        f" && idf.py -B build-{board} -D SDKCONFIG_DEFAULTS='{defaults}'"
        f" set-target {cfg['idf_target']}"
        f" && idf.py -B build-{board} build"
    )

    if use_docker:
        cmd = [
            "docker", "run", "--rm",
            "--workdir", "/project",
            "--env", f"IDF_TARGET={cfg['idf_target']}",
            "--env", f"SDKCONFIG_DEFAULTS={cfg['sdkconfig_defaults']}",
            "--volume", f"{REPO_ROOT}:/project",
            "--volume", f"{CACHE_DIR}:/root/.espressif",
            IMAGE,
            "bash", "-c", idf_cmd,
        ]
    else:
        # Native build: assume we're already inside the esp-idf container/host
        # (e.g. GitHub Actions). Reuse the exact same idf command sequence so
        # the anti-config-leak guarantees hold identically to the Docker path.
        cmd = ["bash", "-c", idf_cmd]

    run(cmd)
    _verify_config(board, cfg)
    _collect_artifacts(board, build_dir, out_dir)
    generate_flasher(board, out_dir)

    if not keep_build:
        shutil.rmtree(build_dir, ignore_errors=True)


def _verify_config(board: str, cfg: dict) -> None:
    """Assert the generated sdkconfig honors every explicit setting from the
    board's own defaults file. Catches a stale/leaked config (e.g. PSRAM
    enabled on a no-PSRAM module) and fails loudly instead of shipping a
    binary that bootloops on real hardware."""
    sdkconfig = REPO_ROOT / "sdkconfig"
    if not sdkconfig.exists():
        sys.exit(f"Config check failed for {board}: no sdkconfig was generated")
    text = sdkconfig.read_text(encoding="utf-8", errors="ignore").splitlines()
    have = set(line.rstrip() for line in text)

    # The board-specific file is the last entry in the defaults chain.
    board_defaults = REPO_ROOT / cfg["sdkconfig_defaults"].split(";")[-1]
    if not board_defaults.exists():
        return

    missing = []
    for raw in board_defaults.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        # An explicit "CONFIG_X=..." assignment, or a "# CONFIG_X is not set".
        is_assign = s.startswith("CONFIG_") and "=" in s
        is_disable = s.startswith("# CONFIG_") and s.endswith("is not set")
        if (is_assign or is_disable) and s not in have:
            missing.append(s)

    if missing:
        detail = "\n  ".join(missing)
        sys.exit(f"Config check failed for {board}: generated sdkconfig does not "
                 f"match board defaults (stale/leaked config?). Expected:\n  {detail}")


def _collect_artifacts(board: str, build_dir: Path, out_dir: Path) -> None:
    copies = {
        f"mate-{board}.bin":            build_dir / "janos-web-client.bin",
        f"partition-table-{board}.bin": build_dir / "partition_table" / "partition-table.bin",
        f"bootloader-{board}.bin":      build_dir / "bootloader" / "bootloader.bin",
        f"storage-{board}.bin":         build_dir / "storage.bin",
    }
    found = False
    for dest_name, src in copies.items():
        if src.exists():
            shutil.copy2(src, out_dir / dest_name)
            log(f"  copied {dest_name}")
            found = True
        else:
            log(f"  WARNING: {src} not found, skipping")
    if not found:
        sys.exit(f"No artifacts found in {build_dir} — build may have failed silently")


# ---------------------------------------------------------------------------
# Flasher generator
# ---------------------------------------------------------------------------

FLASHER_TEMPLATE = '''\
#!/usr/bin/env python3
"""
flash_board.py – Mate firmware flasher for {board}
Chip: {chip} | Flash: {flash_size} | Mode: {flash_mode} @ {flash_freq}

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

RED    = "\\033[91m"
GREEN  = "\\033[92m"
YELLOW = "\\033[93m"
CYAN   = "\\033[96m"
RESET  = "\\033[0m"

BOARD         = "{board}"
CHIP          = "{chip}"
FLASH_SIZE    = "{flash_size}"
FLASH_MODE    = "{flash_mode}"
FLASH_FREQ    = "{flash_freq}"
DEFAULT_BAUD  = 460800
MIN_ESPTOOL   = "5.2.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR   = os.environ.get("FLASH_BOARD_VENV", os.path.join(SCRIPT_DIR, ".venv"))

FILES = {{
    "bootloader":      ("{boot_offset}",   "bootloader-{board}.bin"),
    "partition-table": ("{ptable_offset}", "partition-table-{board}.bin"),
    "app":             ("{app_offset}",    "mate-{board}.bin"),
    "storage":         ("{spiffs_offset}", "storage-{board}.bin"),
}}

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
        print(f"{{YELLOW}}Creating .venv at {{VENV_DIR}}{{RESET}}")
        try:
            subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
        except subprocess.CalledProcessError:
            print(f"{{RED}}Failed to create venv. Install python3-venv and retry.{{RESET}}")
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
            missing.append(f"esptool>={{MIN_ESPTOOL}}")
    except ImportError:
        missing.append(f"esptool>={{MIN_ESPTOOL}}")
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
        print(f"{{RED}}Missing: {{', '.join(missing)}}{{RESET}}")
        sys.exit(1)
    print(f"{{GREEN}}All files present.{{RESET}}")

def list_ports():
    return {{p.device for p in serial.tools.list_ports.comports()}}

def wait_for_port(before, timeout=30.0):
    print(f"{{CYAN}}Hold BOOT and connect the board (or press BOOT + RESET).{{RESET}}")
    sp = ["|", "/", "-", "\\\\"]
    t0, i = time.time(), 0
    while time.time() - t0 < timeout:
        new = list_ports() - before
        sys.stdout.write(f"\\r{{sp[i % 4]}} "); sys.stdout.flush()
        i += 1
        if new:
            sys.stdout.write("\\r"); sys.stdout.flush()
            return new.pop()
        time.sleep(0.15)
    print(f"\\n{{RED}}Timeout — no new port detected.{{RESET}}")
    sys.exit(1)

def erase(port, baud):
    cmd = [sys.executable, "-m", "esptool",
           "-p", port, "-b", str(baud),
           "--chip", CHIP, "--before", "default-reset", "--after", "no_reset",
           "erase_flash"]
    print(f"{{CYAN}}Erasing flash...{{RESET}}")
    r = subprocess.run(cmd)
    if r.returncode:
        print(f"{{RED}}Erase failed ({{r.returncode}}).{{RESET}}")
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
    print(f"{{CYAN}}Flashing {board}{{mode}}...{{RESET}}")
    return subprocess.run(cmd).returncode

def reset_to_app(port):
    try:
        with serial.Serial(port, 115200, timeout=0.1) as s:
            s.dtr = False; time.sleep(0.05)
            s.rts = True;  time.sleep(0.05)
            s.rts = False
        print(f"{{GREEN}}Reset sent.{{RESET}}")
    except Exception as e:
        print(f"{{YELLOW}}RTS/DTR reset failed: {{e}} — press RESET manually.{{RESET}}")

def monitor(port, baud):
    print(f"{{CYAN}}Monitor on {{port}} @ {{baud}} (Ctrl+C to exit)...{{RESET}}")
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
        print(f"{{RED}}Monitor error: {{e}}{{RESET}}")

def main():
    ap = argparse.ArgumentParser(description=f"Mate flasher – {{BOARD}}")
    ap.add_argument("--port",    help="Serial port (e.g. COM3 or /dev/ttyUSB0)")
    ap.add_argument("--baud",    type=int, default=DEFAULT_BAUD)
    ap.add_argument("--erase",   action="store_true", help="Full erase before flashing")
    ap.add_argument("--monitor", action="store_true", help="Serial monitor after flash")
    ap.add_argument("--no-stub", action="store_true", help="Flash without the stub (slower, robust for finicky ESP32 modules)")
    args = ap.parse_args()

    check_files()
    print(f"{{CYAN}}Mate flasher | board: {{BOARD}} | chip: {{CHIP}} | flash: {{FLASH_SIZE}}{{RESET}}")

    port = args.port
    if not port:
        before = list_ports()
        port   = wait_for_port(before)
    print(f"{{GREEN}}Port: {{port}}{{RESET}}")

    if args.erase:
        erase(port, args.baud)

    rc = flash(port, args.baud, no_stub=args.no_stub)
    if rc and not args.no_stub:
        # Some ESP32 modules (e.g. ESP32-PICO-D4 on Atom Lite) drop the stub
        # when the baud is bumped. Fall back to a robust no-stub @ 115200 pass.
        print(f"{{YELLOW}}Flash failed at {{args.baud}} baud — retrying with --no-stub @ 115200 (slower but robust)...{{RESET}}")
        rc = flash(port, 115200, no_stub=True)
    if rc:
        print(f"{{RED}}Flash failed ({{rc}}).{{RESET}}")
        sys.exit(rc)
    reset_to_app(port)

    if args.monitor:
        monitor(port, args.baud)

if __name__ == "__main__":
    main()
'''


def generate_flasher(board: str, out_dir: Path) -> None:
    cfg = BOARDS[board]
    content = FLASHER_TEMPLATE.format(
        board          = board,
        chip           = cfg["chip"],
        flash_size     = cfg["flash_size"],
        flash_mode     = cfg["flash_mode"],
        flash_freq     = cfg["flash_freq"],
        boot_offset    = cfg["boot_offset"],
        ptable_offset  = cfg["ptable_offset"],
        app_offset     = cfg["app_offset"],
        spiffs_offset  = cfg["spiffs_offset"],
    )
    dest = out_dir / "flash_board.py"
    dest.write_text(content, encoding="utf-8")
    log(f"  generated flash_board.py")


# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build all Mate firmware permutations")
    p.add_argument(
        "--targets", default=None,
        help="Comma-separated boards to build (default: all). "
             f"Available: {','.join(BOARDS)}",
    )
    p.add_argument(
        "--keep-build", action="store_true",
        help="Keep build-<board>/ directories after build",
    )
    p.add_argument(
        "--output-dir", default=str(BINARIES_DIR),
        help=f"Root output directory (default: {BINARIES_DIR})",
    )
    p.add_argument(
        "--no-docker", action="store_true",
        help="Run idf.py directly instead of via Docker (for CI inside the "
             "espressif/idf container, or a host with esp-idf installed)",
    )
    p.add_argument(
        "--print-matrix", action="store_true",
        help="Print the board build matrix as JSON and exit. Single source of "
             "truth for the GitHub Actions matrix.",
    )
    p.add_argument(
        "--retry-failed", action="store_true",
        help="Rebuild only the boards that failed on the last run (read from "
             "the .build_failed state file). Leaves all other boards untouched.",
    )
    p.add_argument(
        "--retry", type=int, default=0, metavar="N",
        help="Auto re-attempt boards that fail, up to N extra times in this "
             "run (useful for flaky Docker/network failures). Default: 0.",
    )
    return p.parse_args()


def print_matrix() -> None:
    """Emit the board matrix as a compact JSON array for GitHub Actions to
    consume via `fromJSON`. Keeps the CI matrix in lockstep with BOARDS."""
    matrix = [{"board": b, "idf_target": cfg["idf_target"]}
              for b, cfg in BOARDS.items()]
    print(json.dumps(matrix))


STATE_FILE_NAME = ".build_failed"


def clean_board_dirs(out_root: Path, boards: list) -> None:
    for b in boards:
        d = out_root / b
        if d.exists():
            log(f"Cleaning {d} ...")
            shutil.rmtree(d)


def build_boards(boards: list, keep_build: bool, out_root: Path,
                 use_docker: bool) -> list:
    """Build each board; return the list that failed (in order)."""
    failed: list[str] = []
    for board in boards:
        try:
            build_board(board, keep_build, out_root, use_docker=use_docker)
            log(f"  -> artifacts written to {out_root / board}")
        except SystemExit as exc:
            log(f"  FAILED: {exc}")
            failed.append(board)
    return failed


def main() -> None:
    args = parse_args()

    if args.print_matrix:
        print_matrix()
        return

    if not args.no_docker and not docker_available():
        sys.exit("Docker is not available. Please install Docker and ensure the daemon is running.")

    out_root   = Path(args.output_dir)
    state_file = out_root / STATE_FILE_NAME

    # Read the previous run's failures BEFORE any cleaning (a full build wipes
    # out_root, taking the state file with it).
    prev_failed: list[str] = []
    if state_file.exists():
        prev_failed = [b for b in state_file.read_text(encoding="utf-8").split()
                       if b in BOARDS]

    # Decide which boards to build. retry-failed and targets are both "subset"
    # builds that leave untargeted boards' artifacts untouched.
    if args.retry_failed:
        if not prev_failed:
            sys.exit(f"No failed boards recorded in {state_file}; nothing to "
                     f"retry. Run a build first, or use --targets.")
        boards = prev_failed
        subset = True
        log(f"Retrying last failed board(s): {', '.join(boards)}")
    elif args.targets:
        boards = [b.strip() for b in args.targets.split(",")]
        unknown = [b for b in boards if b not in BOARDS]
        if unknown:
            sys.exit(f"Unknown board(s): {', '.join(unknown)}. Available: {', '.join(BOARDS)}")
        subset = True
    else:
        boards = list(BOARDS.keys())
        subset = False

    if subset:
        # Only clear the boards we're about to rebuild, so siblings' artifacts
        # (and their flashers) survive. CI builds one board per job into a
        # shared tree and relies on this.
        out_root.mkdir(parents=True, exist_ok=True)
        clean_board_dirs(out_root, boards)
    else:
        # Full build: wipe everything so a removed board leaves no stale output.
        if out_root.exists():
            log(f"Cleaning {out_root} ...")
            shutil.rmtree(out_root)
        out_root.mkdir(parents=True)

    log(f"Build matrix ({len(boards)} jobs):")
    for b in boards:
        log(f"  {b}  [{BOARDS[b]['idf_target']}]")

    failed = build_boards(boards, args.keep_build, out_root, not args.no_docker)

    # Auto re-attempt flaky failures within this same run.
    attempts_left = args.retry
    while failed and attempts_left > 0:
        attempts_left -= 1
        log(f"Re-attempting {len(failed)} failed board(s) "
            f"({attempts_left} more retr{'y' if attempts_left == 1 else 'ies'} after this): "
            f"{', '.join(failed)}")
        clean_board_dirs(out_root, failed)
        failed = build_boards(failed, args.keep_build, out_root, not args.no_docker)

    # Persist the failed set for --retry-failed. Merge with prior state: keep
    # previously-failed boards we didn't touch this run, drop the ones we just
    # fixed, add this run's failures.
    new_state = (set(prev_failed) - set(boards)) | set(failed)
    if new_state:
        out_root.mkdir(parents=True, exist_ok=True)
        state_file.write_text("\n".join(sorted(new_state)) + "\n", encoding="utf-8")
    elif state_file.exists():
        state_file.unlink()

    print()
    if failed:
        log(f"Build FAILED for: {', '.join(failed)}")
        log("Rebuild just these with:  python tools/build_all.py --retry-failed")
        sys.exit(1)
    else:
        log(f"All {len(boards)} build(s) succeeded. Binaries in: {out_root}")


if __name__ == "__main__":
    main()
