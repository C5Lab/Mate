#!/usr/bin/env python3
"""
build_all_cache.py – build_all.py with an EFFECTIVE ccache + smart parallelism.

Why the first naive attempt got 0% ccache hits, and how this fixes it
---------------------------------------------------------------------
ccache keys a compile on (preprocessed source + the exact compiler args). Two
things were busting the key across boards:

  1. Per-board build dir.  Building board X into build-X/ puts "build-X/config"
     on the -I line; board Y uses "build-Y/config". Different args => different
     key => every file a miss, even when the source is identical.
     FIX: build INSIDE the container at a FIXED path (/tmp/idfbuild) for every
     board. The path is identical across boards, so same-target siblings share
     the cache. Bonus: the build tree lives on the container's fast fs, not the
     slow Windows bind mount, so builds are quicker too. Artifacts are copied
     out to binaries/<board>/ at the end.

  2. Same target built concurrently.  If two esp32c6 boards compile at once they
     BOTH miss (neither's objects are cached yet). Different targets never share
     a cache anyway.
     FIX: schedule per-target "lanes". Boards of the same target run
     SEQUENTIALLY (board 1 primes ccache, board 2..N hit); different targets run
     in PARALLEL (up to -n lanes). One board is built first as a warmup to prime
     the shared component-manager cache (managed_components/ + dependencies.lock)
     before any concurrency.

Net effect: the first board of each target is cold; every sibling is a near-full
cache hit. See BUILD.md ("Fast local builds: ccache + target lanes").

Output is identical to build_all.py: binaries/<board>/{mate,bootloader,
partition-table,storage}.bin + flash_board.py.

Usage:
  python tools/build_all_cache.py                 # all boards, auto lanes, ccache
  python tools/build_all_cache.py -n 3            # up to 3 target-lanes at once
  python tools/build_all_cache.py -n 2 --targets cores3,atoms3,nanoc6,xiao-c6
  python tools/build_all_cache.py --ccache-max 30G --build-cpus 8
  python tools/build_all_cache.py --no-color --verbose
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Single source of truth: reuse build_all.py's matrix + pure helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_all  # noqa: E402
from build_all import (  # noqa: E402
    BOARDS, IMAGE, REPO_ROOT, CACHE_DIR, BINARIES_DIR,
    build_web, generate_flasher, _collect_artifacts, docker_available,
    print_matrix,
)

CCACHE_DIR          = REPO_ROOT / ".ccache"   # host dir, only used on --no-docker
CCACHE_VOLUME       = "mate_ccache"     # Docker named volume for the ccache store.
                                        # Bind-mounting a Windows .ccache dir makes
                                        # ccache *store* but never *hit* (virtiofs
                                        # breaks its atomic lookups) -> the named
                                        # volume lives on ext4 in the WSL2 VM, where
                                        # ccache works and is faster. Clear it with:
                                        #   docker volume rm mate_ccache
STATE_FILE_NAME     = ".build_failed"
CONTAINER_BUILD_DIR = "/tmp/idfbuild"   # identical path for every board -> ccache shares

# ---------------------------------------------------------------------------
# Colors (ANSI, auto-off when piped / NO_COLOR / --no-color; Windows VT enabled)
# ---------------------------------------------------------------------------

_USE_COLOR = False
_UNICODE   = True
RESET = BOLD = DIM = RED = GREEN = YELLOW = CYAN = ""
SYM_OK, SYM_FAIL, SYM_RUN, RULE, DOT = "OK", "XX", ">", "-", "-"


def _init_style(force_off: bool) -> None:
    global _USE_COLOR, _UNICODE
    global RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN
    global SYM_OK, SYM_FAIL, SYM_RUN, RULE, DOT

    use = (not force_off) and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    if use and os.name == "nt":
        os.system("")  # enable ANSI VT processing in Win10+ consoles

    _USE_COLOR = use
    if use:
        RESET  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
        RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; CYAN = "\033[96m"

    # Fancy glyphs only if the console encoding can render them (cmd.exe on a
    # legacy codepage cannot -> fall back to ASCII to avoid mojibake/crashes).
    try:
        "✓✗▶━·".encode(sys.stdout.encoding or "ascii")
        _UNICODE = True
    except (UnicodeEncodeError, LookupError):
        _UNICODE = False
    if _UNICODE:
        SYM_OK, SYM_FAIL, SYM_RUN, RULE, DOT = "✓", "✗", "▶", "━", "·"
    else:
        SYM_OK, SYM_FAIL, SYM_RUN, RULE, DOT = "OK", "XX", ">", "=", "-"


_print_lock = threading.Lock()


def out(msg: str = "") -> None:
    with _print_lock:
        print(msg, flush=True)


def rule(label: str = "") -> None:
    bar = RULE * 54
    if label:
        out(f"{BOLD}{CYAN}{bar}{RESET}")
        out(f"{BOLD}  {label}{RESET}")
        out(f"{BOLD}{CYAN}{bar}{RESET}")
    else:
        out(f"{BOLD}{CYAN}{bar}{RESET}")


def _tail(path: Path, n: int) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="ignore").splitlines()[-n:])
    except OSError:
        return "(no log)"


# ---------------------------------------------------------------------------
# Progress (thread-safe; lanes run in worker threads)
# ---------------------------------------------------------------------------

class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = self.ok = self.fail = 0
        self.times: dict = {}
        self._lock = threading.Lock()

    def start(self, board: str, target: str, extra: str = "") -> None:
        out(f"        {CYAN}{SYM_RUN}{RESET} {board:<16} {DIM}{target}{extra}{RESET}")

    def finish(self, board: str, ok: bool, secs: float, note: str = "") -> None:
        with self._lock:
            self.done += 1
            if ok:
                self.ok += 1
            else:
                self.fail += 1
            self.times[board] = secs
            done, left = self.done, self.total - self.done
        mark = f"{GREEN}{SYM_OK}{RESET}" if ok else f"{RED}{SYM_FAIL}{RESET}"
        left_s = f"  {DIM}{DOT} {left} left{RESET}" if left else ""
        note_s = f"  {note}" if note else ""
        out(f"[{done:>2}/{self.total}] {mark} {board:<16} {secs:>4.0f}s{left_s}{note_s}")


# ---------------------------------------------------------------------------
# Per-board build
# ---------------------------------------------------------------------------

def _verify_config(board: str, cfg: dict, sdkconfig: Path) -> None:
    if not sdkconfig.exists():
        raise RuntimeError(f"no sdkconfig produced ({sdkconfig.name})")
    have = set(l.rstrip() for l in
               sdkconfig.read_text(encoding="utf-8", errors="ignore").splitlines())
    board_defaults = REPO_ROOT / cfg["sdkconfig_defaults"].split(";")[-1]
    if not board_defaults.exists():
        return
    missing = []
    for raw in board_defaults.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        is_assign  = s.startswith("CONFIG_") and "=" in s
        is_disable = s.startswith("# CONFIG_") and s.endswith("is not set")
        if (is_assign or is_disable) and s not in have:
            missing.append(s)
    if missing:
        raise RuntimeError("sdkconfig does not match board defaults "
                           "(stale/leaked config?): " + "; ".join(missing))


def build_board(board: str, out_root: Path, use_docker: bool,
                ccache_max: str, build_cpus: int, keep_build: bool) -> None:
    """Build one board. Raises RuntimeError on failure. Output is captured to
    build-<board>.log (kept on failure, removed on success)."""
    cfg      = BOARDS[board]
    target   = cfg["idf_target"]
    defaults = cfg["sdkconfig_defaults"]
    out_dir  = out_root / board
    log_path = REPO_ROOT / f"build-{board}.log"
    out_dir.mkdir(parents=True, exist_ok=True)

    if use_docker:
        # Build at a FIXED in-container path (fast fs + identical -I across boards
        # => ccache shares). Copy the 4 images + sdkconfig out to the mounted
        # binaries/<board> dir. `&&` chain so any step failing fails the build.
        b = CONTAINER_BUILD_DIR
        inner = (
            ". /opt/esp/idf/export.sh >/dev/null 2>&1"
            f" && idf.py -B {b} -D SDKCONFIG={b}/sdkconfig"
            f" -D SDKCONFIG_DEFAULTS='{defaults}' set-target {target}"
            f" && idf.py -B {b} -D SDKCONFIG={b}/sdkconfig build"
            f" && cp {b}/janos-web-client.bin /out/mate-{board}.bin"
            f" && cp {b}/partition_table/partition-table.bin /out/partition-table-{board}.bin"
            f" && cp {b}/bootloader/bootloader.bin /out/bootloader-{board}.bin"
            f" && cp {b}/storage.bin /out/storage-{board}.bin"
            f" && cp {b}/sdkconfig /out/.sdkconfig.check"
        )
        cmd = [
            "docker", "run", "--rm",
            "--workdir", "/project",
            "--env", f"IDF_TARGET={target}",
            "--env", "IDF_CCACHE_ENABLE=1",
            "--env", "CCACHE_DIR=/root/.ccache",
            "--env", "CCACHE_BASEDIR=/project",
            "--env", f"CCACHE_MAXSIZE={ccache_max}",
            # Preprocessor mode: DIRECT mode hashes the full content of every
            # included header, and near-every ESP-IDF file includes the
            # per-board sdkconfig.h -> 0 hits. Preprocessor mode hashes the
            # PREPROCESSED output, so files that don't use the board-specific
            # CONFIG_JANOS_* defines are identical across same-target boards
            # and hit. time_macros keeps __DATE__/__TIME__ from busting it.
            "--env", "CCACHE_NODIRECT=1",
            "--env", "CCACHE_SLOPPINESS=time_macros",
            # Hash the compiler by CONTENT, not mtime. The IDF toolchain lives on
            # the bind-mounted .espressif (Windows) and virtiofs reports an
            # unstable mtime across container instances -> compiler_check=mtime
            # gives a different key every `docker run` -> 0 hits even on an
            # identical rebuild. Content hashing is stable across containers.
            "--env", "CCACHE_COMPILERCHECK=content",
            "--volume", f"{REPO_ROOT}:/project",
            "--volume", f"{CACHE_DIR}:/root/.espressif",
            "--volume", f"{CCACHE_VOLUME}:/root/.ccache",
            "--volume", f"{out_dir}:/out",
        ]
        if build_cpus and build_cpus > 0:
            cmd += ["--cpus", str(build_cpus)]
        cmd += [IMAGE, "bash", "-c", inner]

        with open(log_path, "w", encoding="utf-8", errors="ignore") as lf:
            rc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=lf, stderr=subprocess.STDOUT).returncode
        if rc != 0:
            raise RuntimeError(f"docker build rc={rc}")

        check = out_dir / ".sdkconfig.check"
        _verify_config(board, cfg, check)
        for name in (f"mate-{board}.bin", f"bootloader-{board}.bin",
                     f"partition-table-{board}.bin", f"storage-{board}.bin"):
            if not (out_dir / name).exists():
                raise RuntimeError(f"artifact missing: {name}")
        generate_flasher(board, out_dir)
        check.unlink(missing_ok=True)
        log_path.unlink(missing_ok=True)
        return

    # --------- --no-docker path (CI / host inside the esp-idf container) --------
    # One board per runner there, so per-board build dir is fine (no cross-board
    # sharing needed). Isolated sdkconfig keeps it parallel-safe regardless.
    build_dir     = REPO_ROOT / f"build-{board}"
    sdkconfig_rel = f"sdkconfig.build-{board}"
    for p in (REPO_ROOT / sdkconfig_rel, REPO_ROOT / f"{sdkconfig_rel}.old"):
        p.unlink(missing_ok=True)
    shutil.rmtree(build_dir, ignore_errors=True)

    inner = (
        ". /opt/esp/idf/export.sh >/dev/null 2>&1"
        f" && idf.py -B build-{board} -D SDKCONFIG='{sdkconfig_rel}'"
        f" -D SDKCONFIG_DEFAULTS='{defaults}' set-target {target}"
        f" && idf.py -B build-{board} -D SDKCONFIG='{sdkconfig_rel}' build"
    )
    env = {**os.environ, "IDF_CCACHE_ENABLE": "1",
           "CCACHE_DIR": str(CCACHE_DIR), "CCACHE_MAXSIZE": ccache_max,
           "CCACHE_NODIRECT": "1", "CCACHE_SLOPPINESS": "time_macros",
           "CCACHE_COMPILERCHECK": "content"}
    with open(log_path, "w", encoding="utf-8", errors="ignore") as lf:
        rc = subprocess.run(["bash", "-c", inner], cwd=REPO_ROOT, env=env,
                            stdout=lf, stderr=subprocess.STDOUT).returncode
    if rc != 0:
        raise RuntimeError(f"build rc={rc}")

    _verify_config(board, cfg, REPO_ROOT / sdkconfig_rel)
    _collect_artifacts(board, build_dir, out_dir)
    generate_flasher(board, out_dir)
    if not keep_build:
        shutil.rmtree(build_dir, ignore_errors=True)
        for p in (REPO_ROOT / sdkconfig_rel, REPO_ROOT / f"{sdkconfig_rel}.old"):
            p.unlink(missing_ok=True)
    log_path.unlink(missing_ok=True)


def _run_one(board: str, out_root: Path, use_docker: bool, ccache_max: str,
             build_cpus: int, keep_build: bool, prog: Progress) -> bool:
    prog.start(board, BOARDS[board]["idf_target"],
               f"  cpus={build_cpus}" if (use_docker and build_cpus) else "")
    t0 = time.time()
    try:
        build_board(board, out_root, use_docker, ccache_max, build_cpus, keep_build)
        prog.finish(board, True, time.time() - t0)
        return True
    except (Exception, SystemExit) as exc:
        prog.finish(board, False, time.time() - t0,
                    note=f"{RED}{exc}{RESET} {DIM}-> build-{board}.log{RESET}")
        out(f"{DIM}{_tail(REPO_ROOT / f'build-{board}.log', 12)}{RESET}")
        return False


# ---------------------------------------------------------------------------
# Target-lane scheduling: same target sequential, different targets parallel
# ---------------------------------------------------------------------------

def _target_lanes(boards: list) -> list:
    lanes: dict = {}
    for b in boards:
        lanes.setdefault(BOARDS[b]["idf_target"], []).append(b)
    return list(lanes.items())  # [(target, [boards...]), ...] in first-seen order


def run_build(boards: list, n: int, out_root: Path, use_docker: bool,
              ccache_max: str, build_cpus: int, keep_build: bool,
              prog: Progress, warmup: bool) -> list:
    failed: list = []
    lanes = _target_lanes(boards)

    # Warmup: build one board sequentially first. Primes the shared
    # component-manager cache (managed_components/ + dependencies.lock) so the
    # concurrent lanes only read it, and warms that target's ccache.
    if warmup and len(boards) > 1:
        wt, wl = lanes[0]
        first = wl.pop(0)
        out(f"{YELLOW}warmup{RESET} (sequential; primes deps + {wt} ccache): {first}")
        if not _run_one(first, out_root, use_docker, ccache_max, build_cpus, keep_build, prog):
            failed.append(first)
        if not wl:
            lanes.pop(0)

    def run_lane(bl: list) -> list:
        lane_failed = []
        for b in bl:  # sequential within a lane => same target never overlaps
            if not _run_one(b, out_root, use_docker, ccache_max, build_cpus, keep_build, prog):
                lane_failed.append(b)
        return lane_failed

    lanes = [bl for _, bl in lanes if bl]
    if n <= 1 or len(lanes) <= 1:
        for bl in lanes:
            failed += run_lane(bl)
    else:
        with ThreadPoolExecutor(max_workers=min(n, len(lanes))) as ex:
            for res in [f.result() for f in [ex.submit(run_lane, bl) for bl in lanes]]:
                failed += res
    return failed


# ---------------------------------------------------------------------------
# ccache control + stats
# ---------------------------------------------------------------------------

def _ccache(args: str, use_docker: bool, capture: bool = False):
    if use_docker:
        cmd = ["docker", "run", "--rm",
               "--volume", f"{CCACHE_VOLUME}:/root/.ccache",
               "--env", "CCACHE_DIR=/root/.ccache",
               IMAGE, "bash", "-c", f"ccache {args}"]
        env = None
    else:
        if not shutil.which("ccache"):
            return ""
        cmd = ["bash", "-c", f"ccache {args}"]
        env = {**os.environ, "CCACHE_DIR": str(CCACHE_DIR)}
    try:
        r = subprocess.run(cmd, env=env, capture_output=capture, text=True)
        return (r.stdout or "") if capture else ""
    except Exception:
        return ""


def ccache_prime(use_docker: bool, ccache_max: str) -> None:
    # Persist the max size (so `ccache -s` reflects it) and zero the counters so
    # the end-of-run stats describe THIS run only.
    _ccache(f"-M {ccache_max} && ccache -z", use_docker)


def ccache_summary(use_docker: bool, verbose: bool) -> None:
    s = _ccache("-s", use_docker, capture=True)
    if not s:
        return
    if verbose:
        out(DIM + s.strip() + RESET)
    m_hits = re.search(r"Hits:\s+(\d+)\s*/\s*(\d+)", s)
    m_miss = re.search(r"Misses:\s+(\d+)", s)
    m_size = re.search(r"Cache size \(([GM]iB)\):\s+([\d.]+)\s*/\s*([\d.]+)", s)
    hits  = int(m_hits.group(1)) if m_hits else 0
    calls = int(m_hits.group(2)) if m_hits else 0
    miss  = int(m_miss.group(1)) if m_miss else 0
    pct   = (100.0 * hits / calls) if calls else 0.0
    color = GREEN if pct >= 50 else (YELLOW if pct >= 15 else RED)
    line  = f"  ccache: {color}{pct:.0f}% hit{RESET} ({hits} hit / {miss} miss)"
    if m_size:
        line += f"  {DIM}{DOT} {m_size.group(2)}/{m_size.group(3)} {m_size.group(1)}{RESET}"
    out(line)


# ---------------------------------------------------------------------------

def clean_board_dirs(out_root: Path, boards: list) -> None:
    for b in boards:
        d = out_root / b
        if d.exists():
            shutil.rmtree(d)


def parse_args() -> argparse.Namespace:
    argv = []
    for a in sys.argv[1:]:                       # accept the colloquial "-n=2"
        argv += ["-n", a[3:]] if a.startswith("-n=") else [a]

    p = argparse.ArgumentParser(
        description="Build Mate firmware with an effective ccache + target lanes")
    p.add_argument("-n", "--jobs", type=int, default=0, metavar="N",
                   help="Max target-lanes to build concurrently (default: number "
                        "of distinct targets among the selected boards). Same "
                        "target never overlaps; only different targets run at once.")
    p.add_argument("--targets", default=None,
                   help=f"Comma-separated boards (default: all). {','.join(BOARDS)}")
    p.add_argument("--keep-build", action="store_true",
                   help="Keep build-<board>/ (only affects --no-docker path)")
    p.add_argument("--output-dir", default=str(BINARIES_DIR))
    p.add_argument("--no-docker", action="store_true",
                   help="Run idf.py directly (inside esp-idf container / CI); "
                        "requires --no-web because the web build uses Docker")
    p.add_argument("--no-web", action="store_true", help="Skip the web UI rebuild")
    p.add_argument("--ccache-max", default="20G", metavar="SIZE",
                   help="ccache max size, e.g. 20G / 30G (default: 20G)")
    p.add_argument("--build-cpus", type=int, default=None, metavar="C",
                   help="Docker CPUs per concurrent build (default: ~ncpu/lanes; "
                        "0 = no cap)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--verbose", action="store_true",
                   help="Show full ccache -s and don't hide build_all chatter")
    p.add_argument("--retry-failed", action="store_true")
    p.add_argument("--retry", type=int, default=0, metavar="N")
    p.add_argument("--print-matrix", action="store_true")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    if args.print_matrix:
        print_matrix()
        return

    _init_style(args.no_color)
    if not args.verbose:
        build_all.log = lambda *a, **k: None      # hush the "copied X.bin" chatter

    if not args.no_docker and not docker_available():
        sys.exit("Docker is not available. Install Docker and start the daemon.")

    out_root   = Path(args.output_dir)
    state_file = out_root / STATE_FILE_NAME
    prev_failed = [b for b in (state_file.read_text(encoding="utf-8").split()
                               if state_file.exists() else []) if b in BOARDS]

    if args.retry_failed:
        if not prev_failed:
            sys.exit(f"No failed boards in {state_file}; nothing to retry.")
        boards, subset = prev_failed, True
    elif args.targets:
        boards = [b.strip() for b in args.targets.split(",")]
        unknown = [b for b in boards if b not in BOARDS]
        if unknown:
            sys.exit(f"Unknown board(s): {', '.join(unknown)}")
        subset = True
    else:
        boards, subset = list(BOARDS.keys()), False

    n_targets = len({BOARDS[b]["idf_target"] for b in boards})
    n = args.jobs if args.jobs > 0 else n_targets
    if args.build_cpus is not None:
        build_cpus = args.build_cpus
    else:
        ncpu = os.cpu_count() or 4
        lanes_at_once = min(n, n_targets)
        build_cpus = max(1, ncpu // lanes_at_once) if (lanes_at_once > 1 and not args.no_docker) else 0

    if subset:
        out_root.mkdir(parents=True, exist_ok=True)
        clean_board_dirs(out_root, boards)
    else:
        if out_root.exists():
            shutil.rmtree(out_root)
        out_root.mkdir(parents=True)
    CCACHE_DIR.mkdir(exist_ok=True)
    CACHE_DIR.mkdir(exist_ok=True)

    rule(f"Mate firmware {DOT} {len(boards)} boards {DOT} {min(n, n_targets)} lanes "
         f"({n_targets} targets) {DOT} ccache {args.ccache_max}")
    for t, bl in _target_lanes(boards):
        out(f"  {DIM}{t}:{RESET} {', '.join(bl)}")

    if not args.no_web:
        out(f"{DIM}building web UI -> spiffs/ ...{RESET}")
        build_web(not args.no_docker)

    ccache_prime(not args.no_docker, args.ccache_max)

    prog = Progress(len(boards))
    t0 = time.time()
    failed = run_build(boards, n, out_root, not args.no_docker, args.ccache_max,
                       build_cpus, args.keep_build, prog, warmup=True)

    attempts_left = args.retry
    while failed and attempts_left > 0:
        attempts_left -= 1
        out(f"{YELLOW}retry{RESET} {len(failed)} board(s): {', '.join(failed)}")
        clean_board_dirs(out_root, failed)
        failed = run_build(failed, n, out_root, not args.no_docker, args.ccache_max,
                           build_cpus, args.keep_build, prog, warmup=False)

    new_state = (set(prev_failed) - set(boards)) | set(failed)
    if new_state:
        out_root.mkdir(parents=True, exist_ok=True)
        state_file.write_text("\n".join(sorted(new_state)) + "\n", encoding="utf-8")
    elif state_file.exists():
        state_file.unlink()

    total = time.time() - t0
    slow = sorted(prog.times.items(), key=lambda kv: kv[1], reverse=True)[:3]
    out()
    rule()
    ok_n = len(boards) - len(failed)
    out(f"  {GREEN}{SYM_OK} {ok_n} ok{RESET}   "
        + (f"{RED}{SYM_FAIL} {len(failed)} failed{RESET}   " if failed else "")
        + f"{DIM}{DOT} {total:.0f}s{RESET}")
    if slow:
        out("  " + DIM + "slowest: " + " · ".join(f"{b} {s:.0f}s" for b, s in slow) + RESET)
    ccache_summary(not args.no_docker, args.verbose)
    if failed:
        out(f"  {RED}failed:{RESET} {', '.join(failed)}   "
            f"{DIM}-> python tools/build_all_cache.py --retry-failed{RESET}")
    rule()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
