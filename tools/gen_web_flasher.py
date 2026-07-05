#!/usr/bin/env python3
"""
gen_web_flasher.py – generate the web-flasher manifests + board index for docs/
(served by GitHub Pages).

Single source of truth for the board set is tools/build_all.py:BOARDS, so the
dropdown on the flasher always lists exactly the boards CI builds — add a board
there and it shows up here automatically. Offsets, chip family and flash params
come from the same BOARDS entry, so what the browser flashes can never drift
from what build_all.py / flash_board.py flash.

For every board that has firmware present under --firmware-dir/<board>/ it writes:
  <out-dir>/manifest-<board>.json   esptool-js parts (bootloader, ptable, app, storage)
  <out-dir>/boards.json             dropdown index (id, label, chip, chipFamily, …)

A part is included only if its .bin exists on disk, so a partial download or a
board without a SPIFFS image degrades gracefully instead of producing a manifest
that points at a missing file.

Usage:
  python tools/gen_web_flasher.py --firmware-dir docs/firmware --out-dir docs \
      --version 0.1.0 --build v0.1.0
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_all import BOARDS  # noqa: E402  (single source of truth for the matrix)

# Human-friendly names for the dropdown. Missing entries fall back to the board
# id, so an unlabeled board is still listed (just with its raw id).
LABELS = {
    "xiao-c6":      "XIAO ESP32-C6",
    "nanoc6":       "M5Stack NanoC6",
    "cores3":       "M5Stack CoreS3 SE",
    "atoms3r":      "M5Stack AtomS3R",
    "atoms3":       "M5Stack AtomS3",
    "atoms3-lite":  "M5Stack AtomS3 Lite",
    "stickc-plus2": "M5StickC PLUS2",
    "sticks3":      "M5Stack StickS3",
    "atom-lite":    "M5Stack Atom Lite",
    "atom-lite-c21_25": "M5Stack Atom Lite C21_25",
    "atom-matrix":  "M5Stack Atom Matrix",
    "coreink":      "M5Stack CoreInk",
    "atoms3u":      "M5Stack AtomS3U",
}

# idf_target/chip -> esptool-js / ESP Web Tools chipFamily string.
CHIP_FAMILY = {
    "esp32":   "ESP32",
    "esp32c6": "ESP32-C6",
    "esp32s3": "ESP32-S3",
}

# (BOARDS offset key, filename template) in flash order. Mate always ships a
# SPIFFS "storage" image (the embedded web UI), so it is a first-class part —
# omitting it would boot the device with no UI.
PARTS = [
    ("boot_offset",   "bootloader-{board}.bin"),
    ("ptable_offset", "partition-table-{board}.bin"),
    ("app_offset",    "mate-{board}.bin"),
    ("spiffs_offset", "storage-{board}.bin"),
]


def chip_family(chip: str) -> str:
    return CHIP_FAMILY.get(chip, chip.upper())


def build_manifest(board: str, cfg: dict, fw_dir: Path, version: str, build_tag: str):
    parts = []
    for off_key, fname_tpl in PARTS:
        fname = fname_tpl.format(board=board)
        if not (fw_dir / board / fname).exists():
            continue
        parts.append({
            "path":   f"firmware/{board}/{fname}",
            "offset": int(cfg[off_key], 16),  # 0x1000 etc. -> flat byte offset
        })
    if not parts:
        return None
    return {
        "name":       f"Mate — {LABELS.get(board, board)}",
        "board":      board,
        "version":    version,
        "build":      build_tag,
        "chipFamily": chip_family(cfg["chip"]),
        "flashSize":  cfg["flash_size"],
        "flashMode":  cfg["flash_mode"],
        "flashFreq":  cfg["flash_freq"],
        "parts":      parts,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate web-flasher manifests + board index")
    p.add_argument("--firmware-dir", required=True,
                   help="Directory containing <board>/ subdirs with the .bin files")
    p.add_argument("--out-dir", required=True,
                   help="Where to write manifest-*.json and boards.json")
    p.add_argument("--version", default="", help="Firmware version stamp (e.g. 0.1.0)")
    p.add_argument("--build", default="", help="Build/tag label (e.g. v0.1.0)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    fw_dir  = Path(args.firmware_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    version   = args.version or "dev"
    build_tag = args.build or version

    index = []
    for board, cfg in BOARDS.items():
        manifest = build_manifest(board, cfg, fw_dir, version, build_tag)
        if not manifest:
            print(f"skip {board}: no firmware under {fw_dir / board}", file=sys.stderr)
            continue
        (out_dir / f"manifest-{board}.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        index.append({
            "id":         board,
            "label":      LABELS.get(board, board),
            "chip":       cfg["chip"],
            "chipFamily": chip_family(cfg["chip"]),
            "flashSize":  cfg["flash_size"],
            "manifest":   f"manifest-{board}.json",
        })

    if not index:
        sys.exit(f"No manifests generated — no firmware found under {fw_dir}")

    boards_json = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "version":     version,
        "build":       build_tag,
        "boards":      index,
    }
    (out_dir / "boards.json").write_text(
        json.dumps(boards_json, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(index)} manifest(s) + boards.json in {out_dir}")


if __name__ == "__main__":
    main()
