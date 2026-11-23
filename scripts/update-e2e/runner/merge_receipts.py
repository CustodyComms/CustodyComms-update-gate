#!/usr/bin/env python3
"""Merges the per-cell receipts of one platform into that platform's single receipt, and copies the cells'
encrypted diagnostics beside it. Exit 0 only when every planned cell passed.

    python merge_receipts.py --platform windows|macos --mac-variant A|B|C --mode gate|live|pin --only IDS
        --bind gate-run.json --cells-dir DIR --planned JSON --receipt OUT.json --diag-out DIR
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True, choices=common.PLATFORMS)
    ap.add_argument("--mac-variant", required=True, choices=common.MAC_VARIANTS)
    ap.add_argument("--mode", required=True, choices=("gate", "live", "pin"))
    ap.add_argument("--only", default="")
    ap.add_argument("--bind", required=True)
    ap.add_argument("--cells-dir", required=True)
    ap.add_argument("--planned", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--diag-out", required=True)
    a = ap.parse_args(argv)
    try:
        planned = [str(x) for x in json.loads(a.planned or "[]")]
    except ValueError:
        planned = []
    bind = common.load_json(Path(a.bind))
    cells_dir = Path(a.cells_dir)
    found = []
    if cells_dir.is_dir():
        for f in sorted(cells_dir.glob("update-e2e-cell-*.json")):
            try:
                found.append(json.loads(f.read_text(encoding="utf-8")))
            except ValueError:
                continue
    receipt = common.merge_receipts(
        found, planned=[p for p in planned if p != "pin"], bind=bind, platform=a.platform, mode=a.mode,
        mac_variant=a.mac_variant, only=a.only, cells_doc=common.load_json(common.CELLS),
        finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    Path(a.receipt).write_text(json.dumps(receipt, indent=1) + "\n", encoding="utf-8")
    out = Path(a.diag_out)
    out.mkdir(parents=True, exist_ok=True)
    if cells_dir.is_dir():
        for f in sorted(cells_dir.glob("update-e2e-diag-*.enc")):
            shutil.copy(f, out / f.name)
    for c in receipt["cells"]:
        print(f"cell {c['id']}: {c['result']} {c['detail']} ({c['seconds']} s, attempt {c['attempts']})")
    ok = bool(receipt["cells"]) and all(c["result"] == "pass" for c in receipt["cells"])
    print(f"overall: {'pass' if ok else 'not pass'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
