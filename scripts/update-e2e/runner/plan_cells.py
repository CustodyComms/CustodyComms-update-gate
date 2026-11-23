#!/usr/bin/env python3
"""Lists the cells each platform's matrix runs, as GitHub step outputs (`windows=[...]`, `macos=[...]`).

    python plan_cells.py --mode gate|live|pin --mac-variant A|B|C [--only id,id]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=("gate", "live", "pin"))
    ap.add_argument("--mac-variant", required=True, choices=common.MAC_VARIANTS)
    ap.add_argument("--only", default="")
    a = ap.parse_args(argv)
    for platform, ids in common.plan(common.load_json(common.CELLS), a.mode, a.mac_variant, a.only).items():
        print(f"{platform}={json.dumps(ids, separators=(',', ':'))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
