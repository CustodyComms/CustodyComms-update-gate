#!/usr/bin/env python3
"""Binds this run to the commit its gate files came from, before any cell runs.

In the staging repo (public): GATE-SOURCE.json names the source commit, the gate-files hash and the staging tag;
the hash of this checkout's own gate files must equal it. Only a manual dispatch may run there.
Anywhere else (private): the source commit is this run's own head.

    python bind.py --out gate-run.json        exit 0 bound; 1 refused (one line says why)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common  # noqa: E402

REPO_ROOT = HERE.parents[2]


def bind(env: dict, repo_root: Path = REPO_ROOT) -> dict:
    cfg = common.load_json(common.CONFIG)
    here = env.get("GITHUB_REPOSITORY", "")
    head = env.get("GITHUB_SHA", "")
    event = env.get("GITHUB_EVENT_NAME", "")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("no run head")
    if here != cfg["runsIn"]:
        raise ValueError("this repository is not the one the gate is configured to run in")
    digest, _ = common.files_hash(repo_root, "HEAD")
    if here == cfg["stagingRepo"]:
        if event != "workflow_dispatch":
            raise ValueError("in the staging repository the gate runs only on a manual dispatch")
        src = common.load_json(repo_root / "GATE-SOURCE.json")
        if src.get("gateFilesHash") != digest:
            raise ValueError("this checkout's gate files are not the ones the source commit holds")
        if not re.fullmatch(r"[0-9a-f]{40}", src.get("sourceCommit", "")):
            raise ValueError("GATE-SOURCE.json has no source commit")
        variant, source, tag = "public", src["sourceCommit"], src["stagingTag"]
    else:
        variant, source = "private", head
        pkg = json.loads((repo_root / "frontend" / "package.json").read_text(encoding="utf-8"))
        tag = "v" + pkg["version"]
    return {"variant": variant, "gateRepo": here, "gateCommit": head, "sourceCommit": source,
            "gateFilesHash": digest, "stagingRepo": cfg["stagingRepo"], "stagingTag": tag,
            "runId": env.get("GITHUB_RUN_ID"), "runAttempt": env.get("GITHUB_RUN_ATTEMPT")}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        b = bind(dict(os.environ))
    except (ValueError, OSError, KeyError) as e:
        print(f"bind: refused: {e}")
        return 1
    Path(a.out).write_text(json.dumps(b, indent=1) + "\n", encoding="utf-8")
    print(f"bind: {b['variant']} run of source commit {b['sourceCommit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
