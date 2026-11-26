"""Shared pieces of the update test runner: job names, file formats, hashing, cell selection, result codes,
and the encryption of diagnostics.

Everything printed to the job log is a step name, a cell id, a result and a duration. Anything longer (driver
traces, application output) goes into a diagnostics bundle that is encrypted to the public key beside this file
before it leaves the machine.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = HERE / "from-versions.json"
CELLS = HERE / "cells.json"
DIAG_PUBKEY = HERE / "diag-pubkey.pem"
CONFIG = HERE / "gate-config.json"

# The files a gate run is made of. Their git blob ids, hashed, bind a run to the commit they came from.
GATE_PATHS = (".github/workflows/update-e2e.yml", "scripts/update-e2e/runner")

RECEIPT_FORMAT = "cc-update-e2e-receipt/1"
INVENTORY_FORMAT = "cc-update-e2e-inventory/1"
CELLS_FORMAT = "cc-update-e2e-cells/1"
DIAG_FORMAT = "cc-update-e2e-diag/1"

JOB_NAMES = {
    "windows": "Update gate, Windows x64",
    "macos": "Update gate, macOS Apple Silicon",
}
PLATFORMS = tuple(JOB_NAMES)
MAC_VARIANTS = ("A", "B", "C")
RESULTS = ("pass", "fail", "inconclusive", "not_run")
BLOCKING_KINDS = ("required", "control")  # a "reported" cell is recorded and never fails a job


def all_blocking_passed(cells: list[dict]) -> bool:
    """True when every required or control cell passed and there is at least one. Reported cells do not count."""
    blocking = [c for c in cells if c.get("kind", "required") in BLOCKING_KINDS]
    return bool(blocking) and all(c["result"] == "pass" for c in blocking)

# The only words a cell may carry in its `detail`. A closed list keeps free text (and with it anything an
# application wrote) out of the plain receipt.
REASONS = frozenset({
    "ok", "precondition_failed", "pin_missing", "download_mismatch", "signature_invalid", "debug_port_unreachable",
    "offer_timeout", "download_timeout", "ready_button_not_clickable", "installer_timeout", "installer_exit_nonzero",
    "setup_window_seen", "wrong_version", "not_reopened", "reopened_unexpectedly", "reopened_exited",
    "arrival_record_missing", "health_failed", "trace_mismatch", "control_no_defect", "control_no_window",
    "still_running_expected_exit", "exited_expected_running", "reset_failed", "unsupported_on_platform", "error",
    # bring-up 23 Nov: an inconclusive cell says which step it stopped at
    "update_never_ready", "offer_not_opened", "cell_timeout", "cell_job_lost",
    # mac-quit-during-verify
    "verify_window_missed",
    # win-quit-from-self
    "backstop_exit", "quit_not_logged", "orphans",
})


def sha512_b64(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return base64.b64encode(h.digest()).decode("ascii")


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── a file staged as parts ────────────────────────────────────────────────────────────────────────

# A release asset has a size limit (2 GiB), so a larger file is staged as ordered parts, listed in the inventory
# under the one file they join to. No part may be larger than this.
PART_MAX_BYTES = 2_000_000_000
PART_MAX_COUNT = 16  # so a file in parts is at most 32,000,000,000 bytes


def plain_name(v) -> bool:
    """A bare file name: nothing that could name a folder, a drive or another place."""
    return (isinstance(v, str) and 0 < len(v) <= 200 and v not in (".", "..") and v[-1] not in ". "
            and not any(c in "/\\:" or c < " " for c in v))


def part_name(name: str, i: int, n: int) -> str:
    """The release asset holding part `i` of `n` (counted from 1) of the file `name`."""
    return f"{name}.part{i}of{n}"


def _is_sha256(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _is_sha512_b64(v) -> bool:
    """The form `sha512_b64` writes: 64 bytes in base64, 88 characters."""
    return (isinstance(v, str) and len(v) == 88 and v.endswith("==")
            and all(c.isascii() and (c.isalnum() or c in "+/") for c in v[:86]))


def _is_count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def parts_problems(ent) -> list[str]:
    """Every reason an inventory entry with `parts` is not ONE file cut into ordered parts. Empty = it is."""
    if not isinstance(ent, dict) or not plain_name(ent.get("name")):
        return ["an entry in parts has no plain file name"]
    name = ent["name"]
    bad = []
    if not _is_count(ent.get("size")):
        bad.append(f"{name}: size is not a positive whole number")
    if not _is_sha256(ent.get("sha256")):
        bad.append(f"{name}: no sha256 of the whole file")
    if not _is_sha512_b64(ent.get("sha512")):
        bad.append(f"{name}: no sha512 of the whole file")
    parts = ent.get("parts")
    if not isinstance(parts, list) or not 2 <= len(parts) <= PART_MAX_COUNT:
        return [*bad, f"{name}: a file in parts has at least two parts and at most {PART_MAX_COUNT}"]
    total = 0
    for i, p in enumerate(parts, 1):
        want = part_name(name, i, len(parts))
        if not isinstance(p, dict):
            bad.append(f"{name}: part {i} is not an entry")
            continue
        if p.get("name") != want:
            bad.append(f"{name}: part {i} is named {p.get('name')!r}, want {want!r}")
        if not _is_count(p.get("size")) or p["size"] > PART_MAX_BYTES:
            bad.append(f"{name}: part {i} must hold at least 1 and at most {PART_MAX_BYTES} bytes")
        else:
            total += p["size"]
        if not _is_sha256(p.get("sha256")):
            bad.append(f"{name}: part {i} has no sha256")
    if not bad and total != ent["size"]:
        bad.append(f"{name}: the parts do not add up to the file ({total} bytes, want {ent['size']})")
    return bad


def files_hash(repo: Path, commit: str = "HEAD") -> tuple[str, list[str]]:
    """sha256 over the sorted `<mode> <blob> <path>` lines of the gate files at `commit`. Blob ids, not
    working-tree bytes, so a checkout that converts line endings hashes the same."""
    import subprocess

    out = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--full-tree", commit, "--", *GATE_PATHS],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise ValueError(f"git ls-tree failed at {commit}")
    lines = []
    for raw in out.stdout.splitlines():
        meta, path = raw.split("\t", 1)
        mode, kind, blob = meta.split()
        if kind == "blob":
            lines.append(f"{mode} {blob} {path}")
    if not any(line.endswith(" " + GATE_PATHS[0]) for line in lines):
        raise ValueError(f"{GATE_PATHS[0]} is not in the tree at {commit}")
    lines.sort(key=lambda s: s.split(" ", 2)[2])
    return hashlib.sha256("".join(line + "\n" for line in lines).encode("utf-8")).hexdigest(), lines


def load_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cells_for(cells_doc: dict, platform: str, mac_variant: str) -> list[dict]:
    """The cells one job runs, from the runner's cells.json (already free of waived cells)."""
    if cells_doc.get("format") != CELLS_FORMAT:
        raise ValueError(f"cells file format {cells_doc.get('format')!r}")
    if platform not in PLATFORMS or mac_variant not in MAC_VARIANTS:
        raise ValueError(f"platform {platform!r} / variant {mac_variant!r}")
    return [c for c in cells_doc["cells"] if c["platform"] == platform and mac_variant in c["variants"]]


def new_cell(cell: dict) -> dict:
    return {"id": cell["id"], "from": cell["from"], "path": cell["path"], "kind": cell["kind"],
            "result": "not_run", "landed_version": None, "seconds": 0, "detail": "error", "attempts": 0}


def finish_cell(rec: dict, result: str, detail: str, landed: str | None, started: float, **extra) -> dict:
    if result not in RESULTS:
        raise ValueError(f"result {result!r}")
    if detail not in REASONS:
        raise ValueError(f"detail {detail!r} is not a known reason")
    for k, v in extra.items():
        if not (v is None or isinstance(v, (bool, int)) or (isinstance(v, str) and len(v) <= 40)):
            raise ValueError(f"extra field {k} is not a short value")
    rec.update(result=result, detail=detail, landed_version=landed, seconds=int(time.monotonic() - started), **extra)
    return rec


# ── diagnostics: encrypted before upload ──────────────────────────────────────────────────────────


def encrypt_bundle(files: list[Path], out: Path, pubkey_pem: bytes | None = None) -> None:
    """Pack `files` (name -> bytes) into JSON, encrypt it with a fresh AES-256-GCM key, wrap that key with
    RSA-OAEP-SHA256 to the diagnostics public key, and write only the ciphertext. Nothing readable is left in
    `out`. The private half of the key never comes near a runner."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    pub = serialization.load_pem_public_key(pubkey_pem if pubkey_pem is not None else DIAG_PUBKEY.read_bytes())
    payload = {}
    for f in files:
        f = Path(f)
        if f.is_file():
            payload[f.name] = base64.b64encode(f.read_bytes()[-8 * 1024 * 1024:]).decode("ascii")
    plain = json.dumps(payload).encode("utf-8")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plain, None)
    wrapped = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    out.write_text(json.dumps({
        "format": DIAG_FORMAT,
        "wrappedKey": base64.b64encode(wrapped).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
    }), encoding="utf-8")


def decrypt_bundle(enc: Path, private_pem: bytes) -> dict[str, bytes]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    doc = json.loads(Path(enc).read_text(encoding="utf-8"))
    if doc.get("format") != DIAG_FORMAT:
        raise ValueError("not a diagnostics bundle")
    priv = serialization.load_pem_private_key(private_pem, password=None)
    key = priv.decrypt(base64.b64decode(doc["wrappedKey"]),
                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    plain = AESGCM(key).decrypt(base64.b64decode(doc["nonce"]), base64.b64decode(doc["ciphertext"]), None)
    return {k: base64.b64decode(v) for k, v in json.loads(plain).items()}


# ── one receipt per platform, merged from the per-cell jobs ───────────────────────────────────────

BIND_KEYS = ("variant", "gateRepo", "gateCommit", "sourceCommit", "gateFilesHash", "runId", "runAttempt",
             "stagingRepo", "stagingTag")
SHARED_KEYS = ("candidateVersion", "probeVersion", "inventorySha256")


def plan(cells_doc: dict, mode: str, mac_variant: str, only: str) -> dict:
    """The cell ids each platform's matrix runs. `only` keeps the listed ids (bring-up); unknown ids are dropped,
    so nothing a dispatcher types reaches a job but a known cell id. pin mode is one job per platform."""
    if mode == "pin":
        return {p: ["pin"] for p in PLATFORMS}
    wanted = {x.strip() for x in only.split(",") if x.strip()}
    out = {}
    for p in PLATFORMS:
        ids = [c["id"] for c in cells_for(cells_doc, p, mac_variant) if c.get("mode", "gate") == mode]
        out[p] = [i for i in ids if not wanted or i in wanted]
    return out


def merge_receipts(cell_receipts: list[dict], *, planned: list[str], bind: dict, platform: str, mode: str,
                   mac_variant: str, only: str, cells_doc: dict, finished_at: str) -> dict:
    """The platform receipt, the same shape a single job wrote before (cc-update-e2e-receipt/1). Every planned cell
    appears once, in plan order: from its own job's receipt when that receipt is bound to this run, else
    `not_run` / `cell_job_lost`. A cell receipt from another run, commit or staged inventory is ignored (and its
    cell is lost), never trusted."""
    by_cell = {c["id"]: c for c in cells_doc["cells"]}
    receipt = {"format": RECEIPT_FORMAT, "platform": platform, "job": JOB_NAMES[platform], "mode": mode,
               "macVariant": mac_variant, "only": only or None, **{k: bind.get(k) for k in BIND_KEYS},
               "cells": []}
    got: dict[str, dict] = {}
    shared: dict[str, object] = {}
    files: dict[str, dict] = {}
    starts = []
    for r in cell_receipts:
        if r.get("format") != RECEIPT_FORMAT or r.get("platform") != platform or r.get("mode") != mode:
            continue
        if any(r.get(k) != bind.get(k) for k in ("sourceCommit", "gateFilesHash", "runId", "gateCommit")):
            continue
        if r.get("macVariant") != mac_variant:
            continue
        clash = any(k in shared and r.get(k) != shared[k] for k in SHARED_KEYS if r.get(k) is not None)
        if clash:
            continue
        for k in SHARED_KEYS:
            if r.get(k) is not None:
                shared.setdefault(k, r.get(k))
        for f in r.get("candidateFiles") or []:
            if f.get("name") in files and files[f["name"]] != f:
                shared["_files_clash"] = True
            files.setdefault(f.get("name"), f)
        if r.get("startedAt"):
            starts.append(r["startedAt"])
        for c in r.get("cells") or []:
            if c.get("id") in planned and c.get("id") not in got:
                got[c["id"]] = c
    for cid in planned:
        if cid in got:
            receipt["cells"].append(got[cid])
        else:
            c = by_cell.get(cid, {"id": cid, "from": None, "path": None, "kind": "required"})
            rec = new_cell(c)
            rec.update(detail="cell_job_lost")
            receipt["cells"].append(rec)
    receipt.update({k: shared.get(k) for k in SHARED_KEYS})
    receipt["candidateFiles"] = [] if shared.get("_files_clash") else sorted(files.values(), key=lambda f: f["name"])
    receipt["startedAt"] = min(starts) if starts else None
    receipt["finishedAt"] = finished_at
    return receipt
