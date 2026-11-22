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

# The only words a cell may carry in its `detail`. A closed list keeps free text (and with it anything an
# application wrote) out of the plain receipt.
REASONS = frozenset({
    "ok", "precondition_failed", "pin_missing", "download_mismatch", "signature_invalid", "debug_port_unreachable",
    "offer_timeout", "download_timeout", "ready_button_not_clickable", "installer_timeout", "installer_exit_nonzero",
    "setup_window_seen", "wrong_version", "not_reopened", "reopened_unexpectedly", "reopened_exited",
    "arrival_record_missing", "health_failed", "trace_mismatch", "control_no_defect", "control_no_window",
    "still_running_expected_exit", "exited_expected_running", "reset_failed", "unsupported_on_platform", "error",
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
