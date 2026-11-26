"""What "the update landed" is checked by. Pure readers first (unit-tested anywhere), then thin per-OS readers.

Windows: the registered DisplayVersion, the version inside resources/app.asar, the same install folder, the
installer's exit code inside the time box, no setup window seen, the app reopened from that folder (or not, by
path) and still alive 30 s later, the installer's start/done lines. macOS: the bundle's
CFBundleShortVersionString, a strict deep signature check naming the publisher's team, relaunched or not by
path. Both: the new version's first launch wrote its arrival record naming both versions, and the local
health endpoint answers.
"""

from __future__ import annotations

import json
import plistlib
import re
import struct
import subprocess
import time
import urllib.request
from pathlib import Path

TEAM_ID = "85LVDC9MBL"  # the publisher's Apple team, as shown by `codesign -dv` on any shipped build
WIN_PUBLISHER = re.compile(r'CN="?Custodycomms Inc\.')
HEALTH_URL = "http://127.0.0.1:8000/api/health"


# ── pure ──────────────────────────────────────────────────────────────────────────────────────────


def asar_package_version(asar: Path) -> str | None:
    """`version` of package.json inside an Electron asar archive (header: uint32 4, uint32 header size, then a
    pickle: uint32 payload size, uint32 JSON length, JSON). File data starts at 8 + header size."""
    with open(asar, "rb") as f:
        head = f.read(16)
        if len(head) < 16:
            return None
        _, header_size, _, json_len = struct.unpack("<4I", head)
        header = json.loads(f.read(json_len).decode("utf-8"))
        entry = header.get("files", {}).get("package.json")
        if not entry or "offset" not in entry:
            return None
        f.seek(8 + header_size + int(entry["offset"]))
        return json.loads(f.read(int(entry["size"])).decode("utf-8")).get("version")


def bundle_version(app: Path) -> str | None:
    p = Path(app) / "Contents" / "Info.plist"
    if not p.is_file():
        return None
    with open(p, "rb") as f:
        return plistlib.load(f).get("CFBundleShortVersionString")


def read_trace(text: str) -> dict:
    """Classify the installer's own start/done lines: `start <pid> ...`, `start-inner <pid> ...`, `done <pid> ...`.
    A start whose pid has no done = started_not_finished; a second outer start before the first's done =
    lock_collision; an inner start completes the outer start written just before it."""
    starts, done, collision, last_outer = [], set(), False, None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        kind, pid = parts[0], parts[1]
        if kind == "start":
            if last_outer is not None and last_outer not in done:
                collision = True
            starts.append(pid)
            last_outer = pid
        elif kind == "start-inner":
            if last_outer is not None:
                starts.append(("inner", pid, last_outer))
        elif kind == "done":
            done.add(pid)
            for s in starts:
                if isinstance(s, tuple) and s[1] == pid:
                    done.add(s[2])
    outer = [s for s in starts if not isinstance(s, tuple)]
    finished = [s for s in outer if s in done]
    if not outer:
        cls = "none"
    elif collision:
        cls = "lock_collision"
    elif len(finished) == len(outer):
        cls = "done"
    else:
        cls = "started_not_finished"
    return {"class": cls, "starts": len(outer), "done": len(finished)}


def arrival_names(text: str, from_version: str, to_version: str) -> bool:
    """The arrival record must name both versions. Checked as whole version tokens, nothing more."""
    def has(v):
        return re.search(r'(?<![\d.])' + re.escape(v) + r'(?![\d.])', text) is not None
    return has(from_version) and has(to_version)


def health_ok(url: str = HEALTH_URL, timeout_s: float = 180, sleep=time.sleep, now=time.monotonic) -> bool:
    end = now() + timeout_s
    while now() < end:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        sleep(3)
    return False


def install_dir(location: str | None, uninstall: str | None, icon: str | None = None) -> str | None:
    """The install folder from an Uninstall key. InstallLocation when the installer wrote one (bring-up: the 1.9.0
    installer does not), else the folder of the quoted uninstaller in UninstallString, else of DisplayIcon."""
    if location and str(location).strip():
        return str(location).strip().rstrip("\\")
    for raw in (uninstall, icon):
        s = str(raw or "").strip()
        m = re.match(r'^"([^"]+)"', s) or re.match(r"^(.+?\.exe)\b", s, re.I)
        if m:
            path = m.group(1).split(",")[0]
            if "\\" in path:
                return path.rsplit("\\", 1)[0]
    return None


# ── Windows (runner only) ─────────────────────────────────────────────────────────────────────────


def win_installs() -> list[dict]:
    import winreg  # noqa: PLC0415

    out = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            root = winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
        except OSError:
            continue
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                k = winreg.OpenKey(root, name)
                disp = winreg.QueryValueEx(k, "DisplayName")[0]
            except OSError:
                continue
            if not str(disp).startswith("CustodyComms"):
                continue
            def val(n):
                try:
                    return winreg.QueryValueEx(k, n)[0]
                except OSError:
                    return None
            out.append({"hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                        "version": val("DisplayVersion"), "uninstall": val("UninstallString"),
                        "location": install_dir(val("InstallLocation"), val("UninstallString"), val("DisplayIcon"))})
    return out


def win_setup_window_open() -> bool:
    ps = ("Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like 'CustodyComms*Setup*' "
          "-or $_.MainWindowTitle -like 'CustodyComms*Uninstall*' } | Measure-Object | Select-Object -ExpandProperty Count")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    return r.stdout.strip() not in ("", "0")


def win_signature_status(exe: Path) -> tuple[str, str]:
    """(status word, signer subject) from Get-AuthenticodeSignature under PowerShell 7, the same call the runtime
    proof makes on these installers. Windows PowerShell 5.1 refused the signed 2.4 GB 1.9.0 installer (bring-up)."""
    ps = f"$s = Get-AuthenticodeSignature -LiteralPath '{exe}'; \"$($s.Status)|$($s.SignerCertificate.Subject)\""
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    status, _, subject = r.stdout.strip().partition("|")
    return status.strip(), subject.strip()


def win_signature_valid(exe: Path) -> bool:
    status, subject = win_signature_status(exe)
    return status == "Valid" and bool(WIN_PUBLISHER.search(subject))


# The seven names of PowerShell's SignatureStatus. Any other answer is "unreadable" and never a pass.
WIN_SIGNATURE_WORDS = frozenset({"Valid", "UnknownError", "NotSigned", "HashMismatch", "NotTrusted",
                                 "NotSupportedFileFormat", "Incompatible"})
# The INSTALLED app exe (not an installer). No Windows build signs it yet: the build leaves the app exe as it is
# and only the installer goes to the signer, so `NotSigned` is the true state of every install and is accepted.
# Set this to False once a release signs the app exe; from then on only the publisher's `Valid` passes.
WIN_LANDED_UNSIGNED_OK = True


def win_landed_signature(exe: Path | None) -> tuple[bool, str]:
    """(acceptable, word for the receipt) for the INSTALLED app exe. Acceptable: `Valid` from the publisher, or
    `NotSigned` while WIN_LANDED_UNSIGNED_OK. A signature that is there and wrong (HashMismatch, NotTrusted, any
    other status, another publisher), an answer that cannot be read and a missing exe all fail. A file that never
    had a signature and one whose signature was removed both read NotSigned; this check cannot tell them apart.
    The word is one of a closed list of ten, so nothing a file or a tool wrote reaches the receipt."""
    if exe is None or not Path(exe).is_file():
        return False, "exe_missing"
    try:
        status, subject = win_signature_status(Path(exe))
    except (OSError, subprocess.SubprocessError):
        return False, "unreadable"
    if status not in WIN_SIGNATURE_WORDS:
        return False, "unreadable"
    if status == "Valid":
        return (True, "Valid") if WIN_PUBLISHER.search(subject) else (False, "Valid_other_publisher")
    if status == "NotSigned":
        return WIN_LANDED_UNSIGNED_OK, "NotSigned"
    return False, status


# ── processes (both) ──────────────────────────────────────────────────────────────────────────────


def started_after(exe_path: str, t0_epoch: float) -> list:
    import psutil

    want = str(exe_path).lower()
    hits = []
    for p in psutil.process_iter(["exe", "create_time"]):
        try:
            if (p.info["exe"] or "").lower() == want and p.info["create_time"] >= t0_epoch:
                hits.append(p)
        except Exception:
            continue
    return hits


def is_child_process(cmdline) -> bool:
    """An Electron child: its command line can be read and names `--type=<kind>` (renderer, gpu-process, utility,
    crashpad-handler). On Windows these run from the app's own exe; the main (browser) process has no `--type=`. A
    command line that cannot be read or is empty is not called a child, so such a process is counted exactly as it
    was before this check existed."""
    if not isinstance(cmdline, (list, tuple)):
        return False
    return any(isinstance(a, str) and a.startswith("--type=") for a in cmdline)


def child_kind(cmdline) -> str:
    """For the diagnostics: `main`, or the child's --type value."""
    for a in cmdline if isinstance(cmdline, (list, tuple)) else ():
        if isinstance(a, str) and a.startswith("--type="):
            return a[len("--type="):][:40]
    return "main"


def main_started_after(exe_path: str, t0_epoch: float) -> list:
    """`started_after`, without the Electron children: the app's own (main) processes started at or after t0."""
    import psutil

    want = str(exe_path).lower()
    hits = []
    for p in psutil.process_iter(["exe", "create_time", "cmdline"]):
        try:
            info = p.info
            if (info["exe"] or "").lower() == want and info["create_time"] >= t0_epoch and not is_child_process(info.get("cmdline")):
                hits.append(p)
        except Exception:
            continue
    return hits


def describe_started_after(exe_path: str, t0_epoch: float) -> list[str]:
    """For the encrypted diagnostics: `pid <n> <main|kind> +<s>s` for every process of exe_path started at or after t0."""
    import psutil

    want = str(exe_path).lower()
    out = []
    try:
        for p in psutil.process_iter(["pid", "exe", "create_time", "cmdline"]):
            try:
                info = p.info
                if (info["exe"] or "").lower() == want and info["create_time"] >= t0_epoch:
                    out.append(f"pid {info['pid']} {child_kind(info.get('cmdline'))} +{int(info['create_time'] - t0_epoch)}s")
            except Exception:
                continue
    except Exception as e:  # noqa: BLE001 - diagnostics only: never the reason a cell fails
        out.append(f"listing stopped: {type(e).__name__}")
    return out


def main_running_since(exe_path: str, t0_epoch: float) -> list:
    """The app's main processes started at or after t0 that are running now. A fresh scan, so a main process the app
    started in place of the first one (a relaunch) counts. A process that is gone (NoSuchProcess) or a zombie is not
    running; one whose state cannot be read (AccessDenied, anything else) is counted as running: an answer that is
    not known is never read as an exit."""
    import psutil

    gone = getattr(psutil, "NoSuchProcess", ProcessLookupError)
    alive = []
    for p in main_started_after(exe_path, t0_epoch):
        try:
            if not p.is_running():
                continue
        except gone:
            continue
        except Exception:  # noqa: BLE001 - not known: counted, see above
            alive.append(p)
            continue
        try:
            if p.status() == getattr(psutil, "STATUS_ZOMBIE", "zombie"):
                continue
        except Exception:  # noqa: BLE001 - is_running above already answered
            pass
        alive.append(p)
    return alive


def wait_started(exe_path: str, t0_epoch: float, timeout_s: float, sleep=time.sleep, now=time.monotonic,
                 seen: list | None = None):
    """The first main process of the app started at or after t0, or None after `timeout_s`. A child (renderer, GPU,
    utility) is never returned: run 45743211127 took a splash window's renderer for the app and failed the cell
    `reopened_exited` when that window closed. With `seen`, every process of the exe met during the wait is added
    to it once (describe_started_after's rows), for the diagnostics."""
    end = now() + timeout_s
    while now() < end:
        hits = main_started_after(exe_path, t0_epoch)
        if seen is not None:
            seen.extend(r for r in describe_started_after(exe_path, t0_epoch) if r not in seen)
        if hits:
            return hits[0]
        sleep(2)
    return None


# ── macOS (runner only) ───────────────────────────────────────────────────────────────────────────


def mac_signature_valid(app: Path) -> bool:
    r = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], capture_output=True, text=True)
    if r.returncode != 0:
        return False
    d = subprocess.run(["codesign", "-dv", str(app)], capture_output=True, text=True)
    return f"TeamIdentifier={TEAM_ID}" in (d.stderr + d.stdout)
