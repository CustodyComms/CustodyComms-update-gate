#!/usr/bin/env python3
"""Runs every update cell for one platform on a disposable machine and writes the receipt.

    python run_cells.py --platform windows|macos --mac-variant A|B|C --mode gate|live|pin
                        --bind gate-run.json --work DIR --receipt OUT.json --diag OUT.enc

A cell starts from a published version, built from that version's published installers (checked by size
and hash first), lets that version's own updater find, download and install the candidate from the staging
release, and checks that the candidate landed. Every cell runs even after a failure; a failed or inconclusive
cell gets exactly one more attempt. The log shows the cell id, the result and the seconds, nothing else; every
detail goes into the diagnostics bundle, which is encrypted before upload.

Exit: 0 every cell passed; 1 any cell did not pass (or mode=pin, which only measures); 2 usage or binding error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import common  # noqa: E402
import drive  # noqa: E402
import landed  # noqa: E402

DEBUG_PORT = 9333
# A child process never writes to the job log: installers get no console, the app writes into the diagnostics.
QUIET = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
LOG: list[str] = []          # goes into the encrypted bundle only
DIAG_FILES: list[Path] = []  # ditto


def note(msg: str) -> None:
    LOG.append(f"{time.strftime('%H:%M:%S')} {msg}")


def say(msg: str) -> None:
    """The only thing that reaches the public log."""
    print(msg, flush=True)


# ── downloads ─────────────────────────────────────────────────────────────────────────────────────


def fetch(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "update-gate"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    tmp.rename(dest)
    return dest


def fetch_pinned(url: str, size: int, sha256: str | None, cache: Path) -> Path | None:
    """Download once and refuse any other bytes. None = the pin is incomplete (the cell is not_run)."""
    if not sha256:
        return None
    p = fetch(url, cache / url.rsplit("/", 1)[1])
    if p.stat().st_size != size or common.sha256_hex(p) != sha256:
        p.unlink()
        raise RuntimeError("download_mismatch")
    return p


class Staging:
    """The candidate (and probe) files on the staging release, checked against its inventory."""

    def __init__(self, bind: dict, cache: Path):
        self.repo = bind["stagingRepo"]
        base = f"https://github.com/{self.repo}/releases/download/{bind['stagingTag']}"
        self.base = base
        inv = fetch(f"{base}/gate-inventory.json", cache / "gate-inventory.json")
        self.inventory_sha256 = common.sha256_hex(inv)
        self.inv = common.load_json(inv)
        if self.inv.get("format") != common.INVENTORY_FORMAT:
            raise RuntimeError("inventory format")
        if self.inv["sourceCommit"] != bind["sourceCommit"]:
            raise RuntimeError("the staged inventory is for another commit")
        self.cache = cache
        self.files: dict[str, dict] = {}

    def get(self, name: str, base: str | None = None) -> Path:
        ent = next((a for a in self.inv["assets"] + self.inv.get("extras", []) if a["name"] == name), None)
        if ent is None:
            raise RuntimeError("download_mismatch")
        p = fetch(f"{base or self.base}/{name}", self.cache / name)
        if p.stat().st_size != ent["size"] or common.sha512_b64(p) != ent["sha512"]:
            p.unlink()
            raise RuntimeError("download_mismatch")
        self.files[name] = {"name": name, "size": ent["size"], "sha512": ent["sha512"]}
        return p

    def candidate_asset(self, suffix: str, version: str | None = None) -> str:
        """The one draft asset that is `version`'s file of this kind (the draft can also carry an older version's
        update file, e.g. the previous release's installer)."""
        version = version or self.inv["candidateVersion"]
        names = [a["name"] for a in self.inv["assets"] if a["name"].endswith(suffix)
                 and (f"-{version}-" in a["name"] or a["name"].endswith(f"-{version}{suffix}"))]
        if len(names) != 1:
            raise RuntimeError("download_mismatch")
        return names[0]


# ── the app's update feed setting ─────────────────────────────────────────────────────────────────


def feed_yml_text(original: str, mode: str, staging_repo: str = "", probe_url: str = "") -> str:
    """Rewrite app-update.yml. "staging": only the `owner:`/`repo:` values change (owner is the same). "probe": the
    generic provider at the probe release. "nowhere": a generic feed that refuses at once, so a from-state's first
    launch cannot fetch anything. The publisher name (with its list lines) and the cache folder are always kept."""
    lines = original.splitlines()
    if mode == "staging":
        owner, name = staging_repo.split("/", 1)
        out, saw = [], False
        for ln in lines:
            key = ln.split(":", 1)[0]
            if key == "repo":
                out.append(f"repo: {name}")
                saw = True
            elif key == "owner":
                out.append(f"owner: {owner}")
            else:
                out.append(ln)
        if not saw:
            raise RuntimeError("precondition_failed")
        return "\n".join(out) + "\n"
    if mode not in ("probe", "nowhere"):
        raise ValueError(mode)
    kept, in_block = [], False
    for ln in lines:
        key = ln.split(":", 1)[0]
        if ln[:1] not in (" ", "-", "\t", ""):
            in_block = key == "publisherName"
            if key in ("publisherName", "updaterCacheDirName"):
                kept.append(ln)
        elif in_block and ln.strip():
            kept.append(ln)
    url = probe_url if mode == "probe" else "http://127.0.0.1:9/"
    if not url:
        raise RuntimeError("precondition_failed")
    return "\n".join(["provider: generic", f"url: {url}", *kept]) + "\n"


def launched_exited(plat, timeout: float, step: float, now=time.monotonic, sleep=time.sleep) -> bool:
    """The app the gate launched has exited. Judged by that process itself (Popen.poll, which also reaps it), not
    by scanning for the executable's path: run 45137602974 counted macOS apps as still running after they had quit
    and Squirrel had installed the update (screen picture: no app open). Without a launched process, the scan."""
    proc = getattr(plat, "proc", None)
    end = now() + timeout
    while now() < end:
        if (proc.poll() is not None) if proc is not None else (not plat.running()):
            return True
        sleep(step)
    return False


# ── platforms ─────────────────────────────────────────────────────────────────────────────────────


class Win:
    name = "windows"
    data = Path(os.environ.get("APPDATA", "")) / "CustodyComms"
    updater_cache = Path(os.environ.get("LOCALAPPDATA", "")) / "custodycomms-updater"

    def __init__(self, pins, cache):
        self.pins, self.cache = pins, cache

    def ps(self, script: str, timeout=900, keep=400) -> subprocess.CompletedProcess:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=timeout)
        note(f"ps rc={r.returncode} {r.stdout[-keep:]} {r.stderr[-400:]}")
        return r

    def install(self) -> dict | None:
        inst = landed.win_installs()
        return inst[0] if len(inst) == 1 else None

    def app_exe(self) -> Path | None:
        i = self.install()
        return Path(i["location"]) / "CustodyComms.exe" if i and i["location"] else None

    def kill_all(self):
        # The app, any of its installers (named after their file) and NSIS's temporary uninstaller copies.
        self.ps("Get-Process 'CustodyComms*','Un_A*','Au_*' -ErrorAction SilentlyContinue | Stop-Process -Force")
        time.sleep(3)

    def reset(self):
        self.kill_all()
        for i in landed.win_installs():
            if i["uninstall"]:
                r = subprocess.run(f"{i['uninstall']} /S", shell=True, capture_output=True, text=True, timeout=600)
                note(f"uninstall rc={r.returncode}")
        time.sleep(5)
        for p in (self.data, self.updater_cache, Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "CustodyComms"):
            shutil.rmtree(p, ignore_errors=True)
        self.kill_all()
        if landed.win_installs() or self.running():
            raise RuntimeError("reset_failed")

    def running(self) -> bool:
        r = self.ps("Get-Process CustodyComms -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count")
        return r.stdout.strip() not in ("", "0")

    def run_installer(self, exe: Path, args: list[str], timeout=1200) -> int:
        p = subprocess.Popen([str(exe), *args], **QUIET)
        try:
            return p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            raise RuntimeError("installer_timeout")

    PROC_DUMP_AT_S = (20, 60)

    def proc_dump(self, label: str) -> None:
        """Encrypted diagnostics only: every process with its parent and start time, `tasklist /v`, and whether a
        taskkill.exe or conhost.exe is alive and under which parent. Tells a taskkill that never exits apart from a
        main thread blocked in process creation (the 2.0.4 quit freeze)."""
        cim = ("Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CreationDate, "
               "ExecutablePath, CommandLine | Format-Table -AutoSize | Out-String -Width 600")
        watch = ("Get-CimInstance Win32_Process -Filter \"Name='taskkill.exe' OR Name='conhost.exe'\" | ForEach-Object { "
                 "$p = Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.ParentProcessId)\"; "
                 "'{0} pid={1} parent={2} ({3}) started={4} cmd={5}' -f $_.Name, $_.ProcessId, $_.ParentProcessId, "
                 "$(if ($p) { $p.Name } else { 'gone' }), $_.CreationDate, $_.CommandLine }")
        note(f"proc-dump {label}")
        self.ps(watch, keep=6000)
        self.ps(cim, keep=60000)
        r = subprocess.run(["tasklist", "/v"], capture_output=True, text=True, timeout=120)
        note(f"tasklist /v rc={r.returncode} {r.stdout[-30000:]}")

    def dumps_after_close(self, label: str, at=None, sleep=time.sleep) -> threading.Thread:
        """Takes proc_dump at 20 s and 60 s after a close, on its own thread so the quit's timing is untouched."""
        def run():
            last = 0
            for s in (at or self.PROC_DUMP_AT_S):
                sleep(s - last)
                last = s
                try:
                    self.proc_dump(f"{label} +{s}s")
                except Exception as e:  # noqa: BLE001 - diagnostics never break a cell
                    note(f"proc-dump failed: {type(e).__name__}")

        th = threading.Thread(target=run, daemon=True)
        th.start()
        return th

    def main_log(self) -> Path:
        return self.data / "logs" / "main.log"

    def log_since_launch(self) -> str:
        """The app's own main.log from the last launch on (it appends across launches)."""
        try:
            with open(self.main_log(), "rb") as f:
                f.seek(getattr(self, "log_offset", 0))
                return f.read().decode("utf-8", errors="replace")
        except OSError:
            return ""

    def close_and_time(self, limit: float) -> tuple[bool, int]:
        """One person-like close (SC_CLOSE to the visible window, after it has been up 20 s) and whether the launched
        app exits within `limit` seconds of it. No second close, no kill."""
        end = time.monotonic() + 300
        while self.close_window_ps("list") != 0 and time.monotonic() < end:
            time.sleep(5)
        time.sleep(20)
        t = time.monotonic()
        self.close_window_ps("close")
        self.dumps_after_close("after the close")
        ok = launched_exited(self, limit, 1)
        return ok, int(time.monotonic() - t)

    def census(self, procs=None) -> list[str]:
        """App processes left behind: CustodyComms.exe, ollama.exe or python.exe under the install or data folders,
        and any taskkill.exe. The list goes into the diagnostics; the receipt carries its length."""
        import psutil

        roots = [str(self.data).lower(), str(Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "CustodyComms").lower()]
        i = self.install()
        if i and i.get("location"):
            roots.append(str(i["location"]).lower())
        names = {"custodycomms.exe", "ollama.exe", "python.exe"}
        left = []
        for p in (procs if procs is not None else psutil.process_iter(["name", "exe", "pid"])):
            info = p.info if hasattr(p, "info") else p
            name, exe = (info.get("name") or "").lower(), (info.get("exe") or "").lower()
            if name == "taskkill.exe" or (name in names and any(r and exe.startswith(r) for r in roots)):
                left.append(f"{name} {info.get('pid')}")
        note(f"census: {left}")
        return left

    def launch(self, debug=True, quiet=False) -> subprocess.Popen:
        exe = self.app_exe()
        if not exe or not exe.exists():
            raise RuntimeError("precondition_failed")
        try:
            self.log_offset = self.main_log().stat().st_size
        except OSError:
            self.log_offset = 0
        if quiet:
            self.proc = subprocess.Popen([str(exe)], **QUIET)
            return self.proc
        out = open(self.cache / f"app-{int(time.time())}.log", "wb")
        DIAG_FILES.append(Path(out.name))
        self.proc = subprocess.Popen([str(exe)] + ([f"--remote-debugging-port={DEBUG_PORT}"] if debug else []), stdout=out, stderr=out)
        return self.proc

    def close_window_ps(self, mode: str) -> int:
        """Runs CLOSE_WINDOW_PS (mode list|close); its output (window handles, names, results) goes into the
        encrypted diagnostics only. Exit 0 = a visible app window was found (and, for close, SC_CLOSE posted)."""
        script = self.cache / "close-window.ps1"
        script.write_text(CLOSE_WINDOW_PS, encoding="utf-8")
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Mode", mode],
                           capture_output=True, text=True, timeout=120)
        note(f"close-window {mode} rc={r.returncode} {r.stdout[-3000:]} {r.stderr[-500:]}")
        return r.returncode

    def quit_like_a_person(self, timeout=300, settle=20) -> bool:
        """Close the app's main window the way a person does (the X button or Alt+F4 = WM_SYSCOMMAND SC_CLOSE),
        once its window is up and has been for `settle` seconds; a second close after 90 s if it is still open,
        as a person clicks again. Never kills: on Windows closing the window is the quit that starts the
        install-on-quit. Bring-up run 45137602974: Process.CloseMainWindow 28 s after launch left 2.0.4 open."""
        end = time.monotonic() + timeout
        while self.close_window_ps("list") != 0 and time.monotonic() < end:
            time.sleep(5)
        time.sleep(settle)
        first = True
        for wait in (90, max(0.0, end - time.monotonic())):
            self.close_window_ps("close")
            if first and settle:
                self.dumps_after_close("after the close")
                first = False
            if launched_exited(self, wait, 3):
                return True
        return False

    def feed_file(self) -> Path:
        i = self.install()
        return Path(i["location"]) / "resources" / "app-update.yml"

    def snapshot(self, why: str) -> None:
        """Into the encrypted diagnostics only: what is running, which windows are open, the app's own log files."""
        note(f"snapshot: {why}")
        self.close_window_ps("list")
        for f in sorted(self.data.glob("logs/*.log"))[:6]:
            copy = self.cache / f"applog-{int(time.time())}-{f.name}"
            try:
                shutil.copy(f, copy)
                DIAG_FILES.append(copy)
            except OSError:
                continue
        self.ps("Get-Process | Where-Object { $_.ProcessName -match 'CustodyComms|Setup|Un_A|Au_' } | "
                "Select-Object Id, ProcessName, MainWindowTitle, StartTime | Format-Table -AutoSize | Out-String -Width 300",
                keep=8000)

    def ready_on_disk(self, want: str) -> bool:
        """The updater finished downloading `want`: its pending folder names the installer in update-info.json and
        that installer is there (electron-updater writes update-info.json only after the download checks out)."""
        pend = self.updater_cache / "pending"
        try:
            info = json.loads((pend / "update-info.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        name = str(info.get("fileName") or "")
        return bool(name) and want in name and (pend / name).is_file()

    def version(self) -> str | None:
        i = self.install()
        return i["version"] if i else None

    def files_version(self) -> str | None:
        exe = self.app_exe()
        return landed.asar_package_version(exe.parent / "resources" / "app.asar") if exe else None

    def build_from(self, ver: str, per_machine=False) -> None:
        """Windows from-state: the 1.9.0 full installer, launched once; then the from-version's update installer
        exactly as the quit-time install runs it (--updated /S); launched once."""
        entry = self.pins["windows"][ver]
        for step in entry["recipe"]:
            kind, ref = step.split(":", 1)
            if kind == "full":
                f = self.pins["fullInstallers"][ref]
                exe = fetch_pinned(f["url"], f["size"], f["sha256"], self.cache)
                if exe is None:
                    raise RuntimeError("pin_missing")
                if not landed.win_signature_valid(exe):
                    note(f"signature of {ref}: {landed.win_signature_status(exe)[0]}")
                    raise RuntimeError("signature_invalid")
                if self.run_installer(exe, ["/S", "/allusers" if per_machine else "/currentuser"]) != 0:
                    raise RuntimeError("installer_exit_nonzero")
            else:
                u = self.pins["windows"][ref]["update"]
                exe = fetch_pinned(u["url"], u["size"], u["sha256"], self.cache)
                if exe is None or common.sha512_b64(exe) != u["sha512"]:
                    raise RuntimeError("download_mismatch")
                if self.run_installer(exe, ["--updated", "/S"]) != 0:
                    raise RuntimeError("installer_exit_nonzero")
            self.kill_all()
            self.first_launch()
        if self.version() != ver or self.files_version() != ver:
            raise RuntimeError("precondition_failed")

    def first_launch(self):
        ff = self.feed_file()
        orig = ff.read_text(encoding="utf-8")
        ff.write_text(feed_yml_text(orig, "nowhere"), encoding="utf-8")
        p = self.launch(debug=False)
        ok = landed.health_ok(timeout_s=1200)
        time.sleep(15)
        self.quit_like_a_person(timeout=120, settle=0)
        self.kill_all()
        ff.write_text(orig, encoding="utf-8")
        if not ok:
            raise RuntimeError("health_failed")
        del p


class Mac:
    name = "macos"
    app = Path("/Applications/CustodyComms.app")
    exe = app / "Contents" / "MacOS" / "CustodyComms"
    home = Path.home()
    data = home / "Library" / "Application Support" / "CustodyComms"
    caches = (home / "Library" / "Caches" / "custodycomms-updater", home / "Library" / "Caches" / "com.custodycomms.app.ShipIt")

    def __init__(self, pins, cache):
        self.pins, self.cache = pins, cache
        self.snap = cache / "snap"

    def sh(self, *args, timeout=900, check=False, keep=300) -> subprocess.CompletedProcess:
        r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
        note(f"{args[0]} rc={r.returncode} {r.stdout[-keep:]} {r.stderr[-300:]}")
        if check and r.returncode != 0:
            raise RuntimeError("error")
        return r

    def running(self) -> bool:
        return bool(landed.started_after(str(self.exe), 0))

    def kill_all(self):
        self.sh("pkill", "-x", "CustodyComms")
        self.sh("pkill", "-x", "ShipIt")
        time.sleep(3)

    def reset(self):
        self.kill_all()
        self.sh("launchctl", "remove", "com.custodycomms.app.ShipIt")
        for p in (self.app, self.data, *self.caches):
            shutil.rmtree(p, ignore_errors=True)
        if self.app.exists() or self.running():
            raise RuntimeError("reset_failed")

    def launch(self, debug=True) -> subprocess.Popen:
        out = open(self.cache / f"app-{int(time.time())}.log", "wb")
        DIAG_FILES.append(Path(out.name))
        self.proc = subprocess.Popen([str(self.exe)] + ([f"--remote-debugging-port={DEBUG_PORT}"] if debug else []), stdout=out, stderr=out)
        return self.proc

    def quit_like_a_person(self, timeout=90) -> bool:
        self.sh("osascript", "-e", 'tell application "CustodyComms" to quit')
        return launched_exited(self, timeout, 2)

    def close_window(self, browser) -> str:
        r = self.sh("osascript", "-e", 'tell application "System Events" to tell process "CustodyComms" to click (first button of window 1 whose subrole is "AXCloseButton")')
        if r.returncode == 0:
            return "button"
        return "renderer" if drive.close_first_window(browser) else "none"

    def feed_file(self) -> Path:
        return self.app / "Contents" / "Resources" / "app-update.yml"

    def version(self):
        return landed.bundle_version(self.app)

    files_version = version

    def staged(self, want: str | None = None) -> bool:
        """Squirrel.Mac has the update: its unpacked copy of `want` (or, without a version, any ShipIt request)."""
        d = self.caches[1]
        if not d.exists():
            return False
        if want:
            return any(landed.bundle_version(p.parents[1]) == want for p in d.glob("update.*/*.app/Contents/Info.plist"))
        return any(p.name.endswith(".plist") for p in d.glob("*"))

    STAGE_SETTLE_S = 30

    def snapshot(self, why: str) -> None:
        """Into the encrypted diagnostics only: the app's processes, Squirrel's folder and a screen picture."""
        note(f"snapshot: {why}")
        self.sh("ps", "-axo", "pid,ppid,etime,stat,command", keep=20000)
        self.sh("ls", "-laR", str(self.caches[1]), keep=6000)
        shot = self.cache / f"screen-{int(time.time())}.png"
        self.sh("screencapture", "-x", str(shot))
        if shot.is_file():
            DIAG_FILES.append(shot)

    def in_verify_window(self, want: str) -> bool:
        """The update is downloaded (electron-updater's pending zip, or Squirrel's own copy) and Squirrel has not
        finished unpacking and verifying it: the gap mac-quit-during-verify quits in (about 3 s, bring-up run
        45074289608)."""
        if self.staged(want):
            return False
        pending = list((self.caches[0] / "pending").glob("*.zip")) if (self.caches[0] / "pending").is_dir() else []
        ship = list(self.caches[1].glob("update.*/*.zip")) if self.caches[1].is_dir() else []
        return bool(pending or ship)

    def ready_on_disk(self, want: str, now=time.monotonic) -> bool:
        """Squirrel's unpacked copy has been there for STAGE_SETTLE_S. Bring-up run 45087190217: the copy appears
        when the download lands, about 3 s before Squirrel reports it staged; quitting in that gap left the app
        running for 10 minutes."""
        if not self.staged(want):
            self._seen = None
            return False
        seen = getattr(self, "_seen", None)
        if seen is None or seen[0] != want:
            self._seen = (want, now())
            return False
        return now() - self._seen[1] >= self.STAGE_SETTLE_S

    def build_from(self, ver: str, per_machine=False) -> None:
        if (self.snap / ver).exists():
            self.reset()
            self.sh("cp", "-Rc", str(self.snap / ver / "CustodyComms.app"), str(self.app), check=True)
            self.data.parent.mkdir(parents=True, exist_ok=True)
            self.sh("cp", "-Rc", str(self.snap / ver / "data"), str(self.data), check=True)
        else:
            for step in self.pins["macos"][ver]["recipe"]:
                kind, ref = step.split(":", 1)
                if kind == "full":
                    f = self.pins["fullInstallers"][ref]
                    dmg = fetch_pinned(f["url"], f["size"], f["sha256"], self.cache)
                    if dmg is None:
                        raise RuntimeError("pin_missing")
                    mnt = self.cache / "mnt"
                    mnt.mkdir(exist_ok=True)
                    self.sh("hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mnt), str(dmg), check=True)
                    try:
                        self.sh("ditto", str(mnt / "CustodyComms.app"), str(self.app), check=True)
                    finally:
                        self.sh("hdiutil", "detach", str(mnt))
                else:
                    u = self.pins["macos"][ref]["update"]
                    z = fetch_pinned(u["url"], u["size"], u["sha256"], self.cache)
                    if z is None or common.sha512_b64(z) != u["sha512"]:
                        raise RuntimeError("download_mismatch")
                    tmp = self.cache / f"unz-{ref}"
                    shutil.rmtree(tmp, ignore_errors=True)
                    self.sh("ditto", "-x", "-k", str(z), str(tmp), check=True)
                    shutil.rmtree(self.app, ignore_errors=True)
                    self.sh("ditto", str(tmp / "CustodyComms.app"), str(self.app), check=True)
                if not landed.mac_signature_valid(self.app):
                    raise RuntimeError("signature_invalid")
                self.first_launch()
            snap = self.snap / ver
            snap.mkdir(parents=True, exist_ok=True)
            self.sh("cp", "-Rc", str(self.app), str(snap / "CustodyComms.app"), check=True)
            self.sh("cp", "-Rc", str(self.data), str(snap / "data"), check=True)
        if self.version() != ver:
            raise RuntimeError("precondition_failed")

    def first_launch(self):
        ff = self.feed_file()
        orig = ff.read_text(encoding="utf-8")
        ff.write_text(feed_yml_text(orig, "nowhere"), encoding="utf-8")
        self.launch(debug=False)
        ok = landed.health_ok(timeout_s=1200)
        time.sleep(15)
        self.quit_like_a_person()
        self.kill_all()
        ff.write_text(orig, encoding="utf-8")
        if not ok:
            raise RuntimeError("health_failed")


# ── cells ─────────────────────────────────────────────────────────────────────────────────────────


class Watch(threading.Thread):
    """Polls for a setup window for the whole of a Windows cell."""

    def __init__(self):
        super().__init__(daemon=True)
        self.seen, self.stop = False, threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                if landed.win_setup_window_open():
                    self.seen = True
            except Exception as e:  # noqa: BLE001 - a thread's traceback would reach the job log
                note(f"watch: {type(e).__name__}")
            time.sleep(2)


def arrival_ok(plat, frm: str, to: str) -> bool:
    p = plat.data / "update-arrival.json"
    end = time.monotonic() + 180
    while time.monotonic() < end:
        if p.is_file() and landed.arrival_names(p.read_text(encoding="utf-8", errors="replace"), frm, to):
            return True
        time.sleep(3)
    return False


def trace_class(plat) -> str:
    p = plat.data / "update-installer-trace.log"
    return landed.read_trace(p.read_text(encoding="ascii", errors="replace"))["class"] if p.is_file() else "none"


def run_one(plat, cell: dict, ctx: dict) -> tuple[str, str, str | None, dict]:
    """Returns (result, reason, landed_version, extra)."""
    frm, path = cell["from"], cell["path"]
    extra: dict = {}
    cand, probe = ctx["candidate"], ctx.get("probe")
    want = probe if frm == "candidate" else cand
    plat.reset()
    if path == "fresh-wizard":
        return fresh_wizard(plat, ctx)
    if plat.name == "windows" and frm == "candidate" and path == "quit":
        return win_quit_from_self(plat, ctx, want, extra)
    if frm == "candidate":
        # The candidate's own next hop starts from the candidate, installed over the newest shipped version the
        # way an update installs it.
        plat.build_from(ctx["newest_shipped"][plat.name])
        land_candidate_directly(plat, ctx)
    else:
        plat.build_from(frm, per_machine=(path == "click-permachine"))
    if path == "control":
        return control_cell(plat, ctx)
    if path in ("lock", "old-wizard-open"):
        return lock_cells(plat, ctx, path)
    ff = plat.feed_file()
    orig = ff.read_text(encoding="utf-8")
    if path == "noclose":
        ff.write_text(feed_yml_text(orig, "nowhere"), encoding="utf-8")  # nothing to stage: the app must stay open
    elif ctx["mode"] == "gate":
        ff.write_text(feed_yml_text(orig, "probe" if frm == "candidate" else "staging", ctx["staging_repo"], ctx.get("probe_url", "")), encoding="utf-8")
        extra["feed"] = "generic-probe" if frm == "candidate" else "staging"
    t0 = time.time()
    watch = Watch() if plat.name == "windows" else None
    if watch:
        watch.start()
    try:
        if plat.name == "windows" and path == "quit":
            # As the installed app runs for a person: no debugging port, no redirected output (run 45160618293: the app began
            # quitting and stalled; this takes the gate's own launch switches out of that question). Readiness is
            # read from disk; the app's own log file goes into the diagnostics.
            plat.launch(debug=False, quiet=True)
            extra["debug_port"] = "not_used"
            end = time.monotonic() + 900
            while not plat.ready_on_disk(want) and time.monotonic() < end:
                time.sleep(5)
            extra["ready_on_disk"] = plat.ready_on_disk(want)
            if not extra["ready_on_disk"]:
                return "inconclusive", "update_never_ready", plat.version(), extra
            t0 = time.time()
            if not plat.quit_like_a_person(timeout=300):
                plat.snapshot("asked to quit, still running")
                return "fail", "still_running_expected_exit", plat.version(), extra
            return after_quit(plat, ctx, t0, want, frm, watch, extra)
        plat.launch()
        browser = drive.Browser(DEBUG_PORT)
        if not drive.wait_for_debug_port(browser, 600):
            return "inconclusive", "debug_port_unreachable", plat.version(), extra
        extra["debug_port"] = "ok"
        if path == "quit-during-verify":
            return quit_during_verify(plat, want, extra)
        if path == "noclose":
            plat.close_window(browser)
            time.sleep(180)
            still = plat.proc.poll() is None if getattr(plat, "proc", None) is not None else plat.running()
            return ("pass", "ok", plat.version(), extra) if still else ("fail", "exited_expected_running", plat.version(), extra)
        r = drive.drive_offer(browser, want="install" if path.startswith("click") else "ready", timeout_s=900,
                              ready_probe=lambda: plat.ready_on_disk(want))
        t0 = time.time()  # processes started from here on are the reopened app, never the one under test
        extra["header"] = r["header"]
        extra["ready_on_disk"] = r.get("ready_on_disk", False)
        if r.get("open_ready", "not_tried") != "not_tried":
            extra["open_ready"] = r["open_ready"]
        if r["state"] == "timeout":
            return "inconclusive", timeout_reason(r, path), plat.version(), extra
        if path.startswith("click"):
            return after_click(plat, ctx, t0, want, frm, watch, extra)
        if plat.name == "macos":
            end = time.monotonic() + 300
            while not plat.ready_on_disk(want) and time.monotonic() < end:
                time.sleep(3)
        if path == "close":
            extra["close"] = plat.close_window(browser)
            if not launched_exited(plat, 600, 3):
                plat.snapshot("window closed, still running")
                return "fail", "still_running_expected_exit", plat.version(), extra
        elif not plat.quit_like_a_person(timeout=300):
            plat.snapshot("asked to quit, still running")
            return "fail", "still_running_expected_exit", plat.version(), extra
        return after_quit(plat, ctx, t0, want, frm, watch, extra)
    finally:
        if watch:
            watch.stop.set()
        plat.kill_all()


QUIT_DONE_LINES = ("[Quit] child processes stopped: quitting", "[Quit] child processes not confirmed stopped: quitting")
QUIT_BACKSTOP_LINE = "[Quit] the quit did not finish in 10 s"


def win_quit_from_self(plat, ctx, want, extra, now=time.monotonic, sleep=time.sleep, wall=time.time) -> tuple:
    """win-quit-from-self: the candidate, closed like a person, must quit by
    itself and its quit-time install must land the probe. Never a kill.
    1. land the candidate as an update does; first launch with the feed pointed nowhere; one close; exit in 60 s.
    2. feed at the probe; launch as a person runs it; wait until the probe is ready on disk.
    3. one close; exit in 60 s.
    4. main.log of that launch has the normal quit line and not the backstop line; 15 s after exit no app process
       is left; the probe lands (registered and in the files), signed."""
    if not want or not ctx.get("probe_url"):
        raise RuntimeError("precondition_failed")
    plat.build_from(ctx["newest_shipped"]["windows"])
    st = ctx["staging"]
    if plat.run_installer(st.get(st.candidate_asset("-update.exe")), ["--updated", "/S"]) != 0:
        raise RuntimeError("installer_exit_nonzero")
    plat.kill_all()
    if plat.version() != ctx["candidate"]:
        raise RuntimeError("precondition_failed")
    ff = plat.feed_file()
    orig = ff.read_text(encoding="utf-8")
    ff.write_text(feed_yml_text(orig, "nowhere"), encoding="utf-8")
    plat.launch(debug=False, quiet=True)
    if not landed.health_ok(timeout_s=1200):
        raise RuntimeError("health_failed")
    exited, secs = plat.close_and_time(60)
    extra["first_close_s"] = secs
    if not exited:
        plat.snapshot("first launch of the candidate closed, still running")
        return "fail", "still_running_expected_exit", plat.version(), extra
    ff.write_text(feed_yml_text(orig, "probe", ctx["staging_repo"], ctx["probe_url"]), encoding="utf-8")
    extra["feed"] = "generic-probe"
    plat.launch(debug=False, quiet=True)
    end = now() + 900
    while not plat.ready_on_disk(want) and now() < end:
        sleep(5)
    extra["ready_on_disk"] = plat.ready_on_disk(want)
    if not extra["ready_on_disk"]:
        return "inconclusive", "update_never_ready", plat.version(), extra
    exited, secs = plat.close_and_time(60)
    extra["close_s"] = secs
    if not exited:
        plat.snapshot("candidate closed with the probe ready, still running")
        return "fail", "still_running_expected_exit", plat.version(), extra
    exit_at = wall()
    log = plat.log_since_launch()
    if QUIT_BACKSTOP_LINE in log:
        plat.snapshot("the quit was ended by the backstop")
        return "fail", "backstop_exit", plat.version(), extra
    if not any(line in log for line in QUIT_DONE_LINES):
        plat.snapshot("no normal quit line in main.log")
        return "fail", "quit_not_logged", plat.version(), extra
    sleep(max(0.0, 15 - (wall() - exit_at)))
    left = plat.census()
    extra["orphans"] = len(left)
    if left:
        plat.snapshot("processes left 15 s after the quit")
        return "fail", "orphans", plat.version(), extra
    end = now() + 600
    while plat.version() != want and now() < end:
        sleep(5)
    got = plat.version()
    if got != want or plat.files_version() != want:
        plat.snapshot("the probe did not land after the quit")
        return "fail", "wrong_version", got, extra
    if not landed.win_signature_valid(plat.app_exe()):
        return "fail", "signature_invalid", got, extra
    return "pass", "ok", got, extra


def quit_during_verify(plat, want: str, extra: dict, now=time.monotonic, sleep=time.sleep,
                       quit_timeout: float = 120) -> tuple:
    """mac-quit-during-verify: quit the way a person does while Squirrel is still verifying the downloaded update.
    Pass = the app exits within `quit_timeout`, and the update is then installed, or offered again (staged) at the
    next launch. Bring-up run 45087190217: a 2.0.4 app quit in that gap was still running 10 minutes later."""
    if plat.name != "macos":
        return "fail", "unsupported_on_platform", plat.version(), extra
    end = now() + 900
    while True:
        if plat.in_verify_window(want):
            break
        if plat.staged(want):
            extra["window"] = "missed"
            return "inconclusive", "verify_window_missed", plat.version(), extra
        if now() >= end:
            return "inconclusive", "update_never_ready", plat.version(), extra
        sleep(0.2)
    extra["window"] = "hit"
    if not plat.quit_like_a_person(timeout=quit_timeout):
        plat.snapshot("quit while Squirrel was verifying, still running")
        return "fail", "still_running_expected_exit", plat.version(), extra
    end = now() + 120
    while plat.version() != want and now() < end:
        sleep(3)
    if plat.version() == want:
        extra["outcome"] = "installed"
        if not landed.mac_signature_valid(plat.app):
            return "fail", "signature_invalid", want, extra
        return "pass", "ok", want, extra
    plat.launch()
    end = now() + 600
    while not plat.staged(want) and now() < end:
        sleep(3)
    if plat.staged(want):
        extra["outcome"] = "offered_again"
        return "pass", "ok", plat.version(), extra
    return "fail", "update_never_ready", plat.version(), extra


def timeout_reason(r: dict, path: str) -> str:
    """Which step an offer that timed out stopped at (bring-up run 45097794033 had only `offer_timeout`)."""
    if r.get("header") == "not_clickable":
        return "ready_button_not_clickable"
    if not r.get("ready_on_disk") and not r.get("seen_window") and r.get("header") in ("absent", None):
        return "update_never_ready"
    if path.startswith("click") and r.get("ready_on_disk") and not r.get("seen_window"):
        return "offer_not_opened"
    return "offer_timeout"


def old_quit_word(log: str) -> str:
    """How the clicked app's own quit went, from its main.log after the click: finished (its child-stop step logged
    its result), stalled (it began quitting and logged nothing after), or not_logged."""
    if "stopped=" in log or any(line in log for line in QUIT_DONE_LINES):
        return "finished"
    if "[Quit] quit begun" in log:
        return "stalled"
    return "not_logged"


def after_click(plat, ctx, t0, want, frm, watch, extra):
    if plat.name == "windows":
        plat.dumps_after_close("after Restart & Install")
    old = getattr(plat, "proc", None)
    old_exit = None
    end = time.monotonic() + 600
    while plat.version() != want and time.monotonic() < end:
        if old is not None and old_exit is None and old.poll() is not None:
            old_exit = int(time.time() - t0)
        time.sleep(5)
    got = plat.version()
    if watch:
        extra["setup_window"] = "seen" if watch.seen else "not_seen"
    if plat.name == "windows":
        # Coordinator, 23 Nov: after Restart & Install, did the old app's quit hang, and did the silent installer
        # close it (NSIS app-close) or give up? Seconds from the click until the clicked app exited (None = never).
        if old is not None and old_exit is None and old.poll() is not None:
            old_exit = int(time.time() - t0)
        extra["old_app_exit_s"] = old_exit
        extra["old_quit"] = old_quit_word(plat.log_since_launch())
        extra["trace"] = trace_class(plat)
    if got != want or plat.files_version() != want:
        if plat.name == "windows":
            plat.snapshot("after the click, the version did not change")
        return "fail", "wrong_version", got, extra
    exe = plat.exe if plat.name == "macos" else plat.app_exe()
    proc = landed.wait_started(str(exe), t0 + 1, 180)
    if proc is None:
        return "fail", "not_reopened", got, extra
    time.sleep(30)
    if not proc.is_running():
        return "fail", "reopened_exited", got, extra
    return common_checks(plat, ctx, frm, want, watch, extra)


def after_quit(plat, ctx, t0, want, frm, watch, extra):
    end = time.monotonic() + 600
    while plat.version() != want and time.monotonic() < end:
        time.sleep(5)
    got = plat.version()
    if got != want or plat.files_version() != want:
        return "fail", "wrong_version", got, extra
    exe = plat.exe if plat.name == "macos" else plat.app_exe()
    time.sleep(30)
    if landed.started_after(str(exe), t0 + 1):
        return "fail", "reopened_unexpectedly", got, extra
    plat.launch(debug=False)
    return common_checks(plat, ctx, frm, want, watch, extra)


def common_checks(plat, ctx, frm, want, watch, extra):
    sig = landed.mac_signature_valid(plat.app) if plat.name == "macos" else landed.win_signature_valid(plat.app_exe())
    if not sig:
        if plat.name == "windows":
            note(f"signature of the landed app: {landed.win_signature_status(plat.app_exe())[0]}")
        return "fail", "signature_invalid", want, extra
    if watch and watch.seen:
        return "fail", "setup_window_seen", want, extra
    if plat.name == "windows":
        tc = trace_class(plat)
        extra["trace"] = tc
        if tc != "done":
            return "fail", "trace_mismatch", want, extra
    from_ver = ctx["candidate"] if frm == "candidate" else frm
    if not arrival_ok(plat, from_ver, want):
        return "fail", "arrival_record_missing", want, extra
    if not landed.health_ok(timeout_s=600):
        return "fail", "health_failed", want, extra
    return "pass", "ok", want, extra


def land_candidate_directly(plat, ctx):
    """For the candidate's own next hop: install the candidate over the from-state the way an update does."""
    st = ctx["staging"]
    if plat.name == "windows":
        exe = st.get(st.candidate_asset("-update.exe"))
        if plat.run_installer(exe, ["--updated", "/S"]) != 0:
            raise RuntimeError("installer_exit_nonzero")
    else:
        z = st.get(st.candidate_asset("-mac-arm64-update.zip"))
        tmp = ctx["cache"] / "unz-candidate"
        shutil.rmtree(tmp, ignore_errors=True)
        plat.sh("ditto", "-x", "-k", str(z), str(tmp), check=True)
        shutil.rmtree(plat.app, ignore_errors=True)
        plat.sh("ditto", str(tmp / "CustodyComms.app"), str(plat.app), check=True)
    plat.kill_all()
    plat.first_launch()
    if plat.version() != ctx["candidate"]:
        raise RuntimeError("precondition_failed")


def prove_ps1(args: list[str]) -> subprocess.CompletedProcess:
    r = subprocess.run(["pwsh", "-NoProfile", "-File", str(HERE / "prove-updated-installer.ps1"), *args],
                       capture_output=True, text=True, timeout=1800)
    note(f"prove rc={r.returncode} {r.stdout[-1500:]} {r.stderr[-800:]}")
    return r


def control_cell(plat, ctx):
    u = plat.pins["windows"]["2.0.4"]["update"]
    exe = fetch_pinned(u["url"], u["size"], u["sha256"], ctx["cache"])
    out = ctx["cache"] / "control.json"
    r = prove_ps1(["-NewInstaller", str(exe), "-ExpectVersion", "2.0.4", "-FromVersion", "2.0.3", "-TimeoutSeconds", "180", "-Control", "-ResultOut", str(out)])
    res = common.load_json(out) if out.exists() else {}
    if r.returncode == 0 and res.get("observed") == "wizard_seen":
        return "pass", "ok", plat.version(), {"observed": "wizard_seen"}
    return "fail", res.get("reason", "control_no_defect"), plat.version(), {}


def lock_cells(plat, ctx, path):
    st = ctx["staging"]
    cand = st.get(st.candidate_asset("-update.exe"))
    if path == "lock":
        a = subprocess.Popen([str(cand), "--updated", "--force-run"], **QUIET)
        time.sleep(5)
        b = subprocess.Popen([str(cand), "--updated", "--force-run"], **QUIET)
        for p in (a, b):
            try:
                p.wait(timeout=900)
            except subprocess.TimeoutExpired:
                p.kill()
                return "fail", "installer_timeout", plat.version(), {}
        tc = trace_class(plat)
        ok = plat.version() == ctx["candidate"] and len(landed.win_installs()) == 1 and tc == "lock_collision"
        return ("pass" if ok else "fail"), ("ok" if ok else "trace_mismatch"), plat.version(), {"trace": tc}
    # old-wizard-open: the shipped 2.0.4 wizard left open, then the candidate with the click arguments.
    u = plat.pins["windows"]["2.0.4"]["update"]
    old = fetch_pinned(u["url"], u["size"], u["sha256"], ctx["cache"])
    wiz = subprocess.Popen([str(old), "--updated", "--force-run"], **QUIET)
    time.sleep(20)
    if not landed.win_setup_window_open():
        wiz.kill()
        return "inconclusive", "control_no_window", plat.version(), {}
    first = subprocess.Popen([str(cand), "--updated", "--force-run"], **QUIET)
    try:
        first.wait(timeout=300)
    except subprocess.TimeoutExpired:
        first.kill()
    first_ok = plat.version() == "2.0.3" and trace_class(plat) == "started_not_finished"
    wiz.kill()
    plat.kill_all()
    if plat.run_installer(cand, ["--updated", "--force-run"]) != 0:
        return "fail", "installer_exit_nonzero", plat.version(), {}
    ok = first_ok and plat.version() == ctx["candidate"]
    return ("pass" if ok else "fail"), ("ok" if ok else "wrong_version"), plat.version(), {"first_run_blocked": first_ok}


CLOSE_WINDOW_PS = r"""
param([ValidateSet('list','close')][string]$Mode = 'list')
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class CcWin {
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
'@
$root = [System.Windows.Automation.AutomationElement]::RootElement
$all = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
$cand = @()
foreach ($w in $all) {
  try { $p = Get-Process -Id $w.Current.ProcessId -ErrorAction Stop } catch { continue }
  if ($p.ProcessName -ne 'CustodyComms') { continue }
  $r = $w.Current.BoundingRectangle
  $o = [pscustomobject]@{ Hwnd = [int64]$w.Current.NativeWindowHandle; Name = $w.Current.Name; Cls = $w.Current.ClassName;
                          ProcId = $w.Current.ProcessId; Area = [double]($r.Width * $r.Height); Off = $w.Current.IsOffscreen }
  $cand += $o
  Write-Output ("window hwnd={0} pid={1} name='{2}' class={3} area={4} offscreen={5}" -f $o.Hwnd, $o.ProcId, $o.Name, $o.Cls, $o.Area, $o.Off)
}
foreach ($p in Get-Process CustodyComms -ErrorAction SilentlyContinue) {
  Write-Output ("process pid={0} mainHandle={1} mainTitle='{2}'" -f $p.Id, [int64]$p.MainWindowHandle, $p.MainWindowTitle)
}
$main = $cand | Where-Object { -not $_.Off -and $_.Area -gt 0 } | Sort-Object Area -Descending | Select-Object -First 1
if (-not $main) { Write-Output 'no visible app window'; exit 3 }
if ($Mode -eq 'list') { exit 0 }
$fg = [CcWin]::SetForegroundWindow([IntPtr]$main.Hwnd)
$posted = [CcWin]::PostMessage([IntPtr]$main.Hwnd, 0x0112, [IntPtr]0xF060, [IntPtr]::Zero)   # WM_SYSCOMMAND, SC_CLOSE
Write-Output ("close hwnd={0} foreground={1} posted={2}" -f $main.Hwnd, $fg, $posted)
exit 0
"""


FRESH_WIZARD_PS = r"""
param([string]$Exe, [int]$TimeoutSeconds = 900)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$p = Start-Process -FilePath $Exe -PassThru
$root = [System.Windows.Automation.AutomationElement]::RootElement
$seen = $false; $end = (Get-Date).AddSeconds($TimeoutSeconds)
while (-not $p.HasExited -and (Get-Date) -lt $end) {
  $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
  $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
  if ($win -and $win.Current.Name -like 'CustodyComms*Setup*') {
    $seen = $true
    $btns = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)))
    foreach ($b in $btns) {
      $n = $b.Current.Name -replace '&', ''
      if ($b.Current.IsEnabled -and $n -match '^(Next|Install|Finish)') {
        $b.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); break
      }
    }
  }
  Start-Sleep -Seconds 2
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force; Write-Output "timeout seen=$seen"; exit 3 }
Write-Output "exit=$($p.ExitCode) seen=$seen"
if (-not $seen) { exit 4 }
exit $p.ExitCode
"""


def fresh_wizard(plat, ctx):
    if plat.name != "windows":
        return "fail", "unsupported_on_platform", None, {}
    st = ctx["staging"]
    names = [a["name"] for a in st.inv.get("extras", []) if a["name"].endswith(".exe") and "-update" not in a["name"]]
    if len(names) != 1:
        return "not_run", "pin_missing", None, {}
    full = st.get(names[0])
    script = ctx["cache"] / "fresh-wizard.ps1"
    script.write_text(FRESH_WIZARD_PS, encoding="utf-8")
    r = subprocess.run(["powershell", "-NoProfile", "-File", str(script), "-Exe", str(full)], capture_output=True, text=True, timeout=1200)
    note(f"fresh-wizard rc={r.returncode} {r.stdout[-300:]}")
    if r.returncode == 4:
        return "fail", "control_no_window", plat.version(), {}
    if r.returncode != 0:
        return "fail", "installer_exit_nonzero", plat.version(), {}
    plat.kill_all()
    if plat.version() != ctx["candidate"]:
        return "fail", "wrong_version", plat.version(), {}
    plat.launch(debug=False)
    if not landed.health_ok(timeout_s=1200):
        return "fail", "health_failed", plat.version(), {}
    return "pass", "ok", plat.version(), {"fullSha256": common.sha256_hex(full)[:40]}


# ── main ──────────────────────────────────────────────────────────────────────────────────────────


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in v.split("-")[0].split("."))


def pin_mode(pins: dict, platform: str, cache: Path) -> int:
    prefix = f"{platform}-"
    for key, f in pins["fullInstallers"].items():
        if key.startswith(prefix) and not f.get("sha256"):
            p = fetch(f["url"], cache / f["url"].rsplit("/", 1)[1])
            say(f"PIN {key} size {p.stat().st_size} sha256 {common.sha256_hex(p)}")
    return 1


class Flusher:
    """Writes the receipt and the encrypted diagnostics after every attempt, so a cancelled or capped job still
    leaves both behind. With a cap, a watchdog ends the run at the cap: the cell in progress becomes
    `inconclusive` / `cell_timeout`, both files are written, and the process exits before the job's own limit."""

    def __init__(self, receipt: dict, receipt_path: Path, diag_path: Path, work: Path):
        self.receipt, self.receipt_path, self.diag_path, self.work = receipt, receipt_path, diag_path, work
        self.lock = threading.Lock()
        self.staging = None
        self.current: tuple[dict, float] | None = None

    def flush(self) -> None:
        with self.lock:
            self._write()

    def _write(self) -> None:
        if self.staging is not None:
            self.receipt["candidateFiles"] = sorted(self.staging.files.values(), key=lambda f: f["name"])
        self.receipt["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tmp = self.receipt_path.with_name(self.receipt_path.name + ".tmp")
        tmp.write_text(json.dumps(self.receipt, indent=1) + "\n", encoding="utf-8")
        os.replace(tmp, self.receipt_path)
        log = self.work / "driver.log"
        log.write_text("\n".join(LOG) + "\n", encoding="utf-8")
        try:
            common.encrypt_bundle([log, *DIAG_FILES], self.diag_path)
        except Exception:  # noqa: BLE001
            say("diagnostics: not written")

    def cap(self, seconds: int, exit=os._exit) -> threading.Thread:
        def fire():
            time.sleep(seconds)
            got = self.lock.acquire(timeout=60)
            try:
                if self.current is not None:
                    rec, started = self.current
                    if rec.pop("_open", None):
                        if rec["result"] == "not_run":
                            common.finish_cell(rec, "inconclusive", "cell_timeout", None, started)
                        else:  # a retry hit the cap: the first attempt's result is the evidence, kept as it was
                            note(f"{rec['id']}: attempt {rec['attempts']} hit the cell cap")
                            rec["attempts"] -= 1
                note("cell cap reached")
                self._write()
                for c in self.receipt["cells"]:
                    say(f"cell {c['id']}: {c['result']} {c['detail']} ({c['seconds']} s, attempt {c['attempts']})")
                say("overall: not pass")
            finally:
                if got:
                    self.lock.release()
            exit(1)

        th = threading.Thread(target=fire, daemon=True)
        th.start()
        return th


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True, choices=common.PLATFORMS)
    ap.add_argument("--mac-variant", required=True, choices=common.MAC_VARIANTS)
    ap.add_argument("--mode", required=True, choices=("gate", "live", "pin"))
    ap.add_argument("--bind", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--diag", required=True)
    ap.add_argument("--only", default="", help="comma-separated cell ids (bring-up); such a receipt never clears a release")
    ap.add_argument("--cell-cap", type=int, default=0, help="seconds; the run ends itself here with its receipt written")
    a = ap.parse_args(argv)
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    pins = common.load_json(common.PINS)
    if a.mode == "pin":
        return pin_mode(pins, a.platform, work)
    bind = common.load_json(Path(a.bind))
    receipt = {
        "format": common.RECEIPT_FORMAT, "platform": a.platform, "job": common.JOB_NAMES[a.platform],
        "mode": a.mode, "macVariant": a.mac_variant, "only": a.only or None, "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **{k: bind.get(k) for k in common.BIND_KEYS},
        "cells": [],
    }
    cells = [c for c in common.cells_for(common.load_json(common.CELLS), a.platform, a.mac_variant)
             if c.get("mode", "gate") == a.mode]
    if a.only:
        wanted = {x.strip() for x in a.only.split(",") if x.strip()}
        cells = [c for c in cells if c["id"] in wanted]
    recs = [common.new_cell(c) for c in cells]
    receipt["cells"] = recs
    fl = Flusher(receipt, Path(a.receipt), Path(a.diag), work)
    fl.flush()
    if a.cell_cap > 0:
        fl.cap(a.cell_cap)
    rc = 1
    run_started = time.monotonic()
    try:
        staging = Staging(bind, work)
        fl.staging = staging
        receipt.update(candidateVersion=staging.inv["candidateVersion"], probeVersion=staging.inv.get("probeVersion"),
                       inventorySha256=staging.inventory_sha256)
        ctx = {"candidate": staging.inv["candidateVersion"], "probe": staging.inv.get("probeVersion"),
               "probe_url": (f"https://github.com/{bind['stagingRepo']}/releases/download/{staging.inv['probeTag']}"
                             if staging.inv.get("probeTag") else ""),
               "staging": staging, "staging_repo": bind["stagingRepo"], "mode": a.mode, "cache": work,
               "newest_shipped": {p: max((v for v in pins[p] if "recipe" in pins[p][v]), key=_vkey) for p in common.PLATFORMS}}
        plat = Win(pins, work) if a.platform == "windows" else Mac(pins, work)
        for name in [staging.candidate_asset("-update.exe" if a.platform == "windows" else "-mac-arm64-update.zip")]:
            staging.get(name)
        for cell, rec in zip(cells, recs):
            first_s = 0.0
            for attempt in (1, 2):
                if attempt == 2 and a.cell_cap > 0 and (time.monotonic() - run_started) + first_s > a.cell_cap - 60:
                    note(f"{cell['id']}: no time left for a second attempt")
                    break
                started = time.monotonic()
                rec["attempts"] = attempt
                rec["_open"] = True
                fl.current = (rec, started)
                try:
                    result, reason, got, extra = run_one(plat, cell, ctx)
                except RuntimeError as e:
                    reason = str(e) if str(e) in common.REASONS else "error"
                    result, got, extra = ("not_run" if reason == "pin_missing" else "inconclusive"), None, {}
                except Exception as e:  # noqa: BLE001 - any crash is a non-pass, never a pass
                    note(f"{cell['id']} crashed: {type(e).__name__}: {e}")
                    result, reason, got, extra = "inconclusive", "error", None, {}
                with fl.lock:
                    rec.pop("_open", None)
                    common.finish_cell(rec, result, reason, got, started, **extra)
                    note(f"{cell['id']} attempt {attempt}: {result} {reason}")
                    fl._write()
                first_s = time.monotonic() - started
                if result == "pass" or result == "not_run":
                    break
            fl.current = None
            say(f"cell {rec['id']}: {rec['result']} {rec['detail']} ({rec['seconds']} s, attempt {rec['attempts']})")
        rc = 0 if common.all_blocking_passed(receipt["cells"]) else 1
    except RuntimeError as e:
        note(f"setup refused: {e}")
        say("setup: refused")
        word = str(e) if str(e) in common.REASONS else "error"
        for rec in recs:
            if rec["result"] == "not_run" and not rec.get("attempts"):
                rec.update(result="inconclusive", detail=word)
        rc = 2
    except Exception as e:  # noqa: BLE001 - a traceback would put paths and messages in the public log
        note(f"setup crashed: {type(e).__name__}: {e}")
        say("setup: error")
        for rec in recs:
            if rec["result"] == "not_run" and not rec.get("attempts"):
                rec.update(result="inconclusive", detail="error")
        rc = 2
    finally:
        with fl.lock:
            for rec in recs:
                rec.pop("_open", None)
            fl._write()
    if cells and all(c.get("kind") == "reported" for c in cells):
        # A reported cell is recorded on the receipt and never fails its job (the publish step needs every job green).
        say("overall: reported only")
        return 0
    say(f"overall: {'pass' if rc == 0 else 'not pass'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
