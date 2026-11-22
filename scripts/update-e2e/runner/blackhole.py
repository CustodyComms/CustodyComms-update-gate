"""Keeps test machines out of product analytics: every analytics host the tested versions can send to is pointed
at an unroutable address in the OS hosts file, and the block is PROVEN before any app starts (a connection to
each host on 443 must fail). `python blackhole.py apply` exits 1 if any host still connects.
"""

from __future__ import annotations

import json
import platform
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARK = "# update-gate analytics block"


def hosts_path() -> Path:
    if platform.system() == "Windows":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


def block_lines(hosts: list[str]) -> list[str]:
    out = []
    for h in hosts:
        if not h or any(c.isspace() for c in h) or "/" in h:
            raise ValueError(f"not a host name: {h!r}")
        out += [f"0.0.0.0 {h} {MARK}", f"::1 {h} {MARK}"]
    return out


def merged(existing: str, hosts: list[str]) -> str:
    keep = [ln for ln in existing.splitlines() if MARK not in ln]
    return "\n".join(keep + block_lines(hosts)) + "\n"


def connects(host: str, port: int = 443, timeout: float = 4.0) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    for fam, kind, proto, _, addr in infos:
        if addr[0] in ("0.0.0.0", "::1", "127.0.0.1", "::"):
            continue
        s = socket.socket(fam, kind, proto)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


def flush_dns() -> None:
    if platform.system() == "Windows":
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
    elif platform.system() == "Darwin":
        subprocess.run(["sudo", "dscacheutil", "-flushcache"], capture_output=True)
        subprocess.run(["sudo", "killall", "-HUP", "mDNSResponder"], capture_output=True)


def apply(hosts: list[str]) -> int:
    p = hosts_path()
    text = merged(p.read_text(encoding="utf-8", errors="replace"), hosts)
    if platform.system() == "Darwin":
        subprocess.run(["sudo", "tee", str(p)], input=text, text=True, capture_output=True, check=True)
    else:
        p.write_text(text, encoding="utf-8")
    flush_dns()
    leaks = [h for h in hosts if connects(h)]
    for h in hosts:
        print(f"analytics host blocked: {'NO' if h in leaks else 'yes'}  {h}")
    return 1 if leaks else 0


if __name__ == "__main__":
    pins = json.loads((HERE / "from-versions.json").read_text(encoding="utf-8"))
    if sys.argv[1:] != ["apply"]:
        print("usage: blackhole.py apply", file=sys.stderr)
        sys.exit(2)
    sys.exit(apply(pins["analyticsHosts"]))
