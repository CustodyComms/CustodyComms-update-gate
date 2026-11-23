"""Drives an installed app's update offer the way a person does, through the Chrome DevTools Protocol.

It finds buttons only by the words a person sees on them (or their accessible name) and presses them with a real
mouse event at their centre, and only when the point under that centre is the button itself (so a button hidden
behind another layer is never pressed).

One exception, used only when the version's header button cannot exist: 2.0.0 to 2.0.4 mount it only into the
signed-in screen's header, and a test machine is signed out. Once the update is ready on disk (Squirrel's staged copy
on macOS, the finished download on Windows) and no header button is on any page, the driver calls the one function the
header button itself calls, `api.update.openReady()`, exposed by every such version, and records `header: bypassed`.
The What's New buttons are still pressed with the mouse.

The offer arrives one of two ways, by version:
  window         a "What's New" window opens by itself: press "Download & Install", wait, press "Restart & Install".
  header-button  the update downloads quietly and a small "Update ready" button appears in the header: press it,
                 the What's New window opens already downloaded, press "Restart & Install".
Either way also accepts the other's screens if they appear.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request

DOWNLOAD_LABEL = re.compile(r"^Download\s*&\s*Install$")
INSTALL_LABEL = re.compile(r"^Restart\s*&\s*Install$")
# The header button's words and accessible name, in every version that has one.
HEADER_LABEL = re.compile(r"(^Update ready$)|( is ready · Restart$)|(^Update (required|now) · Restart$)|(is ready\. Restart to install it\.$)")

# Returns the first visible button whose text or accessible name matches, with its centre and whether the point
# under the centre belongs to it. The pattern is passed in; nothing here knows the page's structure.
FIND_BUTTON_JS = r"""(function (src, flags) {
  const re = new RegExp(src, flags);
  const vis = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const nodes = Array.from(document.querySelectorAll('button, [role="button"]'));
  for (const el of nodes) {
    const text = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
    const name = (el.getAttribute('aria-label') || el.getAttribute('title') || '').trim();
    if (!(re.test(text) || (name && re.test(name)))) continue;
    if (!vis(el)) continue;
    const r = el.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    const at = document.elementFromPoint(x, y);
    return JSON.stringify({found: true, x: x, y: y, hit: !!at && (at === el || el.contains(at)),
                           disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true'});
  }
  return JSON.stringify({found: false});
})"""


class Browser:
    """The real transport: /json/list over HTTP and one websocket per call."""

    def __init__(self, port: int, timeout: float = 15.0):
        self.port, self.timeout = port, timeout

    def pages(self) -> list[dict]:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=5) as r:
            body = json.loads(r.read().decode("utf-8"))
        return [{"id": t["id"], "url": t.get("url", ""), "ws": t["webSocketDebuggerUrl"]}
                for t in body if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]

    def _call(self, page: dict, method: str, params: dict) -> dict:
        import websocket  # websocket-client

        ws = websocket.create_connection(page["ws"], timeout=self.timeout, suppress_origin=True)
        try:
            ws.send(json.dumps({"id": 1, "method": method, "params": params}))
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                msg = json.loads(ws.recv())
                if msg.get("id") == 1:
                    if "error" in msg:
                        raise RuntimeError(method)
                    return msg.get("result") or {}
            raise TimeoutError(method)
        finally:
            ws.close()

    def evaluate(self, page: dict, expr: str, await_promise: bool = False):
        res = self._call(page, "Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                                    "awaitPromise": await_promise})
        return (res.get("result") or {}).get("value")

    def click(self, page: dict, x: float, y: float) -> None:
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            p = {"type": kind, "x": x, "y": y}
            if kind != "mouseMoved":
                p.update(button="left", clickCount=1)
            self._call(page, "Input.dispatchMouseEvent", p)


def find_button(browser, page: dict, pattern: re.Pattern) -> dict:
    expr = f"{FIND_BUTTON_JS}({json.dumps(pattern.pattern)}, '')"
    try:
        return json.loads(browser.evaluate(page, expr) or '{"found": false}')
    except Exception:
        return {"found": False}


def wait_for_debug_port(browser, timeout_s: float, sleep=time.sleep, now=time.monotonic) -> bool:
    end = now() + timeout_s
    while now() < end:
        try:
            if browser.pages():
                return True
        except Exception:
            pass
        sleep(2)
    return False


# Bring-up run 45097794033: the function lives at window.api.update (preload `exposeInMainWorld('api', {update: ...})`
# in every 2.0.x); the first version looked at window.update and never opened anything. Returns one short word.
OPEN_READY_JS = ("(async function(){ const u = (window.api && window.api.update) || window.update;"
                 " if (!u || typeof u.openReady !== 'function') return 'missing';"
                 " try { const r = await u.openReady(); return (r && r.success) ? 'opened'"
                 " : ((r && r.code === 'NOT_READY') ? 'not_ready' : 'refused'); } catch (e) { return 'error'; } })()")
OPEN_READY_WORDS = ("missing", "opened", "not_ready", "refused", "error")


def drive_offer(browser, *, want: str, timeout_s: float, sleep=time.sleep, now=time.monotonic,
                ready_probe=None) -> dict:
    """Take the offer to the point `want` asks for.

    want="install": press Restart & Install (the click path). want="ready": stop once the update is downloaded
    and ready, pressing nothing that installs (the quit and close paths).
    `ready_probe()`: True once the update is ready on disk. want="ready" then needs no button at all; want="install"
    with no header button on any page then opens the ready window the way the header button does (`bypassed`).
    Returns {"state": "installed_clicked"|"ready"|"timeout", "header": "clicked"|"seen"|"not_clickable"|"absent"|
             "bypassed", "download_clicked": bool, "seen_window": bool, "ready_on_disk": bool,
             "open_ready": "not_tried"|one of OPEN_READY_WORDS}."""
    if want not in ("install", "ready"):
        raise ValueError(want)
    out = {"state": "timeout", "header": "absent", "download_clicked": False, "seen_window": False,
           "ready_on_disk": False, "open_ready": "not_tried"}
    last_header_click = last_bypass = -1e9
    end = now() + timeout_s
    while now() < end:
        try:
            pages = browser.pages()
        except Exception:
            pages = []
        header_on_a_page = False
        for page in pages:
            b = find_button(browser, page, INSTALL_LABEL)
            if b.get("found"):
                out["seen_window"] = True
                if not b.get("disabled") and b.get("hit"):
                    if want == "ready":
                        out["state"] = "ready"
                        return out
                    browser.click(page, b["x"], b["y"])
                    out["state"] = "installed_clicked"
                    return out
                continue
            b = find_button(browser, page, DOWNLOAD_LABEL)
            if b.get("found"):
                out["seen_window"] = True
                if not out["download_clicked"] and not b.get("disabled") and b.get("hit"):
                    browser.click(page, b["x"], b["y"])
                    out["download_clicked"] = True
                continue
            b = find_button(browser, page, HEADER_LABEL)
            if b.get("found"):
                header_on_a_page = True
                if not b.get("hit"):
                    if out["header"] == "absent":
                        out["header"] = "not_clickable"
                    continue
                if want == "ready":
                    # The header button appears only once the update is downloaded (and, on macOS, staged).
                    out["header"] = "seen"
                    out["state"] = "ready"
                    return out
                if now() - last_header_click > 30:
                    browser.click(page, b["x"], b["y"])
                    out["header"] = "clicked"
                    last_header_click = now()
        if ready_probe is not None and not header_on_a_page and out["header"] in ("absent", "bypassed"):
            try:
                ready = bool(ready_probe())
            except Exception:
                ready = False
            if ready:
                out["ready_on_disk"] = True
            if ready and want == "ready":
                out["state"] = "ready"
                return out
            if ready and not out["seen_window"] and now() - last_bypass > 30:
                last_bypass = now()
                for page in pages:
                    try:
                        word = browser.evaluate(page, OPEN_READY_JS, await_promise=True)
                    except Exception:
                        word = "error"
                    word = word if word in OPEN_READY_WORDS else "error"
                    if out["open_ready"] in ("not_tried", "missing", "error") or word == "opened":
                        out["open_ready"] = word
                    if word == "opened":
                        out["header"] = "bypassed"
                        break
        sleep(3)
    return out


def close_first_window(browser) -> bool:
    """Close the app's main window from inside the page, as the window's close control does. Used on macOS only
    when the native close button cannot be pressed through the accessibility interface."""
    for page in browser.pages():
        try:
            browser.evaluate(page, "window.close(); true")
            return True
        except Exception:
            continue
    return False
