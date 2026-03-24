#!/usr/bin/env python3
import urllib.request
import hashlib
import os
import sys
import time
from datetime import datetime

C2_URL = "https://checkmarx.zone/raw"
UA = "Mozilla/5.0"
INTERVAL = 60
OUTDIR = "payloads"

os.makedirs(OUTDIR, exist_ok=True)


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open("c2_monitor.log", "a") as f:
        f.write(line + "\n")


def beep():
    sys.stdout.write("\a")
    sys.stdout.flush()
    for _ in range(5):
        sys.stdout.write("\a")
        sys.stdout.flush()
        time.sleep(0.3)


def fetch_c2():
    try:
        req = urllib.request.Request(
            C2_URL, headers={"User-Agent": UA}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8").strip()
    except Exception as e:
        log(f"Fetch error: {e}")
        return None


def download_payload(url):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    h = hashlib.sha256(url.encode()).hexdigest()[:8]
    filename = os.path.join(OUTDIR, f"payload_{ts}_{h}")
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": UA}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        with open(filename, "wb") as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        size = len(data)
        log(f"Downloaded: {filename} ({size} bytes)")
        log(f"SHA256: {sha}")
        return filename
    except Exception as e:
        log(f"Download error: {e}")
        return None


def main():
    log(f"Monitoring {C2_URL} every {INTERVAL}s")
    log(f"Payloads saved to {OUTDIR}/")
    seen = set()

    while True:
        resp = fetch_c2()
        if resp is None:
            log("No response from C2")
        elif "youtube.com" in resp:
            log(f"YouTube (dormant): {resp}")
        elif not resp.startswith("http"):
            log(f"Non-URL response: {resp[:100]}")
        elif resp in seen:
            log(f"Already seen: {resp}")
        else:
            log(f"NEW PAYLOAD URL: {resp}")
            beep()
            path = download_payload(resp)
            if path:
                seen.add(resp)
                log(f"Saved to {path}")
                beep()

        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Stopped by user")
