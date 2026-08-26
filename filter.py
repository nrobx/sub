#!/usr/bin/env python3
import base64
import glob
import json
import os
import re
import subprocess
import sys
import urllib.parse

SRC_REPO = os.environ.get("SRC_REPO", "https://github.com/hamedp-71/Sub_Checker_Creator.git")
CLONE_DIR = os.path.expanduser("~/Sub_Checker_Creator")
HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.abspath(os.environ.get("OUTPUT_DIR", HERE))

TARGET_TRANSPORTS = ("ws", "httpupgrade")
TARGET_PROTOCOLS = ("vless", "vmess", "trojan")
TARGET_PORT = 443

FILE_HEADER = (
    "//profile-title: base64:d3MtaHR0cHVwZ3JhZGUtcG9ydC00NDMtaGFtZWRwNzE=\n"
    "//profile-update-interval: 1\n"
    "//subscription-userinfo: filter=ws+httpupgrade+port443\n"
)


def _b64_decode_vmess(encoded: str):
    missing = len(encoded) % 4
    if missing:
        encoded += "=" * (4 - missing)
    return json.loads(base64.b64decode(encoded).decode("utf-8"))


def detect_transport(protocol: str, rest_no_frag: str):
    if protocol in ("vless", "trojan"):
        if "?" not in rest_no_frag:
            return ""
        params = urllib.parse.parse_qs(rest_no_frag.split("?", 1)[1])
        return params.get("type", [""])[0]
    if protocol == "vmess":
        try:
            return _b64_decode_vmess(rest_no_frag).get("net", "")
        except Exception:
            return ""
    return None


def classify(config: str):
    config = config.strip()
    if not config or "://" not in config:
        return None, None
    protocol = config.split("://", 1)[0].lower()
    rest = config.split("://", 1)[1].split("#", 1)[0]
    transport = detect_transport(protocol, rest)
    if transport in TARGET_TRANSPORTS and protocol in TARGET_PROTOCOLS:
        return protocol, transport
    return None, None


def get_port(config: str):
    config = config.strip()
    if "://" not in config:
        return None
    protocol = config.split("://", 1)[0].lower()
    rest = config.split("://", 1)[1].split("#", 1)[0]
    if protocol in ("vless", "trojan"):
        core = rest.split("?", 1)[0]
        m = re.search(r":(\d+)$", core)
        return int(m.group(1)) if m else None
    if protocol == "vmess":
        try:
            return int(_b64_decode_vmess(rest).get("port", 0))
        except Exception:
            return None
    return None


def decode_line(line: str):
    line = line.strip()
    if line.startswith(("vless://", "vmess://", "trojan://")):
        return line
    try:
        dec = base64.b64decode(line).decode("utf-8").strip()
        if dec.startswith(("vless://", "vmess://", "trojan://")):
            return dec
    except Exception:
        pass
    return None


def clone_source():
    if os.path.isdir(os.path.join(CLONE_DIR, ".git")):
        subprocess.run(["git", "-C", CLONE_DIR, "pull", "--ff-only"], check=False)
    else:
        subprocess.run(["git", "clone", "--depth", "1", SRC_REPO, CLONE_DIR], check=True)
    loc_dir = os.path.join(CLONE_DIR, "loc")
    if not os.path.isdir(loc_dir):
        sys.exit(1)
    return sorted(glob.glob(os.path.join(loc_dir, "*.txt")))


def load_configs(sources):
    seen = set()
    out = []
    for path in sources:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                cfg = decode_line(line)
                if not cfg:
                    continue
                proto, trans = classify(cfg)
                if proto is None:
                    continue
                key = cfg.split("#", 1)[0]
                if key in seen:
                    continue
                seen.add(key)
                out.append((cfg, proto, trans))
    return out


def write_file(name, lines):
    if not lines:
        return
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(FILE_HEADER)
        f.write("\n".join(lines) + "\n")
    print(f"  [ok] {name}  ({len(lines)} config)")


def save(port443_only=True):
    ws_files = {p: os.path.join(OUTPUT_DIR, f"{p}_ws.txt") for p in TARGET_PROTOCOLS}
    by_proto = {p: [] for p in TARGET_PROTOCOLS}
    for proto, path in ws_files.items():
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                cfg = decode_line(line)
                if not cfg:
                    continue
                if port443_only and get_port(cfg) != TARGET_PORT:
                    continue
                by_proto[proto].append(cfg)
    for proto in TARGET_PROTOCOLS:
        cfgs = list(dict.fromkeys(by_proto[proto]))
        if not cfgs:
            continue
        cfgs_b64 = [base64.b64encode(c.encode("utf-8")).decode("utf-8") for c in cfgs]
        if port443_only:
            write_file(f"{proto}_ws_443.txt", cfgs)
            write_file(f"{proto}_ws_443_b64.txt", cfgs_b64)
        else:
            write_file(f"{proto}_ws.txt", cfgs)
            write_file(f"{proto}_ws_b64.txt", cfgs_b64)


def main():
    sources = clone_source()
    print(f"Source  : {len(sources)} file from loc/ ({SRC_REPO})")
    results = load_configs(sources)
    print(f"Config ws/httpupgrade found: {len(results)}")
    from collections import Counter
    print("  per protocol :", dict(Counter(p for _, p, _ in results)))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    order = {p: i for i, p in enumerate(TARGET_PROTOCOLS)}
    order_t = {"ws": 0, "httpupgrade": 1}
    sorted_r = sorted(results, key=lambda r: (order.get(r[1], 9), order_t.get(r[2], 9)))
    by_proto = {p: [] for p in TARGET_PROTOCOLS}
    for cfg, proto, _ in sorted_r:
        by_proto[proto].append(cfg)
    print("-" * 50)
    print("Writing ws/httpupgrade results ->", OUTPUT_DIR)
    for proto in TARGET_PROTOCOLS:
        cfgs = by_proto[proto]
        if not cfgs:
            continue
        cfgs_b64 = [base64.b64encode(c.encode("utf-8")).decode("utf-8") for c in cfgs]
        write_file(f"{proto}_ws.txt", cfgs)
        write_file(f"{proto}_ws_b64.txt", cfgs_b64)
    print("-" * 50)
    print(f"Filtering port {TARGET_PORT} ->", OUTPUT_DIR)
    save(port443_only=True)
    print("=" * 50)
    print("Done. Output at:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
