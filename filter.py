#!/usr/bin/env python3
import base64
import glob
import json
import os
import subprocess
import sys
import urllib.parse
import yaml

SRC_REPO = os.environ.get("SRC_REPO", "https://github.com/hamedp-71/Sub_Checker_Creator.git")
CLONE_DIR = os.path.expanduser("~/Sub_Checker_Creator")
HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.abspath(os.environ.get("OUTPUT_DIR", HERE))

TARGET_TRANSPORTS = ("ws", "httpupgrade")
TARGET_PROTOCOLS = ("vless", "vmess", "trojan")

FILE_HEADER = (
    "//profile-title: base64:d3MtaHR0cHVwZ3JhZGUtcG9ydC00NDMtaGFtZWRwNzE=\n"
    "//profile-update-interval: 1\n"
    "//subscription-userinfo: filter=ws+httpupgrade\n"
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


def has_tls(protocol: str, rest_no_frag: str):
    if protocol in ("vless", "trojan"):
        if "?" not in rest_no_frag:
            return False
        params = urllib.parse.parse_qs(rest_no_frag.split("?", 1)[1])
        return params.get("security", [""])[0].lower() == "tls"
    if protocol == "vmess":
        try:
            return _b64_decode_vmess(rest_no_frag).get("tls", "") == "tls"
        except Exception:
            return False
    return False


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
    SKIP_FILES = {"🏴\u200d☠️.txt"}
    return sorted(p for p in glob.glob(os.path.join(loc_dir, "*.txt"))
                  if os.path.basename(p) not in SKIP_FILES)


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
                rest = cfg.split("://", 1)[1].split("#", 1)[0]
                if not has_tls(proto, rest):
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


def _decode_vmess(encoded: str) -> dict:
    missing = len(encoded) % 4
    if missing:
        encoded += "=" * (4 - missing)
    return json.loads(base64.b64decode(encoded).decode("utf-8"))


def _name_for(config: str) -> str:
    if "#" in config:
        return urllib.parse.unquote(config.rsplit("#", 1)[1])
    return "node"


def _strip_prefix(name: str) -> str:
    prefix = "hamedp71::"
    if name.lower().startswith(prefix):
        name = name[len(prefix):]
    return name.strip() or "node"


def rename_config(cfg: str, new_name: str) -> str:
    head, sep, _frag = cfg.rpartition("#")
    encoded = urllib.parse.quote(new_name)
    if sep:
        return head + "#" + encoded
    return cfg + "#" + encoded


def to_clash_proxy(config: str) -> dict:
    """Convert a vless/vmess/trojan ws:// config line into a Clash proxy dict."""
    proto = config.split("://", 1)[0].lower()
    rest = config.split("://", 1)[1]
    name = _strip_prefix(_name_for(config))
    server_part, _, _frag = rest.partition("#")
    core = server_part.split("?", 1)[0]
    host, _, port = core.rpartition(":")
    port = int(port) if port.isdigit() else 443

    if proto == "vmess":
        base = core.rsplit("@", 1)[-1] if "@" in core else core
        vm = _decode_vmess(base)
        proxy = {
            "name": name or vm.get("ps", "node"),
            "type": "vmess",
            "server": vm.get("add"),
            "port": int(vm.get("port", 443)),
            "uuid": vm.get("id"),
            "alterId": int(vm.get("aid", 0)),
            "cipher": vm.get("scy") or vm.get("cipher", "auto"),
            "network": vm.get("net", "ws"),
            "tls": vm.get("tls", "") == "tls",
        }
        if vm.get("net") == "ws":
            proxy["ws-opts"] = {
                "path": vm.get("path", "/"),
                "headers": {"Host": vm.get("host", vm.get("add"))},
            }
        return proxy

    # vless / trojan
    userinfo, _, host = host.rpartition("@")
    uuid = userinfo
    params = urllib.parse.parse_qs(server_part.split("?", 1)[1]) if "?" in server_part else {}
    get = lambda k: (params.get(k, [""])[0])
    sni = get("sni") or get("peer") or host
    ws_opts = {"path": urllib.parse.unquote(get("path") or "/"),
               "headers": {"Host": get("host") or sni}}
    skip = get("allowInsecure") == "1" or get("insecure") == "1"
    if proto == "trojan":
        return {
            "name": name,
            "type": "trojan",
            "server": host,
            "port": port,
            "password": uuid,
            "sni": sni,
            "network": "ws",
            "ws-opts": ws_opts,
            "skip-cert-verify": skip,
        }
    # vless
    flow = get("flow") or ""
    proxy = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid,
        "network": "ws",
        "tls": get("security") == "tls",
        "sni": sni,
        "ws-opts": ws_opts,
        "skip-cert-verify": skip,
    }
    if flow:
        proxy["flow"] = flow
    return proxy


def write_clash_yaml(name, configs):
    if not configs:
        return
    proxies = []
    for cfg in configs:
        try:
            proxies.append(to_clash_proxy(cfg))
        except Exception as e:
            print(f"  [skip] clash parse error: {e} -> {cfg[:60]}")
    if not proxies:
        return
    doc = {"proxies": proxies}
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    print(f"  [ok] {name}  ({len(proxies)} proxies)")


def main():
    for fn in os.listdir(OUTPUT_DIR) if os.path.isdir(OUTPUT_DIR) else []:
        if fn.endswith(".txt"):
            try:
                os.remove(os.path.join(OUTPUT_DIR, fn))
            except FileNotFoundError:
                pass
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
    ordered = []
    for proto in TARGET_PROTOCOLS:
        ordered.extend(by_proto[proto])
    renamed = []
    for i, cfg in enumerate(ordered, 1):
        base = _strip_prefix(_name_for(cfg))
        renamed.append(rename_config(cfg, f"{i} {base}"))
    by_proto = {p: [] for p in TARGET_PROTOCOLS}
    for cfg in renamed:
        proto = cfg.split("://", 1)[0].lower()
        by_proto.setdefault(proto, []).append(cfg)
    print("-" * 50)
    print("Writing ws/httpupgrade results ->", OUTPUT_DIR)
    for proto in TARGET_PROTOCOLS:
        cfgs = by_proto[proto]
        if not cfgs:
            continue
        write_file(f"{proto}_ws.txt", cfgs)
    print("-" * 50)
    print("Building All.txt (all ports, ws/httpupgrade + tls) ->", OUTPUT_DIR)
    all_cfgs = []
    for proto in TARGET_PROTOCOLS:
        p = os.path.join(OUTPUT_DIR, f"{proto}_ws.txt")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                for line in f:
                    cfg = decode_line(line)
                    if cfg:
                        all_cfgs.append(cfg)
    all_cfgs = list(dict.fromkeys(all_cfgs))
    write_file("All.txt", all_cfgs)
    print("-" * 50)
    print("Building vless_ws.yaml (Clash format, proxies only) ->", OUTPUT_DIR)
    vless_cfgs = []
    p = os.path.join(OUTPUT_DIR, "vless_ws.txt")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                cfg = decode_line(line)
                if cfg:
                    vless_cfgs.append(cfg)
    write_clash_yaml("vless_ws.yaml", vless_cfgs)
    print("=" * 50)
    print("Done. Output at:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
