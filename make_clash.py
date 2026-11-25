#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nodes.txt(分享链接) -> clash.yaml (mihomo/Clash.Meta 可直接导入的完整配置)"""
import base64, json, re, sys, urllib.parse


def b64d(s):
    s = (s or "").strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def q(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


def to_int(v, d=0):
    try:
        return int(str(v).strip())
    except Exception:
        return d


def truthy(v):
    return str(v).lower() in ("1", "true", "yes")


def frag_name(link, default="node"):
    if "#" in link:
        n = urllib.parse.unquote(link.split("#", 1)[1]).strip()
        return n or default
    return default


def qs(link):
    if "?" not in link:
        return {}
    raw = link.split("?", 1)[1].split("#", 1)[0]
    d = {}
    for part in raw.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        d[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
    return d


def parse_ss(link):
    body = link[5:].split("#", 1)[0]
    plugin = ""
    if "?" in body:
        body, _, qq = body.partition("?")
        for part in qq.split("&"):
            k, _, v = part.partition("=")
            if k == "plugin":
                plugin = urllib.parse.unquote(v)
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        cred = b64d(userinfo)
        if ":" not in cred:
            cred = urllib.parse.unquote(userinfo)
    else:
        dec = b64d(body)
        if "@" not in dec:
            return None
        cred, _, hostport = dec.rpartition("@")
    if ":" not in cred or ":" not in hostport:
        return None
    method, _, password = cred.partition(":")
    host, _, port = hostport.rpartition(":")
    p = {"type": "ss", "server": host.strip("[]"), "port": to_int(port),
         "cipher": method.strip(), "password": password, "udp": True}
    if plugin:
        pname, _, opts = plugin.partition(";")
        od = {}
        for part in opts.split(";"):
            k, _, v = part.partition("=")
            if k:
                od[k] = v
        if pname == "v2ray-plugin":
            p["plugin"] = "v2ray-plugin"
            po = {"mode": od.get("mode", "websocket")}
            if od.get("tls") in ("1", "true"):
                po["tls"] = True
            if od.get("host"):
                po["host"] = od["host"]
            if od.get("path"):
                po["path"] = od["path"]
            p["plugin-opts"] = po
        elif pname in ("obfs-local", "simple-obfs"):
            p["plugin"] = "obfs"
            po = {"mode": od.get("obfs", "http")}
            if od.get("obfs-host"):
                po["host"] = od["obfs-host"]
            p["plugin-opts"] = po
        else:
            return None
    return p


def parse_vmess(link):
    try:
        d = json.loads(b64d(link[8:]))
    except Exception:
        return None
    host = str(d.get("add", "")).strip()
    if not host:
        return None
    net = str(d.get("net") or "tcp").lower()
    if net in ("h2", "http"):
        net = "h2"
    if net == "quic":
        return None
    p = {"type": "vmess", "server": host, "port": to_int(d.get("port")),
         "uuid": str(d.get("id", "")), "alterId": to_int(d.get("aid", 0)),
         "cipher": str(d.get("scy") or "auto"), "udp": True}
    if str(d.get("tls", "")).lower() in ("tls", "1", "true"):
        p["tls"] = True
        sni = str(d.get("sni") or d.get("host") or "")
        if sni:
            p["servername"] = sni
    if truthy(d.get("skip-cert-verify")):
        p["skip-cert-verify"] = True
    if d.get("fp"):
        p["client-fingerprint"] = str(d["fp"])
    if net == "ws":
        p["network"] = "ws"
        wo = {}
        if d.get("path"):
            wo["path"] = str(d["path"])
        h = str(d.get("host") or "")
        if h:
            wo["headers"] = {"Host": h}
        if wo:
            p["ws-opts"] = wo
    elif net == "grpc":
        p["network"] = "grpc"
        gs = str(d.get("path") or d.get("host") or "")
        if gs:
            p["grpc-opts"] = {"grpc-service-name": gs}
    elif net == "h2":
        p["network"] = "h2"
        ho = {}
        if d.get("path"):
            ho["path"] = str(d["path"])
        if d.get("host"):
            ho["host"] = [str(d["host"])]
        if ho:
            p["h2-opts"] = ho
    return p


def parse_vless(link):
    m = re.match(r"^vless://([^@]+)@([^:/?#]+):(\d+)", link)
    if not m:
        return None
    uuid, host, port = urllib.parse.unquote(m.group(1)), m.group(2), to_int(m.group(3))
    pp = qs(link)
    sec = (pp.get("security") or "none").lower()
    net = (pp.get("type") or "tcp").lower()
    out = {"type": "vless", "server": host, "port": port, "uuid": uuid, "udp": True}
    if sec in ("tls", "reality"):
        out["tls"] = True
        sni = pp.get("sni") or pp.get("host") or ""
        if sni:
            out["servername"] = sni
        if pp.get("alpn"):
            out["alpn"] = [a for a in pp["alpn"].split(",") if a]
        if pp.get("fp"):
            out["client-fingerprint"] = pp["fp"]
        if truthy(pp.get("allowInsecure")) or truthy(pp.get("insecure")):
            out["skip-cert-verify"] = True
    if sec == "reality":
        ro = {}
        if pp.get("pbk"):
            ro["public-key"] = pp["pbk"]
        if pp.get("sid"):
            ro["short-id"] = pp["sid"]
        if ro:
            out["reality-opts"] = ro
        if not out.get("client-fingerprint"):
            out["client-fingerprint"] = "chrome"
    if pp.get("flow"):
        out["flow"] = pp["flow"]
    if net == "ws":
        out["network"] = "ws"
        wo = {"path": pp.get("path") or "/"}
        if pp.get("host"):
            wo["headers"] = {"Host": pp["host"]}
        out["ws-opts"] = wo
    elif net == "grpc":
        out["network"] = "grpc"
        gs = pp.get("serviceName") or pp.get("path") or ""
        if gs:
            out["grpc-opts"] = {"grpc-service-name": gs}
    elif net in ("h2", "http"):
        out["network"] = "h2"
        ho = {}
        if pp.get("path"):
            ho["path"] = pp["path"]
        if pp.get("host"):
            ho["host"] = [pp["host"]]
        if ho:
            out["h2-opts"] = ho
    return out


def parse_trojan(link):
    m = re.match(r"^trojan://([^@]+)@([^:/?#]+):(\d+)", link)
    if not m:
        return None
    pw = urllib.parse.unquote(m.group(1))
    host, port = m.group(2), to_int(m.group(3))
    pp = qs(link)
    out = {"type": "trojan", "server": host, "port": port, "password": pw, "udp": True}
    sni = pp.get("sni") or pp.get("peer") or ""
    if sni:
        out["sni"] = sni
    if truthy(pp.get("allowInsecure")) or truthy(pp.get("insecure")):
        out["skip-cert-verify"] = True
    net = (pp.get("type") or "tcp").lower()
    if net == "ws":
        out["network"] = "ws"
        wo = {"path": pp.get("path") or "/"}
        if pp.get("host"):
            wo["headers"] = {"Host": pp["host"]}
        out["ws-opts"] = wo
    elif net == "grpc":
        out["network"] = "grpc"
        gs = pp.get("serviceName") or ""
        if gs:
            out["grpc-opts"] = {"grpc-service-name": gs}
    return out


def parse_hy2(link, scheme):
    body = link[len(scheme) + 3:]
    if "@" not in body:
        return None
    auth, _, rest = body.rpartition("@")
    hostport = rest.split("#", 1)[0].split("?", 1)[0].strip().rstrip("/")
    if ":" not in hostport:
        return None
    host, _, port = hostport.rpartition(":")
    pp = qs(link)
    out = {"type": "hysteria2", "server": host.strip("[]"), "port": to_int(port),
           "password": urllib.parse.unquote(auth)}
    if pp.get("sni"):
        out["sni"] = pp["sni"]
    if truthy(pp.get("insecure")) or truthy(pp.get("allowInsecure")):
        out["skip-cert-verify"] = True
    if pp.get("obfs"):
        out["obfs"] = pp["obfs"]
        if pp.get("obfs-password"):
            out["obfs-password"] = pp["obfs-password"]
    return out


def parse_socks(link):
    body = link[8:].split("#", 1)[0]
    if "@" not in body:
        return None
    ui, _, hp = body.rpartition("@")
    cred = b64d(ui)
    if ":" not in cred or ":" not in hp:
        return None
    u, _, pw = cred.partition(":")
    host, _, port = hp.rpartition(":")
    return {"type": "socks5", "server": host, "port": to_int(port),
            "username": u, "password": pw, "udp": True}


def yaml_proxy(p):
    out = []
    for i, (k, v) in enumerate(p.items()):
        prefix = "  - " if i == 0 else "    "
        if isinstance(v, dict):
            out.append("%s%s:" % (prefix, k))
            sub = "      "
            for kk, vv in v.items():
                if isinstance(vv, dict):
                    out.append("%s%s:" % (sub, kk))
                    for k3, v3 in vv.items():
                        out.append("%s  %s: %s" % (sub, k3, q(v3)))
                elif isinstance(vv, list):
                    out.append("%s%s:" % (sub, kk))
                    for item in vv:
                        out.append("%s  - %s" % (sub, q(item)))
                else:
                    out.append("%s%s: %s" % (sub, kk, q(vv)))
        else:
            out.append("%s%s: %s" % (prefix, k, q(v)))
    return "\n".join(out)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "nodes.txt"
    dst = sys.argv[2] if len(sys.argv) > 2 else "clash.yaml"
    with open(src, encoding="utf-8") as f:
        links = [l.strip() for l in f if l.strip()]

    proxies, seen, skipped = [], {}, 0
    for link in links:
        try:
            if link.startswith("ss://"):
                p = parse_ss(link)
            elif link.startswith("vmess://"):
                p = parse_vmess(link)
            elif link.startswith("vless://"):
                p = parse_vless(link)
            elif link.startswith("trojan://"):
                p = parse_trojan(link)
            elif link.startswith("hysteria2://"):
                p = parse_hy2(link, "hysteria2")
            elif link.startswith("hy2://"):
                p = parse_hy2(link, "hy2")
            elif link.startswith("socks://"):
                p = parse_socks(link)
            else:
                p = None
        except Exception:
            p = None
        if not p or not p.get("server") or not p.get("port"):
            skipped += 1
            continue
        name = re.sub(r"[\r\n\t]+", " ", frag_name(link)).strip() or "node"
        if name in seen:
            seen[name] += 1
            name = "%s %d" % (name, seen[name])
        else:
            seen[name] = 1
        proxies.append({"name": name, **p})

    if not proxies:
        print("no proxies converted", file=sys.stderr)
        return 2

    names = [p["name"] for p in proxies]
    o = []
    o.append("mixed-port: 7890")
    o.append("allow-lan: false")
    o.append("mode: rule")
    o.append("log-level: info")
    o.append("ipv6: false")
    o.append("external-controller: 127.0.0.1:9090")
    o.append("dns:")
    o.append("  enable: true")
    o.append("  ipv6: false")
    o.append("  enhanced-mode: fake-ip")
    o.append('  fake-ip-range: "198.18.0.1/16"')
    o.append("  nameserver:")
    for ns in ("223.5.5.5", "119.29.29.29", "https://dns.alidns.com/dns-query"):
        o.append("    - %s" % q(ns))
    o.append("  fallback:")
    for ns in ("https://1.1.1.1/dns-query", "https://dns.google/dns-query"):
        o.append("    - %s" % q(ns))
    o.append("proxies:")
    for p in proxies:
        o.append(yaml_proxy(p))
    o.append("proxy-groups:")
    o.append("  - name: %s" % q("🚀 节点选择"))
    o.append("    type: select")
    o.append("    proxies:")
    o.append("      - %s" % q("♻️ 自动选择"))
    o.append("      - %s" % q("DIRECT"))
    for n in names:
        o.append("      - %s" % q(n))
    o.append("  - name: %s" % q("♻️ 自动选择"))
    o.append("    type: url-test")
    o.append("    url: %s" % q("http://www.gstatic.com/generate_204"))
    o.append("    interval: 300")
    o.append("    tolerance: 50")
    o.append("    proxies:")
    for n in names:
        o.append("      - %s" % q(n))
    o.append("rules:")
    o.append("  - %s" % q("GEOIP,LAN,DIRECT,no-resolve"))
    o.append("  - %s" % q("GEOIP,CN,DIRECT"))
    o.append("  - %s" % q("MATCH,🚀 节点选择"))
    body = "\n".join(o) + "\n"
    with open(dst, "w", encoding="utf-8") as f:
        f.write(body)

    kinds = {}
    for p in proxies:
        kinds[p["type"]] = kinds.get(p["type"], 0) + 1
    print(json.dumps({"proxies": len(proxies), "skipped": skipped,
                      "by_type": kinds, "bytes": len(body.encode())},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
