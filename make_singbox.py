#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nodes.txt -> sing-box JSON (1.10 ~ 1.12 兼容)"""
import argparse, json, sys
import make_clash as mc


def _sni(p):
    h = (p.get("ws-opts") or {}).get("headers") or {}
    for k, v in h.items():
        if k.lower() == "host":
            return str(v).split(",")[0].strip()
    return p.get("servername") or p.get("sni") or ""


def transport_of(p):
    net = (p.get("network") or "tcp").lower()
    if net == "ws":
        o = p.get("ws-opts") or {}
        t = {"type": "ws", "path": o.get("path") or "/"}
        h = o.get("headers") or {}
        if h:
            t["headers"] = {str(k): str(v) for k, v in h.items()}
        return t
    if net == "grpc":
        g = p.get("grpc-opts") or {}
        return {"type": "grpc", "service_name": g.get("grpc-service-name") or ""}
    if net in ("h2", "http"):
        h = p.get("h2-opts") or {}
        t = {"type": "http", "path": h.get("path") or "/"}
        host = h.get("host")
        if host:
            t["host"] = host if isinstance(host, list) else [str(host)]
        return t
    return None


def tls_of(p, server):
    ro = p.get("reality-opts")
    if not (p.get("tls") or ro):
        return None
    t = {"enabled": True}
    sni = _sni(p) or server
    if sni:
        t["server_name"] = sni
    if p.get("skip-cert-verify"):
        t["insecure"] = True
    alpn = p.get("alpn")
    if alpn:
        t["alpn"] = alpn if isinstance(alpn, list) else [str(alpn)]
    fp = p.get("client-fingerprint")
    if ro:
        t["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
        t["reality"] = {
            "enabled": True,
            "public_key": ro.get("public-key") or "",
            "short_id": ro.get("short-id") or "",
        }
    elif fp:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    return t


def to_outbound(p):
    typ = p.get("type")
    name, server, port = p.get("name"), p.get("server"), p.get("port")
    if not server or not port:
        return None
    base = {"tag": name, "server": str(server), "server_port": int(port)}

    if typ == "ss":
        o = {"type": "shadowsocks"}
        o.update(base)
        o["method"] = p.get("cipher") or "aes-128-gcm"
        o["password"] = p.get("password") or ""
        pl = p.get("plugin")
        if pl:
            opts = p.get("plugin-opts") or {}
            if pl == "obfs":
                o["plugin"] = "obfs-local"
                s = "obfs=%s" % (opts.get("mode") or "http")
                if opts.get("host"):
                    s += ";obfs-host=%s" % opts["host"]
                o["plugin_opts"] = s
            elif pl == "v2ray-plugin":
                o["plugin"] = "v2ray-plugin"
                s = "mode=websocket"
                if opts.get("host"):
                    s += ";host=%s" % opts["host"]
                s += ";path=%s" % (opts.get("path") or "/")
                if opts.get("tls"):
                    s += ";tls"
                o["plugin_opts"] = s
            else:
                o["plugin"] = str(pl)
        return o

    if typ == "vmess":
        o = {"type": "vmess"}
        o.update(base)
        o["uuid"] = p.get("uuid") or ""
        o["security"] = p.get("cipher") or "auto"
        o["alter_id"] = int(p.get("alterId") or 0)
        tr = transport_of(p)
        if tr:
            o["transport"] = tr
        t = tls_of(p, server)
        if t:
            o["tls"] = t
        return o

    if typ == "vless":
        o = {"type": "vless"}
        o.update(base)
        o["uuid"] = p.get("uuid") or ""
        if p.get("flow"):
            o["flow"] = p["flow"]
        o["packet_encoding"] = "xudp"
        tr = transport_of(p)
        if tr:
            o["transport"] = tr
        t = tls_of(p, server)
        if t:
            o["tls"] = t
        return o

    if typ == "trojan":
        o = {"type": "trojan"}
        o.update(base)
        o["password"] = p.get("password") or ""
        tr = transport_of(p)
        if tr:
            o["transport"] = tr
        t = tls_of(p, server) or {"enabled": True, "server_name": _sni(p) or str(server)}
        o["tls"] = t
        return o

    if typ == "hysteria2":
        o = {"type": "hysteria2"}
        o.update(base)
        o["password"] = p.get("password") or ""
        if p.get("up"):
            o["up_mbps"] = int(p["up"])
        if p.get("down"):
            o["down_mbps"] = int(p["down"])
        if p.get("obfs"):
            o["obfs"] = {"type": str(p["obfs"]), "password": p.get("obfs-password") or ""}
        t = tls_of(p, server) or {"enabled": True, "server_name": _sni(p) or str(server)}
        t.pop("utls", None)
        t.pop("reality", None)
        o["tls"] = t
        return o

    return None


def build(links):
    import re as _re
    out, skipped, seen = [], 0, {}
    for link in links:
        try:
            if link.startswith("ss://"):
                p = mc.parse_ss(link)
            elif link.startswith("vmess://"):
                p = mc.parse_vmess(link)
            elif link.startswith("vless://"):
                p = mc.parse_vless(link)
            elif link.startswith("trojan://"):
                p = mc.parse_trojan(link)
            elif link.startswith("hysteria2://"):
                p = mc.parse_hy2(link, "hysteria2")
            elif link.startswith("hy2://"):
                p = mc.parse_hy2(link, "hy2")
            else:
                skipped += 1
                continue
            o = to_outbound(p) if p else None
        except Exception:
            o = None
        if o and o.get("type"):
            nm = _re.sub(r"[\r\n\t]+", " ", mc.frag_name(link)).strip() or "node"
            if nm in seen:
                seen[nm] += 1
                nm = "%s %d" % (nm, seen[nm])
            else:
                seen[nm] = 1
            o["tag"] = nm
            out.append(o)
        else:
            skipped += 1

    tags = [o["tag"] for o in out]
    sel_tag, auto_tag = "🚀 节点选择", "♻️ 自动选择"
    used = set(tags)
    for t in (sel_tag, auto_tag, "direct"):
        if t in used:
            sel_tag = sel_tag + " A"; auto_tag = auto_tag + " A"

    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "local", "address": "https://dns.alidns.com/dns-query", "detour": "direct"},
                {"tag": "local2", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": sel_tag},
            ],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
            {"type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30",
             "auto_route": True, "strict_route": True, "stack": "mixed", "sniff": True},
        ],
        "outbounds": [
            {"type": "selector", "tag": sel_tag, "outbounds": [auto_tag, "direct"] + tags,
             "default": auto_tag},
            {"type": "urltest", "tag": auto_tag, "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204",
             "interval": "10m", "tolerance": 50},
        ] + out + [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": [".cn","baidu.com","bdstatic.com","qq.com","qpic.cn","gtimg.cn","tencent.com","weixin.qq.com","taobao.com","tmall.com","alipay.com","alicdn.com","aliyun.com","aliyuncs.com","alipayobjects.com","jd.com","360buyimg.com","sina.com.cn","sinaimg.cn","weibo.com","weibo.cn","bilibili.com","hdslb.com","zhihu.com","zhimg.com","douban.com","iqiyi.com","youku.com","netease.com","163.com","126.net","xiaomi.com","mi.com","huawei.com","hicloud.com","meituan.com","dianping.com","ctrip.com","pinduoduo.com","yangkeduo.com","kuaishou.com","douyin.com","bytedance.com","toutiao.com","ixigua.com","csdn.net","gitee.com","cnblogs.com","jianshu.com","amap.com","58.com","sohu.com","ifeng.com","people.com.cn","xinhuanet.com","12306.cn","cmbchina.com","icbc.com.cn","ccb.com","abchina.com","unionpay.com","alibaba.com","1688.com","wps.cn","kingsoft.com","quark.cn","uc.cn"], "outbound": "direct"},
            ],
            "final": sel_tag,
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {"enabled": True},
            "clash_api": {"external_controller": "127.0.0.1:9090"},
        },
    }
    return cfg, len(out), skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    a = ap.parse_args()
    links = [l.strip() for l in open(a.src, encoding="utf-8") if l.strip()]
    cfg, n, sk = build(links)
    with open(a.dst, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    print(json.dumps({"outbounds": n, "skipped": sk,
                      "bytes": os.path.getsize(a.dst)}, ensure_ascii=False))


import os
if __name__ == "__main__":
    sys.exit(main())
