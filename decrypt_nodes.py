#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v2cross / Shadowrocket 内置节点提取器（纯标准库）

官方 ecfg 文件 = AES-128-CBC(key=IV=d3JV8tcWGPzgcVbB) + Base64 的协议链接列表。
输出: nodes.txt（一行一条分享链接，可直接作为 v2rayNG 订阅）
"""
import argparse, base64, hashlib, json, os, re, sys, urllib.request

KEY = b"d3JV8tcWGPzgcVbB"
BASE = "/data/"
HOSTS = [
    "https://cdn.shadowrockets.app/ecfg",
    "https://files.shadowrockets.app/ecfg",
    "https://raw.githubusercontent.com/pixelor/ecfg/refs/heads/main",
    "https://cdn.jsdelivr.net/gh/pixelor/ecfg@main",
]
LANGS = ["ecfg6", "ecfg6_zh", "ecfg6_en", "ecfg6_es", "ecfg6_de",
         "ecfg6_fr", "ecfg6_ja", "ecfg6_pt", "ecfg6_ru"]
SCHEMES = ("ss://", "vmess://", "vless://", "trojan://", "hysteria2://",
           "hy2://", "tuic://", "wireguard://", "socks://")

SBOX = bytes([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])
INV = bytearray(256)
for _i, _v in enumerate(SBOX):
    INV[_v] = _i
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a

def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xff

M9  = [_mul(i, 9)  for i in range(256)]
M11 = [_mul(i, 11) for i in range(256)]
M13 = [_mul(i, 13) for i in range(256)]
M14 = [_mul(i, 14) for i in range(256)]

def expand_key(key):
    w = list(key)
    for i in range(4, 44):
        t = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % 4 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 4 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        for j in range(4):
            w.append(w[(i - 4) * 4 + j] ^ t[j])
    return w

def _dec_block(blk, w):
    s = list(blk)
    for i in range(16):
        s[i] ^= w[160 + i]
    for rnd in range(9, 0, -1):
        t = list(s)
        for r in range(4):
            for c in range(4):
                s[r + 4 * c] = t[r + 4 * ((c - r) % 4)]
        s = [INV[b] for b in s]
        for i in range(16):
            s[i] ^= w[rnd * 16 + i]
        for c in range(4):
            a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
            s[4*c]   = M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3]
            s[4*c+1] = M9[a0]  ^ M14[a1] ^ M11[a2] ^ M13[a3]
            s[4*c+2] = M13[a0] ^ M9[a1]  ^ M14[a2] ^ M11[a3]
            s[4*c+3] = M11[a0] ^ M13[a1] ^ M9[a2]  ^ M14[a3]
    t = list(s)
    for r in range(4):
        for c in range(4):
            s[r + 4 * c] = t[r + 4 * ((c - r) % 4)]
    s = [INV[b] for b in s]
    for i in range(16):
        s[i] ^= w[i]
    return bytes(s)

def aes_cbc_decrypt(ct, key=KEY, iv=None):
    iv = iv or key
    w = expand_key(key)
    out = bytearray(len(ct))
    prev = iv
    for o in range(0, len(ct), 16):
        blk = ct[o:o + 16]
        dec = _dec_block(blk, w)
        for i in range(16):
            out[o + i] = dec[i] ^ prev[i]
        prev = blk
    pad = out[-1] if out else 0
    if 1 <= pad <= 16:
        out = out[:-pad]
    return bytes(out)

def decrypt_b64(text):
    s = re.sub(r"\s+", "", text)
    if not s or len(s) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        raise ValueError("not valid base64")
    raw = base64.b64decode(s)
    if len(raw) % 16:
        raise ValueError("ciphertext length not multiple of 16")
    return aes_cbc_decrypt(raw).decode("utf-8", "replace")

def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace"), r.headers.get("Last-Modified")

def fetch_one(name):
    errs = []
    for host in HOSTS:
        url = host + BASE + name
        try:
            print("  fetch", url, flush=True)
            txt, lm = http_get(url)
            if len(txt) > 100:
                return txt, url, lm
            errs.append(url + " too short")
        except Exception as e:
            errs.append(f"{url} {type(e).__name__}: {e}")
    raise RuntimeError("all sources failed:\n  " + "\n  ".join(errs))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", default="default")
    ap.add_argument("--out", default="nodes.txt")
    ap.add_argument("--split", action="store_true")
    args = ap.parse_args()

    if args.lang == "default":
        names = ["ecfg6", "ecfg6_zh"]
    elif args.lang == "all":
        names = LANGS
    else:
        names = [args.lang]

    all_lines, seen, last_lm = [], set(), None
    for n in names:
        try:
            txt, url, lm = fetch_one(n)
            plain = decrypt_b64(txt)
            lines = [l.strip() for l in plain.splitlines() if l.strip()]
            lines = [l for l in lines if l.startswith(SCHEMES)]
            new = [l for l in lines if l not in seen]
            seen.update(new)
            all_lines.extend(new)
            last_lm = lm or last_lm
            print(f"  OK {n}: {len(lines)} nodes (new {len(new)}) LM={lm}", flush=True)
        except Exception as e:
            print(f"  FAIL {n}: {e}", flush=True)

    if not all_lines:
        print("no nodes", file=sys.stderr)
        return 2

    body = "\n".join(all_lines) + "\n"
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(body)

    if args.split:
        groups = {}
        for l in all_lines:
            groups.setdefault(l.split("://")[0], []).append(l)
        base = os.path.splitext(args.out)[0]
        for k, v in groups.items():
            with open(f"{base}_{k}_{len(v)}.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(v) + "\n")

    counts = {}
    for l in all_lines:
        k = l.split("://")[0]
        counts[k] = counts.get(k, 0) + 1
    print(json.dumps({
        "nodes": len(all_lines), "by_protocol": counts,
        "sha256_16": hashlib.sha256(body.encode()).hexdigest()[:16],
        "last_modified": last_lm,
    }, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
