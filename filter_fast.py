#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按 TCP 握手延迟过滤节点（默认 <=500ms），输出按延迟升序的链接列表"""
import argparse, asyncio, json, sys, time
import make_clash as mc


def endpoint(link):
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
        elif link.startswith("socks://"):
            p = mc.parse_socks(link)
        else:
            return None
    except Exception:
        return None
    if not p:
        return None
    h, port = p.get("server"), p.get("port")
    if not h or not port:
        return None
    try:
        return str(h), int(port)
    except Exception:
        return None


async def probe(host, port, timeout, sem):
    async with sem:
        t0 = time.monotonic()
        writer = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port), timeout)
            return (time.monotonic() - t0) * 1000.0
        except Exception:
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass


async def amain(links, timeout, workers, max_ms):
    sem = asyncio.Semaphore(workers)
    jobs = []
    for l in links:
        ep = endpoint(l)
        if ep is None:
            jobs.append(asyncio.sleep(0, result=None))
        else:
            jobs.append(probe(ep[0], ep[1], timeout, sem))
    results = await asyncio.gather(*jobs)
    ok = []
    for l, ms in zip(links, results):
        if ms is not None and ms <= max_ms:
            ok.append((ms, l))
    ok.sort(key=lambda x: x[0])
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--max-ms", type=int, default=500)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--workers", type=int, default=300)
    args = ap.parse_args()

    links = [l.strip() for l in open(args.src, encoding="utf-8") if l.strip()]
    t0 = time.time()
    ok = asyncio.run(amain(links, args.timeout, args.workers, args.max_ms))
    if not ok:
        print("no node passed the filter", file=sys.stderr)
        return 2
    with open(args.dst, "w", encoding="utf-8") as f:
        for _ms, l in ok:
            f.write(l + "\n")
    lat = [ms for ms, _ in ok]
    print(json.dumps({
        "input": len(links), "passed": len(ok), "max_ms": args.max_ms,
        "min_ms": round(lat[0], 1), "p50_ms": round(lat[len(lat) // 2], 1),
        "p90_ms": round(lat[int(len(lat) * 0.9)], 1),
        "elapsed_s": round(time.time() - t0, 1),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
