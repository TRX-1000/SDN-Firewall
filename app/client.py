#!/usr/bin/env python3
"""
TCP client - sends requests to the server and measures the response time.

  h2 python3 app/client.py --count 5                       5 PINGs
  h2 python3 app/client.py --count 3 --request "DATA 1000000"   bulk data
  h1 python3 app/client.py --port 2222 --count 1 --request STATS  admin port
  h2 python3 app/client.py --count 8 --parallel 4 --rate 1   4 clients at once
     (keep the TOTAL below 5 new connections/s per host, or the firewall
      will - correctly - treat it as a flood)
  h2 python3 app/client.py --duration 30 --rate 4 --json results/h2.json

Every request opens a NEW TCP connection (connect, request, QUIT).  Each
one is therefore a new flow that the SDN controller has to classify, and
the measured latency includes that work.
"""

import argparse
import json
import socket
import statistics
import threading
import time


def one_request(server, port, request, timeout):
    """Connect, send one request, read the full reply.  Returns
    (ok, latency_ms, bytes_received, error)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            stream = sock.makefile("rb")
            sock.sendall((request + "\n").encode())
            reply = stream.readline().decode().strip()
            if not reply or reply.startswith("ERR"):
                return False, ms_since(start), 0, reply or "closed"
            received = 0
            if reply.startswith("DATA "):                       # read n raw bytes
                n = int(reply.split()[1])
                while received < n:
                    chunk = stream.read(min(65536, n - received))
                    if not chunk:
                        return False, ms_since(start), received, "short read"
                    received += len(chunk)
            sock.sendall(b"QUIT\n")
            return True, ms_since(start), received, None
    except socket.timeout:
        return False, ms_since(start), 0, "timeout"
    except OSError as exc:
        return False, ms_since(start), 0, type(exc).__name__


def ms_since(start):
    return round((time.perf_counter() - start) * 1000, 2)


def run(args, name, quiet):
    """Send requests at a fixed rate; return the list of results."""
    records = []
    start = time.time()
    i = 0
    while (args.count and i < args.count) or (args.duration and time.time() - start < args.duration):
        next_time = start + i / args.rate
        time.sleep(max(0, next_time - time.time()))
        i += 1
        ok, latency, nbytes, error = one_request(args.server, args.port, args.request,
                                                 args.timeout)
        records.append({"t": round(time.time(), 3), "ok": ok, "latency_ms": latency,
                        "bytes": nbytes, "error": error})
        if not quiet:
            print("[%s] #%-3d %s %8.2f ms %s" % (name, i, "ok  " if ok else "FAIL", latency,
                                                ("%d bytes" % nbytes) if nbytes else (error or "")),
                  flush=True)
    return records


def summary(records):
    lat = [r["latency_ms"] for r in records if r["ok"]]
    total_bytes = sum(r["bytes"] for r in records if r["ok"])
    busy_sec = sum(lat) / 1000
    return {"requests": len(records), "ok": len(lat),
            "success_pct": round(100 * len(lat) / len(records), 1) if records else 0,
            "avg_ms": round(statistics.mean(lat), 2) if lat else None,
            "max_ms": round(max(lat), 2) if lat else None,
            "mbit_per_s": round(total_bytes * 8 / busy_sec / 1e6, 2) if total_bytes else None}


def main():
    ap = argparse.ArgumentParser(description="TCP client")
    ap.add_argument("--server", default="10.0.0.100")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--request", default="PING")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0)
    ap.add_argument("--rate", type=float, default=2, help="requests per second")
    ap.add_argument("--timeout", type=float, default=2)
    ap.add_argument("--parallel", type=int, default=1, help="number of clients at once")
    ap.add_argument("--json", help="save every request + summary to this file")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    if not args.count and not args.duration:
        args.count = 5

    results = {}

    def client(n):
        results[n] = run(args, "client-%d" % n if args.parallel > 1 else "client",
                         args.quiet or args.parallel > 1)

    threads = [threading.Thread(target=client, args=(n,)) for n in range(1, args.parallel + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for n in sorted(results):
        s = summary(results[n])
        print("[client%s] SUMMARY %d/%d ok (%.1f%%)  avg %s ms  max %s ms%s" % (
            "-%d" % n if args.parallel > 1 else "", s["ok"], s["requests"],
            s["success_pct"], s["avg_ms"], s["max_ms"],
            ("  %s Mbit/s" % s["mbit_per_s"]) if s["mbit_per_s"] else ""), flush=True)
    if args.json:
        records = [r for n in sorted(results) for r in results[n]]
        with open(args.json, "w") as f:
            json.dump({"summary": summary(records), "records": records}, f)


if __name__ == "__main__":
    main()
