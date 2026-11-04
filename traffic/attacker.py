#!/usr/bin/env python3
"""
Controlled attack traffic for the Mininet lab (never use it outside the lab).

  flood : opens many new TCP connections per second to the server, each one
          downloading data -> uses the 10 Mbit/s link and server threads
  scan  : TCP connect() scan over a list of ports

  h4 python3 traffic/attacker.py flood --rate 100 --duration 5
  h4 python3 traffic/attacker.py scan --ports 1-1024,2222,8080

It records the result of every attempt, so we can see from the attacker's
side when the firewall started dropping its packets ("blocked after").
"""

import argparse
import json
import socket
import threading
import time


def parse_ports(text):
    ports = []
    for part in text.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports += range(int(lo), int(hi) + 1)
        else:
            ports.append(int(part))
    return ports


def flood_attempt(target, port, payload, timeout):
    """One attack connection: connect, ask for `payload` bytes, read them."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"DATA %d\n" % payload)
            stream = s.makefile("rb")
            if not stream.readline().startswith(b"DATA"):
                return "busy"
            stream.read(payload)
            return "ok"
    except socket.timeout:
        return "timeout"          # packets silently dropped = blocked
    except OSError:
        return "error"


def scan_attempt(target, port, timeout):
    try:
        socket.create_connection((target, port), timeout=timeout).close()
        return "open"
    except ConnectionRefusedError:
        return "closed"           # the host answered with a TCP RST
    except OSError:
        return "timeout"          # no answer at all = filtered / blocked


def run_attack(jobs, rate, threads):
    """Run the callables in `jobs` from several threads, `rate` per second."""
    results, lock = [], threading.Lock()
    start = time.time()
    next_job = [0]

    def worker():
        while True:
            with lock:                        # each thread takes the next job
                i = next_job[0]
                next_job[0] += 1
            if i >= len(jobs):
                return
            time.sleep(max(0, start + i / rate - time.time()))   # keep the rate
            t = time.time()
            outcome = jobs[i]()
            with lock:
                results.append({"i": i, "t": round(t, 4), "result": outcome})

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for th in pool:
        th.start()
    for th in pool:
        th.join()
    return start, sorted(results, key=lambda r: r["t"])


def main():
    ap = argparse.ArgumentParser(description="Controlled attack traffic (lab only)")
    ap.add_argument("mode", choices=["flood", "scan"])
    ap.add_argument("--target", default="10.0.0.100")
    ap.add_argument("--port", type=int, default=8080, help="flood: target port")
    ap.add_argument("--rate", type=float, default=None, help="attempts per second")
    ap.add_argument("--duration", type=float, default=5, help="flood: seconds")
    ap.add_argument("--payload", type=int, default=20000, help="flood: bytes per connection")
    ap.add_argument("--ports", default="1-1024,2222,8080", help="scan: port list")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--json", help="save every attempt + summary to this file")
    args = ap.parse_args()

    if args.mode == "flood":
        rate = args.rate or 100
        n = int(rate * args.duration)
        print("[flood] %d connections to %s:%d at %d/s, %d bytes each" % (
            n, args.target, args.port, rate, args.payload), flush=True)
        jobs = [lambda: flood_attempt(args.target, args.port, args.payload, 1.0)] * n
    else:
        rate = args.rate or 200
        ports = parse_ports(args.ports)
        print("[scan] %d ports on %s at %d probes/s" % (len(ports), args.target, rate),
              flush=True)
        jobs = [lambda p=p: scan_attempt(args.target, p, 0.5) for p in ports]

    start, results = run_attack(jobs, rate, args.threads)

    counts = {}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    blocked = [r["t"] for r in results if r["result"] == "timeout"]
    summary = {"mode": args.mode, "start": start, "attempts": len(results),
               "results": counts,
               "blocked_after_ms": round((blocked[0] - start) * 1000) if blocked else None}
    if args.mode == "scan":
        summary["open_ports"] = sorted(ports[r["i"]] for r in results if r["result"] == "open")
        summary["answered"] = counts.get("open", 0) + counts.get("closed", 0)
        print("[scan] open ports found: %s   probes that got an answer: %d" % (
            summary["open_ports"] or "none", summary["answered"]), flush=True)
    print("[%s] SUMMARY %d attempts: %s   first dropped attempt after %s ms" % (
        args.mode, len(results), counts, summary["blocked_after_ms"]), flush=True)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"summary": summary, "records": results}, f)


if __name__ == "__main__":
    main()
