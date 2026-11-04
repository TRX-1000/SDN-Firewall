#!/usr/bin/env python3
"""
Performance evaluation: dynamic firewall vs the static (baseline) firewall.

    ./scripts/cleanup.sh
    sudo python3 experiments/run_experiments.py              (1 run each, ~6 min)
    sudo python3 experiments/run_experiments.py --repeat 3   (for the report, ~18 min)
    python3 experiments/plot_results.py                      (charts + table, averages)

Part 1 - comparison.  For each mode (static, dynamic) and each condition
  (no attack, connection flood, port scan) a fresh network is started.
  h1-h3 download 20 kB four times a second for 25 s (normal users);
  h4 attacks from t=5 s to t=20 s.  We measure the normal users' success
  rate, latency and goodput while the attack is running, how much of
  the attack got through, and the controller load (packet-ins).

Part 2 - blocking response time vs attack rate (dynamic mode).
  h4 floods at 10, 25, 50, 100, 200 new connections/s; we record detection
  time, rule installation time and total response time from blocks.csv.
"""

import argparse
import csv
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from topology.lab import Lab  # noqa: E402
from topology.topo import give_back  # noqa: E402

OUT = os.path.join(ROOT, "results", "experiments")
RUN_SEC, ATTACK_AT, ATTACK_SEC = 25, 5, 15
ATTACKS = {
    "none": None,
    "flood": ["flood", "--rate", 150, "--duration", ATTACK_SEC, "--payload", 50000],
    "scan": ["scan", "--ports", "1-1024,2222,8080", "--rate", 100],
}


def read_json(path):
    with open(path) as f:
        return json.load(f)


def read_blocks(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def comparison_run(mode, attack, rep):
    name = "%s_%s_r%d" % (mode, attack, rep)
    out = os.path.join(OUT, name)
    print("\n=== mode=%s attack=%s run=%d ===" % (mode, attack, rep), flush=True)
    lab = Lab(mode, out, block_seconds=60)            # stays blocked for the whole run
    try:
        t0 = time.time()
        users = [lab.start(h, lab.py("app/client.py", "--quiet", "--duration", RUN_SEC,
                                     "--rate", 4, "--request", "DATA 20000",
                                     "--json", os.path.join(out, "%s.json" % h)))
                 for h in ("h1", "h2", "h3")]
        attacker = None
        if ATTACKS[attack]:
            time.sleep(ATTACK_AT)
            attacker = lab.start("h4", lab.py("traffic/attacker.py", *ATTACKS[attack],
                                              "--json", os.path.join(out, "attacker.json")))
        for p in users:
            p.wait(RUN_SEC + 60)
        if attacker:
            attacker.wait(120)
    finally:
        lab.stop()

    # only look at the normal users' requests made while the attack was running
    start, end = t0 + ATTACK_AT, t0 + ATTACK_AT + ATTACK_SEC
    records = [r for h in ("h1", "h2", "h3")
               for r in read_json(os.path.join(out, "%s.json" % h))["records"]
               if start <= r["t"] < end]
    ok = [r for r in records if r["ok"]]
    result = {"mode": mode, "attack": attack, "rep": rep, "run": name, "t0": t0,
              "success_pct": round(100 * len(ok) / len(records), 1) if records else None,
              "avg_ms": round(sum(r["latency_ms"] for r in ok) / len(ok), 1) if ok else None,
              "goodput_mbps": round(sum(r["bytes"] for r in ok) * 8 / ATTACK_SEC / 1e6, 2)}
    if attacker:
        a = read_json(os.path.join(out, "attacker.json"))["summary"]
        result["attack_ok"] = a["results"].get("ok", 0) + a["results"].get("open", 0)
        result["attack_attempts"] = a["attempts"]
        result["scan_answered"] = a.get("answered")
        result["scan_open_ports"] = a.get("open_ports")
    blocks = read_blocks(os.path.join(out, "blocks.csv"))
    result["response_ms"] = float(blocks[0]["response_ms"]) if blocks else None
    result["packet_ins"] = read_json(os.path.join(out, "controller_stats.json"))["packet_ins"]
    print("  normal users: %s%% ok, avg %s ms, goodput %s Mbit/s | attack successes: %s | "
          "blocked after: %s ms | packet-ins: %d" % (
              result["success_pct"], result["avg_ms"], result["goodput_mbps"],
              result.get("attack_ok", "-"), result["response_ms"] or "-",
              result["packet_ins"]), flush=True)
    return result


def rate_sweep(repeat):
    out = os.path.join(OUT, "rate_sweep")
    print("\n=== blocking response time vs flood rate ===", flush=True)
    lab = Lab("dynamic", out, block_seconds=3, max_block_seconds=3)   # no escalation here
    rows = []
    try:
        for rate in [r for _ in range(repeat) for r in (10, 25, 50, 100, 200)]:
            before = len(read_blocks(os.path.join(out, "blocks.csv")))
            lab.run("h4", lab.py("traffic/attacker.py", "flood", "--rate", rate,
                                 "--duration", 4, "--payload", 1000))
            new = read_blocks(os.path.join(out, "blocks.csv"))[before:]
            if new:
                b = new[0]
                rows.append({"rate": rate, "detection_ms": float(b["detection_ms"]),
                             "install_ms": float(b["install_ms"]),
                             "response_ms": float(b["response_ms"])})
                print("  %4d conn/s: detection %s ms + install %s ms = %s ms" % (
                    rate, b["detection_ms"], b["install_ms"], b["response_ms"]), flush=True)
            time.sleep(9)                    # block (3 s) expires + detection window empties
    finally:
        lab.stop()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=1, help="runs per test (report: 3)")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo: sudo python3 experiments/run_experiments.py")
    os.makedirs(OUT, exist_ok=True)
    runs = []
    for rep in range(1, args.repeat + 1):
        for i, attack in enumerate(ATTACKS):
            # alternate which mode goes first, so neither always gets the "fresh" slot
            order = ("static", "dynamic") if (rep + i) % 2 else ("dynamic", "static")
            runs += [comparison_run(mode, attack, rep) for mode in order]
    summary = {"comparison": runs,
               "rate_sweep": rate_sweep(args.repeat),
               "settings": {"run_sec": RUN_SEC, "attack_at": ATTACK_AT,
                            "attack_sec": ATTACK_SEC, "repeat": args.repeat}}
    with open(os.path.join(OUT, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    give_back(os.path.join(ROOT, "results"))
    print("\nSaved results/experiments/summary.json - now run: python3 experiments/plot_results.py")


if __name__ == "__main__":
    main()
