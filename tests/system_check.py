#!/usr/bin/env python3
"""
End-to-end test in Mininet - checks every requirement automatically.

    ./scripts/cleanup.sh               (nothing else may be running)
    sudo python3 tests/system_check.py

Starts its own logger + POX (dynamic mode, 8 s blocks so it is quick) +
Mininet, runs 12 scenarios and prints PASS/FAIL.  Takes about 1.5 minutes.
Report: results/system_check/report.md
"""

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from topology.lab import Lab  # noqa: E402
from topology.topo import give_back  # noqa: E402

OUT = os.path.join(ROOT, "results", "system_check")
BLOCK = 8
results = []


def check(name, ok, detail):
    results.append((name, bool(ok), detail))
    print("[%s] %s - %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def client(lab, host, *args):
    out = os.path.join(OUT, "client_%s_%d.json" % (host, len(results)))
    lab.run(host, lab.py("app/client.py", "--quiet", "--json", out, *args))
    with open(out) as f:
        return json.load(f)["summary"]


def attack(lab, host, *args):
    out = os.path.join(OUT, "attack_%s_%d.json" % (host, len(results)))
    lab.run(host, lab.py("traffic/attacker.py", *args, "--json", out))
    with open(out) as f:
        return json.load(f)["summary"]


def events(lab, etype, ip=None):
    return [e for e in lab.events() if e["type"] == etype and (ip is None or e.get("src") == ip)]


def scenarios(lab):
    loss = lab.net.pingAll(timeout=1)
    check("Mininet connectivity", loss == 0, "pingall loss %s%%" % loss)
    time.sleep(1)
    check("Controller -> logger over TCP", events(lab, "SWITCH_CONNECTED"),
          "%d SWITCH_CONNECTED events in the central log" % len(events(lab, "SWITCH_CONNECTED")))

    jobs = {h: lab.start(h, lab.py("app/client.py", "--quiet", "--count", 10, "--rate", 4,
                                   "--json", os.path.join(OUT, "multi_%s.json" % h)))
            for h in ("h1", "h2", "h3")}
    for p in jobs.values():
        p.wait(60)
    oks = {}
    for h in jobs:
        with open(os.path.join(OUT, "multi_%s.json" % h)) as f:
            oks[h] = json.load(f)["summary"]["ok"]
    check("3 clients on 3 hosts at the same time", sum(oks.values()) == 30,
          " ".join("%s:%d/10" % kv for kv in sorted(oks.items())))

    s = client(lab, "h3", "--count", 3, "--rate", 5, "--request", "DATA 500000")
    check("Bulk transfer DATA 500 kB", s["ok"] == 3, "%s Mbit/s" % s["mbit_per_s"])

    a = client(lab, "h1", "--count", 1, "--port", 2222, "--request", "STATS")
    b = client(lab, "h2", "--count", 1, "--port", 2222, "--request", "STATS", "--timeout", 1)
    check("Classification by source: admin port 2222", a["ok"] == 1 and b["ok"] == 0,
          "h1 allowed (R1): %s, h2 denied (R2): %s" % (a["ok"] == 1, b["ok"] == 0))
    time.sleep(0.5)
    check("DENY events reach the logger", events(lab, "DENY", "10.0.0.2"),
          "%d DENY events for h2" % len(events(lab, "DENY", "10.0.0.2")))

    f = attack(lab, "h4", "flood", "--rate", 100, "--duration", 2, "--payload", 5000)
    time.sleep(0.5)
    enf = events(lab, "BLOCK_ENFORCED", "10.0.0.4")
    check("Flood detected and blocked", enf and enf[0]["reason"] == "CONN_FLOOD",
          "response %s ms (detection %s + install %s); attacker: %s" % (
              enf[0]["response_ms"] if enf else "-", enf[0]["detection_ms"] if enf else "-",
              enf[0]["install_ms"] if enf else "-", f["results"]))

    s = client(lab, "h2", "--count", 5, "--rate", 5)
    cut_off = "0 received" in lab.net.get("h4").cmd("ping -c 2 -W 1 10.0.0.100")
    check("Attacker cut off, others unaffected", cut_off and s["ok"] == 5,
          "h4 ping blocked: %s, h2 %d/5 ok" % (cut_off, s["ok"]))

    deadline = time.time() + BLOCK + 10            # wait until every block has expired
    while (len(events(lab, "UNBLOCK", "10.0.0.4")) < len(events(lab, "BLOCK", "10.0.0.4"))
           and time.time() < deadline):
        time.sleep(0.5)
    time.sleep(1)
    s = client(lab, "h4", "--count", 3, "--rate", 5)
    unb = events(lab, "UNBLOCK", "10.0.0.4")
    check("Automatic recovery after %ds" % BLOCK, unb and s["ok"] == 3,
          "UNBLOCK after %s s, %s packets dropped; h4 %d/3 ok" % (
              unb[0]["blocked_seconds"] if unb else "-",
              unb[0]["dropped_packets"] if unb else "-", s["ok"]))

    attack(lab, "h4", "flood", "--rate", 100, "--duration", 1, "--payload", 1000)
    time.sleep(0.5)
    blocks = events(lab, "BLOCK", "10.0.0.4")
    check("Repeat offender is blocked longer", len(blocks) >= 2 and
          blocks[-1]["offence"] == 2 and blocks[-1]["block_seconds"] == 2 * BLOCK,
          "block durations for h4: %s s" % [b["block_seconds"] for b in blocks])

    client(lab, "h2", "--count", 6, "--rate", 2, "--port", 2222, "--timeout", 1)
    time.sleep(0.5)
    b = events(lab, "BLOCK", "10.0.0.2")
    s = client(lab, "h2", "--count", 1, "--timeout", 1)
    check("Repeated denied access -> whole host blocked", b and
          b[0]["reason"] == "POLICY_VIOLATION" and s["ok"] == 0,
          "%s after %s denied attempts; h2 -> port 8080 now: %s" % (
              b[0]["reason"] if b else "no block", b[0]["evidence"] if b else "-",
              "blocked" if s["ok"] == 0 else "still allowed"))

    sc = attack(lab, "h3", "scan", "--ports", "1-200,2222,8080")
    time.sleep(0.5)
    enf = events(lab, "BLOCK_ENFORCED", "10.0.0.3")
    check("Port scan detected and blocked", enf and enf[0]["reason"] == "PORT_SCAN",
          "response %s ms; scanner found open ports %s, got %d answers out of %d" % (
              enf[0]["response_ms"] if enf else "-", sc["open_ports"] or "none",
              sc["answered"], sc["attempts"]))


def main():
    if os.geteuid() != 0:
        sys.exit("run with sudo: sudo python3 tests/system_check.py")
    os.makedirs(OUT, exist_ok=True)
    print("Starting logger + controller + Mininet (block time %ds) ..." % BLOCK, flush=True)
    lab = Lab("dynamic", OUT, block_seconds=BLOCK)
    try:
        scenarios(lab)
    finally:
        lab.stop()
    passed = sum(ok for _, ok, _ in results)
    lines = ["# System check: %d / %d passed (%s)" % (passed, len(results), time.ctime()), "",
             "| Test | Result | Details |", "|---|---|---|"]
    lines += ["| %s | %s | %s |" % (n, "PASS" if ok else "FAIL", d) for n, ok, d in results]
    with open(os.path.join(OUT, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    give_back(os.path.join(ROOT, "results"))
    print("\n%d / %d passed - report: results/system_check/report.md" % (passed, len(results)))
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
