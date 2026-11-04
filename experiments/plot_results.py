#!/usr/bin/env python3
"""
Charts and a results table from results/experiments/summary.json.
With --repeat N, every number is the MEDIAN of the N runs (the middle value):
one disturbed run (VM hiccup, laptop sleep) cannot drag the result away.

    python3 experiments/plot_results.py

  results/experiments/results.md               all numbers as tables
  results/experiments/fig1_normal_users.png    success + latency, static vs dynamic
  results/experiments/fig2_flood_timeline.png  latency over time during the flood (run 1)
  results/experiments/fig3_response_time.png   blocking response time vs attack rate
"""

import json
import os
import statistics
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "experiments")
COLOR = {"dynamic": "#2a78d6", "static": "#eb6834"}
LABEL = {"dynamic": "Dynamic firewall", "static": "Static firewall (baseline)"}
ATTACK = {"none": "No attack", "flood": "Connection flood", "scan": "Port scan"}
FIELDS = ("success_pct", "avg_ms", "goodput_mbps", "attack_ok", "response_ms", "packet_ins")


def mean(values):
    """Median of the repeated runs (robust against one disturbed run)."""
    values = [v for v in values if v is not None]
    return round(statistics.median(values), 2) if values else None


def fmt(value, decimals=1):
    return "-" if value is None else "%.*f" % (decimals, value)


def average_runs(s):
    """(mode, attack) -> median over the repeated runs."""
    groups = defaultdict(list)
    for r in s["comparison"]:
        groups[(r["mode"], r["attack"])].append(r)
    avg = {}
    for key, runs in groups.items():
        avg[key] = {f: mean(r.get(f) for r in runs) for f in FIELDS}
        avg[key]["runs"] = len(runs)
        avg[key]["open_ports"] = runs[0].get("scan_open_ports")
        avg[key]["t0"] = runs[0]["t0"]
        avg[key]["dir"] = runs[0]["run"]
    return avg


def average_sweep(s):
    groups = defaultdict(list)
    for r in s["rate_sweep"]:
        groups[r["rate"]].append(r)
    return [{"rate": rate, "runs": len(rows),
             "detection_ms": mean(r["detection_ms"] for r in rows),
             "install_ms": mean(r["install_ms"] for r in rows),
             "response_ms": mean(r["response_ms"] for r in rows)}
            for rate, rows in sorted(groups.items())]


def write_table(avg, sweep, settings):
    n = settings.get("repeat", 1)
    lines = ["# Results (%s)" % ("median of %d runs each" % n if n > 1 else "1 run each"), "",
             "## Normal users (h1-h3) while the attack runs", "",
             "| Condition | Mode | Success % | Avg latency ms | Goodput Mbit/s | "
             "Attack successes | Blocked after ms | Controller packet-ins |",
             "|---|---|---|---|---|---|---|---|"]
    for attack in ATTACK:
        for mode in ("static", "dynamic"):
            r = avg.get((mode, attack))
            if not r:
                continue
            extra = ""
            if attack == "scan":
                extra = " (open ports found: %s)" % (
                    ", ".join(map(str, r["open_ports"] or [])) or "none")
            lines.append("| %s | %s | %s | %s | %s | %s%s | %s | %s |" % (
                ATTACK[attack], LABEL[mode], fmt(r["success_pct"]), fmt(r["avg_ms"]),
                fmt(r["goodput_mbps"], 2), "-" if attack == "none" else fmt(r["attack_ok"], 0),
                extra, fmt(r["response_ms"]), fmt(r["packet_ins"], 0)))
    lines += ["", "## Blocking response time vs flood rate (dynamic)", "",
              "| Flood rate (conn/s) | Detection ms | Rule install ms | Total response ms |",
              "|---|---|---|---|"]
    for r in sweep:
        lines.append("| %d | %s | %s | %s |" % (r["rate"], fmt(r["detection_ms"]),
                                              fmt(r["install_ms"]), fmt(r["response_ms"])))
    with open(os.path.join(OUT, "results.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def plots(avg, sweep, settings):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False,
                         "axes.grid": True, "grid.color": "#e4e3df", "axes.axisbelow": True,
                         "font.size": 10, "legend.frameon": False})
    attacks = [a for a in ATTACK if ("static", a) in avg]

    # fig 1: success and latency per condition
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, key, title in ((axes[0], "success_pct", "Requests that succeeded (%)"),
                           (axes[1], "avg_ms", "Average latency (ms)")):
        for i, mode in enumerate(("static", "dynamic")):
            xs = [j + (i - 0.5) * 0.38 for j in range(len(attacks))]
            vals = [avg[(mode, a)][key] or 0 for a in attacks]
            bars = ax.bar(xs, vals, 0.36, color=COLOR[mode], label=LABEL[mode])
            for b, v in zip(bars, vals):
                ax.annotate("%.0f" % v, (b.get_x() + b.get_width() / 2, v), xytext=(0, 2),
                            textcoords="offset points", ha="center", fontsize=8)
        ax.set_xticks(range(len(attacks)))
        ax.set_xticklabels([ATTACK[a] for a in attacks])
        ax.set_title(title, loc="left", fontweight="bold")
        ax.grid(axis="x", visible=False)
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center", ncol=2)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(os.path.join(OUT, "fig1_normal_users.png"), dpi=150)

    # fig 2: latency of normal users over time during the flood (first run)
    if ("static", "flood") in avg:
        fig, ax = plt.subplots(figsize=(9, 4))
        for mode in ("static", "dynamic"):
            r = avg[(mode, "flood")]
            buckets = defaultdict(list)
            for h in ("h1", "h2", "h3"):
                with open(os.path.join(OUT, r["dir"], "%s.json" % h)) as f:
                    for rec in json.load(f)["records"]:
                        if rec["ok"]:
                            buckets[int(rec["t"] - r["t0"])].append(rec["latency_ms"])
            xs = sorted(buckets)
            ax.plot([x + 0.5 for x in xs], [statistics.median(buckets[x]) for x in xs],
                    color=COLOR[mode], lw=2, marker="o", ms=3, label=LABEL[mode])
        start, length = settings["attack_at"], settings["attack_sec"]
        ax.axvspan(start, start + length, color="#efeee9", zorder=0)
        ax.text(start + length / 2, 0.95, "flood from h4", ha="center",
                transform=ax.get_xaxis_transform(), color="#52514e")
        ax.set_yscale("log")
        ax.set_xlabel("time (s)")
        ax.set_ylabel("median latency of normal users (ms, log scale)")
        ax.set_title("Normal users during a connection flood", loc="left", fontweight="bold")
        ax.legend(loc="center left")
        fig.tight_layout()
        fig.savefig(os.path.join(OUT, "fig2_flood_timeline.png"), dpi=150)

    # fig 3: response time vs flood rate
    if sweep:
        fig, ax = plt.subplots(figsize=(7, 4))
        xs = range(len(sweep))
        det = [r["detection_ms"] for r in sweep]
        ins = [r["install_ms"] for r in sweep]
        ax.bar(xs, det, 0.6, color="#2a78d6", label="detection (collecting evidence)")
        ax.bar(xs, ins, 0.6, bottom=det, color="#86b6ef", label="rule installation")
        for x, r in zip(xs, sweep):
            ax.annotate("%.0f ms" % r["response_ms"], (x, r["response_ms"]), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=8)
        ax.set_xticks(list(xs))
        ax.set_xticklabels([str(r["rate"]) for r in sweep])
        ax.set_xlabel("flood rate (new TCP connections per second)")
        ax.set_ylabel("blocking response time (ms)")
        ax.set_title("Blocking response time vs attack rate", loc="left", fontweight="bold")
        ax.legend()
        ax.grid(axis="x", visible=False)
        fig.tight_layout()
        fig.savefig(os.path.join(OUT, "fig3_response_time.png"), dpi=150)
    print("\ncharts saved in results/experiments/")


def main():
    with open(os.path.join(OUT, "summary.json")) as f:
        s = json.load(f)
    avg, sweep = average_runs(s), average_sweep(s)
    write_table(avg, sweep, s["settings"])
    try:
        plots(avg, sweep, s["settings"])
    except ImportError:
        print("matplotlib missing: sudo apt install python3-matplotlib")


if __name__ == "__main__":
    main()
