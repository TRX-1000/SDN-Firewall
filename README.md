# Dynamic SDN Firewall with Security-Event Logger

**Computer Networks: SDN + socket programming mini project, Problem 1 (TCP)**

A POX SDN controller acts as a firewall for a Mininet network. It does three things:

* It **classifies** every new TCP connection by source IP, destination IP and
  port, using a small rule table, and allows or denies it.
* It **automatically blocks** a host that floods the server with connections,
  scans its ports, or keeps trying connections the rules deny. The switch
  lifts the block by itself after 20 s (**automatic recovery**). Repeat
  offenders get longer blocks: 40 s, 80 s, and so on.
* It reports every security event over TCP to a **centralized logger**.

We measure the **blocking response time** and the **impact on normal users**,
and compare the result with a static firewall.

| Requirement | Where |
|---|---|
| TCP client/server communication | `app/server.py`, `app/client.py` |
| Classify traffic by source, destination, port | `controller/rules.py` → `Policy`, used in `controller/firewall.py` → `check_tcp()` |
| Dynamic firewall rules via the SDN controller | `controller/firewall.py` → `install_drop()`, `block()` |
| Centralized security-event logger | `app/logger_server.py` (TCP 9999) ← `EventSender` in the controller |
| Multiple clients | thread per client in `app/server.py`; `--parallel`; h1–h3 at once |
| Automatic blocking and recovery | `rules.py` → `Detector`; drop rule with `hard_timeout` (doubles for repeat offenders); `FlowRemoved` → UNBLOCK |
| Blocking response time and network impact | barrier timing in `firewall.py` → `results/blocks.csv`; packet-in counter; `experiments/` |

The code is about 1,000 lines, plus tests and experiments. **`docs/CODE_WALKTHROUGH.md`**
explains every file and lists likely viva questions with answers.

---

## Quick start: two commands

You don't need to type anything else. Open a terminal **in the project folder**:

```bash
bash scripts/run_everything.sh     # once, ~25 min: installs, tests, experiments, charts
bash scripts/demo.sh               # on demo day: the live demo, press Enter for each step
```

* `run_everything.sh` asks for your password once and then runs unattended. It keeps
  the VM awake (keep the laptop plugged in). At the end it prints `12 / 12 passed` and
  puts the report, results table and charts in `docs/results/`. Its output is also saved
  to `run_everything.log`.
* `demo.sh` opens one window split into three panes: logger (top left), controller
  (top right) and Mininet (bottom). It walks through steps a–k, stops and restarts the
  logger and controller for you, and opens the charts at the end.
  * `bash scripts/demo.sh auto`: runs the whole demo hands-free.
  * `bash scripts/demo.sh from e`: starts again from step e.
  * During the demo: **Enter** = run step, **s** = skip, **q** = quit to the `mininet>` prompt.
  * Closing the window or pressing **q** then `exit` cleans everything up.

The rest of this README explains the design and the manual commands.

---

## Architecture

```
    h1 10.0.0.1 (admin)    --+
    h2 10.0.0.2            --+
    h3 10.0.0.3            --+-- s1 ===10 Mbit/s=== srv 10.0.0.100   TCP server :8080 (service), :2222 (admin)
    h4 10.0.0.4 (attacker) --+     |
                                   | OpenFlow 1.0 (127.0.0.1:6633)
                       +-----------+------------+          JSON over TCP
                       |  POX controller        | ------------------------> security logger
                       |  controller/firewall.py |                           127.0.0.1:9999
                       +------------------------+                           app/logger_server.py
```

**What happens to a new TCP connection.** When `h2` connects to `srv:8080`, the switch has no flow for it yet. It
sends the first packet (the SYN) to the controller as a **packet-in**. The controller then does four things:

1. Learns `h2`'s MAC address and port (normal L2 learning switch).
2. Drops the packet if `h2` is currently blocked.
3. Checks the **rules** (`config/policy.json`, first match wins):

| Rule | Source | Destination | Port | Action | Class |
|---|---|---|---|---|---|
| R1 | 10.0.0.1 | 10.0.0.100 | 2222 | allow | ADMIN |
| R2 | any | 10.0.0.100 | 2222 | deny | ADMIN |
| R3 | 10.0.0.0/24 | 10.0.0.100 | 8080 | allow | SERVICE |
| R4 | any | any | 23 | deny | TELNET |
| – | otherwise | | | allow | OTHER |

   On **deny**, the controller installs a drop flow for that connection and sends a `DENY` event to the logger.

4. In **dynamic** mode, shows the new connection to the **Detector**. That is a 5-second sliding window per source IP:
   * ≥ 25 new connections → `CONN_FLOOD`
   * ≥ 8 different ports or hosts → `PORT_SCAN`
   * ≥ 5 connections stopped by DENY rules → `POLICY_VIOLATION`

   On any verdict the controller **blocks** the source.

Otherwise the controller installs a forwarding flow, so the rest of the connection is handled by the switch alone.

**How a block works** (`block()` in `controller/firewall.py`):
1. Delete the attacker's existing flows. In OpenFlow 1.0, exact-match flows would win over our rule.
2. Install `DROP all IPv4 from <ip>`, priority 60000, `hard_timeout=20`. Each repeat offence doubles the time, up to 160 s.
3. Send a **barrier request**. The switch's reply proves the rule is active.

The **response time** is measured as:
- detection = from the first connection of the evidence to the verdict
- rule installation = from the verdict to the barrier reply
- total = the two added together

These go to the log and to `results/blocks.csv`.

When the time is up, the switch deletes the rule by itself (**recovery**, which works even if the controller is down). It sends **FlowRemoved** with the number of packets it dropped, and the controller logs `UNBLOCK`.

**Modes.** `dynamic` is the proposed design. `static` (rules only, no automatic blocking) is the **baseline** for the comparison.

**App protocol** (TCP, one text line per request). `PING`→`PONG`, `ECHO x`, `DATA n` (n raw bytes follow), `STATS`, `QUIT`. If more than 50 clients are connected, new ones get `ERR BUSY`.

---

## Setup (Ubuntu 26.04, once)

```bash
unzip sdn-firewall-final.zip && cd sdn-firewall
chmod +x scripts/*.sh
./scripts/setup.sh        # installs Mininet, Open vSwitch, matplotlib; downloads POX into ./pox; runs tests
```
If the self-check says only the userspace switch works, add `--userspace` to the topology command.

## Run it (3 terminals, all in the project folder)

```bash
python3 app/logger_server.py           # T1: central security logger (start first)
./scripts/start_controller.sh          # T2: POX firewall (or: ./scripts/start_controller.sh static)
sudo python3 topology/topo.py          # T3: Mininet, also starts the server on srv
```
Then type the demo commands at the `mininet>` prompt (see **`docs/DEMO.md`**), or let the
**guided demo** type them for you: start Terminal 3 with `sudo python3 topology/topo.py --demo`
and press Enter for each step (it also tells you what to point out). `--from e` resumes at a step.
Leave Mininet with `exit` and stop T1/T2 with Ctrl+C. After a crash, run `./scripts/cleanup.sh`.

**Starting again from scratch:** `./scripts/cleanup.sh --all` stops everything and also deletes `logs/` and `results/`.
Nothing else carries over: blocks, repeat-offence counts and the detector's history live only in the
controller's memory, and Mininet rebuilds the network each time.

## Tests and results

```bash
python3 -m unittest discover -s tests -v      # rule + detector unit tests (no Mininet)
./scripts/cleanup.sh                          # nothing else may be running for the next two
sudo python3 tests/system_check.py            # 12 end-to-end checks, about 1.5 min → results/system_check/report.md
sudo python3 experiments/run_experiments.py --repeat 3   # static vs dynamic + rate sweep, about 18 min
python3 experiments/plot_results.py           # → results/experiments/results.md + fig1–fig3 (medians)
```

**Experiments.**
- Three users (h1–h3) download 20 kB four times per second, while h4 runs no attack, a flood (150 conn/s) or a port scan.
- For each case we record the users' success rate, latency and goodput, how much of the attack got through, and the controller load (packet-ins), for static vs dynamic.
- A second part floods at 10 to 200 conn/s and records the blocking response time.
- `--repeat 3` runs everything three times and the table and charts show the median of the three runs, so one disturbed run can't skew them. Use that for the report; without it, each test runs once (about 6 min), which is fine for a quick check.

## Troubleshooting

| Problem | Fix |
|---|---|
| Switch does not connect | start the controller before the topology |
| `Address already in use` / leftovers from a crash | `./scripts/cleanup.sh` |
| Ping works but TCP does not (userspace switch) | use `--userspace` (it turns off checksum offload) |
| A demo client gets blocked | one host made more than 25 new connections in 5 s. That's the detector doing its job; slow the client down (`--rate`) |
| `apt install mininet` fails | `sudo add-apt-repository universe && sudo apt update`, then retry |

## Team split (everyone should still know the whole path)

| Member | Files | Must explain |
|---|---|---|
| 1 | `app/server.py`, `app/client.py`, `app/logger_server.py` | sockets, threads, framing, `ERR BUSY`, event logging |
| 2 | `controller/firewall.py`, `controller/rules.py`, `config/policy.json` | packet-in flow, rules, detector, block, escalation, barrier, recovery |
| 3 | `topology/`, `traffic/attacker.py`, `tests/`, `experiments/` | topology, attack traffic, test cases, results and baseline |
