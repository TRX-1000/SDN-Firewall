# Demo script (about 10 minutes)

> **Easiest way (recommended):** `bash scripts/demo.sh` in the project folder.
> It opens the logger, controller and Mininet in one split window and runs every step below.
> Press **Enter** to run a step, **s** to skip one, **q** to stop and get the `mininet>` prompt.
> It stops and restarts the logger and controller itself (steps h and i) and opens the charts at the end.
> `bash scripts/demo.sh auto` runs it hands-free; `bash scripts/demo.sh from e` resumes at step e.
> The manual commands below are the same ones, for reference only.

Use three terminals side by side:

| Terminal | Runs | You show |
|---|---|---|
| **T1** | `python3 app/logger_server.py` | the central security log |
| **T2** | `./scripts/start_controller.sh` | the firewall's decisions |
| **T3** | `sudo python3 topology/topo.py` | the Mininet CLI where you type |

Before the professor arrives, run `./scripts/cleanup.sh` and `python3 -m unittest discover -s tests`.
(Use `./scripts/cleanup.sh --all` instead to also start with an empty security log. It also deletes `results/`, so save your experiment charts somewhere else first.)
Have the charts from `results/experiments/` ready to open.

---

### 1. Start everything (Mininet + SDN, socket–SDN link)

Start T1, then T2, then T3, in that order.
- **T2** shows `Dynamic SDN firewall started, mode=dynamic, 4 rules` and `switch 1 connected`.
- **T1** shows `CONTROLLER_START` and `SWITCH_CONNECTED`. The controller is talking to the logger over TCP.
- **T3** shows `pingall` with 0% dropped.

```
mininet> net
mininet> sh ovs-ofctl dump-flows s1
```
→ the topology, and the flows the controller installed.

### 2. TCP client/server, multiple clients

```
mininet> h2 python3 app/client.py --count 5
mininet> h2 python3 app/client.py --count 8 --parallel 4 --rate 1
mininet> h3 python3 app/client.py --count 3 --request "DATA 1000000"
```
→ 5 OK requests; 4 clients at once, each `8/8 ok`; about 9–10 Mbit/s (the 10 Mbit/s link).

**Say:** each request is a new TCP connection, so the first packet of each one is a packet-in to the controller.

### 3. Classification by source, destination and port

```
mininet> h1 python3 app/client.py --port 2222 --request STATS --count 1    # allowed (R1)
mininet> h2 python3 app/client.py --port 2222 --request STATS --count 1    # FAIL timeout (R2)
mininet> h2 nc -zv -w 2 10.0.0.3 23                                        # times out (R4 telnet)
mininet> h2 nc -zv -w 2 10.0.0.3 5555                                      # "refused" quickly = allowed
```
- **T2:** `DENY 10.0.0.2 -> 10.0.0.100:2222 (ADMIN, rule R2)`
- **T1:** a `DENY` event with `rule=R2 traffic_class=ADMIN`

```
mininet> sh ovs-ofctl dump-flows s1 | grep "actions=drop"
```
→ the drop flow the controller installed for that connection.

### 4. Automatic blocking (dynamic SDN)

```
mininet> h4 python3 traffic/attacker.py flood
```
- **T3:** about 25 `ok`, then everything `timeout`. The summary says `first dropped attempt after ~250 ms`.
- **T2:** `BLOCK 10.0.0.4: CONN_FLOOD (25 events)` and `enforced: detection ~240 ms + rule install ~5 ms = response ~250 ms`.
- **T1:** `BLOCK`, then `BLOCK_ENFORCED` with the timings.

While h4 is blocked:
```
mininet> sh ovs-ofctl dump-flows s1 | grep priority=60000     # the block rule + its packet counter
mininet> h4 ping -c 2 10.0.0.100                              # 100% loss: h4 is cut off
mininet> h2 python3 app/client.py --count 3                   # everyone else is fine
```

### 5. Automatic recovery (about 20 s after the block)

```
mininet> sh ovs-ofctl dump-flows s1 | grep priority=60000     # gone
mininet> h4 ping -c 2 10.0.0.100                              # works again
```
- **T2:** `RECOVERY 10.0.0.4: block expired, N packets were dropped`
- **T1:** `UNBLOCK ... dropped_packets=N`

**Repeat offender.** Run the flood again:
```
mininet> h4 python3 traffic/attacker.py flood
```
→ **T2:** `BLOCK 10.0.0.4: CONN_FLOOD ... offence #2, blocked for 40s`. The block time doubles each time.

### 5b. Repeated denied access (static rules + dynamic blocking together)

```
mininet> h2 python3 app/client.py --port 2222 --request STATS --count 6 --rate 2 --timeout 1
mininet> h2 python3 app/client.py --count 2 --timeout 1
```
- The first command: every attempt fails, because rule R2 denies h2 on the admin port.
- **T2** shows 5 `DENY` lines, then `BLOCK 10.0.0.2: POLICY_VIOLATION (5 events)`.
- The second command now fails too: h2 kept trying something it isn't allowed to do, so the whole host is blocked, even the normal service on 8080.

### 6. Port scan (second attack type)

```
mininet> h3 python3 traffic/attacker.py scan
```
→ `open ports found: none`. h3 is blocked after 8 probes (`PORT_SCAN`, about 40–80 ms), so it never finds port 8080 or 2222.

### 7. Challenging scenarios / robustness (pick two)

**Logger outage.**
- Ctrl+C in T1, then make a denied request: `h2 python3 app/client.py --port 2222 --count 1`.
- **T2** says `security logger ... not reachable - buffering events`.
- Restart T1 (`python3 app/logger_server.py`). The buffered `DENY` arrives, so no events are lost.

**Controller failure.**
- Ctrl+C in T2, then try `h1 python3 app/client.py --count 2`. It fails.
- That's because the switch is in `failMode=secure`: without a controller no new flows are forwarded, so the firewall fails closed.
- Restart T2. The switch reconnects and everything works again.

**Baseline comparison live.**
- Restart T2 as `./scripts/start_controller.sh static` and run the flood again.
- h4 is never blocked, and `h2 python3 app/client.py --count 5` during the flood is slow or fails.

### 8. Results (performance evaluation)

Run `sudo python3 experiments/run_experiments.py --repeat 3` and `python3 experiments/plot_results.py` beforehand (about 18 min).
Open `results/experiments/results.md` and the three charts. Point out:
- **fig1:** with no attack, the two modes are within a few ms of each other, so the dynamic checks add almost no overhead. During a flood, static is slow and loses requests while dynamic stays at about 30 ms and 100%.
- **fig2:** the timeline of that flood.
- **fig3:** response time ≈ 25 connections ÷ attack rate, plus a few ms to install the rule.
- **Controller packet-ins column:** the static firewall keeps sending the attack's packets to the controller; dynamic drops them in the switch, so the controller does less work.

### 9. Automated tests (initial testing)

After the demo (stop T1–T3 first):
```bash
sudo python3 tests/system_check.py     # 12 PASS lines
```
