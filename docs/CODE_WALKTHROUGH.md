# Code walkthrough and viva preparation

Read the files in this order. The core is about 1,000 lines.

| # | File | Lines | What it is |
|---|---|---|---|
| 1 | `config/policy.json` | 20 | rules, thresholds, block times |
| 2 | `controller/rules.py` | 105 | `Policy` (rule matching) and `Detector` (sliding windows), plain Python |
| 3 | `controller/firewall.py` | 280 | the POX controller: packet-in → classify → detect → block |
| 4 | `app/server.py` | 130 | multi-client TCP server |
| 5 | `app/client.py` | 130 | TCP client, measures latency |
| 6 | `app/logger_server.py` | 95 | central logger, TCP server receiving JSON lines |
| 7 | `topology/topo.py` | 105 | Mininet network |
| 8 | `traffic/attacker.py` | 135 | flood and scan generator |

`topology/lab.py`, `tests/` and `experiments/` only automate runs. Know what they do, but you don't need every line.

---

## 1. `controller/rules.py`: the brain, without any SDN

**`Policy.check(src, dst, dst_port)`** walks through the rules top to bottom and returns the
first match: `("deny", "R2", "ADMIN")`. If nothing matches, it returns the default (`allow`, `OTHER`).
`ipaddress.ip_network("10.0.0.0/24")` lets one rule cover a whole subnet.

**`Detector.new_connection(src, dst, port, now)`** keeps a **deque per source IP** of
`(time, dst, port)` for the last 5 seconds:
* It appends the new event, then pops events older than 5 s from the left. That's the sliding window.
* It counts **distinct (dst, port)** pairs. 8 or more means `PORT_SCAN`, because a scanner tries many ports and a client uses one.
* It counts **all** events. 25 or more means `CONN_FLOOD`, because a normal client makes a few connections per second.
* It returns `(reason, count, first_time)`. `first_time` is when the evidence started, which gives us the detection delay.

**`Detector.denied(src, now)`** is a second, simpler window: the times when this source was stopped by
a DENY rule. 5 in 5 seconds means `POLICY_VIOLATION`. One denied attempt can be a mistake;
five in a row means the host keeps trying something it isn't allowed to do, so the whole host gets blocked.

Why only SYN packets? A SYN (without ACK) is the start of a **new** TCP connection, so
counting SYNs counts connection attempts, not bytes.

## 2. `controller/firewall.py`: the POX component

* **`launch()`** is called by POX at start-up. It reads the config and registers the `Firewall` object.
* **`_handle_ConnectionUp`** runs when the switch connects. It creates an empty MAC table.
* **`_handle_PacketIn`** runs for every packet the switch could not match:
  1. `mac_to_port[switch][src_mac] = in_port` learns where hosts are.
  2. If the IP source is blocked, the packet is dropped (`return`).
  3. If it's TCP, `check_tcp()` decides.
  4. `forward()` sends it on and installs a flow.
* **`check_tcp()`** asks the policy. On deny it calls `install_drop()` and logs `DENY`. In dynamic mode, each new connection (`tcp.SYN and not tcp.ACK`) goes to the detector. If it was also denied, it goes to `detector.denied()` too. Any verdict calls `block()`.
* **`self.packet_ins`** counts every packet the switch sent up. `save_stats()` writes it to a file every 2 s (a POX `Timer`). The experiments read it to show controller load.
* **`forward()`**
  * If the destination MAC is unknown or multicast, it **floods** (packet-out to all ports).
  * Otherwise it sends a **flow_mod** with `ofp_match.from_packet()`, an *exact match* on all header fields: MACs, IPs, ports and the input port. That's why every new TCP connection (new source port) comes to the controller once.
  * `idle_timeout=10` removes the flow after 10 s without traffic. `hard_timeout=30` removes it after 30 s regardless.
* **`install_drop()`** sends the same kind of exact-match flow_mod but with **no actions**. In OpenFlow, no actions means drop.
* **`block(ip)`**
  1. `OFPFC_DELETE` removes the host's existing flows. *Why? In OpenFlow 1.0, an exact-match flow always beats a wildcard rule, whatever the priority. Without this, connections that already had flows would keep working.*
  2. `OFPFC_ADD` installs a match on `dl_type=0x800` (IPv4) and `nw_src=ip`, which is wildcarded everywhere else. It has `priority=60000`, flag `SEND_FLOW_REM` and no actions, so it drops all IPv4 from the attacker. The `hard_timeout` is `20 × 2^(offence−1)`, capped at 160 s, so 20 s, 40 s, 80 s… `self.offences[ip]` remembers how many times each host has been blocked.
  3. `ofp_barrier_request`: the switch answers only after it has processed everything sent before. When the reply comes back (`_handle_BarrierIn`), the rule is definitely active, and we compute *install_ms*.
* **`_handle_FlowRemoved`** runs when the switch deletes the block rule after 20 s. The message includes `packet_count`, the number of packets the rule dropped. We log `UNBLOCK`. This is the **automatic recovery**: the switch does it by itself, so it works even if the controller has crashed.
* **`EventSender`** is a TCP client to the logger.
  * `send()` only puts the event in a `queue.Queue`, so the controller never waits for the network.
  * A background thread takes events and `sendall()`s them. If the logger is down, it keeps the event and retries every 2 s, so nothing is lost.
  * `select()` notices when the logger closed the connection.

## 3. `app/server.py`: multi-client TCP server

* `socket()` → `setsockopt(SO_REUSEADDR)` → `bind()` → `listen()` → `accept()` loop, one per port (8080 and 2222).
* **One thread per client** (`threading.Thread(target=self.handle)`).
* **`BoundedSemaphore(max_clients)`** allows at most 50 at once. `acquire(blocking=False)` fails if the server is full, and the client gets `ERR BUSY`. This is how overload shows up.
* **Framing.** TCP is a byte stream, not messages. `conn.makefile("rb").readline()` buffers bytes until it has a full line, so one line = one request. `DATA n` replies with a header line, then exactly n raw bytes.
* `settimeout(10)`: idle clients are disconnected, so they can't hold a slot forever.
* A shared `Counter` is protected by a `Lock`, because many threads update it.

## 4. `app/client.py`

* `one_request()`: `create_connection` (with timeout) → send the line → read the reply (and n bytes for DATA) → `QUIT` → close. `perf_counter()` gives the latency.
* `run()` sends at a fixed rate: request *i* starts at `start + i/rate`.
* `--parallel N` starts N threads, so N clients run at once. `--json` saves every request for the experiments.

## 5. `app/logger_server.py`

* TCP server with a thread per sender. Each line is one JSON event (newline-delimited JSON).
* A `Lock` around writing, because several threads write the same file.
* Lines that aren't valid JSON are logged as `MALFORMED_INPUT` instead of crashing the logger.

## 6. `topology/topo.py`

* `FirewallTopo`: 4 hosts plus `srv` on switch `s1`. The `srv` link is limited to `bw=10` Mbit/s with `TCLink` (Linux traffic control). That bottleneck is what a flood fills up.
* `RemoteController(127.0.0.1:6633)`: the switch connects to POX.
* `protocols=OpenFlow10`, because POX speaks OpenFlow 1.0.
* `failMode=secure`: without a controller the switch does **not** fall back to a normal switch (fail-closed).

## 7. `traffic/attacker.py`

* **flood**: many threads, each opening connections at a fixed overall rate (`start + i/rate`) and downloading data.
* **scan**: `connect()` to each port. `open` = connected; `closed` = the host answered with a RST; `timeout` = no answer, so the firewall dropped it.
* It records when the first attempt was dropped (`first dropped attempt after … ms`). That's the attacker's view of the blocking time.

---

## Likely viva questions

1. **What is the role of the SDN controller here?** It decides what the switch does. The switch asks it about every new flow (packet-in). The controller classifies the flow, and installs flow rules to forward or drop it. It also installs block rules when it detects an attack.
2. **What is a packet-in and when does it happen?** The switch sends a packet to the controller when no flow matches it. Because our flows are exact-match, that's the first packet of every new TCP connection.
3. **flow_mod vs packet_out?** flow_mod installs a rule in the switch for future packets. packet_out tells the switch what to do with this one packet.
4. **How do you classify traffic by source, destination and port?** First-match rule list in `policy.json` (R1–R4). The admin port 2222 is allowed for h1 but denied for h2. That's the same destination and port with a different source, so a different result.
5. **How does the detector work?** A 5 s sliding window per source IP of new connections (SYNs). At least 25 means a flood; at least 8 different ports means a scan.
6. **Why per source IP? What about false positives?** Each host is judged separately. Many users behind one IP (NAT), or one host opening more than 5 connections/s, would be flagged. That's a limitation; the thresholds are configurable.
7. **How is the attacker blocked?** A priority-60000 drop rule for `nw_src=attacker` on the switch. The switch drops its packets without asking the controller, so the controller load also goes down.
8. **Why delete the old flows first?** OpenFlow 1.0: exact-match entries always win over wildcard entries, so the attacker's existing connections would keep working.
9. **How do you measure the blocking response time?**
   * Detection = verdict time − first connection of the evidence.
   * Installation = barrier reply time − verdict time.
   * The barrier reply proves the switch has applied the rule.
   * The attacker also measures when its first connection was dropped.
10. **Why does the response time go down as the attack rate goes up?** The attacker needs 25 connections to be detected. At 100/s that takes ~250 ms; at 10/s it takes ~2.5 s. Installation is only a few ms.
11. **Why do repeat offenders get longer blocks?** An attacker who just waits out a 20 s block and starts again would otherwise get through for ~0.25 s every 20 s. Doubling the time makes repeating the attack less and less worthwhile, while a one-off mistake only costs 20 s.
12. **What is POLICY_VIOLATION and why block the whole host for it?** Five connections stopped by DENY rules within 5 s. The static rules already stop each attempt; the dynamic part notices the *pattern* (someone probing what they aren't allowed to reach) and isolates the host completely.
13. **How do you measure controller load?** We count packet-ins. With the static firewall every new attack connection reaches the controller; once the dynamic firewall blocks the attacker, the switch drops its packets without asking, so the count stays low.
14. **How does recovery work?** `hard_timeout` (20 s for a first offence): the switch removes the rule by itself and sends FlowRemoved, and we log UNBLOCK with the dropped-packet count. It works even if the controller is down.
15. **What if the controller crashes?** `failMode=secure`: existing flows keep working until they time out, but new connections are not forwarded (fail-closed). Blocks still expire on the switch.
16. **What if the logger crashes?** The EventSender keeps the event and retries every 2 s. When the logger restarts, the buffered events arrive.
17. **How does the server handle many clients?** A thread per connection, with a semaphore limit of 50. Above that, new clients get `ERR BUSY`. Idle clients time out after 10 s.
18. **How do you know where one message ends in TCP?** We use lines: `readline()` collects bytes up to `\n`. For DATA the header says how many bytes follow.
19. **What is the baseline?** The same controller with `--mode=static`: same rules, no automatic blocking. Under a flood the static firewall lets it through, and normal users' latency goes from ~20–30 ms to almost 1 s.
20. **Why is a port scan detected faster than a flood?** It needs only 8 different ports, not 25 connections.
21. **Why does ping still work for a denied TCP port, but not for a blocked host?** Deny rules are for one TCP connection. A block drops *all* IPv4 from the host, including ICMP.
22. **Why run every experiment three times?** One run can be noisy (a few ms either way). `--repeat 3` runs each test three times and reports the **median** (middle value), so one disturbed run (a VM hiccup, the laptop sleeping) can't skew the result.
23. **Limitations?**
    * Attackers could spoof source IPs.
    * Per-IP thresholds can hit legitimate busy hosts.
    * A slow attack under the threshold is not detected.
    * Offence counts are never forgotten while the controller runs, and are lost when it restarts.
    * Single controller, OpenFlow 1.0, no encryption on the logger channel.

## Exercises (each takes 5 minutes and is the best way to learn the code)

1. In `policy.json` set `"max_new_conns": 10`. Restart the controller and run `h2 python3 app/client.py --count 20 --rate 3`. What happens, and why?
2. Add a rule that denies h3 → srv:8080. Show it working with the client, and find the DENY event in the log.
3. Change `block_seconds` to 5 and watch the `priority=60000` rule disappear in `ovs-ofctl dump-flows s1`. Flood again and check its `hard_timeout` is now 10.
4. Run the flood with `./scripts/start_controller.sh static` and compare `h2`'s latency during the attack.
5. In `firewall.py`, comment out the `OFPFC_DELETE` line in `block()`. Start a long `DATA` download from h4, then the flood. Does the download keep going? (Question 8.)
