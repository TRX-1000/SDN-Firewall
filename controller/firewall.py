"""
Dynamic SDN Firewall - POX controller component (OpenFlow 1.0)

Start:  ./scripts/start_controller.sh            (mode dynamic)
        ./scripts/start_controller.sh static     (baseline: static rules only)

For every packet the switch cannot handle by itself (a "packet-in"):
  1. learn  MAC address -> switch port                (L2 learning switch)
  2. if the packet comes from a BLOCKED host: drop it
  3. if it is TCP: classify it with the policy (src IP, dst IP, dst port)
        DENY  -> install a drop flow for this connection, log a DENY event
        new connection (SYN) in dynamic mode -> show it to the Detector;
        a flood or port scan -> BLOCK the source IP on the switch
  4. otherwise forward it and install a flow, so the next packets of this
     connection are handled by the switch without asking the controller

Blocking = a high-priority DROP rule for the attacker's IP with a
hard_timeout.  The switch deletes it by itself when the time is up
(automatic recovery) and tells us (FlowRemoved), so we log UNBLOCK.
Repeat offenders are blocked longer: 20 s, 40 s, 80 s ... (max 160 s).
Every security event is sent as one JSON line over TCP to the central
logger (app/logger_server.py).
"""

import json
import os
import queue
import select
import socket
import sys
import threading
import time

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.recoco import Timer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from rules import Detector, Policy, load_config  # noqa: E402

log = core.getLogger("firewall")
BLOCK_PRIORITY = 60000      # higher than every normal flow
FLOW_IDLE, FLOW_HARD = 10, 30


class EventSender:
    """Sends security events to the logger over TCP without ever blocking
    the controller: events go into a queue, a background thread sends them,
    and if the logger is down it keeps retrying (nothing is lost)."""

    def __init__(self, host, port):
        self.addr = (host, port)
        self.queue = queue.Queue()
        self.sock = None
        threading.Thread(target=self._run, daemon=True).start()

    def send(self, event_type, **fields):
        event = {"time": time.strftime("%H:%M:%S"), "ts": round(time.time(), 3),
                 "source": "sdn-controller", "type": event_type}
        event.update(fields)
        self.queue.put(json.dumps(event) + "\n")

    def _connected(self):
        if self.sock is None:
            return False
        # the logger never sends us data, so "readable" means it closed the socket
        readable, _, _ = select.select([self.sock], [], [], 0)
        if readable:
            self.sock.close()
            self.sock = None
            return False
        return True

    def _run(self):
        warned = False
        while True:
            line = self.queue.get()                 # wait for the next event
            while True:                             # retry until it is delivered
                try:
                    if not self._connected():
                        self.sock = socket.create_connection(self.addr, timeout=2)
                        log.info("connected to security logger %s:%d", *self.addr)
                        warned = False
                    self.sock.sendall(line.encode())
                    break
                except OSError:
                    self.sock = None
                    if not warned:
                        log.warning("security logger %s:%d not reachable - "
                                    "buffering events and retrying", *self.addr)
                        warned = True
                    time.sleep(2)


class Firewall(object):
    def __init__(self, cfg, mode, metrics_file):
        self.mode = mode
        self.policy = Policy(cfg["rules"], cfg.get("default_action", "allow"))
        self.detector = Detector(**cfg["detection"])
        self.block_seconds = int(cfg["block_seconds"])
        self.max_block_seconds = int(cfg.get("max_block_seconds", 160))
        self.events = EventSender(cfg["logger"]["host"], cfg["logger"]["port"])
        self.mac_to_port = {}      # switch id -> {mac: port}
        self.blocked = {}          # ip -> info about the block
        self.offences = {}         # ip -> how many times it has been blocked
        self.barriers = {}         # (switch id, xid) -> blocked ip
        self.packet_ins = 0        # controller load: packets the switch sent us
        self.metrics_file = metrics_file
        core.openflow.addListeners(self)
        Timer(2, self.save_stats, recurring=True)
        log.info("Dynamic SDN firewall started, mode=%s, %d rules, block %ds",
                 mode, len(self.policy.rules), self.block_seconds)
        self.events.send("CONTROLLER_START", mode=mode, rules=len(self.policy.rules))

    # ------------------------------------------------------------ switches
    def _handle_ConnectionUp(self, event):
        self.mac_to_port[event.dpid] = {}
        log.info("switch %s connected", event.dpid)
        self.events.send("SWITCH_CONNECTED", switch=event.dpid)

    # ------------------------------------------------------------ packet-in
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        self.packet_ins += 1
        self.mac_to_port[event.dpid][packet.src] = event.port       # 1. learn

        ip = packet.find("ipv4")
        if ip is not None:
            src, dst = str(ip.srcip), str(ip.dstip)
            if self.is_blocked(src):                                 # 2. blocked
                return
            tcp = packet.find("tcp")
            if tcp is not None and not self.check_tcp(event, packet, src, dst, tcp):
                return                                               # 3. firewall
        self.forward(event, packet)                                  # 4. forward

    def check_tcp(self, event, packet, src, dst, tcp):
        """Return True if this TCP packet may be forwarded."""
        action, rule_id, traffic_class = self.policy.check(src, dst, tcp.dstport)
        new_connection = tcp.SYN and not tcp.ACK

        if action == "deny":
            self.install_drop(event, packet)
            if new_connection:
                log.info("DENY  %s -> %s:%d  (%s, rule %s)", src, dst, tcp.dstport,
                         traffic_class, rule_id)
                self.events.send("DENY", src=src, dst=dst, dst_port=tcp.dstport,
                                 rule=rule_id, traffic_class=traffic_class)

        if new_connection and self.mode == "dynamic":
            verdict = self.detector.new_connection(src, dst, tcp.dstport, time.time())
            if verdict is None and action == "deny":
                verdict = self.detector.denied(src, time.time())
            if verdict is not None:
                self.block(src, verdict)
                return False
        return action == "allow"

    # ------------------------------------------------------------ flows
    def forward(self, event, packet):
        table = self.mac_to_port[event.dpid]
        if packet.dst.is_multicast or packet.dst not in table:
            msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)   # flood
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
            return
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)   # exact match
        msg.idle_timeout, msg.hard_timeout = FLOW_IDLE, FLOW_HARD
        msg.actions.append(of.ofp_action_output(port=table[packet.dst]))
        msg.data = event.ofp                  # also send this first packet out
        event.connection.send(msg)

    def install_drop(self, event, packet):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = FLOW_IDLE          # no actions = drop
        event.connection.send(msg)

    # ------------------------------------------------------------ blocking
    def is_blocked(self, ip):
        info = self.blocked.get(ip)
        if info and time.time() > info["until"] + 2:   # safety: missed FlowRemoved
            del self.blocked[ip]
            return False
        return info is not None

    def block(self, ip, verdict):
        reason, evidence, first_ts = verdict
        detect_ts = time.time()
        offence = self.offences[ip] = self.offences.get(ip, 0) + 1
        seconds = min(self.block_seconds * 2 ** (offence - 1), self.max_block_seconds)
        self.blocked[ip] = {"reason": reason, "first_ts": first_ts,
                            "detect_ts": detect_ts, "evidence": evidence,
                            "until": detect_ts + seconds, "waiting": 0}
        self.detector.forget(ip)
        match = of.ofp_match(dl_type=0x800, nw_src=IPAddr(ip))     # all IPv4 from ip
        for conn in core.openflow.connections:
            # exact-match flows always beat wildcard rules in OpenFlow 1.0,
            # so first delete the flows this host already has
            conn.send(of.ofp_flow_mod(command=of.OFPFC_DELETE, match=match))
            conn.send(of.ofp_flow_mod(command=of.OFPFC_ADD, match=match,
                                      priority=BLOCK_PRIORITY,
                                      hard_timeout=seconds,
                                      flags=of.OFPFF_SEND_FLOW_REM))  # drop
            barrier = of.ofp_barrier_request()      # "tell me when that is done"
            conn.send(barrier)
            self.barriers[(conn.dpid, barrier.xid)] = ip
            self.blocked[ip]["waiting"] += 1
        log.warning("BLOCK %s: %s (%d events), offence #%d, blocked for %ds", ip,
                    reason, evidence, offence, seconds)
        self.events.send("BLOCK", src=ip, reason=reason, evidence=evidence,
                         offence=offence, block_seconds=seconds)

    def _handle_BarrierIn(self, event):
        ip = self.barriers.pop((event.dpid, event.xid), None)
        if ip is None or ip not in self.blocked:
            return
        info = self.blocked[ip]
        info["waiting"] -= 1
        if info["waiting"] > 0:
            return
        now = time.time()                              # rule is active on every switch
        detection_ms = (info["detect_ts"] - info["first_ts"]) * 1000
        install_ms = (now - info["detect_ts"]) * 1000
        total_ms = (now - info["first_ts"]) * 1000
        log.warning("BLOCK %s enforced: detection %.0f ms + rule install %.0f ms "
                    "= response %.0f ms", ip, detection_ms, install_ms, total_ms)
        self.events.send("BLOCK_ENFORCED", src=ip, reason=info["reason"],
                         detection_ms=round(detection_ms, 1),
                         install_ms=round(install_ms, 1), response_ms=round(total_ms, 1))
        self.save_metrics([ip, info["reason"], info["evidence"], round(detection_ms, 2),
                           round(install_ms, 2), round(total_ms, 2)])

    def _handle_FlowRemoved(self, event):
        if event.ofp.priority != BLOCK_PRIORITY:
            return
        ip = str(event.ofp.match.nw_src)
        info = self.blocked.pop(ip, None)
        if info is None:
            return
        why = "expired" if event.hardTimeout else "rule deleted"
        log.warning("RECOVERY %s: block %s, %d packets were dropped", ip, why,
                    event.ofp.packet_count)
        self.events.send("UNBLOCK", src=ip, reason=info["reason"], why=why,
                         blocked_seconds=round(time.time() - info["detect_ts"], 1),
                         dropped_packets=event.ofp.packet_count)

    def save_stats(self):
        """Every 2 s: write the controller load counter (used by the experiments)."""
        if self.metrics_file:
            path = os.path.join(os.path.dirname(self.metrics_file), "controller_stats.json")
            with open(path, "w") as f:
                json.dump({"packet_ins": self.packet_ins,
                           "blocks": sum(self.offences.values())}, f)

    def save_metrics(self, row):
        if not self.metrics_file:
            return
        new = not os.path.exists(self.metrics_file)
        with open(self.metrics_file, "a") as f:
            if new:
                f.write("ip,reason,evidence,detection_ms,install_ms,response_ms\n")
            f.write(",".join(str(v) for v in row) + "\n")


def launch(mode="dynamic", config=None, metrics=None):
    if mode not in ("static", "dynamic"):
        raise RuntimeError("mode must be static or dynamic")
    cfg = load_config(config or os.path.join(ROOT, "config", "policy.json"))
    metrics = metrics or os.path.join(ROOT, "results", "blocks.csv")
    os.makedirs(os.path.dirname(metrics), exist_ok=True)
    core.registerNew(Firewall, cfg, mode, metrics)
