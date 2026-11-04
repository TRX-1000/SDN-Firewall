"""
The firewall's "brain" in plain Python (no POX), so it can be unit-tested.

Policy   - static rules: classify a TCP connection by source IP,
           destination IP and destination port -> allow / deny + a class name.
Detector - sliding window per source IP: spots connection floods and
           port scans from the new TCP connections (SYN packets) it is shown,
           and hosts that keep hitting DENY rules (policy violations).
"""

import ipaddress
import json
from collections import defaultdict, deque


def load_config(path):
    with open(path) as f:
        return json.load(f)


class Rule:
    def __init__(self, spec):
        self.id = spec["id"]
        self.action = spec["action"]                 # "allow" or "deny"
        self.traffic_class = spec.get("class", "GENERAL")
        self.src = self._net(spec.get("src", "any"))
        self.dst = self._net(spec.get("dst", "any"))
        port = spec.get("dst_port", "any")
        self.dst_port = None if port == "any" else int(port)

    @staticmethod
    def _net(value):
        # "any" matches everything; "10.0.0.1" or "10.0.0.0/24" is a network
        return None if value == "any" else ipaddress.ip_network(value)

    def matches(self, src, dst, dst_port):
        if self.src and ipaddress.ip_address(src) not in self.src:
            return False
        if self.dst and ipaddress.ip_address(dst) not in self.dst:
            return False
        if self.dst_port is not None and self.dst_port != dst_port:
            return False
        return True


class Policy:
    def __init__(self, rule_specs, default_action="allow"):
        self.rules = [Rule(r) for r in rule_specs]
        self.default_action = default_action

    def check(self, src, dst, dst_port):
        """First matching rule wins.  Returns (action, rule_id, class)."""
        for rule in self.rules:
            if rule.matches(src, dst, dst_port):
                return rule.action, rule.id, rule.traffic_class
        return self.default_action, "DEFAULT", "OTHER"


class Detector:
    def __init__(self, window_sec=5, max_new_conns=25, max_ports=8, max_denied=5):
        self.window = window_sec
        self.max_new_conns = max_new_conns
        self.max_ports = max_ports
        self.max_denied = max_denied
        self.history = defaultdict(deque)    # src -> deque of (time, dst, dst_port)
        self.denials = defaultdict(deque)    # src -> deque of times it was denied

    def new_connection(self, src, dst, dst_port, now):
        """Record one new TCP connection attempt from src.

        Returns None, or a verdict tuple (reason, evidence_count, first_time)
        where first_time is when the attacker started producing the evidence.
        """
        events = self.history[src]
        events.append((now, dst, dst_port))
        while now - events[0][0] > self.window:          # slide the window
            events.popleft()

        # port scan: many DIFFERENT destination ports / hosts
        targets = set()
        for t, d, p in reversed(events):
            targets.add((d, p))
            if len(targets) >= self.max_ports:
                return ("PORT_SCAN", len(targets), t)

        # connection flood: many new connections, even to the same port
        if len(events) >= self.max_new_conns:
            return ("CONN_FLOOD", len(events), events[-self.max_new_conns][0])
        return None

    def denied(self, src, now):
        """Record one connection that a DENY rule stopped.  Too many in the
        window -> the host keeps trying what it is not allowed to do."""
        times = self.denials[src]
        times.append(now)
        while now - times[0] > self.window:
            times.popleft()
        if len(times) >= self.max_denied:
            return ("POLICY_VIOLATION", len(times), times[-self.max_denied])
        return None

    def forget(self, src):
        self.history.pop(src, None)
        self.denials.pop(src, None)
