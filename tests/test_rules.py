"""Unit tests for the firewall logic (no Mininet needed).
Run:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "controller"))
from rules import Detector, Policy, load_config  # noqa: E402


class PolicyTests(unittest.TestCase):
    def setUp(self):
        cfg = load_config(os.path.join(ROOT, "config", "policy.json"))
        self.policy = Policy(cfg["rules"], cfg["default_action"])

    def test_service_port_open_to_lan(self):
        for host in ("10.0.0.1", "10.0.0.2", "10.0.0.4"):
            self.assertEqual(self.policy.check(host, "10.0.0.100", 8080),
                             ("allow", "R3", "SERVICE"))

    def test_admin_port_depends_on_source(self):
        self.assertEqual(self.policy.check("10.0.0.1", "10.0.0.100", 2222)[0], "allow")
        self.assertEqual(self.policy.check("10.0.0.2", "10.0.0.100", 2222),
                         ("deny", "R2", "ADMIN"))

    def test_telnet_denied_to_any_destination(self):
        self.assertEqual(self.policy.check("10.0.0.2", "10.0.0.3", 23)[0], "deny")

    def test_default_action(self):
        self.assertEqual(self.policy.check("10.0.0.2", "10.0.0.3", 5555),
                         ("allow", "DEFAULT", "OTHER"))


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.d = Detector(window_sec=5, max_new_conns=25, max_ports=8)

    def test_normal_client_never_flagged(self):
        for i in range(200):                       # 2 connections/s for 100 s
            self.assertIsNone(self.d.new_connection("10.0.0.2", "10.0.0.100", 8080, i * 0.5))

    def test_connection_flood(self):
        verdict = None
        for i in range(25):                        # 25 connections in 0.24 s
            verdict = self.d.new_connection("10.0.0.4", "10.0.0.100", 8080, 100 + i * 0.01)
        self.assertEqual(verdict[0], "CONN_FLOOD")
        self.assertEqual(verdict[2], 100)          # evidence started at the first SYN

    def test_port_scan(self):
        verdict = None
        for port in range(1, 9):                   # 8 different ports
            verdict = self.d.new_connection("10.0.0.4", "10.0.0.100", port, port * 0.01)
        self.assertEqual(verdict[0], "PORT_SCAN")

    def test_old_events_leave_the_window(self):
        for port in range(1, 8):                   # 7 ports ...
            self.d.new_connection("h", "srv", port, 0)
        for port in range(8, 15):                  # ... and 7 more 10 s later
            self.assertIsNone(self.d.new_connection("h", "srv", port, 10))

    def test_repeated_denied_access(self):
        for i in range(4):                         # 4 denied attempts: still ok
            self.assertIsNone(self.d.denied("10.0.0.2", i * 0.5))
        self.assertEqual(self.d.denied("10.0.0.2", 2.0)[0], "POLICY_VIOLATION")

    def test_sources_are_independent(self):
        for i in range(20):
            self.d.new_connection("10.0.0.2", "srv", 8080, i * 0.01)
            self.assertIsNone(self.d.new_connection("10.0.0.3", "srv", 8080, i * 0.01))


if __name__ == "__main__":
    unittest.main()
