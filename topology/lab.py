"""
Helper for the automated scripts (tests/system_check.py and
experiments/run_experiments.py): starts the logger, the POX controller
and the Mininet network in one go, and stops them again.
You do not need this file for the manual demo.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from topology.topo import build_network, give_back, start_server  # noqa: E402

PY = os.environ.get("FW_PYTHON", "python3")
POX = os.environ.get("POX_DIR", os.path.join(ROOT, "pox"))


def port_in_use(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        return True
    except OSError:
        return False


def wait_port(port, proc, what):
    for _ in range(75):
        if port_in_use(port):
            return
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    raise SystemExit("%s did not start" % what)


class Lab:
    def __init__(self, mode, outdir, userspace=None, **settings):
        from mininet.log import setLogLevel
        setLogLevel("warning")
        for port, what in ((6633, "a controller"), (9999, "a logger")):
            if port_in_use(port):
                raise SystemExit("%s is already running on port %d - stop it first "
                                 "(./scripts/cleanup.sh)" % (what, port))
        if userspace is None:
            userspace = bool(os.environ.get("FW_USERSPACE"))
        shutil.rmtree(outdir, ignore_errors=True)    # start clean: no data from old runs
        os.makedirs(outdir)
        self.outdir = outdir
        with open(os.path.join(ROOT, "config", "policy.json")) as f:
            cfg = json.load(f)
        cfg.update(settings)              # e.g. block_seconds=8 for quick tests
        config = os.path.join(outdir, "policy.json")
        with open(config, "w") as f:
            json.dump(cfg, f, indent=2)

        self.logger = subprocess.Popen(
            [PY, "-u", os.path.join(ROOT, "app", "logger_server.py"),
             "--logdir", os.path.join(outdir, "logs")],
            stdout=open(os.path.join(outdir, "logger.txt"), "w"), stderr=subprocess.STDOUT)
        wait_port(9999, self.logger, "logger")
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "controller"))
        self.pox = subprocess.Popen(
            [PY, "-u", os.path.join(POX, "pox.py"), "log.level", "--INFO", "firewall",
             "--mode=" + mode, "--config=" + config,
             "--metrics=" + os.path.join(outdir, "blocks.csv")],
            stdout=open(os.path.join(outdir, "controller.txt"), "w"),
            stderr=subprocess.STDOUT, env=env, cwd=ROOT)
        self.net = self.server = None
        try:
            wait_port(6633, self.pox, "POX (is it in ./pox ?)")
            self.net = build_network(userspace)
            self.server = start_server(self.net, os.path.join(outdir, "server.txt"), PY)
            self.net.pingAll(timeout=1)
        except BaseException:
            self.stop()
            raise

    def py(self, script, *args):
        return [PY, "-u", os.path.join(ROOT, script)] + [str(a) for a in args]

    def run(self, host, args, timeout=120):
        """Run a command on a Mininet host and return its output."""
        p = self.net.get(host).popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=ROOT)
        try:
            return p.communicate(timeout=timeout)[0].decode(errors="replace")
        except subprocess.TimeoutExpired:
            p.kill()
            return p.communicate()[0].decode(errors="replace")

    def start(self, host, args):
        return self.net.get(host).popen(args, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.STDOUT, cwd=ROOT)

    def events(self):
        path = os.path.join(self.outdir, "logs", "security_events.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def stop(self):
        if self.server:
            self.server.terminate()
        if self.net:
            self.net.stop()
        for p in (self.pox, self.logger):
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        give_back(os.path.join(ROOT, "results"))
