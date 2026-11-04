#!/usr/bin/env python3
"""
Centralized security-event logger (TCP server, port 9999).

The SDN controller connects and sends one JSON object per line, e.g.
  {"time": "19:31:05", "source": "sdn-controller", "type": "BLOCK",
   "src": "10.0.0.4", "reason": "CONN_FLOOD", "evidence": 25}

The logger accepts several senders at once (one thread per connection),
numbers every event, prints it and appends it to
  logs/security_events.log     (human readable)
  logs/security_events.jsonl   (one JSON object per line, for scripts)
Ctrl+C prints a summary (events per type).

Run:  python3 app/logger_server.py
"""

import argparse
import collections
import json
import os
import socket
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SecurityLogger:
    def __init__(self, logdir):
        os.makedirs(logdir, exist_ok=True)
        self.text = open(os.path.join(logdir, "security_events.log"), "a", buffering=1)
        self.jsonl = open(os.path.join(logdir, "security_events.jsonl"), "a", buffering=1)
        self.lock = threading.Lock()        # several threads write the same files
        self.count = 0
        self.by_type = collections.Counter()

    def store(self, event, peer):
        with self.lock:
            self.count += 1
            event["seq"] = self.count
            self.by_type[event.get("type", "?")] += 1
            details = " ".join("%s=%s" % (k, v) for k, v in event.items()
                               if k not in ("time", "ts", "source", "type", "seq"))
            line = "#%-4d %s %-15s %-16s %s" % (self.count, event.get("time", "?"),
                                                event.get("source", peer),
                                                event.get("type", "?"), details)
            print(line, flush=True)
            self.text.write(line + "\n")
            self.jsonl.write(json.dumps(event) + "\n")

    def handle_client(self, conn, addr):
        peer = "%s:%d" % addr
        print("[logger] %s connected" % peer, flush=True)
        with conn, conn.makefile("rb") as stream:   # makefile gives us readline()
            for raw in stream:                      # one line = one event
                try:
                    event = json.loads(raw)
                    if not isinstance(event, dict) or "type" not in event:
                        raise ValueError
                except ValueError:
                    event = {"type": "MALFORMED_INPUT", "source": "logger",
                             "from": peer, "sample": raw[:60].decode(errors="replace")}
                self.store(event, peer)
        print("[logger] %s disconnected" % peer, flush=True)


def main():
    ap = argparse.ArgumentParser(description="Centralized security-event logger")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--logdir", default=os.path.join(ROOT, "logs"))
    args = ap.parse_args()

    logger = SecurityLogger(args.logdir)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(16)
    print("[logger] listening on %s:%d, writing %s/security_events.log" %
          (args.host, args.port, args.logdir), flush=True)
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=logger.handle_client, args=(conn, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print("\n[logger] %d events: %s" % (logger.count, dict(logger.by_type)), flush=True)


if __name__ == "__main__":
    main()
