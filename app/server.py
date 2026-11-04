#!/usr/bin/env python3
"""
Multi-client TCP server (runs on host srv, 10.0.0.100).

Listens on two ports with the same protocol:
   8080  service port - open to the whole LAN        (rule R3)
   2222  admin port   - the firewall only lets h1 in (rules R1/R2)

Protocol: one text line per request, one line per reply.
   PING          -> PONG <server time>
   ECHO <text>   -> ECHO <text>
   DATA <n>      -> DATA <n>   followed by n raw bytes  (bulk transfer)
   STATS         -> STATS <json counters>
   QUIT          -> BYE   (server closes the connection)

Concurrency: one thread per client.  At most --max-clients at the same
time (a semaphore); extra clients get "ERR BUSY" - this is what
overload looks like during a flood.

Run inside Mininet:  srv python3 app/server.py &     (topology does this)
"""

import argparse
import collections
import json
import socket
import threading
import time

PAYLOAD = b"x" * 65536


class Server:
    def __init__(self, max_clients, idle_timeout):
        self.slots = threading.BoundedSemaphore(max_clients)
        self.idle_timeout = idle_timeout
        self.lock = threading.Lock()
        self.stats = collections.Counter()
        self.per_ip = collections.Counter()

    def listen(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(128)
        print("[server] listening on port %d" % port, flush=True)
        threading.Thread(target=self.accept_loop, args=(sock,), daemon=True).start()

    def accept_loop(self, sock):
        while True:
            conn, addr = sock.accept()                          # wait for a client
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        with self.lock:
            self.stats["connections"] += 1
            self.per_ip[addr[0]] += 1
        if not self.slots.acquire(blocking=False):              # too many clients
            with self.lock:
                self.stats["busy_rejects"] += 1
            conn.sendall(b"ERR BUSY\n")
            conn.close()
            return
        try:
            conn.settimeout(self.idle_timeout)                  # drop idle clients
            stream = conn.makefile("rb")
            while True:
                line = stream.readline(1024)                    # one request per line
                if not line:
                    break                                       # client closed
                if not self.reply(conn, line.decode(errors="replace").strip()):
                    break
        except OSError:                                         # timeout / reset
            with self.lock:
                self.stats["errors"] += 1
        finally:
            self.slots.release()
            conn.close()

    def reply(self, conn, line):
        """Answer one request.  Returns False when the client said QUIT."""
        cmd, _, arg = line.partition(" ")
        cmd = cmd.upper()
        with self.lock:
            self.stats["requests"] += 1
        if cmd == "PING":
            conn.sendall(b"PONG %.3f\n" % time.time())
        elif cmd == "ECHO":
            conn.sendall(("ECHO %s\n" % arg).encode())
        elif cmd == "DATA":
            if not arg.isdigit():
                conn.sendall(b"ERR usage: DATA <bytes>\n")
                return True
            n = min(int(arg), 10_000_000)
            conn.sendall(b"DATA %d\n" % n)
            while n > 0:                                        # send n raw bytes
                chunk = PAYLOAD[:min(n, len(PAYLOAD))]
                conn.sendall(chunk)
                n -= len(chunk)
        elif cmd == "STATS":
            with self.lock:
                text = json.dumps({"stats": dict(self.stats), "per_ip": dict(self.per_ip)})
            conn.sendall(("STATS %s\n" % text).encode())
        elif cmd == "QUIT":
            conn.sendall(b"BYE\n")
            return False
        else:
            conn.sendall(b"ERR unknown command\n")
        return True


def main():
    ap = argparse.ArgumentParser(description="Multi-client TCP server")
    ap.add_argument("--ports", default="8080,2222")
    ap.add_argument("--max-clients", type=int, default=50)
    ap.add_argument("--idle-timeout", type=float, default=10)
    args = ap.parse_args()

    server = Server(args.max_clients, args.idle_timeout)
    for port in args.ports.split(","):
        server.listen(int(port))
    last = None
    while True:                                   # print counters when they change
        time.sleep(5)
        with server.lock:
            now = (dict(server.stats), dict(server.per_ip))
        if now != last:
            print("[server] %s  per client: %s" % now, flush=True)
            last = now


if __name__ == "__main__":
    main()
