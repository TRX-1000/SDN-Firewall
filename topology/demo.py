"""
Guided demo: press Enter for each step and the commands are typed and run
for you, exactly as if you had typed them at the mininet> prompt.
After each step it tells you what to point out in Terminals 1 and 2.

Easiest: run  bash scripts/demo.sh  - it opens all three "terminals" on one
screen (tmux panes) and starts this guide.  Inside tmux the guide can also
stop/restart the logger and the controller by itself (steps h and i).

Manual start from Terminal 3 (logger and controller already running):
    sudo python3 topology/topo.py --demo          press Enter per step
    sudo python3 topology/topo.py --demo --auto   hands-free
    sudo python3 topology/topo.py --demo --from e resume at step e
At any prompt:  Enter = run the step,  s = skip it,  q = stop the guide
(you then get the normal mininet> prompt).
"""

import os
import subprocess
import tempfile
import time

from mininet.cli import CLI
from mininet.log import setLogLevel

BOLD, BLUE, GREEN, YELLOW, GREY, RESET = ("\033[1m", "\033[94m", "\033[92m",
                                          "\033[93m", "\033[90m", "\033[0m")

# Each step: key, title, commands (typed at mininet>), then what to point out.
# "%stop X" / "%start X" stop or start the logger / controller (done for you
# inside tmux, otherwise you are told what to do); "@" = built-in wait.
STEPS = [
    ("a", "Topology and normal TCP traffic",
     ["net",
      "h2 python3 app/client.py --count 5",
      "h2 python3 app/client.py --count 8 --parallel 4 --rate 1",
      'h3 python3 app/client.py --count 3 --request "DATA 1000000"'],
     "5 ok; 4 clients at once, each 8/8 ok; ~9-10 Mbit/s over the 10 Mbit/s link.\n"
     "Say: every request is a NEW TCP connection, so its first packet goes to the\n"
     "controller (packet-in), which classifies it before the switch forwards it."),

    ("b", "Classification by source, destination and port",
     ["h1 python3 app/client.py --port 2222 --request STATS --count 1",
      "h2 python3 app/client.py --port 2222 --request STATS --count 1",
      "h2 nc -zv -w 2 10.0.0.3 23",
      "h2 nc -zv -w 2 10.0.0.3 5555"],
     "h1 allowed on the admin port (rule R1), h2 denied (R2) -> same port, different source.\n"
     "Port 23 dropped (R4 telnet), port 5555 'refused' = allowed (nothing listening).\n"
     "Terminal 2: DENY lines with the rule.   Terminal 1: DENY events."),

    ("c", "Connection flood -> automatic block",
     ["h4 python3 traffic/attacker.py flood --duration 2",
      "sh ovs-ofctl dump-flows s1 | grep priority=60000",
      "h4 ping -c 2 10.0.0.100",
      "h2 python3 app/client.py --count 3"],
     "Terminal 2: BLOCK 10.0.0.4 CONN_FLOOD, offence #1, 20 s, and 'response ... ms'.\n"
     "The switch now holds the drop rule (priority=60000 ... actions=drop),\n"
     "h4 is cut off (100% ping loss) while h2 is still served."),

    ("d", "Automatic recovery",
     ["@wait-unblock 10.0.0.4",
      "h4 ping -c 2 10.0.0.100"],
     "The switch removed the rule by itself (hard_timeout); h4 is reachable again.\n"
     "Terminal 2: RECOVERY ... packets were dropped.   Terminal 1: UNBLOCK."),

    ("e", "Repeat offender gets a longer block",
     ["h4 python3 traffic/attacker.py flood --duration 2",
      "sh ovs-ofctl dump-flows s1 | grep priority=60000"],
     "Terminal 2: offence #2, blocked for 40s.  The rule shows hard_timeout=40."),

    ("f", "Port scan -> automatic block",
     ["h3 python3 traffic/attacker.py scan"],
     "open ports found: none - h3 was blocked after 8 probes.\n"
     "Terminal 2: BLOCK 10.0.0.3 PORT_SCAN with its response time."),

    ("g", "Repeated denied access -> whole host blocked",
     ["h2 python3 app/client.py --port 2222 --request STATS --count 6 --rate 2 --timeout 1",
      "h2 python3 app/client.py --count 2 --timeout 1"],
     "5 DENYs, then BLOCK 10.0.0.2 POLICY_VIOLATION (Terminal 2).\n"
     "h2 can no longer reach even the normal service on port 8080.\n"
     "(Detection takes ~4 s here: h2 only tries once per second, and it takes 5 tries.)"),

    ("h", "Robustness: security logger outage",
     ["%stop logger",
      "h1 nc -zv -w 1 10.0.0.3 23",
      "@sleep 2",
      "%start logger",
      "@sleep 4"],
     "While the logger was down, Terminal 2 said 'not reachable - buffering events'.\n"
     "After the restart, Terminal 1 received the DENY 10.0.0.1 -> 10.0.0.3:23 that\n"
     "happened during the outage - no event was lost."),

    ("i", "Robustness: controller crash (fail-closed)",
     ["%stop controller",
      "h1 python3 app/client.py --count 2 --timeout 1",
      "%start controller",
      "@wait-switch",
      "h1 python3 app/client.py --count 2"],
     "With the controller down the requests FAILED: the switch forwards no new flows\n"
     "without it (failMode=secure, the firewall fails closed). After the restart the\n"
     "switch reconnected and traffic flows again."),

    ("j", "The centralized security log",
     ["sh tail -n 25 logs/security_events.log"],
     "Every DENY, BLOCK, BLOCK_ENFORCED and UNBLOCK of this demo, from one TCP logger."),

    ("k", "Results (performance evaluation)",
     ["@results"],
     "fig1: static vs dynamic for normal users;  fig2: latency over time during a flood;\n"
     "fig3: blocking response time vs attack rate.  Median of 3 runs each."),
]


PANES = {"logger": os.environ.get("FW_PANE_LOGGER"),
         "controller": os.environ.get("FW_PANE_CONTROLLER")}
START = {"logger": "python3 app/logger_server.py",
         "controller": "./scripts/start_controller.sh"}
TERMINAL = {"logger": "TERMINAL 1", "controller": "TERMINAL 2"}


def say(text, color=""):
    print(color + text + RESET, flush=True)


def ask(prompt):
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return "q"


def wait_unblock(ip, limit=60):
    """Wait until the switch has removed the block rule for ip."""
    for remaining in range(limit, 0, -1):
        flows = subprocess.run(["ovs-ofctl", "dump-flows", "s1"],
                               capture_output=True, text=True).stdout
        if "nw_src=%s" % ip not in flows:
            print()
            say("   The block rule for %s is gone - the switch removed it by itself." % ip,
                GREEN)
            time.sleep(1)
            return
        print("\r   waiting for the block on %s to expire ... %2d s " % (ip, remaining),
              end="", flush=True)
        time.sleep(1)
    print()


def wait_switch(net, limit=40):
    sw = net.get("s1")
    for _ in range(limit * 2):
        if sw.connected():
            time.sleep(1)
            say("   Switch s1 is connected to the controller again.", GREEN)
            return
        print("\r   waiting for s1 to reconnect to the controller ...", end="", flush=True)
        time.sleep(0.5)
    print()
    say("   s1 did not reconnect - is the controller running in Terminal 2?", YELLOW)


def stop_start(action, what, auto):
    """Stop or start the logger/controller: automatically inside tmux,
    otherwise tell the presenter what to do."""
    pane = PANES.get(what)
    if pane:
        if action == "stop":
            say("\n>> Stopping the %s (%s), like pressing Ctrl+C there ..." %
                (what, TERMINAL[what]), BOLD + YELLOW)
            subprocess.run(["tmux", "send-keys", "-t", pane, "C-c"])
        else:
            say("\n>> Restarting the %s (%s) ..." % (what, TERMINAL[what]), BOLD + YELLOW)
            subprocess.run(["tmux", "send-keys", "-t", pane, START[what], "Enter"])
        time.sleep(2)
        return
    if action == "stop":
        say("\n>> Go to %s and press Ctrl+C (the %s stops)." % (TERMINAL[what], what),
            BOLD + YELLOW)
    else:
        say("\n>> Restart the %s in %s: press Up-arrow, then Enter." % (what, TERMINAL[what]),
            BOLD + YELLOW)
    ask("   (press Enter when done) ")


def show_results(root):
    for folder in ("docs/results", "results/experiments"):
        full = os.path.join(root, folder, "results.md")
        if os.path.exists(full):
            say("mininet> sh cat %s/results.md" % folder, BOLD + BLUE)
            print(open(full).read())
            open_charts(os.path.join(root, folder))
            return
    say("   No results yet - run  bash scripts/run_everything.sh  first.", YELLOW)


def open_charts(folder):
    """Open the 3 charts in the image viewer, as the normal (non-root) user."""
    charts = [os.path.join(folder, f) for f in ("fig1_normal_users.png",
              "fig2_flood_timeline.png", "fig3_response_time.png")]
    charts = [c for c in charts if os.path.exists(c)]
    user = os.environ.get("SUDO_USER")
    gui = {k: os.environ[k] for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                                      "DBUS_SESSION_BUS_ADDRESS") if os.environ.get(k)}
    if not charts:
        return
    if user and gui:
        for c in charts:
            subprocess.Popen(["runuser", "-u", user, "--", "env"] +
                             ["%s=%s" % kv for kv in gui.items()] + ["xdg-open", c],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        say("   Opened the 3 charts in the image viewer.", GREEN)
    else:
        say("   Charts: open %s/fig1..fig3 from the Files app." % folder, YELLOW)


def run_demo(net, root, start="a", auto=False, pause=6):
    setLogLevel("output")                       # hide Mininet's info chatter
    empty = tempfile.NamedTemporaryFile("w", suffix=".mn", delete=False)
    empty.close()
    cli = CLI(net, script=empty.name)           # a CLI we can feed commands to
    os.unlink(empty.name)

    keys = [s[0] for s in STEPS]
    first = keys.index(start) if start in keys else 0
    say("\n" + "=" * 70, BOLD)
    if auto:
        say(" AUTOMATIC DEMO - runs every step by itself (Ctrl+C to stop)", BOLD)
    else:
        say(" GUIDED DEMO - Enter = run step, s = skip, q = stop and get mininet>", BOLD)
    say("=" * 70, BOLD)
    for key, title, commands, point_out in STEPS[first:]:
        say("\n[%s] %s" % (key, title), BOLD + YELLOW)
        for cmd in commands:
            if not cmd.startswith(("%", "@")):
                say("      " + cmd, GREY)
        if auto:
            time.sleep(2)
        else:
            choice = ask("   Enter = run, s = skip, q = stop > ")
            if choice == "q":
                break
            if choice == "s":
                continue
        for cmd in commands:
            if cmd.startswith("%"):
                action, what = cmd[1:].split()
                stop_start(action, what, auto)
            elif cmd.startswith("@wait-unblock"):
                wait_unblock(cmd.split()[1])
            elif cmd == "@wait-switch":
                wait_switch(net)
            elif cmd.startswith("@sleep"):
                time.sleep(float(cmd.split()[1]))
            elif cmd == "@results":
                show_results(root)
            else:
                say("\nmininet> " + cmd, BOLD + BLUE)
                cli.onecmd(cmd)
        say("\n   POINT OUT: " + point_out.replace("\n", "\n              "), GREEN)
        if auto:
            time.sleep(pause)
    say("\nGuide finished - normal mininet> prompt below "
        "(type 'exit' when you are done).", BOLD)
    setLogLevel("info")
