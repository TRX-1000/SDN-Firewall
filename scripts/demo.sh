#!/usr/bin/env bash
# ONE command for the live demo. Opens all three "terminals" on one screen:
#
#   +------------------------------+------------------------------+
#   | TERMINAL 1  security logger  | TERMINAL 2  SDN controller   |
#   +------------------------------+------------------------------+
#   | TERMINAL 3  Mininet - the guided demo runs here             |
#   +-------------------------------------------------------------+
#
#   bash scripts/demo.sh          press Enter for each step (recommended)
#   bash scripts/demo.sh auto     every step runs by itself
#   bash scripts/demo.sh from e   restart the guide at step e
#
# The guide stops/restarts the logger and controller by itself (steps h, i).
# At the end it opens the charts. Type  exit  at the mininet> prompt to finish;
# everything is then stopped and cleaned up automatically.
# Tip: maximise the terminal window first. Ctrl + minus makes the text smaller.
cd "$(dirname "$0")/.." || exit 1
if [ "$(id -u)" != 0 ]; then
  # keep the desktop session variables so the guide can open the charts
  exec sudo DISPLAY="$DISPLAY" WAYLAND_DISPLAY="$WAYLAND_DISPLAY" \
       XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
       bash scripts/demo.sh "$@"
fi
PROJECT="$(pwd)"
OWNER="${SUDO_UID:-0}:${SUDO_GID:-0}"

GUIDE_ARGS="--demo"
case "$1" in
  auto) GUIDE_ARGS="--demo --auto" ;;
  from) GUIDE_ARGS="--demo --from ${2:-a}" ;;
esac
[ -n "$FW_USERSPACE" ] && GUIDE_ARGS="$GUIDE_ARGS --userspace"

command -v tmux >/dev/null || apt-get install -y tmux
if [ ! -f pox/pox.py ]; then
  echo "POX is missing - run  bash scripts/run_everything.sh  first."; exit 1
fi

echo "Cleaning up ..."
bash scripts/cleanup.sh >/dev/null 2>&1
tmux kill-session -t sdn 2>/dev/null

# three panes: logger (top-left), controller (top-right), Mininet (bottom)
LOGGER=$(tmux new-session -d -s sdn -c "$PROJECT" -P -F '#{pane_id}')
CONTROLLER=$(tmux split-window -h -t "$LOGGER" -c "$PROJECT" -P -F '#{pane_id}')
MININET=$(tmux split-window -v -f -l 60% -t "$CONTROLLER" -c "$PROJECT" -P -F '#{pane_id}')
tmux set -t sdn mouse on >/dev/null
tmux set -t sdn pane-border-status top >/dev/null
tmux set -t sdn pane-border-format " #{pane_title} " >/dev/null
tmux set -t sdn status off >/dev/null
tmux select-pane -t "$LOGGER" -T "TERMINAL 1 - security logger"
tmux select-pane -t "$CONTROLLER" -T "TERMINAL 2 - SDN controller (firewall)"
tmux select-pane -t "$MININET" -T "TERMINAL 3 - Mininet (guided demo)"

tmux send-keys -t "$LOGGER" "clear; python3 app/logger_server.py" Enter
sleep 1
tmux send-keys -t "$CONTROLLER" "clear; ./scripts/start_controller.sh" Enter
sleep 3
tmux send-keys -t "$MININET" "clear; FW_PANE_LOGGER=$LOGGER FW_PANE_CONTROLLER=$CONTROLLER python3 topology/topo.py $GUIDE_ARGS; tmux kill-session -t sdn" Enter
tmux select-pane -t "$MININET"

if [ -t 1 ]; then
  tmux attach -t sdn
else                      # not a real terminal (testing): wait for the end
  while tmux has-session -t sdn 2>/dev/null; do sleep 1; done
fi

echo "Stopping everything and cleaning up ..."
bash scripts/cleanup.sh >/dev/null 2>&1
chown -R "$OWNER" "$PROJECT"
echo "Demo finished. The security log is in logs/security_events.log"
