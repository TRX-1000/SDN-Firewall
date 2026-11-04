#!/usr/bin/env bash
# ONE command for everything before the demo (about 25 minutes, unattended):
#   installs anything missing, cleans up, runs the unit tests, the 12-point
#   system check, the experiments (3 runs each) and makes the charts.
#
#   bash scripts/run_everything.sh          (asks for your password once)
#
# Keep the laptop plugged in. The VM is kept awake automatically.
# Everything it prints is also saved in run_everything.log.
cd "$(dirname "$0")/.." || exit 1
if [ "$(id -u)" != 0 ]; then
  exec sudo bash scripts/run_everything.sh "$@"
fi
PROJECT="$(pwd)"
OWNER="${SUDO_UID:-0}:${SUDO_GID:-0}"
exec > >(tee "$PROJECT/run_everything.log") 2>&1

step() { echo; echo "=================================================================="; echo " $*"; echo "=================================================================="; }
# keep the VM awake while a long step runs (falls back to plain run if unavailable)
awake() {
  if command -v systemd-inhibit >/dev/null && systemd-inhibit --what=idle:sleep --why=x true 2>/dev/null; then
    systemd-inhibit --what=idle:sleep --why="SDN firewall tests" "$@"
  else
    "$@"
  fi
}
fail() {
  echo; echo "!!! FAILED: $* - the full output is in run_everything.log"
  chown -R "$OWNER" "$PROJECT"
  exit 1
}

step "1/6  Checking requirements"
missing=""
command -v mn >/dev/null        || missing="$missing mininet"
command -v ovs-vsctl >/dev/null || missing="$missing openvswitch-switch"
command -v tmux >/dev/null      || missing="$missing tmux"
command -v nc >/dev/null        || missing="$missing netcat-openbsd"
command -v ethtool >/dev/null   || missing="$missing ethtool"
command -v git >/dev/null       || missing="$missing git"
python3 -c "import matplotlib" 2>/dev/null || missing="$missing python3-matplotlib"
if [ -n "$missing" ]; then
  echo "installing:$missing"
  apt-get update
  apt-get install -y $missing || {
    add-apt-repository -y universe && apt-get update && apt-get install -y $missing; } \
    || fail "could not install:$missing (check the internet connection)"
else
  echo "all packages present"
fi
systemctl enable --now openvswitch-switch >/dev/null 2>&1 || true
if [ ! -f pox/pox.py ]; then
  echo "downloading POX ..."
  git clone -q https://github.com/noxrepo/pox.git pox || fail "could not download POX"
fi
(cd pox && git checkout -q ichthyosaur 2>/dev/null || true)
echo "POX ready"

step "2/6  Cleaning up old processes and Mininet leftovers"
bash scripts/cleanup.sh

step "3/6  Unit tests"
python3 -m unittest discover -s tests || fail "unit tests"

step "4/6  System check (12 end-to-end tests, ~1.5 min)"
awake python3 tests/system_check.py || fail "system check"

step "5/6  Experiments: static vs dynamic, 3 runs each (~18 min, do not close)"
awake python3 experiments/run_experiments.py --repeat 3 || fail "experiments"

step "6/6  Charts and tables"
python3 experiments/plot_results.py || fail "charts"
mkdir -p docs/results
cp results/experiments/results.md results/experiments/fig*.png \
   results/system_check/report.md docs/results/
bash scripts/cleanup.sh >/dev/null 2>&1
chown -R "$OWNER" "$PROJECT"

step "ALL DONE"
echo "Test report : docs/results/report.md"
echo "Results     : docs/results/results.md"
echo "Charts      : docs/results/fig1_normal_users.png, fig2_flood_timeline.png, fig3_response_time.png"
echo
grep -E "passed" docs/results/report.md
echo
echo "Next, for the live demo:   bash scripts/demo.sh"
