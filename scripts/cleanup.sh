#!/usr/bin/env bash
# Stop everything and clean Mininet leftovers (after Ctrl+C or a crash).
#   ./scripts/cleanup.sh          keep logs/ and results/
#   ./scripts/cleanup.sh --all    also delete logs/ and results/ (fresh start)
sudo pkill -f "[p]ox.py"
sudo pkill -f "[l]ogger_server.py"
sudo pkill -f "[a]pp/server.py"
sudo pkill -f "[t]raffic/attacker.py"
sudo mn -c >/dev/null 2>&1
if [ "$1" = "--all" ]; then
  cd "$(dirname "$0")/.." && sudo rm -rf logs results
  echo "logs/ and results/ deleted"
fi
echo "clean"
