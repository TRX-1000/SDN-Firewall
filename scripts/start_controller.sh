#!/usr/bin/env bash
# Start the POX controller with our firewall component.
#   ./scripts/start_controller.sh           dynamic mode (proposed)
#   ./scripts/start_controller.sh static    baseline: static rules only
cd "$(dirname "$0")/.." || exit 1
MODE="${1:-dynamic}"
if [ ! -f pox/pox.py ]; then
  echo "POX is missing - run ./scripts/setup.sh first" >&2; exit 1
fi
PYTHONPATH="$(pwd)/controller" exec python3 pox/pox.py log.level --INFO \
    firewall --mode="$MODE" --config=config/policy.json --metrics=results/blocks.csv
