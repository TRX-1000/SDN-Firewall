#!/usr/bin/env bash
# One-time setup on Ubuntu 26.04 (also fine on 22.04 / 24.04).
set -e
cd "$(dirname "$0")/.."

sudo apt update
sudo apt install -y mininet openvswitch-switch python3-matplotlib git ethtool netcat-openbsd
sudo systemctl enable --now openvswitch-switch

# POX controller ('ichthyosaur' is the newest branch, works with Python 3.14)
[ -f pox/pox.py ] || git clone https://github.com/noxrepo/pox.git pox
(cd pox && git checkout -q ichthyosaur 2>/dev/null || true)

mkdir -p logs results
python3 -m unittest discover -s tests

echo "--- Mininet self-check ---"
sudo mn -c >/dev/null 2>&1 || true
if sudo mn --switch ovsbr --controller none --test pingall; then
  echo "OK: Mininet works.  Next: see README section 'Run it'."
else
  sudo mn -c >/dev/null 2>&1 || true
  sudo mn --switch ovsbr,datapath=user --controller none --test pingall && \
    echo "Only the userspace switch works: add --userspace to the topology command."
fi
sudo mn -c >/dev/null 2>&1 || true
