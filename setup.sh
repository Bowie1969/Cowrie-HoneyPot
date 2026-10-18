#!/bin/bash
# Cowrie honeypot setup — run as root on the droplet (scp'd up to /root/cowrie-bundle/).
#
# Does the base install and config. It deliberately does NOT touch sshd or start
# cowrie: those are done separately, with connectivity verification, so we can't
# lock ourselves out of the box.
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive

echo "== [1/6] apt packages =="
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv libssl-dev libffi-dev \
  build-essential libpython3-dev python3-minimal authbind fail2ban ufw \
  curl wget >/dev/null

echo "== [2/6] swap (pip/apt need headroom on a 512MB droplet) =="
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "== [3/6] cowrie user =="
id -u cowrie >/dev/null 2>&1 || adduser --disabled-password --gecos "" cowrie

echo "== [4/6] install cowrie (pip) =="
mkdir -p /opt/cowrie
chown cowrie:cowrie /opt/cowrie
sudo -u cowrie bash -s <<'EOF'
set -euo pipefail
cd /opt/cowrie
[ -d cowrie-env ] || python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install cowrie >/dev/null
if [ ! -f etc/cowrie.cfg ]; then cowrie init; fi
EOF

echo "== [5/6] deploy config + build juicy filesystem =="
cp "$BUNDLE/cowrie.cfg"    /opt/cowrie/etc/cowrie.cfg
cp "$BUNDLE/userdb.txt"    /opt/cowrie/etc/userdb.txt
cp "$BUNDLE/augment_fs.py" /opt/cowrie/augment_fs.py
chown -R cowrie:cowrie /opt/cowrie

sudo -u cowrie bash -s <<'EOF'
set -euo pipefail
cd /opt/cowrie
source cowrie-env/bin/activate
python augment_fs.py /opt/cowrie/custom.pickle
EOF

echo "== [6/6] authbind + systemd unit (not started yet) =="
touch /etc/authbind/byport/22
chown cowrie:cowrie /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22
cp "$BUNDLE/cowrie.service" /etc/systemd/system/cowrie.service
systemctl daemon-reload

echo "SETUP DONE. Next steps (separate, verified):"
echo "  1. move real sshd to port 2200"
echo "  2. systemctl enable --now cowrie"
echo "  3. verify port 22 answers with the honeypot banner"
