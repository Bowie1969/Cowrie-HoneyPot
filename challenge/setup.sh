#!/bin/bash
# Cowrie CHALLENGE instance setup - run as root on the droplet.
# Reuses the existing cowrie venv (from the blackhat instance) and creates a
# second, independent state directory /opt/challenge serving on port 2222.
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")" && pwd)"

echo "== [1/5] state dir =="
mkdir -p /opt/challenge
chown cowrie:cowrie /opt/challenge

echo "== [2/5] cowrie init (creates etc/cowrie.cfg + var skeleton) =="
sudo -u cowrie bash -s <<'EOF'
set -euo pipefail
cd /opt/challenge
export PATH=/opt/cowrie/cowrie-env/bin:$PATH
if [ ! -f etc/cowrie.cfg ]; then /opt/cowrie/cowrie-env/bin/cowrie init; fi
EOF

echo "== [3/5] deploy config (as root; bundle lives under /root) =="
cp "$BUNDLE/cowrie.cfg"    /opt/challenge/etc/cowrie.cfg
cp "$BUNDLE/userdb.txt"    /opt/challenge/etc/userdb.txt
cp "$BUNDLE/augment_fs.py" /opt/challenge/augment_fs.py
chown -R cowrie:cowrie /opt/challenge

echo "== [4/5] build challenge filesystem (as cowrie) =="
sudo -u cowrie bash -s <<'EOF'
set -euo pipefail
cd /opt/challenge
/opt/cowrie/cowrie-env/bin/python augment_fs.py /opt/challenge/custom.pickle
EOF
chown -R cowrie:cowrie /opt/challenge

echo "== [5/5] systemd unit + firewall + start =="
cp "$BUNDLE/cowrie-challenge.service" /etc/systemd/system/cowrie-challenge.service
systemctl daemon-reload
ufw allow 2222/tcp >/dev/null 2>&1
systemctl enable --now cowrie-challenge
sleep 4
echo "challenge: $(systemctl is-active cowrie-challenge)"
ss -tlnp 2>/dev/null | grep ":2222 " || echo "(not listening on 2222)"
