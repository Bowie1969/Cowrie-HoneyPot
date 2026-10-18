#!/usr/bin/env python3
"""
Augment the installed Cowrie fs.pickle for the CHALLENGE instance.

Same mechanism as the blackhat augment_fs.py: loads the installed package's
bundled fs.pickle as the base and injects files, writing a custom.pickle that
the challenge config points at via [shell] filesystem.

What's different here:
  * 4 flags hidden at escalating depth (flag2..flag4 as files; flag1 is in the MOTD).
  * Honeytoken files (fake keys/creds) that score as "detected" when touched.
  * A challenge MOTD that announces the game and hands out flag1.

Flag/canary paths here MUST stay in sync with score.py.
All content is fabricated.
"""
import os
import pickle
import sys
import time
from importlib.resources import files

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2
MTIME = 1638316800

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/challenge/custom.pickle"

FLAG1 = "flag{knock_knock}"
FLAG2 = "flag{home_is_where_the_flag_is}"
FLAG3 = "flag{root_of_all_evil}"
FLAG4 = "flag{ghost_mode}"


def find_node(tree, path):
    node = tree
    for part in [p for p in path.split("/") if p]:
        children = node[A_CONTENTS]
        if not isinstance(children, list):
            return None
        node = next((c for c in children if c[A_NAME] == part), None)
        if node is None:
            return None
    return node


def ensure_dir(tree, path):
    node = find_node(tree, path)
    if node is not None and node[A_TYPE] == T_DIR:
        return node
    cur = tree
    for part in [p for p in path.split("/") if p]:
        children = cur[A_CONTENTS]
        nxt = next((c for c in children if c[A_NAME] == part), None)
        if nxt is None:
            nxt = [part, T_DIR, 0, 0, 4096, 0o40755, MTIME, [], None, None]
            children.append(nxt)
        cur = nxt
    return cur


def set_file(tree, path, content, mode=0o100644):
    content = content.encode() if isinstance(content, str) else content
    parent, name = os.path.split(path)
    pnode = ensure_dir(tree, parent)
    children = pnode[A_CONTENTS]
    existing = next((c for c in children if c[A_NAME] == name), None)
    if existing is not None:
        existing[A_TYPE] = T_FILE
        existing[A_SIZE] = len(content)
        existing[A_MODE] = mode
        existing[A_CTIME] = MTIME
        existing[A_CONTENTS] = content
    else:
        children.append([name, T_FILE, 0, 0, len(content), mode, MTIME, content, None, None])


FILES = {
    # ---- OS identity (kept light but consistent) ----
    "/etc/hostname": "ctf-box\n",
    "/etc/debian_version": "buster/sid\n",
    "/etc/issue": "Ubuntu 18.04.6 LTS \\n \\l\n\n",
    "/etc/issue.net": "Ubuntu 18.04.6 LTS\n",
    "/etc/os-release": (
        'NAME="Ubuntu"\nVERSION="18.04.6 LTS (Bionic Beaver)"\nID=ubuntu\n'
        'ID_LIKE=debian\nPRETTY_NAME="Ubuntu 18.04.6 LTS"\nVERSION_ID="18.04"\n'
        "VERSION_CODENAME=bionic\nUBUNTU_CODENAME=bionic\n"
    ),
    "/etc/motd": (
        "==============================================================\n"
        "   FLAG HUNT CHALLENGE - 4 flags are hidden on this box.\n"
        "\n"
        "   RULES\n"
        "   -----\n"
        "   * Every command you run is logged.\n"
        "   * Some files are HONEYTOKENS: reading them counts as DETECTED.\n"
        "   * Brute-forcing, recon spam, and downloading payloads are NOISY.\n"
        "   * Score = flags captured - detection events. Be stealthy.\n"
        "\n"
        f"   FLAG 1 (freebie): {FLAG1}\n"
        "\n"
        "   Find flags 2, 3 and 4. Good luck - you're being watched.\n"
        "==============================================================\n"
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
        "ctf:x:1000:1000:CTF Player:/home/ctf:/bin/bash\n"
        "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
        "webapp:x:1002:1002:Web App:/home/webapp:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$bFj9Qk2X$0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f:18800:0:99999:7:::\n"
        "daemon:*:18353:0:99999:7:::\n"
        "www-data:*:18353:0:99999:7:::\n"
        "backup:*:18353:0:99999:7:::\n"
        "nobody:*:18353:0:99999:7:::\n"
        "sshd:*:18353:0:99999:7:::\n"
        "ctf:$6$CtFpLaYr$Xb7e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e:18800:0:99999:7:::\n"
        "deploy:$6$DePlOy$N9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c:18800:0:99999:7:::\n"
        "webapp:$6$WeBaPp$M1n2b3v4c5x6z7l8k9j0h1g2f3d4s5a6p7o8i9u0y1t2r3e4w5:18800:0:99999:7:::\n"
    ),
    "/etc/group": (
        "root:x:0:\ndaemon:x:1:\nwww-data:x:33:\nbackup:x:34:\n"
        "nobody:x:65534:\nssh:x:108:\nctf:x:1000:\ndeploy:x:1001:\nwebapp:x:1002:\n"
    ),

    # ---- FLAG 2: /home/ctf ----
    "/home/ctf/readme.txt": (
        "Welcome to the challenge box.\n"
        "You are logged in as 'ctf'. There are 4 flags total; you just saw flag 1.\n"
        "Hint: other users leave files lying around. Check the home directories.\n"
    ),
    "/home/ctf/flag2.txt": FLAG2 + "\n",
    "/home/ctf/.bash_history": (
        "ls -la\n"
        "cat readme.txt\n"
        "ls /home\n"
        "cat /home/deploy/config.ini\n"
        "exit\n"
    ),

    # ---- /home/deploy (contains a honeytoken) ----
    "/home/deploy/config.ini": (
        "[database]\nhost = ctf-box\nport = 3306\nname = prod\n"
        "user = deploy\npassword = D3ploy#2021\n"
        "\n[api]\nbase_url = https://api.example.com\ntoken = deploy-example-token\n"
    ),
    "/home/deploy/deploy.sh": (
        "#!/bin/bash\n"
        "# deploy script - usage: ./deploy.sh <env>\n"
        "ENV=${1:-prod}\n"
        "rsync -avz --delete /home/deploy/app/ deploy@10.0.0.15:/srv/app/$ENV/\n"
        "ssh deploy@10.0.0.15 \"cd /srv/app/$ENV && ./restart.sh\"\n"
    ),

    # ---- /root (flags 3 + 4, plus honeytokens) ----
    "/root/flag3.txt": FLAG3 + "\n",
    "/root/.canary/flag4.txt": FLAG4 + "\n",
    "/root/.canary/README": (
        "If you are reading this, you found the canary directory.\n"
        "The flag in here is worth the most, but reading it is LOUD.\n"
    ),
    "/root/.bash_history": (
        "ls -la /root\n"
        "cat /root/flag3.txt\n"
        "ls -la /root/.canary\n"
        "cat /root/.canary/flag4.txt\n"
        "exit\n"
    ),
    "/root/backup.sh": (
        "#!/bin/bash\n"
        "# nightly backup - cron (root) 02:00\n"
        "mysqldump -u root --all-databases | gzip > /var/backups/db-$(date +%F).sql.gz\n"
    ),

    # ---- HONEYTOKENS (touching these = DETECTED) ----
    "/root/.ssh/id_rsa": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAuTvDcS4pY7QmW9eK2rXaHn0FbJ8gCz1TdU6mVlE5oRx7iYwA\n"
        "NbQp3sLfH8xZ2K0cVnM4GjE7uYtR9fW6dS1bN8oP2qXvC4hK0lA5mJ3iU7eF9bG\n"
        "bH1xJ4zT8wN2vQ5kR0sL6fY3aE9cD7gI2pB0oU4tX1mZ8jK5nS3wF7hV9yA6eG\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "/root/.wallet/seed.txt": (
        "# wallet seed - do not share\n"
        "abandon ability able about above absent absorb abstract absurd abuse access accident\n"
    ),
    "/root/.aws/credentials": (
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = ap-southeast-2\n"
    ),
    "/var/www/html/config.php": (
        "<?php\n"
        "define('DB_HOST', '127.0.0.1');\n"
        "define('DB_NAME', 'prod');\n"
        "define('DB_USER', 'webapp');\n"
        "define('DB_PASS', 'W3bApp#2021');\n"
        "define('ADMIN_USER', 'admin');\n"
        "define('ADMIN_PASS', 'Admin#Panel!2021');\n"
        "?>\n"
    ),
    "/var/www/html/index.php": (
        "<?php\nrequire_once 'config.php';\necho '<h1>ctf-box</h1>';\n?>\n"
    ),
}


def main():
    src = files("cowrie.data") / "fs.pickle"
    with open(src, "rb") as f:
        tree = pickle.load(f)

    for path, content in FILES.items():
        set_file(tree, path, content)

    for p in ("/root/backup.sh", "/home/deploy/deploy.sh"):
        node = find_node(tree, p)
        if node is not None:
            node[A_MODE] = 0o100755

    with open(OUT, "wb") as f:
        pickle.dump(tree, f)

    print(f"wrote {OUT}: {len(FILES)} challenge files injected")


if __name__ == "__main__":
    main()
