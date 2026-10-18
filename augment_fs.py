#!/usr/bin/env python3
"""
Augment the installed Cowrie fs.pickle with juicy decoy files.

Runs on the honeypot as the `cowrie` user, using the *installed* package's
bundled fs.pickle as the base (so the pickle format always matches the running
Cowrie version). It injects/overrides files, then writes /opt/cowrie/custom.pickle.

EVERYTHING added here is fabricated decoy content. There is no real credential,
key, or wallet data anywhere in this file — the goal is to give an attacker
realistic-looking bait so they linger and reveal their tooling.
"""
import os
import pickle
import sys
import time
from importlib.resources import files

# Node field indices (must match cowrie.shell.fs / cowrie.shell.honeyfs).
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# A plausible past mtime for a "neglected" box (~Dec 2021).
MTIME = 1638316800

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/cowrie/custom.pickle"


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
        existing[A_UID] = 0
        existing[A_GID] = 0
        existing[A_SIZE] = len(content)
        existing[A_MODE] = mode
        existing[A_CTIME] = MTIME
        existing[A_CONTENTS] = content
    else:
        children.append([name, T_FILE, 0, 0, len(content), mode, MTIME, content, None, None])


# ---------------------------------------------------------------------------
# Decoy file contents (all fabricated).
# ---------------------------------------------------------------------------
FILES = {
    # ---- OS identity (kept consistent: Ubuntu 18.04.6 LTS) ----
    "/etc/hostname": "prod-db-01\n",
    "/etc/debian_version": "buster/sid\n",
    "/etc/issue": "Ubuntu 18.04.6 LTS \\n \\l\n\n",
    "/etc/issue.net": "Ubuntu 18.04.6 LTS\n",
    "/etc/os-release": (
        'NAME="Ubuntu"\n'
        'VERSION="18.04.6 LTS (Bionic Beaver)"\n'
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        'PRETTY_NAME="Ubuntu 18.04.6 LTS"\n'
        'VERSION_ID="18.04"\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        "VERSION_CODENAME=bionic\n"
        "UBUNTU_CODENAME=bionic\n"
    ),
    "/etc/motd": (
        "\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)\n\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n"
        " * Support:        https://ubuntu.com/advantage\n\n"
        "  System information as of Wed Dec  1 10:12:33 UTC 2021\n\n"
        "  System load:  0.34               Processes:           128\n"
        "  Usage of /:   71.2% of 39.12GB   Users logged in:     0\n"
        "  Memory usage: 54%                IP address for eth0: 10.126.0.2\n"
        "  Swap usage:   2%\n\n"
        "  => /var/backups is using 89.7% of 39.12GB\n\n"
        "0 updates can be applied immediately.\n\n"
        "*** System restart required ***\n"
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
        "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\n"
        "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin\n"
        "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin\n"
        "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\n"
        "mysql:x:103:107:MySQL Server,,,:/nonexistent:/bin/false\n"
        "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
        "phil:x:1000:1000:Phil Collins:/home/phil:/bin/bash\n"
        "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
        "webapp:x:1002:1002:Web App:/home/webapp:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$bFj9Qk2X$0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f:18800:0:99999:7:::\n"
        "daemon:*:18353:0:99999:7:::\n"
        "bin:*:18353:0:99999:7:::\n"
        "sys:*:18353:0:99999:7:::\n"
        "sync:*:18353:0:99999:7:::\n"
        "games:*:18353:0:99999:7:::\n"
        "man:*:18353:0:99999:7:::\n"
        "lp:*:18353:0:99999:7:::\n"
        "mail:*:18353:0:99999:7:::\n"
        "news:*:18353:0:99999:7:::\n"
        "uucp:*:18353:0:99999:7:::\n"
        "proxy:*:18353:0:99999:7:::\n"
        "www-data:*:18353:0:99999:7:::\n"
        "backup:*:18353:0:99999:7:::\n"
        "list:*:18353:0:99999:7:::\n"
        "irc:*:18353:0:99999:7:::\n"
        "gnats:*:18353:0:99999:7:::\n"
        "nobody:*:18353:0:99999:7:::\n"
        "systemd-network:*:18353:0:99999:7:::\n"
        "systemd-resolve:*:18353:0:99999:7:::\n"
        "syslog:*:18353:0:99999:7:::\n"
        "mysql:*:18353:0:99999:7:::\n"
        "sshd:*:18353:0:99999:7:::\n"
        "phil:$6$Qw3Rtz91$Xb7e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d:18800:0:99999:7:::\n"
        "deploy:$6$LaS8dEw2$N9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d:18800:0:99999:7:::\n"
        "webapp:$6$PoIuYtRe$M1n2b3v4c5x6z7l8k9j0h1g2f3d4s5a6p7o8i9u0y1t2r3e4w5q6z:18800:0:99999:7:::\n"
    ),
    "/etc/group": (
        "root:x:0:\n"
        "daemon:x:1:\n"
        "bin:x:2:\n"
        "sys:x:3:\n"
        "adm:x:4:\n"
        "tty:x:5:\n"
        "disk:x:6:\n"
        "lp:x:7:\n"
        "mail:x:8:\n"
        "news:x:9:\n"
        "uucp:x:10:\n"
        "man:x:12:\n"
        "proxy:x:13:\n"
        "kmem:x:15:\n"
        "dialout:x:20:\n"
        "fax:x:21:\n"
        "voice:x:22:\n"
        "cdrom:x:24:\n"
        "floppy:x:25:\n"
        "tape:x:26:\n"
        "sudo:x:27:phil,deploy\n"
        "audio:x:29:\n"
        "dip:x:30:\n"
        "www-data:x:33:\n"
        "backup:x:34:\n"
        "operator:x:37:\n"
        "list:x:38:\n"
        "irc:x:39:\n"
        "src:x:40:\n"
        "gnats:x:41:\n"
        "shadow:x:42:\n"
        "utmp:x:43:\n"
        "video:x:44:\n"
        "sasl:x:45:\n"
        "plugdev:x:46:\n"
        "staff:x:50:\n"
        "games:x:60:\n"
        "users:x:100:\n"
        "nogroup:x:65534:\n"
        "systemd-network:x:102:\n"
        "systemd-resolve:x:103:\n"
        "syslog:x:106:\n"
        "mysql:x:107:\n"
        "ssh:x:108:\n"
        "phil:x:1000:\n"
        "deploy:x:1001:\n"
        "webapp:x:1002:\n"
    ),

    # ---- /root — the crown jewels ----
    "/root/.bash_history": (
        "ls -la /var/backups\n"
        "mysql -u root -p'DBpassw0rd!2021' prod\n"
        "mysqldump -u root -p'DBpassw0rd!2021' prod > /root/db_backup.sql\n"
        "tar czf /var/backups/db-backup-2021-12-01.tar.gz /root/db_backup.sql\n"
        "scp /var/backups/db-backup-2021-12-01.tar.gz ops@10.0.0.15:/srv/offsite/\n"
        "cat /root/.ssh/authorized_keys\n"
        "vi /root/backup.sh\n"
        "crontab -e\n"
        "chmod 600 /root/.wallet/seed.txt\n"
        "df -h\n"
        "uptime\n"
        "exit\n"
    ),
    "/root/.ssh/id_rsa": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAuTvDcS4pY7QmW9eK2rXaHn0FbJ8gCz1TdU6mVlE5oRx7iYwA\n"
        "NbQp3sLfH8xZ2K0cVnM4GjE7uYtR9fW6dS1bN8oP2qXvC4hK0lA5mJ3iU7eF9bG\n"
        "bH1xJ4zT8wN2vQ5kR0sL6fY3aE9cD7gI2pB0oU4tX1mZ8jK5nS3wF7hV9yA6eG\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "/root/.ssh/authorized_keys": (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJf9k2qXv8sTz3bCw5eH7mN1pR4uY6aD0gE2hL9jK4x ops@backup-box\n"
    ),
    "/root/.ssh/known_hosts": (
        "10.0.0.15 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP8x\n"
    ),
    "/root/backup.sh": (
        "#!/bin/bash\n"
        "# Nightly DB backup - run by cron (root) at 02:00 daily\n"
        "MYSQL_PWD='DBpassw0rd!2021' mysqldump -u root --all-databases \\\n"
        "  | gzip > /var/backups/db-backup-$(date +%F).sql.gz\n"
        "\n"
        "# Offsite copy to ops server\n"
        "scp /var/backups/db-backup-$(date +%F).sql.gz \\\n"
        "    ops@10.0.0.15:/srv/offsite/db/ 2>/dev/null\n"
        "\n"
        "# Cleanup older than 14 days\n"
        "find /var/backups -name 'db-backup-*.sql.gz' -mtime +14 -delete\n"
    ),
    "/root/credentials.txt": (
        "# Production credentials - updated 2021-11-02\n"
        "# DO NOT COMMIT TO GIT\n"
        "\n"
        "MySQL (prod-db-01):\n"
        "  host: 127.0.0.1:3306\n"
        "  user: prodapp\n"
        "  pass: Pr0d#App!2021\n"
        "\n"
        "PostgreSQL (reports):\n"
        "  host: 10.0.0.20:5432\n"
        "  user: reports\n"
        "  pass: R3ports$2021\n"
        "\n"
        "Redis (cache):\n"
        "  host: 127.0.0.1:6379\n"
        "  pass: RedisCache#2021\n"
        "\n"
        "SSH backup key passphrase: BackUpK3y$2021\n"
    ),
    "/root/db_backup.sql": (
        "-- MySQL dump 10.13  Distrib 5.7.33, for Linux (x86_64)\n"
        "--\n"
        "-- Host: localhost    Database: prod\n"
        "-- Server version\t5.7.33-0ubuntu0.18.04.1\n"
        "\n"
        "CREATE TABLE `users` (\n"
        "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
        "  `username` varchar(64) NOT NULL,\n"
        "  `email` varchar(128) NOT NULL,\n"
        "  `password_hash` varchar(128) NOT NULL,\n"
        "  `role` varchar(16) NOT NULL DEFAULT 'user',\n"
        "  `created_at` datetime NOT NULL,\n"
        "  PRIMARY KEY (`id`)\n"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
        "\n"
        "INSERT INTO `users` VALUES "
        "(1,'admin','admin@prod-db-01.local','$2y$10$Xb7e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e','admin','2020-01-15 09:00:00');\n"
    ),
    "/root/.aws/credentials": (
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = ap-southeast-2\n"
    ),
    "/root/.wallet/seed.txt": (
        "# wallet seed - created 2021-06-14 - do not share\n"
        "abandon ability able about above absent absorb abstract absurd abuse access accident\n"
    ),
    "/root/notes.txt": (
        "TODO:\n"
        "- rotate DB password (still using 2021 creds - move to vault when I get time)\n"
        "- renew TLS cert for app.example.com (expired 2021-11)\n"
        "- decommission old reports server 10.0.0.20\n"
        "- check why load avg spikes at 03:00 nightly (cron backup?)\n"
        "\n"
        "Reminder: don't leave keys in /root. Move to /root/.wallet and chmod 600.\n"
    ),

    # ---- /home/deploy ----
    "/home/deploy/.ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\n"
        "OQAAACBjcmVhdGVkIGZvciBkZXBsb3kgYnkgdGhlIGhvbml5cG90IGRlY29ueQAAAAMwAAAAL\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "/home/deploy/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0deploykeyplaceholder0f9d2c3b4a5e6f7 deploy@ci-box\n"
    ),
    "/home/deploy/deploy.sh": (
        "#!/bin/bash\n"
        "# Deploy script - usage: ./deploy.sh <env>\n"
        "ENV=${1:-prod}\n"
        "echo \"Deploying to $ENV ...\"\n"
        "rsync -avz --delete /home/deploy/app/ deploy@10.0.0.15:/srv/app/$ENV/\n"
        "ssh deploy@10.0.0.15 \"cd /srv/app/$ENV && ./restart.sh\"\n"
    ),
    "/home/deploy/config.ini": (
        "[database]\n"
        "host = prod-db-01\n"
        "port = 3306\n"
        "name = prod\n"
        "user = deploy\n"
        "password = D3ploy#2021\n"
        "\n"
        "[redis]\n"
        "host = 127.0.0.1\n"
        "port = 6379\n"
        "password = RedisCache#2021\n"
        "\n"
        "[api]\n"
        "base_url = https://api.example.com\n"
        "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.deploy-example\n"
    ),

    # ---- /home/webapp ----
    "/home/webapp/.ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\n"
        "OQAAACBjcmVhdGVkIGZvciB3ZWJhcHAgYnkgdGhlIGhvbml5cG90IGRlY29ueQAAAAMwAAAAL\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "/home/webapp/.bash_history": (
        "cd /var/www/html\n"
        "vi config.php\n"
        "git pull origin master\n"
        "sudo systemctl restart apache2\n"
        "tail -f /var/log/apache2/error.log\n"
        "exit\n"
    ),

    # ---- /var/www/html — the fake web app ----
    "/var/www/html/index.php": (
        "<?php\n"
        "// prod-db-01 web application\n"
        "require_once 'config.php';\n"
        "echo '<h1>Database Status</h1>';\n"
        "echo '<p>Connected to ' . DB_NAME . '</p>';\n"
        "?>\n"
    ),
    "/var/www/html/config.php": (
        "<?php\n"
        "// Database configuration\n"
        "define('DB_HOST', '127.0.0.1');\n"
        "define('DB_NAME', 'prod');\n"
        "define('DB_USER', 'webapp');\n"
        "define('DB_PASS', 'W3bApp#2021');\n"
        "define('DB_CHARSET', 'utf8mb4');\n"
        "\n"
        "// Admin panel (change before go-live!)\n"
        "define('ADMIN_USER', 'admin');\n"
        "define('ADMIN_PASS', 'Admin#Panel!2021');\n"
        "\n"
        "$redis = new Redis();\n"
        "$redis->connect('127.0.0.1', 6379);\n"
        "$redis->auth('RedisCache#2021');\n"
        "?>\n"
    ),
    "/var/www/html/admin/login.php": (
        "<?php\n"
        "session_start();\n"
        "if ($_SERVER['REQUEST_METHOD'] === 'POST') {\n"
        "    if ($_POST['user'] === ADMIN_USER && $_POST['pass'] === ADMIN_PASS) {\n"
        "        $_SESSION['admin'] = true;\n"
        "        header('Location: dashboard.php');\n"
        "    }\n"
        "}\n"
        "?>\n"
        "<form method=\"post\">\n"
        "  <input name=\"user\" placeholder=\"username\">\n"
        "  <input name=\"pass\" type=\"password\" placeholder=\"password\">\n"
        "  <button type=\"submit\">Login</button>\n"
        "</form>\n"
    ),

    # ---- /var/backups ----
    "/var/backups/db-backup-2021-12-01.sql": (
        "-- MySQL dump 10.13  Distrib 5.7.33, for Linux (x86_64)\n"
        "--\n"
        "-- Host: localhost    Database: prod\n"
        "-- Server version\t5.7.33-0ubuntu0.18.04.1\n"
        "\n"
        "/*!40101 SET NAMES utf8mb4 */;\n"
        "\n"
        "CREATE TABLE `orders` (\n"
        "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
        "  `customer_email` varchar(128) NOT NULL,\n"
        "  `amount` decimal(10,2) NOT NULL,\n"
        "  `card_last4` char(4) DEFAULT NULL,\n"
        "  `created_at` datetime NOT NULL,\n"
        "  PRIMARY KEY (`id`)\n"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
    ),
}


def main():
    src = files("cowrie.data") / "fs.pickle"
    with open(src, "rb") as f:
        tree = pickle.load(f)

    for path, content in FILES.items():
        set_file(tree, path, content)

    # Make the shell scripts look executable.
    for p in ("/root/backup.sh", "/home/deploy/deploy.sh"):
        node = find_node(tree, p)
        if node is not None:
            node[A_MODE] = 0o100755

    with open(OUT, "wb") as f:
        pickle.dump(tree, f)

    print(f"wrote {OUT}: {len(FILES)} decoy files injected")


if __name__ == "__main__":
    main()
