# Cowrie Honeypot — *prod-db-01*

> **Deployed a low-interaction SSH honeypot on DigitalOcean, watched real attackers for 18 days, reverse-engineered five distinct campaigns, and fed every technique they used back into my own (scoped) offensive tooling — closing the blue-to-red loop.**

![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![events](https://img.shields.io/badge/events_logged-547%2C857-informational)
![ips](https://img.shields.io/badge/unique_source_IPs-1%2C605-informational)
![campaigns](https://img.shields.io/badge/campaigns_identified-5-blueviolet)
![status](https://img.shields.io/badge/status-deployed-9cf)

A defensive research project: a [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot on a
DigitalOcean droplet, disguised as a neglected Ubuntu 18.04 production database box, logging
real internet attack traffic. Everything the honeypot serves — credentials, SSH keys, wallet
seeds, database dumps — is **fabricated decoy bait**. The value is what comes back: who is
attacking, how, and what they drop.

This is the *blue* half of my red/blue loop. The techniques observed here were codified into
scoped, inert emulation tooling in **[evilkit](https://github.com/Bowie1969/evilkit)** (see
[Red/blue loop](#redblue-loop)).

---

## What it is

| Layer | What it does |
|-------|--------------|
| **Honeypot** | Cowrie on port `22`, branded as `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7`, hostname `prod-db-01`, kernel `4.15.0-213-generic` — a consistent, EOL, "easy prize" story |
| **Decoy filesystem** | A fabricated Ubuntu 18.04 filesystem with realistic bait (keys, wallet seed, AWS creds, DB dumps) so attackers linger and reveal their tooling |
| **Analysis pipeline** | `analyze.py` turns `cowrie.json` into a threat report; `live.py` tails attacks in real time |
| **Challenge instance** | A second Cowrie on port `2222` — a flag-hunt with honeytokens and a stealth score, for invited researchers |
| **Discipline** | Log-and-report only. No scanning back, no hack-back, no touching attacker infrastructure. Defensive throughout. |

## Deployment & architecture

```
                     Internet
                        │
                        │  SSH scans · brute force · payload drops
                        ▼
   ┌────────────────────────────────────────────────────────┐
   │        DigitalOcean droplet (syd1, Ubuntu 24.04)       │
   │        public IP 134.199.170.29 · 512 MB / 1 vCPU      │
   │                                                        │
   │   :22    Cowrie honeypot   ←  attackers land here      │
   │   :2200  real sshd         ←  admin (key-only +        │
   │                                fail2ban sshd jail)     │
   │   :2222  Cowrie challenge  ←  invited researchers      │
   │                                (flag hunt + stealth)   │
   │                                                        │
   │   /opt/cowrie     — blackhat instance + venv           │
   │   /opt/challenge  — challenge instance (reuses venv)   │
   │   custom.pickle   — injected decoy filesystem          │
   │   UFW: 22 / 2200 / 2222 only                           │
   └────────────────────────────────────────────────────────┘
                        │
                        ▼
        cowrie.json  ──▶  analyze.py  →  threat report
                     ──▶  live.py     →  live colorized tail
```

* `22` is bound by Cowrie via `authbind`; the real `sshd` is moved to `2200` (key-only).
* The two instances are independent systemd units (`cowrie.service`,
  `challenge/cowrie-challenge.service`) and share the one Python venv.

## The five campaigns observed

Over ~18 days the box saw **547,857 events from 1,605 unique IPs**. Almost all of it is
`SSH-2.0-Go` mass brute-force noise — the interesting part is the **117 IPs that actually
reached a shell** and the payloads they pulled. Those reduced to **five distinct campaigns**:

| # | Campaign | Signature | Infrastructure |
|---|----------|-----------|----------------|
| **C1** | Mirai-family loader | pulls `handshakebins.sh`, `telnetd`, `kworker` from a `/nokillbins/` path | `213.232.114.14` (VirMach/xTom NL) |
| **C2** | Multi-arch IoT dropper | fetches `cat.sh` + `iran.{x86_64,aarch64,mips,mipsel,m68k,sparc,powerpc,arc,sh4,armv4l…7l,i486}` — up to 15 CPU architectures | `144.202.28.52` + `45.32.215.222` (Vultr; the latter is an open directory) |
| **C3** | Self-propagating SSH worm | plants an `ed25519` key, `scp`s a second stage | `217.60.102.5` (SWISSNET NL) |
| **C4** | Open-SOCKS relay abuse | **12,744** `direct-tcpip` tunnels through the box to Yahoo/Google/Cloudflare — turning the honeypot into a relay | (uses each victim as its own egress) |
| **C5** | Windows RDP tooling drop | drops `rdpcIip.exe`, `sqhost.exe`, `7z` — RDP credential-stuffing kit | (staged from a payload host) |

### Attribution highlight

The two largest brute-force clusters — `109.160.32.x` ("GBTCloud") and `77.239.124.x`
("RocketCloud"), roughly 120k combined login attempts — turned out to be **the same operator**:
both prefixes belong to **BANATSYNC SRL, AS198364**, operating under two reseller brands.
A follow-up passive pass found the same pattern again: four prefixes across **AS47890
(UNMANAGED/"DMZHOST") and AS48090 (TECHOFF)** all share a single abuse contact
(`dmzhostabuse@gmail.com`) — one bulletproof operator wearing several ASN/brand masks.

Captured malware spans **4 CPU architectures** (ARM, MIPS, x86-64, RISC-V), mostly packed.
Top credential attempted: `admin:admin` (5,434 attempts), then the standard root/default
dictionary.

## Decoy filesystem

`augment_fs.py` loads the installed Cowrie `fs.pickle` and injects **29 fabricated files**
into a `custom.pickle` the honeypot serves. The idea: give an attacker a realistic box worth
exploring, so they stay long enough to expose their methods.

Bait includes `/root/.ssh/id_rsa`, `/root/.aws/credentials`, `/root/.wallet/seed.txt`,
`/root/credentials.txt`, `/home/deploy/config.ini`, `/var/www/html/config.php`, a fake MySQL
dump, and a `.bash_history` full of tempting leads — all consistent with the "neglected DB box"
persona (Ubuntu 18.04, Dec-2021 mtimes, EOL kernel).

> **Every key, password, and credential in this repo is fabricated decoy content.** There is
> no real secret anywhere. The AWS keys are the public AWS documentation examples, and the
> "private keys" are self-identifying fakes that decode to *"created for … by the honeypot
> decoy"*. See `augment_fs.py` and `challenge/augment_fs.py`.

## Analysis pipeline

Two stdlib-only Python tools, no dependencies beyond `whois` for optional enrichment.

```bash
# Pull the log down, then build a threat report:
scp -P 2200 -i ~/.ssh/id_honeypot root@134.199.170.29:/opt/cowrie/var/log/cowrie/cowrie.json .
python3 analyze.py cowrie.json --top 20 --whois
# → top source IPs, successful logins, attempted creds, commands, and — highest value —
#   the download URLs where bots pull their own payloads/C2 from.

# Watch attacks live (colorized, streams over the admin SSH channel):
python3 live.py                    # tail the deployed honeypot
python3 live.py --local cowrie.json --history 100
python3 live.py --no-color         # plain text for piping/logging
```

`live.py` prints a running summary on exit (event counts, unique IPs, top talkers).

## Challenge instance (port 2222)

A second Cowrie on the same droplet for invited researchers: a **flag hunt where stealth is
the skill being graded**. Four flags at escalating depth, plus honeytokens that count as
*DETECTED* when touched.

```
stealth score = flag points − detection points
```

`challenge/score.py` renders the leaderboard or a single player's timeline
(`--ip 1.2.3.4`). Full rules in [`challenge/CHALLENGE.md`](challenge/CHALLENGE.md).

## Red/blue loop

Defense feeds offense here. The dictionary the bots brute-force with (`admin:admin` first),
the multi-arch transfer ladders (`wget`/`curl`/`tftp`/`ftp`/`busybox`), and the SSH key-reuse
propagation were each turned into **inert, scoped emulation tools** in
**[Bowie1969/evilkit](https://github.com/Bowie1969/evilkit)** — script generators that produce
detectable telemetry without touching a real network — plus proving targets on my isolated
lab range. Observing the attack once lets me reproduce it safely, forever.

## Results & highlights

- **547,857 events** and **1,605 unique source IPs** over ~18 days of real traffic.
- **5 distinct campaigns** identified (IoT/Mirai, multi-arch dropper, SSH worm, SOCKS-relay
  abuse, Windows RDP tooling).
- **117 IPs reached a shell** — the signal behind ~1,500 mass-brute-force scanners.
- **Cross-ASN attribution** of brute-force clusters to a single operator.
- **4 CPU architectures** of live malware captured for analysis.
- **Defensive discipline**: 100% passive observation — no scan-back, no hack-back.

## Repo layout

| File | Purpose |
|------|---------|
| `cowrie.cfg` / `userdb.txt` | Honeypot identity + credentials the honeypot *accepts* (fabricated) |
| `augment_fs.py` | Injects the decoy filesystem (`custom.pickle`) |
| `setup.sh` / `cowrie.service` | Droplet provisioning + systemd unit (auto-restart) |
| `analyze.py` / `live.py` | Threat-report + live-tail analysis pipeline |
| `challenge/` | Flag-hunt instance: config, decoy FS, scorer, systemd unit |

## Authorized use

This project is for **defensive security research and education only**. Run a honeypot only
on infrastructure you own or are explicitly authorized to operate. Log and report what you
observe; never scan back, never interact with attacker infrastructure, and never "hack back".
Know your local laws (e.g. Australia's *Criminal Code* and *Privacy Act*) before exposing a
sensor to the public internet. Any captured malware should be treated as live and handled in
an isolated environment.

## License

[MIT](LICENSE) — © 2026 Bowie1969
