# Cowrie Flag Hunt — Stealth Challenge

A public challenge for researchers and anyone who wants to practice moving
through a box quietly. Four flags are hidden on a honeypot; the twist is that
**you are being watched the whole time**.

## How to play

Connect over SSH (password auth):

```
ssh ctf@<HOST> -p 2222        # password: ctf
```

You'll land in a shell as the `ctf` user. Flag 1 is handed to you on login.
Flags 2–4 are hidden on the box and require escalating access (other users'
homes, then root). Flag format is `flag{...}`.

## Rules

- **Every command is logged.** There is no way around the logging — that's the
  point. The skill being measured is *footprint*, not invisibility.
- **Honeytokens.** Some files look like loot (SSH keys, wallet seeds, AWS keys,
  app credentials) but are tripwires. Reading one counts as DETECTED.
- **Noise.** Brute-forcing, recon spam, `wget`/`curl`/`scp`, and destructive
  commands all add detection points.
- **Escalate cleanly.** The box runs weak default credentials — a good operator
  guesses them in one try; a lazy one sprays a wordlist and gets scored for it.

## Scoring

```
stealth score = flag points − detection points
```

| Flag | Points | Location |
|------|--------|----------|
| flag1 | 10 | given on login (MOTD) |
| flag2 | 20 | a home directory |
| flag3 | 30 | requires root |
| flag4 | 40 | in the canary directory — reading it trips a honeytoken (−10) |

Detection costs: failed login `−1`, honeytoken read `−10`, noisy/destructive
command `−5`.

The leaderboard ranks players by stealth score, so a clean three-flag run can
beat a sloppy four-flag one.

## Operator notes

This is the **challenge instance** of the Cowrie honeypot. It is a separate
Cowrie process on port 2222 from the blackhat instance on port 22. Score a run
with:

```
python3 score.py                 # leaderboard
python3 score.py --ip <ip>       # one player's timeline
python3 score.py --save leaderboard.md
```

All content (flags, honeytokens, credentials) is fabricated. This is a
defensive/research tool: you own the box, you log everything, and you never
touch the players back.
