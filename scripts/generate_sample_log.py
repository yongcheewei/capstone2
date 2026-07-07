"""Generate a small synthetic auth.log mixing benign and brute-force events.

Usage
-----
python scripts/generate_sample_log.py \
    --out data/processed/sample_auth.log \
    --attacker-ip 1.2.3.4 \
    --second-attacker 5.5.5.5 \
    --benign-count 30 \
    --attack-count 60
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

INVALID_USERS = ["admin", "root", "oracle", "postgres", "nagios",
                 "test", "guest", "user", "ubuntu", "pi"]
VALID_USERS = ["alice", "bob", "carol", "dave"]
ATTACK_PORTS = list(range(40000, 60000, 17))
BENIGN_IPS = ["9.9.9.9", "9.9.9.10", "192.168.1.50", "192.168.1.51"]


def _month(day: datetime) -> str:
    return day.strftime("%b")


def _format_line(ts: datetime, host: str, pid: int, msg: str) -> str:
    return (f"{_month(ts)} {ts.day:>2} {ts.strftime('%H:%M:%S')} "
            f"{host} sshd[{pid}]: {msg}\n")


def _attack_event(ts: datetime, attacker_ip: str, used_users: list[str],
                  pid: int) -> str:
    user = random.choice(INVALID_USERS)
    used_users.append(user)
    port = random.choice(ATTACK_PORTS)
    return _format_line(
        ts, "srv", pid,
        f"Failed password for invalid user {user} from "
        f"{attacker_ip} port {port} ssh2",
    )


def _benign_event(ts: datetime, pid: int) -> str:
    user = random.choice(VALID_USERS)
    ip = random.choice(BENIGN_IPS)
    port = random.choice(range(35000, 55000, 23))
    return _format_line(
        ts, "srv", pid,
        f"Accepted password for {user} from {ip} port {port} ssh2",
    )


def generate(out_path: Path,
             attacker_ip: str = "1.2.3.4",
             second_attacker: str | None = None,
             benign_count: int = 30,
             attack_count: int = 60,
             seed: int = 42) -> None:
    random.seed(seed)
    lines: list[str] = []
    now = datetime(2026, 3, 15, 10, 0, 0)
    pid = 1234
    used_attacker_users: list[str] = []
    used_second_users: list[str] = []
    i = 0
    for _ in range(attack_count // 2):
        ts = now + timedelta(seconds=i)
        lines.append(_attack_event(ts, attacker_ip, used_attacker_users,
                                   pid + len(lines)))
        if second_attacker:
            ts2 = now + timedelta(seconds=i + 20)
            lines.append(_attack_event(ts2, second_attacker,
                                       used_second_users, pid + len(lines)))
        i += random.randint(2, 12)
    for _ in range(benign_count):
        ts = now + timedelta(seconds=i)
        lines.append(_benign_event(ts, pid + len(lines)))
        i += random.randint(30, 300)
    for _ in range(attack_count // 2):
        ts = now + timedelta(seconds=i)
        lines.append(_attack_event(ts, attacker_ip, used_attacker_users,
                                   pid + len(lines)))
        if second_attacker:
            ts2 = now + timedelta(seconds=i + 5)
            lines.append(_attack_event(ts2, second_attacker,
                                       used_second_users, pid + len(lines)))
        i += random.randint(2, 8)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("".join(lines), encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {out_path}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path,
                   default=Path("data/processed/sample_auth.log"))
    p.add_argument("--attacker-ip", default="1.2.3.4")
    p.add_argument("--second-attacker", default="5.5.5.5")
    p.add_argument("--benign-count", type=int, default=30)
    p.add_argument("--attack-count", type=int, default=60)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    generate(args.out, args.attacker_ip, args.second_attacker,
             args.benign_count, args.attack_count, args.seed)


if __name__ == "__main__":
    main()
