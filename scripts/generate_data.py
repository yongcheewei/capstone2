# generator script - builds a realistic auth.log for testing
# run this if you want a fresh sample data set
import random
from datetime import datetime, timedelta

random.seed(42)

# 3 days of simulated traffic
START = datetime(2026, 1, 12, 0, 0, 0)
DAYS = 3

# normal users on the office network
NORMAL_USERS = ["yong", "alice", "bob", "charlie", "dave", "eve", "frank", "grace"]
NORMAL_IPS = [f"10.0.0.{i}" for i in range(5, 13)]

# known attacker IPs in the synthetic data
ATTACKER_IPS = {
    "203.0.113.45",   # fast brute force root
    "198.51.100.77",  # account spray
    "192.0.2.13",     # slow stealth attack
    "45.32.10.4",     # distributed attack (part of a botnet)
    "45.32.10.5",
    "45.32.10.6",
    "45.32.10.7",
    "185.220.101.50", # tor exit node style attacker
    "91.240.118.172", # second slow attacker
}


def fmt(ts, line):
    # auth.log format: "Mon DD HH:MM:SS hostname process[pid]: message"
    return f"{ts.strftime('%b %d %H:%M:%S')} server01 " + line


def make_line(ts, ip, username, status, pid=None):
    # build a single log line
    if pid is None:
        pid = random.randint(2000, 9000)
    if status == "failed":
        return fmt(ts, f"sshd[{pid}]: Failed password for{' invalid user' if random.random() < 0.5 else ''} {username} from {ip} port {random.randint(20000, 60000)} ssh2")
    else:
        return fmt(ts, f"sshd[{pid}]: Accepted password for {username} from {ip} port {random.randint(20000, 60000)} ssh2")


def gen_normal_traffic():
    # normal users logging in during working hours, with occasional typo
    lines = []
    for day in range(DAYS):
        day_start = START + timedelta(days=day)
        for user, ip in zip(NORMAL_USERS, NORMAL_IPS):
            # each user logs in 2-4 times per day
            for _ in range(random.randint(2, 4)):
                # pick a time during working hours
                login_time = day_start + timedelta(
                    hours=random.randint(8, 18),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59),
                )
                lines.append((login_time, make_line(login_time, ip, user, "success")))

                # occasional typo - 20% chance
                if random.random() < 0.2:
                    typo_time = login_time + timedelta(minutes=random.randint(1, 30))
                    lines.append((typo_time, make_line(typo_time, ip, user, "failed")))
                    # then a successful retry
                    retry_time = typo_time + timedelta(seconds=random.randint(3, 10))
                    lines.append((retry_time, make_line(retry_time, ip, user, "success")))
    return lines


def gen_fast_brute_force():
    # 203.0.113.45 hammers root with many usernames in 30 seconds
    lines = []
    base = datetime(2026, 1, 12, 14, 15, 0)
    users = ["root", "admin", "oracle", "postgres", "nagios", "ubuntu", "git", "deploy", "jenkins", "pi", "vagrant", "ansible"]
    for i, u in enumerate(users):
        ts = base + timedelta(seconds=i * 3)
        lines.append((ts, make_line(ts, "203.0.113.45", u, "failed")))
    return lines


def gen_account_spray():
    # 198.51.100.77 tries 8 different real-ish usernames, 1 fail each
    lines = []
    base = datetime(2026, 1, 13, 10, 30, 0)
    users = ["ftpuser", "mysql", "webadmin", "jenkins", "tomcat", "rabbitmq", "redis", "elasticsearch"]
    for i, u in enumerate(users):
        ts = base + timedelta(seconds=i * 8)
        lines.append((ts, make_line(ts, "198.51.100.77", u, "failed")))
    return lines


def gen_slow_stealth():
    # 192.0.2.13 does 1 fail every 20 min over 3 hours, late at night
    lines = []
    base = datetime(2026, 1, 13, 1, 0, 0)
    users = ["root", "admin", "support", "test", "user", "guest", "info", "operator"]
    for i, u in enumerate(users):
        ts = base + timedelta(minutes=i * 20)
        lines.append((ts, make_line(ts, "192.0.2.13", u, "failed")))
    return lines


def gen_distributed_attack():
    # 4 IPs from same subnet, all targeting the same accounts in a small window
    # this is the classic botnet pattern - distributed rule should catch it
    lines = []
    base = datetime(2026, 1, 14, 3, 0, 0)
    ips = ["45.32.10.4", "45.32.10.5", "45.32.10.6", "45.32.10.7"]
    # each IP targets the same 3 usernames within a 60-sec window
    # this is a coordinated attack - they pick the same target list
    for i, ip in enumerate(ips):
        for j, u in enumerate(["root", "root", "root"]):  # all hammer root
            ts = base + timedelta(seconds=i * 10 + j * 2)
            lines.append((ts, make_line(ts, ip, u, "failed")))
    return lines


def gen_tor_exit():
    # 185.220.101.50 - rapid root brute force
    lines = []
    base = datetime(2026, 1, 12, 22, 30, 0)
    for i in range(8):
        ts = base + timedelta(seconds=i * 2)
        u = random.choice(["root", "admin", "user", "test"])
        lines.append((ts, make_line(ts, "185.220.101.50", u, "failed")))
    return lines


def gen_second_slow():
    # 91.240.118.172 - off-hours low-and-slow over 2 hours
    lines = []
    base = datetime(2026, 1, 14, 23, 0, 0)
    for i in range(5):
        ts = base + timedelta(minutes=i * 25)
        u = random.choice(["root", "admin", "ubuntu", "ec2-user"])
        lines.append((ts, make_line(ts, "91.240.118.172", u, "failed")))
    return lines


def gen_typo_false_positive():
    # charlie types password wrong 6 times, then succeeds
    # this is the FP scenario - static rule will flag, adaptive will skip
    lines = []
    base = datetime(2026, 1, 13, 9, 15, 0)
    for i in range(6):
        ts = base + timedelta(seconds=i * 3)
        lines.append((ts, make_line(ts, "10.0.0.9", "charlie", "failed")))
    ts = base + timedelta(seconds=21)
    lines.append((ts, make_line(ts, "10.0.0.9", "charlie", "success")))
    return lines


def main():
    all_lines = []
    all_lines.extend(gen_normal_traffic())
    all_lines.extend(gen_fast_brute_force())
    all_lines.extend(gen_account_spray())
    all_lines.extend(gen_slow_stealth())
    all_lines.extend(gen_distributed_attack())
    all_lines.extend(gen_tor_exit())
    all_lines.extend(gen_second_slow())
    all_lines.extend(gen_typo_false_positive())

    # sort by timestamp
    all_lines.sort(key=lambda x: x[0])

    out_path = "data/sample_auth.log"
    with open(out_path, "w", encoding="utf-8") as f:
        for _, line in all_lines:
            f.write(line + "\n")

    print(f"Wrote {len(all_lines)} log lines to {out_path}")
    print(f"Attacker IPs in dataset: {len(ATTACKER_IPS)}")


if __name__ == "__main__":
    main()
