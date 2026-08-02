# parses linux auth.log into structured events
import re
from datetime import datetime
from collections import defaultdict


# these are the patterns we look for in auth.log
# tried to keep them flexible so they work across debian/ubuntu lines
FAILED_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for(?:\s+invalid user)?\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
)

ACCEPTED_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
)

INVALID_USER_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# current year is hardcoded since auth.log doesn't include it
CURRENT_YEAR = datetime.now().year


def parse_timestamp(ts_string):
    # auth.log uses "Mon DD HH:MM:SS" format, no year
    # so we just tack on the current year
    try:
        return datetime.strptime(f"{CURRENT_YEAR} {ts_string}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_log(file_path):
    # reads the log file line by line and pulls out the bits we care about
    events = []
    skipped = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            event = None
            if "Failed password" in line:
                m = FAILED_PATTERN.match(line)
                if m:
                    event = {
                        "timestamp": parse_timestamp(m.group("ts")),
                        "username": m.group("user"),
                        "ip": m.group("ip"),
                        "status": "failed",
                    }
            elif "Accepted password" in line:
                m = ACCEPTED_PATTERN.match(line)
                if m:
                    event = {
                        "timestamp": parse_timestamp(m.group("ts")),
                        "username": m.group("user"),
                        "ip": m.group("ip"),
                        "status": "success",
                    }
            elif "Invalid user" in line:
                # invalid user lines are usually followed by a Failed password
                # but we still log them as a failed attempt
                m = INVALID_USER_PATTERN.match(line)
                if m:
                    event = {
                        "timestamp": parse_timestamp(m.group("ts")),
                        "username": m.group("user"),
                        "ip": m.group("ip"),
                        "status": "failed",
                    }

            if event and event["timestamp"]:
                events.append(event)
            else:
                skipped += 1

    return events, skipped


def normalize_events(events):
    # normalising = making sure all fields are clean before rule engine sees them
    # empty usernames get replaced, ip stays ip, timestamps in a single format
    cleaned = []
    for e in events:
        cleaned.append({
            "timestamp": e["timestamp"],
            "username": (e["username"] or "").strip().lower(),
            "ip": (e["ip"] or "").strip(),
            "status": e["status"],
        })
    # sort by time so window-based rules work nicely later
    cleaned.sort(key=lambda x: x["timestamp"])
    return cleaned


def build_baseline(events):
    # used by adaptive thresholding - we want a "normal" baseline
    # the trick is: don't let the attacker themselves pollute the baseline
    # so we use the median of all per-ip-per-hour counts, which is robust
    # to outliers
    per_ip_hours = defaultdict(lambda: defaultdict(int))
    for e in events:
        if e["status"] == "failed":
            key = e["ip"]
            hour_key = e["timestamp"].strftime("%Y-%m-%d %H:00")
            per_ip_hours[key][hour_key] += 1

    # collect all the per-hour counts from "quiet" ips
    # (ips that have at most 2 fails per hour, those are likely normal users)
    all_quiet_counts = []
    for ip, hours in per_ip_hours.items():
        for hour, count in hours.items():
            if count <= 2:
                all_quiet_counts.append(count)

    if all_quiet_counts:
        # median is robust to attack spikes
        sorted_counts = sorted(all_quiet_counts)
        mid = len(sorted_counts) // 2
        if len(sorted_counts) % 2 == 0:
            median = (sorted_counts[mid - 1] + sorted_counts[mid]) / 2
        else:
            median = sorted_counts[mid]
        # adaptive threshold = median + 4 extra fails of headroom
        # e.g. median is 1, threshold becomes 5
        global_baseline = max(3, int(median) + 4)
    else:
        global_baseline = 5

    # every ip gets the same baseline, since we can't trust per-ip data
    # (a brand new attacker would have a low baseline otherwise)
    baseline = {ip: global_baseline for ip in per_ip_hours.keys()}
    return baseline
