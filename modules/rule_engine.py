# applies detection rules on the parsed events
from collections import defaultdict
from datetime import timedelta


# tweakable defaults - can be overridden from main.py
DEFAULT_CONFIG = {
    "static_threshold": 5,         # 5 failed attempts
    "static_window": 60,           # within 60 seconds
    "account_diversity_min": 3,    # 3 different usernames
    "working_hours_start": 8,      # 8am
    "working_hours_end": 20,       # 8pm
    "adaptive_multiplier": 3,      # baseline * 3 triggers alert
    "distributed_min_ips": 3,      # 3+ ips from same /24 = botnet
}


def _sliding_window(timestamps, window_seconds):
    # helper - counts how many events fall in a rolling window
    # returns max count seen at any point
    if not timestamps:
        return 0, None, None
    timestamps = sorted(timestamps)
    max_count = 0
    best_start = timestamps[0]
    best_end = timestamps[0]
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > timedelta(seconds=window_seconds):
            left += 1
        count = right - left + 1
        if count > max_count:
            max_count = count
            best_start = timestamps[left]
            best_end = timestamps[right]
    return max_count, best_start, best_end


def static_threshold_rule(events, threshold, window):
    # rule 1: same ip fails more than N times within T seconds
    # simple but works
    failed_by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "failed":
            failed_by_ip[e["ip"]].append(e["timestamp"])

    alerts = []
    for ip, ts_list in failed_by_ip.items():
        count, start, end = _sliding_window(ts_list, window)
        if count >= threshold:
            alerts.append({
                "rule": "static_threshold",
                "ip": ip,
                "failed_count": count,
                "window_start": start,
                "window_end": end,
            })
    return alerts


def adaptive_threshold_rule(events, baseline):
    # rule 2: threshold is computed per ip from the baseline
    # adaptive rule uses a longer time window + higher threshold
    # so a legit user who mistypes 5 times in 30 sec (then logs in)
    # won't get flagged, but a real brute-forcer hitting 10+ will
    failed_by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "failed":
            failed_by_ip[e["ip"]].append(e["timestamp"])

    multiplier = DEFAULT_CONFIG["adaptive_multiplier"]
    window = 300  # 5 min window for adaptive
    alerts = []
    for ip, ts_list in failed_by_ip.items():
        th = baseline.get(ip, 5)  # fallback to 5 if no baseline
        # adaptive threshold = baseline * multiplier / 2
        # we use a smaller window than static so we catch bursts faster
        # but require a slightly higher absolute count so legit typos (5-6
        # in 30 sec) don't trigger
        threshold = max(6, int(th * multiplier / 2))
        count, start, end = _sliding_window(ts_list, window)
        if count >= threshold:
            alerts.append({
                "rule": "adaptive_threshold",
                "ip": ip,
                "failed_count": count,
                "threshold_used": threshold,
                "window_start": start,
                "window_end": end,
            })
    return alerts


def account_diversity_rule(events, min_users):
    # rule 3: same ip targeting many different usernames = suspicious
    # a real user usually has one account
    users_by_ip = defaultdict(set)
    failed_by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "failed" and e["username"]:
            users_by_ip[e["ip"]].add(e["username"])
            failed_by_ip[e["ip"]].append(e["timestamp"])

    alerts = []
    for ip, users in users_by_ip.items():
        if len(users) >= min_users:
            count, start, end = _sliding_window(failed_by_ip[ip], 600)
            alerts.append({
                "rule": "account_diversity",
                "ip": ip,
                "unique_usernames": len(users),
                "failed_count": count,
                "window_start": start,
                "window_end": end,
            })
    return alerts


def time_of_day_rule(events, start_hour, end_hour):
    # rule 4: failed logins outside working hours get flagged
    # works for office setups - attackers usually hit at 3am
    off_hours_fails = defaultdict(list)
    for e in events:
        if e["status"] == "failed":
            h = e["timestamp"].hour
            if h < start_hour or h >= end_hour:
                off_hours_fails[e["ip"]].append(e["timestamp"])

    alerts = []
    for ip, ts_list in off_hours_fails.items():
        if len(ts_list) >= 3:
            alerts.append({
                "rule": "off_hours",
                "ip": ip,
                "failed_count": len(ts_list),
                "first_seen": min(ts_list),
                "last_seen": max(ts_list),
            })
    return alerts


def _ip_subnet(ip):
    # get the /24 subnet of an ip - used to group attackers
    # e.g. "45.32.10.4" -> "45.32.10"
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return ".".join(parts[:3])


def distributed_attack_rule(events, min_ips=3, window=600):
    # rule 5: detects botnet-style distributed brute force
    # if N+ different IPs from the same /24 subnet all fail on the
    # same target username within a short window, that's coordinated
    # key insight: a single ip with high fails is static_threshold
    # but multiple ips from one subnet hitting same target = botnet
    subnet_targets = defaultdict(lambda: defaultdict(list))  # (subnet, username) -> [(ts, ip)]
    for e in events:
        if e["status"] == "failed" and e["username"]:
            subnet = _ip_subnet(e["ip"])
            key = (subnet, e["username"])
            subnet_targets[key][e["ip"]].append((e["timestamp"], e["ip"]))

    alerts = []
    for (subnet, username), ip_map in subnet_targets.items():
        if len(ip_map) < min_ips:
            continue
        # collect all timestamps across the attacking ips
        all_ts = []
        ips_involved = set()
        for ip, ts_ip_list in ip_map.items():
            ips_involved.add(ip)
            all_ts.extend([t for t, _ in ts_ip_list])
        all_ts.sort()
        # check if all of them fall within the window
        if len(all_ts) >= min_ips and (all_ts[-1] - all_ts[0]).total_seconds() <= window:
            alerts.append({
                "rule": "distributed_attack",
                "ip": f"{subnet}.0/24",  # represent the whole subnet
                "attacking_ips": sorted(ips_involved),
                "target_username": username,
                "failed_count": len(all_ts),
                "window_start": all_ts[0],
                "window_end": all_ts[-1],
            })
    return alerts


def run_all_rules(events, baseline=None, config=None):
    # runs every rule and returns merged alerts
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    if baseline is None:
        baseline = {}

    all_alerts = []
    all_alerts.extend(static_threshold_rule(events, cfg["static_threshold"], cfg["static_window"]))
    all_alerts.extend(adaptive_threshold_rule(events, baseline))
    all_alerts.extend(account_diversity_rule(events, cfg["account_diversity_min"]))
    all_alerts.extend(time_of_day_rule(events, cfg["working_hours_start"], cfg["working_hours_end"]))
    all_alerts.extend(distributed_attack_rule(events, cfg.get("distributed_min_ips", 3)))

    # de-dupe: same ip + same rule fires multiple times, keep one
    # for distributed rule the "ip" is the subnet so this works fine
    seen = set()
    unique = []
    for a in all_alerts:
        key = (a["ip"], a["rule"])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique
