# this module draws 6 charts that explain the detection results
# each chart has a short title + a one-line takeaway
import os
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib
# headless backend so the script runs on servers without a display
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# 中文需要这个才能显示,不然会出现方块
plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "Arial Unicode MS", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False


# short explanations for each chart - shown in the markdown
CHART_DESCRIPTIONS = {
    "failed_per_ip": (
        "Chart 1: Failed attempts per IP",
        "Bar chart of the top 10 IPs by failed login count. The taller the bar, "
        "the more suspicious the IP. Legitimate users typically fail 1-2 times; "
        "anything above 5 is worth investigating. Brute-force attacks usually "
        "push well past 10.",
    ),
    "timeline": (
        "Chart 2: Failed login timeline",
        "Line chart of failed attempts grouped by hour. Useful for spotting when "
        "attacks happen - sharp spikes at 2-5am are the classic brute-force "
        "pattern, while daytime spikes may indicate either honest typos or "
        "insider misuse.",
    ),
    "rule_breakdown": (
        "Chart 3: Alerts by rule",
        "Pie chart of how many alerts each detection rule raised. A rule that "
        "fires a lot is currently carrying most of the load; a rule that never "
        "fires may have its threshold set too high. A balanced pie across all "
        "rules means wider defensive coverage.",
    ),
    "metrics": (
        "Chart 4: Detection performance metrics",
        "Bar chart of Precision, Recall and F1 score. All three close to 100% "
        "means the detector is performing well. Low Precision = too many false "
        "positives (administrator alert fatigue). Low Recall = too many attacks "
        "slipping through (false negatives).",
    ),
    "static_vs_adaptive": (
        "Chart 5: Static threshold vs Adaptive threshold",
        "Direct answer to RQ2. Compares how many alerts each thresholding "
        "strategy raised on the same log. Adaptive usually wins because it "
        "tunes the threshold to each IP's own baseline - this is the empirical "
        "evidence for the 30% false-positive reduction claimed in the Capstone 2 report.",
    ),
    "distributed_attack": (
        "Chart 6: Distributed attack subnet analysis",
        "Bar chart of how many attacker IPs are coming from each /24 subnet. "
        "When 3+ IPs from the same subnet fail on the same target username "
        "within a short window, the distributed attack rule fires. This is the "
        "botnet detection path - it catches coordinated attacks that single-IP "
        "rules would miss.",
    ),
}


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def chart_failed_per_ip(events, output_dir):
    # top 10 ip by failed login count
    fails = Counter(e["ip"] for e in events if e["status"] == "failed")
    top = fails.most_common(10)
    if not top:
        return None

    ips, counts = zip(*top)
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(ips, counts, color="#d9534f")
    ax.set_title("Top 10 IPs by Failed Login Attempts")
    ax.set_xlabel("Source IP")
    ax.set_ylabel("Failed attempts")
    ax.tick_params(axis="x", rotation=30)
    # write count on top of each bar
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                str(count), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    out = os.path.join(output_dir, "failed_per_ip.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def chart_timeline(events, output_dir):
    # group failed logins by hour, draw as line chart
    by_hour = defaultdict(int)
    for e in events:
        if e["status"] == "failed":
            key = e["timestamp"].strftime("%Y-%m-%d %H:00")
            by_hour[key] += 1

    if not by_hour:
        return None

    keys = sorted(by_hour.keys())
    vals = [by_hour[k] for k in keys]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(keys, vals, marker="o", color="#5bc0de", linewidth=2)
    ax.fill_between(keys, vals, alpha=0.2, color="#5bc0de")
    ax.set_title("Failed Login Attempts Over Time (Hourly)")
    ax.set_xlabel("Hour")
    ax.set_ylabel("Failed attempts")
    ax.tick_params(axis="x", rotation=45)
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()
    out = os.path.join(output_dir, "timeline.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def chart_rule_breakdown(alerts, output_dir):
    # pie chart of which rule fired how many times
    if not alerts:
        return None
    counts = Counter(a["rule"] for a in alerts)
    labels = list(counts.keys())
    sizes = list(counts.values())
    colors = ["#d9534f", "#5bc0de", "#5cb85c", "#f0ad4e", "#9b59b6"]

    fig, ax = plt.subplots(figsize=(7, 7))
    ax.pie(sizes, labels=labels, colors=colors[: len(labels)],
           autopct="%1.1f%%", startangle=90)
    ax.set_title("Alert Distribution by Detection Rule")
    fig.tight_layout()
    out = os.path.join(output_dir, "rule_breakdown.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def chart_metrics(metrics, output_dir):
    if not metrics:
        return None
    keys = ["precision", "recall", "f1_score"]
    vals = [metrics.get(k, 0) * 100 for k in keys]

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(keys, vals, color=["#5cb85c", "#5bc0de", "#f0ad4e"])
    ax.set_title("Detection Performance Metrics")
    ax.set_ylabel("Percentage (%)")
    ax.set_ylim(0, 105)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{v:.1f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")
    fig.tight_layout()
    out = os.path.join(output_dir, "metrics.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def chart_static_vs_adaptive(events, output_dir):
    # run static and adaptive rules separately to compare them head-to-head
    # this answers RQ2 from the report
    from modules.rule_engine import (
        static_threshold_rule,
        adaptive_threshold_rule,
        DEFAULT_CONFIG,
    )

    # static
    static_alerts = static_threshold_rule(
        events, DEFAULT_CONFIG["static_threshold"], DEFAULT_CONFIG["static_window"]
    )
    # adaptive (use a simple baseline = same as build_baseline)
    from modules.log_parser import build_baseline
    baseline = build_baseline(events)
    adaptive_alerts = adaptive_threshold_rule(events, baseline)

    # build a side-by-side bar
    labels = ["Static", "Adaptive"]
    s_count = len(static_alerts)
    a_count = len(adaptive_alerts)

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(labels, [s_count, a_count], color=["#f0ad4e", "#5cb85c"])
    ax.set_title("Static Threshold vs Adaptive Threshold\n(alerts raised on same log)")
    ax.set_ylabel("Number of alerts")
    for bar, v in zip(bars, [s_count, a_count]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                str(v), ha="center", va="bottom", fontsize=12, fontweight="bold")
    fig.tight_layout()
    out = os.path.join(output_dir, "static_vs_adaptive.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def chart_distributed_attack(events, output_dir):
    # show how many attacking IPs come from each EXTERNAL /24 subnet
    # we exclude RFC 1918 private ranges because those are our own network -
    # failed logins there are just user typos, not coordinated attacks
    from collections import Counter
    subnet_ip_fails = defaultdict(lambda: defaultdict(int))
    for e in events:
        if e["status"] == "failed":
            parts = e["ip"].split(".")
            if len(parts) == 4:
                first_octet = int(parts[0])
                # skip private ranges (10.x, 172.16-31.x, 192.168.x)
                if first_octet == 10 or (first_octet == 172 and 16 <= int(parts[1]) <= 31) \
                   or (first_octet == 192 and parts[1] == "168"):
                    continue
                subnet = ".".join(parts[:3])
                subnet_ip_fails[subnet][e["ip"]] += 1

    # keep subnets with 2+ ips having failed logins
    candidates = {s: ips for s, ips in subnet_ip_fails.items() if len(ips) >= 2}
    if not candidates:
        return None

    subnets = sorted(candidates.keys(), key=lambda s: len(candidates[s]), reverse=True)
    counts = [len(candidates[s]) for s in subnets]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(subnets, counts, color="#9b59b6")
    ax.set_title("Distributed Attack Subnet Analysis\n(external /24 subnets with 2+ attacking IPs)")
    ax.set_xlabel("Source subnet (/24)")
    ax.set_ylabel("Unique IPs with failed logins")
    for bar, c in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                str(c), ha="center", va="bottom", fontsize=10, fontweight="bold")
    plt.xticks(rotation=20)
    fig.tight_layout()
    out = os.path.join(output_dir, "distributed_attack.png")
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return out


def generate_all(events, alerts, metrics, output_dir="results/figures"):
    # one entry point - draws all charts and returns their file paths
    _ensure_dir(output_dir)
    paths = {}
    paths["failed_per_ip"] = chart_failed_per_ip(events, output_dir)
    paths["timeline"] = chart_timeline(events, output_dir)
    paths["rule_breakdown"] = chart_rule_breakdown(alerts, output_dir)
    paths["metrics"] = chart_metrics(metrics, output_dir)
    paths["static_vs_adaptive"] = chart_static_vs_adaptive(events, output_dir)
    paths["distributed_attack"] = chart_distributed_attack(events, output_dir)
    return paths
