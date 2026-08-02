# one-click script - parse, detect, generate figures, save everything
# use this for cp2 demo / viva
import os
import sys
import json

# so we can run from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.log_parser import parse_log, normalize_events, build_baseline
from modules.rule_engine import run_all_rules
from modules.storage import save_json, save_csv
from modules.reporting import compute_metrics, rule_breakdown, print_report
from modules.visualizer import generate_all


SAMPLE_GROUND_TRUTH = {
    "203.0.113.45",
    "198.51.100.77",
    "192.0.2.13",
    "45.32.10.4",
    "45.32.10.5",
    "45.32.10.6",
    "45.32.10.7",
    "185.220.101.50",
    "91.240.118.172",
}


def main():
    log_path = "data/sample_auth.log"
    output_dir = "results"
    fig_dir = os.path.join(output_dir, "figures")

    if not os.path.exists(log_path):
        print(f"[!] log not found: {log_path}")
        sys.exit(1)

    print("=" * 50)
    print(" SSH BRUTE-FORCE DETECTOR - FULL REPORT RUN")
    print("=" * 50)

    # 1. parse
    print("\n[1/5] Parsing log...")
    events, skipped = parse_log(log_path)
    events = normalize_events(events)
    print(f"      {len(events)} events, {skipped} lines skipped")

    # 2. baseline + rules
    print("[2/5] Building baseline + running rules...")
    baseline = build_baseline(events)
    alerts = run_all_rules(events, baseline=baseline)
    print(f"      {len(alerts)} alerts raised")

    # 3. metrics
    print("[3/5] Computing metrics...")
    metrics = compute_metrics(alerts, SAMPLE_GROUND_TRUTH)
    breakdown = rule_breakdown(alerts)

    # 4. print + save
    print("[4/5] Saving text results...")
    print_report(metrics, breakdown, len(events), skipped)
    os.makedirs(output_dir, exist_ok=True)
    save_json(alerts, os.path.join(output_dir, "alerts.json"))
    save_csv(alerts, os.path.join(output_dir, "alerts.csv"))
    with open(os.path.join(output_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    # 5. figures
    print("[5/5] Generating figures...")
    paths = generate_all(events, alerts, metrics, output_dir=fig_dir)
    n = sum(1 for p in paths.values() if p)
    print(f"      {n} figure(s) saved to {fig_dir}/")

    print("\n[done] All results in 'results/' folder.")
    print("       Open results/figures/ to see the 6 charts.")


if __name__ == "__main__":
    main()
