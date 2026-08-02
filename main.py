# main entry point - ties everything together
import argparse
import os
import sys

from modules.log_parser import parse_log, normalize_events, build_baseline
from modules.rule_engine import run_all_rules
from modules.storage import save_json, save_csv
from modules.reporting import compute_metrics, rule_breakdown, print_report


# ground truth for the sample log - which IPs are actually attackers
# in real deployment this would come from a labelled dataset or threat intel
SAMPLE_GROUND_TRUTH = {
    "203.0.113.45",   # fast brute force on root
    "198.51.100.77",  # account spray across many usernames
    "192.0.2.13",     # slow stealth attack, off-hours
    "45.32.10.4",     # distributed botnet attack
    "45.32.10.5",
    "45.32.10.6",
    "45.32.10.7",
    "185.220.101.50", # tor exit node, rapid root brute force
    "91.240.118.172", # low-and-slow off-hours attack
}


def run(log_path, output_dir="results", ground_truth=None, config=None, with_figures=False):
    # step 1: parse the log file
    print(f"[+] Reading log: {log_path}")
    events, skipped = parse_log(log_path)
    print(f"[+] Parsed {len(events)} events ({skipped} lines skipped)")

    if not events:
        print("[!] No events found, nothing to do.")
        return

    # step 2: normalise the events
    events = normalize_events(events)
    print(f"[+] Normalised {len(events)} events")

    # step 3: build adaptive baseline from "benign" portion of the log
    # for the sample log we just compute baseline from everything
    baseline = build_baseline(events)
    print(f"[+] Built baseline for {len(baseline)} IPs")

    # step 4: run all detection rules
    alerts = run_all_rules(events, baseline=baseline, config=config)
    print(f"[+] Raised {len(alerts)} alert(s)")

    # step 5: compute metrics if we have ground truth
    metrics = {}
    if ground_truth is not None:
        metrics = compute_metrics(alerts, ground_truth)
    breakdown = rule_breakdown(alerts)

    # step 6: print to console
    print_report(metrics, breakdown, len(events), skipped)

    # step 7: save results
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "alerts.json")
    csv_path = os.path.join(output_dir, "alerts.csv")
    save_json(alerts, json_path)
    save_csv(alerts, csv_path)
    print(f"[+] Saved alerts to {json_path}")
    print(f"[+] Saved alerts to {csv_path}")

    if metrics:
        import json as _json
        with open(os.path.join(output_dir, "metrics.json"), "w") as f:
            _json.dump(metrics, f, indent=2)
        print(f"[+] Saved metrics to {os.path.join(output_dir, 'metrics.json')}")

    # step 8 (optional): draw all 5 figures
    if with_figures:
        try:
            from modules.visualizer import generate_all
            fig_dir = os.path.join(output_dir, "figures")
            paths = generate_all(events, alerts, metrics, output_dir=fig_dir)
            print(f"[+] Generated {len([p for p in paths.values() if p])} figure(s) in {fig_dir}")
        except ImportError:
            print("[!] matplotlib not installed - skip figures (pip install matplotlib)")


def main():
    parser = argparse.ArgumentParser(
        description="Rule-based SSH brute-force attack detector"
    )
    parser.add_argument(
        "--log",
        default="data/sample_auth.log",
        help="path to auth.log file (default: data/sample_auth.log)",
    )
    parser.add_argument(
        "--output",
        default="results",
        help="output directory for alerts and metrics (default: results)",
    )
    parser.add_argument(
        "--no-ground-truth",
        action="store_true",
        help="skip metrics calculation (when ground truth is unavailable)",
    )
    parser.add_argument(
        "--figures",
        action="store_true",
        help="also generate matplotlib figures (saved under results/figures/)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[!] Log file not found: {args.log}")
        sys.exit(1)

    gt = None if args.no_ground_truth else SAMPLE_GROUND_TRUTH
    run(args.log, output_dir=args.output, ground_truth=gt, with_figures=args.figures)


if __name__ == "__main__":
    main()
