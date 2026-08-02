# measures CPU time, memory usage and throughput on a given log file
# this is the "Performance Testing" mentioned in cp1 section 3.4
# and the "Measure system resource usage" from section 3.6
import time
import sys
import os
import tracemalloc
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.log_parser import parse_log, normalize_events, build_baseline
from modules.rule_engine import run_all_rules
from modules.storage import save_json, save_csv
from modules.reporting import compute_metrics, rule_breakdown


SAMPLE_GROUND_TRUTH = {
    "203.0.113.45", "198.51.100.77", "192.0.2.13",
    "45.32.10.4", "45.32.10.5", "45.32.10.6", "45.32.10.7",
    "185.220.101.50", "91.240.118.172",
}


def benchmark(log_path, runs=3):
    # run the full pipeline runs times to get an average
    timings = []
    peak_mem = 0
    alerts = []

    for i in range(runs):
        tracemalloc.start()
        t0 = time.perf_counter()

        # step 1: parse
        events, _ = parse_log(log_path)
        events = normalize_events(events)
        baseline = build_baseline(events)

        # step 2: detect
        alerts = run_all_rules(events, baseline=baseline)

        # step 3: metrics
        metrics = compute_metrics(alerts, SAMPLE_GROUND_TRUTH)

        elapsed = time.perf_counter() - t0
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        timings.append(elapsed)
        peak_mem = max(peak_mem, peak)

    avg_time = sum(timings) / len(timings)
    throughput = len(events) / avg_time if avg_time > 0 else 0

    # count log lines
    with open(log_path, "r") as f:
        n_lines = sum(1 for _ in f)

    return {
        "log_file": log_path,
        "log_lines": n_lines,
        "runs": runs,
        "avg_time_seconds": round(avg_time, 4),
        "min_time_seconds": round(min(timings), 4),
        "max_time_seconds": round(max(timings), 4),
        "events_parsed": len(events),
        "alerts_raised": len(alerts),
        "throughput_events_per_sec": round(throughput, 1),
        "peak_memory_mb": round(peak_mem / 1024 / 1024, 2),
        "metrics": metrics,
    }


def main():
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    else:
        log_path = "data/sample_auth.log"

    if not os.path.exists(log_path):
        print(f"[!] log not found: {log_path}")
        sys.exit(1)

    print("=" * 55)
    print(" PERFORMANCE BENCHMARK")
    print("=" * 55)
    print(f" Log: {log_path}")
    print()

    result = benchmark(log_path, runs=3)

    print(f" Log lines        : {result['log_lines']}")
    print(f" Events parsed    : {result['events_parsed']}")
    print(f" Alerts raised    : {result['alerts_raised']}")
    print()
    print(f" Avg time         : {result['avg_time_seconds']}s")
    print(f" Min time         : {result['min_time_seconds']}s")
    print(f" Max time         : {result['max_time_seconds']}s")
    print(f" Throughput       : {result['throughput_events_per_sec']} events/sec")
    print(f" Peak memory      : {result['peak_memory_mb']} MB")
    print()
    print(" Detection metrics:")
    m = result["metrics"]
    print(f"   Precision      : {m['precision']*100:.1f}%")
    print(f"   Recall         : {m['recall']*100:.1f}%")
    print(f"   F1 Score       : {m['f1_score']*100:.1f}%")
    print("=" * 55)

    # save report
    os.makedirs("results", exist_ok=True)
    with open("results/benchmark.json", "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n[+] Saved to results/benchmark.json")


if __name__ == "__main__":
    main()
