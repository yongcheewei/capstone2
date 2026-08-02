# Detection of SSH Brute-Force Attacks Using Log-Pattern Rules

Rule-based detector for SSH brute-force attacks, implemented in pure
Python (stdlib + matplotlib). Reads Linux `auth.log`, applies 5
log-pattern detection rules (static threshold, adaptive threshold,
account diversity, off-hours, distributed botnet), and produces
alerts + precision/recall/F1 metrics + 6 result charts. Terminal-based
CLI only (no GUI).

## Project layout

```
capstone2-main/
├── main.py                  # CLI entry point
├── modules/
│   ├── log_parser.py        # parses + normalises auth.log
│   ├── rule_engine.py       # 5 rules: static, adaptive, account_diversity, off_hours, distributed
│   ├── storage.py           # json / csv writers
│   ├── reporting.py         # precision / recall / f1 / fpr
│   └── visualizer.py        # 6 matplotlib charts
├── tests/
│   ├── test_log_parser.py   # unit tests for parser
│   ├── test_rule_engine.py  # unit tests for all 5 rules
│   └── test_reporting.py    # unit tests for metrics math
├── data/
│   └── sample_auth.log      # sample log (167 events, 9 attackers)
├── scripts/
│   ├── generate_report.py   # one-click full run
│   ├── generate_data.py     # builds the sample auth.log
│   ├── run_tests.py         # run all unit tests
│   └── benchmark.py         # CPU / memory / throughput measurement
├── docs/
│   └── figures_explained.md # explanations for all 6 charts
├── results/                 # alerts, metrics, figures, benchmark
│   └── figures/             # 6 .png charts
├── requirements.txt
└── README.md
```

## Install

```bash
pip install -r requirements.txt
```

(Only matplotlib is needed; everything else is Python stdlib.)

## How to run

```bash
# run on bundled sample log
python main.py

# also generate the 6 figures
python main.py --figures

# run on your own log
python main.py --log /var/log/auth.log

# skip metrics (no ground truth available)
python main.py --no-ground-truth
```

## Rules implemented

| Rule | What it catches | Configurable in `rule_engine.DEFAULT_CONFIG` |
|---|---|---|
| `static_threshold` | N failed attempts in T seconds from one IP | `static_threshold`, `static_window` |
| `adaptive_threshold` | Failed attempts that exceed IP's own baseline | `adaptive_multiplier` |
| `account_diversity` | One IP hitting many different usernames | `account_diversity_min` |
| `off_hours` | Failed logins outside working hours | `working_hours_start`, `working_hours_end` |
| `distributed_attack` | 3+ IPs from same /24 subnet targeting same user (botnet) | `distributed_min_ips` |

## The 6 figures (saved to `results/figures/`)

1. `failed_per_ip.png` — Top 10 IPs by failed login count
2. `timeline.png` — Hourly failed login trend
3. `rule_breakdown.png` — Pie chart of which rules fired
4. `metrics.png` — Precision / Recall / F1 bar chart
5. `static_vs_adaptive.png` — Static vs adaptive comparison (RQ2 answer)
6. `distributed_attack.png` — /24 subnets with multiple failing IPs (botnet view)

For explanations of each chart, see `docs/figures_explained.md`.

## Tests and benchmarking

```bash
# run all unit tests (26 tests covering parser, rules, metrics)
python scripts/run_tests.py

# measure CPU time, memory, throughput
python scripts/benchmark.py
```

See the capstone report (Chapter 3) for the full design rationale.
