# SSH Brute-Force Detector

A simple rule-based detector for SSH brute-force attacks. Built as the
implementation for **Capstone Project 1** (SSH Brute-Force Detection using
Authentication Logs).

Reads Linux `auth.log`, applies 4 detection rules (static threshold,
adaptive threshold, account diversity, off-hours), produces alerts +
metrics + 5 figures. Has both a CLI and a GUI.

## Project layout

```
capstone2-main/
├── main.py                  # CLI entry point
├── run_gui.py               # GUI entry point
├── modules/
│   ├── log_parser.py        # parses + normalises auth.log
│   ├── rule_engine.py       # 5 rules: static, adaptive, account_diversity, off_hours, distributed
│   ├── storage.py           # json / csv writers
│   ├── reporting.py         # precision / recall / f1 / fpr
│   ├── visualizer.py        # 6 matplotlib charts
│   └── gui.py               # tkinter window + embedded charts
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

### CLI (terminal)

```bash
# run on bundled sample log
python main.py

# also generate the 5 figures
python main.py --figures

# run on your own log
python main.py --log /var/log/auth.log

# skip metrics (no ground truth available)
python main.py --no-ground-truth
```

### GUI (point-and-click)

```bash
python run_gui.py
```

GUI has:
- File picker for log file
- "Run Detection" button
- "Generate Figures" button
- List of 5 charts on the left
- Embedded matplotlib chart in the middle
- Detection report + chart explanation (中文) on the right
- "Open Results Folder" button to view output

### One-click full report

```bash
python scripts/generate_report.py
```

Parses log, runs rules, computes metrics, generates all 5 figures, prints
report. Easiest way to demo.

### Regenerate sample data

If you want a fresh sample log (the bundled one is generated with a fixed
random seed so it stays reproducible):

```bash
python scripts/generate_data.py
```

This rebuilds `data/sample_auth.log` with 3 days of normal traffic and 9
attacker IPs using different attack patterns (fast brute force, account
spray, slow stealth, distributed botnet, off-hours).

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
6. `distributed_attack.png` — External /24 subnets with multiple attackers (botnet detection)

For explanations of each chart, see `docs/figures_explained.md`.

## Tests and benchmarking

```bash
# run all unit tests (26 tests covering parser, rules, metrics)
python scripts/run_tests.py

# measure CPU time, memory, throughput
python scripts/benchmark.py
```

See the capstone report (Chapter 3) for the full design rationale.
