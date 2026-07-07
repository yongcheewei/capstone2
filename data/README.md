# Datasets

This project uses **publicly available** authentication log datasets plus a
locally generated brute-force traffic capture. No real production logs are
committed; raw and processed data are listed in `.gitignore`.

## Sources

1. **Loghub Linux_auth** — labelled Linux syslog events. Download from
   <https://github.com/logpai/loghub>. Used for EDA in `notebooks/01_eda.ipynb`.
2. **Kaggle SSH brute-force datasets** — search "ssh brute force" on Kaggle
   for public mirrors of `hydra`/`medusa` traffic. Used for robustness tests.
3. **CERT/LANL** — anonymised insider-threat datasets, sampled for cross-eval.

## Synthetic

`scripts/generate_sample_log.py` produces a small synthetic `auth.log`
mixing benign `Accepted password` lines with `Failed password for invalid
user` floods. This file is the offline fixture used by the dashboard
and the unit tests.

To regenerate:

```bash
python scripts/generate_sample_log.py --out data/processed/sample_auth.log \
    --attacker 1.2.3.4 --benign-count 40 --attack-count 60
```

## Label / attack-IP convention

During training, attack IPs are derived from rule-engine detections
(self-supervision) or from a curated list in
`data/processed/groundtruth_ips.txt`. The latter is the source of truth
for evaluation; one IP per line.
