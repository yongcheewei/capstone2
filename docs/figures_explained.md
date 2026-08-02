# Figures Explained

This document explains each of the 6 charts that the project generates,
how to read them, and which Research Question (RQ) from the Capstone 2
report each one addresses. All charts are produced by `modules/visualizer.py`
and saved to `results/figures/`.

---

## Chart 1: Top 10 IPs by Failed Login Attempts
**File:** `results/figures/failed_per_ip.png`

**How to read it:**
- X axis = source IP address
- Y axis = number of failed login attempts from that IP
- The number on top of each bar is the exact count

**How to interpret it:**
- Normal users fail 1-2 times (typos); above 5 starts to be suspicious
- Brute-force attacks usually push past 10
- In the sample log, the top 3 are `203.0.113.45`, `198.51.100.77` and `192.0.2.13` - these are the attackers

**Maps to RQ:** RQ1 - which IP behaviours are most suspicious and need rules to catch them.

---

## Chart 2: Failed Login Timeline (Hourly)
**File:** `results/figures/timeline.png`

**How to read it:**
- X axis = time (one data point per hour)
- Y axis = total failed login attempts during that hour
- Blue line + light blue fill

**How to interpret it:**
- Normal working hours (9-5) with a few failures = users mistyping
- Sudden spike at 2-5am = classic brute-force timing
- Attackers prefer off-hours because nobody is watching the alerts

**Maps to RQ:** RQ2 + RQ3 - the empirical basis for adaptive thresholding and the off-hours rule.

---

## Chart 3: Alert Distribution by Detection Rule
**File:** `results/figures/rule_breakdown.png`

**How to read it:**
- Pie chart where each slice = one detection rule (static_threshold, adaptive_threshold, account_diversity, off_hours)
- Percentage = share of total alerts raised by that rule

**How to interpret it:**
- A rule that dominates the pie is doing most of the heavy lifting right now
- A rule that never fires may have its threshold set too high
- Ideally all four rules contribute - that means broader defensive coverage

**Maps to RQ:** RQ1 - the multi-rule hybrid approach the Capstone 2 report recommends.

---

## Chart 4: Detection Performance Metrics
**File:** `results/figures/metrics.png`

**How to read it:**
- Three bars: Precision (green), Recall (blue), F1 Score (yellow)
- Units are percentages (%), scale 0-100

**How to interpret it:**
- **Precision (positive predictive value):** of all alerts raised, how many were real attackers. High = few false positives, low = lots of false positives and the rules need tuning.
- **Recall (sensitivity):** of all real attackers, how many did we catch. High = few false negatives, low = dangerous because attacks are slipping through.
- **F1 Score:** harmonic mean of Precision and Recall; a single number to summarise the detector. 80%+ is acceptable, 90%+ is excellent.

**Maps to RQ:** RQ1 + RQ2 - the empirical evidence that the detector actually works.

---

## Chart 6: Distributed Attack Subnet Analysis
**File:** `results/figures/distributed_attack.png`

**How to read it:**
- X axis = external /24 subnet (we exclude private RFC 1918 ranges because those are our own network, not attackers)
- Y axis = number of unique IPs inside that subnet that produced failed logins
- Bar height = how many bots are working together from one subnet

**How to interpret it:**
- A single IP with many failures is normal brute force (caught by static_threshold)
- Multiple IPs from the same subnet failing in a coordinated way is a **botnet** (caught by distributed_attack rule)
- Subnets with 2-3 IPs are the most common botnet pattern

**Maps to RQ:** RQ1 + addresses the distributed-attack research gap from Capstone 2 Section 2.4 (where Fail2Ban/SSHGuard struggle).

---

## Chart 5: Static Threshold vs Adaptive Threshold
**File:** `results/figures/static_vs_adaptive.png`

**How to read it:**
- Two bars: yellow = alerts raised by static threshold, green = alerts raised by adaptive threshold
- Both run on the same log for a fair comparison

**How to interpret it:**
- **Static threshold** uses a fixed "5 failed logins" rule for every IP. Easy to implement but flag innocent users who mistype a lot.
- **Adaptive threshold** tunes the limit per IP based on observed baseline behaviour. Tolerant of normal noise, strict on anomalies.

**From the Capstone 2 report:**
> "Adaptive thresholding, tailored to baseline login behaviour, improved detection performance by approximately 30% compared to static rules."

**Demo result on the sample log:**
- Static: 4 alerts (includes 1 false positive - a legitimate user who mistyped 6 times in a row)
- Adaptive: 3 alerts (skipped the false positive)
- Direct empirical support for the Capstone 2 claim

**Maps to RQ:** **Direct answer to RQ2** - the static-vs-adaptive comparison.

---

## How to generate the figures

```bash
# Method 1: CLI with --figures flag
python main.py --figures

# Method 2: one-click script
python scripts/generate_report.py
```
