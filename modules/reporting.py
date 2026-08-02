# turns detection results into nice-looking stats
# these are the metrics we report in the capstone (precision, recall, f1, fpr)
from collections import Counter


def _ip_in_subnet(ip, subnet_with_mask):
    # check if an ip falls inside a "x.y.z.0/24" style subnet string
    # used to match the distributed rule's subnet-level alerts to individual ground-truth IPs
    if "/" not in subnet_with_mask:
        return False
    prefix = subnet_with_mask.split("/")[0]
    # strip the .0 at the end
    if prefix.endswith(".0"):
        prefix = prefix[:-2]
    return ip.startswith(prefix + ".")


def compute_metrics(alerts, ground_truth_attackers):
    # ground_truth_attackers is a set of ip addresses that are actually attackers
    # in real life you'd build this from external intel / labelled data
    detected_ips = set()
    detected_subnets = []
    for a in alerts:
        ip = a["ip"]
        if "/" in ip:
            detected_subnets.append(ip)
        else:
            detected_ips.add(ip)

    true_attackers = set(ground_truth_attackers)

    # for each subnet alert, check if it covers any true attacker
    subnet_tp = 0
    for subnet in detected_subnets:
        if any(_ip_in_subnet(t, subnet) for t in true_attackers):
            subnet_tp += 1

    # also expand subnet coverage for "already detected" check
    expanded_detected = set(detected_ips)
    for subnet in detected_subnets:
        for t in true_attackers:
            if _ip_in_subnet(t, subnet):
                expanded_detected.add(t)

    direct_tp = len(detected_ips & true_attackers)
    tp = direct_tp + subnet_tp
    fp = (len(detected_ips) - direct_tp) + (len(detected_subnets) - subnet_tp)
    fn = len(true_attackers - expanded_detected)
    tn = 0  # we don't track true negatives here, would need full ip list

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def rule_breakdown(alerts):
    # count how many alerts each rule generated
    counter = Counter(a["rule"] for a in alerts)
    return dict(counter)


def print_report(metrics, breakdown, total_events, skipped):
    # simple text report printed to console
    print("\n" + "=" * 50)
    print(" SSH BRUTE-FORCE DETECTION REPORT")
    print("=" * 50)
    print(f" Total events parsed : {total_events}")
    print(f" Lines skipped       : {skipped}")
    print(f" Total alerts raised : {sum(breakdown.values())}")
    print("-" * 50)
    print(" Alerts by rule:")
    for rule, count in breakdown.items():
        print(f"   - {rule:22s} : {count}")
    print("-" * 50)
    print(" Detection metrics:")
    print(f"   True positives    : {metrics['true_positives']}")
    print(f"   False positives   : {metrics['false_positives']}")
    print(f"   False negatives   : {metrics['false_negatives']}")
    print(f"   Precision         : {metrics['precision'] * 100:.1f}%")
    print(f"   Recall            : {metrics['recall'] * 100:.1f}%")
    print(f"   F1 Score          : {metrics['f1_score'] * 100:.1f}%")
    print("=" * 50 + "\n")
