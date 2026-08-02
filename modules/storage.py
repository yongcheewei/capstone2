# saves alerts/events to disk for later review
import json
import csv
from datetime import datetime
import os


def save_json(alerts, output_path):
    # dump alerts as json - easier to read and use in other tools
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    serializable = []
    for a in alerts:
        a_copy = dict(a)
        for k, v in a_copy.items():
            if isinstance(v, datetime):
                a_copy[k] = v.isoformat()
        serializable.append(a_copy)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)


def save_csv(alerts, output_path):
    # same data but csv - nicer for opening in excel
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    if not alerts:
        # still write header so file isn't empty
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write("rule,ip,details,timestamp\n")
        return

    rows = []
    for a in alerts:
        # flatten details for csv
        details = {k: v for k, v in a.items() if k not in ("rule", "ip")}
        for k, v in list(details.items()):
            if isinstance(v, datetime):
                details[k] = v.isoformat()
        rows.append({
            "rule": a["rule"],
            "ip": a["ip"],
            "details": json.dumps(details),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        })

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rule", "ip", "details", "timestamp"])
        writer.writeheader()
        writer.writerows(rows)
