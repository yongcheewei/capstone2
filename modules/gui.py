# tkinter GUI - lets you click buttons instead of using the CLI
# embeds the 5 matplotlib figures so you can see results visually
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from modules.log_parser import parse_log, normalize_events, build_baseline
from modules.rule_engine import run_all_rules
from modules.storage import save_json, save_csv
from modules.reporting import compute_metrics, rule_breakdown
from modules.visualizer import generate_all, CHART_DESCRIPTIONS


# these are the IPs we know are real attackers in the sample log
# used for the precision/recall calculation
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


class DetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Brute-Force Detector")
        self.root.geometry("1100x750")

        # these are filled in after a run
        self.events = []
        self.alerts = []
        self.metrics = {}
        self.fig_paths = {}

        self._build_ui()

    def _build_ui(self):
        # top bar - file picker + buttons
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Log file:").pack(side="left")
        self.log_var = tk.StringVar(value="data/sample_auth.log")
        ttk.Entry(top, textvariable=self.log_var, width=60).pack(side="left", padx=5)

        ttk.Button(top, text="Browse", command=self._browse).pack(side="left", padx=2)
        ttk.Button(top, text="Run Detection", command=self._run).pack(side="left", padx=2)
        ttk.Button(top, text="Generate Figures", command=self._gen_figures).pack(side="left", padx=2)
        ttk.Button(top, text="Open Results Folder", command=self._open_results).pack(side="left", padx=2)

        # main area: left = chart list, middle = chart, right = explanation
        main = ttk.Frame(self.root, padding=5)
        main.pack(fill="both", expand=True)

        # left: listbox of charts
        left = ttk.Frame(main)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="Charts", font=("Arial", 10, "bold")).pack()
        self.chart_list = tk.Listbox(left, height=8, width=22, exportselection=False)
        for key in CHART_DESCRIPTIONS:
            title, _ = CHART_DESCRIPTIONS[key]
            self.chart_list.insert("end", title)
        self.chart_list.pack(fill="y", expand=False)
        self.chart_list.bind("<<ListboxSelect>>", self._on_chart_select)

        # middle: chart canvas
        mid = ttk.Frame(main)
        mid.pack(side="left", fill="both", expand=True)
        self.canvas_frame = ttk.Frame(mid)
        self.canvas_frame.pack(fill="both", expand=True)

        # right: report text + explanation
        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True, padx=5)

        ttk.Label(right, text="Detection Report", font=("Arial", 10, "bold")).pack(anchor="w")
        self.report_text = scrolledtext.ScrolledText(right, height=14, width=45, wrap="word")
        self.report_text.pack(fill="x")

        ttk.Label(right, text="Chart Explanation", font=("Arial", 10, "bold")).pack(anchor="w", pady=(8, 0))
        self.explain_text = scrolledtext.ScrolledText(right, height=8, width=45, wrap="word")
        self.explain_text.pack(fill="both", expand=True)

        # status bar
        self.status_var = tk.StringVar(value="Ready. Click 'Run Detection' to start.")
        ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", side="bottom")

    def _browse(self):
        path = filedialog.askopenfilename(title="Pick auth.log file",
                                          filetypes=[("Log files", "*.log"), ("All", "*.*")])
        if path:
            self.log_var.set(path)

    def _open_results(self):
        path = os.path.abspath("results")
        if not os.path.exists(path):
            messagebox.showinfo("No results", "Run detection first.")
            return
        # on windows, os.startfile opens the folder in explorer
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform.startswith("darwin"):
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _run(self):
        log_path = self.log_var.get().strip()
        if not log_path or not os.path.exists(log_path):
            messagebox.showerror("Error", f"Log file not found:\n{log_path}")
            return

        try:
            self.status_var.set("Parsing log...")
            self.root.update()

            events, skipped = parse_log(log_path)
            events = normalize_events(events)
            baseline = build_baseline(events)
            alerts = run_all_rules(events, baseline=baseline)

            # use sample ground truth if the file is the bundled one
            gt = SAMPLE_GROUND_TRUTH if "sample_auth" in log_path else None
            metrics = compute_metrics(alerts, gt) if gt else {}

            self.events = events
            self.alerts = alerts
            self.metrics = metrics

            # write results to disk
            os.makedirs("results", exist_ok=True)
            save_json(alerts, "results/alerts.json")
            save_csv(alerts, "results/alerts.csv")
            if metrics:
                import json as _json
                with open("results/metrics.json", "w") as f:
                    _json.dump(metrics, f, indent=2)

            self._fill_report(skipped)
            self.status_var.set(f"Done. {len(events)} events, {len(alerts)} alerts.")
        except Exception as e:
            messagebox.showerror("Run failed", str(e))
            self.status_var.set("Failed.")

    def _fill_report(self, skipped):
        self.report_text.delete("1.0", "end")
        self.report_text.insert("end", "=" * 40 + "\n")
        self.report_text.insert("end", " SSH BRUTE-FORCE DETECTION REPORT\n")
        self.report_text.insert("end", "=" * 40 + "\n")
        self.report_text.insert("end", f" Events parsed     : {len(self.events)}\n")
        self.report_text.insert("end", f" Lines skipped     : {skipped}\n")
        self.report_text.insert("end", f" Total alerts      : {len(self.alerts)}\n")
        self.report_text.insert("end", "-" * 40 + "\n")
        self.report_text.insert("end", " Alerts by rule:\n")
        for rule, count in rule_breakdown(self.alerts).items():
            self.report_text.insert("end", f"   - {rule:22s} : {count}\n")
        if self.metrics:
            self.report_text.insert("end", "-" * 40 + "\n")
            self.report_text.insert("end", " Metrics:\n")
            self.report_text.insert("end", f"   TP={self.metrics['true_positives']}  "
                                          f"FP={self.metrics['false_positives']}  "
                                          f"FN={self.metrics['false_negatives']}\n")
            self.report_text.insert("end", f"   Precision : {self.metrics['precision']*100:.1f}%\n")
            self.report_text.insert("end", f"   Recall    : {self.metrics['recall']*100:.1f}%\n")
            self.report_text.insert("end", f"   F1 Score  : {self.metrics['f1_score']*100:.1f}%\n")

    def _gen_figures(self):
        if not self.events:
            messagebox.showinfo("No data", "Run detection first.")
            return
        try:
            self.status_var.set("Drawing figures...")
            self.root.update()
            self.fig_paths = generate_all(self.events, self.alerts, self.metrics,
                                         output_dir="results/figures")
            self.status_var.set(f"Generated {len(self.fig_paths)} figures.")

            # auto-select first chart to display
            if self.chart_list.size() > 0:
                self.chart_list.selection_clear(0, "end")
                self.chart_list.selection_set(0)
                self._on_chart_select(None)
        except Exception as e:
            messagebox.showerror("Figure error", str(e))
            self.status_var.set("Figure generation failed.")

    def _on_chart_select(self, _event):
        if not self.fig_paths:
            return
        sel = self.chart_list.curselection()
        if not sel:
            return
        idx = sel[0]
        key = list(CHART_DESCRIPTIONS.keys())[idx]
        path = self.fig_paths.get(key)
        if not path or not os.path.exists(path):
            self.status_var.set(f"Figure not found: {key}")
            return

        # clear old canvas
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        # embed matplotlib figure
        fig = plt.figure(figsize=(7, 5))
        img = plt.imread(path)
        plt.imshow(img)
        plt.axis("off")
        plt.title(CHART_DESCRIPTIONS[key][0])
        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

        # show explanation text
        self.explain_text.delete("1.0", "end")
        title, desc = CHART_DESCRIPTIONS[key]
        self.explain_text.insert("end", f"{title}\n\n", "bold")
        self.explain_text.insert("end", desc)
        self.explain_text.tag_config("bold", font=("Arial", 10, "bold"))


def launch():
    root = tk.Tk()
    DetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
