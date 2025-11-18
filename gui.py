import os
import json
import csv
import threading
import subprocess
import psutil
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, Optional, List
from socket import getservbyport
from config import APP_NAME, DATA_DIR
from config import APP_NAME, APP_VERSION, LAST_SCAN_JSON, IS_WINDOWS
from plugins import STATUS_PASS, STATUS_WARN, STATUS_FAIL, STATUS_SKIPPED, OpenPortsCheck
from orchestrator import Orchestrator
from quiz_manager import QuizManager
from plugins import (
    FirewallStatusCheck,
    AntivirusStatusCheck,
    OSUpdatesCheck,
    AutoLoginCheck,
    WifiSecurityCheck
)
from utils import is_admin
import webbrowser
import sys
import pathlib

def open_manual():
    path = pathlib.Path(__file__).parent / "manual.html"
    if not path.exists():
        print(f"File not found: {path}")
        return
    file_url = path.resolve().as_uri()
    webbrowser.open(file_url)

# ---------------- Status Colors ----------------
STATUS_COLORS = {
    STATUS_PASS: "#22c55e",
    STATUS_WARN: "#eab308",
    STATUS_FAIL: "#ef4444",
    STATUS_SKIPPED: "#9ca3af",
}

# ---------------- Plugin Setup ----------------
PLUGINS = [
    FirewallStatusCheck(),
    AntivirusStatusCheck(),
    OSUpdatesCheck(),
    OpenPortsCheck(),
    AutoLoginCheck(),
    WifiSecurityCheck(),
]

DEFAULT_WEIGHTS = {
    "antivirus_status": 15,
    "firewall_status": 15,
    "os_updates": 12,
    "open_ports": 10,
    "auto_login": 8,
    "wifi_security": 8,
}

# ---------------- Common Ports Info ----------------
COMMON_PORT_INFO = {
    21: ("FTP", "Legacy clear-text file transfer; brute-force/leak risk."),
    22: ("SSH", "Remote shell; exposed creds/bruteforce risk if public."),
    23: ("Telnet", "Clear-text remote shell; high risk."),
    25: ("SMTP", "Mail transfer; open relay abuse risk."),
    53: ("DNS", "DNS server; reflection/amplification risk."),
    80: ("HTTP", "Web server; if unpatched, vuln exposure."),
    135: ("RPC Endpoint Mapper", "Lateral movement target, DCOM/RPC abuse."),
    139: ("NetBIOS Session", "Legacy fileshares; info leakage/lateral move."),
    443: ("HTTPS", "Web server; patching/cert hygiene required."),
    445: ("SMB", "Ransomware/worm favorite; block on unneeded hosts."),
    3306: ("MySQL", "Database; credential brute-force/data exfil risk."),
    3389: ("RDP", "Remote Desktop; brute-force/RCE risk if exposed."),
}

# ---------------- Helpers ----------------
def parse_port(addr: str) -> Optional[int]:
    m = re.search(r":(\d+)$", addr.strip())
    return int(m.group(1)) if m else None


def get_port_hint(port: int) -> str:
    if port in COMMON_PORT_INFO:
        return COMMON_PORT_INFO[port][0]
    try:
        return getservbyport(port)
    except Exception:
        return "Unknown/Custom"

def get_services_for_pid_windows(pid: int, port: Optional[int] = None) -> List[str]:
    services = []
    try:
        out = subprocess.check_output(
            ["tasklist", "/svc", "/FI", f"PID eq {pid}"],
            text=True,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        lines = [l for l in out.splitlines() if l.strip()]
        if len(lines) >= 4:
            svc_line = lines[-1]
            cols = re.split(r"\s{2,}", svc_line.strip())
            if len(cols) >= 3:
                svc_names = [
                    s.strip()
                    for s in re.split(r"[,\s]+", cols[-1])
                    if s.strip() and s != "N/A"
                ]
                if svc_names:
                    return svc_names
    except Exception:
        pass

    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        if exe:
            services.append(f"EXE: {exe}")
        else:
            services.append(f"PROC: {proc.name()}")
    except Exception:
        try:
            proc_name = psutil.Process(pid).name()
            services.append(f"PROC: {proc_name}")
        except Exception:
            services.append("Unknown process")

    if port is not None:
        port_name = get_port_hint(port)
        if port_name and port_name not in services:
            services.append(f"Port Hint: {port_name}")

    return services

def list_listeners() -> List[Dict[str, Any]]:
    results = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                addr = f"{c.laddr.ip}:{c.laddr.port}"
                pid = c.pid or 0
                proc_name = None
                try:
                    if pid:
                        proc_name = psutil.Process(pid).name()
                except Exception:
                    proc_name = None
                services = (
                    get_services_for_pid_windows(pid, c.laddr.port)
                    if IS_WINDOWS and pid
                    else [f"Port Hint: {get_port_hint(c.laddr.port)}"]
                )
                results.append(
                    {
                        "addr": addr,
                        "port": c.laddr.port,
                        "pid": pid,
                        "proc": proc_name,
                        "services": services,
                    }
                )
    except Exception as e:
        results.append({"error": str(e)})
    results.sort(key=lambda x: (x.get("port") or 0, x.get("addr", "")))
    return results

def close_port_windows(pid: int, services: List[str]) -> bool:
    for s in services:
        try:
            # subprocess.run(["sc", "stop", s], capture_output=True, text=True)
            creationflags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
            subprocess.run(
                ["sc", "stop", s],
                capture_output=True,
                text=True,
                creationflags=creationflags
            )

        except Exception:
            pass
        try:
            if pid:
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                    p.wait(timeout=2)
                except Exception:
                    pass
                if IS_WINDOWS:
                    subprocess.run(
                        ["taskkill", "/PID", str(pid), "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW  # 👈 prevents CMD flash
                    )
                else:
                    # Unix / Linux fallback
                    try:
                        psutil.Process(pid).kill()
                    except Exception:
                        pass
        except Exception:
            pass

    return True

def port_is_still_listening(target_port: int) -> bool:
    try:
        for c in psutil.net_connections(kind="inet"):
            if (
                c.status == psutil.CONN_LISTEN
                and c.laddr
                and c.laddr.port == target_port
            ):
                return True
    except Exception:
        return False
    return False

def describe_port(port: int) -> str:
    name, risk = COMMON_PORT_INFO.get(
        port, ("Unknown/Custom", "May expose the application bound to this port.")
    )
    return f"{name} (TCP/{port}) — {risk}"

# ---------------- Open Ports GUI ----------------
class OpenPortsGUI(ttk.Frame):
    def __init__(self, parent, initial_ports: List[Dict[str, Any]]):
        super().__init__(parent)
        self.all_ports: List[Dict[str, Any]] = initial_ports[:] if initial_ports else []
        self._build_ui()
        self._render_all()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, pady=6)
        ttk.Label(top, text="Open Ports (Listening)", font=("Segoe UI", 12, "bold")).pack(
            side=tk.LEFT
        )
        actions = ttk.Frame(top)
        actions.pack(side=tk.RIGHT)
        ttk.Button(actions, text="Refresh", command=self.refresh, cursor="hand2").pack(side=tk.LEFT, padx=4)

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("address", "pid", "process", "services"),
            show="headings",
            height=20,
        )
        for c, w in zip(("address", "pid", "process", "services"), (220, 80, 160, 380)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor=tk.W if c != "pid" else tk.CENTER)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.close_btn = ttk.Button(
            self, text="CLOSE Selected Port", command=self.close_selected, cursor="hand2"
        )
        self.close_btn.pack(anchor=tk.E, padx=6, pady=4)

    def set_data(self, ports: List[Dict[str, Any]]):
        self.all_ports = ports[:] if ports else []
        self._render_all()

    def _render_all(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        if not self.all_ports:
            return
        for p in self.all_ports:
            services_str = ", ".join(p.get("services", []))
            self.tree.insert(
                "", tk.END, values=(p.get("addr", "?"), p.get("pid", ""), p.get("proc", ""), services_str)
            )

    def refresh(self):
        def _refresh():
            ports = list_listeners()
            self.after(0, lambda: self.set_data(ports))
        threading.Thread(target=_refresh, daemon=True).start()


    def close_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select a port row first.")
            return
        addr, pid_str, proc, services_str = self.tree.item(sel[0], "values")
        port = parse_port(addr) or 0
        pid = int(pid_str) if str(pid_str).isdigit() else 0
        services = [s.strip() for s in services_str.split(",") if s.strip()]

        msg = (
            f"{describe_port(port)}\n\nListening: {addr}\nProcess: {proc or 'Unknown'} (PID: {pid or 'N/A'})\n"
            f"Dependent services: {', '.join(services) if services else 'None detected'}\n\n"
            "Risks if OPEN:\n"
            "• If exposed, attackers may scan and attempt exploits/bruteforce.\n"
            "• If closed, any app using this port will stop responding.\n\nProceed to CLOSE?"
        )
        if not messagebox.askyesno("Close Port", msg):
            return

        success = False
        err = None
        try:
            if IS_WINDOWS:
                success = close_port_windows(pid, services)
            else:
                if pid:
                    try:
                        psutil.Process(pid).terminate()
                    except Exception:
                        pass
                    try:
                        psutil.Process(pid).kill()
                    except Exception:
                        pass
                success = True
        except Exception as e:
            success = False
            err = str(e)

        still = port_is_still_listening(port) if port else False
        if success and not still:
            messagebox.showinfo("Port Closed", f"Port {port} is now closed.")
            self.refresh()
        else:
            detail = f"\nDetail: {err}" if err else ""
            messagebox.showerror(
                "Failed",
                "Could not close port. Run as Administrator or close via app/service config." + detail,
            )

# ---------------- Modern GUI Styling ----------------
def apply_styles(root: tk.Tk):
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # ---------------- Colors ----------------
    BG_COLOR = "#ffe4e1"        # Pale pink background
    FRAME_COLOR = "#fff0f5"     # Lighter frame / panel color
    ACCENT_COLOR = "#56a7e4"    # Crimson for buttons & selected tabs
    TEXT_COLOR = "#2f2f2f"      # Dark text for readability
    STATUS_READY_COLOR = "#af9c9c"

    root.configure(bg=BG_COLOR)

    # ---------------- Buttons ----------------
    style.configure(
        "TButton",
        background=ACCENT_COLOR,
        foreground="#fff",
        font=("Segoe UI", 10, "bold"),
        padding=6,
        borderwidth=0,
    )
    style.map(
        "TButton",
        background=[("active", "#56a7e4")],  # slightly darker crimson on hover
        relief=[("pressed", "sunken")],
    )

    # ---------------- Treeview ----------------
    style.configure(
        "Treeview",
        background=FRAME_COLOR,
        foreground=TEXT_COLOR,
        rowheight=24,
        fieldbackground=FRAME_COLOR,
        font=("Segoe UI", 10),
    )
    style.configure(
        "Treeview.Heading",
        font=("Segoe UI", 10, "bold"),
        background=ACCENT_COLOR,
        foreground="#fff",
    )
    style.map(
        "Treeview",
        background=[("selected", ACCENT_COLOR)],
        foreground=[("selected", "#fff")]
    )

    # ---------------- Notebook Tabs ----------------
    style.configure("TNotebook", background=BG_COLOR)
    style.configure(
        "TNotebook.Tab",
        padding=[12, 8],
        font=("Segoe UI", 10, "bold"),
        background=FRAME_COLOR,
        foreground=TEXT_COLOR,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", ACCENT_COLOR)],
        foreground=[("selected", "#fff")],
    )

    # ---------------- Text widget ----------------
    root.option_add("*Text.Background", FRAME_COLOR)
    root.option_add("*Text.Foreground", TEXT_COLOR)
    root.option_add("*Text.Font", ("Segoe UI", 10))

# ---------------- Main App ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()

        apply_styles(self)

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.state("zoomed")
        self.minsize(900, 600)

        self.showing_last = False

        self.orchestrator = Orchestrator(PLUGINS, DEFAULT_WEIGHTS)
        self.current_results: Optional[Dict[str, Any]] = None
        self.quiz_manager = QuizManager("quiz.json")
        self.quiz_total = 10

        # Privilege banner
        self.banner_var = tk.StringVar(value="")
        self.banner_label = tk.Label(
            self,
            textvariable=self.banner_var,
            bg="orange",
            fg="black",
            font=("Segoe UI", 10, "bold")
        )
        self.banner_label.pack(fill=tk.X)

        self._build_ui()
        self.status_var.set("Ready. Click Run Scan.")
        self.load_question()

        # Show admin warning at startup
        if not is_admin():
            self.banner_var.set("⚠️ Some checks may be incomplete without Admin/Root privileges")
            self.banner_label.pack(fill=tk.X)
        else:
            self.banner_label.pack_forget()

    # ---------------- UI BUILD ----------------
    def _build_ui(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        scan_tab = ttk.Frame(self.tabs)
        self.tabs.add(scan_tab, text="Security Scan")
        self._build_scan_ui(scan_tab)

        quiz_tab = ttk.Frame(self.tabs)
        self.tabs.add(quiz_tab, text="Quiz")
        self._build_quiz_ui(quiz_tab)

        self.ports_tab = None
        self.ports_gui: Optional[OpenPortsGUI] = None

    # ---------------- Security Scan Tab ----------------
    def _build_scan_ui(self, parent):
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, padx=12, pady=10)
        self.score_var = tk.StringVar(value="Score: RUN SCAN")
        ttk.Label(header, textvariable=self.score_var, font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT)
        btn_frame = ttk.Frame(header)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Run Scan", command=self.run_scan, cursor="hand2").pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv, cursor="hand2").pack(side=tk.LEFT, padx=6)
        
        self.report_button = ttk.Button(btn_frame, text="Open Last Report", command=self.toggle_report, cursor="hand2")
        self.report_button.pack(side=tk.LEFT, padx=6)

        ttk.Button(btn_frame, text="Manual", command=open_manual, cursor="hand2").pack(side=tk.LEFT, padx=6)

        mid = ttk.Panedwindow(parent, orient=tk.HORIZONTAL)
        mid.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)
        left = ttk.Frame(mid)
        right = ttk.Frame(mid)
        mid.add(left, weight=0)
        mid.add(right, weight=5)

        # ---------------- LEFT PANEL ----------------
        cols = ("Check", "Status", "Score")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=18)

        # Configure columns
        for i, c in enumerate(cols):
            anchor = tk.W if i == 0 else tk.CENTER
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor=anchor, width=260 if i == 0 else 110)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        # Create a tag for placeholder row (bigger font + centered text)
        self.tree.tag_configure(
            "placeholder",
            font=("Segoe UI", 13, "bold"),
            foreground="#375412",
            anchor="center"  # centers text horizontally
        )

        # Insert placeholder row
        self.tree.insert(
            "",
            tk.END,
            values=("Results Shown Here", "", ""),
            tags=("placeholder",)
        )

        # ---------------- RIGHT PANEL ----------------
        ttk.Label(right, text="Details & Advice", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W)
        self.detail_text = tk.Text(right, height=22, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # Insert centered and colored welcome message
        welcome_text = (
            "\n\n\n\n\n\n"  # vertical spacing
            "⭐ HELLO BUDDY! WELCOME TO CyberResponder ⭐\n\n"
            "Safeguard Your System & Stay Cyber Smart! 🖥️\n\n"
        )

        # Configure text tag for center, big font, and color
        self.detail_text.tag_configure(
            "center_color",
            justify="center",
            font=("Segoe UI", 18, "bold"),
            foreground="#e98670"  # Crimson text color
        )

        self.detail_text.insert(tk.END, welcome_text, "center_color")
        self.detail_text.configure(state=tk.DISABLED)


        footer = ttk.Frame(parent)
        footer.pack(fill=tk.X, padx=12, pady=8)
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status_var).pack(side=tk.LEFT)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

    def toggle_report(self):
        if not self.showing_last:
            # Show last report
            prev_file = os.path.join(DATA_DIR, "prev_scan.json")
            if not os.path.exists(prev_file):
                messagebox.showinfo(APP_NAME, "No previous report found.")
                return
            try:
                with open(prev_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.render_results(data)
                self.status_var.set("Viewing: Last Report")
                self.showing_last = True
                self.report_button.config(text="Open Current Report")
            except Exception as e:
                messagebox.showerror(APP_NAME, f"Failed to open report: {e}")
        else:
            # Show current report
            if not os.path.exists(LAST_SCAN_JSON):
                messagebox.showinfo(APP_NAME, "No current report found. Run a scan first.")
                return
            try:
                with open(LAST_SCAN_JSON, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.render_results(data)
                self.status_var.set("Viewing: Current Report")
                self.showing_last = False
                self.report_button.config(text="Open Last Report")
            except Exception as e:
                messagebox.showerror(APP_NAME, f"Failed to open report: {e}")

    # ---------------- Quiz Tab ----------------
    def _build_quiz_ui(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.quiz_question_var = tk.StringVar(value="Click 'Next Question' to start.")
        ttk.Label(frame, textvariable=self.quiz_question_var, wraplength=800, font=("Segoe UI", 12)).pack(pady=10)
        self.quiz_opts, self.quiz_var = [], tk.IntVar(value=-1)
        for i in range(4):
            rb = ttk.Radiobutton(frame, text="", variable=self.quiz_var, value=i)
            rb.pack(anchor=tk.W)
            self.quiz_opts.append(rb)
        self.quiz_feedback = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.quiz_feedback, foreground="blue").pack(pady=8)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=12)
        self.quiz_next_btn = ttk.Button(btn_frame, text="Next Question", command=self.load_question, cursor="hand2")
        self.quiz_next_btn.pack(side=tk.LEFT, padx=5)
        self.quiz_submit_btn = ttk.Button(
            btn_frame, text="Submit Answer", command=self.submit_answer, state=tk.DISABLED, cursor="hand2"
        )
        self.quiz_submit_btn.pack(side=tk.LEFT, padx=5)
        self.quiz_score_var = tk.StringVar(value="Ready to Play?")
        ttk.Label(frame, textvariable=self.quiz_score_var, font=("Segoe UI", 11, "bold")).pack(pady=8)

    # ---------------- Quiz Methods ----------------
    def load_question(self):
        if self.quiz_manager.attempts >= self.quiz_total:
            choice = messagebox.askquestion(
                "Quiz Completed",
                f"✅ Quiz completed!\n\nFinal Score: {self.quiz_manager.score}/{self.quiz_total}\n\nDo you want to retake?",
                icon="info",
            )
            if choice == "yes":
                self.quiz_manager.reset()
            else:
                self.quiz_manager.reset()
                self.quiz_question_var.set("Click 'Next Question' to start.")
                self.quiz_feedback.set("")
                self.quiz_submit_btn.config(state=tk.DISABLED)
                self.quiz_var.set(-1)
                self.select_tab("Security Scan")
                return

        q = self.quiz_manager.get_random_question()
        if not q:
            self.quiz_question_var.set("No more questions available.")
            return
        self.current_question = q
        self.quiz_question_var.set(q["question"])
        for i, opt in enumerate(q["options"]):
            self.quiz_opts[i].config(text=opt, state=tk.NORMAL)
        self.quiz_var.set(-1)
        self.quiz_feedback.set("")
        self.quiz_submit_btn.config(state=tk.NORMAL)

    def submit_answer(self):
        sel = self.quiz_var.get()
        if sel == -1:
            messagebox.showinfo("Quiz", "Please select an option.")
            return
        correct = self.current_question["answer"]
        self.quiz_manager.attempts += 1
        if sel == correct:
            self.quiz_manager.score += 1
            self.quiz_feedback.set("✅ Correct!")
        else:
            self.quiz_feedback.set(
                f"❌ Incorrect! Correct: {self.current_question['options'][correct]}"
            )
            self.quiz_submit_btn.config(state=tk.DISABLED)
        self.quiz_score_var.set(
            f"Score: {self.quiz_manager.score}/{self.quiz_manager.attempts}"
        )
        self.after(800, self.load_question)

    def select_tab(self, tab_name: str):
        for i in range(self.tabs.index("end")):
            if self.tabs.tab(i, "text") == tab_name:
                self.tabs.select(i)
                break

    # ---------------- Scan Methods ----------------
    def run_scan(self):
        self.status_var.set("Scanning...")
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, "Running checks. Please wait...\n")
        self.detail_text.configure(state=tk.DISABLED)

        def _work():
            data = self.orchestrator.run_scan()
            self.after(0, lambda: self.render_results(data))

        threading.Thread(target=_work, daemon=True).start()

    def _ensure_ports_tab(self):
        if self.ports_tab is None:
            self.ports_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.ports_tab, text="Open Ports")
            self.ports_gui = OpenPortsGUI(self.ports_tab, initial_ports=[])
            self.ports_gui.pack(fill=tk.BOTH, expand=True)

    def _remove_ports_tab_if_exists(self):
        if self.ports_tab is not None:
            idx = None
            for i in range(self.tabs.index("end")):
                if self.tabs.tab(i, "text") == "Open Ports":
                    idx = i
                    break
            if idx is not None:
                self.tabs.forget(idx)
            self.ports_tab = None
            self.ports_gui = None

    def render_results(self, data: Dict[str, Any]):
        self.current_results = data
        overall = data.get("overall_score", 0)
        self.score_var.set(f"Cyber Health Score: {overall}/100")
        for row in self.tree.get_children():
            self.tree.delete(row)

        for r in data.get("breakdown", []):
            label = r.get("label")
            if "admin" in str(r.get("evidence")).lower() or "root" in str(r.get("evidence")).lower():
                label = f"⚠️ {label}"
            self.tree.insert(
                "",
                tk.END,
                values=(label, r.get("status"), r.get("score")),
                tags=(r.get("status"),),
            )

        for status, color in STATUS_COLORS.items():
            try:
                self.tree.tag_configure(status, background=color)
            except Exception:
                pass

        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(
            tk.END,
            f"Scan Time: {data.get('timestamp')}\nSystem: {data.get('os')}\nHost: {data.get('hostname')}\n\n",
        )
        self.detail_text.insert(
            tk.END, "Click a check on the left to view evidence and advice.\n"
        )
        self.detail_text.configure(state=tk.DISABLED)

        open_ports_result = next(
            (r for r in data.get("breakdown", []) if r.get("id") == "open_ports"), None
        )
        ports_list = list_listeners() if open_ports_result else []
        if ports_list:
            self._ensure_ports_tab()
            self.ports_gui.set_data(ports_list)
        else:
            self._remove_ports_tab_if_exists()
        self.status_var.set("Scan complete.")

    def on_row_select(self, _event=None):
        if not self.current_results:
            return
        sel = self.tree.selection()
        if not sel:
            return
        label = self.tree.item(sel[0])["values"][0].replace("⚠️ ", "")
        for r in self.current_results.get("breakdown", []):
            if r.get("label") == label:
                self._show_details(r)
                break

    def _show_details(self, r: Dict[str, Any]):
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)

        # Header info
        self.detail_text.insert(
            tk.END,
            f"Check: {r.get('label')}\n"
            f"Status: {r.get('status')}\n"
            f"Score: {r.get('score')}\n"
            f"Weight: {r.get('weight')}\n\n"
        )

        # Evidence section
        self.detail_text.insert(tk.END, "Evidence:\n")

        evidence = r.get("evidence", {})
        for key, value in evidence.items():
            if isinstance(value, str) and "\n" in value:
                # Preserve multi-line strings like your 'raw' Wi-Fi output
                self.detail_text.insert(tk.END, f"{key}:\n{value}\n")
            else:
                # Pretty-print other key-value pairs
                self.detail_text.insert(tk.END, f"{key}: {value}\n")

        # Advice section
        self.detail_text.insert(
            tk.END,
            "\nAdvice:\n" + (r.get("advice") or "No advice provided.") + "\n"
        )

        # Privilege warning
        evidence_str = str(evidence).lower()
        if "admin" in evidence_str or "root" in evidence_str:
            self.detail_text.insert(
                tk.END,
                "\n⚠️ PRIVILEGE WARNING: Some checks require Admin/Root privileges. "
                "Rerun the tool with elevated rights for complete results.\n"
            )

        self.detail_text.configure(state=tk.DISABLED)

    # ---------------- Export / Open Last ----------------
    def export_csv(self):
        if not self.current_results:
            messagebox.showinfo(APP_NAME, "No results to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([APP_NAME, f"v{APP_VERSION}"])
                w.writerow(["Timestamp", self.current_results.get("timestamp", "")])
                w.writerow(["OS", self.current_results.get("os", "")])
                w.writerow(["Hostname", self.current_results.get("hostname", "")])
                w.writerow(["Overall Score", self.current_results.get("overall_score", 0)])
                w.writerow([])
                w.writerow(["Check", "Status", "Score", "Weight", "Evidence", "Advice"])
                for r in self.current_results.get("breakdown", []):
                    w.writerow(
                        [
                            r.get("label"),
                            r.get("status"),
                            r.get("score"),
                            r.get("weight"),
                            json.dumps(r.get("evidence", {})),
                            r.get("advice", ""),
                        ]
                    )
            messagebox.showinfo(APP_NAME, f"Exported to {path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to export CSV: {e}")

    def open_last(self):
        prev_file = os.path.join(DATA_DIR, "prev_scan.json")
        if not os.path.exists(prev_file):
            messagebox.showinfo(APP_NAME, "No previous report found.")
            return
        try:
            with open(prev_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.render_results(data)
            self.status_var.set("Loaded previous report.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to open report: {e}")