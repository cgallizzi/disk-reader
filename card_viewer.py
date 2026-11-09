"""Windows viewer for USB disks that Windows can't mount, such as Xbox storage cards.

Read-only: every disk access goes through disk_reader.RawDisk (GENERIC_READ).
Relaunches itself through a UAC prompt because raw disks need Administrator.

Developed against a Unitek R1005A CFexpress Type B reader:
https://www.amazon.com/dp/B083W2XJBM
"""
import csv
import ctypes
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import ntfs_security
import visibility
import xbox_card
import xvd

BG, PANEL, FIELD = "#16181b", "#1f2226", "#2a2e33"
TEXT, MUTED, BORDER = "#e8eaed", "#a3a9b0", "#3a3f45"
GAME, LOCAL, OTHER, FREE = "#3fb950", "#58a6ff", "#8b949e", "#2a2e33"
WARN = "#e3b341"
FONT = "Segoe UI"


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_elevated():
    """Start this script as Administrator. True if the UAC prompt was accepted."""
    exe, params = sys.executable, None
    if not getattr(sys, "frozen", False):
        windowed = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(windowed):
            exe = windowed
        params = '"%s"' % os.path.abspath(__file__)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32


def selftest(number, out_path):
    """Exercise the whole app on a disk, including a verified copy of its smallest title.

    For checking a packaged build, which has no console and can't be driven by test scripts.
    The copy goes to a temp folder that is removed afterwards.
    """
    report = {"frozen": bool(getattr(sys, "frozen", False)), "ok": False}
    try:
        root = tk.Tk()
        app = CardViewer(root)
        model = xbox_card.read_card(number)
        catalog, failed = xbox_card.fetch_catalog([t["store"] for t in model["titles"] if t["store"]])
        xbox_card.apply_catalog(model, catalog)
        app.show(model)
        root.update()
        smallest = min((t for t in model["titles"] if t["size"]), key=lambda t: t["size"])
        with tempfile.TemporaryDirectory() as tmp:
            folders = xbox_card.export_titles(number, model, [smallest], tmp, lambda *a: None, threading.Event())
            copied = sorted(os.listdir(folders[0]))
            labels = xbox_card.file_labels(model)
            loose = [f for f in model["files"] if not f["is_dir"] and f["size"] < 32 * 10**6
                     and (labels[f["path"]][0] in ("Xbox card", "Card filesystem", "Unidentified container")
                          or f["path"].lower().endswith(".pfm"))]
            bulk = xbox_card.export_files(number, model, loose, tmp, lambda *a: None, threading.Event())
            on_disk = sum(len(names) for _, _, names in os.walk(bulk["folder"])) - 1  # minus the manifest
        root.destroy()
        report.update(ok=True, headline=app_headline(model), title_rows=len(model["titles"]),
                      catalog_failed=failed, copied_title=smallest["title"], copied_files=copied,
                      loose_requested=bulk["requested"], loose_copied=len(bulk["copied"]), loose_on_disk=on_disk,
                      loose_failed=bulk["failed"], loose_complete=bulk["complete"],
                      loose_paths=sorted(e["path"] for e in bulk["copied"] if "-" not in e["path"]),
                      streams_not_copied=[e["path"] for e in bulk["copied"] if "named_streams_not_copied" in e],
                      card_info=xbox_card.card_info_text(model),
                      xvd_parsed=sum(1 for t in model["titles"] if t.get("xvd") and t["xvd"]["is_xvd"]),
                      xvd_encrypted=sum(1 for t in model["titles"] if t.get("xvd") and t["xvd"].get("encrypted")),
                      xvd_sample=next(({"title": t["title"], **{k: t["xvd"][k] for k in
                                       ("content_id", "format_version", "payload_bytes", "overhead_bytes",
                                        "encrypted", "cleartext_end", "created")}}
                                      for t in model["titles"] if t.get("xvd") and t["xvd"]["is_xvd"]), None),
                      permission_rules=len(model["security"]), permission_error=model["security_error"],
                      files_without_rule=sum(1 for f in model["files"]
                                             if f.get("security_id") not in model["security"]))
    except Exception as e:  # the report is the only output a windowless build can leave
        report["error"] = "%s: %s" % (type(e).__name__, e)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)


def list_usb_disks():
    """USB disks only, so the app can't be pointed at the system drives."""
    script = ("@(Get-Disk | Where-Object BusType -eq 'USB' | "
              "Select-Object Number,FriendlyName,Size,PartitionStyle) | ConvertTo-Json")
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, stdin=subprocess.DEVNULL, text=True, errors="replace",
                         creationflags=subprocess.CREATE_NO_WINDOW, timeout=30).stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    return [data] if isinstance(data, dict) else data


def gb(n):
    if not n:
        return "—"
    if n >= 10**9:
        return "%.2f GB" % (n / 1e9)
    if n >= 10**6:
        return "%.1f MB" % (n / 1e6)
    return "%.1f KB" % (n / 1e3)


def day(iso):
    return iso[:10] if iso else "—"


def duration(seconds):
    if seconds < 90:
        return "%d seconds" % max(seconds, 1)
    if seconds < 5400:
        return "%d minutes" % (seconds / 60)
    return "%.1f hours" % (seconds / 3600)


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def app_headline(model):
    c = xbox_card.totals(model)["counts"]
    parts = [plural(c[k], label) for k, label in (("Game", "game"), ("Add-on", "add-on"), ("App", "app"),
                                                  (xbox_card.UNKNOWN, "unidentified item")) if c.get(k)]
    return ", ".join(parts) or "No Xbox titles found"


class CardViewer:
    TITLE_COLS = (("title", "Title", 400, "w"), ("kind", "Type", 70, "w"), ("size", "Installed", 95, "e"),
                  ("pls", "Local data", 95, "e"), ("modified", "Last changed", 105, "w"),
                  ("store", "Store ID", 125, "w"))
    FILE_COLS = (("owner", "Belongs to", 300, "w"), ("what", "What it is", 185, "w"), ("path", "Path", 270, "w"),
                 ("size", "Size", 90, "e"), ("modified", "Modified", 95, "w"))
    PERM_COLS = (("id", "Rule", 60, "w"), ("access", "Who has access", 610, "w"), ("owner", "Owner", 200, "w"),
                 ("count", "Files", 70, "e"))
    XVD_COLS = (("title", "Title", 300, "w"), ("vduid", "Content ID (VDUID)", 250, "w"),
                ("built", "Built", 90, "w"), ("payload", "Payload", 90, "e"), ("overhead", "Overhead", 90, "e"),
                ("enc", "Encrypted", 75, "w"), ("fmt", "Fmt", 45, "e"))

    def __init__(self, root):
        self.root, self.model, self.disks = root, None, []
        self.events = queue.Queue()
        self.sort_titles = ("size", True)
        self.sort_files = ("owner", False)
        self.sort_perms = ("count", True)
        self.sort_xvd = ("payload", True)
        self.labels = {}
        self.busy = False
        self.cik_folder = None
        root.title("Card Viewer")
        root.geometry("1040x720")
        root.minsize(800, 520)
        root.configure(bg=BG)
        self._style()
        self._build()
        self.refresh_disks()
        root.after(100, self._drain)

    def _style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, font=(FONT, 10), bordercolor=BORDER,
                    fieldbackground=FIELD, troughcolor=PANEL, lightcolor=BG, darkcolor=BG)
        s.configure("TFrame", background=BG)
        s.configure("Muted.TLabel", foreground=MUTED, background=BG)
        s.configure("Warn.TLabel", foreground=WARN, background=BG)
        s.configure("Big.TLabel", font=(FONT, 15, "bold"), background=BG)
        s.configure("TButton", background=FIELD, foreground=TEXT, padding=(12, 5), borderwidth=1)
        s.map("TButton", background=[("active", BORDER), ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
        s.configure("Accent.TButton", background="#238636", foreground="#ffffff")
        s.map("Accent.TButton", background=[("active", "#2ea043"), ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
        s.configure("TEntry", insertcolor=TEXT, padding=5)
        s.configure("TCombobox", arrowcolor=TEXT, padding=4, background=FIELD)
        s.map("TCombobox", fieldbackground=[("readonly", FIELD)], foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", FIELD)], selectforeground=[("readonly", TEXT)])
        self.root.option_add("*TCombobox*Listbox.background", FIELD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        s.configure("TCheckbutton", background=BG, foreground=TEXT)
        s.map("TCheckbutton", background=[("active", BG)])
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=26,
                    borderwidth=0)
        s.map("Treeview", background=[("selected", "#1f4f8f")], foreground=[("selected", "#ffffff")])
        s.configure("Treeview.Heading", background=FIELD, foreground=TEXT, relief="flat", padding=(6, 5),
                    font=(FONT, 10, "bold"))
        s.map("Treeview.Heading", background=[("active", BORDER)])
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 4, 0, 0))
        s.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(16, 7))
        s.map("TNotebook.Tab", background=[("selected", FIELD)], foreground=[("selected", TEXT)])
        s.configure("Vertical.TScrollbar", background=FIELD, arrowcolor=TEXT, bordercolor=BG, gripcount=0)
        s.configure("Horizontal.TProgressbar", background=GAME, troughcolor=FIELD, bordercolor=BG)

    def _build(self):
        top = ttk.Frame(self.root, padding=(16, 14, 16, 6))
        top.pack(fill="x")
        ttk.Label(top, text="USB disk").pack(side="left")
        self.disk_var = tk.StringVar()
        self.disk_box = ttk.Combobox(top, textvariable=self.disk_var, state="readonly", width=46)
        self.disk_box.pack(side="left", padx=8)
        self.refresh_btn = ttk.Button(top, text="Refresh list", command=self.refresh_disks)
        self.refresh_btn.pack(side="left")
        self.read_btn = ttk.Button(top, text="Read disk", style="Accent.TButton", command=self.read_selected)
        self.read_btn.pack(side="left", padx=8)
        self.online = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Look up titles online (sends Store IDs to Microsoft)",
                        variable=self.online).pack(side="left", padx=6)

        info = ttk.Frame(self.root, padding=(16, 6, 16, 4))
        info.pack(fill="x")
        self.headline = ttk.Label(info, text="No disk read yet", style="Big.TLabel")
        self.headline.pack(anchor="w")
        self.status = ttk.Label(info, text="Choose a USB disk and select Read disk.", style="Muted.TLabel")
        self.status.pack(anchor="w", pady=(2, 6))
        self.bar = tk.Canvas(info, height=16, bg=FREE, highlightthickness=0)
        self.bar.pack(fill="x")
        self.bar.bind("<Configure>", lambda e: self._draw_bar())
        legend = ttk.Frame(info)
        legend.pack(anchor="w", pady=(4, 0))
        self.legend_vals = {}
        for key, color in (("Installed", GAME), ("Local data", LOCAL), ("Other", OTHER)):
            ttk.Label(legend, text="■", foreground=color).pack(side="left")
            self.legend_vals[key] = ttk.Label(legend, text="", style="Muted.TLabel")
            self.legend_vals[key].pack(side="left", padx=(3, 14))
        self.legend_free = ttk.Label(legend, text="", style="Muted.TLabel")
        self.legend_free.pack(side="left")

        foot = ttk.Frame(self.root, padding=(16, 2, 16, 10))
        foot.pack(side="bottom", fill="x")
        ttk.Label(foot, text="The disk is only ever read. If Windows offers to Initialize or Format it, "
                             "decline: that could erase it.", style="Warn.TLabel").pack(side="left")
        self.export_btn = ttk.Button(foot, text="Export CSV", command=self.export, state="disabled")
        self.export_btn.pack(side="right")

        self.job = ttk.Frame(self.root, padding=(16, 2, 16, 6))
        self.job_label = ttk.Label(self.job, text="", style="Muted.TLabel")
        self.job_label.pack(anchor="w")
        row = ttk.Frame(self.job)
        row.pack(fill="x", pady=(3, 0))
        self.job_cancel = ttk.Button(row, text="Cancel copy", command=self.cancel_extract)
        self.job_cancel.pack(side="right", padx=(8, 0))
        self.job_bar = ttk.Progressbar(row, maximum=1000)
        self.job_bar.pack(side="left", fill="x", expand=True)

        search = ttk.Frame(self.root, padding=(16, 6, 16, 4))
        search.pack(fill="x")
        ttk.Label(search, text="Search").pack(side="left")
        self.query = tk.StringVar()
        self.query.trace_add("write", lambda *_: self.fill())
        ttk.Entry(search, textvariable=self.query, width=40).pack(side="left", padx=8)
        self.show_meta = tk.BooleanVar(value=False)
        ttk.Checkbutton(search, text="Show system and sidecar files in All files", variable=self.show_meta,
                        command=self.fill).pack(side="left", padx=6)
        self.extract_btn = ttk.Button(search, text="Copy to PC", command=self.extract_selected, state="disabled")
        self.extract_btn.pack(side="right")
        self.whole_btn = ttk.Button(search, text="Copy whole card", command=self.extract_whole, state="disabled")
        self.whole_btn.pack(side="right", padx=8)

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=16, pady=(4, 6))
        self.tabs.bind("<<NotebookTabChanged>>", lambda e: self._update_detail())

        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Games and apps")
        self.titles = self._tree(tab, self.TITLE_COLS, self._sort_title_col)
        self.titles.bind("<<TreeviewSelect>>", lambda e: self._update_detail())
        self.detail = tk.Text(tab, height=4, bg=PANEL, fg=TEXT, relief="flat", wrap="word",
                              font=("Consolas", 9), padx=8, pady=6, insertbackground=TEXT)
        self.detail.pack(fill="x", pady=(6, 0))
        self.detail.insert("1.0", "Select a row for its package and container details.")
        self.detail.configure(state="disabled")

        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="All files")
        self.files = self._tree(tab, self.FILE_COLS, self._sort_file_col)
        self.files.bind("<<TreeviewSelect>>", lambda e: self._update_file_detail())
        self.file_rows = {}
        self.file_detail = self._detail_panel(tab, "Select a file to see its permission rule.")

        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Permissions")
        self.perms = self._tree(tab, self.PERM_COLS, self._sort_perm_col)
        self.perms.bind("<<TreeviewSelect>>", lambda e: self._update_perm_detail())
        self.perm_rows = {}
        self.perm_detail = self._detail_panel(tab, "Select a rule to see who it applies to and which files use it.")

        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Containers")
        tools = ttk.Frame(tab, padding=(6, 4))
        tools.pack(fill="x")
        self.cik_btn = ttk.Button(tools, text="Extract CIKs…", command=self.extract_ciks)
        self.cik_btn.pack(side="left")
        self.xvd_btn = ttk.Button(tools, text="Decrypt and extract copied game…", command=self.extract_xvd)
        self.xvd_btn.pack(side="left", padx=6)
        self.scan_cik_btn = ttk.Button(tools, text="Scan SSD for matching CIKs…",
                                       command=self.scan_cik_matches, state="disabled")
        self.scan_cik_btn.pack(side="left")
        self.containers = self._tree(tab, self.XVD_COLS, self._sort_xvd_col)
        self.containers.bind("<<TreeviewSelect>>", lambda e: self._update_xvd_detail())
        self.xvd_rows = {}
        self.xvd_detail = self._detail_panel(tab, "Select a container to see its XVD header fields.")

        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Card info")
        bar = ttk.Scrollbar(tab, orient="vertical")
        self.card_info = tk.Text(tab, bg=PANEL, fg=TEXT, relief="flat", wrap="word", font=("Consolas", 10),
                                 padx=12, pady=10, insertbackground=TEXT, yscrollcommand=bar.set)
        bar.configure(command=self.card_info.yview)
        bar.pack(side="right", fill="y")
        self.card_info.pack(side="left", fill="both", expand=True)
        self._set_text(self.card_info, "Read a disk to see the consoles linked to it.")

    def _detail_panel(self, parent, text):
        panel = tk.Text(parent, height=5, bg=PANEL, fg=TEXT, relief="flat", wrap="word",
                        font=("Consolas", 9), padx=8, pady=6, insertbackground=TEXT)
        panel.pack(fill="x", pady=(6, 0))
        self._set_text(panel, text)
        return panel

    @staticmethod
    def _set_text(panel, text):
        panel.configure(state="normal")
        panel.delete("1.0", "end")
        panel.insert("1.0", text)
        panel.configure(state="disabled")

    def _update_file_detail(self):
        self._sync_extract_btn()
        sel = self.files.selection()
        f = self.file_rows.get(sel[0]) if sel else None
        if f:
            sentence = visibility.file_line(self.model, f)[1]
            self._set_text(self.file_detail, "%s\n%s\n\n%s" % (
                f["path"], sentence, xbox_card.file_permission(self.model, f)))
        else:
            self._set_text(self.file_detail, "Select a file to see its permission rule.")

    def _update_perm_detail(self):
        sel = self.perms.selection()
        row = self.perm_rows.get(sel[0]) if sel else None
        if not row:
            self._set_text(self.perm_detail, "Select a rule to see who it applies to and which files use it.")
            return
        shown = row["files"][:8]
        more = len(row["files"]) - len(shown)
        used = "Used by: " + (", ".join(shown) if shown else "no files") + (" and %d more" % more if more > 0 else "")
        self._set_text(self.perm_detail, "Rule %d\n%s\n%s" % (row["id"], ntfs_security.describe(row["rule"]), used))

    def _sort_perm_col(self, key):
        self.sort_perms = (key, not self.sort_perms[1] if self.sort_perms[0] == key else key in ("count", "id"))
        self.fill()

    def _fill_perms(self, q):
        self.perms.delete(*self.perms.get_children())
        self.perm_rows = {}
        rows = [r for r in xbox_card.permission_rows(self.model)
                if not q or q in " ".join((r["summary"], r["owner"], str(r["id"]))).lower()]
        key, rev = self.sort_perms
        values = {"id": lambda r: r["id"], "count": lambda r: len(r["files"]),
                  "access": lambda r: r["summary"].lower(), "owner": lambda r: r["owner"].lower()}
        rows.sort(key=values[key], reverse=rev)
        for r in rows:
            iid = self.perms.insert("", "end", values=(r["id"], r["summary"], r["owner"], len(r["files"])))
            self.perm_rows[iid] = r
        self.tabs.tab(2, text="Permissions (%d)" % len(rows))
        self._update_perm_detail()
        if self.model.get("security_error"):
            self._set_text(self.perm_detail, self.model["security_error"])

    def extract_ciks(self):
        exe = filedialog.askopenfilename(
            parent=self.root, title="Select CikExtractor.exe from the extracted release",
            filetypes=[("CikExtractor", "CikExtractor.exe")])
        if not exe:
            return
        current = messagebox.askyesnocancel(
            "CIK source",
            "Use this PC's Windows registry?\n\n"
            "Yes uses this PC. No lets you select a hive saved with CikExtractor's export-hive command.",
            parent=self.root)
        if current is None:
            return
        hive = None
        if not current:
            hive = filedialog.askopenfilename(parent=self.root, title="Select an exported CikExtractor hive")
            if not hive:
                return
        dest = filedialog.askdirectory(
            parent=self.root, title="Choose a local folder for the CIKs and private device key",
            mustexist=True)
        if dest:
            self._set_busy(True)
            self.status.configure(text="Running CikExtractor…")
            self._run(self._work_extract_ciks, exe, hive, dest)

    def _work_extract_ciks(self, exe, hive, dest):
        folder = None
        try:
            exe = os.path.abspath(exe)
            folder = tempfile.mkdtemp(prefix="CikExtractor-", dir=os.path.abspath(dest))
            cik_dir = os.path.join(folder, "Cik")
            device_key = os.path.join(folder, "deviceKey.txt")
            args = [exe, "dump", "--export-cik-path", cik_dir, "--device-key-path", device_key]
            if hive:
                args.extend(["--reg-hive", os.path.abspath(hive)])
            result = subprocess.run(
                args, cwd=os.path.dirname(exe), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode or not os.path.isfile(device_key) or not os.path.isdir(cik_dir):
                raise RuntimeError(
                    "CikExtractor did not finish. Check that .NET 10 is installed, "
                    "the release was fully extracted, and the registry source is valid.")
            with os.scandir(cik_dir) as entries:
                count = sum(entry.is_file() and entry.name.lower().endswith(".cik") for entry in entries)
        except (OSError, RuntimeError) as exc:
            if folder:
                shutil.rmtree(folder, ignore_errors=True)
            self.events.put(("cik_failed", str(exc)))
        else:
            self.events.put(("cik_done", (count, folder)))

    def extract_xvd(self):
        source = filedialog.askopenfilename(
            parent=self.root, title="Select a game container copied to your PC",
            filetypes=[("Game containers", "*.xvc *.xvd *.msixvc"), ("All files", "*")])
        if not source:
            return
        options = self._xvd_options()
        if options:
            exe, keys, dest = options
            self._set_busy(True)
            self.status.configure(text="Decrypting and extracting with xvdtool…")
            self._run(self._work_extract_xvd, exe, source, keys, dest)

    def _xvd_options(self):
        keys = filedialog.askdirectory(
            parent=self.root, title="Select the Cik folder saved by CikExtractor",
            initialdir=self.cik_folder, mustexist=True)
        if not keys:
            return None
        self.cik_folder = keys
        app_dir = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
        if not getattr(sys, "frozen", False):
            app_dir = os.path.join(app_dir, "dist")
        exe = os.path.join(app_dir, "xvdtool", "XVDTool.exe")
        if not os.path.isfile(exe):
            exe = filedialog.askopenfilename(
                parent=self.root, title="Select XVDTool.exe from the Windows x64 release",
                filetypes=[("XVDTool", "XVDTool.exe")])
            if not exe:
                return None
        dest = filedialog.askdirectory(
            parent=self.root, title="Choose a destination with room for a temporary game copy and the extracted files",
            mustexist=True)
        return (exe, keys, dest) if dest else None

    def scan_cik_matches(self):
        options = self._xvd_options()
        if options:
            self._set_busy(True)
            self.status.configure(text="Scanning SSD game containers for matching CIKs…")
            self._run(self._work_scan_ciks, self.model, *options)

    def _work_scan_ciks(self, model, exe, keys, dest):
        try:
            checked, skipped, matches, source = xbox_card.copy_smallest_cik_match(
                model["disk_number"], model, xvd.cik_ids(keys), dest,
                lambda message: self.events.put(("status", message)))
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            self.events.put(("cik_scan_result", (False, "CIK scan failed. " + str(exc))))
            return

        summary = ("Checked %s. Full CIK matches: %d." % (plural(checked, "container"), matches))
        if skipped:
            summary += " Could not inspect %s." % plural(skipped, "container")
        if source is None:
            self.events.put(("cik_scan_result", (True, summary)))
            return

        self.events.put(("status", "Trying extraction with xvdtool"))
        summary += "\n\nVerified copy saved in\n" + os.path.dirname(source)
        try:
            output = xvd.extract_game(exe, source, keys, dest)
        except (OSError, RuntimeError) as exc:
            self.events.put(("cik_scan_result", (False, summary + "\n\n" + str(exc))))
        else:
            self.events.put(("cik_scan_result", (True, summary + "\n\nExtracted files saved in\n" + output)))

    def _work_extract_xvd(self, exe, source, keys, dest):
        try:
            folder = xvd.extract_game(exe, source, keys, dest)
        except (OSError, RuntimeError) as exc:
            self.events.put(("xvd_failed", str(exc)))
        else:
            self.events.put(("xvd_done", folder))

    def _sort_xvd_col(self, key):
        self.sort_xvd = (key, not self.sort_xvd[1] if self.sort_xvd[0] == key
                         else key in ("payload", "overhead", "built", "fmt"))
        self.fill()

    def _fill_xvd(self, q):
        self.containers.delete(*self.containers.get_children())
        self.xvd_rows = {}
        rows = [t for t in self.model["titles"] if t.get("xvd") and t["xvd"]["is_xvd"]
                and (not q or q in " ".join((t["title"], t["id"])).lower())]
        key, rev = self.sort_xvd
        values = {"title": lambda t: t["title"].lower(), "vduid": lambda t: t["xvd"]["content_id"],
                  "built": lambda t: t["xvd"]["created"] or "", "payload": lambda t: t["xvd"]["payload_bytes"],
                  "overhead": lambda t: t["xvd"]["overhead_bytes"], "enc": lambda t: t["xvd"]["encrypted"],
                  "fmt": lambda t: t["xvd"]["format_version"]}
        rows.sort(key=values[key], reverse=rev)
        for t in rows:
            x = t["xvd"]
            iid = self.containers.insert("", "end", values=(
                t["title"], x["content_id"], day(x["created"]), gb(x["payload_bytes"]), gb(x["overhead_bytes"]),
                "Yes" if x["encrypted"] else "No", x["format_version"]))
            self.xvd_rows[iid] = t
        self.tabs.tab(3, text="Containers (%d)" % len(rows))
        self._update_xvd_detail()

    def _update_xvd_detail(self):
        sel = self.containers.selection()
        t = self.xvd_rows.get(sel[0]) if sel else None
        if not t:
            self._set_text(self.xvd_detail, "Select a container to see its XVD header fields.")
            return
        x = t["xvd"]
        boundary = "0x%X" % x["cleartext_end"] if x["cleartext_end"] is not None else "not found"
        lines = [t["title"],
                 "Content ID (VDUID): %s   %s" % (x["content_id"], "(matches filename)" if x["content_id"] == t["id"] else ""),
                 "User ID (UDUID):    %s" % x["user_id"],
                 "Store ID:           %s" % (t["store"] or "unknown"),
                 "Format version:     %s    Flags: %s" % (x["format_version"], x["flags"]),
                 "Built:              %s" % (x["created"] or "unknown"),
                 "Payload size:       %s" % gb(x["payload_bytes"]),
                 "Header/overhead:    %s" % gb(x["overhead_bytes"]),
                 "Encrypted:          %s   (cleartext ends at %s)" % ("yes" if x["encrypted"] else "no", boundary),
                 "Content type / embedded-XVD: %s / %s  (tentative, per xvdtool spec)"
                 % (x["content_type"], gb(x["embedded_xvd_bytes"])),
                 "", "Header fields are plaintext metadata. The payload is not decoded; encryption is recorded, not broken."]
        self._set_text(self.xvd_detail, "\n".join(lines))

    def _tree(self, parent, cols, on_sort):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", selectmode="extended")
        for key, label, width, anchor in cols:
            tree.heading(key, text=label, anchor=anchor, command=lambda k=key: on_sort(k))
            tree.column(key, width=width, anchor=anchor, stretch=key in ("title", "path"))
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        return tree

    def refresh_disks(self):
        self.status.configure(text="Looking for USB disks")
        self._run(self._work_list)

    def _work_list(self):
        try:
            self.events.put(("disks", list_usb_disks()))
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            self.events.put(("error", "Couldn't list disks: %s" % e))

    def read_selected(self):
        i = self.disk_box.current()
        if i < 0:
            return
        self.read_disk(self.disks[i]["Number"])

    def read_disk(self, number):
        self.disk_number = number
        self._set_busy(True)
        self._run(self._work_read, number, self.online.get())

    def _work_read(self, number, online):
        try:
            model = xbox_card.read_card(number, lambda m: self.events.put(("status", m)))
        except (OSError, ValueError, MemoryError) as e:
            self.events.put(("error", "Couldn't read this disk as NTFS: %s" % e))
            return
        model["disk_number"] = number
        self.events.put(("model", model))
        if online:
            self.events.put(("status", "Looking up titles"))
            cache = xbox_card.load_cache()
            ids = [t["store"] for t in model["titles"] if t["store"]]
            catalog, failed = xbox_card.fetch_catalog(ids, cache)
            try:
                xbox_card.save_cache(catalog)
            except OSError:
                pass
            self.events.put(("catalog", (catalog, failed)))
        else:
            self.events.put(("done", "Online lookup is off, so titles come from package names."))

    def _run(self, fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    def _drain(self):
        try:
            while True:
                self._handle(*self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _handle(self, kind, value):
        if kind == "disks":
            self.disks = value
            labels = ["Disk %d: %s, %s (%s)" % (d["Number"], d["FriendlyName"], gb(d["Size"]), d["PartitionStyle"])
                      for d in value]
            self.disk_box["values"] = labels
            self.disk_box.set(labels[0] if labels else "")
            self.status.configure(text="Choose a USB disk and select Read disk." if labels
                                  else "No USB disks found. Plug one in and select Refresh list.")
            self.read_btn.configure(state="normal" if labels and not self.busy else "disabled")
        elif kind == "status":
            self.status.configure(text=value + "…")
        elif kind == "error":
            self._set_busy(False)
            self.status.configure(text=value)
        elif kind == "model":
            self.show(value)
        elif kind == "catalog":
            catalog, failed = value
            xbox_card.apply_catalog(self.model, catalog)
            self.show(self.model)
            matched = sum(1 for t in self.model["titles"] if t["title_source"] == "catalog")
            with_id = sum(1 for t in self.model["titles"] if t["store"])
            note = "Matched %d of %d Store IDs in Microsoft's catalog." % (matched, with_id)
            self._finish(note + (" Some lookups failed, so those titles use package names." if failed else ""))
        elif kind == "done":
            self._finish(value)
        elif kind == "cik_done":
            count, folder = value
            if count:
                self.cik_folder = os.path.join(folder, "Cik")
            summary = "Saved %s and deviceKey.txt." % plural(count, "CIK file")
            self._finish(summary)
            messagebox.showinfo(
                "CikExtractor", "%s\n\n%s\n\nKeep the key files private." % (summary, folder),
                parent=self.root)
        elif kind == "cik_failed":
            self._finish("CIK extraction failed.")
            messagebox.showerror("CikExtractor", value, parent=self.root)
        elif kind == "cik_scan_result":
            ok, message = value
            self._finish(message.split("\n", 1)[0])
            show = messagebox.showinfo if ok else messagebox.showerror
            show("SSD CIK scan", message, parent=self.root)
        elif kind == "xvd_done":
            self._finish("Game files extracted.")
            messagebox.showinfo("XVDTool", "Game files saved in\n" + value, parent=self.root)
        elif kind == "xvd_failed":
            self._finish("Game extraction failed.")
            messagebox.showerror("XVDTool", value, parent=self.root)
        elif kind == "copy":
            self._show_copy_progress(*value)
        elif kind == "copied":
            self._end_copy("Copied and verified %s in %s" % (plural(len(value[0]), "package"), value[1]))
        elif kind == "copied_files":
            self._end_copy(self._files_summary(value))
        elif kind == "copy_cancelled":
            self._end_copy("Copy cancelled. The unfinished package was removed from your PC.")
        elif kind == "copy_failed":
            self._end_copy("Copy failed, and the unfinished package was removed: %s" % value)

    @staticmethod
    def _files_summary(r):
        text = "Copied and verified %d of %s" % (len(r["copied"]), plural(r["requested"], "file"))
        if r["cancelled"]:
            text += " before you cancelled"
        if r["failed"]:
            text += ", %d failed" % len(r["failed"])
        return "%s, in %s. Details are in %s." % (text, r["folder"], xbox_card.MANIFEST_NAME)

    def _on_files_tab(self):
        return self.tabs.index("current") == 1

    def extract_whole(self):
        self._confirm_files([f for f in self.model["files"] if not f["is_dir"]], "the whole card")

    def _confirm_files(self, files, what):
        dest = filedialog.askdirectory(parent=self.root, title="Choose where to save the copy", mustexist=True)
        if not dest:
            return
        need = sum(f["size"] for f in files)
        free = shutil.disk_usage(dest).free
        if need + 2**30 > free:
            messagebox.showerror("Not enough space", "This copy needs %s plus 1 GB spare, and that drive has %s "
                                 "free. Choose a drive with more space." % (gb(need), gb(free)), parent=self.root)
            return
        ok = messagebox.askokcancel(
            "Copy to PC",
            "Copy %s (%s, %s) to a new folder in:\n%s\n\nNothing on the card changes, so this won't free up "
            "any card space. Each file is read and then verified, so large copies can take a long time.\n\n"
            "This app can't put files back on the card." % (what, plural(len(files), "file"), gb(need), dest),
            parent=self.root)
        if ok:
            self.start_extract_files(files, dest)

    def start_extract_files(self, files, dest):
        self._begin_copy()
        self._run(self._work_extract_files, self.disk_number, self.model, files, dest, self.cancel_flag)

    def _work_extract_files(self, number, model, files, dest, cancel):
        last = [0.0]

        def progress(done, total, label):
            if time.time() - last[0] > 0.25 or done >= total:
                last[0] = time.time()
                self.events.put(("copy", (done, total, label)))
        try:
            self.events.put(("copied_files", xbox_card.export_files(number, model, files, dest, progress, cancel)))
        except (OSError, ValueError) as e:
            self.events.put(("copy_failed", str(e)))

    def extract_selected(self):
        if self._on_files_tab():
            chosen = [self.file_rows[i] for i in self.files.selection() if i in self.file_rows]
            files = xbox_card.expand_selection(self.model, chosen)
            if files:
                self._confirm_files(files, "the selected items")
            return
        if self.tabs.index("current") != 0:
            return
        titles = [self.title_rows[i] for i in self.titles.selection() if i in self.title_rows]
        if not titles:
            return
        dest = filedialog.askdirectory(parent=self.root, title="Choose where to save the copy", mustexist=True)
        if not dest:
            return
        need = sum(xbox_card.package_size(self.model, t) for t in titles)
        names = ", ".join(t["title"] for t in titles[:3]) + (" and more" if len(titles) > 3 else "")
        ok = messagebox.askokcancel(
            "Copy to PC",
            "Copy %s (%s) to:\n%s\n\nNothing on the card changes, so this won't free up any card space.\n\n"
            "This app can't put a copy back on the card, and an Xbox may not accept one restored another "
            "way. Don't treat this as a replacement for re-downloading until you've confirmed a restore "
            "works." % (names, gb(need), dest), parent=self.root)
        if ok:
            self.start_extract(titles, dest)

    def start_extract(self, titles, dest):
        self._begin_copy()
        self._run(self._work_extract, self.disk_number, self.model, titles, dest, self.cancel_flag)

    def _begin_copy(self):
        self.cancel_flag = threading.Event()
        self._set_busy(True)
        self.extract_btn.configure(state="disabled")
        self.job_cancel.configure(state="normal")
        self.job_bar["value"] = 0
        self.job_label.configure(text="Reading the file table…")
        self.job.pack(side="bottom", fill="x", before=self.tabs)
        self.copy_started = time.time()

    def _work_extract(self, number, model, titles, dest, cancel):
        last = [0.0]

        def progress(done, total, label):
            if time.time() - last[0] > 0.25 or done >= total:
                last[0] = time.time()
                self.events.put(("copy", (done, total, label)))
        try:
            folders = xbox_card.export_titles(number, model, titles, dest, progress, cancel)
        except xbox_card.Cancelled:
            self.events.put(("copy_cancelled", None))
        except (OSError, ValueError) as e:
            self.events.put(("copy_failed", str(e)))
        else:
            self.events.put(("copied", (folders, dest)))

    def cancel_extract(self):
        self.cancel_flag.set()
        self.job_cancel.configure(state="disabled")
        self.job_label.configure(text="Cancelling…")

    def _show_copy_progress(self, done, total, label):
        self.job_bar["value"] = 1000 * done / max(total, 1)
        rate = done / max(time.time() - self.copy_started, 0.1)
        left = (total - done) / max(rate, 1)
        self.job_label.configure(text="Copying and verifying %s: %.0f%%, about %s left"
                                 % (label, 100 * done / max(total, 1), duration(left)))

    def _end_copy(self, text):
        self.job.pack_forget()
        self._set_busy(False)
        self._sync_extract_btn()
        self.status.configure(text=text)

    def _sync_extract_btn(self):
        tab = self.tabs.index("current")
        ready = tab in (0, 1) and bool((self.titles, self.files)[tab].selection()) and not self.busy
        self.extract_btn.configure(state="normal" if ready else "disabled")
        self.whole_btn.configure(state="normal" if self.model and not self.busy else "disabled")

    def _finish(self, text):
        self._set_busy(False)
        self.status.configure(text=text)

    def _set_busy(self, busy):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.read_btn.configure(state=state)
        self.refresh_btn.configure(state=state)
        self.cik_btn.configure(state=state)
        self.xvd_btn.configure(state=state)
        ready = not busy and self.model and "disk_number" in self.model
        self.scan_cik_btn.configure(state="normal" if ready else "disabled")
        self._sync_extract_btn()

    def show(self, model):
        """Render a model. Also the entry point for tests, which have no disk."""
        self.model = model
        self.labels = xbox_card.file_labels(model)
        self._set_text(self.card_info, visibility.report_text(model) + "\n\n" + xbox_card.card_info_text(model))
        self.headline.configure(text=app_headline(model))
        self.export_btn.configure(state="normal")
        self._draw_bar()
        self.fill()

    def _draw_bar(self):
        self.bar.delete("all")
        m = self.model
        if not m or not m["volume_bytes"]:
            return
        t = xbox_card.totals(m)
        vol, width = m["volume_bytes"], self.bar.winfo_width()
        used = m["used_bytes"] if m["used_bytes"] is not None else t["installed"] + t["local"]
        other = max(used - t["installed"] - t["local"], 0)
        x = 0.0
        for size, color in ((t["installed"], GAME), (t["local"], LOCAL), (other, OTHER)):
            w = size / vol * width
            self.bar.create_rectangle(x, 0, x + w, 16, fill=color, width=0)
            x += w
        for key, size in (("Installed", t["installed"]), ("Local data", t["local"]), ("Other", other)):
            self.legend_vals[key].configure(text="%s %s" % (key, gb(size)))
        self.legend_free.configure(text="Free %s of %s" % (gb(max(vol - used, 0)), gb(vol)))

    def fill(self):
        if not self.model:
            return
        q = self.query.get().strip().lower()
        self.titles.delete(*self.titles.get_children())
        self.title_rows = {}
        key, rev = self.sort_titles
        rows = [t for t in self.model["titles"]
                if not q or q in " ".join((t["title"], t["package"], t["store"], t["id"])).lower()]
        rows.sort(key=lambda t: (t[key] or 0) if key in ("size", "pls") else str(t[key] or "").lower(), reverse=rev)
        for t in rows:
            iid = self.titles.insert("", "end", values=(t["title"], t["kind"], gb(t["size"]), gb(t["pls"]),
                                                        day(t["modified"]), t["store"] or "—"))
            self.title_rows[iid] = t
        self.files.delete(*self.files.get_children())
        key, rev = self.sort_files
        show_meta = self.show_meta.get()
        no_label = ("", "")

        def matches(f):
            owner, what = self.labels.get(f["path"], no_label)
            return not q or q in " ".join((owner, what, f["path"])).lower()

        def sort_value(f):
            if key == "size":
                return f["size"] or 0
            if key in ("owner", "what"):
                return self.labels.get(f["path"], no_label)[key == "what"].lower()
            return str(f[key] or "").lower()

        rows = [f for f in self.model["files"] if f["path"] != "/" and matches(f) and
                (show_meta or not self._is_meta(f["path"]))]
        rows.sort(key=sort_value, reverse=rev)
        self.file_rows = {}
        for f in rows:
            owner, what = self.labels.get(f["path"], no_label)
            iid = self.files.insert("", "end", values=(owner, what, f["path"], "folder" if f["is_dir"] else gb(f["size"]),
                                                       day(f["modified"])))
            self.file_rows[iid] = f
        self._update_file_detail()
        self._fill_perms(q)
        self._fill_xvd(q)
        self.tabs.tab(0, text="Games and apps (%d)" % len(self.title_rows))
        self.tabs.tab(1, text="All files (%d)" % len(rows))
        self._update_detail()

    @staticmethod
    def _is_meta(path):
        return path.startswith("/$") or path.lower().endswith((".xvs", ".xvi", ".xct", ".pfm"))

    def _update_detail(self):
        sel = self.titles.selection()
        t = self.title_rows.get(sel[0]) if sel and hasattr(self, "title_rows") else None
        self._sync_extract_btn()
        if t:
            lines = ["Package:   %s" % (t["package"] or "unknown"),
                     "Container: %s" % t["id"],
                     "Version:   %s    Platform: %s" % (t["version"] or "unknown", t["platform"] or "unknown"),
                     "Created:   %s    Title from: %s" % (day(t["created"]), t["title_source"])]
            text = "\n".join(lines)
        else:
            text = "Select a row for its package and container details."
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _sort_title_col(self, key):
        self.sort_titles = (key, not self.sort_titles[1] if self.sort_titles[0] == key else key in ("size", "pls", "modified"))
        self.fill()

    def _sort_file_col(self, key):
        self.sort_files = (key, not self.sort_files[1] if self.sort_files[0] == key else key in ("size", "modified"))
        self.fill()

    def export(self):
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".csv", initialfile="card_titles.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["title", "type", "installed_bytes", "local_data_bytes", "last_changed", "store_id",
                            "package", "container_id"])
                for t in self.model["titles"]:
                    w.writerow([t["title"], t["kind"], t["size"], t["pls"], t["modified"], t["store"],
                                t["package"], t["id"]])
            self.status.configure(text="Saved %s" % path)
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (OSError, AttributeError):
        pass
    if not is_admin():
        if relaunch_elevated():
            return
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Card Viewer", "Reading a raw disk needs Administrator approval, "
                                           "so the app can't continue without it. Nothing was read.")
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--selftest":
        selftest(int(sys.argv[2]), sys.argv[3])
        return
    root = tk.Tk()
    CardViewer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
