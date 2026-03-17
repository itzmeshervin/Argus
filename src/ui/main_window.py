"""
Main Tkinter Application Window — Argus Futuristic UI
Dark, modern, cyberpunk-lite redesign. All original functionality preserved.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import queue
import math
from typing import Optional, List, Dict
from datetime import datetime
from pathlib import Path

from src.core.scanner import VulnerabilityScanner, ScanResult
from src.core.cvss_calculator import CVSSCalculator
from src.models.finding import Finding
from src.models.cvss import CVSSMetrics
from src.reporting.exporter import ReportExporter

# ── Colour palette ────────────────────────────────────────────────────────────
BG       = "#080c14"
SURFACE  = "#0d1421"
SURFACE2 = "#111827"
SURFACE3 = "#1a2235"
BORDER   = "#1e2d40"
ACCENT   = "#00d4ff"
ACCENT2  = "#00ff88"
TEXT     = "#e2e8f0"
MUTED    = "#64748b"
CRIT     = "#ff4757"
HIGH     = "#ff6b35"
MED      = "#ffd32a"
LOW      = "#2ed573"
NONE_C   = "#64748b"

SEV_COLORS = {"Critical": CRIT, "High": HIGH, "Medium": MED, "Low": LOW, "None": NONE_C}

FONT_TITLE  = ("Segoe UI", 18, "bold")
FONT_HEAD   = ("Segoe UI", 11, "bold")
FONT_BODY   = ("Segoe UI", 10)
FONT_SMALL  = ("Segoe UI", 9)
FONT_MONO   = ("Consolas", 9)


def _hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


class GlowButton(tk.Frame):
    """A styled button using tk.Frame + tk.Label — reliable across all Tkinter versions."""

    def __init__(self, parent, text, command=None, width=120, height=36,
                 bg_color=ACCENT, text_color=BG, font=FONT_BODY, **kwargs):
        # Strip width/height from kwargs to avoid conflicts; we control sizing via the label
        super().__init__(parent, bg=bg_color, cursor="hand2",
                         highlightthickness=0, bd=0, **kwargs)
        self._command = command
        self._bg_color = bg_color
        self._text_color = text_color
        self._disabled = False

        self._label = tk.Label(
            self, text=text, font=font,
            fg=text_color, bg=bg_color,
            padx=14, pady=6, cursor="hand2"
        )
        self._label.pack(fill=tk.BOTH, expand=True)

        for w in (self, self._label):
            w.bind("<Enter>",    self._on_enter)
            w.bind("<Leave>",    self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _lighten(self, color):
        rgb = _hex_to_rgb(color)
        rgb = tuple(min(255, int(c * 1.3)) for c in rgb)
        return "#{:02x}{:02x}{:02x}".format(*rgb)

    def _on_enter(self, e=None):
        if self._disabled:
            return
        c = self._lighten(self._bg_color)
        self.config(bg=c)
        self._label.config(bg=c)

    def _on_leave(self, e=None):
        if self._disabled:
            return
        self.config(bg=self._bg_color)
        self._label.config(bg=self._bg_color)

    def _on_click(self, e=None):
        if not self._disabled and self._command:
            self._command()

    def set_state(self, state):
        if state == "disabled":
            self._disabled = True
            self._bg_color_orig = self._bg_color
            self._bg_color = MUTED
            self.config(bg=MUTED, cursor="arrow")
            self._label.config(bg=MUTED, fg=SURFACE2, cursor="arrow")
        else:
            self._disabled = False
            self._bg_color = getattr(self, "_bg_color_orig", self._bg_color)
            self.config(bg=self._bg_color, cursor="hand2")
            self._label.config(bg=self._bg_color, fg=self._text_color, cursor="hand2")


class PillToggle(tk.Frame):
    """Three-way pill toggle: LOW / MEDIUM / HIGH."""

    def __init__(self, parent, values, default=1, **kwargs):
        super().__init__(parent, bg=SURFACE2, **kwargs)
        self._values = values
        self._selected = default
        self._disabled = False
        self._buttons = []
        for i, v in enumerate(values):
            btn = tk.Label(self, text=v, font=("Segoe UI", 9, "bold"),
                           padx=14, pady=5, cursor="hand2")
            btn.pack(side=tk.LEFT)
            btn.bind("<Button-1>", lambda e, idx=i: self._select(idx))
            self._buttons.append(btn)
        self._refresh()

    def _select(self, idx):
        if self._disabled:
            return
        self._selected = idx
        self._refresh()

    def _refresh(self):
        for i, btn in enumerate(self._buttons):
            if self._disabled:
                btn.config(bg=SURFACE3, fg=SURFACE3 if i != self._selected else MUTED,
                           cursor="arrow")
            elif i == self._selected:
                btn.config(bg=ACCENT, fg=BG, cursor="hand2")
            else:
                btn.config(bg=SURFACE3, fg=MUTED, cursor="hand2")

    def set_state(self, state):
        self._disabled = (state == "disabled")
        self._refresh()

    def get(self):
        return self._values[self._selected]

    def set(self, value):
        for i, v in enumerate(self._values):
            if v == value:
                self._selected = i
        self._refresh()


class RadarCanvas(tk.Canvas):
    """Animated radar/pulse ring drawn on canvas."""

    def __init__(self, parent, size=120, **kwargs):
        bg = kwargs.pop("bg", SURFACE)
        super().__init__(parent, width=size, height=size,
                         bg=bg, highlightthickness=0, **kwargs)
        self._size = size
        self._cx = size // 2
        self._cy = size // 2
        self._angle = 0
        self._scanning = False
        self._pulse_r = 0
        self._pulse_alpha = 1.0
        self._draw_idle()

    def _draw_idle(self):
        self.delete("all")
        cx, cy, s = self._cx, self._cy, self._size
        # Outer ring
        self.create_oval(4, 4, s-4, s-4, outline=BORDER, width=1)
        # Inner ring
        r2 = s // 4
        self.create_oval(cx-r2, cy-r2, cx+r2, cy+r2, outline=BORDER, width=1)
        # Cross hairs
        self.create_line(cx, 4, cx, s-4, fill=BORDER, width=1)
        self.create_line(4, cy, s-4, cy, fill=BORDER, width=1)
        # Center dot
        self.create_oval(cx-3, cy-3, cx+3, cy+3, fill=ACCENT, outline="")

    def start_scan(self):
        self._scanning = True
        self._angle = 0
        self._animate()

    def stop_scan(self):
        self._scanning = False
        self._draw_idle()

    def _animate(self):
        if not self._scanning:
            return
        self.delete("all")
        cx, cy, s = self._cx, self._cy, self._size
        r = s // 2 - 4

        # Background rings
        self.create_oval(4, 4, s-4, s-4, outline=BORDER, width=1)
        r2 = s // 4
        self.create_oval(cx-r2, cy-r2, cx+r2, cy+r2, outline=BORDER, width=1)
        self.create_line(cx, 4, cx, s-4, fill=BORDER, width=1)
        self.create_line(4, cy, s-4, cy, fill=BORDER, width=1)

        # Sweep arc (filled wedge using multiple lines)
        sweep = 60
        for i in range(sweep):
            a = math.radians(self._angle - i)
            alpha = (sweep - i) / sweep
            # Fade from accent to transparent
            intensity = int(alpha * 80)
            color = "#{:02x}{:02x}{:02x}".format(
                int(_hex_to_rgb(ACCENT)[0] * alpha),
                int(_hex_to_rgb(ACCENT)[1] * alpha),
                int(_hex_to_rgb(ACCENT)[2] * alpha),
            )
            x2 = cx + r * math.cos(a)
            y2 = cy + r * math.sin(a)
            self.create_line(cx, cy, x2, y2, fill=color, width=1)

        # Sweep tip line
        a = math.radians(self._angle)
        x2 = cx + r * math.cos(a)
        y2 = cy + r * math.sin(a)
        self.create_line(cx, cy, x2, y2, fill=ACCENT, width=2)

        # Center dot
        self.create_oval(cx-3, cy-3, cx+3, cy+3, fill=ACCENT, outline="")

        self._angle = (self._angle + 4) % 360
        self.after(30, self._animate)


class VulnScannerApp:
    """Main Tkinter application — futuristic redesign."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Argus — Web Vulnerability Scanner")
        self.root.geometry("1440x900")
        self.root.minsize(1200, 720)
        self.root.configure(bg=BG)

        self.scanner = VulnerabilityScanner()
        self.exporter = ReportExporter()
        self.scan_result: Optional[ScanResult] = None
        self.current_finding: Optional[Finding] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.message_queue = queue.Queue()

        self._setup_styles()
        self._create_menu()
        self._build_layout()
        self._start_queue_processor()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # General
        style.configure(".", background=BG, foreground=TEXT,
                         font=FONT_BODY, borderwidth=0)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_BODY)
        style.configure("TCheckbutton", background=SURFACE, foreground=TEXT,
                         font=FONT_BODY, indicatorcolor=SURFACE3,
                         selectcolor=ACCENT)
        style.map("TCheckbutton",
                  background=[("active", SURFACE)],
                  foreground=[("active", TEXT)])

        # Entry
        style.configure("TEntry", fieldbackground=SURFACE2, foreground=TEXT,
                         insertcolor=ACCENT, bordercolor=BORDER,
                         lightcolor=BORDER, darkcolor=BORDER,
                         font=FONT_BODY)
        style.map("TEntry", bordercolor=[("focus", ACCENT)])

        # Combobox
        style.configure("TCombobox", fieldbackground=SURFACE2, foreground=TEXT,
                         background=SURFACE2, selectbackground=SURFACE3,
                         arrowcolor=ACCENT, bordercolor=BORDER,
                         font=FONT_BODY)
        style.map("TCombobox",
                  fieldbackground=[("readonly", SURFACE2)],
                  foreground=[("readonly", TEXT)],
                  selectbackground=[("readonly", SURFACE3)])

        # Treeview
        style.configure("Argus.Treeview",
                         background=SURFACE,
                         foreground=TEXT,
                         fieldbackground=SURFACE,
                         rowheight=28,
                         font=FONT_BODY,
                         borderwidth=0)
        style.configure("Argus.Treeview.Heading",
                         background=SURFACE2,
                         foreground=MUTED,
                         font=("Segoe UI", 9, "bold"),
                         relief="flat",
                         borderwidth=0)
        style.map("Argus.Treeview",
                  background=[("selected", SURFACE3)],
                  foreground=[("selected", ACCENT)])
        style.map("Argus.Treeview.Heading",
                  background=[("active", SURFACE3)])

        # Notebook
        style.configure("Argus.TNotebook", background=SURFACE, borderwidth=0,
                         tabmargins=[0, 0, 0, 0])
        style.configure("Argus.TNotebook.Tab",
                         background=SURFACE2, foreground=MUTED,
                         font=("Segoe UI", 9, "bold"),
                         padding=[14, 6],
                         borderwidth=0)
        style.map("Argus.TNotebook.Tab",
                  background=[("selected", SURFACE), ("active", SURFACE3)],
                  foreground=[("selected", ACCENT), ("active", TEXT)])

        # Scrollbar
        style.configure("Argus.Vertical.TScrollbar",
                         background=SURFACE2, troughcolor=SURFACE,
                         arrowcolor=MUTED, borderwidth=0, width=6)
        style.map("Argus.Vertical.TScrollbar",
                  background=[("active", SURFACE3)])

        # Progressbar (used as fallback)
        style.configure("Argus.Horizontal.TProgressbar",
                         background=ACCENT, troughcolor=SURFACE2,
                         borderwidth=0, thickness=6)

        # PanedWindow
        style.configure("TPanedwindow", background=BG)

        # Separator
        style.configure("TSeparator", background=BORDER)

    # ── Menu ──────────────────────────────────────────────────────────────────

    def _create_menu(self):
        menubar = tk.Menu(self.root, bg=SURFACE2, fg=TEXT,
                          activebackground=SURFACE3, activeforeground=ACCENT,
                          borderwidth=0, relief="flat")
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE2, fg=TEXT,
                            activebackground=SURFACE3, activeforeground=ACCENT)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export HTML Report", command=self._export_html)
        file_menu.add_command(label="Export PDF Report",  command=self._export_pdf)
        file_menu.add_command(label="Export JSON Report", command=self._export_json)
        file_menu.add_command(label="Export CSV Summary", command=self._export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        scan_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE2, fg=TEXT,
                            activebackground=SURFACE3, activeforeground=ACCENT)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="New Scan",  command=self._focus_scan_input)
        scan_menu.add_command(label="Stop Scan", command=self._stop_scan)

        help_menu = tk.Menu(menubar, tearoff=0, bg=SURFACE2, fg=TEXT,
                            activebackground=SURFACE3, activeforeground=ACCENT)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        # Header
        self._create_header()

        # Body: main content only (sidebar removed)
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True)

        main = tk.Frame(body, bg=BG)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._create_scan_panel(main)
        self._create_results_area(main)
        self._create_status_bar(main)

    # ── Header ────────────────────────────────────────────────────────────────

    def _create_header(self):
        hdr = tk.Frame(self.root, bg=SURFACE, height=60)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        # Separator line at bottom
        sep = tk.Frame(self.root, bg=BORDER, height=1)
        sep.pack(fill=tk.X)

        # Logo
        logo_frame = tk.Frame(hdr, bg=SURFACE)
        logo_frame.pack(side=tk.LEFT, padx=20)

        tk.Label(logo_frame, text="◉", font=("Segoe UI", 20), fg=ACCENT,
                 bg=SURFACE).pack(side=tk.LEFT)
        tk.Label(logo_frame, text=" ARGUS", font=("Segoe UI", 16, "bold"),
                 fg=TEXT, bg=SURFACE).pack(side=tk.LEFT)

        # URL entry (center)
        url_frame = tk.Frame(hdr, bg=SURFACE2, bd=0,
                              highlightthickness=1, highlightbackground=BORDER)
        url_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=20, pady=10)

        tk.Label(url_frame, text="  🔗", font=("Segoe UI", 11), fg=MUTED,
                 bg=SURFACE2).pack(side=tk.LEFT)
        self.url_entry = tk.Entry(url_frame, font=("Segoe UI", 11),
                                   bg=SURFACE2, fg=TEXT,
                                   insertbackground=ACCENT,
                                   relief="flat", bd=0)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=4)
        self.url_entry.insert(0, "https://")
        self.url_entry.bind("<FocusIn>",  lambda e: url_frame.config(highlightbackground=ACCENT))
        self.url_entry.bind("<FocusOut>", lambda e: url_frame.config(highlightbackground=BORDER))
        self.url_entry.bind("<Return>", lambda e: self._start_scan())

        # Scan button
        self.scan_btn = GlowButton(hdr, text="⚡  SCAN", command=self._start_scan,
                                    width=110, height=38, bg_color=ACCENT,
                                    text_color=BG, font=("Segoe UI", 10, "bold"))
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Stop button
        self.stop_btn = GlowButton(hdr, text="■  STOP", command=self._stop_scan,
                                    width=100, height=38, bg_color=SURFACE3,
                                    text_color=MUTED, font=("Segoe UI", 10, "bold"))
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 20))

    # ── Sidebar ───────────────────────────────────────────────────────────────

    def _create_sidebar(self, parent):
        sb = tk.Frame(parent, bg=SURFACE, width=64)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        sb.pack_propagate(False)

        # Separator line
        tk.Frame(parent, bg=BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Use short ASCII text icons — reliable on all Linux systems
        # (icon_text, label, click_action)
        items = [
            ("[ ]",  "Scan",     self._sidebar_scan),
            ("[=]",  "Findings", self._sidebar_findings),
            ("[#]",  "CVSS",     self._sidebar_cvss),
            ("[>]",  "Reports",  self._sidebar_reports),
            ("[*]",  "Settings", self._sidebar_settings),
        ]

        self._sidebar_frames = []
        self._active_sidebar = 0

        for i, (icon, tip, action) in enumerate(items):
            f = tk.Frame(sb, bg=SURFACE, cursor="hand2")
            f.pack(fill=tk.X, pady=1)

            lbl = tk.Label(f, text=icon, font=("Consolas", 13, "bold"),
                           fg=MUTED, bg=SURFACE, pady=8)
            lbl.pack()
            tip_lbl = tk.Label(f, text=tip, font=("Segoe UI", 7),
                               fg=MUTED, bg=SURFACE)
            tip_lbl.pack(pady=(0, 4))

            self._sidebar_frames.append((f, lbl, tip_lbl))

            def _enter(e, frame=f, icon_lbl=lbl, tip=tip_lbl):
                frame.config(bg=SURFACE2)
                icon_lbl.config(bg=SURFACE2, fg=ACCENT)
                tip.config(bg=SURFACE2, fg=TEXT)

            def _leave(e, frame=f, icon_lbl=lbl, tip=tip_lbl, idx=i):
                # Keep active item highlighted
                if idx == self._active_sidebar:
                    frame.config(bg=SURFACE3)
                    icon_lbl.config(bg=SURFACE3, fg=ACCENT)
                    tip.config(bg=SURFACE3, fg=TEXT)
                else:
                    frame.config(bg=SURFACE)
                    icon_lbl.config(bg=SURFACE, fg=MUTED)
                    tip.config(bg=SURFACE, fg=MUTED)

            def _click(e, idx=i, act=action):
                self._set_active_sidebar(idx)
                act()

            for w in (f, lbl, tip_lbl):
                w.bind("<Enter>",    _enter)
                w.bind("<Leave>",    _leave)
                w.bind("<Button-1>", _click)

        # Highlight first item (Scan) as active by default
        self._set_active_sidebar(0)

    def _set_active_sidebar(self, idx):
        self._active_sidebar = idx
        for i, (f, lbl, tip_lbl) in enumerate(self._sidebar_frames):
            if i == idx:
                f.config(bg=SURFACE3)
                lbl.config(bg=SURFACE3, fg=ACCENT)
                tip_lbl.config(bg=SURFACE3, fg=TEXT)
            else:
                f.config(bg=SURFACE)
                lbl.config(bg=SURFACE, fg=MUTED)
                tip_lbl.config(bg=SURFACE, fg=MUTED)

    def _sidebar_scan(self):
        """Focus the URL entry for a new scan."""
        self._focus_scan_input()

    def _sidebar_findings(self):
        """Bring findings table into focus."""
        try:
            self.findings_tree.focus_set()
            children = self.findings_tree.get_children()
            if children:
                self.findings_tree.selection_set(children[0])
                self.findings_tree.see(children[0])
        except Exception:
            pass

    def _sidebar_cvss(self):
        """Switch detail panel to CVSS Editor tab."""
        try:
            # Find the CVSS tab index
            for i in range(self.detail_notebook.index("end")):
                if "CVSS" in self.detail_notebook.tab(i, "text"):
                    self.detail_notebook.select(i)
                    break
        except Exception:
            pass

    def _sidebar_reports(self):
        """Show a small export popup menu near the sidebar."""
        menu = tk.Menu(self.root, tearoff=0, bg=SURFACE2, fg=TEXT,
                       activebackground=SURFACE3, activeforeground=ACCENT,
                       font=FONT_BODY, bd=0)
        menu.add_command(label="  Export HTML Report", command=self._export_html)
        menu.add_command(label="  Export PDF Report",  command=self._export_pdf)
        menu.add_command(label="  Export JSON Report", command=self._export_json)
        menu.add_command(label="  Export CSV Summary", command=self._export_csv)
        try:
            # Position next to sidebar
            x = self._sidebar_frames[3][0].winfo_rootx() + 68
            y = self._sidebar_frames[3][0].winfo_rooty()
            menu.tk_popup(x, y)
        except Exception:
            menu.tk_popup(100, 200)
        finally:
            menu.grab_release()

    def _sidebar_settings(self):
        """Show the about/settings dialog."""
        self._show_about()

    # ── Scan Panel ────────────────────────────────────────────────────────────

    def _create_scan_panel(self, parent):
        card = tk.Frame(parent, bg=SURFACE, bd=0,
                         highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill=tk.X, padx=16, pady=(12, 6))

        inner = tk.Frame(card, bg=SURFACE)
        inner.pack(fill=tk.X, padx=16, pady=12)

        # Left: radar + level
        left = tk.Frame(inner, bg=SURFACE)
        left.pack(side=tk.LEFT, padx=(0, 24))

        self.radar = RadarCanvas(left, size=110, bg=SURFACE)
        self.radar.pack()

        # Right: controls
        right = tk.Frame(inner, bg=SURFACE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scan level label
        tk.Label(right, text="SCAN LEVEL", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SURFACE).pack(anchor=tk.W)

        level_row = tk.Frame(right, bg=SURFACE)
        level_row.pack(anchor=tk.W, pady=(4, 12))

        self.scan_level_pill = PillToggle(level_row, ["LOW", "MEDIUM", "HIGH"], default=1)
        self.scan_level_pill.pack(side=tk.LEFT)

        # Intrusive toggle
        self.intrusive_var = tk.BooleanVar()
        intr_frame = tk.Frame(right, bg=SURFACE)
        intr_frame.pack(anchor=tk.W, pady=(0, 10))

        self.intr_check = tk.Checkbutton(
            intr_frame, text="Allow Intrusive Checks",
            variable=self.intrusive_var,
            bg=SURFACE, fg=TEXT, selectcolor=SURFACE2,
            activebackground=SURFACE, activeforeground=TEXT,
            font=FONT_SMALL, cursor="hand2",
            highlightthickness=0
        )
        self.intr_check.pack(side=tk.LEFT)

        intr_warn = tk.Label(intr_frame,
                              text="  ⚠ May cause delays on target",
                              font=("Segoe UI", 8), fg=MED, bg=SURFACE)
        intr_warn.pack(side=tk.LEFT)

        # Progress area
        prog_frame = tk.Frame(right, bg=SURFACE)
        prog_frame.pack(fill=tk.X, pady=(4, 0))

        prog_top = tk.Frame(prog_frame, bg=SURFACE)
        prog_top.pack(fill=tk.X)

        self.progress_label = tk.Label(prog_top, text="Ready",
                                        font=FONT_SMALL, fg=MUTED, bg=SURFACE)
        self.progress_label.pack(side=tk.LEFT)

        self.progress_pct = tk.Label(prog_top, text="",
                                      font=("Segoe UI", 9, "bold"),
                                      fg=ACCENT, bg=SURFACE)
        self.progress_pct.pack(side=tk.RIGHT)

        # Custom canvas progress bar
        self.prog_canvas = tk.Canvas(prog_frame, height=6, bg=SURFACE2,
                                      highlightthickness=0)
        self.prog_canvas.pack(fill=tk.X, pady=(4, 0))
        self._progress_val = 0
        self.prog_canvas.bind("<Configure>", self._redraw_progress)

    def _redraw_progress(self, event=None):
        self.prog_canvas.delete("all")
        w = self.prog_canvas.winfo_width()
        h = 6
        # Track
        self.prog_canvas.create_rectangle(0, 0, w, h, fill=SURFACE2, outline="")
        # Fill
        fill_w = int(w * self._progress_val / 100)
        if fill_w > 0:
            color = ACCENT2 if self._progress_val >= 100 else ACCENT
            self.prog_canvas.create_rectangle(0, 0, fill_w, h, fill=color, outline="")

    def _set_progress(self, val, text=""):
        self._progress_val = val
        self._redraw_progress()
        self.progress_pct.config(text=f"{int(val)}%" if val > 0 else "")
        if text:
            self.progress_label.config(text=text)

    # ── Results area (findings + detail) ─────────────────────────────────────

    def _create_results_area(self, parent):
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=16, pady=6)

        self._create_findings_panel(paned)
        self._create_detail_panel(paned)

    # ── Findings panel ────────────────────────────────────────────────────────

    def _create_findings_panel(self, parent):
        card = tk.Frame(parent, bg=SURFACE,
                         highlightthickness=1, highlightbackground=BORDER)
        parent.add(card, weight=1)

        # Header row
        hdr = tk.Frame(card, bg=SURFACE2)
        hdr.pack(fill=tk.X)

        tk.Label(hdr, text="FINDINGS", font=("Segoe UI", 9, "bold"),
                 fg=MUTED, bg=SURFACE2, padx=12, pady=8).pack(side=tk.LEFT)

        self.findings_count = tk.Label(hdr, text="0 items",
                                        font=("Segoe UI", 9, "bold"),
                                        fg=ACCENT, bg=SURFACE2, padx=8)
        self.findings_count.pack(side=tk.LEFT)

        # Severity filter pills
        filter_frame = tk.Frame(hdr, bg=SURFACE2)
        filter_frame.pack(side=tk.RIGHT, padx=8)

        tk.Label(filter_frame, text="Filter:", font=FONT_SMALL,
                 fg=MUTED, bg=SURFACE2).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_var = tk.StringVar(value="All")
        for val in ["All", "Critical", "High", "Medium", "Low"]:
            color = SEV_COLORS.get(val, MUTED) if val != "All" else MUTED
            btn = tk.Label(filter_frame, text=val, font=("Segoe UI", 8, "bold"),
                           fg=color, bg=SURFACE3, padx=8, pady=3, cursor="hand2")
            btn.pack(side=tk.LEFT, padx=2, pady=4)
            btn.bind("<Button-1>", lambda e, v=val, b=btn: self._apply_filter_pill(v))

        # Treeview
        tree_frame = tk.Frame(card, bg=SURFACE)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("severity", "name", "score", "confidence", "plugin")
        self.findings_tree = ttk.Treeview(tree_frame, columns=cols,
                                           show="headings", selectmode="browse",
                                           style="Argus.Treeview")

        heads = [("severity", "Severity", 90, "center"),
                 ("name",     "Vulnerability", 220, "w"),
                 ("score",    "CVSS", 60, "center"),
                 ("confidence","Conf.", 65, "center"),
                 ("plugin",   "Plugin", 140, "w")]
        for col, label, width, anchor in heads:
            self.findings_tree.heading(col, text=label)
            self.findings_tree.column(col, width=width, anchor=anchor, minwidth=40)

        sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                            command=self.findings_tree.yview,
                            style="Argus.Vertical.TScrollbar")
        self.findings_tree.configure(yscrollcommand=sb.set)
        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_select)

        # Severity tag colours
        self.findings_tree.tag_configure("critical", foreground=CRIT)
        self.findings_tree.tag_configure("high",     foreground=HIGH)
        self.findings_tree.tag_configure("medium",   foreground=MED)
        self.findings_tree.tag_configure("low",      foreground=LOW)
        self.findings_tree.tag_configure("none",     foreground=NONE_C)
        self.findings_tree.tag_configure("odd",      background=SURFACE)
        self.findings_tree.tag_configure("even",     background=SURFACE2)

    # ── Detail panel ──────────────────────────────────────────────────────────

    def _create_detail_panel(self, parent):
        card = tk.Frame(parent, bg=SURFACE,
                         highlightthickness=1, highlightbackground=BORDER)
        parent.add(card, weight=2)

        self.detail_notebook = ttk.Notebook(card, style="Argus.TNotebook")
        self.detail_notebook.pack(fill=tk.BOTH, expand=True)

        self._create_overview_tab()
        self._create_evidence_tab()
        self._create_cvss_tab()
        self._create_sitemap_tab()

    def _dark_text(self, parent, **kwargs):
        """Helper: dark-styled ScrolledText."""
        t = scrolledtext.ScrolledText(
            parent, bg=SURFACE2, fg=TEXT,
            insertbackground=ACCENT,
            selectbackground=SURFACE3, selectforeground=TEXT,
            relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            **kwargs
        )
        return t

    def _create_overview_tab(self):
        f = tk.Frame(self.detail_notebook, bg=SURFACE)
        self.detail_notebook.add(f, text="  Overview  ")
        self.overview_text = self._dark_text(f, wrap=tk.WORD, font=FONT_BODY)
        self.overview_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.overview_text.insert(tk.END, "Select a finding to view details…")
        self.overview_text.configure(state=tk.DISABLED)

    def _create_evidence_tab(self):
        f = tk.Frame(self.detail_notebook, bg=SURFACE)
        self.detail_notebook.add(f, text="  Evidence  ")

        paned = ttk.PanedWindow(f, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        req_card = tk.Frame(paned, bg=SURFACE2,
                             highlightthickness=1, highlightbackground=BORDER)
        paned.add(req_card, weight=1)
        tk.Label(req_card, text="REQUEST", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SURFACE2, padx=8, pady=4).pack(anchor=tk.W)
        self.request_text = self._dark_text(req_card, font=FONT_MONO, height=8)
        self.request_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        resp_card = tk.Frame(paned, bg=SURFACE2,
                              highlightthickness=1, highlightbackground=BORDER)
        paned.add(resp_card, weight=1)
        tk.Label(resp_card, text="RESPONSE", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SURFACE2, padx=8, pady=4).pack(anchor=tk.W)
        self.response_text = self._dark_text(resp_card, font=FONT_MONO, height=8)
        self.response_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

    def _create_cvss_tab(self):
        f = tk.Frame(self.detail_notebook, bg=SURFACE)
        self.detail_notebook.add(f, text="  CVSS Editor  ")

        # Score display
        score_card = tk.Frame(f, bg=SURFACE2,
                               highlightthickness=1, highlightbackground=BORDER)
        score_card.pack(fill=tk.X, padx=8, pady=(8, 4))

        score_inner = tk.Frame(score_card, bg=SURFACE2)
        score_inner.pack(fill=tk.X, padx=12, pady=8)

        self.cvss_score_label = tk.Label(score_inner, text="—",
                                          font=("Segoe UI", 32, "bold"),
                                          fg=ACCENT, bg=SURFACE2)
        self.cvss_score_label.pack(side=tk.LEFT)

        info_col = tk.Frame(score_inner, bg=SURFACE2)
        info_col.pack(side=tk.LEFT, padx=16)

        self.cvss_severity_label = tk.Label(info_col, text="N/A",
                                             font=("Segoe UI", 12, "bold"),
                                             fg=MUTED, bg=SURFACE2)
        self.cvss_severity_label.pack(anchor=tk.W)
        self.cvss_vector_label = tk.Label(info_col, text="Vector: N/A",
                                           font=FONT_SMALL, fg=MUTED, bg=SURFACE2)
        self.cvss_vector_label.pack(anchor=tk.W)

        # Metrics editor
        editor_card = tk.Frame(f, bg=SURFACE2,
                                highlightthickness=1, highlightbackground=BORDER)
        editor_card.pack(fill=tk.X, padx=8, pady=4)

        tk.Label(editor_card, text="EDIT METRICS", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SURFACE2, padx=12, pady=6).pack(anchor=tk.W)

        grid = tk.Frame(editor_card, bg=SURFACE2)
        grid.pack(fill=tk.X, padx=12, pady=(0, 8))

        self.cvss_vars = {}
        metrics = [
            ("AV", "Attack Vector",      ["N (Network)", "A (Adjacent)", "L (Local)", "P (Physical)"]),
            ("AC", "Attack Complexity",  ["L (Low)", "H (High)"]),
            ("PR", "Privileges Required",["N (None)", "L (Low)", "H (High)"]),
            ("UI", "User Interaction",   ["N (None)", "R (Required)"]),
            ("S",  "Scope",              ["U (Unchanged)", "C (Changed)"]),
            ("C",  "Confidentiality",    ["N (None)", "L (Low)", "H (High)"]),
            ("I",  "Integrity",          ["N (None)", "L (Low)", "H (High)"]),
            ("A",  "Availability",       ["N (None)", "L (Low)", "H (High)"]),
        ]
        for i, (key, label, values) in enumerate(metrics):
            row, col = divmod(i, 2)
            tk.Label(grid, text=label + ":", font=FONT_SMALL, fg=MUTED,
                     bg=SURFACE2).grid(row=row, column=col*2, sticky=tk.W,
                                       padx=(0, 4), pady=2)
            var = tk.StringVar(value=values[0])
            self.cvss_vars[key] = var
            cb = ttk.Combobox(grid, textvariable=var, values=values,
                              state="readonly", width=16, font=FONT_SMALL)
            cb.grid(row=row, column=col*2+1, padx=(0, 16), pady=2)

        # Action buttons
        btn_row = tk.Frame(f, bg=SURFACE)
        btn_row.pack(fill=tk.X, padx=8, pady=4)

        for txt, cmd in [("Recalculate CVSS", self._recalculate_cvss),
                          ("Mark Verified",    self._mark_verified),
                          ("Mark False Positive", self._mark_false_positive)]:
            b = GlowButton(btn_row, text=txt, command=cmd,
                           width=160, height=32, bg_color=SURFACE3,
                           text_color=TEXT, font=FONT_SMALL)
            b.pack(side=tk.LEFT, padx=(0, 8))

        # Notes
        notes_card = tk.Frame(f, bg=SURFACE2,
                               highlightthickness=1, highlightbackground=BORDER)
        notes_card.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))

        tk.Label(notes_card, text="ANALYST NOTES", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SURFACE2, padx=12, pady=6).pack(anchor=tk.W)

        self.notes_text = self._dark_text(notes_card, wrap=tk.WORD, height=4,
                                           font=FONT_BODY)
        self.notes_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        save_btn = GlowButton(notes_card, text="Save Notes",
                               command=self._save_notes,
                               width=110, height=28, bg_color=ACCENT2,
                               text_color=BG, font=FONT_SMALL)
        save_btn.pack(anchor=tk.E, padx=8, pady=(0, 8))

    def _create_sitemap_tab(self):
        f = tk.Frame(self.detail_notebook, bg=SURFACE)
        self.detail_notebook.add(f, text="  Site Map  ")
        
        hdr = tk.Frame(f, bg=SURFACE2)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="DISCOVERED ATTACK SURFACE", font=("Segoe UI", 9, "bold"),
                 fg=MUTED, bg=SURFACE2, padx=12, pady=8).pack(side=tk.LEFT)
                 
        tree_frame = tk.Frame(f, bg=SURFACE)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        self.sitemap_tree = ttk.Treeview(tree_frame, show="tree", style="Argus.Treeview")
        
        sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                            command=self.sitemap_tree.yview,
                            style="Argus.Vertical.TScrollbar")
        self.sitemap_tree.configure(yscrollcommand=sb.set)
        self.sitemap_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.sitemap_nodes = {}

    def _add_to_sitemap(self, url: str):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain: return
        
        if domain not in self.sitemap_nodes:
            self.sitemap_nodes[domain] = self.sitemap_tree.insert("", "end", text=f"🌐 {domain}", open=True)
            
        parent_id = self.sitemap_nodes[domain]
        path_segments = [s for s in parsed.path.split("/") if s]
        
        current_path = domain
        for i, segment in enumerate(path_segments):
            current_path += f"/{segment}"
            if current_path not in self.sitemap_nodes:
                is_last = (i == len(path_segments) - 1)
                icon = "📄 " if is_last and not url.endswith("/") else "📁 "
                self.sitemap_nodes[current_path] = self.sitemap_tree.insert(parent_id, "end", text=f"{icon}{segment}", open=False)
            parent_id = self.sitemap_nodes[current_path]

    # ── Status bar ────────────────────────────────────────────────────────────

    def _create_status_bar(self, parent):
        sep = tk.Frame(parent, bg=BORDER, height=1)
        sep.pack(fill=tk.X)

        bar = tk.Frame(parent, bg=SURFACE2, height=28)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        self._status_dot = tk.Label(bar, text="●", font=("Segoe UI", 10),
                                     fg=ACCENT2, bg=SURFACE2, padx=8)
        self._status_dot.pack(side=tk.LEFT)

        self.status_label = tk.Label(bar, text="Ready", font=FONT_SMALL,
                                      fg=MUTED, bg=SURFACE2)
        self.status_label.pack(side=tk.LEFT)

        self.stats_label = tk.Label(bar, text="", font=FONT_SMALL,
                                     fg=MUTED, bg=SURFACE2, padx=12)
        self.stats_label.pack(side=tk.RIGHT)

    def _set_status(self, text, dot_color=ACCENT2):
        self.status_label.config(text=text)
        self._status_dot.config(fg=dot_color)

    # ── Queue processor ───────────────────────────────────────────────────────

    def _start_queue_processor(self):
        self._process_queue()

    def _process_queue(self):
        try:
            while True:
                message = self.message_queue.get_nowait()
                msg_type = message.get("type")
                if msg_type == "progress":
                    self._set_progress(message["percentage"], message["text"])
                elif msg_type == "complete":
                    self._on_scan_complete(message["result"])
                elif msg_type == "error":
                    messagebox.showerror("Scan Error", message["text"])
                    self._reset_scan_ui()
                elif msg_type == "sitemap_url":
                    self._add_to_sitemap(message["url"])
        except queue.Empty:
            pass
        self.root.after(100, self._process_queue)

    # ── Scan control ──────────────────────────────────────────────────────────

    def _start_scan(self):
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showwarning("Invalid URL", "Please enter a valid target URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)

        if self.intrusive_var.get():
            confirm = messagebox.askyesno(
                "Intrusive Checks",
                "Intrusive checks may cause delays on the target server.\n\n"
                "Only use on systems you have permission to test.\n\n"
                "Continue with intrusive checks?"
            )
            if not confirm:
                self.intrusive_var.set(False)

        # Update UI — lock controls during scan
        self.scan_btn.set_state("disabled")
        self.scan_level_pill.set_state("disabled")
        self.intr_check.config(state=tk.DISABLED)
        self._set_progress(0, "Starting scan…")
        self._set_status("Scanning…", ACCENT)
        self.radar.start_scan()

        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        self.findings_count.config(text="0 items")

        if hasattr(self, 'sitemap_tree'):
            self.sitemap_tree.delete(*self.sitemap_tree.get_children())
            self.sitemap_nodes.clear()

        scan_level = self.scan_level_pill.get().lower()
        allow_intrusive = self.intrusive_var.get()

        def scan_worker():
            try:
                self.scanner.set_progress_callback(
                    lambda msg, pct: self.message_queue.put(
                        {"type": "progress", "text": msg, "percentage": pct}
                    )
                )
                self.scanner.set_sitemap_callback(
                    lambda url: self.message_queue.put(
                        {"type": "sitemap_url", "url": url}
                    )
                )
                result = self.scanner.scan(url, scan_level, allow_intrusive)
                self.message_queue.put({"type": "complete", "result": result})
            except Exception as e:
                self.message_queue.put({"type": "error", "text": str(e)})

        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.scanner.stop_scan()
        self._set_progress(self._progress_val, "Stopping scan…")
        self._set_status("Stopping…", MED)

    def _on_scan_complete(self, result: ScanResult):
        self.scan_result = result
        self._reset_scan_ui()

        for i, finding in enumerate(result.findings):
            tag_sev = finding.cvss_severity.lower()
            row_tag = "even" if i % 2 == 0 else "odd"
            self.findings_tree.insert("", tk.END, iid=finding.id, values=(
                finding.cvss_severity,
                finding.vuln_name[:45],
                f"{finding.cvss_score:.1f}",
                finding.confidence,
                finding.plugin_name[:25],
            ), tags=(tag_sev, row_tag))

        count = len(result.findings)
        self.findings_count.config(text=f"{count} item{'s' if count != 1 else ''}")

        counts = result.severity_counts
        self.stats_label.config(
            text=f"C:{counts['Critical']}  H:{counts['High']}  M:{counts['Medium']}  L:{counts['Low']}"
        )
        self._set_status(
            f"Scan complete — {result.duration:.1f}s · {count} findings",
            ACCENT2
        )
        self._set_progress(100, "Complete")

        if result.findings:
            first = self.findings_tree.get_children()[0]
            self.findings_tree.selection_set(first)
            self._on_finding_select(None)

    def _reset_scan_ui(self):
        self.scan_btn.set_state("normal")
        self.scan_level_pill.set_state("normal")
        self.intr_check.config(state=tk.NORMAL)
        self.radar.stop_scan()

    # ── Finding selection ─────────────────────────────────────────────────────

    def _on_finding_select(self, event):
        selection = self.findings_tree.selection()
        if not selection or not self.scan_result:
            return
        finding_id = selection[0]
        finding = next((f for f in self.scan_result.findings if f.id == finding_id), None)
        if not finding:
            return
        self.current_finding = finding
        self._update_overview(finding)
        self._update_evidence(finding)
        self._update_cvss_editor(finding)

    def _update_overview(self, finding: Finding):
        self.overview_text.configure(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)

        sev_color = SEV_COLORS.get(finding.cvss_severity, MUTED)

        text = (
            f"VULNERABILITY: {finding.vuln_name}\n"
            f"{'─'*60}\n\n"
            f"SEVERITY:    {finding.cvss_severity}  (CVSS {finding.cvss_score})\n"
            f"CONFIDENCE:  {finding.confidence}\n"
            f"PLUGIN:      {finding.plugin_name}\n\n"
            f"SUMMARY\n{'─'*40}\n{finding.short_intro}\n\n"
            f"DESCRIPTION\n{'─'*40}\n{finding.description}\n\n"
            f"AFFECTED ENDPOINTS\n{'─'*40}\n"
        )
        for ep in finding.affected_endpoints:
            text += f"  • {ep}\n"

        text += f"\nIMPACT\n{'─'*40}\n"
        for imp in finding.impact:
            text += f"  ✦ {imp}\n"

        text += f"\nPROOF OF CONCEPT\n{'─'*40}\n"
        for step in finding.proof_of_concept:
            text += f"  {step}\n"

        text += f"\nREMEDIATION\n{'─'*40}\n"
        for step in finding.remediation:
            text += f"  → {step}\n"

        text += f"\nREFERENCES\n{'─'*40}\n"
        for ref in finding.references:
            text += f"  {ref}\n"

        text += (
            f"\nCVSS DETAILS\n{'─'*40}\n"
            f"Vector:   {finding.cvss_vector}\n"
            f"Score:    {finding.cvss_score}\n"
            f"Severity: {finding.cvss_severity}\n\n"
            f"Status: {'✔ VERIFIED' if finding.verified else '○ Unverified'}\n"
        )
        if finding.false_positive:
            text += "⚠ MARKED AS FALSE POSITIVE\n"

        self.overview_text.insert(tk.END, text)
        self.overview_text.configure(state=tk.DISABLED)

    def _update_evidence(self, finding: Finding):
        self.request_text.delete(1.0, tk.END)
        self.response_text.delete(1.0, tk.END)
        if finding.evidence:
            ev = finding.evidence[0]
            self.request_text.insert(tk.END, ev.request or "No request data")
            self.response_text.insert(tk.END, ev.response or "No response data")
        else:
            self.request_text.insert(tk.END, "No evidence captured")
            self.response_text.insert(tk.END, "No evidence captured")

    def _update_cvss_editor(self, finding: Finding):
        score = finding.cvss_score
        sev = finding.cvss_severity
        color = SEV_COLORS.get(sev, MUTED)

        self.cvss_score_label.config(text=str(score), fg=color)
        self.cvss_severity_label.config(text=sev, fg=color)
        self.cvss_vector_label.config(text=f"Vector: {finding.cvss_vector}")

        metrics = finding.suggested_cvss
        value_map = {
            "AV": {"N": "N (Network)", "A": "A (Adjacent)", "L": "L (Local)", "P": "P (Physical)"},
            "AC": {"L": "L (Low)", "H": "H (High)"},
            "PR": {"N": "N (None)", "L": "L (Low)", "H": "H (High)"},
            "UI": {"N": "N (None)", "R": "R (Required)"},
            "S":  {"U": "U (Unchanged)", "C": "C (Changed)"},
            "C":  {"N": "N (None)", "L": "L (Low)", "H": "H (High)"},
            "I":  {"N": "N (None)", "L": "L (Low)", "H": "H (High)"},
            "A":  {"N": "N (None)", "L": "L (Low)", "H": "H (High)"},
        }
        for key, var in self.cvss_vars.items():
            val = metrics.get(key, "N")
            var.set(value_map.get(key, {}).get(val, val))

        self.notes_text.delete(1.0, tk.END)
        if finding.analyst_notes:
            self.notes_text.insert(tk.END, finding.analyst_notes)

    # ── CVSS actions ──────────────────────────────────────────────────────────

    def _recalculate_cvss(self):
        if not self.current_finding:
            return
        new_metrics = {}
        for key, var in self.cvss_vars.items():
            val = var.get()
            if " (" in val:
                val = val.split(" (")[0]
            new_metrics[key] = val

        self.scanner.update_finding_cvss(self.current_finding, new_metrics, "analyst")

        score = self.current_finding.cvss_score
        sev   = self.current_finding.cvss_severity
        color = SEV_COLORS.get(sev, MUTED)
        self.cvss_score_label.config(text=str(score), fg=color)
        self.cvss_severity_label.config(text=sev, fg=color)
        self.cvss_vector_label.config(text=f"Vector: {self.current_finding.cvss_vector}")

        selection = self.findings_tree.selection()
        if selection:
            self.findings_tree.item(selection[0], values=(
                sev,
                self.current_finding.vuln_name[:45],
                f"{score:.1f}",
                self.current_finding.confidence,
                self.current_finding.plugin_name[:25],
            ), tags=(sev.lower(),))

        messagebox.showinfo("CVSS Updated",
                            f"New score: {score} ({sev})")

    def _mark_verified(self):
        if not self.current_finding:
            return
        self.current_finding.verified = True
        self.current_finding.false_positive = False
        messagebox.showinfo("Verified", "Finding marked as verified.")

    def _mark_false_positive(self):
        if not self.current_finding:
            return
        self.current_finding.false_positive = True
        self.current_finding.verified = False
        messagebox.showinfo("False Positive", "Finding marked as false positive.")

    def _save_notes(self):
        if not self.current_finding:
            return
        self.current_finding.analyst_notes = self.notes_text.get(1.0, tk.END).strip()
        messagebox.showinfo("Notes Saved", "Analyst notes saved.")

    # ── Filter ────────────────────────────────────────────────────────────────

    def _apply_filter_pill(self, value):
        self._filter_var.set(value)
        if not self.scan_result:
            return
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        i = 0
        for finding in self.scan_result.findings:
            if value == "All" or finding.cvss_severity == value:
                tag_sev = finding.cvss_severity.lower()
                row_tag = "even" if i % 2 == 0 else "odd"
                self.findings_tree.insert("", tk.END, iid=finding.id, values=(
                    finding.cvss_severity,
                    finding.vuln_name[:45],
                    f"{finding.cvss_score:.1f}",
                    finding.confidence,
                    finding.plugin_name[:25],
                ), tags=(tag_sev, row_tag))
                i += 1

    # ── Exports ───────────────────────────────────────────────────────────────

    def _export_html(self):
        if not self.scan_result or not self.scan_result.findings:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML files", "*.html")]
        )
        if filepath:
            self.exporter.output_dir = Path(filepath).parent
            self.exporter.export_html(
                self.scan_result.findings, self.scan_result.target_url,
                self.scan_result.scan_level, self.scan_result.duration,
                Path(filepath).name
            )
            messagebox.showinfo("Exported", f"HTML report saved to {filepath}")

    def _export_pdf(self):
        if not self.scan_result or not self.scan_result.findings:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")]
        )
        if filepath:
            self.exporter.output_dir = Path(filepath).parent
            self.exporter.export_pdf(
                self.scan_result.findings, self.scan_result.target_url,
                self.scan_result.scan_level, self.scan_result.duration,
                Path(filepath).name
            )
            messagebox.showinfo("Exported", f"PDF report saved to {filepath}")

    def _export_json(self):
        if not self.scan_result or not self.scan_result.findings:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON files", "*.json")]
        )
        if filepath:
            self.exporter.output_dir = Path(filepath).parent
            self.exporter.export_json(
                self.scan_result.findings, self.scan_result.target_url,
                self.scan_result.scan_level, self.scan_result.duration,
                self.scan_result.attack_surface,
                Path(filepath).name
            )
            messagebox.showinfo("Exported", f"JSON report saved to {filepath}")

    def _export_csv(self):
        if not self.scan_result or not self.scan_result.findings:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
        )
        if filepath:
            self.exporter.output_dir = Path(filepath).parent
            self.exporter.export_csv(self.scan_result.findings, Path(filepath).name)
            messagebox.showinfo("Exported", f"CSV report saved to {filepath}")

    # ── Misc ──────────────────────────────────────────────────────────────────

    def _focus_scan_input(self):
        self.url_entry.focus_set()
        self.url_entry.select_range(0, tk.END)

    def _show_about(self):
        messagebox.showinfo(
            "About Argus",
            "Argus v1.0.0\n\n"
            "Professional Web Vulnerability Scanner\n\n"
            "Features:\n"
            "  • Modular plugin-driven architecture\n"
            "  • Automatic CVSS v3.1 scoring\n"
            "  • Intrusive & non-intrusive scan modes\n"
            "  • Request repeater & evidence capture\n"
            "  • HTML / PDF / JSON / CSV export\n\n"
            "Use responsibly and only on systems you have permission to test."
        )


def main():
    """Run the application."""
    root = tk.Tk()
    app = VulnScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
