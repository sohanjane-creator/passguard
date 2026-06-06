"""
gui.py — Password Auditor & Manager (Tkinter UI)
Drop-in replacement for main.py's terminal UI.

New in this version:
  • Dark / Light theme toggle
  • Show / hide passwords in vault table
  • Clipboard auto-clear after 30 seconds
  • Auto-lock timer (idle → locks vault)
  • Password History log per credential

Install dependencies first:
    pip install cryptography requests colorama

Run:
    python gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import glob
import time
import json
import os

# ── Try importing app modules ─────────────────────────────────────────────────
try:
    from analyzer import score_password
    from pwned import check_pwned
    from generator import generate_password, generate_passphrase, estimate_crack_time
    from vault import (
        vault_exists, create_vault, unlock_vault,
        add_credential, get_all_credentials, search_credentials,
        delete_credential, get_vault_stats
    )
    MODULES_OK = True
except ImportError as e:
    MODULES_OK = False
    IMPORT_ERROR = str(e)


# ── Theme Palettes ────────────────────────────────────────────────────────────

DARK = dict(
    BG="#0d1117", BG2="#161b22", BG3="#21262d", BORDER="#30363d",
    ACCENT="#58a6ff", ACCENT2="#3fb950", DANGER="#f85149",
    WARN="#e3b341", TEXT="#e6edf3", TEXT_DIM="#8b949e",
)
LIGHT = dict(
    BG="#f6f8fa", BG2="#ffffff", BG3="#eaeef2", BORDER="#d0d7de",
    ACCENT="#0969da", ACCENT2="#1a7f37", DANGER="#cf222e",
    WARN="#9a6700", TEXT="#1f2328", TEXT_DIM="#636c76",
)

# Active palette (mutable globals so all widgets read same values)
_T = dict(DARK)

def _apply_palette(palette: dict):
    _T.update(palette)

def BG():      return _T["BG"]
def BG2():     return _T["BG2"]
def BG3():     return _T["BG3"]
def BORDER():  return _T["BORDER"]
def ACCENT():  return _T["ACCENT"]
def ACCENT2(): return _T["ACCENT2"]
def DANGER():  return _T["DANGER"]
def WARN():    return _T["WARN"]
def TEXT():    return _T["TEXT"]
def TEXT_DIM():return _T["TEXT_DIM"]

FONT_MONO  = ("Consolas", 11)
FONT_UI    = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI Semibold", 13)
FONT_BIG   = ("Segoe UI Semibold", 22)

AUTO_LOCK_SECONDS  = 5 * 60   # 5 minutes idle → lock
CLIPBOARD_CLEAR_S  = 30        # seconds before clipboard is wiped

# ── Password History file (simple JSON log) ───────────────────────────────────
HISTORY_FILE = "pw_history.json"

def _load_history() -> dict:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_history(h: dict):
    with open(HISTORY_FILE, "w") as f:
        json.dump(h, f, indent=2)

def record_history(site: str, username: str, note: str = ""):
    """Append a timestamped entry to the history log."""
    h = _load_history()
    key = f"{site}|{username}"
    h.setdefault(key, [])
    h[key].append({
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "note": note or "Password saved/updated"
    })
    _save_history(h)

def get_history(site: str, username: str) -> list:
    h = _load_history()
    return h.get(f"{site}|{username}", [])


# ── Reusable Widgets ──────────────────────────────────────────────────────────

class Card(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2(), relief="flat",
                         highlightbackground=BORDER(), highlightthickness=1, **kw)

    def theme_update(self):
        self.config(bg=BG2(), highlightbackground=BORDER())


class PrimaryBtn(tk.Button):
    def __init__(self, parent, text, command=None, danger=False, **kw):
        self._danger = danger
        color = DANGER() if danger else ACCENT()
        super().__init__(parent, text=text, command=command,
                         bg=color, fg=BG(), font=("Segoe UI Semibold", 10),
                         relief="flat", bd=0, cursor="hand2",
                         activebackground=color, activeforeground=BG(),
                         padx=14, pady=7, **kw)

    def theme_update(self):
        color = DANGER() if self._danger else ACCENT()
        self.config(bg=color, fg=BG(), activebackground=color, activeforeground=BG())


class GhostBtn(tk.Button):
    def __init__(self, parent, text, command=None, **kw):
        super().__init__(parent, text=text, command=command,
                         bg=BG3(), fg=TEXT(), font=FONT_UI,
                         relief="flat", bd=0, cursor="hand2",
                         activebackground=BORDER(), activeforeground=TEXT(),
                         padx=12, pady=6, **kw)

    def theme_update(self):
        self.config(bg=BG3(), fg=TEXT(), activebackground=BORDER(), activeforeground=TEXT())


class StyledEntry(tk.Entry):
    def __init__(self, parent, show="", **kw):
        super().__init__(parent, show=show,
                         bg=BG3(), fg=TEXT(), insertbackground=TEXT(),
                         relief="flat", bd=0, font=FONT_MONO,
                         highlightthickness=1, highlightbackground=BORDER(),
                         highlightcolor=ACCENT(), **kw)

    def theme_update(self):
        self.config(bg=BG3(), fg=TEXT(), insertbackground=TEXT(),
                    highlightbackground=BORDER(), highlightcolor=ACCENT())


class StrengthBar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG3(), height=6, **kw)
        self.fill = tk.Frame(self, bg=ACCENT2(), height=6)
        self.fill.place(x=0, y=0, relheight=1, relwidth=0)
        self._target = 0
        self._current = 0

    def set(self, score: int):
        grade = _score_to_grade(score)
        color = {"A+": ACCENT2(), "A": ACCENT2(), "B": ACCENT(),
                 "C": WARN(), "D": DANGER(), "F": DANGER()}.get(grade, TEXT_DIM())
        self.fill.config(bg=color)
        self._target = score / 100
        self._animate()

    def _animate(self):
        if abs(self._current - self._target) < 0.01:
            self._current = self._target
        else:
            self._current += (self._target - self._current) * 0.25
        self.fill.place_configure(relwidth=self._current)
        if self._current != self._target:
            self.after(16, self._animate)

    def theme_update(self):
        self.config(bg=BG3())


def _score_to_grade(score):
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 65: return "B"
    if score >= 50: return "C"
    if score >= 35: return "D"
    return "F"


# ── Theme Engine ──────────────────────────────────────────────────────────────

class ThemeEngine:
    """Walks the widget tree and refreshes colours on every registered widget."""
    _widgets = []

    @classmethod
    def register(cls, w):
        cls._widgets.append(w)

    @classmethod
    def apply(cls, root, palette: dict):
        _apply_palette(palette)
        cls._refresh_tree(root)

    @classmethod
    def _refresh_tree(cls, widget):
        try:
            cls._refresh_one(widget)
        except Exception:
            pass
        for child in widget.winfo_children():
            cls._refresh_tree(child)

    @classmethod
    def _refresh_one(cls, w):
        cls_name = w.__class__.__name__
        if isinstance(w, (tk.Frame, tk.LabelFrame)):
            bg = BG2() if cls_name == "Card" else BG()
            try: w.config(bg=bg)
            except Exception: pass
        elif isinstance(w, tk.Label):
            try:
                curr_fg = w.cget("fg")
                curr_bg = w.cget("bg")
                # heuristic remap
                old_d, old_l = DARK, LIGHT
                palette_map = {
                    old_d["TEXT"]:     TEXT(),
                    old_d["TEXT_DIM"]: TEXT_DIM(),
                    old_d["ACCENT"]:   ACCENT(),
                    old_d["ACCENT2"]:  ACCENT2(),
                    old_d["DANGER"]:   DANGER(),
                    old_d["WARN"]:     WARN(),
                    old_l["TEXT"]:     TEXT(),
                    old_l["TEXT_DIM"]: TEXT_DIM(),
                    old_l["ACCENT"]:   ACCENT(),
                    old_l["ACCENT2"]:  ACCENT2(),
                    old_l["DANGER"]:   DANGER(),
                    old_l["WARN"]:     WARN(),
                }
                new_fg = palette_map.get(curr_fg, curr_fg)
                new_bg = BG2() if curr_bg in (old_d["BG2"], old_l["BG2"]) else BG()
                w.config(fg=new_fg, bg=new_bg)
            except Exception:
                pass
        elif isinstance(w, (tk.Button,)):
            try:
                if hasattr(w, 'theme_update'): w.theme_update()
            except Exception:
                pass
        elif isinstance(w, (tk.Entry,)):
            try:
                w.config(bg=BG3(), fg=TEXT(), insertbackground=TEXT(),
                         highlightbackground=BORDER(), highlightcolor=ACCENT())
            except Exception:
                pass


# ── Main Application ──────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 PassGuard")
        self.configure(bg=BG())
        self.geometry("960x660")
        self.minsize(820, 600)
        self._dark_mode = True
        self._fernet = None

        self._style = ttk.Style(self)
        self._apply_ttk_style()
        self._build_layout()

        if not MODULES_OK:
            self._show_import_error()
            return
        self._show_frame("Audit")

    # ── TTK style ─────────────────────────────────────────────────────────────

    def _apply_ttk_style(self):
        s = self._style
        s.theme_use("clam")
        s.configure("Treeview",
                    background=BG2(), foreground=TEXT(), fieldbackground=BG2(),
                    rowheight=36, font=FONT_UI, borderwidth=0)
        s.configure("Treeview.Heading",
                    background=BG3(), foreground=TEXT_DIM(),
                    font=("Segoe UI Semibold", 9), borderwidth=0)
        s.map("Treeview",
              background=[("selected", BG3())],
              foreground=[("selected", ACCENT())])
        s.configure("Vertical.TScrollbar",
                    background=BG3(), troughcolor=BG2(),
                    borderwidth=0, arrowcolor=TEXT_DIM())

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        # Sidebar
        self._sidebar = tk.Frame(self, bg=BG2(), width=190,
                                 highlightthickness=1, highlightbackground=BORDER())
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        tk.Label(self._sidebar, text="🔐", font=("Segoe UI", 30),
                 bg=BG2(), fg=ACCENT()).pack(pady=(28, 4))
        tk.Label(self._sidebar, text="PassGuard", font=("Segoe UI Semibold", 15),
                 bg=BG2(), fg=TEXT()).pack()
        tk.Label(self._sidebar, text="v2.0", font=("Segoe UI", 9),
                 bg=BG2(), fg=TEXT_DIM()).pack(pady=(0, 20))

        ttk.Separator(self._sidebar, orient="horizontal").pack(fill="x", padx=16, pady=4)

        self._nav_btns = {}
        pages = [("🔍  Audit", "Audit"),
                 ("⚡  Generate", "Generate"),
                 ("🗄️  Vault", "Vault"),
                 ("📜  History", "History")]

        for label, key in pages:
            b = tk.Button(self._sidebar, text=label, anchor="w",
                          bg=BG2(), fg=TEXT(), font=FONT_UI,
                          relief="flat", bd=0, cursor="hand2",
                          activebackground=BG3(), activeforeground=ACCENT(),
                          padx=20, pady=11,
                          command=lambda k=key: self._nav(k))
            b.pack(fill="x", padx=8, pady=2)
            self._nav_btns[key] = b

        # Theme toggle at sidebar bottom
        ttk.Separator(self._sidebar, orient="horizontal").pack(
            fill="x", padx=16, pady=4, side="bottom")
        self._theme_btn = tk.Button(
            self._sidebar, text="☀️  Light Mode", anchor="w",
            bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9),
            relief="flat", bd=0, cursor="hand2",
            activebackground=BG3(), activeforeground=TEXT(),
            padx=20, pady=10,
            command=self._toggle_theme)
        self._theme_btn.pack(side="bottom", fill="x", padx=8)

        # Content area
        self._content = tk.Frame(self, bg=BG())
        self._content.pack(side="left", fill="both", expand=True)

        self._frames = {}
        self._frames["Audit"]   = AuditPage(self._content, self)
        self._frames["Generate"]= GeneratePage(self._content, self)
        self._frames["Vault"]   = VaultPage(self._content, self)
        self._frames["History"] = HistoryPage(self._content, self)

        for f in self._frames.values():
            f.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _nav(self, key):
        self._show_frame(key)
        if key == "History":
            self._frames["History"].refresh()

    def _show_frame(self, key):
        self._frames[key].tkraise()
        for k, b in self._nav_btns.items():
            b.config(bg=BG3() if k == key else BG2(),
                     fg=ACCENT() if k == key else TEXT())

    def _toggle_theme(self):
        self._dark_mode = not self._dark_mode
        palette = DARK if self._dark_mode else LIGHT
        ThemeEngine.apply(self, palette)
        self._apply_ttk_style()
        self._theme_btn.config(
            text="☀️  Light Mode" if self._dark_mode else "🌙  Dark Mode")
        # Re-highlight active nav
        for k, b in self._nav_btns.items():
            b.config(bg=BG2(), fg=TEXT())

    def _show_import_error(self):
        f = tk.Frame(self._content, bg=BG())
        f.place(relx=0, rely=0, relwidth=1, relheight=1)
        tk.Label(f, text="⚠️  Missing Modules", font=FONT_BIG,
                 bg=BG(), fg=DANGER()).pack(pady=(80, 12))
        tk.Label(f, text=f"Could not import: {IMPORT_ERROR}",
                 bg=BG(), fg=TEXT_DIM(), font=FONT_UI, wraplength=500).pack()
        tk.Label(f, text="pip install cryptography requests colorama",
                 bg=BG3(), fg=ACCENT(), font=FONT_MONO, padx=16, pady=10).pack(pady=20)


# ── Audit Page ────────────────────────────────────────────────────────────────

class AuditPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG())
        self.app = app
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=BG(), pady=20)
        hdr.pack(fill="x", padx=32)
        tk.Label(hdr, text="Audit a Password", font=FONT_BIG,
                 bg=BG(), fg=TEXT()).pack(anchor="w")
        tk.Label(hdr, text="Check strength, entropy, and data-breach exposure",
                 bg=BG(), fg=TEXT_DIM(), font=FONT_UI).pack(anchor="w")

        inp_card = Card(self)
        inp_card.pack(fill="x", padx=32, pady=(0, 12))

        tk.Label(inp_card, text="Password", bg=BG2(), fg=TEXT_DIM(),
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(14, 2))

        row = tk.Frame(inp_card, bg=BG2())
        row.pack(fill="x", padx=14, pady=(0, 14))

        self._pw_var = tk.StringVar()
        self._pw_var.trace_add("write", self._on_type)

        self._entry = StyledEntry(row, textvariable=self._pw_var, show="•")
        self._entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(2, 8))

        self._show_var = False
        self._show_btn = GhostBtn(row, text="👁", command=self._toggle_show, width=3)
        self._show_btn.pack(side="left")
        PrimaryBtn(row, text="Audit", command=self._run_audit).pack(side="left", padx=(8, 2))

        bar_row = tk.Frame(inp_card, bg=BG2())
        bar_row.pack(fill="x", padx=16, pady=(0, 16))
        self._bar = StrengthBar(bar_row)
        self._bar.pack(fill="x", pady=(0, 4))
        self._grade_lbl = tk.Label(bar_row, text="", bg=BG2(), fg=TEXT_DIM(), font=FONT_UI)
        self._grade_lbl.pack(anchor="e")

        self._result_frame = tk.Frame(self, bg=BG())
        self._result_frame.pack(fill="both", expand=True, padx=32, pady=(0, 16))
        self._score_card  = self._make_card()
        self._issues_card = self._make_card()
        self._breach_card = self._make_card()

    def _make_card(self):
        c = Card(self._result_frame)
        c.pack(fill="x", pady=(0, 8))
        return c

    def _toggle_show(self):
        self._show_var = not self._show_var
        self._entry.config(show="" if self._show_var else "•")

    def _on_type(self, *_):
        pw = self._pw_var.get()
        if not pw or not MODULES_OK:
            self._bar.set(0); self._grade_lbl.config(text=""); return
        try:
            r = score_password(pw)
            self._bar.set(r["score"])
            grade = r["grade"]
            color = {"A+": ACCENT2(), "A": ACCENT2(), "B": ACCENT(),
                     "C": WARN(), "D": DANGER(), "F": DANGER()}.get(grade, TEXT_DIM())
            self._grade_lbl.config(text=f"{r['score']}/100 · Grade {grade}", fg=color)
        except Exception:
            pass

    def _run_audit(self):
        pw = self._pw_var.get()
        if not pw:
            messagebox.showwarning("Empty", "Please enter a password to audit.", parent=self)
            return
        result = score_password(pw)
        self._show_score(result, pw)

    def _show_score(self, r, pw):
        s = r["score"]; grade = r["grade"]
        color = {"A+": ACCENT2(), "A": ACCENT2(), "B": ACCENT(),
                 "C": WARN(), "D": DANGER(), "F": DANGER()}.get(grade, TEXT_DIM())

        for w in self._score_card.winfo_children(): w.destroy()
        tk.Label(self._score_card, text="Strength Analysis",
                 bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(12, 4))
        metrics = tk.Frame(self._score_card, bg=BG2())
        metrics.pack(fill="x", padx=16, pady=(0, 12))
        self._metric(metrics, "Score", f"{s}/100 [{grade}]", color)
        self._metric(metrics, "Entropy", f"{r['entropy']} bits")
        self._metric(metrics, "Est. crack time", estimate_crack_time(r["entropy"]))
        if r.get("breakdown"):
            tk.Label(self._score_card, text="Breakdown",
                     bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).pack(anchor="w", padx=16)
            for k, v in r["breakdown"].items():
                rw = tk.Frame(self._score_card, bg=BG2())
                rw.pack(fill="x", padx=24, pady=1)
                tk.Label(rw, text=k, bg=BG2(), fg=TEXT_DIM(), font=FONT_UI).pack(side="left")
                tk.Label(rw, text=str(v), bg=BG2(), fg=TEXT(), font=FONT_UI).pack(side="right")
        tk.Frame(self._score_card, bg=BG2(), height=12).pack()

        for w in self._issues_card.winfo_children(): w.destroy()
        tk.Label(self._issues_card, text="Issues & Suggestions",
                 bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(12, 4))
        for issue in r.get("issues", []):
            self._tag_row(self._issues_card, "✘", issue, DANGER())
        for tip in r.get("suggestions", []):
            self._tag_row(self._issues_card, "→", tip, WARN())
        if not r.get("issues") and not r.get("suggestions"):
            tk.Label(self._issues_card, text="No issues found ✔",
                     bg=BG2(), fg=ACCENT2(), font=FONT_UI).pack(anchor="w", padx=20, pady=8)
        tk.Frame(self._issues_card, bg=BG2(), height=8).pack()

        for w in self._breach_card.winfo_children(): w.destroy()
        tk.Label(self._breach_card, text="HaveIBeenPwned Check",
                 bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(12, 4))
        lbl = tk.Label(self._breach_card, text="Checking…",
                       bg=BG2(), fg=TEXT_DIM(), font=FONT_UI)
        lbl.pack(anchor="w", padx=20, pady=(0, 12))

        def do_check():
            pwned = check_pwned(pw)
            if pwned.get("error"):
                lbl.config(text=f"⚠  Skipped: {pwned['error']}", fg=WARN())
            elif pwned.get("found"):
                lbl.config(text=f"✘  Found {pwned['count']:,} times — change immediately!", fg=DANGER())
            else:
                lbl.config(text="✔  Not found in any known data breaches.", fg=ACCENT2())

        threading.Thread(target=do_check, daemon=True).start()

    def _metric(self, parent, label, value, color=None):
        color = color or TEXT()
        row = tk.Frame(parent, bg=BG2())
        row.pack(side="left", padx=(0, 24), pady=4)
        tk.Label(row, text=label, bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 8)).pack(anchor="w")
        tk.Label(row, text=value,  bg=BG2(), fg=color, font=("Segoe UI Semibold", 12)).pack(anchor="w")

    def _tag_row(self, parent, icon, text, color):
        row = tk.Frame(parent, bg=BG2())
        row.pack(fill="x", padx=16, pady=2)
        tk.Label(row, text=icon, bg=BG2(), fg=color, font=FONT_UI, width=2).pack(side="left")
        tk.Label(row, text=text, bg=BG2(), fg=TEXT(), font=FONT_UI,
                 wraplength=480, justify="left").pack(side="left", anchor="w")


# ── Generate Page ─────────────────────────────────────────────────────────────

class GeneratePage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG())
        self.app = app
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=BG(), pady=20)
        hdr.pack(fill="x", padx=32)
        tk.Label(hdr, text="Generate Password", font=FONT_BIG,
                 bg=BG(), fg=TEXT()).pack(anchor="w")
        tk.Label(hdr, text="Create strong random passwords or memorable passphrases",
                 bg=BG(), fg=TEXT_DIM(), font=FONT_UI).pack(anchor="w")

        opt = Card(self)
        opt.pack(fill="x", padx=32, pady=(0, 12))
        top = tk.Frame(opt, bg=BG2())
        top.pack(fill="x", padx=16, pady=14)

        tk.Label(top, text="Mode", bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).grid(
            row=0, column=0, sticky="w", pady=4)
        self._mode = tk.StringVar(value="random")
        for i, (lbl, val) in enumerate([("Random", "random"), ("Passphrase", "passphrase")]):
            tk.Radiobutton(top, text=lbl, variable=self._mode, value=val,
                           bg=BG2(), fg=TEXT(), selectcolor=BG3(),
                           activebackground=BG2(), activeforeground=TEXT(),
                           font=FONT_UI).grid(row=0, column=i+1, padx=6, sticky="w")

        tk.Label(top, text="Length", bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).grid(
            row=1, column=0, sticky="w", pady=6)
        self._length = tk.IntVar(value=20)
        tk.Spinbox(top, from_=8, to=128, textvariable=self._length,
                   bg=BG3(), fg=TEXT(), buttonbackground=BG3(),
                   insertbackground=TEXT(), relief="flat",
                   highlightthickness=1, highlightbackground=BORDER(),
                   font=FONT_MONO, width=6).grid(row=1, column=1, sticky="w")

        self._special = tk.BooleanVar(value=True)
        tk.Checkbutton(top, text="Special characters", variable=self._special,
                       bg=BG2(), fg=TEXT(), selectcolor=BG3(),
                       activebackground=BG2(), activeforeground=TEXT(),
                       font=FONT_UI).grid(row=1, column=2, padx=16, sticky="w")

        tk.Label(top, text="Separator", bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 9)).grid(
            row=2, column=0, sticky="w", pady=4)
        self._sep = tk.StringVar(value="-")
        StyledEntry(top, textvariable=self._sep, width=4).grid(row=2, column=1, sticky="w")

        PrimaryBtn(opt, text="⚡  Generate", command=self._generate).pack(
            anchor="e", padx=16, pady=(0, 14))

        out = Card(self)
        out.pack(fill="x", padx=32, pady=(0, 12))
        tk.Label(out, text="Generated Password", bg=BG2(), fg=TEXT_DIM(),
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(12, 4))
        row = tk.Frame(out, bg=BG2())
        row.pack(fill="x", padx=14, pady=(0, 8))
        self._output_var = tk.StringVar()
        StyledEntry(row, textvariable=self._output_var, state="readonly").pack(
            side="left", fill="x", expand=True, ipady=10, padx=(2, 8))
        GhostBtn(row, text="Copy", command=self._copy).pack(side="left")
        self._out_bar = StrengthBar(out)
        self._out_bar.pack(fill="x", padx=16, pady=(0, 4))
        self._out_grade = tk.Label(out, text="", bg=BG2(), fg=TEXT_DIM(), font=FONT_UI)
        self._out_grade.pack(anchor="e", padx=16, pady=(0, 12))

    def _generate(self):
        if self._mode.get() == "passphrase":
            pw = generate_passphrase(word_count=4, separator=self._sep.get() or "-")
        else:
            pw = generate_password(length=self._length.get(), use_special=self._special.get())
        self._output_var.set(pw)
        r = score_password(pw)
        self._out_bar.set(r["score"])
        grade = r["grade"]
        color = {"A+": ACCENT2(), "A": ACCENT2(), "B": ACCENT(),
                 "C": WARN(), "D": DANGER(), "F": DANGER()}.get(grade, TEXT_DIM())
        self._out_grade.config(
            text=f"{r['score']}/100 · {grade} · {r['entropy']} bits · {estimate_crack_time(r['entropy'])}",
            fg=color)

    def _copy(self):
        pw = self._output_var.get()
        if pw:
            self.clipboard_clear(); self.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self)


# ── Vault Page ────────────────────────────────────────────────────────────────

class VaultPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG())
        self.app = app
        self._fernet = None
        self._pw_visible = False           # show/hide toggle
        self._last_activity = time.time()  # for auto-lock
        self._clipboard_job = None         # pending clipboard clear
        self._creds = []
        self._build()
        self._tick_autolock()

    def _build(self):
        self._lock_screen = self._make_lock_screen()
        self._main_screen = self._make_main_screen()
        self._lock_screen.place(relx=0, rely=0, relwidth=1, relheight=1)

    # ── Auto-lock ticker ──────────────────────────────────────────────────────

    def _tick_autolock(self):
        if self._fernet and (time.time() - self._last_activity > AUTO_LOCK_SECONDS):
            self._lock()
        self.after(10_000, self._tick_autolock)  # check every 10 s

    def _reset_activity(self, *_):
        self._last_activity = time.time()

    # ── Lock screen ───────────────────────────────────────────────────────────

    def _make_lock_screen(self):
        f = tk.Frame(self, bg=BG())

        box = tk.Frame(f, bg=BG2(), highlightthickness=1,
                       highlightbackground=BORDER(), padx=44, pady=44)
        box.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(box, text="🗄️", font=("Segoe UI", 38), bg=BG2(), fg=ACCENT()).pack()
        tk.Label(box, text="Password Vault", font=FONT_BIG, bg=BG2(), fg=TEXT()).pack(pady=(8, 2))
        tk.Label(box, text="Your credentials are encrypted end-to-end",
                 bg=BG2(), fg=TEXT_DIM(), font=FONT_UI).pack(pady=(0, 24))

        # Auto-lock notice
        mins = AUTO_LOCK_SECONDS // 60
        tk.Label(box, text=f"🔒 Auto-locks after {mins} min idle",
                 bg=BG2(), fg=TEXT_DIM(), font=("Segoe UI", 8)).pack(pady=(0, 12))

        tk.Label(box, text="Master Password", bg=BG2(), fg=TEXT_DIM(),
                 font=("Segoe UI", 9)).pack(anchor="w")
        self._master_entry = StyledEntry(box, show="•", width=30)
        self._master_entry.pack(pady=(4, 16), ipady=8)
        self._master_entry.bind("<Return>", lambda _: self._unlock())
        self._master_entry.bind("<Key>", self._reset_activity)

        PrimaryBtn(box, text="Unlock Vault", command=self._unlock).pack(fill="x")

        self._lock_msg = tk.Label(box, text="", bg=BG2(), fg=DANGER(), font=FONT_UI)
        self._lock_msg.pack(pady=(8, 0))

        # Divider + reset link
        tk.Frame(box, bg=BORDER(), height=1).pack(fill="x", pady=(18, 12))
        reset_row = tk.Frame(box, bg=BG2())
        reset_row.pack()
        tk.Label(reset_row, text="Forgot your password?", bg=BG2(),
                 fg=TEXT_DIM(), font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        rl = tk.Label(reset_row, text="Reset Vault", bg=BG2(),
                      fg=DANGER(), font=("Segoe UI", 9, "underline"), cursor="hand2")
        rl.pack(side="left")
        rl.bind("<Button-1>", lambda _: self._reset_vault())

        return f

    def _reset_vault(self):
        if not messagebox.askyesno("⚠️ Reset Vault",
                "This will permanently delete your vault and ALL saved passwords.\n\n"
                "This action CANNOT be undone.\n\nContinue?",
                icon="warning", parent=self):
            return
        typed = simpledialog.askstring("Confirm Reset",
                "Type  RESET  (all caps) to permanently delete the vault:", parent=self)
        if typed != "RESET":
            self._lock_msg.config(text="Reset cancelled — must type RESET exactly.")
            return
        deleted = []
        for pattern in ["vault.db", "vault.json", "vault.enc", "*.vault",
                         os.path.expanduser("~/.passguard/vault*")]:
            for path in glob.glob(pattern):
                try: os.remove(path); deleted.append(path)
                except OSError: pass
        if deleted:
            self._lock_msg.config(text="Vault reset. Create a new one below.", fg=ACCENT2())
            messagebox.showinfo("Vault Reset",
                "Vault deleted:\n" + "\n".join(deleted) +
                "\n\nCreate a fresh vault with a new master password.", parent=self)
        else:
            self._lock_msg.config(text="No vault file found — already clean.", fg=WARN())
        self._master_entry.delete(0, "end")

    def _unlock(self):
        pw = self._master_entry.get()
        if not pw:
            self._lock_msg.config(text="Enter your master password."); return

        if not vault_exists():
            pw2 = simpledialog.askstring("Confirm", "Confirm master password:", show="•", parent=self)
            if pw2 != pw:
                self._lock_msg.config(text="Passwords don't match."); return
            if len(pw) < 8:
                self._lock_msg.config(text="Master password must be ≥ 8 characters."); return
            create_vault(pw)

        fernet = unlock_vault(pw)
        if fernet is None:
            self._lock_msg.config(text="Wrong master password."); return

        self._fernet = fernet
        self._master_entry.delete(0, "end")
        self._lock_msg.config(text="")
        self._last_activity = time.time()
        self._refresh()
        self._main_screen.tkraise()

    # ── Main vault screen ─────────────────────────────────────────────────────

    def _make_main_screen(self):
        f = tk.Frame(self, bg=BG())
        f.bind("<Motion>", self._reset_activity)

        # Header
        hdr = tk.Frame(f, bg=BG(), pady=16)
        hdr.pack(fill="x", padx=32)
        tk.Label(hdr, text="Password Vault", font=FONT_BIG,
                 bg=BG(), fg=TEXT()).pack(side="left")

        # Right-side controls
        ctrl = tk.Frame(hdr, bg=BG())
        ctrl.pack(side="right")

        # Auto-lock countdown label
        self._lock_lbl = tk.Label(ctrl, text="", bg=BG(), fg=TEXT_DIM(),
                                  font=("Segoe UI", 8))
        self._lock_lbl.pack(side="left", padx=(0, 12))
        self._tick_display()

        GhostBtn(ctrl, text="🔒 Lock", command=self._lock).pack(side="left", padx=(0, 8))
        PrimaryBtn(ctrl, text="+ Add", command=self._add_dialog).pack(side="left")

        # Toolbar: search + show/hide
        tb = tk.Frame(f, bg=BG())
        tb.pack(fill="x", padx=32, pady=(0, 10))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._on_search)
        StyledEntry(tb, textvariable=self._search_var).pack(
            side="left", fill="x", expand=True, ipady=7, padx=(0, 10))

        self._show_pw_var = tk.BooleanVar(value=False)
        tk.Checkbutton(tb, text="👁 Show passwords", variable=self._show_pw_var,
                       command=self._toggle_pw_visible,
                       bg=BG(), fg=TEXT_DIM(), selectcolor=BG3(),
                       activebackground=BG(), activeforeground=TEXT(),
                       font=("Segoe UI", 9)).pack(side="left")

        # Stats
        self._stats_lbl = tk.Label(f, text="", bg=BG(), fg=TEXT_DIM(), font=FONT_UI)
        self._stats_lbl.pack(anchor="w", padx=32, pady=(0, 8))

        # Table
        cols = ("site", "username", "password", "notes", "created")
        self._tree = ttk.Treeview(f, columns=cols, show="headings", selectmode="browse")
        headers = {"site": "Site / App", "username": "Username",
                   "password": "Password", "notes": "Notes", "created": "Saved"}
        widths   = {"site": 160, "username": 160, "password": 160, "notes": 120, "created": 130}
        for col in cols:
            self._tree.heading(col, text=headers[col])
            self._tree.column(col, width=widths[col], stretch=True)
        self._tree.bind("<Motion>", self._reset_activity)

        vsb = ttk.Scrollbar(f, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0, 8))
        self._tree.pack(fill="both", expand=True, padx=32, pady=(0, 8))

        # Action bar
        act = tk.Frame(f, bg=BG())
        act.pack(fill="x", padx=32, pady=(4, 16))

        # Clipboard clear countdown
        self._clip_lbl = tk.Label(act, text="", bg=BG(), fg=WARN(), font=("Segoe UI", 9))
        self._clip_lbl.pack(side="right", padx=(0, 8))

        GhostBtn(act, text="📋 Copy Password", command=self._copy_selected).pack(side="left", padx=(0, 8))
        GhostBtn(act, text="📜 History",       command=self._show_history).pack(side="left", padx=(0, 8))
        GhostBtn(act, text="🗑️ Delete",        command=self._delete_selected).pack(side="left")

        self._creds = []
        return f

    def _tick_display(self):
        """Update the auto-lock countdown in the header."""
        if self._fernet:
            remaining = AUTO_LOCK_SECONDS - int(time.time() - self._last_activity)
            remaining = max(0, remaining)
            mins, secs = divmod(remaining, 60)
            self._lock_lbl.config(text=f"🔒 auto-lock in {mins}:{secs:02d}")
        else:
            self._lock_lbl.config(text="")
        self.after(1000, self._tick_display)

    def _toggle_pw_visible(self):
        self._pw_visible = self._show_pw_var.get()
        self._render(self._creds)

    def _refresh(self):
        self._creds = get_all_credentials(self._fernet)
        self._render(self._creds)
        stats = get_vault_stats()
        self._stats_lbl.config(
            text=f"{stats['total_passwords']} password(s)  ·  {stats['unique_sites']} unique sites")

    def _render(self, creds):
        self._tree.delete(*self._tree.get_children())
        for c in creds:
            pw_display = c["password"] if self._pw_visible else "••••••••"
            self._tree.insert("", "end", iid=str(c["id"]),
                              values=(c["site"], c["username"],
                                      pw_display, c.get("notes", ""),
                                      c.get("created_at", "")))

    def _on_search(self, *_):
        q = self._search_var.get()
        results = search_credentials(self._fernet, q) if q else self._creds
        self._render(results)

    def _copy_selected(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Nothing selected", "Select a row first.", parent=self); return
        cred_id = int(sel[0])
        cred = next((c for c in self._creds if c["id"] == cred_id), None)
        if not cred: return
        self.clipboard_clear(); self.clipboard_append(cred["password"])

        # Cancel any previous clear job
        if self._clipboard_job:
            self.after_cancel(self._clipboard_job)

        # Schedule clipboard wipe
        self._start_clipboard_countdown(CLIPBOARD_CLEAR_S)

    def _start_clipboard_countdown(self, remaining):
        if remaining <= 0:
            try: self.clipboard_clear(); self.clipboard_append("")
            except Exception: pass
            self._clip_lbl.config(text="")
            self._clipboard_job = None
            return
        self._clip_lbl.config(text=f"Clipboard clears in {remaining}s")
        self._clipboard_job = self.after(1000, self._start_clipboard_countdown, remaining - 1)

    def _show_history(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Nothing selected", "Select a credential first.", parent=self); return
        cred_id = int(sel[0])
        cred = next((c for c in self._creds if c["id"] == cred_id), None)
        if not cred: return
        HistoryDialog(self, cred["site"], cred["username"])

    def _delete_selected(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Nothing selected", "Select a row first.", parent=self); return
        cred_id = int(sel[0])
        if messagebox.askyesno("Confirm Delete", f"Delete credential ID {cred_id}?", parent=self):
            delete_credential(cred_id)
            self._refresh()

    def _lock(self):
        self._fernet = None
        if self._clipboard_job:
            self.after_cancel(self._clipboard_job)
            try: self.clipboard_clear()
            except Exception: pass
            self._clip_lbl.config(text="")
        self._lock_screen.tkraise()

    def _add_dialog(self):
        dlg = AddCredentialDialog(self, self._fernet)
        self.wait_window(dlg)
        self._refresh()


# ── Add Credential Dialog ─────────────────────────────────────────────────────

class AddCredentialDialog(tk.Toplevel):
    def __init__(self, parent, fernet):
        super().__init__(parent, bg=BG())
        self.fernet = fernet
        self.title("Add Credential")
        self.geometry("440x460")
        self.resizable(False, False)
        self.grab_set()
        self._build()

    def _build(self):
        tk.Label(self, text="Add Credential", font=FONT_TITLE,
                 bg=BG(), fg=TEXT()).pack(anchor="w", padx=24, pady=(20, 4))
        tk.Label(self, text="All fields are encrypted in your vault",
                 bg=BG(), fg=TEXT_DIM(), font=FONT_UI).pack(anchor="w", padx=24, pady=(0, 16))

        self._fields = {}
        for label, key, secret in [
            ("Site / App",       "site",     False),
            ("Username / Email", "username", False),
            ("Password",         "password", True),
            ("Notes (optional)", "notes",    False),
        ]:
            tk.Label(self, text=label, bg=BG(), fg=TEXT_DIM(),
                     font=("Segoe UI", 9)).pack(anchor="w", padx=24)
            v = tk.StringVar()
            e = StyledEntry(self, textvariable=v, show="•" if secret else "")
            e.pack(fill="x", padx=24, pady=(2, 10), ipady=7)
            self._fields[key] = v
            if key == "password":
                self._pw_bar = StrengthBar(self)
                self._pw_bar.pack(fill="x", padx=24, pady=(0, 8))
                v.trace_add("write", self._pw_typed)

        row = tk.Frame(self, bg=BG())
        row.pack(fill="x", padx=24, pady=(8, 0))
        GhostBtn(row, text="Generate", command=self._gen).pack(side="left")
        GhostBtn(row, text="Cancel",   command=self.destroy).pack(side="right", padx=(8, 0))
        PrimaryBtn(row, text="Save",   command=self._save).pack(side="right")

    def _pw_typed(self, *_):
        pw = self._fields["password"].get()
        if pw and MODULES_OK:
            try: self._pw_bar.set(score_password(pw)["score"])
            except Exception: pass

    def _gen(self):
        self._fields["password"].set(generate_password(length=20))

    def _save(self):
        site  = self._fields["site"].get()
        user  = self._fields["username"].get()
        pw    = self._fields["password"].get()
        notes = self._fields["notes"].get()
        if not site or not user or not pw:
            messagebox.showwarning("Missing fields",
                "Site, username, and password are required.", parent=self); return
        if add_credential(self.fernet, site, user, pw, notes):
            record_history(site, user, "Password created")
            self.destroy()
        else:
            messagebox.showerror("Error", "Failed to save credential.", parent=self)


# ── History Dialog (per credential) ──────────────────────────────────────────

class HistoryDialog(tk.Toplevel):
    def __init__(self, parent, site, username):
        super().__init__(parent, bg=BG())
        self.title(f"History — {site}")
        self.geometry("480x360")
        self.resizable(False, False)
        self.grab_set()
        self._build(site, username)

    def _build(self, site, username):
        tk.Label(self, text=f"📜  Change History", font=FONT_TITLE,
                 bg=BG(), fg=TEXT()).pack(anchor="w", padx=24, pady=(20, 2))
        tk.Label(self, text=f"{site}  ·  {username}",
                 bg=BG(), fg=TEXT_DIM(), font=FONT_UI).pack(anchor="w", padx=24, pady=(0, 16))

        entries = get_history(site, username)

        if not entries:
            tk.Label(self, text="No history recorded yet.\nHistory is recorded each time you add or update a credential.",
                     bg=BG(), fg=TEXT_DIM(), font=FONT_UI, justify="left").pack(padx=24, anchor="w")
        else:
            frame = tk.Frame(self, bg=BG())
            frame.pack(fill="both", expand=True, padx=24, pady=(0, 16))
            for entry in reversed(entries):
                row = tk.Frame(frame, bg=BG2(), highlightthickness=1,
                               highlightbackground=BORDER())
                row.pack(fill="x", pady=3)
                tk.Label(row, text=entry["ts"], bg=BG2(), fg=ACCENT(),
                         font=("Consolas", 9), padx=12, pady=8).pack(side="left")
                tk.Label(row, text=entry["note"], bg=BG2(), fg=TEXT(),
                         font=FONT_UI, padx=8).pack(side="left")

        GhostBtn(self, text="Close", command=self.destroy).pack(pady=(0, 20))


# ── Global History Page ───────────────────────────────────────────────────────

class HistoryPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG())
        self.app = app
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=BG(), pady=20)
        hdr.pack(fill="x", padx=32)
        tk.Label(hdr, text="Password History", font=FONT_BIG,
                 bg=BG(), fg=TEXT()).pack(anchor="w")
        tk.Label(hdr, text="A timestamped log of every password save/update",
                 bg=BG(), fg=TEXT_DIM(), font=FONT_UI).pack(anchor="w")

        act = tk.Frame(hdr, bg=BG())
        act.pack(anchor="e", side="right")
        GhostBtn(act, text="🔄 Refresh", command=self.refresh).pack(side="left", padx=(0, 8))
        GhostBtn(act, text="🗑️ Clear All", command=self._clear).pack(side="left")

        self._body = tk.Frame(self, bg=BG())
        self._body.pack(fill="both", expand=True, padx=32, pady=(0, 16))
        self.refresh()

    def refresh(self):
        for w in self._body.winfo_children(): w.destroy()
        h = _load_history()
        if not h:
            tk.Label(self._body,
                     text="No history yet.\nHistory is recorded when you add credentials via the Vault tab.",
                     bg=BG(), fg=TEXT_DIM(), font=FONT_UI, justify="left").pack(anchor="w", pady=20)
            return

        canvas = tk.Canvas(self._body, bg=BG(), highlightthickness=0)
        vsb = ttk.Scrollbar(self._body, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG())
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(window, width=canvas.winfo_width())
        inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(window, width=e.width))

        for key, entries in sorted(h.items(), key=lambda x: x[0]):
            site, user = (key.split("|", 1) + [""])[:2]
            sec = tk.Frame(inner, bg=BG2(), highlightthickness=1,
                           highlightbackground=BORDER())
            sec.pack(fill="x", pady=(0, 10))
            tk.Label(sec, text=f"  {site}  ·  {user}", bg=BG2(), fg=TEXT(),
                     font=("Segoe UI Semibold", 11), pady=8).pack(anchor="w")
            for entry in reversed(entries):
                row = tk.Frame(sec, bg=BG3())
                row.pack(fill="x", padx=12, pady=2)
                tk.Label(row, text=entry["ts"], bg=BG3(), fg=ACCENT(),
                         font=("Consolas", 9), padx=10, pady=6).pack(side="left")
                tk.Label(row, text=entry.get("note", ""), bg=BG3(), fg=TEXT_DIM(),
                         font=FONT_UI).pack(side="left", padx=8)
            tk.Frame(sec, bg=BG2(), height=6).pack()

    def _clear(self):
        if messagebox.askyesno("Clear History",
                "Delete all password history?\nThis does not affect your vault.", parent=self):
            _save_history({})
            self.refresh()


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
