from __future__ import annotations

import collections
import ctypes
import hashlib
import json
import math
import os
import queue
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

IS_WIN = os.name == "nt"
NOWIN = 0x08000000 if IS_WIN else 0
try:
    import winreg  # type: ignore
except ImportError:
    winreg = None
try:
    from PIL import Image, ImageDraw, ImageFilter, ImageTk  # type: ignore
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ───────────────────────────── Палітра ─────────────────────────────
BG, SIDEBAR = "#120a26", "#0a0519"
CARD, CARD2 = "#1d1140", "#2a1a57"
TEXT, MUTED = "#f1ecff", "#9c8fc2"
ACCENT, ACCENT_H, ON_ACCENT = "#b05cff", "#cf8dff", "#1a0633"
GLOW1, GLOW2 = "#7b2ff7", "#ff5cc8"
BLUE, BLUE_L = "#8a5cff", "#b89bff"
OK = "#34e0a1"
WARN, DANGER = "#ffc247", "#ff5d6c"
FONT = "Segoe UI"

DATA = (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "UAShield") if IS_WIN else Path.home() / ".ua_shield"
QDIR = DATA / "Quarantine"
for _d in (DATA, QDIR):
    _d.mkdir(parents=True, exist_ok=True)

# Тестовий рядок EICAR (безпечний; стандартний тест антивірусів). Збираємо з частин,
# щоб сам файл програми не спрацьовував як «вірус».
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*").encode()

BUILTIN_SIGS = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
}

SCAN_EXTS = set("exe dll scr sys com pif msi msp bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta jar lnk cpl reg "
                "docm xlsm pptm dotm xlam doc xls ppt rtf inf".split())
SCRIPT_EXTS = set("ps1 psm1 vbs vbe js jse wsf wsh hta bat cmd".split())
DOC_EXTS = set("jpg jpeg png gif bmp pdf txt doc docx xls xlsx ppt pptx mp3 mp4 avi mkv zip rar".split())
MAX_SIZE = 150 * 1024 * 1024

SCRIPT_PATTERNS = [(re.compile(p, re.I), w, d) for p, w, d in [
    (r"frombase64string", 20, "декодування Base64"),
    (r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", 40, "закодована команда PowerShell"),
    (r"downloadstring|downloadfile|invoke-webrequest|net\.webclient|urldownloadtofile|msxml2\.xmlhttp", 20,
     "завантаження файлів із мережі"),
    (r"\biex\b|invoke-expression", 25, "виконання динамічного коду (IEX)"),
    (r"-w(indowstyle)?\s+hidden|\s-nop\b|\s-noni\b", 15, "прихований запуск PowerShell"),
    (r"certutil[^\n]*-urlcache|bitsadmin[^\n]*/transfer", 40, "завантаження системними утилітами"),
    (r"regsvr32[^\n]*scrobj|mshta\s+(http|vbscript|javascript)", 40, "запуск віддаленого скрипта"),
    (r"string\.fromcharcode|eval\s*\(\s*unescape|chr\(\s*\d+\s*\)\s*&\s*chr", 25, "обфускація коду"),
    (r"vssadmin[^\n]*delete\s+shadows|wbadmin\s+delete|bcdedit[^\n]*recoveryenabled\s+no", 70,
     "видалення резервних копій (ознака шифрувальника)"),
    (r"disableantispyware|set-mppreference[^\n]*-disable", 50, "спроба вимкнути антивірус"),
]]
FAKE_DOC = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\s*\.(exe|scr|com|bat|cmd|pif|vbs|js|jse|hta|lnk)$", re.I)
RISKY_PARTS = ("\\temp\\", "\\downloads\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\", "$recycle.bin",
               "/tmp/", "/downloads/")
API_HITS = [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"SetWindowsHookEx",
            b"GetAsyncKeyState", b"NtUnmapViewOfSection", b"URLDownloadToFile"]
SYS_PROCS = {"svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe", "services.exe",
             "smss.exe", "wininit.exe", "taskhostw.exe", "spoolsv.exe"}


# ───────────────────────────── Утиліти ─────────────────────────────
def fmt_size(n: float) -> str:
    n = float(n)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or u == "ТБ":
            return f"{int(n)} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024
    return "0 Б"


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M") if ts else "ніколи"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WIN else os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if not IS_WIN:
        return False
    exe = sys.executable
    if getattr(sys, "frozen", False):
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        if exe.lower().endswith("python.exe") and os.path.exists(exe[:-10] + "pythonw.exe"):
            exe = exe[:-10] + "pythonw.exe"
        params = " ".join(f'"{a}"' for a in sys.argv)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32


TRANSPARENT_KEY = "#0a0014"  # «магічний» колір-ключ: усі пікселі саме цього кольору стають наскрізь прозорими


def enable_glass(root) -> str:
    """Вмикає напівпрозоре/«скляне» вікно. Повертає 'acrylic' (справжній розмитий Windows-блюр
    крізь вікно — тоді елементи з bg=TRANSPARENT_KEY стають прозорими), 'alpha' (просте
    приглушення прозорості всього вікна, якщо acrylic недоступний) або '' (не вдалося жодного)."""
    if IS_WIN:
        try:
            class ACCENT(ctypes.Structure):
                _fields_ = [("AccentState", ctypes.c_int), ("AccentFlags", ctypes.c_int),
                           ("GradientColor", ctypes.c_int), ("AnimationId", ctypes.c_int)]

            class WCAD(ctypes.Structure):
                _fields_ = [("Attribute", ctypes.c_int), ("Data", ctypes.POINTER(ACCENT)),
                           ("SizeOfData", ctypes.c_size_t)]
            root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            tint = hex_rgb(BG)
            abgr = (210 << 24) | (tint[2] << 16) | (tint[1] << 8) | tint[0]
            accent = ACCENT(AccentState=4, AccentFlags=2, GradientColor=ctypes.c_int(abgr).value, AnimationId=0)
            data = WCAD(Attribute=19, Data=ctypes.pointer(accent), SizeOfData=ctypes.sizeof(accent))
            res = ctypes.windll.user32.SetWindowCompositionAttribute(hwnd, ctypes.pointer(data))
            if res:
                root.attributes("-transparentcolor", TRANSPARENT_KEY)
                return "acrylic"
        except Exception:
            pass
    try:
        root.attributes("-alpha", 0.95)
        return "alpha"
    except Exception:
        return ""


def ps(cmd: str, timeout: int | None = 120) -> str:
    if not IS_WIN:
        return ""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd],
                           capture_output=True, timeout=timeout, creationflags=NOWIN)
        return r.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def ps_json(cmd: str, timeout: int | None = 120) -> list[dict]:
    out = ps(cmd + " | ConvertTo-Json -Compress -Depth 3", timeout)
    try:
        data = json.loads(out) if out else []
    except ValueError:
        return []
    return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])


def open_in_folder(path: str):
    try:
        if IS_WIN:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path)])
    except Exception:
        pass


def in_risky(path: str) -> bool:
    p = path.lower().replace("/", "\\") if IS_WIN else path.lower()
    return any(x in p for x in RISKY_PARTS)


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


def walk_files(root: str, stop: threading.Event, max_depth: int | None = None):
    skip_tail = ("\\winsxs",) if IS_WIN else ()
    skip_pref = () if IS_WIN else ("/proc", "/sys", "/dev", "/run")
    qd = str(QDIR).lower()
    stack = [(root, 0)]
    while stack and not stop.is_set():
        d, depth = stack.pop()
        dl = d.lower()
        if dl.startswith(qd) or dl.endswith(skip_tail) or (skip_pref and dl.startswith(skip_pref)):
            continue
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if max_depth is None or depth < max_depth:
                                stack.append((e.path, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            yield e.path
                    except OSError:
                        pass
        except OSError:
            pass


# ───────────────────────────── Налаштування та журнал ─────────────────────────────
DEFAULTS = dict(sens=1, auto_q=True, realtime=False, all_types=False, exclusions=[],
                last_scan=0, scans=0, files_total=0, last_threats=0)


class Store:
    def __init__(self):
        self.path = DATA / "settings.json"
        self.d = dict(DEFAULTS)
        try:
            self.d.update(json.loads(self.path.read_text("utf-8")))
        except (OSError, ValueError):
            pass

    def __getitem__(self, k):
        return self.d[k]

    def __setitem__(self, k, v):
        self.d[k] = v
        self.save()

    def save(self):
        try:
            self.path.write_text(json.dumps(self.d, ensure_ascii=False, indent=1), "utf-8")
        except OSError:
            pass


LOG_FILE = DATA / "log.txt"
LOG_HOOK = None


def log(msg: str):
    line = f"[{datetime.now():%d.%m.%Y %H:%M:%S}] {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    if LOG_HOOK:
        LOG_HOOK(line)


# ───────────────────────────── Рушій сканування ─────────────────────────────
@dataclass
class Detection:
    path: str
    name: str
    level: str      # high / medium / low
    reason: str
    sha256: str = ""
    score: int = 0


LEVEL_UA = {"high": "Висока", "medium": "Середня", "low": "Низька"}


class Engine:
    def __init__(self, store: Store):
        self.store = store
        self.sigs: dict[str, str] = {}
        self.cache: dict[str, int] = {}
        self.sig_file = DATA / "signatures.txt"
        self.cache_file = DATA / "clean_cache.json"
        self.load_sigs()
        try:
            self.cache = json.loads(self.cache_file.read_text("utf-8"))
        except (OSError, ValueError):
            pass

    # --- бази
    def load_sigs(self):
        self.sigs = dict(BUILTIN_SIGS)
        try:
            for line in self.sig_file.read_text("utf-8", "ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"[\s,;]+", line, 1)
                h = parts[0].strip('"\'').lower()
                if len(h) in (32, 64) and re.fullmatch(r"[0-9a-f]+", h):
                    self.sigs[h] = (parts[1].strip('"\' ') if len(parts) > 1 and parts[1].strip() else
                                    "Відома загроза (імпортована база)")
        except OSError:
            pass

    def import_sigs(self, file: str) -> int:
        before = len(self.sigs)
        text = Path(file).read_text("utf-8", "ignore")
        with open(self.sig_file, "a", encoding="utf-8") as f:
            f.write("\n" + text + "\n")
        self.load_sigs()
        return len(self.sigs) - before

    def reset_sigs(self):
        try:
            self.sig_file.unlink()
        except OSError:
            pass
        self.load_sigs()

    def save_cache(self):
        if len(self.cache) > 400000:
            self.cache.clear()
        try:
            self.cache_file.write_text(json.dumps(self.cache), "utf-8")
        except OSError:
            pass

    # --- перевірка
    @property
    def min_score(self) -> int:
        return {0: 70, 1: 45, 2: 30}.get(self.store["sens"], 45)

    def excluded(self, low: str) -> bool:
        return any(low.startswith(x.lower()) for x in self.store["exclusions"])

    def scan_file(self, path: str, deep: bool = False) -> Detection | None:
        low = path.lower()
        if self.excluded(low) or low.startswith(str(QDIR).lower()):
            return None
        try:
            st = os.stat(path)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
            return None
        size = st.st_size
        key = f"{path}|{size}|{int(st.st_mtime)}|{self.min_score}"
        if key in self.cache:
            return None

        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower().lstrip(".")
        risky = in_risky(path)
        score, reasons, threat, sha = 0, [], None, ""

        def add(points, why):
            nonlocal score
            score += points
            reasons.append(why)

        # 1) евристика за назвою
        if FAKE_DOC.search(name):
            add(80, "подвійне розширення (файл маскується під документ)")
        if "\u202e" in name:
            add(90, "у назві є символ зворотного напрямку тексту (підміна розширення)")
        if re.search(r"\s{6,}\.[a-z]{2,4}$", name, re.I):
            add(60, "назва заповнена пробілами, щоб приховати розширення")

        candidate = deep or ext in SCAN_EXTS or size <= 256 or score > 0
        if not candidate and ext in DOC_EXTS and (risky or deep):
            try:
                with open(path, "rb") as f:
                    if f.read(2) == b"MZ":
                        add(60, "виконуваний код під виглядом документа")
                        candidate = True
            except OSError:
                pass

        if candidate and size <= MAX_SIZE:
            try:
                sha, md5, buf = self._read(path)
            except OSError:
                return None
            # 2) сигнатури
            hit = self.sigs.get(sha) or self.sigs.get(md5)
            if hit:
                threat, score = hit, 100
                reasons.insert(0, "збіг із базою сигнатур")
            elif size <= 200 and buf.strip().startswith(EICAR):
                threat, score = "EICAR-Test-File", 100
                reasons.insert(0, "тестовий файл EICAR (безпечний)")
            else:
                if ext in SCRIPT_EXTS:
                    s, r = self._script(buf, ext)
                    if s:
                        add(s, "; ".join(r))
                if buf[:2] == b"MZ":
                    self._pe(buf, ext, risky, add)
                if ext in ("docm", "xlsm", "pptm", "dotm", "xlam"):
                    try:
                        with zipfile.ZipFile(path) as z:
                            if any(n.lower().endswith("vbaproject.bin") for n in z.namelist()):
                                add(35, "документ містить макроси VBA")
                    except (OSError, zipfile.BadZipFile):
                        pass
                elif ext in ("doc", "xls", "ppt") and buf[:4] == b"\xd0\xcf\x11\xe0":
                    if re.search(rb"Auto_?Open|AutoExec|Document_Open|Workbook_Open", buf):
                        add(35, "автозапуск макросу в документі")
                        if re.search(rb"(?i)powershell|cmd\.exe|wscript|mshta", buf):
                            add(30, "макрос запускає системні команди")
                elif ext == "lnk":
                    t = buf.replace(b"\x00", b"").lower()
                    if b"powershell" in t or b"cmd.exe" in t or b"mshta" in t:
                        add(30, "ярлик запускає командний рядок")
                        if re.search(rb"-enc|http|iex|bypass|-w hidden|/c ", t):
                            add(35, "ярлик містить ознаки завантажувача")
                elif ext == "inf" and name.lower() == "autorun.inf":
                    if re.search(rb"(?i)open\s*=|shellexecute", buf):
                        add(50, "autorun.inf автоматично запускає програму")

        if threat or score >= self.min_score:
            lvl = "high" if score >= 70 else "medium" if score >= 45 else "low"
            return Detection(path, threat or "Підозрілий файл (евристика)", lvl,
                             "; ".join(reasons) or "підозрілі ознаки", sha, min(score, 100))
        self.cache[key] = 1
        return None

    @staticmethod
    def _read(path, keep=2 * 1024 * 1024):
        s, m, buf = hashlib.sha256(), hashlib.md5(), bytearray()
        with open(path, "rb") as f:
            while True:
                c = f.read(1 << 20)
                if not c:
                    break
                s.update(c)
                m.update(c)
                if len(buf) < keep:
                    buf += c[: keep - len(buf)]
        return s.hexdigest(), m.hexdigest(), bytes(buf)

    @staticmethod
    def _script(buf: bytes, ext: str):
        if buf[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = buf.decode("utf-16", "ignore")
        else:
            text = buf.decode("utf-8", "ignore")
        score, why = 0, []
        for rx, w, d in SCRIPT_PATTERNS:
            if rx.search(text):
                score += w
                why.append(d)
        if ext in ("ps1", "vbs", "bat", "cmd", "hta") and max((len(l) for l in text.splitlines()), default=0) > 8000:
            score += 20
            why.append("дуже довгий рядок коду (обфускація)")
        return score, why

    @staticmethod
    def _pe(buf, ext, risky, add):
        if risky and ext in ("exe", "scr", "dll", "com", "pif"):
            if entropy(buf[:262144]) > 7.4:
                add(20, "висока ентропія (ймовірно запакований файл)")
        hits = [a.decode() for a in API_HITS if a in buf]
        if len(hits) >= 3:
            add(min(45, 15 * len(hits)) if risky else 15 * (len(hits) // 2),
                "імпортує «агресивні» функції: " + ", ".join(hits[:3]))
        if risky and ext in ("exe", "scr", "com", "pif"):
            add(10, "виконуваний файл у папці користувача/тимчасовій папці")


# ───────────────────────────── Карантин ─────────────────────────────
_XOR = bytes(i ^ 0x5A for i in range(256))


class Quarantine:
    def __init__(self):
        self.idx = DATA / "quarantine.json"
        try:
            self.items: dict = json.loads(self.idx.read_text("utf-8"))
        except (OSError, ValueError):
            self.items = {}

    def _save(self):
        self.idx.write_text(json.dumps(self.items, ensure_ascii=False, indent=1), "utf-8")

    def add(self, det: Detection) -> tuple[bool, str]:
        qid = uuid.uuid4().hex
        dst = QDIR / (qid + ".quar")
        try:
            size = os.path.getsize(det.path)
            with open(det.path, "rb") as f, open(dst, "wb") as o:
                for c in iter(lambda: f.read(1 << 20), b""):
                    o.write(c.translate(_XOR))
            try:
                os.remove(det.path)
            except PermissionError:
                os.chmod(det.path, stat.S_IWRITE)
                os.remove(det.path)
        except OSError as e:
            try:
                dst.unlink()
            except OSError:
                pass
            return False, str(e)
        self.items[qid] = dict(path=det.path, name=det.name, size=size, ts=time.time(), sha=det.sha256)
        self._save()
        log(f"Карантин: {det.path} → {det.name}")
        return True, ""

    def restore(self, qid: str) -> tuple[bool, str]:
        meta = self.items.get(qid)
        if not meta:
            return False, "запис не знайдено"
        dest = meta["path"]
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.exists(dest):
                dest += ".restored"
            with open(QDIR / (qid + ".quar"), "rb") as f, open(dest, "wb") as o:
                for c in iter(lambda: f.read(1 << 20), b""):
                    o.write(c.translate(_XOR))
        except OSError as e:
            return False, str(e)
        self.delete(qid, quiet=True)
        log(f"Відновлено з карантину: {dest}")
        return True, dest

    def delete(self, qid: str, quiet=False):
        try:
            (QDIR / (qid + ".quar")).unlink()
        except OSError:
            pass
        if self.items.pop(qid, None) is not None:
            self._save()
            if not quiet:
                log(f"Остаточно видалено з карантину: {qid[:8]}")


# ───────────────────────────── Мішені сканування ─────────────────────────────
def quick_targets() -> list[tuple[str, int | None]]:
    e, h = os.environ.get, Path.home()
    t: list[tuple[str, int | None]] = [(str(h / "Downloads"), None), (str(h / "Desktop"), None),
                                       (tempfile.gettempdir(), 4)]
    if IS_WIN:
        ap, pd = e("APPDATA", ""), e("PROGRAMDATA", "")
        t += [(ap, 2), (pd, 2), (r"C:\Users\Public", 3), (e("LOCALAPPDATA", "") + r"\Temp", 4),
              (os.path.join(ap, r"Microsoft\Windows\Start Menu\Programs\Startup"), None),
              (os.path.join(pd, r"Microsoft\Windows\Start Menu\Programs\StartUp"), None)]
    seen, out = set(), []
    for p, d in t:
        if p and os.path.isdir(p) and p.lower() not in seen:
            seen.add(p.lower())
            out.append((p, d))
    return out


def list_drives() -> list[str]:
    if not IS_WIN:
        return ["/"]
    res, mask = [], ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if mask >> i & 1 and ctypes.windll.kernel32.GetDriveTypeW(f"{chr(65 + i)}:\\") == 3:
            res.append(f"{chr(65 + i)}:\\")
    return res


def process_list() -> list[dict]:
    rows = ps_json("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath", 60)
    out = []
    for r in rows:
        name, path = str(r.get("Name") or ""), str(r.get("ExecutablePath") or "")
        risk = ""
        pl = path.lower()
        if path:
            if name.lower() in SYS_PROCS and not (pl.startswith(os.environ.get("WINDIR", r"c:\windows").lower())):
                risk = "Маскування під системний процес"
            elif in_risky(path) and "\\microsoft\\" not in pl and "\\programdata\\" not in pl.replace("\\windowsapps", ""):
                risk = "Запущено з тимчасової папки / Завантажень"
        out.append(dict(pid=r.get("ProcessId"), name=name, path=path, risk=risk))
    return out


# ───────────────────────────── Захист у реальному часі ─────────────────────────────
class Monitor(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.app, self.halt = app, threading.Event()

    def run(self):
        h = Path.home()
        dirs = [str(h / "Downloads"), str(h / "Desktop"), tempfile.gettempdir()]
        seen: dict[str, tuple] = {}
        first = True
        while not self.halt.is_set():
            fresh = []
            for d in dirs:
                if not os.path.isdir(d):
                    continue
                for i, p in enumerate(walk_files(d, self.halt, 3)):
                    if i > 20000:
                        break
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    sig = (st.st_mtime, st.st_size)
                    if seen.get(p) != sig:
                        seen[p] = sig
                        if not first and not p.lower().endswith((".crdownload", ".part", ".tmp", ".download")):
                            fresh.append(p)
            first = False
            for p in fresh:
                if self.halt.wait(0.6):
                    return
                det = self.app.engine.scan_file(p)
                if det:
                    self.app.ui(self.app.on_realtime_hit, det)
            self.halt.wait(4)


# ───────────────────────────── Перевірки безпеки системи ─────────────────────────────
HOSTS = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), r"System32\drivers\etc\hosts")
HOSTS_DEFAULT = ("# Файл hosts відновлено UA Shield\r\n127.0.0.1       localhost\r\n::1             localhost\r\n")


def hosts_suspicious() -> list[str]:
    bad = []
    try:
        for line in Path(HOSTS).read_text("utf-8", "ignore").splitlines():
            s = line.split("#")[0].strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) >= 2 and parts[0] not in ("127.0.0.1", "0.0.0.0", "::1", "::"):
                bad.append(s)
    except OSError:
        pass
    return bad


def fix_hosts():
    bak = HOSTS + ".bak_" + datetime.now().strftime("%Y%m%d%H%M")
    try:
        if os.path.exists(HOSTS):
            os.replace(HOSTS, bak)
        Path(HOSTS).write_text(HOSTS_DEFAULT, "utf-8")
        return True
    except OSError:
        return False


def reg_get(root, path, name):
    try:
        with winreg.OpenKey(root, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def fix_rdp():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
        return True
    except OSError:
        return False


def suspicious_startup() -> list[str]:
    res = []
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    rx = re.compile(r"\\temp\\|\\downloads\\|\\users\\public\\|powershell[^\n]*-e(nc)?\s|mshta|wscript|cscript|\.vbs|\.js\b", re.I)
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(root, run) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if rx.search(str(v)):
                        res.append(f"{n}: {v}")
        except OSError:
            pass
    return res


def run_checks() -> list[dict]:
    res: list[dict] = []

    def add(title, level, detail, fix=None):
        res.append(dict(title=title, level=level, detail=detail, fix=fix))

    if not IS_WIN or not winreg:
        add("Перевірка системи", "warn", "Повний набір перевірок доступний лише у Windows")
        return res
    st = (ps_json("Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,"
                  "@{n='SigDate';e={$_.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')}}", 60) or [{}])[0]
    if not st:
        add("Microsoft Defender", "warn", "Не вдалося отримати стан (можливо, встановлено інший антивірус)")
    else:
        rt = str(st.get("RealTimeProtectionEnabled")).lower() == "true"
        add("Захист у реальному часі (Defender)", "ok" if rt else "bad",
            "Увімкнено" if rt else "Вимкнено — комп'ютер вразливий",
            None if rt else lambda: ps("Set-MpPreference -DisableRealtimeMonitoring $false") == "" or True)
        try:
            age = (datetime.now() - datetime.strptime(st.get("SigDate", ""), "%Y-%m-%d %H:%M")).days
            add("Бази сигнатур Defender", "ok" if age <= 3 else "warn", f"Оновлено {age} дн. тому ({st.get('SigDate')})",
                None if age <= 3 else lambda: ps("Update-MpSignature", 300) or True)
        except ValueError:
            pass
    fw = ps_json("Get-NetFirewallProfile | Select-Object Name,Enabled", 30)
    if fw:
        off = [str(p.get("Name")) for p in fw if str(p.get("Enabled")).lower() not in ("true", "1")]
        add("Брандмауер Windows", "ok" if not off else "bad",
            "Увімкнено для всіх профілів" if not off else "Вимкнено для: " + ", ".join(off),
            None if not off else lambda: ps("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True") == "" or True)
    uac = reg_get(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    add("Контроль облікових записів (UAC)", "ok" if uac != 0 else "bad",
        "Увімкнено" if uac != 0 else "Вимкнено — програми можуть змінювати систему без запиту")
    rdp = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    add("Віддалений робочий стіл (RDP)", "ok" if rdp != 0 else "warn",
        "Вимкнено" if rdp != 0 else "Увімкнено — вимкніть, якщо не користуєтесь",
        None if rdp != 0 else fix_rdp)
    hs = hosts_suspicious()
    add("Файл hosts", "ok" if not hs else "bad",
        "Підозрілих перенаправлень немає" if not hs else f"Перенаправлень: {len(hs)} (напр. {hs[0][:60]})", None if not hs else fix_hosts)
    su = suspicious_startup()
    add("Підозрілий автозапуск", "ok" if not su else "warn",
        "Не виявлено" if not su else f"{len(su)} запис(ів): {su[0][:70]}")
    return res


# ───────────────────────────── Віджети ─────────────────────────────
class Btn(tk.Label):
    STYLES = {"primary": (ACCENT, ACCENT_H, ON_ACCENT), "ghost": (CARD2, "#24475f", TEXT),
              "danger": (DANGER, "#ff8591", "#2b0a0f"), "warn": (WARN, "#ffd98a", "#2b2105")}

    def __init__(self, master, text, command=None, style="primary", **kw):
        self._bg, self._hv, self._fg = self.STYLES[style]
        super().__init__(master, text=text, bg=self._bg, fg=self._fg, font=(FONT, 10, "bold"),
                         padx=18, pady=9, cursor="hand2", **kw)
        self._cmd, self._on = command, True
        self.bind("<Enter>", lambda e: self._on and self.config(bg=self._hv))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg if self._on else CARD2))
        self.bind("<Button-1>", self._press)
        self.bind("<ButtonRelease-1>", self._release)

    def _press(self, e):
        if self._on:
            self.config(bg=_mix(self._bg, "#000000", .22))

    def _release(self, e):
        if not self._on:
            return
        inside = 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height()
        self.config(bg=self._hv if inside else self._bg)
        if inside and self._cmd:
            self._cmd()

    def enable(self, v: bool):
        self._on = v
        self.config(bg=self._bg if v else CARD2, fg=self._fg if v else MUTED, cursor="hand2" if v else "arrow")

    def set_text(self, t):
        self.config(text=t)


class Card(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=CARD, **kw)


def lbl(parent, text, fg=TEXT, size=10, bold=False, **kw):
    return tk.Label(parent, text=text, fg=fg, bg=parent.cget("bg"), font=(FONT, size, "bold" if bold else "normal"), **kw)


class ScrollFrame(tk.Frame):
    def __init__(self, master, bg=BG):
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.win, width=e.width))
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")


def _mix(c1: str, c2: str, t: float) -> str:
    c1, c2 = c1.lstrip("#"), c2.lstrip("#")
    r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
    r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
    return f"#{int(r1 + (r2 - r1) * t):02x}{int(g1 + (g2 - g1) * t):02x}{int(b1 + (b2 - b1) * t):02x}"


def hex_rgb(c: str) -> tuple:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def round_pts(x0, y0, x1, y1, r):
    r = max(0, min(r, (x1 - x0) / 2, (y1 - y0) / 2))
    return [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1, x1 - r, y1, x0 + r, y1,
            x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]


def round_rect(canvas, x0, y0, x1, y1, r, **kw):
    return canvas.create_polygon(round_pts(x0, y0, x1, y1, r), smooth=True, **kw)


DIAL_COLORS = {"ok": (GLOW1, GLOW2), "warn": (WARN, "#ffdf8a"), "bad": (DANGER, "#ff95a1")}


def draw_shield_icon(canvas, cx, cy, r, glow, state):
    """Іконка щита (з галочкою чи знаком оклику) прямо на переданому canvas."""
    w, h = r * 1.86, r * 2.0
    x0, y0 = cx - w / 2, cy - h / 2
    pf = [.5, .0, .92, .16, .92, .54, .5, 1.0, .08, .54, .08, .16]
    pts = []
    for i in range(0, len(pf), 2):
        pts += [x0 + pf[i] * w, y0 + pf[i + 1] * h]
    canvas.create_polygon(pts, smooth=True, fill=TEXT, outline=_mix(glow, TEXT, .5), width=1)
    mark = CARD2
    if state == "ok":
        canvas.create_line(cx - r * .32, cy + .02 * h, cx - r * .06, cy + r * .34, cx + r * .36, cy - r * .32,
                           fill=mark, width=max(2, int(r * .22)), capstyle="round", joinstyle="round")
    else:
        canvas.create_line(cx, cy - r * .42, cx, cy + r * .12, fill=mark, width=max(2, int(r * .24)), capstyle="round")
        canvas.create_oval(cx - r * .055, cy + r * .40, cx + r * .055, cy + r * .51, fill=mark, outline="")


def draw_power_ring(canvas, cx, cy, s, state, label="", hov=False):
    """Малює градієнтне кільце-індикатор зі щитом прямо на canvas (без власного фону —
    картинка-підложка з розмитим сяйвом малюється окремо, щоб диск «плавав» без шва
    навколо себе). Повертає радіус кільця (для перевірки кліку/наведення)."""
    c1, c2 = DIAL_COLORS.get(state, DIAL_COLORS["ok"])
    n, R = 130, s * .345 * (1.03 if hov else 1.0)
    for i in range(n):
        t = i / n
        col = _mix(c2, c1, t)
        canvas.create_arc(cx - R, cy - R, cx + R, cy + R, start=360 * t, extent=360 / n + 1.3,
                          style="pieslice", fill=col, outline=col)
    ri = R - s * .085
    canvas.create_oval(cx - ri, cy - ri, cx + ri, cy + ri, fill=_mix(CARD2, c1, .08 if hov else 0), outline="")
    canvas.create_oval(cx - ri, cy - ri, cx + ri, cy + ri, outline=_mix(c1, CARD2, .4), width=1)
    draw_shield_icon(canvas, cx, cy - s * .035, s * .165, c1, state)
    if label:
        canvas.create_text(cx, cy + s * .165, text=label.upper(), fill=MUTED, font=(FONT, int(s * .058), "bold"))
    return R


def dashboard_bg_image(w, h, dcx, dcy, s, state):
    """Фонове зображення сторінки «Захист»: слабке розсіяне тло на всю ширину
    + помітніше сяйво безпосередньо під диском — усе одним склеєним шаром блюру,
    тому диск і бейджі «плавають» на градієнті без прямокутного контуру навколо."""
    base = Image.new("RGB", (w, h), hex_rgb(BG))
    wash = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dr = ImageDraw.Draw(wash)
    dr.ellipse((-w * .15, -h * .55, w * .55, h * .55), fill=hex_rgb(GLOW1) + (60,))
    dr.ellipse((w * .5, -h * .55, w * 1.15, h * .55), fill=hex_rgb(GLOW2) + (46,))
    wash = wash.filter(ImageFilter.GaussianBlur(radius=min(w, h) * .32))
    base.paste(wash, (0, 0), wash)
    c1, c2 = DIAL_COLORS.get(state, DIAL_COLORS["ok"])
    local = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dr2 = ImageDraw.Draw(local)
    x0, y0 = dcx - s, dcy - s
    dr2.ellipse((x0, y0, x0 + 2 * s, y0 + 2 * s), fill=hex_rgb(c1) + (190,))
    dr2.ellipse((x0 + s * .25, y0 - s * .05, x0 + s * 1.75, y0 + s * 1.05), fill=hex_rgb(c2) + (120,))
    local = local.filter(ImageFilter.GaussianBlur(radius=s * .17))
    out = Image.alpha_composite(base.convert("RGBA"), local)
    return out.convert("RGB")


def setup_style(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT, borderwidth=0, rowheight=30, font=(FONT, 10))
    s.configure("Treeview.Heading", background=CARD2, foreground=MUTED, relief="flat", font=(FONT, 9, "bold"), padding=(8, 7))
    s.map("Treeview", background=[("selected", BLUE)], foreground=[("selected", "#ffffff")])
    s.map("Treeview.Heading", background=[("active", "#24475f")])
    s.configure("Vertical.TScrollbar", background=CARD2, troughcolor=CARD, bordercolor=CARD, arrowcolor=MUTED, relief="flat")
    s.map("Vertical.TScrollbar", background=[("active", "#3a6a8c")])
    s.configure("Accent.Horizontal.TProgressbar", troughcolor=CARD2, background=ACCENT, bordercolor=CARD,
                lightcolor=ACCENT, darkcolor=ACCENT, thickness=10)
    s.configure("Card.TCheckbutton", background=CARD, foreground=TEXT, font=(FONT, 10, "bold"), focuscolor=CARD, indicatorsize=16)
    s.map("Card.TCheckbutton", background=[("active", CARD)], indicatorcolor=[("selected", ACCENT), ("!selected", CARD2)])
    s.configure("Dark.TEntry", fieldbackground=CARD2, foreground=TEXT, insertcolor=TEXT, bordercolor=CARD2,
                lightcolor=CARD2, darkcolor=CARD2, padding=7)


def make_tree(parent, cols, height=10, selectmode="extended"):
    frame = tk.Frame(parent, bg=CARD)
    tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", selectmode=selectmode, height=height)
    for cid, title, w, stretch in cols:
        tree.heading(cid, text=title, anchor="w")
        tree.column(cid, width=w, stretch=stretch, anchor="w")
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    tree.tag_configure("high", foreground=DANGER)
    tree.tag_configure("medium", foreground=WARN)
    tree.tag_configure("low", foreground=BLUE_L)
    tree.tag_configure("ok", foreground=OK)
    tree.tag_configure("warn", foreground=WARN)
    tree.tag_configure("bad", foreground=DANGER)
    return frame, tree


def draw_blob_icon(canvas, cx, cy, r, c1, c2, glyph, refs):
    """Кольорова розмита «гліянцева» плямка-іконка (стиль «Кмітливого догляду»)."""
    if HAS_PIL:
        size = max(8, int(r * 2.5))
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        dr = ImageDraw.Draw(img)
        dr.ellipse((size * .08, size * .08, size * .92, size * .92), fill=hex_rgb(c1) + (255,))
        dr.ellipse((size * .36, size * .06, size * .96, size * .56), fill=hex_rgb(c2) + (215,))
        img = img.filter(ImageFilter.GaussianBlur(radius=size * .035))
        ref = ImageTk.PhotoImage(img)
        refs.append(ref)
        canvas.create_image(cx - size / 2, cy - size / 2, image=ref, anchor="nw")
    else:
        canvas.create_oval(cx - r, cy - r, cx + r, cy + r, fill=c1, outline="")
    canvas.create_text(cx, cy, text=glyph, fill="#ffffff", font=("Segoe UI Symbol", int(r * .8), "bold"))


class SmartCard(tk.Canvas):
    """Клікабельна картка категорії у стилі «Кмітливого догляду»: кольорова іконка
    зверху, назва й коротка статистика знизу. big=True — велика картка-герой, що під
    час сканування показує статус замість звичайного вмісту."""

    def __init__(self, master, title, glyph, c1, c2, command=None, big=False):
        super().__init__(master, bg=BG, highlightthickness=0, cursor="hand2" if command else "arrow")
        self.title_txt, self.glyph, self.c1, self.c2 = title, glyph, c1, c2
        self.command, self.big, self.busy, self.busy_text, self.busy_sub = command, big, False, "", ""
        self.stat_main, self.stat_sub = "…", ""
        self._refs = []
        self.bind("<Configure>", lambda e: self._draw())
        if command:
            self.bind("<Button-1>", self._press)
            self.bind("<ButtonRelease-1>", self._release)
            self.bind("<Enter>", lambda e: self._hover(True))
            self.bind("<Leave>", lambda e: self._hover(False))
        self._hov, self._pressed = False, False
        self._draw()

    def _hover(self, v):
        self._hov = v
        self._draw()

    def _press(self, e):
        self._pressed = True
        self._draw()

    def _release(self, e):
        was = self._pressed
        self._pressed = False
        inside = 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height()
        self._draw()
        if was and inside and self.command:
            self.command()

    def set_stat(self, main, sub=""):
        self.stat_main, self.stat_sub = main, sub
        self._draw()

    def set_busy(self, busy, text="", sub=""):
        self.busy, self.busy_text, self.busy_sub = busy, text, sub
        self._draw()

    def _draw(self):
        self.delete("all")
        self._refs.clear()
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10 or h < 10:
            return
        bgcol = _mix(CARD, "#000000", .18) if self._pressed else (_mix(CARD, CARD2, .5) if self._hov else CARD)
        round_rect(self, 0, 0, w, h, 20, fill=bgcol, outline="")
        pad = 18
        if self.big and self.busy:
            cy = h * .40
            r = min(w, h) * .20
            draw_blob_icon(self, w / 2, cy, r, self.c1, self.c2, self.glyph, self._refs)
            self.create_text(w / 2, h * .70, text=self.busy_text, fill=TEXT,
                             font=(FONT, 16, "bold"), width=w - 2 * pad, justify="center")
            self.create_text(w / 2, h * .70 + 30, text=self.busy_sub, fill=MUTED,
                             font=(FONT, 9), width=w - 2 * pad, justify="center")
            return
        self.create_text(pad, pad, text=self.title_txt, fill=MUTED, font=(FONT, 10, "bold"), anchor="nw")
        r = min(w, h) * (.30 if self.big else .20)
        cy = h * (.42 if self.big else .40)
        draw_blob_icon(self, w / 2, cy, r, self.c1, self.c2, self.glyph, self._refs)
        self.create_text(pad, h - pad - (18 if self.stat_sub else 0), text=self.stat_main, fill=TEXT,
                         font=(FONT, 16 if self.big else 14, "bold"), anchor="sw")
        if self.stat_sub:
            self.create_text(pad, h - pad, text=self.stat_sub, fill=MUTED, font=(FONT, 9), anchor="sw")


class CircleButton(tk.Canvas):
    """Кругла кнопка дій, що «накладається» на межу сітки карток (як «Стоп» на референсі)."""

    def __init__(self, master, text, command, color=ACCENT, size=78):
        super().__init__(master, width=size, height=size, bg=BG, highlightthickness=0, cursor="hand2")
        self.text, self.command, self.color, self.size = text, command, color, size
        self.bind("<Button-1>", lambda e: command())
        self.bind("<Enter>", lambda e: self._paint(True))
        self.bind("<Leave>", lambda e: self._paint(False))
        self._paint(False)

    def set_text(self, t):
        self.text = t
        self._paint(False)

    def set_color(self, c):
        self.color = c
        self._paint(False)

    def _paint(self, hov):
        self.delete("all")
        s = self.size
        col = _mix(self.color, "#ffffff", .18) if hov else self.color
        self.create_oval(5, 5, s - 5, s - 5, fill=_mix(self.color, BG, .75), outline="")
        self.create_oval(2, 2, s - 2, s - 2, fill=col, outline="")
        self.create_text(s / 2, s / 2, text=self.text, fill=ON_ACCENT, font=(FONT, 10, "bold"))


class Toast(tk.Frame):
    """Плаваюче сповіщення знизу-справа: з'являється, тримається кілька секунд і плавно
    згасає. Більш помітний і приємний спосіб повідомити про результат дії, ніж лише
    текст у статус-рядку внизу вікна."""
    ICONS = {"ok": "✔", "err": "✖", "info": "ℹ"}

    def __init__(self, master, text, kind="info", on_done=None):
        color = {"ok": OK, "err": DANGER}.get(kind, BLUE_L)
        super().__init__(master, bg=CARD, highlightbackground=color, highlightcolor=color, highlightthickness=1, bd=0)
        self.on_done, self._alive = on_done, True
        row = tk.Frame(self, bg=CARD)
        row.pack(padx=14, pady=11)
        self._icon = tk.Label(row, text=self.ICONS.get(kind, "ℹ"), bg=CARD, fg=color, font=(FONT, 12, "bold"))
        self._icon.pack(side="left", padx=(0, 10))
        self._txt = tk.Label(row, text=text, bg=CARD, fg=TEXT, font=(FONT, 10), wraplength=320,
                             justify="left", anchor="w")
        self._txt.pack(side="left")
        self._row, self._color = row, color
        self.bind("<Button-1>", lambda e: self.dismiss())
        for w in (row, self._icon, self._txt):
            w.bind("<Button-1>", lambda e: self.dismiss())
        self._job = self.after(3400, self._fade)

    def dismiss(self):
        if self._alive:
            self.after_cancel(self._job)
            self._fade(step=0, fast=True)

    def _fade(self, step=0, fast=False):
        steps = 5 if fast else 9
        if step >= steps:
            self._alive = False
            self.destroy()
            if self.on_done:
                self.on_done()
            return
        t = step / steps
        bg = _mix(CARD, BG, t)
        fg = _mix(TEXT, BG, t)
        self.configure(bg=bg, highlightbackground=_mix(self._color, BG, t))
        self._row.configure(bg=bg)
        self._icon.configure(bg=bg, fg=_mix(self._color, BG, t))
        self._txt.configure(bg=bg, fg=fg)
        self.after(28, lambda: self._fade(step + 1, fast))


class GlowPanel(tk.Frame):
    """Картка зі скругленими кутами та м'яким сяйвом по кутах. Діти пакуються в .body."""

    def __init__(self, master, radius=22, glow=True, height=120, bg=CARD):
        super().__init__(master, bg=BG)
        self.radius, self.glow, self.panel_bg = radius, glow, bg
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, height=height)
        self.canvas.pack(fill="both", expand=True)
        self.body = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self.canvas.bind("<Configure>", self._redraw)

    def sync_height(self, extra=0):
        """Підганяє висоту картки під реальний вміст .body (викликати після пакування дітей)."""
        self.body.update_idletasks()
        margin = 20 if self.glow else 1
        inset = margin + max(2, int(self.radius * .6))
        self.canvas.configure(height=self.body.winfo_reqheight() + 2 * inset + extra)

    def _blur_blob(self, w, h):
        bg = Image.new("RGB", (w, h), hex_rgb(BG))
        blob = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        dr = ImageDraw.Draw(blob)
        dr.ellipse((-w * .15, -h * .45, w * .55, h * 1.05), fill=hex_rgb(GLOW1) + (150,))
        dr.ellipse((w * .55, -h * .40, w * 1.15, h * .95), fill=hex_rgb(GLOW2) + (110,))
        blob = blob.filter(ImageFilter.GaussianBlur(radius=min(w, h) * .16))
        bg.paste(blob, (0, 0), blob)
        return bg

    def _redraw(self, e=None):
        self.canvas.delete("bg")
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        if w < 6 or h < 6:
            return
        margin = 20 if self.glow else 1
        if self.glow:
            if HAS_PIL:
                self._glow_ref = ImageTk.PhotoImage(self._blur_blob(w, h))
                self.canvas.create_image(0, 0, image=self._glow_ref, anchor="nw", tags="bg")
            else:
                self.canvas.create_oval(-w * .12, -h * .35, w * .46, h * .95, fill=_mix(GLOW1, BG, .87), outline="", tags="bg")
                self.canvas.create_oval(w * .58, -h * .25, w * 1.1, h * .85, fill=_mix(GLOW2, BG, .9), outline="", tags="bg")
        round_rect(self.canvas, margin, margin, w - margin, h - margin, self.radius, fill=self.panel_bg, outline="", tags="bg")
        self.canvas.tag_lower("bg")
        inset = margin + max(2, int(self.radius * .6))
        self.canvas.coords(self._win, inset, inset)
        self.canvas.itemconfigure(self._win, width=max(1, w - 2 * inset), height=max(1, h - 2 * inset))


class Page(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=BG)
        self.app = app

    def header(self, title, subtitle):
        tk.Label(self, text=title, font=(FONT, 22, "bold"), bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(24, 0))
        tk.Label(self, text=subtitle, font=(FONT, 10), bg=BG, fg=MUTED).pack(anchor="w", padx=28, pady=(2, 16))

    def on_show(self):
        pass


# ───────────────────────────── Сторінка «Захист» (сітка карток «Кмітливий догляд») ─────────────────────────────
class DashboardPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Кмітливий догляд", "Огляньте стан захисту й запустіть аналіз одним кліком")
        self._scanning = False

        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="x", padx=28)
        outer.columnconfigure(0, weight=1, uniform="o")
        outer.columnconfigure(1, weight=1, uniform="o")

        left = tk.Frame(outer, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure((0, 1), weight=1, uniform="l")
        left.rowconfigure(0, minsize=172)
        left.rowconfigure(1, minsize=172)

        self.c_scan = SmartCard(left, "Сканування", "⌕", "#2fd49a", "#1aa876", command=lambda: app.show("scan"))
        self.c_scan.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))

        self.c_protect = SmartCard(left, "Захист", "⛨", "#ff8a4c", "#ff4f8b", command=self.toggle_rt)
        self.c_protect.grid(row=0, column=1, sticky="nsew", pady=(0, 10))

        self.c_quar = SmartCard(left, "Карантин", "▣", "#4f7bff", "#8a5cff", command=lambda: app.show("quar"))
        self.c_quar.grid(row=1, column=0, sticky="nsew", padx=(0, 10))

        self.c_auto = SmartCard(left, "Автозапуск", "⏻", "#ffb020", "#ff6f6f", command=lambda: app.show("auto"))
        self.c_auto.grid(row=1, column=1, sticky="nsew")

        self.c_hero = SmartCard(outer, "Кмітливий аналіз", "⚡", GLOW1, GLOW2, command=self.toggle_scan, big=True)
        self.c_hero.grid(row=0, column=1, sticky="nsew")

        self.action_btn = CircleButton(self, "Сканувати", self.toggle_scan)
        self.action_btn.place(in_=left, relx=.5, rely=1.0, anchor="s", y=20)

        if IS_WIN and not is_admin():
            Btn(self, "Перезапустити від імені адміністратора", self.go_admin, "ghost").pack(
                anchor="w", padx=28, pady=(46, 0))

    def go_admin(self):
        if relaunch_as_admin():
            self.app.destroy()

    def toggle_rt(self):
        self.app.set_realtime(not self.app.store["realtime"])
        self.refresh()

    def toggle_scan(self):
        if self._scanning:
            self._scanning = False
            self.action_btn.set_text("Сканувати")
            self.action_btn.set_color(ACCENT)
            self.c_hero.set_busy(False)
            return
        self._scanning = True
        self.action_btn.set_text("Стоп")
        self.action_btn.set_color(DANGER)
        self.c_hero.set_busy(True, "Досліджуємо вашу систему…", "Перевіряємо файли, автозапуск і запущені процеси")
        self.after(450, self._launch_scan)

    def _launch_scan(self):
        if not self._scanning:
            return
        self._scanning = False
        self.action_btn.set_text("Сканувати")
        self.action_btn.set_color(ACCENT)
        self.c_hero.set_busy(False)
        self.app.start_scan("quick")

    def on_show(self):
        self.refresh()
        if IS_WIN:
            self.app.bg(lambda: (ps_json("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled", 40) or [{}])[0],
                        self._def_done)

    def _def_done(self, r):
        # використовуємо стан Defender лише як запасний індикатор для картки «Захист»,
        # якщо власний захист у реальному часі вимкнено
        pass

    def refresh(self):
        a = self.app
        state, title, sub = a.protection_state()
        n_threats = len(a.pages["scan"].dets) if "scan" in a.pages else 0
        self.c_scan.set_stat(fmt_ts(a.store["last_scan"]), "останнє сканування")
        on = a.store["realtime"]
        self.c_protect.set_stat("Увімкнено" if on else "Вимкнено", "захист у реальному часі")
        self.c_quar.set_stat(str(len(a.quar.items)), "файлів ізольовано")
        self.c_auto.set_stat("Перевірте", "автозапуск і служби")
        if n_threats:
            self.c_hero.set_stat(f"Загроз: {n_threats}", "потребують уваги")
        else:
            self.c_hero.set_stat("Усе гаразд", "натисніть, щоб перевірити ще раз")


# ───────────────────────────── Сторінка «Сканування» ─────────────────────────────
class ScanPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Сканування", "Оберіть режим перевірки. Знайдені загрози можна ізолювати в карантин.")
        self.dets: dict[str, Detection] = {}
        self.running = False
        self.stop = threading.Event()
        self.pause = threading.Event()

        modes = tk.Frame(self, bg=BG)
        modes.pack(fill="x", padx=28)
        modes.columnconfigure((0, 1, 2), weight=1, uniform="m")
        defs = [("Швидке", "Завантаження, Робочий стіл, TEMP, автозапуск і запущені процеси", "quick"),
                ("Повне", "Усі фіксовані диски. Може тривати довго", "full"),
                ("Вибіркове", "Одна папка чи диск на ваш вибір", "custom")]
        self.mode_btns = []
        for i, (t, d, m) in enumerate(defs):
            c = Card(modes)
            c.grid(row=0, column=i, sticky="nsew", padx=(0, 12) if i < 2 else 0)
            lbl(c, t, TEXT, 13, True).pack(anchor="w", padx=16, pady=(14, 0))
            lbl(c, d, MUTED, 9, wraplength=250, justify="left").pack(anchor="w", padx=16, pady=(2, 8))
            b = Btn(c, "Почати", lambda m=m: self.start(m), "primary" if i == 0 else "ghost")
            b.pack(anchor="w", padx=16, pady=(0, 14))
            self.mode_btns.append(b)

        st = Card(self)
        st.pack(fill="x", padx=28, pady=12)
        self.cur = lbl(st, "Очікування запуску", MUTED, 9, anchor="w")
        self.cur.pack(fill="x", padx=16, pady=(12, 4))
        self.pb = ttk.Progressbar(st, style="Accent.Horizontal.TProgressbar", mode="indeterminate")
        self.pb.pack(fill="x", padx=16)
        r = tk.Frame(st, bg=CARD)
        r.pack(fill="x", padx=16, pady=10)
        self.stats = lbl(r, "Файлів: 0 · Загроз: 0 · Час: 0:00", TEXT, 10, True)
        self.stats.pack(side="left")
        self.b_stop = Btn(r, "Стоп", self.on_stop, "danger")
        self.b_stop.pack(side="right")
        self.b_pause = Btn(r, "Пауза", self.on_pause, "ghost")
        self.b_pause.pack(side="right", padx=8)
        self.b_stop.enable(False)
        self.b_pause.enable(False)

        frame, self.tree = make_tree(self, [("lvl", "Ризик", 90, False), ("name", "Загроза", 200, False),
                                            ("path", "Файл", 340, True), ("why", "Причина", 320, True)], height=7)
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=12)
        self.res_lbl = lbl(foot, "Загроз не знайдено", MUTED)
        self.res_lbl.pack(side="left")
        Btn(foot, "Звіт…", self.report, "ghost").pack(side="right")
        Btn(foot, "Показати в папці", self.reveal, "ghost").pack(side="right", padx=8)
        Btn(foot, "Ігнорувати", self.ignore, "ghost").pack(side="right")
        Btn(foot, "Видалити", self.delete, "danger").pack(side="right", padx=8)
        Btn(foot, "У карантин", self.quarantine, "warn").pack(side="right")

    # --- керування
    def set_running(self, v):
        self.running = v
        for b in self.mode_btns:
            b.enable(not v)
        self.b_stop.enable(v)
        self.b_pause.enable(v)
        if v:
            self.pb.start(12)
        else:
            self.pb.stop()

    def on_stop(self):
        self.stop.set()
        self.pause.clear()

    def on_pause(self):
        if self.pause.is_set():
            self.pause.clear()
            self.b_pause.set_text("Пауза")
        else:
            self.pause.set()
            self.b_pause.set_text("Продовжити")

    def update_progress(self, path, files, threats, secs):
        shown = path if len(path) < 110 else path[:50] + "…" + path[-55:]
        self.cur.config(text=("⏸ Пауза — " if self.pause.is_set() else "Перевіряється: ") + shown)
        self.stats.config(text=f"Файлів: {files:,} · Загроз: {threats} · Час: {int(secs // 60)}:{int(secs % 60):02d}".replace(",", " "))

    def add_detection(self, det: Detection):
        if any(d.path == det.path for d in self.dets.values()):
            return
        iid = self.tree.insert("", "end", tags=(det.level,),
                               values=(LEVEL_UA[det.level], det.name, det.path, det.reason))
        self.dets[iid] = det
        self.res_lbl.config(text=f"Знайдено загроз: {len(self.dets)}", fg=DANGER)
        log(f"Виявлено [{LEVEL_UA[det.level]}] {det.name}: {det.path} — {det.reason}")

    def start(self, mode, folder=None):
        if self.running:
            self.app.notify("Сканування вже виконується", "err")
            return
        if mode == "custom":
            folder = folder or filedialog.askdirectory(title="Оберіть папку для перевірки")
            if not folder:
                return
        self.stop, self.pause = threading.Event(), threading.Event()
        self.b_pause.set_text("Пауза")
        self.tree.delete(*self.tree.get_children())
        self.dets.clear()
        self.res_lbl.config(text="Сканування…", fg=MUTED)
        self.set_running(True)
        app, eng, stop, pause = self.app, self.app.engine, self.stop, self.pause
        deep = app.store["all_types"]
        t0 = time.time()
        log(f"Розпочато сканування: {mode}")

        def work():
            stats = {"files": 0, "threats": 0}
            last = [0.0]

            def check(path):
                while pause.is_set() and not stop.is_set():
                    time.sleep(0.2)
                if stop.is_set():
                    return
                stats["files"] += 1
                now = time.time()
                if now - last[0] > 0.12:
                    last[0] = now
                    app.ui(self.update_progress, path, stats["files"], stats["threats"], now - t0)
                det = eng.scan_file(path, deep)
                if det:
                    stats["threats"] += 1
                    app.ui(self.add_detection, det)

            if mode == "quick":
                if IS_WIN:
                    app.ui(self.cur.config, text="Збираю список запущених процесів…")
                    for pr in process_list():
                        if pr["path"] and os.path.isfile(pr["path"]):
                            check(pr["path"])
                for root, depth in quick_targets():
                    for p in walk_files(root, stop, depth):
                        check(p)
            else:
                roots = [folder] if mode == "custom" else list_drives()
                for root in roots:
                    for p in walk_files(root, stop):
                        check(p)
            return stats, time.time() - t0

        def done(res):
            self.set_running(False)
            eng.save_cache()
            if isinstance(res, Exception):
                self.cur.config(text=f"Помилка: {res}")
                return
            stats, secs = res
            s = app.store
            if not stop.is_set():
                s["last_scan"] = time.time()
                s["scans"] = s["scans"] + 1
            s["files_total"] = s["files_total"] + stats["files"]
            s["last_threats"] = len(self.dets)
            self.cur.config(text="Сканування зупинено" if stop.is_set() else "Сканування завершено")
            n = len(self.dets)
            self.res_lbl.config(text=f"Знайдено загроз: {n}" if n else "Загроз не знайдено ✓", fg=DANGER if n else ACCENT)
            log(f"Сканування завершено: файлів {stats['files']}, загроз {n}, {int(secs)} с")
            app.notify(f"Готово: перевірено {stats['files']} файлів, загроз: {n}", "err" if n else "ok")
            app.pages["dash"].refresh()

        app.bg(work, done)

    # --- дії над результатами
    def _selected(self):
        return [(i, self.dets[i]) for i in self.tree.selection() if i in self.dets]

    def _update_label(self):
        n = len(self.dets)
        self.res_lbl.config(text=f"Знайдено загроз: {n}" if n else "Усі загрози оброблено ✓", fg=DANGER if n else ACCENT)
        self.app.pages["dash"].refresh()

    def quarantine(self, items=None):
        items = items or self._selected()
        if not items:
            self.app.notify("Оберіть файли у списку", "err")
            return
        ok = 0
        for iid, det in items:
            good, err = self.app.quar.add(det)
            if good:
                ok += 1
                self.tree.delete(iid)
                del self.dets[iid]
            else:
                self.app.notify(f"Не вдалося ізолювати: {err}", "err")
        self._update_label()
        if ok:
            self.app.notify(f"У карантин переміщено файлів: {ok}", "ok")

    def delete(self):
        items = self._selected()
        if not items:
            self.app.notify("Оберіть файли у списку", "err")
            return
        if not messagebox.askyesno("Видалення", f"Остаточно видалити файлів: {len(items)}?\nЦе неможливо скасувати. "
                                   "Безпечніше — «У карантин»."):
            return
        for iid, det in items:
            try:
                os.chmod(det.path, stat.S_IWRITE)
                os.remove(det.path)
                log(f"Видалено: {det.path}")
                self.tree.delete(iid)
                del self.dets[iid]
            except OSError as e:
                self.app.notify(f"Не вдалося видалити: {e}", "err")
        self._update_label()

    def ignore(self):
        items = self._selected()
        if not items:
            return
        ex = list(self.app.store["exclusions"])
        for iid, det in items:
            if det.path not in ex:
                ex.append(det.path)
            self.tree.delete(iid)
            del self.dets[iid]
        self.app.store["exclusions"] = ex
        log(f"Додано до винятків: {len(items)} файл(ів)")
        self._update_label()

    def reveal(self):
        s = self._selected()
        if s:
            open_in_folder(s[0][1].path)

    def report(self):
        f = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="ua_shield_report.txt",
                                         filetypes=[("Текстовий файл", "*.txt")])
        if not f:
            return
        lines = [f"UA Shield — звіт від {fmt_ts(time.time())}", f"Знайдено загроз: {len(self.dets)}", ""]
        for d in self.dets.values():
            lines += [f"[{LEVEL_UA[d.level]}] {d.name}", f"  Файл: {d.path}", f"  Причина: {d.reason}",
                      f"  SHA-256: {d.sha256 or '—'}", ""]
        Path(f).write_text("\n".join(lines), "utf-8")
        self.app.notify("Звіт збережено", "ok")


# ───────────────────────────── Сторінка «Карантин» ─────────────────────────────
class QuarantinePage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Карантин", "Ізольовані файли зашифровані й не можуть завдати шкоди. Їх можна відновити.")
        frame, self.tree = make_tree(self, [("date", "Дата", 140, False), ("name", "Загроза", 200, False),
                                            ("path", "Початкове розташування", 460, True), ("size", "Розмір", 90, False)])
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Очистити весь карантин", self.clear_all, "danger").pack(side="right")
        Btn(foot, "Видалити назавжди", self.delete, "danger").pack(side="right", padx=8)
        Btn(foot, "Відновити", self.restore, "ghost").pack(side="right")

    def on_show(self):
        self.tree.delete(*self.tree.get_children())
        for qid, m in sorted(self.app.quar.items.items(), key=lambda x: -x[1]["ts"]):
            self.tree.insert("", "end", iid=qid, values=(fmt_ts(m["ts"]), m["name"], m["path"], fmt_size(m["size"])))
        n = len(self.app.quar.items)
        self.info.config(text=f"Файлів у карантині: {n}" if n else "Карантин порожній")

    def restore(self):
        sel = self.tree.selection()
        if not sel:
            self.app.notify("Оберіть файл", "err")
            return
        if not messagebox.askyesno("Відновлення", "Відновити файл на початкове місце?\nВін може бути небезпечним. "
                                   "Додати його до винятків, щоб не блокувався знову?"):
            return
        for qid in sel:
            path = self.app.quar.items[qid]["path"]
            ok, res = self.app.quar.restore(qid)
            if ok:
                ex = list(self.app.store["exclusions"])
                ex.append(path)
                self.app.store["exclusions"] = ex
            else:
                self.app.notify(f"Помилка: {res}", "err")
        self.on_show()
        self.app.pages["dash"].refresh()

    def delete(self):
        sel = self.tree.selection()
        if sel and messagebox.askyesno("Видалення", f"Остаточно видалити файлів: {len(sel)}?"):
            for qid in sel:
                self.app.quar.delete(qid)
            self.on_show()
            self.app.pages["dash"].refresh()

    def clear_all(self):
        if self.app.quar.items and messagebox.askyesno("Очищення", "Остаточно видалити ВСІ файли з карантину?"):
            for qid in list(self.app.quar.items):
                self.app.quar.delete(qid)
            self.on_show()
            self.app.pages["dash"].refresh()


# ───────────────────────────── Сторінка «Процеси» ─────────────────────────────
class ProcessPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Запущені процеси", "Підозрілі процеси позначено: маскування під системні та запуск із тимчасових папок")
        self.rows: dict[str, dict] = {}
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        frame, self.tree = make_tree(self, [("pid", "PID", 70, False), ("name", "Процес", 200, False),
                                            ("risk", "Оцінка", 260, False), ("path", "Шлях", 460, True)],
                                     selectmode="browse")
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Завершити процес", self.kill, "danger").pack(side="right")
        Btn(foot, "Сканувати файл", self.scan_one, "ghost").pack(side="right", padx=8)
        Btn(foot, "Показати в папці", self.reveal, "ghost").pack(side="right")
        Btn(foot, "Оновити", self.load, "ghost").pack(side="right", padx=8)

    def on_show(self):
        if IS_WIN:
            self.load()

    def load(self):
        self.info.config(text="Отримую список процесів…")
        self.app.bg(process_list, self.fill)

    def fill(self, rows):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        if isinstance(rows, Exception):
            self.info.config(text=f"Помилка: {rows}")
            return
        rows.sort(key=lambda r: (not r["risk"], str(r["name"]).lower()))
        for r in rows:
            iid = self.tree.insert("", "end", tags=("high",) if r["risk"] else (),
                                   values=(r["pid"], r["name"], r["risk"] or "—", r["path"]))
            self.rows[iid] = r
        bad = sum(1 for r in rows if r["risk"])
        self.info.config(text=f"Процесів: {len(rows)} · підозрілих: {bad}")

    def _sel(self):
        s = self.tree.selection()
        return self.rows[s[0]] if s else None

    def kill(self):
        r = self._sel()
        if not r:
            return
        if messagebox.askyesno("Завершення процесу", f"Примусово завершити «{r['name']}» (PID {r['pid']})?"):
            subprocess.run(["taskkill", "/PID", str(r["pid"]), "/F"], capture_output=True, creationflags=NOWIN)
            self.load()

    def reveal(self):
        r = self._sel()
        if r and r["path"]:
            open_in_folder(r["path"])

    def scan_one(self):
        r = self._sel()
        if not r or not r["path"]:
            return
        det = self.app.engine.scan_file(r["path"], deep=True)
        if det:
            self.app.pages["scan"].add_detection(det)
            self.app.show("scan")
            self.app.notify(f"Виявлено: {det.name}", "err")
        else:
            self.app.notify("Файл процесу не містить відомих загроз", "ok")


# ───────────────────────────── Розблокування екрана (у стилі SimpleUnlocker) ─────────────────────────────
# Віруси-блокувальники («winlock») показують повноекранне вікно поверх усіх інших, без
# рамки й кнопки закриття, часто вимикають Диспетчер завдань і затискають курсор у своєму
# вікні. Це не знімає хуки/ін'єкції в чужі процеси (зайве втручання в систему) — лише
# знаходить і дозволяє закрити підозріле вікно та повернути контроль над робочим столом.
WS_CAPTION = 0x00C00000
GWL_STYLE, GWL_EXSTYLE = -16, -20
WS_EX_TOPMOST = 0x00000008
WM_CLOSE = 0x0010


class _RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


def enum_top_windows() -> list[dict]:
    if not IS_WIN:
        return []
    u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
    sw, sh = u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)
    results: list[dict] = []
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)

    def cb(hwnd, _lparam):
        try:
            if not u32.IsWindowVisible(hwnd):
                return 1
            n = u32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(n + 1)
            u32.GetWindowTextW(hwnd, buf, n + 1)
            title = buf.value
            rect = _RECT()
            u32.GetWindowRect(hwnd, ctypes.byref(rect))
            style = u32.GetWindowLongW(hwnd, GWL_STYLE)
            exstyle = u32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            pid = ctypes.c_ulong()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            fullscreen = (rect.right - rect.left) >= sw and (rect.bottom - rect.top) >= sh
            topmost = bool(exstyle & WS_EX_TOPMOST)
            no_caption = not bool(style & WS_CAPTION)
            path = ""
            h = k32.OpenProcess(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
            if h:
                size = ctypes.c_ulong(260)
                b2 = ctypes.create_unicode_buffer(260)
                if k32.QueryFullProcessImageNameW(h, 0, b2, ctypes.byref(size)):
                    path = b2.value
                k32.CloseHandle(h)
            sysdir = os.environ.get("WINDIR", r"C:\Windows").lower()
            risky = fullscreen and (topmost or no_caption) and not path.lower().startswith(sysdir)
            if title or risky:
                results.append(dict(hwnd=hwnd, title=title or "(без назви)", pid=pid.value, path=path,
                                    fullscreen=fullscreen, topmost=topmost, no_caption=no_caption, risk=risky))
        except Exception:
            pass
        return 1

    u32.EnumWindows(WNDENUMPROC(cb), 0)
    return results


def close_window(hwnd):
    ctypes.windll.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)


def release_cursor_clip() -> bool:
    try:
        return bool(ctypes.windll.user32.ClipCursor(None))
    except Exception:
        return False


def restore_taskbar() -> bool:
    try:
        hwnd = ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None)
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 5)   # SW_SHOW
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0001 | 0x0002)  # SWP_NOSIZE|NOMOVE, лишаємо z-order
        return bool(hwnd)
    except Exception:
        return False


class UnlockPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Розблокування екрана", "Пошук і закриття вікон вірусів-блокувальників (winlock); "
                    "зняття затискання курсора та відновлення панелі завдань")
        self.rows: dict[str, dict] = {}
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        bar = Card(self)
        bar.pack(fill="x", padx=28, pady=(0, 12))
        r = tk.Frame(bar, bg=CARD)
        r.pack(fill="x", padx=14, pady=12)
        Btn(r, "Зняти затискання курсора", self.t_cursor, "ghost").pack(side="left")
        Btn(r, "Показати панель завдань", self.t_taskbar, "ghost").pack(side="left", padx=8)
        Btn(r, "Увімкнути Диспетчер завдань", self.t_taskmgr, "ghost").pack(side="left")

        frame, self.tree = make_tree(self, [("risk", "Ризик", 90, False), ("title", "Заголовок вікна", 260, False),
                                            ("proc", "Процес", 300, True), ("flags", "Ознаки", 240, False)],
                                     selectmode="browse")
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Завершити процес", self.kill, "danger").pack(side="right")
        Btn(foot, "Закрити вікно", self.close_win, "primary").pack(side="right", padx=8)
        Btn(foot, "Оновити список", self.load, "ghost").pack(side="right")

    def on_show(self):
        if IS_WIN:
            self.load()

    def load(self):
        self.info.config(text="Скануюю відкриті вікна…")
        self.app.bg(enum_top_windows, self.fill)

    def fill(self, rows):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        if isinstance(rows, Exception):
            self.info.config(text=f"Помилка: {rows}")
            return
        rows.sort(key=lambda x: not x["risk"])
        for r in rows:
            flags = []
            if r["fullscreen"]:
                flags.append("на весь екран")
            if r["topmost"]:
                flags.append("поверх усіх вікон")
            if r["no_caption"]:
                flags.append("без рамки")
            iid = self.tree.insert("", "end", tags=("high",) if r["risk"] else (),
                                   values=("Увага" if r["risk"] else "—", r["title"],
                                           r["path"] or f"PID {r['pid']}", ", ".join(flags) or "—"))
            self.rows[iid] = r
        bad = sum(1 for r in rows if r["risk"])
        self.info.config(text=f"Вікон: {len(self.rows)} · підозрілих: {bad}")

    def _sel(self):
        s = self.tree.selection()
        return self.rows.get(s[0]) if s else None

    def close_win(self):
        r = self._sel()
        if not r:
            self.app.notify("Виберіть вікно у списку", "err")
            return
        close_window(r["hwnd"])
        self.app.notify("Команду закриття вікна надіслано", "ok")
        self.after(400, self.load)

    def kill(self):
        r = self._sel()
        if not r:
            self.app.notify("Виберіть вікно у списку", "err")
            return
        if not messagebox.askyesno("Завершення процесу", f"Примусово завершити процес PID {r['pid']}"
                                   f" ({r['path'] or 'невідомий шлях'})?"):
            return
        subprocess.run(["taskkill", "/PID", str(r["pid"]), "/F"], capture_output=True, creationflags=NOWIN)
        self.app.notify("Процес завершено", "ok")
        self.after(400, self.load)

    def t_cursor(self):
        self.app.notify("Курсор звільнено від затискання" if release_cursor_clip() else "Не вдалося звільнити курсор",
                        "ok")

    def t_taskbar(self):
        self.app.notify("Панель завдань показано" if restore_taskbar() else "Не вдалося знайти панель завдань",
                        "ok" if restore_taskbar else "err")

    def t_taskmgr(self):
        if not is_admin():
            self.app.notify("Потрібні права адміністратора (кнопка на вкладці «Захист»)", "err")
            return
        try:
            rdel("HKCU", POL_SYS, "DisableTaskMgr")
            commit_backup("Розблокування: Диспетчер завдань")
        except OSError:
            pass
        self.app.notify("Диспетчер завдань увімкнено", "ok")


# ───────────────────────────── Сторінка «Перевірка системи» ─────────────────────────────
class CheckPage(Page):
    ICON = {"ok": "✔ Норма", "warn": "⚠ Увага", "bad": "✖ Ризик"}

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Безпека системи", "Налаштування Windows, які найчастіше використовують зловмисники")
        self.items: dict[str, dict] = {}
        frame, self.tree = make_tree(self, [("st", "Стан", 110, False), ("title", "Перевірка", 290, False),
                                            ("detail", "Деталі", 560, True), ("fix", "Виправлення", 110, False)],
                                     selectmode="browse")
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Виправити вибране", self.fix, "primary").pack(side="right")
        Btn(foot, "Перевірити знову", self.run, "ghost").pack(side="right", padx=8)
        self.first = True

    def on_show(self):
        if self.first:
            self.first = False
            self.run()

    def run(self):
        self.info.config(text="Перевіряю…")
        self.app.bg(run_checks, self.fill)

    def fill(self, res):
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        if isinstance(res, Exception):
            self.info.config(text=f"Помилка: {res}")
            return
        for r in res:
            iid = self.tree.insert("", "end", tags=(r["level"],),
                                   values=(self.ICON[r["level"]], r["title"], r["detail"], "доступне" if r["fix"] else "—"))
            self.items[iid] = r
        bad = sum(1 for r in res if r["level"] != "ok")
        self.info.config(text="Усе гаразд ✓" if not bad else f"Потребує уваги: {bad}")

    def fix(self):
        s = self.tree.selection()
        r = self.items.get(s[0]) if s else None
        if not r or not r["fix"]:
            self.app.notify("Для цього пункту автоматичного виправлення немає", "err")
            return
        if not messagebox.askyesno("Виправлення", f"Виправити: {r['title']}?\nМоже знадобитися запуск від імені адміністратора."):
            return
        self.info.config(text="Виконую…")
        self.app.bg(r["fix"], lambda ok: (self.app.notify("Виправлено" if ok is not False and not isinstance(ok, Exception)
                                                            else "Не вдалося — потрібні права адміністратора",
                                                            "ok" if ok is not False and not isinstance(ok, Exception) else "err"),
                                          self.run()))


# ───────────────────────────── Сторінка «Defender» ─────────────────────────────
class DefenderPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Microsoft Defender", "Керування вбудованим антивірусом Windows — найнадійніший рушій на вашому ПК")
        self.busy = False
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        grid = tk.Frame(self, bg=BG)
        grid.pack(fill="x", padx=28)
        grid.columnconfigure((0, 1), weight=1, uniform="d")
        acts = [("Швидка перевірка Defender", "Перевіряє найімовірніші місця зараження", "Запустити", self.quick),
                ("Повна перевірка Defender", "Усі файли на всіх дисках — довго", "Запустити", self.full),
                ("Оновити бази сигнатур", "Завантажує свіжі визначення загроз", "Оновити", self.update_sigs),
                ("Офлайн-перевірка", "Для руткітів: ПК перезавантажиться й перевірить систему до старту Windows",
                 "Запустити", self.offline),
                ("Показати виявлені загрози", "Історія знахідок Defender", "Показати", self.threats),
                ("Відкрити «Захист Windows»", "Стандартне вікно безпеки", "Відкрити", self.open_ui)]
        self.btns = []
        for i, (t, d, b, fn) in enumerate(acts):
            c = Card(grid)
            c.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0, 12) if i % 2 == 0 else 0, pady=(0, 12))
            lbl(c, t, TEXT, 11, True).pack(anchor="w", padx=16, pady=(12, 0))
            lbl(c, d, MUTED, 9, wraplength=400, justify="left").pack(anchor="w", padx=16)
            bt = Btn(c, b, fn, "ghost")
            bt.pack(anchor="w", padx=16, pady=(8, 12))
            self.btns.append(bt)
        self.out = tk.Text(self, bg=CARD, fg=MUTED, bd=0, highlightthickness=0, font=("Consolas", 9), height=8,
                           padx=12, pady=10, wrap="word", state="disabled")
        self.out.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    def write(self, t):
        self.out.config(state="normal")
        self.out.insert("end", t + "\n")
        self.out.see("end")
        self.out.config(state="disabled")

    def run_ps(self, label, cmd, timeout=None, after=None):
        if self.busy:
            self.app.notify("Дочекайтесь завершення поточної операції", "err")
            return
        self.busy = True
        for b in self.btns:
            b.enable(False)
        self.write(f"▶ {label}…")

        def done(out):
            self.busy = False
            for b in self.btns:
                b.enable(True)
            self.write(out if isinstance(out, str) and out else f"✓ {label}: завершено")
            if after:
                after()
            log(f"Defender: {label}")
        self.app.bg(lambda: ps(cmd, timeout), done)

    def quick(self):
        self.run_ps("Швидка перевірка", "Start-MpScan -ScanType QuickScan", None, self.threats)

    def full(self):
        if messagebox.askyesno("Повна перевірка", "Повна перевірка може тривати кілька годин. Почати?"):
            self.run_ps("Повна перевірка", "Start-MpScan -ScanType FullScan", None, self.threats)

    def update_sigs(self):
        self.run_ps("Оновлення баз", "Update-MpSignature", 600)

    def offline(self):
        if is_admin() and messagebox.askyesno("Офлайн-перевірка", "Комп'ютер буде ПЕРЕЗАВАНТАЖЕНО. Збережіть роботу.\nПродовжити?"):
            self.run_ps("Офлайн-перевірка", "Start-MpWDOScan", 60)
        elif not is_admin():
            self.app.notify("Потрібні права адміністратора", "err")

    def threats(self):
        def work():
            rows = ps_json("Get-MpThreatDetection | Select-Object -First 15 InitialDetectionTime,ThreatID,"
                           "@{n='Res';e={($_.Resources -join '; ')}}", 60)
            return rows
        if self.busy:
            return

        def show(rows):
            if not rows or isinstance(rows, Exception):
                self.write("✓ Defender не повідомляє про виявлені загрози")
                return
            self.write(f"Знахідок Defender: {len(rows)} (останні):")
            for r in rows:
                self.write(f"  • {str(r.get('Res'))[:140]}")
        self.app.bg(work, show)

    def open_ui(self):
        try:
            subprocess.Popen("start windowsdefender:", shell=True)
        except OSError:
            pass


# ───────────────────────────── Сторінка «Налаштування» ─────────────────────────────
class SettingsPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Налаштування та журнал", "Чутливість, винятки, власні бази сигнатур")
        s = app.store
        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True, padx=(28, 18), pady=(0, 16))
        self.sf = sf
        box = sf.inner

        c1 = Card(box)
        c1.pack(fill="x", pady=(0, 12), padx=(0, 10))
        lbl(c1, "Чутливість евристики", TEXT, 12, True).pack(anchor="w", padx=16, pady=(14, 2))
        lbl(c1, "Вища чутливість знаходить більше підозрілого, але дає більше хибних спрацювань", MUTED, 9).pack(anchor="w", padx=16)
        self.sens = tk.IntVar(value=s["sens"])
        r = tk.Frame(c1, bg=CARD)
        r.pack(anchor="w", padx=16, pady=(8, 14))
        for v, t in ((0, "Низька"), (1, "Середня (рекомендовано)"), (2, "Висока")):
            tk.Radiobutton(r, text=t, variable=self.sens, value=v, command=self.save, bg=CARD, fg=TEXT,
                           selectcolor=CARD2, activebackground=CARD, activeforeground=ACCENT,
                           font=(FONT, 10), bd=0, highlightthickness=0).pack(side="left", padx=(0, 16))

        c2 = Card(box)
        c2.pack(fill="x", pady=(0, 12), padx=(0, 10))
        self.v_auto, self.v_all = tk.BooleanVar(value=s["auto_q"]), tk.BooleanVar(value=s["all_types"])
        ttk.Checkbutton(c2, text="Автоматично ізолювати загрози, знайдені в реальному часі", variable=self.v_auto,
                        style="Card.TCheckbutton", command=self.save).pack(anchor="w", padx=16, pady=(14, 4))
        ttk.Checkbutton(c2, text="Перевіряти файли всіх типів (повільніше, але глибше)", variable=self.v_all,
                        style="Card.TCheckbutton", command=self.save).pack(anchor="w", padx=16, pady=(0, 14))

        c3 = Card(box)
        c3.pack(fill="x", pady=(0, 12), padx=(0, 10))
        lbl(c3, "Винятки (не перевіряти)", TEXT, 12, True).pack(anchor="w", padx=16, pady=(14, 6))
        self.ex = tk.Listbox(c3, bg=CARD2, fg=TEXT, bd=0, highlightthickness=0, height=4, font=(FONT, 9),
                             selectbackground=BLUE, activestyle="none")
        self.ex.pack(fill="x", padx=16)
        rr = tk.Frame(c3, bg=CARD)
        rr.pack(anchor="w", padx=16, pady=10)
        Btn(rr, "Додати папку…", self.add_ex, "ghost").pack(side="left")
        Btn(rr, "Прибрати вибране", self.del_ex, "ghost").pack(side="left", padx=8)

        c4 = Card(box)
        c4.pack(fill="x", pady=(0, 12), padx=(0, 10))
        lbl(c4, "Бази сигнатур", TEXT, 12, True).pack(anchor="w", padx=16, pady=(14, 2))
        lbl(c4, "Імпортуйте текстовий файл зі списком хешів MD5/SHA-256 (по одному в рядку, після хешу — назва загрози). "
            "Такі списки публікують, наприклад, MalwareBazaar та інші дослідницькі сервіси.", MUTED, 9,
            wraplength=720, justify="left").pack(anchor="w", padx=16)
        r2 = tk.Frame(c4, bg=CARD)
        r2.pack(anchor="w", padx=16, pady=10)
        self.sig_lbl = lbl(r2, "", TEXT, 10, True)
        self.sig_lbl.pack(side="left", padx=(0, 14))
        Btn(r2, "Імпортувати список…", self.imp, "ghost").pack(side="left")
        Btn(r2, "Скинути базу", self.reset, "ghost").pack(side="left", padx=8)
        Btn(r2, "Створити тестовий файл EICAR", self.make_eicar, "primary").pack(side="left")

        c5 = Card(box)
        c5.pack(fill="both", expand=True, pady=(0, 12), padx=(0, 10))
        h = tk.Frame(c5, bg=CARD)
        h.pack(fill="x", padx=16, pady=(14, 6))
        lbl(h, "Журнал подій", TEXT, 12, True).pack(side="left")
        Btn(h, "Очистити", self.clear_log, "ghost").pack(side="right")
        self.log = tk.Text(c5, bg=CARD2, fg=MUTED, bd=0, highlightthickness=0, font=("Consolas", 9), height=10,
                           padx=10, pady=8, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.reload_log()
        self.refresh()

    def refresh(self):
        self.ex.delete(0, "end")
        for x in self.app.store["exclusions"]:
            self.ex.insert("end", x)
        self.sig_lbl.config(text=f"Записів у базі: {len(self.app.engine.sigs)}")

    def on_show(self):
        self.refresh()

    def save(self):
        s = self.app.store
        s["sens"], s["auto_q"], s["all_types"] = self.sens.get(), self.v_auto.get(), self.v_all.get()
        self.app.engine.cache.clear()

    def add_ex(self):
        d = filedialog.askdirectory(title="Папка-виняток")
        if d:
            self.app.store["exclusions"] = list(self.app.store["exclusions"]) + [d]
            self.refresh()

    def del_ex(self):
        sel = self.ex.curselection()
        if sel:
            ex = list(self.app.store["exclusions"])
            for i in reversed(sel):
                ex.pop(i)
            self.app.store["exclusions"] = ex
            self.refresh()

    def imp(self):
        f = filedialog.askopenfilename(title="Список хешів", filetypes=[("Текст / CSV", "*.txt *.csv *.list"), ("Усі файли", "*.*")])
        if f:
            try:
                n = self.app.engine.import_sigs(f)
                self.app.engine.cache.clear()
                self.app.notify(f"Імпортовано нових сигнатур: {n}", "ok")
                self.refresh()
            except OSError as e:
                self.app.notify(f"Не вдалося прочитати файл: {e}", "err")

    def reset(self):
        if messagebox.askyesno("Скидання", "Видалити всі імпортовані сигнатури?"):
            self.app.engine.reset_sigs()
            self.refresh()

    def make_eicar(self):
        d = DATA / "Test"
        d.mkdir(exist_ok=True)
        p = d / "eicar_test.txt"
        p.write_bytes(EICAR)
        self.app.notify(f"Тестовий файл створено: {p}. Просканіть цю папку, щоб побачити виявлення.", "ok")
        log(f"Створено тестовий файл EICAR: {p}")
        self.app.pages["scan"].start("custom", str(d))
        self.app.show("scan")

    def reload_log(self):
        try:
            lines = LOG_FILE.read_text("utf-8").splitlines()[-200:]
        except OSError:
            lines = []
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", "\n".join(lines) + ("\n" if lines else ""))
        self.log.see("end")
        self.log.config(state="disabled")

    def append_log(self, line):
        self.log.config(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def clear_log(self):
        try:
            LOG_FILE.write_text("", "utf-8")
        except OSError:
            pass
        self.reload_log()


# ───────────────────────────── Відновлення системи (функції в стилі NHelper) ─────────────────────────────
BACKUP_DIR = DATA / "Backups"
BACKUP_DIR.mkdir(exist_ok=True)
V64 = winreg.KEY_WOW64_64KEY if winreg else 0
_PENDING: list[dict] = []
APPROVED_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


def qps(s: str) -> str:
    return str(s).replace("'", "''")


def ps2(cmd: str, timeout: int | None = 300) -> tuple[int, str, str]:
    if not IS_WIN:
        return 1, "", "Лише Windows"
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd],
                           capture_output=True, timeout=timeout, creationflags=NOWIN)
        return r.returncode, r.stdout.decode("utf-8", "replace").strip(), r.stderr.decode("utf-8", "replace").strip()
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _need(ok):
    if not ok:
        raise OSError("операція не вдалася (можливо, потрібні права адміністратора)")


def _hive(h):
    return winreg.HKEY_CURRENT_USER if h == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def _ser(v):
    return {"hex": bytes(v).hex()} if isinstance(v, (bytes, bytearray)) else v


def _de(v):
    return bytes.fromhex(v["hex"]) if isinstance(v, dict) else v


def rg(h, path, name):
    try:
        with winreg.OpenKey(_hive(h), path, 0, winreg.KEY_READ | V64) as k:
            return winreg.QueryValueEx(k, name)
    except OSError:
        return None


def rnames(h, path):
    subs, vals = [], []
    try:
        with winreg.OpenKey(_hive(h), path, 0, winreg.KEY_READ | V64) as k:
            ns, nv, _ = winreg.QueryInfoKey(k)
            subs = [winreg.EnumKey(k, i) for i in range(ns)]
            vals = [winreg.EnumValue(k, i)[0] for i in range(nv)]
    except OSError:
        pass
    return subs, vals


def rexists(h, path) -> bool:
    try:
        with winreg.OpenKey(_hive(h), path, 0, winreg.KEY_READ | V64):
            return True
    except OSError:
        return False


def _backup(h, path, name):
    v = rg(h, path, name)
    _PENDING.append(dict(h=h, path=path, name=name, existed=v is not None,
                         type=v[1] if v else None, data=_ser(v[0]) if v else None))


def rset(h, path, name, value, rtype=None):
    _backup(h, path, name)
    if rtype is None:
        rtype = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
    with winreg.CreateKeyEx(_hive(h), path, 0, winreg.KEY_SET_VALUE | V64) as k:
        winreg.SetValueEx(k, name, 0, rtype, value)


def rdel(h, path, name):
    _backup(h, path, name)
    with winreg.OpenKey(_hive(h), path, 0, winreg.KEY_SET_VALUE | V64) as k:
        winreg.DeleteValue(k, name)


def rtree_delete(h, path):
    def collect(p):
        subs, vals = rnames(h, p)
        for n in vals:
            v = rg(h, p, n)
            if v:
                _PENDING.append(dict(h=h, path=p, name=n, existed=True, type=v[1], data=_ser(v[0])))
        for s in subs:
            collect(p + "\\" + s)

    def drop(p):
        for s in rnames(h, p)[0]:
            drop(p + "\\" + s)
        winreg.DeleteKeyEx(_hive(h), p, V64, 0)
    collect(path)
    drop(path)


def commit_backup(label: str) -> Path | None:
    if not _PENDING:
        return None
    f = BACKUP_DIR / f"{datetime.now():%Y%m%d_%H%M%S}.json"
    f.write_text(json.dumps(dict(label=label, items=list(_PENDING)), ensure_ascii=False, indent=1), "utf-8")
    _PENDING.clear()
    log(f"Збережено резервну копію змін реєстру: {f.name} ({label})")
    return f


def restore_last_backup() -> tuple[bool, str]:
    files = sorted(BACKUP_DIR.glob("*.json"))
    if not files:
        return False, "Резервних копій немає"
    f = files[-1]
    try:
        data = json.loads(f.read_text("utf-8"))
        for it in reversed(data["items"]):
            h, path, name = it["h"], it["path"], it["name"]
            if it["existed"]:
                with winreg.CreateKeyEx(_hive(h), path, 0, winreg.KEY_SET_VALUE | V64) as k:
                    winreg.SetValueEx(k, name, 0, it["type"], _de(it["data"]))
            else:
                try:
                    with winreg.OpenKey(_hive(h), path, 0, winreg.KEY_SET_VALUE | V64) as k:
                        winreg.DeleteValue(k, name)
                except OSError:
                    pass
        f.rename(f.with_suffix(".restored"))
        log(f"Відкочено зміни з {f.name}: {data.get('label')}")
        return True, data.get("label", f.name)
    except (OSError, ValueError, KeyError) as e:
        return False, str(e)


POL_SYS = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
POL_EXP = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
POL_WD = r"SOFTWARE\Policies\Microsoft\Windows Defender"
POLICIES = [
    ("HKCU", POL_SYS, "DisableTaskMgr", "Диспетчер завдань заблоковано"),
    ("HKLM", POL_SYS, "DisableTaskMgr", "Диспетчер завдань заблоковано (для всіх)"),
    ("HKCU", POL_SYS, "DisableRegistryTools", "Редактор реєстру заблоковано"),
    ("HKLM", POL_SYS, "DisableRegistryTools", "Редактор реєстру заблоковано (для всіх)"),
    ("HKCU", POL_SYS, "DisableLockWorkstation", "Блокування комп'ютера вимкнено"),
    ("HKCU", POL_SYS, "DisableChangePassword", "Зміну пароля заблоковано"),
    ("HKCU", r"Software\Policies\Microsoft\Windows\System", "DisableCMD", "Командний рядок заблоковано"),
    ("HKLM", r"Software\Policies\Microsoft\Windows\System", "DisableCMD", "Командний рядок заблоковано (для всіх)"),
    ("HKCU", POL_EXP, "NoRun", "Вікно «Виконати» заблоковано"),
    ("HKCU", POL_EXP, "NoControlPanel", "Панель керування заблоковано"),
    ("HKCU", POL_EXP, "NoFolderOptions", "Параметри папок заблоковано"),
    ("HKCU", POL_EXP, "NoViewContextMenu", "Контекстне меню заблоковано"),
    ("HKCU", POL_EXP, "NoDesktop", "Елементи робочого стола приховано"),
    ("HKLM", POL_WD, "DisableAntiSpyware", "Defender вимкнено політикою (AntiSpyware)"),
    ("HKLM", POL_WD, "DisableAntiVirus", "Defender вимкнено політикою (AntiVirus)"),
    ("HKLM", POL_WD + r"\Real-Time Protection", "DisableRealtimeMonitoring", "Захист Defender у реальному часі вимкнено політикою"),
    ("HKLM", POL_WD + r"\Real-Time Protection", "DisableBehaviorMonitoring", "Поведінковий захист Defender вимкнено політикою"),
    ("HKLM", POL_WD + r"\Real-Time Protection", "DisableOnAccessProtection", "Перевірку при доступі Defender вимкнено політикою"),
    ("HKLM", r"SOFTWARE\Policies\Microsoft\MRT", "DontOfferThroughWUAU", "Засіб видалення шкідливих програм заблоковано"),
]
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
IFEO32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
ASSOC = {".exe": "exefile", ".com": "comfile", ".bat": "batfile", ".cmd": "cmdfile", ".lnk": "lnkfile",
         ".reg": "regfile", ".msi": "Msi.Package", ".vbs": "VBSFile", ".js": "JSFile"}
BROWSER_POLICIES = [("HKLM", r"SOFTWARE\Policies\Google\Chrome", "Chrome"), ("HKCU", r"SOFTWARE\Policies\Google\Chrome", "Chrome"),
                    ("HKLM", r"SOFTWARE\Policies\Microsoft\Edge", "Edge"), ("HKCU", r"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
                    ("HKLM", r"SOFTWARE\Policies\Mozilla\Firefox", "Firefox")]


@dataclass
class Fix:
    cat: str
    title: str
    detail: str
    level: str
    apply: object


def build_fixes() -> list[Fix]:
    out: list[Fix] = []
    if not IS_WIN or not winreg:
        return out
    # 1) Обмеження, які ставлять віруси та «блокувальники»
    for h, path, name, title in POLICIES:
        v = rg(h, path, name)
        if v and v[0] not in (0, None, ""):
            out.append(Fix("Обмеження", title, f"{h}\\{path} → {name} = {v[0]}", "bad",
                           lambda h=h, p=path, n=name: rdel(h, p, n)))
    # 2) Відладчики IFEO (підміна запуску програм)
    for base in (IFEO, IFEO32):
        for s in rnames("HKLM", base)[0]:
            v = rg("HKLM", base + "\\" + s, "Debugger")
            if v and v[0]:
                out.append(Fix("Відладчики IFEO", f"Підміна запуску «{s}»", f"Debugger = {v[0]}  (легальні програми, напр. Process Explorer, теж так роблять)",
                               "bad", lambda b=base, s=s: rdel("HKLM", b + "\\" + s, "Debugger")))
    # 2b) Бекдор екрана входу: sethc.exe, utilman.exe та інші службові програми спеціальних
    # можливостей, підмінені на cmd.exe. Класичний спосіб отримати доступ до системи без пароля
    # (кнопка «Спеціальні можливості» на екрані блокування запускає командний рядок із правами SYSTEM).
    sysdir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "system32")
    cmd_path = os.path.join(sysdir, "cmd.exe")
    if os.path.isfile(cmd_path):
        try:
            cmd_sha = Engine._read(cmd_path, keep=0)[0]
        except OSError:
            cmd_sha = None
        if cmd_sha:
            for name in ("sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe", "AtBroker.exe"):
                p = os.path.join(sysdir, name)
                if os.path.isfile(p):
                    try:
                        same = Engine._read(p, keep=0)[0] == cmd_sha
                    except OSError:
                        same = False
                    if same:
                        out.append(Fix("Бекдор входу в систему", f"«{name}» замінено на cmd.exe", "На екрані блокування кнопка спеціальних можливостей "
                                       "відкриває командний рядок із системними правами — паролі так обходять. "
                                       "Автоматичне виправлення недоступне: запустіть «Перевірка системних файлів (SFC)» на вкладці «Інструменти», "
                                       "вона відновить оригінальний файл.", "bad", None))
    # 3) Winlogon
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    shell = rg("HKLM", wl, "Shell")
    if shell and str(shell[0]).strip().lower() != "explorer.exe":
        out.append(Fix("Winlogon", "Підмінено оболонку Windows (Shell)", f"Shell = {shell[0]}", "bad",
                       lambda: rset("HKLM", wl, "Shell", "explorer.exe")))
    ui = rg("HKLM", wl, "Userinit")
    if ui and str(ui[0]).strip().lower().rstrip(",") != (sysdir + "\\userinit.exe").lower():
        out.append(Fix("Winlogon", "Підмінено Userinit", f"Userinit = {ui[0]}", "bad",
                       lambda: rset("HKLM", wl, "Userinit", sysdir + "\\userinit.exe,")))
    if rg("HKLM", wl, "Taskman"):
        out.append(Fix("Winlogon", "Перехоплено Диспетчер завдань (Taskman)", f"Taskman = {rg('HKLM', wl, 'Taskman')[0]}", "bad",
                       lambda: rdel("HKLM", wl, "Taskman")))
    # 4) Файлові асоціації
    for ext, cls in ASSOC.items():
        cur = rg("HKLM", r"SOFTWARE\Classes\\" + ext, "")
        if cur and str(cur[0]).lower() != cls.lower():
            out.append(Fix("Асоціації файлів", f"Асоціацію {ext} змінено", f"Зараз: {cur[0]}, має бути: {cls}", "bad",
                           lambda e=ext, c=cls: rset("HKLM", r"SOFTWARE\Classes\\" + e, "", c)))
        if rexists("HKCU", r"Software\Classes\\" + ext):
            out.append(Fix("Асоціації файлів", f"Користувацьке перевизначення {ext}", "У HKCU\\Software\\Classes є запис, який перекриває системний", "warn",
                           lambda e=ext: rtree_delete("HKCU", r"Software\Classes\\" + e)))
    cmd = rg("HKLM", r"SOFTWARE\Classes\exefile\shell\open\command", "")
    if cmd and str(cmd[0]).strip() not in ('"%1" %*', "\"%1\" %*"):
        out.append(Fix("Асоціації файлів", "Змінено команду запуску .exe", f"Зараз: {cmd[0]}", "bad",
                       lambda: rset("HKLM", r"SOFTWARE\Classes\exefile\shell\open\command", "", '"%1" %*')))
    # 5) Проксі
    ie = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    pe, pserv, pac = rg("HKCU", ie, "ProxyEnable"), rg("HKCU", ie, "ProxyServer"), rg("HKCU", ie, "AutoConfigURL")
    if (pe and pe[0] == 1) or pac:
        def fix_proxy():
            rset("HKCU", ie, "ProxyEnable", 0)
            if pserv:
                rdel("HKCU", ie, "ProxyServer")
            if pac:
                rdel("HKCU", ie, "AutoConfigURL")
        out.append(Fix("Мережа", "Увімкнено проксі-сервер", f"Сервер: {pserv[0] if pserv else '—'}; PAC: {pac[0] if pac else '—'}  "
                       "(у корпоративних мережах так і має бути)", "warn", fix_proxy))
    # 6) Файл hosts
    hs = hosts_suspicious()
    if hs:
        out.append(Fix("Мережа", "Підозрілі перенаправлення в hosts", f"Записів: {len(hs)}, напр. {hs[0][:70]}", "bad",
                       lambda: _need(fix_hosts())))
    # 7) Провідник
    hide = rg("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt")
    if hide and hide[0] == 1:
        out.append(Fix("Провідник", "Розширення файлів приховано", "Так шкідливі файли маскуються (document.pdf.exe)", "warn",
                       lambda: rset("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0)))
    # 8) Винятки Defender, додані зловмисниками
    ex = (ps_json("Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension", 40) or [{}])[0]
    for key in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension"):
        vals = ex.get(key) or []
        vals = [vals] if isinstance(vals, str) else vals
        for v in vals:
            if v and not str(v).startswith("N/A"):
                out.append(Fix("Винятки Defender", f"Виняток: {v}", key, "warn",
                               lambda k=key, v=v: _need(ps2(f"Remove-MpPreference -{k} '{qps(v)}'", 60)[0] == 0)))
    # 9) Примусові політики браузерів (адвер/викрадачі домашньої сторінки)
    for h, path, br in BROWSER_POLICIES:
        if rexists(h, path):
            subs, vals = rnames(h, path)
            if subs or vals:
                names = ", ".join((vals + subs)[:5])
                out.append(Fix("Браузери", f"Примусові політики {br}", f"{h}\\{path}: {names}  (на робочих ПК їх задає адміністратор)", "warn",
                               lambda h=h, p=path: rtree_delete(h, p)))
    # 10) Заблоковано запуск певних програм (DisallowRun) — популярна «заборона» у вірусів:
    # taskmgr.exe, regedit.exe, cmd.exe тощо просто не запускаються
    for h in ("HKCU", "HKLM"):
        base = POL_EXP
        restrict = rg(h, base, "RestrictRun")
        if restrict and restrict[0] == 1:
            sub = base + r"\DisallowRun"
            progs = [str(rg(h, sub, n)[0]) for n in rnames(h, sub)[1] if rg(h, sub, n)]
            if progs:
                def _fix_disallow(h=h, base=base, sub=sub):
                    rset(h, base, "RestrictRun", 0)
                    rtree_delete(h, sub)
                out.append(Fix("Обмеження", "Заблоковано запуск певних програм", f"{h}: {', '.join(progs[:6])}"
                               + ("…" if len(progs) > 6 else ""), "bad", _fix_disallow))
    # 11) Приховано літери дисків у Провіднику
    for h in ("HKCU", "HKLM"):
        nd = rg(h, POL_EXP, "NoDrives")
        if nd and nd[0]:
            out.append(Fix("Обмеження", "Приховано диски в Провіднику", f"{h}\\...\\Explorer: NoDrives = {nd[0]}",
                           "bad", lambda h=h: rset("HKCU" if h == "HKCU" else "HKLM", POL_EXP, "NoDrives", 0)))
    # 12) Приховані файли не показуються (віруси часто ховають файли користувача на флешках/диску)
    adv = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    hid = rg("HKCU", adv, "Hidden")
    if hid and hid[0] == 2:
        out.append(Fix("Обмеження", "Приховані файли не відображаються", "Explorer\\Advanced: Hidden = 2 (увімкнути показ прихованих файлів)",
                       "warn", lambda: rset("HKCU", adv, "Hidden", 1)))
    return out


# ───────────────────────────── Автозавантаження: усі типи ─────────────────────────────
SUSP_CMD = re.compile(r"\\temp\\|\\downloads\\|\\users\\public\\|powershell[^|]*\s-e(nc|ncodedcommand)?\s|mshta|wscript|cscript|"
                      r"regsvr32[^|]*scrobj|\.vbs|\.js\b|javascript:|https?://", re.I)


def extract_path(cmd: str) -> str:
    cmd = os.path.expandvars(str(cmd).strip())
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    m = re.match(r"^[A-Za-z]:\\.*?\.(exe|bat|cmd|ps1|vbs|js|dll|com|scr|msi|lnk)\b", cmd, re.I)
    return m.group(0) if m else cmd.split(" ")[0]


def entry_risk(cmd: str) -> str:
    if SUSP_CMD.search(cmd):
        return "Підозрілий шлях або команда"
    p = extract_path(cmd)
    if re.match(r"^[a-z]:\\", p, re.I) and not os.path.exists(p):
        return "Файл не існує (залишок видаленої програми)"
    return ""


def approved_enabled(h, sub, name) -> bool:
    v = rg(h, APPROVED_PATH + "\\" + sub, name)
    return not (v and isinstance(v[0], (bytes, bytearray)) and v[0] and v[0][0] % 2 == 1)


def set_approved(h, sub, name, enabled: bool):
    ft = int((time.time() + 11644473600) * 10 ** 7).to_bytes(8, "little")
    data = (b"\x02\x00\x00\x00" + b"\x00" * 8) if enabled else (b"\x03\x00\x00\x00" + ft)
    rset(h, APPROVED_PATH + "\\" + sub, name, data, winreg.REG_BINARY)


def collect_autoruns() -> list[dict]:
    items: list[dict] = []
    if not IS_WIN or not winreg:
        return items
    cv = r"Software\Microsoft\Windows\CurrentVersion"
    srcs = [("HKCU", cv + r"\Run", "Run", "Реєстр · користувач"), ("HKLM", cv + r"\Run", "Run", "Реєстр · система"),
            ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run32", "Реєстр · система (32-біт)"),
            ("HKCU", cv + r"\RunOnce", "", "Реєстр · RunOnce (користувач)"), ("HKLM", cv + r"\RunOnce", "", "Реєстр · RunOnce (система)")]
    for h, path, sub, where in srcs:
        try:
            with winreg.OpenKey(_hive(h), path, 0, winreg.KEY_READ | V64) as k:
                for i in range(winreg.QueryInfoKey(k)[1]):
                    name, val, _ = winreg.EnumValue(k, i)
                    items.append(dict(kind="reg", h=h, path=path, sub=sub, name=name, cmd=str(val), where=where,
                                      enabled=approved_enabled(h, sub, name) if sub else True))
        except OSError:
            pass
    A, PD = os.environ.get("APPDATA", ""), os.environ.get("PROGRAMDATA", "")
    for h, where, d in (("HKCU", "Папка · користувач", os.path.join(A, r"Microsoft\Windows\Start Menu\Programs\Startup")),
                        ("HKLM", "Папка · усі користувачі", os.path.join(PD, r"Microsoft\Windows\Start Menu\Programs\StartUp"))):
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.lower() != "desktop.ini":
                    items.append(dict(kind="file", h=h, sub="StartupFolder", name=f, cmd=os.path.join(d, f), where=where,
                                      enabled=approved_enabled(h, "StartupFolder", f)))
    for t in ps_json(r"Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { [pscustomobject]@{ "
                     r"Name=$_.TaskName; Path=$_.TaskPath; State=[string]$_.State; "
                     r"Cmd=(($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join '; ') } }", 90):
        items.append(dict(kind="task", name=str(t.get("Name")), tpath=str(t.get("Path") or "\\"), cmd=str(t.get("Cmd") or ""),
                          where="Планувальник завдань", enabled=str(t.get("State")) != "Disabled"))
    for s in ps_json(r"Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch 'Windows\\|Microsoft' } "
                     r"| Select-Object Name,DisplayName,PathName", 90):
        items.append(dict(kind="service", name=str(s.get("Name")), cmd=str(s.get("PathName") or ""),
                          where="Служба (не Microsoft)", enabled=True))
    for it in items:
        it["risk"] = entry_risk(it["cmd"])
    return items


class AutorunPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Автозавантаження", "Усі типи: реєстр, папки, планувальник завдань і служби. Підозрілі записи підсвічено.")
        self.items: dict[str, dict] = {}
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        frame, self.tree = make_tree(self, [("st", "Стан", 90, False), ("name", "Назва", 190, False), ("cmd", "Команда", 360, True),
                                            ("where", "Джерело", 180, False), ("risk", "Оцінка", 230, False)], selectmode="browse")
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Видалити запис", self.remove, "danger").pack(side="right")
        Btn(foot, "Сканувати файл", self.scan_one, "ghost").pack(side="right", padx=8)
        Btn(foot, "Увімк./вимк.", self.toggle, "primary").pack(side="right")
        Btn(foot, "Оновити", self.load, "ghost").pack(side="right", padx=8)

    def on_show(self):
        if IS_WIN:
            self.load()

    def load(self):
        self.info.config(text="Збираю записи (планувальник і служби — кілька секунд)…")
        self.app.bg(collect_autoruns, self.fill)

    def fill(self, rows):
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        if isinstance(rows, Exception):
            self.info.config(text=f"Помилка: {rows}")
            return
        rows.sort(key=lambda r: (not r["risk"], r["where"], r["name"].lower()))
        for r in rows:
            tag = () if not r["risk"] else ("high",) if r["risk"].startswith("Підозр") else ("medium",)
            iid = self.tree.insert("", "end", tags=tag, values=("Увімкнено" if r["enabled"] else "Вимкнено", r["name"],
                                                               r["cmd"], r["where"], r["risk"] or "—"))
            self.items[iid] = r
        bad = sum(1 for r in rows if r["risk"])
        self.info.config(text=f"Записів: {len(rows)} · потребують уваги: {bad}")

    def _sel(self):
        s = self.tree.selection()
        return self.items.get(s[0]) if s else None

    def toggle(self):
        it = self._sel()
        if not it:
            self.app.notify("Виберіть запис", "err")
            return
        new = not it["enabled"]

        def work():
            if it["kind"] in ("reg", "file"):
                if not it.get("sub"):
                    raise OSError("запис RunOnce не можна вимкнути — лише видалити")
                set_approved(it["h"], it["sub"], it["name"], new)
                commit_backup("Автозавантаження: зміна стану")
            elif it["kind"] == "task":
                verb = "Enable" if new else "Disable"
                _need(ps2(f"{verb}-ScheduledTask -TaskPath '{qps(it['tpath'])}' -TaskName '{qps(it['name'])}'", 60)[0] == 0)
            else:
                cmd = (f"Set-Service -Name '{qps(it['name'])}' -StartupType Automatic" if new else
                       f"Set-Service -Name '{qps(it['name'])}' -StartupType Disabled; "
                       f"Stop-Service -Name '{qps(it['name'])}' -Force -ErrorAction SilentlyContinue")
                _need(ps2(cmd, 60)[0] == 0)

        self.app.bg(work, lambda r: (self.app.notify("Стан змінено" if not isinstance(r, Exception) else f"Помилка: {r}",
                                                      "ok" if not isinstance(r, Exception) else "err"), self.load()))

    def remove(self):
        it = self._sel()
        if not it:
            self.app.notify("Виберіть запис", "err")
            return
        if not messagebox.askyesno("Видалення", f"Остаточно видалити «{it['name']}» з автозавантаження?\n"
                                   "Щоб лише тимчасово вимкнути — скористайтеся «Увімк./вимк.»."):
            return

        def work():
            if it["kind"] == "reg":
                rdel(it["h"], it["path"], it["name"])
                commit_backup("Автозавантаження: видалення запису")
            elif it["kind"] == "file":
                os.remove(it["cmd"])
            elif it["kind"] == "task":
                _need(ps2(f"Unregister-ScheduledTask -TaskPath '{qps(it['tpath'])}' -TaskName '{qps(it['name'])}' -Confirm:$false", 60)[0] == 0)
            else:
                _need(ps2(f"Stop-Service -Name '{qps(it['name'])}' -Force -ErrorAction SilentlyContinue; sc.exe delete '{qps(it['name'])}'", 60)[0] == 0)
            log(f"Видалено з автозавантаження: {it['where']} · {it['name']}")

        self.app.bg(work, lambda r: (self.app.notify("Запис видалено" if not isinstance(r, Exception) else f"Помилка: {r}",
                                                      "ok" if not isinstance(r, Exception) else "err"), self.load()))

    def scan_one(self):
        it = self._sel()
        p = extract_path(it["cmd"]) if it else ""
        if not p or not os.path.isfile(p):
            self.app.notify("Файл не знайдено на диску", "err")
            return
        det = self.app.engine.scan_file(p, deep=True)
        if det:
            self.app.pages["scan"].add_detection(det)
            self.app.show("scan")
            self.app.notify(f"Виявлено: {det.name}", "err")
        else:
            self.app.notify("Файл не містить відомих загроз", "ok")


# ───────────────────────────── Сторінка «Відновлення» ─────────────────────────────
class RepairPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Відновлення після вірусів", "Усуває наслідки зараження: блокування, підміни в реєстрі, відладчики, hosts, проксі")
        self.items: dict[str, Fix] = {}
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        bar = Card(self)
        bar.pack(fill="x", padx=28, pady=(0, 12))
        r = tk.Frame(bar, bg=CARD)
        r.pack(fill="x", padx=14, pady=12)
        lbl(r, "Усі зміни реєстру зберігаються в резервну копію — їх можна відкотити.", MUTED, 9).pack(side="left")
        Btn(r, "Точка відновлення", self.restore_point, "ghost").pack(side="right")
        Btn(r, "Відкотити останню зміну", self.rollback, "ghost").pack(side="right", padx=8)
        frame, self.tree = make_tree(self, [("cat", "Категорія", 150, False), ("title", "Проблема", 290, False),
                                            ("detail", "Деталі", 460, True), ("fix", "Виправлення", 110, False)])
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Виправити все", lambda: self.fix(True), "danger").pack(side="right")
        Btn(foot, "Виправити вибране", lambda: self.fix(False), "primary").pack(side="right", padx=8)
        Btn(foot, "Шукати проблеми", self.scan, "ghost").pack(side="right")
        self.first = True

    def on_show(self):
        if IS_WIN and self.first:
            self.first = False
            self.scan()

    def scan(self):
        self.info.config(text="Аналізую систему…")
        self.app.bg(build_fixes, self.fill)

    def fill(self, res):
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        if isinstance(res, Exception):
            self.info.config(text=f"Помилка: {res}")
            return
        for f in res:
            iid = self.tree.insert("", "end", tags=(f.level,),
                                   values=(f.cat, f.title, f.detail, "автоматично" if f.apply else "вручну (SFC)"))
            self.items[iid] = f
        self.info.config(text="Проблем не знайдено ✓" if not res else f"Знайдено проблем: {len(res)}")

    def fix(self, everything: bool):
        ids = list(self.items) if everything else [i for i in self.tree.selection() if i in self.items]
        if not ids:
            self.app.notify("Оберіть проблеми у списку", "err")
            return
        if not messagebox.askyesno("Виправлення", f"Виправити проблем: {len(ids)}?\nЗміни реєстру можна буде відкотити.\n"
                                   "Рекомендуємо спершу створити точку відновлення."):
            return
        fixes = [self.items[i] for i in ids]
        manual = sum(1 for f in fixes if not f.apply)

        def work():
            ok, fails = 0, []
            for f in fixes:
                if not f.apply:
                    continue
                try:
                    f.apply()
                    ok += 1
                except Exception as e:  # noqa: BLE001
                    fails.append(f"{f.title}: {e}")
            commit_backup(f"Відновлення: {ok} виправлень")
            for line in fails:
                log("Не виправлено — " + line)
            return ok, fails

        def done(res):
            if isinstance(res, Exception):
                self.app.notify(f"Помилка: {res}", "err")
                return
            ok, fails = res
            msg = f"Виправлено: {ok}"
            if manual:
                msg += f", вручну через SFC: {manual}"
            if fails:
                msg += f", не вдалося: {len(fails)} (потрібні права адміністратора?)"
            self.app.notify(msg, "err" if fails else "ok")
            self.scan()
        self.app.bg(work, done)

    def rollback(self):
        if not messagebox.askyesno("Відкат", "Відкотити останню групу змін реєстру?"):
            return
        ok, res = restore_last_backup()
        self.app.notify(f"Відкочено: {res}" if ok else f"Не вдалося: {res}", "ok" if ok else "err")
        self.scan()

    def restore_point(self):
        self.app.notify("Створюю точку відновлення…")

        def work():
            return ps2("Checkpoint-Computer -Description 'UA Shield' -RestorePointType MODIFY_SETTINGS", 180)

        def done(r):
            if isinstance(r, Exception) or r[0] != 0:
                err = (r[2] if not isinstance(r, Exception) else str(r))[:160]
                self.app.notify(f"Не вдалося створити точку (потрібен адмін / захист системи): {err}", "err")
            else:
                self.app.notify("Точку відновлення створено", "ok")
        self.app.bg(work, done)


# ───────────────────────────── Інструменти (SFC, DISM, мережа, флешка…) ─────────────────────────────
HIDE_SKIP = {"system volume information", "$recycle.bin", "recycler"}
SCRIPT_ROOT = {".vbs", ".vbe", ".wsf", ".js", ".jse", ".bat", ".cmd", ".scr", ".pif", ".hta"}


def usb_scan(root: str) -> list[tuple[str, str]]:
    sus = []
    try:
        entries = os.listdir(root)
    except OSError:
        return sus
    folders = {e.lower() for e in entries if os.path.isdir(os.path.join(root, e))}
    for e in entries:
        p = os.path.join(root, e)
        if os.path.isdir(p):
            continue
        stem, ext = os.path.splitext(e.lower())
        if ext == ".lnk":
            sus.append((p, "ярлик у корені флешки (підміна папки)"))
        elif ext in SCRIPT_ROOT:
            sus.append((p, "скрипт/виконуваний файл у корені"))
        elif e.lower() == "autorun.inf":
            sus.append((p, "autorun.inf"))
        elif ext == ".exe" and stem in folders:
            sus.append((p, "програма з назвою існуючої папки"))
    return sus


def usb_unhide(root: str) -> int:
    if not IS_WIN:
        return 0
    k32, n = ctypes.windll.kernel32, 0

    def clear(p):
        nonlocal n
        a = k32.GetFileAttributesW(p)
        if a != 0xFFFFFFFF and a & 6:
            new = (a & ~6) or 0x80
            if k32.SetFileAttributesW(p, new):
                n += 1
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x.lower() not in HIDE_SKIP]
        for x in dirs + files:
            clear(os.path.join(d, x))
    return n


def clean_temp() -> int:
    freed = 0
    for d in {tempfile.gettempdir(), os.path.join(os.environ.get("WINDIR", ""), "Temp") if IS_WIN else ""}:
        if not d or not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d, topdown=False):
            for f in files:
                p = os.path.join(root, f)
                try:
                    s = os.path.getsize(p)
                    os.remove(p)
                    freed += s
                except OSError:
                    pass
            for x in dirs:
                try:
                    os.rmdir(os.path.join(root, x))
                except OSError:
                    pass
    return freed


def run_stream(args, emit):
    import codecs
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=NOWIN)
    dec = None
    while True:
        chunk = os.read(p.stdout.fileno(), 4096)
        if not chunk:
            break
        if dec is None:
            enc = "utf-16-le" if b"\x00" in chunk else f"cp{ctypes.windll.kernel32.GetOEMCP()}"
            dec = codecs.getincrementaldecoder(enc)(errors="replace")
        for line in re.split(r"[\r\n]+", dec.decode(chunk)):
            if line.strip().strip("\x00"):
                emit(line.strip())
    return p.wait()


class ToolsPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Інструменти відновлення", "Перевірка системних файлів, мережа, флешки, швидкий доступ до системних консолей")
        self.busy = False
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True, padx=(28, 18))
        grid = sf.inner
        grid.columnconfigure((0, 1), weight=1, uniform="t")
        tools = [
            ("Перевірка системних файлів (SFC)", "sfc /scannow — перевіряє й відновлює пошкоджені файли Windows. Потрібен адмін.", "Запустити", self.t_sfc),
            ("Відновлення образу (DISM)", "DISM /RestoreHealth — лагодить сховище компонентів. Потрібен адмін і інтернет.", "Запустити", self.t_dism),
            ("Перевірка диска (CHKDSK)", "chkdsk /scan на системному диску — пошук помилок файлової системи.", "Запустити", self.t_chk),
            ("Скидання мережі", "winsock reset, ip reset, скидання DNS. Лікує «зламаний» інтернет після вірусів; потрібне перезавантаження.", "Скинути", self.t_net),
            ("Лікування флешки від «ярликів»", "Видаляє ярлики-підміни та скрипти в корені флешки й повертає видимість прихованим папкам.", "Обрати диск…", self.t_usb),
            ("Очистити тимчасові файли", "TEMP користувача та Windows\\Temp.", "Очистити", self.t_temp),
            ("DNS на автоматичні", "Прибирає підмінені DNS-сервери в мережевих адаптерах. Потрібен адмін.", "Скинути DNS", self.t_dns),
            ("Системні консолі", "Швидкий запуск стандартних інструментів Windows.", "", None),
        ]
        for i, (t, d, b, fn) in enumerate(tools):
            c = Card(grid)
            c.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0, 12) if i % 2 == 0 else (0, 10), pady=(0, 12))
            lbl(c, t, TEXT, 11, True).pack(anchor="w", padx=16, pady=(14, 2))
            lbl(c, d, MUTED, 9, wraplength=380, justify="left").pack(anchor="w", padx=16)
            if fn:
                Btn(c, b, fn, "ghost").pack(anchor="w", padx=16, pady=(10, 14))
            else:
                r = tk.Frame(c, bg=CARD)
                r.pack(anchor="w", padx=16, pady=(10, 14))
                for name, cmd in (("Диспетчер", "taskmgr"), ("Реєстр", "regedit"), ("Служби", "services.msc"),
                                  ("msconfig", "msconfig"), ("Програми", "appwiz.cpl")):
                    Btn(r, name, lambda c=cmd: self.launch(c), "ghost").pack(side="left", padx=(0, 6))
        mbr = Card(grid)
        mbr.grid(row=len(tools) // 2, column=0, columnspan=2, sticky="nsew", pady=(0, 12))
        lbl(mbr, "Відновлення завантажувача (MBR/BCD)", TEXT, 11, True).pack(anchor="w", padx=16, pady=(14, 2))
        lbl(mbr, "Для пошкодженого завантажувача після вірусів-буткітів чи некоректного вимкнення. "
            "Якщо Windows узагалі не стартує — краще виконати це із середовища відновлення "
            "(встановлювальна флешка Windows → «Відновлення системи» → «Командний рядок»), а не звідси.",
            MUTED, 9, wraplength=820, justify="left").pack(anchor="w", padx=16)
        r1 = tk.Frame(mbr, bg=CARD)
        r1.pack(anchor="w", padx=16, pady=(10, 4))
        Btn(r1, "Перевірити встановлення Windows", self.t_scanos, "ghost").pack(side="left", padx=(0, 6))
        Btn(r1, "Відновити MBR", self.t_fixmbr, "warn").pack(side="left", padx=(0, 6))
        Btn(r1, "Відновити сектор завантаження", self.t_fixboot, "warn").pack(side="left", padx=(0, 6))
        r2 = tk.Frame(mbr, bg=CARD)
        r2.pack(anchor="w", padx=16, pady=(4, 14))
        Btn(r2, "Перебудувати BCD", self.t_rebuildbcd, "warn").pack(side="left", padx=(0, 6))
        Btn(r2, "Перезавантажити в середовище відновлення", self.t_winre, "ghost").pack(side="left")

        self.prog = lbl(self, "", ACCENT, 9, anchor="w")
        self.prog.pack(fill="x", padx=28)
        self.out = tk.Text(self, bg=CARD, fg=MUTED, bd=0, highlightthickness=0, font=("Consolas", 9), height=8,
                           padx=12, pady=10, wrap="word", state="disabled")
        self.out.pack(fill="x", padx=28, pady=(4, 18))

    # --- консоль
    def write(self, t):
        self.out.config(state="normal")
        self.out.insert("end", t + "\n")
        self.out.see("end")
        self.out.config(state="disabled")

    def line(self, text):
        m = re.search(r"(\d{1,3})\s*%", text)
        if m and len(text) < 90:
            self.prog.config(text=text)
        else:
            self.write(text)

    def need_admin(self):
        if not is_admin():
            self.app.notify("Для цієї дії потрібні права адміністратора (кнопка на вкладці «Захист»)", "err")
            return False
        return True

    def stream(self, title, commands, admin=True):
        if self.busy:
            self.app.notify("Дочекайтесь завершення поточної операції", "err")
            return
        if admin and not self.need_admin():
            return
        self.busy = True
        self.write(f"▶ {title}")
        log(f"Інструмент: {title}")

        def work():
            codes = []
            for c in commands:
                self.app.ui(self.write, "$ " + " ".join(c))
                codes.append(run_stream(c, lambda s: self.app.ui(self.line, s)))
            return codes

        def done(res):
            self.busy = False
            self.prog.config(text="")
            self.write("✓ Завершено" if not isinstance(res, Exception) else f"✖ Помилка: {res}")
        self.app.bg(work, done)

    def t_sfc(self):
        self.stream("Перевірка системних файлів", [["sfc", "/scannow"]])

    def t_dism(self):
        self.stream("Відновлення образу Windows", [["DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"]])

    def t_chk(self):
        self.stream("Перевірка диска", [["chkdsk", os.environ.get("SystemDrive", "C:"), "/scan"]])

    def t_net(self):
        if messagebox.askyesno("Скидання мережі", "Буде скинуто мережеві налаштування. Потрібне перезавантаження. Продовжити?"):
            self.stream("Скидання мережі", [["netsh", "winsock", "reset"], ["netsh", "int", "ip", "reset"], ["ipconfig", "/flushdns"]])

    def t_dns(self):
        if not self.need_admin():
            return
        self.app.bg(lambda: ps2("Get-DnsClient | Set-DnsClientServerAddress -ResetServerAddresses", 60),
                    lambda r: self.app.notify("DNS скинуто на автоматичні" if not isinstance(r, Exception) and r[0] == 0
                                              else "Не вдалося скинути DNS", "ok" if not isinstance(r, Exception) and r[0] == 0 else "err"))

    def t_temp(self):
        self.app.bg(clean_temp, lambda r: self.app.notify(f"Звільнено {fmt_size(r)}" if not isinstance(r, Exception) else str(r), "ok"))

    def t_scanos(self):
        self.stream("Пошук встановлень Windows (bootrec /scanos)", [["bootrec", "/scanos"]])

    def t_fixmbr(self):
        if messagebox.askyesno("Відновлення MBR", "Записати стандартний головний завантажувальний запис (MBR) "
                               "на системний диск?\nЦе офіційна команда Microsoft (bootrec /fixmbr) — вона не "
                               "зачіпає таблицю розділів і ваші файли, лише код запуску завантажувача."):
            self.stream("Відновлення MBR (bootrec /fixmbr)", [["bootrec", "/fixmbr"]])

    def t_fixboot(self):
        if messagebox.askyesno("Відновлення сектора завантаження",
                               "Записати новий завантажувальний сектор на системний розділ (bootrec /fixboot)?"):
            self.stream("Відновлення сектора завантаження (bootrec /fixboot)", [["bootrec", "/fixboot"]])

    def t_rebuildbcd(self):
        if messagebox.askyesno("Перебудова BCD", "Перебудувати конфігурацію завантаження (bootrec /rebuildbcd)?\n"
                               "Інструмент знайде встановлення Windows на дисках і запропонує додати їх до меню завантаження."):
            self.stream("Перебудова BCD (bootrec /rebuildbcd)", [["bootrec", "/rebuildbcd"]])

    def t_winre(self):
        if messagebox.askyesno("Перезавантаження", "Комп'ютер негайно перезавантажиться в середовище відновлення "
                               "Windows (Advanced Startup). Збережіть роботу. Продовжити?"):
            try:
                subprocess.run(["shutdown", "/r", "/o", "/f", "/t", "0"], creationflags=NOWIN)
            except OSError as e:
                self.app.notify(f"Не вдалося перезавантажити: {e}", "err")

    def launch(self, cmd):
        try:
            subprocess.Popen(cmd, shell=True)
        except OSError:
            self.app.notify("Не вдалося запустити", "err")

    def t_usb(self):
        d = filedialog.askdirectory(title="Оберіть флешку (корінь диска, напр. E:\\)")
        if not d:
            return
        self.write(f"▶ Аналіз флешки {d}")

        def done(sus):
            if isinstance(sus, Exception):
                self.write(f"✖ {sus}")
                return
            for p, why in sus:
                self.write(f"  ⚠ {p} — {why}")
            text = (f"Знайдено підозрілих файлів у корені: {len(sus)}.\nВидалити їх" if sus else "Підозрілих файлів у корені не знайдено.\nПродовжити")
            if not messagebox.askyesno("Лікування флешки", text + " і зробити приховані файли та папки видимими?\n"
                                       "(Системні папки Windows не чіпаємо.)"):
                return

            def work():
                gone = 0
                for p, _ in sus:
                    try:
                        os.chmod(p, stat.S_IWRITE)
                        os.remove(p)
                        gone += 1
                    except OSError:
                        pass
                return gone, usb_unhide(d)

            def fin(r):
                if isinstance(r, Exception):
                    self.write(f"✖ {r}")
                    return
                self.write(f"✓ Видалено файлів: {r[0]}, відкрито прихованих елементів: {r[1]}")
                self.app.notify("Флешку вилікувано", "ok")
                log(f"Лікування флешки {d}: видалено {r[0]}, відкрито {r[1]}")
            self.app.bg(work, fin)
        self.app.bg(lambda: usb_scan(d), done)


# ───────────────────────────── Сторінка «Драйвери» ─────────────────────────────
class DriversPage(Page):
    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Драйвери", "Сторонні драйвери в сховищі Windows. Видаляйте лише ті, що точно не потрібні (старе обладнання).")
        self.rows: dict[str, dict] = {}
        if not IS_WIN:
            lbl(self, "Ця функція доступна лише у Windows.", MUTED, 12).pack(padx=28, anchor="w")
            return
        frame, self.tree = make_tree(self, [("drv", "Пакет", 100, False), ("prov", "Виробник", 220, False), ("cls", "Клас", 150, False),
                                            ("ver", "Версія", 140, False), ("date", "Дата", 100, False), ("inf", "Оригінальний INF", 280, True)],
                                     selectmode="browse")
        frame.pack(fill="both", expand=True, padx=28)
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=28, pady=14)
        self.info = lbl(foot, "", MUTED)
        self.info.pack(side="left")
        Btn(foot, "Видалити драйвер", self.delete, "danger").pack(side="right")
        Btn(foot, "Завантажити список", self.load, "ghost").pack(side="right", padx=8)

    def load(self):
        if not is_admin():
            self.info.config(text="Потрібні права адміністратора (кнопка на вкладці «Захист»)", fg=WARN)
            return
        self.info.config(text="Завантажую список драйверів (до хвилини)…", fg=MUTED)
        self.app.bg(lambda: ps_json("Get-WindowsDriver -Online | Where-Object { $_.Driver -like 'oem*' } | Select-Object Driver,OriginalFileName,"
                                    "ProviderName,ClassName,Version,@{n='Date';e={$_.Date.ToString('yyyy-MM-dd')}}", 240), self.fill)

    def fill(self, rows):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        if isinstance(rows, Exception) or not rows:
            self.info.config(text="Сторонніх драйверів не знайдено або немає доступу")
            return
        rows.sort(key=lambda r: (str(r.get("ClassName")), str(r.get("ProviderName"))))
        for r in rows:
            iid = self.tree.insert("", "end", values=(r.get("Driver"), r.get("ProviderName"), r.get("ClassName"),
                                                      r.get("Version"), r.get("Date"), os.path.basename(str(r.get("OriginalFileName")))))
            self.rows[iid] = r
        self.info.config(text=f"Сторонніх драйверів: {len(rows)}")

    def delete(self):
        s = self.tree.selection()
        if not s:
            self.app.notify("Виберіть драйвер", "err")
            return
        r = self.rows[s[0]]
        if not messagebox.askyesno("Видалення драйвера", f"Видалити драйвер {r.get('Driver')} ({r.get('ProviderName')}, {r.get('ClassName')})?\n"
                                   "Пристрої, що ним користуються, можуть перестати працювати.\nРекомендується створити точку відновлення."):
            return
        drv = str(r.get("Driver"))

        def work():
            p = subprocess.run(["pnputil", "/delete-driver", drv, "/uninstall"], capture_output=True, creationflags=NOWIN)
            enc = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
            return p.returncode, p.stdout.decode(enc, "replace").strip()

        def done(res):
            if isinstance(res, Exception):
                self.app.notify(f"Помилка: {res}", "err")
                return
            log(f"pnputil delete-driver {drv}: код {res[0]}")
            self.app.notify(f"Драйвер {drv} видалено" if res[0] == 0 else f"Не вдалося видалити: {res[1][:120]}", "ok" if res[0] == 0 else "err")
            self.load()
        self.app.bg(work, done)


# ───────────────────────────── Головне вікно ─────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        global LOG_HOOK, BG
        self.title("UA Shield — захист ПК")
        self.geometry("1240x820")
        self.minsize(1040, 720)
        # напівпрозоре/«скляне» вікно: на Windows — справжній розмитий Acrylic-блюр крізь
        # вікно (область контенту стає прозорою, бічна панель лишається суцільною для
        # читабельності); інакше — проста альфа-прозорість усього вікна
        self.glass_mode = enable_glass(self)
        if self.glass_mode == "acrylic":
            BG = TRANSPARENT_KEY
        self.configure(bg=BG)
        setup_style(self)
        self.q: queue.Queue = queue.Queue()
        self.store = Store()
        self.engine = Engine(self.store)
        self.quar = Quarantine()
        self.monitor: Monitor | None = None
        self._job = None
        self.toasts: list = []

        side = tk.Frame(self, bg=SIDEBAR, width=236)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        logo = tk.Canvas(side, width=236, height=96, bg=SIDEBAR, highlightthickness=0)
        logo.pack()
        logo.create_polygon(24, 30, 36, 26, 48, 30, 48, 46, 36, 58, 24, 46, fill=ACCENT, outline=ACCENT, width=2, joinstyle="round")
        logo.create_text(60, 34, anchor="w", text="UA Shield", fill=TEXT, font=(FONT, 16, "bold"))
        logo.create_text(60, 56, anchor="w", text="захист ПК", fill=MUTED, font=(FONT, 9))

        self.main = tk.Frame(self, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)
        bottom = tk.Frame(self.main, bg=SIDEBAR, height=34)
        bottom.pack(side="bottom", fill="x")
        self.status = tk.Label(bottom, text="Готово до роботи", bg=SIDEBAR, fg=MUTED, font=(FONT, 9), anchor="w")
        self.status.pack(side="left", padx=18, pady=7)
        tk.Label(bottom, text="Адміністратор" if is_admin() else "Звичайний режим", bg=SIDEBAR,
                 fg=ACCENT if is_admin() else WARN, font=(FONT, 9)).pack(side="right", padx=18)
        glass_txt = {"acrylic": "Скло: увімкнено", "alpha": "Прозорість: легка", "": "Скло: недоступне"}[self.glass_mode]
        tk.Label(bottom, text=glass_txt, bg=SIDEBAR, fg=MUTED, font=(FONT, 9)).pack(side="right", padx=0)
        self.content = tk.Frame(self.main, bg=BG)
        self.content.pack(fill="both", expand=True)
        self.content.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)

        self.pages: dict[str, Page] = {}
        self.nav: dict[str, tk.Frame] = {}
        self.current = "dash"
        defs = [("dash", "⛨", "Захист", DashboardPage), ("scan", "⌕", "Сканування", ScanPage),
                ("quar", "▣", "Карантин", QuarantinePage), ("proc", "☰", "Процеси", ProcessPage),
                ("unlock", "▥", "Розблокування", UnlockPage), ("auto", "⏻", "Автозавантаження", AutorunPage),
                ("repair", "✚", "Відновлення", RepairPage), ("check", "✔", "Безпека системи", CheckPage),
                ("tools", "⚒", "Інструменти", ToolsPage), ("drv", "⬡", "Драйвери", DriversPage),
                ("def", "◈", "Defender", DefenderPage), ("set", "⚙", "Налаштування", SettingsPage)]
        for key, icon, title, _ in defs:
            self.nav[key] = self._nav_item(side, key, icon, title)
        for key, _, _, cls in defs:
            p = cls(self.content, self)
            p.grid(row=0, column=0, sticky="nsew")
            self.pages[key] = p
        LOG_HOOK = lambda line: self.ui(self.pages["set"].append_log, line)

        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(ev, self._wheel)
        self.show("dash")
        self.after(60, self._poll)
        if self.store["realtime"]:
            self.set_realtime(True, silent=True)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        log("UA Shield запущено")

    # --- навігація
    def _nav_item(self, parent, key, icon, title):
        w, h = 206, 42
        c = tk.Canvas(parent, width=w, height=h, bg=SIDEBAR, highlightthickness=0, cursor="hand2")
        c.pack(fill="x", padx=14, pady=2)
        c.icon_char, c.title_text = icon, title
        c.bind("<Button-1>", lambda e, k=key: self.show(k))
        c.bind("<Enter>", lambda e, k=key: k != self.current and self._paint(k, False, True))
        c.bind("<Leave>", lambda e, k=key: k != self.current and self._paint(k, False, False))
        self._paint_item(c, False, False)
        return c

    def _paint_item(self, c, active, hover):
        c.delete("all")
        w, h = int(c["width"]), int(c["height"])
        if active:
            round_rect(c, 0, 1, w, h - 1, 12, fill=_mix(ACCENT, SIDEBAR, .76), outline="")
        elif hover:
            round_rect(c, 0, 1, w, h - 1, 12, fill=CARD, outline="")
        fg = ACCENT if active else (TEXT if hover else MUTED)
        c.create_text(22, h / 2, text=c.icon_char, fill=fg, font=("Segoe UI Symbol", 13), anchor="w")
        c.create_text(48, h / 2, text=c.title_text, fill=(TEXT if active else fg),
                     font=(FONT, 11, "bold" if active else "normal"), anchor="w")

    def _paint(self, key, active, hover=False):
        self._paint_item(self.nav[key], active, hover)

    def show(self, key):
        self.current = key
        for k in self.nav:
            self._paint(k, k == key)
        self.pages[key].tkraise()
        self.pages[key].on_show()

    # --- потоки
    def ui(self, fn, *a, **kw):
        self.q.put((fn, a, kw))

    def _poll(self):
        try:
            while True:
                fn, a, kw = self.q.get_nowait()
                try:
                    fn(*a, **kw)
                except tk.TclError:
                    pass
        except queue.Empty:
            pass
        self.after(60, self._poll)

    def bg(self, work, done=None):
        def runner():
            try:
                res = work()
            except Exception as e:  # noqa: BLE001
                res = e
            if done:
                self.ui(done, res)
        threading.Thread(target=runner, daemon=True).start()

    def notify(self, text, kind="info"):
        self.status.config(text=text, fg={"ok": OK, "err": DANGER}.get(kind, WARN))
        if self._job:
            self.after_cancel(self._job)
        self._job = self.after(7000, lambda: self.status.config(text="Готово до роботи", fg=MUTED))
        if kind in ("ok", "err"):
            self.show_toast(text, kind)

    def show_toast(self, text, kind="info"):
        """Плаваюче сповіщення знизу-справа поверх контенту (стек, якщо їх кілька)."""
        t = Toast(self.content, text, kind, on_done=lambda: self._toast_removed(t))
        t.place(relx=1.0, rely=1.0, anchor="se", x=-18, y=-18)
        self.toasts.append(t)
        self._restack_toasts()

    def _toast_removed(self, t):
        if t in self.toasts:
            self.toasts.remove(t)
        self._restack_toasts()

    def _restack_toasts(self):
        y = 18
        for t in reversed(self.toasts):
            try:
                t.update_idletasks()
                t.place_configure(y=-y)
                y += t.winfo_reqheight() + 10
            except tk.TclError:
                pass

    # --- логіка
    def start_scan(self, mode):
        self.show("scan")
        self.pages["scan"].start(mode)

    def protection_state(self):
        n = len(self.pages["scan"].dets) if "scan" in self.pages else 0
        last = self.store["last_scan"]
        if n:
            return "bad", f"Виявлено загрози: {n}", "Перейдіть до «Сканування», щоб ізолювати або видалити небезпечні файли."
        if not last:
            return "warn", "Перевірку ще не виконували", "Запустіть швидке сканування, щоб оцінити стан комп'ютера."
        if time.time() - last > 7 * 86400:
            return "warn", "Час для нової перевірки", f"Останнє сканування було {fmt_ts(last)}."
        rt = "Захист у реальному часі активний." if self.store["realtime"] else "Увімкніть захист у реальному часі для кращої безпеки."
        return "ok", "Ви під захистом", f"Загроз не виявлено. {rt}"

    def set_realtime(self, on: bool, silent=False):
        self.store["realtime"] = on
        if on and not (self.monitor and self.monitor.is_alive()):
            self.monitor = Monitor(self)
            self.monitor.start()
        elif not on and self.monitor:
            self.monitor.halt.set()
            self.monitor = None
        log("Захист у реальному часі " + ("увімкнено" if on else "вимкнено"))
        if not silent:
            self.notify("Захист у реальному часі " + ("увімкнено" if on else "вимкнено"), "ok" if on else "info")
        self.pages["dash"].refresh()

    def on_realtime_hit(self, det: Detection):
        if self.store["auto_q"]:
            ok, _ = self.quar.add(det)
            if ok:
                self.notify(f"Захист: «{det.name}» ізольовано — {os.path.basename(det.path)}", "err")
                self.pages["dash"].refresh()
                return
        self.pages["scan"].add_detection(det)
        self.notify(f"Захист: виявлено «{det.name}» — {os.path.basename(det.path)}", "err")
        self.pages["dash"].refresh()

    def on_close(self):
        if self.monitor:
            self.monitor.halt.set()
        self.engine.save_cache()
        self.destroy()

    def _wheel(self, e):
        try:
            w = self.winfo_containing(e.x_root, e.y_root)
        except (KeyError, tk.TclError):
            return
        while w is not None:
            if isinstance(w, (ttk.Treeview, tk.Text, tk.Listbox)):
                return
            if isinstance(w, ScrollFrame):
                d = -1 if (getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0) else 1
                w.canvas.yview_scroll(d * 2, "units")
                return
            w = w.master


def main():
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    App().mainloop()


if __name__ == "__main__":
    main()
