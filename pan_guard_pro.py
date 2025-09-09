#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PAN Guard Pro — PAN discovery/masking (first4+last4)
Version: 0.1.0
Menu UI (uk/en), FP ignore list (strict/non-strict), compliance profiles, TOCTOU guard,
audit log with HMAC chain, path allow-list. No external libraries.

License: MIT (see LICENSE)
"""

from __future__ import annotations
import argparse, csv, json, os, re, sys, time, tempfile, shutil, getpass, hashlib, hmac, zipfile
from dataclasses import dataclass
from typing import List, Optional
import fnmatch

VERSION = "0.1.0"

# ----------------------------- i18n -----------------------------

LOCALES = {
    "en": {
        "MENU_HEADER": "========== PAN GUARD PRO ==========",
        "LABEL_PATH": "Path",
        "LABEL_POLICY": "Policy",
        "LABEL_ARCHIVES": "Archives",
        "LABEL_BINARIES": "Binaries",
        "LABEL_BACKUPS": "Backups",
        "LABEL_LIMIT": "Limit (MB)",
        "LABEL_LOGS": "Logs",
        "LABEL_ON": "ON",
        "LABEL_OFF": "OFF",
        "LABEL_LANG": "Language",
        "LABEL_PROFILE": "Profile",
        "PROFILE_NONE": "none",
        "PROFILE_PCI": "pci-strict",
        "PROFILE_SAFE": "safe-detect",
        "LANG_EN": "English",
        "LANG_UK": "Ukrainian",
        "MENU_ITEM_SCAN": "Scan (no changes)",
        "MENU_ITEM_SCAN_ASK": "Scan → ask to mask",
        "MENU_ITEM_AUTOMASK": "Auto-mask (no prompt)",
        "MENU_ITEM_SETTINGS": "Settings…",
        "MENU_ITEM_PROFILE": "Profile…",
        "MENU_ITEM_FP": "FP Ignore List…",
        "MENU_ITEM_SEAL_VERIFY": "SEAL: Verify",
        "MENU_ITEM_SEAL_CREATE": "SEAL: Create",
        "MENU_ITEM_EXIT": "Exit",
        "PROMPT_CHOICE": "Your choice [1-8 or 4.1]: ",
        "HEADING_SCAN": "=== SCAN (no changes) ===",
        "HEADING_SCAN_ASK": "=== SCAN → ASK ===",
        "HEADING_AUTOMASK": "=== AUTO-MASK ===",
        "HEADING_MASK_DONE": "=== MASKING DONE ===",
        "SETTINGS_TITLE": "=== SETTINGS ===",
        "SETTINGS_CURRENT_PATH": "Current path",
        "SET_PATH": "Target path",
        "SET_FIRST": "Visible first digits (≤6)",
        "SET_LAST": "Visible last digits (≤6)",
        "SET_MASKCHAR": "Mask character",
        "SET_REWRITE_ARCH": "Rewrite ZIP/OOXML to mask inside",
        "SET_SCAN_ALL": "Scan binary files (detect; optional byte replace)",
        "SET_BIN_REPLACE": "Allow byte-level masking in binaries (risky)",
        "SET_BACKUP": "Create .bak before changes",
        "SET_SYMLINKS": "Follow symlinks",
        "SET_MAX_MB": "Max file size, MB",
        "SET_EXCLUDE_SYS": "Exclude system paths (recommended)",
        "SET_LOG_PATH": "Log path (empty = none)",
        "SET_LOG_FMT": "Log format (ndjson/csv/json)",
        "SET_LANG": "Language (uk/en)",
        "SET_ALLOW_PATHS": "Allow-list globs (comma-separated; empty = no restrictions)",
        "YN_YESNO": "Y/n",
        "PROMPT_MASK_NOW": "Mask found values now?",
        "PROMPT_POST_SCAN": "Action: [M]ask, [F] mark FP, [S]kip",
        "PROMPT_ENTER_INDEXES": "Enter numbers to mark as FP (e.g., 1,3-5); empty to skip",
        "MARKED_N_FILES": "Marked {n} file(s) as FP.",
        "FP_STRICT_PROMPT": "Add as STRICT FP (sha-locked)?",
        "PROFILE_TITLE": "=== PROFILE ===",
        "PROFILE_SELECT": "Choose profile (none/pci-strict/safe-detect)",
        "WARN_PROFILE_ENFORCED": "Profile constraints enforced.",
        "SUMMARY_FOUND": "Findings: {count}",
        "SUMMARY_NONE": "No PANs found.",
        "SUMMARY_PREVIEW": "↳ {file} :: {where} :: {issuer}/{length} → {preview}",
        "WARN_NOACCESS": "No access",
        "ERR_BADZIP": "Bad ZIP file",
        "INFO_NO_CHANGES": "By user decision, masking not performed.",
        "INFO_AUTOMASKING": "Proceeding with masking without prompt…",
        "INFO_SHA": "Script SHA256: {sha}",
        "INFO_MODE_NOMASK": "Scan-only mode (no-mask/dry-run).",
        "TOCTOU_SKIP": "Skipped due to TOCTOU mismatch: {path}",
        "AUDIT_MISSING_KEY": "PANGUARD_AUDIT_KEY not set — audit HMAC disabled.",
        "VERIFYLOG_OK": "Audit log verification: OK",
        "VERIFYLOG_FAIL": "Audit log verification: FAIL at line {i}",
        "SEAL_PROMPT_KEY": "[SEAL] Enter secret key (hidden): ",
        "SEAL_CREATED": "[SEAL] Seal file created: {file}",
        "SEAL_MISSING": "[SEAL] Seal file missing: {file}",
        "SEAL_UNKNOWN_ALGO": "[SEAL] Unknown seal algorithm.",
        "SEAL_CHANGED": "[SEAL] WARNING: Script modified! Verification failed.",
        "SEAL_OK": "[SEAL] OK: Seal verified.",
        "FP_TITLE": "=== FP IGNORE LIST ===",
        "FP_LIST_EMPTY": "(empty)",
        "FP_LIST_HEADER": "Currently ignored (by path):",
        "FP_ADD_PROMPT": "Enter path to add (absolute or relative)",
        "FP_REMOVE_PROMPT": "Enter path to remove",
        "FP_ADDED": "Added to FP ignore: {path}",
        "FP_REMOVED": "Removed from FP ignore: {path}",
        "FP_CLEARED": "FP ignore list cleared.",
    },
    "uk": {
        "MENU_HEADER": "========== PAN GUARD PRO ==========",
        "LABEL_PATH": "Шлях",
        "LABEL_POLICY": "Політика",
        "LABEL_ARCHIVES": "Архіви",
        "LABEL_BINARIES": "Бінарні",
        "LABEL_BACKUPS": "Бекапи",
        "LABEL_LIMIT": "Ліміт (МБ)",
        "LABEL_LOGS": "Логи",
        "LABEL_ON": "УВІМК",
        "LABEL_OFF": "ВИМК",
        "LABEL_LANG": "Мова",
        "LABEL_PROFILE": "Профіль",
        "PROFILE_NONE": "без профілю",
        "PROFILE_PCI": "pci-strict",
        "PROFILE_SAFE": "safe-detect",
        "LANG_EN": "Англійська",
        "LANG_UK": "Українська",
        "MENU_ITEM_SCAN": "Скан (без змін)",
        "MENU_ITEM_SCAN_ASK": "Скан → запитати про маскування",
        "MENU_ITEM_AUTOMASK": "Авто-маскування (без запитання)",
        "MENU_ITEM_SETTINGS": "Налаштування…",
        "MENU_ITEM_PROFILE": "Профіль…",
        "MENU_ITEM_FP": "Список FP (ігнор)…",
        "MENU_ITEM_SEAL_VERIFY": "SEAL: Перевірити",
        "MENU_ITEM_SEAL_CREATE": "SEAL: Створити",
        "MENU_ITEM_EXIT": "Вихід",
        "PROMPT_CHOICE": "Ваш вибір [1-8 або 4.1]: ",
        "HEADING_SCAN": "=== СКАН (без змін) ===",
        "HEADING_SCAN_ASK": "=== СКАН → ПИТАННЯ ===",
        "HEADING_AUTOMASK": "=== АВТО-МАСКУВАННЯ ===",
        "HEADING_MASK_DONE": "=== МАСКУВАННЯ ВИКОНАНО ===",
        "SETTINGS_TITLE": "=== НАЛАШТУВАННЯ ===",
        "SETTINGS_CURRENT_PATH": "Поточний шлях",
        "SET_PATH": "Шлях до файлу/каталогу",
        "SET_FIRST": "Скільки перших цифр показувати (≤6)",
        "SET_LAST": "Скільки останніх цифр показувати (≤6)",
        "SET_MASKCHAR": "Символ маскування",
        "SET_REWRITE_ARCH": "Перепаковувати ZIP/OOXML для маскування всередині",
        "SET_SCAN_ALL": "Сканувати бінарні файли (детект; опц. байтова заміна)",
        "SET_BIN_REPLACE": "Дозволити байтове маскування у бінарних (ризиково)",
        "SET_BACKUP": "Робити .bak перед змінами",
        "SET_SYMLINKS": "Йти по симлінках",
        "SET_MAX_MB": "Максимальний розмір файлу, МБ",
        "SET_EXCLUDE_SYS": "Виключати системні шляхи (рекомендовано)",
        "SET_LOG_PATH": "Шлях до журналу (порожньо — не писати)",
        "SET_LOG_FMT": "Формат журналу (ndjson/csv/json)",
        "SET_LANG": "Мова (uk/en)",
        "SET_ALLOW_PATHS": "Allow-list (маски через кому; порожньо = без обмежень)",
        "YN_YESNO": "Т/н",
        "PROMPT_MASK_NOW": "Замаскувати знайдені значення зараз?",
        "PROMPT_POST_SCAN": "Дія: [M] маскувати, [F] позначити FP, [S] пропустити",
        "PROMPT_ENTER_INDEXES": "Вкажіть номери файлів для FP (напр. 1,3-5); порожньо — пропустити",
        "MARKED_N_FILES": "Позначено FP: {n} файлів.",
        "FP_STRICT_PROMPT": "Додати як СТРОГИЙ FP (за sha)?",
        "PROFILE_TITLE": "=== ПРОФІЛЬ ===",
        "PROFILE_SELECT": "Оберіть профіль (none/pci-strict/safe-detect)",
        "WARN_PROFILE_ENFORCED": "Обмеження профілю застосовано.",
        "SUMMARY_FOUND": "Виявлень: {count}",
        "SUMMARY_NONE": "PAN не знайдено.",
        "SUMMARY_PREVIEW": "↳ {file} :: {where} :: {issuer}/{length} → {preview}",
        "WARN_NOACCESS": "Немає доступу",
        "ERR_BADZIP": "Пошкоджений ZIP-файл",
        "INFO_NO_CHANGES": "За рішенням користувача маскування не виконано.",
        "INFO_AUTOMASKING": "Виконую маскування без підтвердження…",
        "INFO_SHA": "SHA256 скрипта: {sha}",
        "INFO_MODE_NOMASK": "Режим скану без змін (no-mask/dry-run).",
        "TOCTOU_SKIP": "Пропущено через TOCTOU-невідповідність: {path}",
        "AUDIT_MISSING_KEY": "ПANGUARD_AUDIT_KEY не задано — HMAC-аудит вимкнено.",
        "VERIFYLOG_OK": "Перевірка аудиту: OK",
        "VERIFYLOG_FAIL": "Перевірка аудиту: ПОМИЛКА на рядку {i}",
        "SEAL_PROMPT_KEY": "[SEAL] Введіть секретний ключ (не відображається): ",
        "SEAL_CREATED": "[SEAL] Створено підпис: {file}",
        "SEAL_MISSING": "[SEAL] Файл підпису відсутній: {file}",
        "SEAL_UNKNOWN_ALGO": "[SEAL] Невідомий алгоритм підпису.",
        "SEAL_CHANGED": "[SEAL] ПОПЕРЕДЖЕННЯ: Код скрипта змінено! Перевірка провалена.",
        "SEAL_OK": "ОК: Підпис перевірено.",
        "FP_TITLE": "=== СПИСОК FP (ІГНОР) ===",
        "FP_LIST_EMPTY": "(порожньо)",
        "FP_LIST_HEADER": "Зараз ігноруються (за шляхом):",
        "FP_ADD_PROMPT": "Введіть шлях для додавання (або абсолютний, або відносний)",
        "FP_REMOVE_PROMPT": "Введіть шлях для видалення",
        "FP_ADDED": "Додано до списку FP: {path}",
        "FP_REMOVED": "Видалено зі списку FP: {path}",
        "FP_CLEARED": "Список FP очищено.",
    }
}

YES_WORDS = {
    "en": {"y","yes","t","true","1","m"},
    "uk": {"т","так","y","yes","1","m"},
}
NO_WORDS = {
    "en": {"n","no","false","0","s"},
    "uk": {"н","ні","no","n","false","0","s"},
}

def choose_lang(cli_lang: Optional[str]=None) -> str:
    env = os.environ.get("PANGUARD_LANG","").strip().lower()
    for cand in (cli_lang or "", env, "en"):
        if cand in LOCALES:
            return cand
    return "en"

def t(lang: str, key: str, **vars) -> str:
    txt = LOCALES.get(lang, LOCALES["en"]).get(key)
    if txt is None:
        txt = LOCALES["en"].get(key, key)
    try:
        return txt.format(**vars)
    except Exception:
        return txt

# ----------------------------- Core constants -----------------------------

MAX_FILE_SIZE_MB_DEFAULT = 200
CANDIDATE_RE_STR = r"(?:\d[ -]?){13,19}"
CANDIDATE_RE = re.compile(CANDIDATE_RE_STR)
CANDIDATE_RE_BYTES = re.compile(CANDIDATE_RE_STR.encode())

OFFICE_ZIP_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
ZIP_EXT = {".zip"}

DEFAULT_EXCLUDE_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", "venv", "dist", "build", "target", "bin", "obj", "cache", "tmp"}
DEFAULT_EXCLUDE_SYSTEM_PATHS = {"/proc", "/sys", "/dev", "/run", "/var/run", r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)"}

SEAL_FILE = "pan_guard_pro.seal"
SEAL_ALGO = "HMAC-SHA256"

# ----------------------------- Models -----------------------------

@dataclass
class Finding:
    file_path: str
    location: str
    issuer: str
    length: int
    last4: str
    masked_preview: str

# ----------------------------- Global state -----------------------------
LAST_SCAN_META = {}
AUDIT_EVENTS = []

# ----------------------------- Luhn / Issuer -----------------------------

def luhn_ok_digits(digits: str) -> bool:
    total = 0; alt = False
    for ch in reversed(digits):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9: n -= 9
        total += n; alt = not alt
    return total % 10 == 0

def issuer_of(d: str) -> Optional[str]:
    ln = len(d)
    two = int(d[:2]) if ln >= 2 else -1
    three = int(d[:3]) if ln >= 3 else -1
    four = int(d[:4]) if ln >= 4 else -1
    six = int(d[:6]) if ln >= 6 else -1

    if d.startswith("4") and ln in (13, 16, 19): return "VISA"
    if ln in (16, 19):
        if 51 <= two <= 55: return "MASTERCARD"
        if 222100 <= six <= 272099: return "MASTERCARD"
    if ln == 15 and (d.startswith("34") or d.startswith("37")): return "AMEX"
    if ln in (16, 19):
        if d.startswith("6011") or d.startswith("65"): return "DISCOVER"
        if 644 <= three <= 649: return "DISCOVER"
        if 622126 <= six <= 622925: return "DISCOVER"
    if 16 <= ln <= 19 and 3528 <= four <= 3589: return "JCB"
    if ln in (14, 16) and ((300 <= three <= 305) or two == 36 or 38 <= two <= 39): return "DINERS"
    if 13 <= ln <= 19 and d.startswith(("50","56","57","58","59","60","61","62","64","66","67","69")) and luhn_ok_digits(d): return "MAESTRO"
    return None

# ----------------------------- Masking -----------------------------

def mask_preserving_separators_text(raw: str, first=4, last=4, mask_char="X"):
    digit_idxs = [i for i,ch in enumerate(raw) if ch.isdigit()]
    n = len(digit_idxs)
    if n == 0: return raw, ""
    first = max(0, min(first, n))
    last  = max(0, min(last,  n - first))
    if first + last >= n:
        last = max(0, n - first - 1)
    keep = set(digit_idxs[:first] + digit_idxs[n-last:n])
    last4 = ''.join(raw[i] for i in digit_idxs[-min(4, n):])
    out = []
    for i,ch in enumerate(raw):
        out.append(ch if (not ch.isdigit() or i in keep) else mask_char)
    return ''.join(out), last4

def mask_preserving_separators_bytes(raw: bytes, first=4, last=4, mask_byte=b"X"):
    digit_idxs = [i for i,b in enumerate(raw) if 48 <= b <= 57]
    n = len(digit_idxs)
    if n == 0: return raw, ""
    first = max(0, min(first, n))
    last  = max(0, min(last,  n - first))
    if first + last >= n:
        last = max(0, n - first - 1)
    keep = set(digit_idxs[:first] + digit_idxs[n-last:n])
    last4 = bytes(raw[i] for i in digit_idxs[-min(4, n):]).decode("ascii", "ignore")
    out = bytearray()
    for i,b in enumerate(raw):
        out.append(b if not (48 <= b <= 57) or i in keep else mask_byte[0])
    return bytes(out), last4

# ----------------------------- SEAL -----------------------------

def get_seal_key(lang: str) -> bytes:
    key = os.environ.get("PAN_GUARD_KEY") or ""
    if not key:
        try:
            key = getpass.getpass(t(lang, "SEAL_PROMPT_KEY"))
        except Exception:
            key = ""
    if not key:
        print(t(lang, "SEAL_MISSING", file=SEAL_FILE), file=sys.stderr); sys.exit(2)
    return key.encode("utf-8")

def seal_path(script_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(script_path)), SEAL_FILE)

def seal_create(script_path: str, lang: str):
    key = get_seal_key(lang)
    with open(script_path, "rb") as f: data = f.read()
    digest = hmac.new(key, data, hashlib.sha256).hexdigest()
    payload = {"algo": "HMAC-SHA256", "hmac": digest, "script": os.path.basename(script_path), "ts": int(time.time())}
    with open(seal_path(script_path), "w", encoding="utf-8") as sf:
        json.dump(payload, sf, indent=2, ensure_ascii=False)
    print(t(lang, "SEAL_CREATED", file=SEAL_FILE))

def seal_verify(script_path: str, lang: str):
    p = seal_path(script_path)
    if not os.path.exists(p):
        print(t(lang, "SEAL_MISSING", file=p), file=sys.stderr); sys.exit(3)
    with open(p, "r", encoding="utf-8") as sf:
        payload = json.load(sf)
    if payload.get("algo") != "HMAC-SHA256":
        print(t(lang, "SEAL_UNKNOWN_ALGO"), file=sys.stderr); sys.exit(3)
    key = get_seal_key(lang)
    with open(script_path, "rb") as f: data = f.read()
    actual = hmac.new(key, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, payload.get("hmac", "")):
        print(t(lang, "SEAL_CHANGED"), file=sys.stderr); sys.exit(4)
    print(t(lang, "SEAL_OK"))

# ----------------------------- FP Store -----------------------------

def _fp_store_path() -> str:
    home = os.path.expanduser("~")
    base = os.path.join(home, ".panguard")
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        pass
    return os.path.join(base, "fp_list.json")

def _normpath(p: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return os.path.abspath(p)

def fp_load() -> dict:
    p = _fp_store_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return { _normpath(k): v for k,v in data.items() }
    except Exception:
        pass
    return {}

def fp_save(store: dict) -> None:
    p = _fp_store_path()
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def fp_add(path: str, note: str = "false_positive", strict: bool=False) -> None:
    store = fp_load()
    np = _normpath(path)
    entry = {"note": note, "ts": int(time.time()), "strict": bool(strict)}
    try:
        if os.path.isfile(np):
            with open(np, "rb") as fh:
                entry["sha256"] = hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        pass
    store[np] = entry
    fp_save(store)

def fp_remove(path: str) -> bool:
    store = fp_load()
    np = _normpath(path)
    if np in store:
        store.pop(np, None); fp_save(store); return True
    return False

def fp_clear() -> None:
    fp_save({})

def fp_list() -> list:
    store = fp_load()
    return sorted(store.items())

def fp_should_skip(path: str) -> bool:
    store = fp_load()
    np = _normpath(path)
    meta = store.get(np)
    if not meta:
        return False
    if meta.get("strict"):
        try:
            return meta.get("sha256") == sha256_of_file(np)
        except Exception:
            return False
    return True

# ----------------------------- Helpers -----------------------------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def guess_ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()

def under_excluded_system_path(path: str, excluded) -> bool:
    p = os.path.abspath(path)
    for root in excluded:
        if os.name == "nt":
            if p.upper().startswith(os.path.abspath(root).upper()):
                return True
        else:
            if p.startswith(os.path.abspath(root) + os.sep) or p == os.path.abspath(root):
                return True
    return False

def is_binary_like(sample: bytes) -> bool:
    if b"\x00" in sample: return True
    text_like = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample)
    return len(sample) > 0 and (text_like / len(sample) < 0.75)

# ----------------------------- Allow-list -----------------------------

def is_allowed_path(path: str, allow_globs: list, base_root: str=None) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    if base_root:
        root = os.path.normcase(os.path.abspath(base_root))
        if not p.startswith(root + os.sep) and p != root:
            return False
    if not allow_globs:
        return True
    for g in allow_globs:
        if fnmatch.fnmatch(p, os.path.normcase(os.path.abspath(g))):
            return True
    return False

# ----------------------------- TOCTOU -----------------------------

def collect_file_meta(path: str):
    try:
        st = os.stat(path, follow_symlinks=False)
        meta = {
            "size": st.st_size,
            "mtime_ns": getattr(st, "st_mtime_ns", int(st.st_mtime*1e9)),
            "st_dev": getattr(st, "st_dev", 0),
            "st_ino": getattr(st, "st_ino", 0),
            "sha256": sha256_of_file(path),
        }
        LAST_SCAN_META[os.path.normcase(os.path.abspath(path))] = meta
    except Exception:
        pass

def toctou_check_or_skip(path: str, lang: str, orig_bytes: bytes) -> bool:
    key = os.path.normcase(os.path.abspath(path))
    meta = LAST_SCAN_META.get(key)
    if not meta:
        return True
    try:
        st = os.stat(path, follow_symlinks=False)
        if st.st_size != meta["size"]:
            print(t(lang,"TOCTOU_SKIP", path=path)); 
            AUDIT_EVENTS.append({"event":"skipped_toctou","path":path,"reason":"size_changed"})
            return False
        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime*1e9))
        if mtime_ns != meta["mtime_ns"]:
            print(t(lang,"TOCTOU_SKIP", path=path)); 
            AUDIT_EVENTS.append({"event":"skipped_toctou","path":path,"reason":"mtime_changed"})
            return False
        if sha256_bytes(orig_bytes) != meta["sha256"]:
            print(t(lang,"TOCTOU_SKIP", path=path)); 
            AUDIT_EVENTS.append({"event":"skipped_toctou","path":path,"reason":"sha_mismatch"})
            return False
    except Exception:
        print(t(lang,"TOCTOU_SKIP", path=path)); 
        AUDIT_EVENTS.append({"event":"skipped_toctou","path":path,"reason":"stat_failed"})
        return False
    return True

# ----------------------------- Processors -----------------------------

def process_text_file(path: str, args, findings: List[Finding]):
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="surrogateescape")
    changed = False
    new_lines = []
    pre_count = len(findings)
    for i, line in enumerate(text.splitlines(keepends=True), start=1):
        def repl(m: re.Match) -> str:
            cand = m.group(0)
            digits = re.sub(r"[ -]", "", cand)
            if not (13 <= len(digits) <= 19 and digits.isdigit() and luhn_ok_digits(digits)): return cand
            iss = issuer_of(digits)
            if not iss: return cand
            masked, last4 = mask_preserving_separators_text(cand, args.visible_first, args.visible_last, args.mask_char)
            findings.append(Finding(path, f"line {i}", iss, len(digits), last4, masked.strip()))
            return masked
        masked_line = CANDIDATE_RE.sub(repl, line)
        if masked_line != line: changed = True
        new_lines.append(masked_line)
    if changed and not args.dry_run:
        if not toctou_check_or_skip(path, getattr(args,"lang","en"), raw):
            return
        if args.backup and not os.path.exists(path + ".bak"):
            with open(path + ".bak", "wb") as bf: bf.write(raw)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".pang_", dir=os.path.dirname(path) or ".")
        try:
            with os.fdopen(tmp_fd, "wb") as tf:
                tf.write("".join(new_lines).encode("utf-8", errors="surrogateescape"))
            os.replace(tmp_path, path)
            try:
                AUDIT_EVENTS.append({
                    "event":"mask",
                    "path": path,
                    "sha256_before": sha256_bytes(raw),
                    "sha256_after": sha256_of_file(path),
                    "count": len([1 for x in findings[pre_count:] if x.file_path==path])
                })
            except Exception:
                pass
        finally:
            try:
                if os.path.exists(tmp_path): os.remove(tmp_path)
            except Exception:
                pass

TEXT_LIKE_EXT_IN_ZIP = (".xml", ".rels", ".txt", ".csv", ".json")

def process_zip_with_rewrite(path: str, args, findings: List[Finding]):
    changed_any = False
    with zipfile.ZipFile(path, "r") as zin:
        tmp_path = path + ".tmpzip"
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                name_lower = item.filename.lower()
                if name_lower.endswith(TEXT_LIKE_EXT_IN_ZIP):
                    try:
                        txt = data.decode("utf-8", errors="surrogateescape")
                        changed = False
                        def repl(m: re.Match) -> str:
                            nonlocal changed
                            cand = m.group(0)
                            digits = re.sub(r"[ -]", "", cand)
                            if not (13 <= len(digits) <= 19 and digits.isdigit() and luhn_ok_digits(digits)): return cand
                            iss = issuer_of(digits)
                            if not iss: return cand
                            changed = True
                            masked, last4 = mask_preserving_separators_text(cand, args.visible_first, args.visible_last, args.mask_char)
                            findings.append(Finding(path, f"zip:{item.filename}", iss, len(digits), last4, masked.strip()))
                            return masked
                        masked_txt = CANDIDATE_RE.sub(repl, txt)
                        if changed:
                            data = masked_txt.encode("utf-8", errors="surrogateescape")
                            changed_any = True
                    except Exception:
                        pass
                elif args.binary_replace:
                    def replb(m: re.Match) -> bytes:
                        frag = m.group(0)
                        only = re.sub(br"[ -]", b"", frag)
                        try: s = only.decode("ascii")
                        except Exception: return frag
                        if not (13 <= len(s) <= 19 and s.isdigit() and luhn_ok_digits(s)): return frag
                        iss = issuer_of(s)
                        if not iss: return frag
                        masked, last4 = mask_preserving_separators_bytes(frag, args.visible_first, args.visible_last, args.mask_char.encode())
                        findings.append(Finding(path, f"zipbin:{item.filename}", iss, len(s), last4, masked.decode('latin-1', 'ignore')))
                        return masked
                    data2, n = CANDIDATE_RE_BYTES.subn(replb, data)
                    if n > 0: data = data2; changed_any = True
                zout.writestr(item, data)
    if changed_any and not args.dry_run:
        if args.backup and not os.path.exists(path + ".bak"):
            shutil.copy2(path, path + ".bak")
        os.replace(tmp_path, path)
        try:
            AUDIT_EVENTS.append({
                "event":"mask",
                "path": path,
                "sha256_before": sha256_of_file(path + ".bak") if args.backup and os.path.exists(path + ".bak") else None,
                "sha256_after": sha256_of_file(path)
            })
        except Exception:
            pass
    else:
        try: os.remove(tmp_path)
        except Exception: pass

def process_generic_zip_detect_only(path: str, args, findings: List[Finding]):
    with zipfile.ZipFile(path, "r") as z:
        for item in z.infolist():
            try:
                data = z.read(item.filename)
                try:
                    txt = data.decode("utf-8", errors="surrogateescape")
                    for m in CANDIDATE_RE.finditer(txt):
                        cand = m.group(0)
                        digits = re.sub(r"[ -]", "", cand)
                        if 13 <= len(digits) <= 19 and digits.isdigit() and luhn_ok_digits(digits):
                            iss = issuer_of(digits)
                            if iss: findings.append(Finding(path, f"zip:{item.filename}", iss, len(digits), digits[-4:], "MATCH"))
                except Exception:
                    for m in CANDIDATE_RE_BYTES.finditer(data):
                        frag = m.group(0)
                        only = re.sub(br"[ -]", b"", frag)
                        try: s = only.decode("ascii")
                        except Exception: continue
                        if 13 <= len(s) <= 19 and s.isdigit() and luhn_ok_digits(s):
                            iss = issuer_of(s)
                            if iss: findings.append(Finding(path, f"zipbin:{item.filename}", iss, len(s), s[-4:], "BIN_MATCH"))
            except Exception:
                pass

def process_binary_file(path: str, args, findings: List[Finding]):
    with open(path, "rb") as f:
        orig = f.read()
    data = orig
    changed = False
    if args.binary_replace:
        def replb(m: re.Match) -> bytes:
            nonlocal changed
            frag = m.group(0)
            only = re.sub(br"[ -]", b"", frag)
            try: s = only.decode("ascii")
            except Exception: return frag
            if not (13 <= len(s) <= 19 and s.isdigit() and luhn_ok_digits(s)): return frag
            iss = issuer_of(s)
            if not iss: return frag
            masked, last4 = mask_preserving_separators_bytes(frag, args.visible_first, args.visible_last, args.mask_char.encode())
            findings.append(Finding(path, "bytes", iss, len(s), last4, masked.decode('latin-1', 'ignore')))
            changed = True
            return masked
        data2, n = CANDIDATE_RE_BYTES.subn(replb, data)
        if n > 0: data = data2
        if changed and not args.dry_run:
            if not toctou_check_or_skip(path, getattr(args,"lang","en"), orig):
                return
            if args.backup and not os.path.exists(path + ".bak"):
                with open(path + ".bak", "wb") as bf: bf.write(orig)
            tmp_fd, tmp_path = tempfile.mkstemp(prefix=".pangb_", dir=os.path.dirname(path) or ".")
            try:
                with os.fdopen(tmp_fd, "wb") as tf: tf.write(data)
                os.replace(tmp_path, path)
                try:
                    AUDIT_EVENTS.append({
                        "event":"mask",
                        "path": path,
                        "sha256_before": sha256_bytes(orig),
                        "sha256_after": sha256_of_file(path)
                    })
                except Exception:
                    pass
            finally:
                try:
                    if os.path.exists(tmp_path): os.remove(tmp_path)
                except Exception:
                    pass
    else:
        for m in CANDIDATE_RE_BYTES.finditer(data):
            frag = m.group(0)
            only = re.sub(br"[ -]", b"", frag)
            try: s = only.decode("ascii")
            except Exception: continue
            if 13 <= len(s) <= 19 and s.isdigit() and luhn_ok_digits(s):
                iss = issuer_of(s)
                if iss: findings.append(Finding(path, f"bytes@{m.start()}", iss, len(s), s[-4:], "BIN_MATCH"))

# ----------------------------- Logging -----------------------------

def write_log(findings: List[Finding], log_path: str, fmt: str = "ndjson") -> None:
    os.makedirs(os.path.dirname(os.path.abspath(log_path)) or ".", exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if fmt == "csv":
        with open(log_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["timestamp","file_path","location","issuer","length","last4","masked_preview"])
            for x in findings:
                w.writerow([ts, x.file_path, x.location, x.issuer, x.length, x.last4, x.masked_preview])
    elif fmt in ("json", "ndjson"):
        with open(log_path, "w", encoding="utf-8") as f:
            if fmt == "json":
                json.dump([x.__dict__ | {"timestamp": ts} for x in findings], f, ensure_ascii=False, indent=2)
            else:
                for x in findings:
                    f.write(json.dumps(x.__dict__ | {"timestamp": ts}, ensure_ascii=False) + "\n")
    else:
        raise ValueError("Supported formats: csv|json|ndjson")

# ----------------------------- Audit log with HMAC chain -----------------------------

def _audit_key():
    k = os.environ.get("PANGUARD_AUDIT_KEY","")
    return k.encode("utf-8") if k else None

def _audit_prev_hash(log_path: str):
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            last = None
            for line in f:
                line=line.strip()
                if not line: continue
                last = json.loads(line)
            if last and "hmac_chain" in last:
                return last["hmac_chain"]
    except Exception:
        pass
    return "0"*64

def append_audit_events(events: list, log_path: str, lang: str):
    if not log_path or not events:
        return
    key = _audit_key()
    if not key:
        print(t(lang,"AUDIT_MISSING_KEY"))
        return
    prev = _audit_prev_hash(log_path)
    with open(log_path, "a", encoding="utf-8") as f:
        for ev in events:
            payload = ev.copy()
            payload["ts"] = int(time.time())
            payload_no_hmac = json.dumps(payload, ensure_ascii=False, separators=(",",":")).encode("utf-8")
            hm = hmac.new(key, (prev + hashlib.sha256(payload_no_hmac).hexdigest()).encode("utf-8"), hashlib.sha256).hexdigest()
            payload["hmac_chain"] = hm
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            prev = hm

def verify_audit_log(log_path: str) -> int:
    key = _audit_key()
    if not key:
        return -1
    prev = "0"*64
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for i,line in enumerate(f, start=1):
                line=line.strip()
                if not line: 
                    continue
                obj = json.loads(line)
                chain = obj.pop("hmac_chain", None)
                payload_no_hmac = json.dumps(obj, ensure_ascii=False, separators=(",",":")).encode("utf-8")
                hm = hmac.new(key, (prev + hashlib.sha256(payload_no_hmac).hexdigest()).encode("utf-8"), hashlib.sha256).hexdigest()
                if chain != hm:
                    return i
                prev = hm
        return 0
    except Exception:
        return -2

# ----------------------------- Scanning -----------------------------

def scan_path(base_path: str, args, lang: str) -> List[Finding]:
    findings: List[Finding] = []
    base_path = os.path.abspath(base_path)
    if not os.path.exists(base_path):
        print(f"[!] {t(lang,'LABEL_PATH')}: {base_path} — not found", file=sys.stderr); return findings

    for root, dirs, files in os.walk(base_path, followlinks=args.follow_symlinks):
        dirs[:] = [d for d in dirs if d not in args.exclude_dirs]
        if args.exclude_system_paths and under_excluded_system_path(root, args.exclude_system_paths):
            continue
        for name in files:
            path = os.path.join(root, name)
            if not args.follow_symlinks and os.path.islink(path):
                continue
            if not is_allowed_path(path, getattr(args, "allow_paths", []), getattr(args, "base_root", None)):
                continue
            try:
                if fp_should_skip(path):
                    continue
            except Exception:
                pass
            try:
                if os.path.getsize(path) > args.max_file_size_mb * 1024 * 1024:
                    continue
                ext = guess_ext(path)
                with open(path, "rb") as f:
                    sample = f.read(2048)

                if ext in OFFICE_ZIP_EXT or ext in ZIP_EXT:
                    if args.rewrite_archives:
                        process_zip_with_rewrite(path, args, findings)
                    else:
                        process_generic_zip_detect_only(path, args, findings)
                else:
                    if not is_binary_like(sample):
                        process_text_file(path, args, findings)
                    else:
                        if args.scan_all:
                            process_binary_file(path, args, findings)
            except PermissionError:
                print(f"[i] {t(lang,'WARN_NOACCESS')}: {path}", file=sys.stderr)
            except FileNotFoundError:
                continue
            except zipfile.BadZipFile:
                try:
                    if args.scan_all: process_binary_file(path, args, findings)
                except Exception:
                    pass
            except Exception as e:
                print(f"[!] {path}: {e}", file=sys.stderr)
    return findings

def scan_target(args, lang: str) -> List[Finding]:
    target = os.path.abspath(args.path)
    findings: List[Finding] = []
    if os.path.isfile(target):
        if not args.follow_symlinks and os.path.islink(target):
            return []
        if not is_allowed_path(target, getattr(args, "allow_paths", []), getattr(args, "base_root", None)):
            return []
        try:
            if fp_should_skip(target):
                return []
        except Exception:
            pass
        ext = guess_ext(target)
        try:
            if os.path.getsize(target) <= args.max_file_size_mb * 1024 * 1024:
                with open(target, "rb") as f: sample = f.read(2048)
                if ext in OFFICE_ZIP_EXT or ext in ZIP_EXT:
                    if args.rewrite_archives: process_zip_with_rewrite(target, args, findings)
                    else: process_generic_zip_detect_only(target, args, findings)
                else:
                    if not is_binary_like(sample):
                        process_text_file(target, args, findings)
                    else:
                        if args.scan_all: process_binary_file(target, args, findings)
        except Exception as e:
            print(f"[!] {target}: {e}", file=sys.stderr)
    else:
        findings = scan_path(args.path, args, lang)
    return findings

# ----------------------------- Menu & prompts -----------------------------

def clear():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass

def prompt_bool(lang: str, label: str, default: bool) -> bool:
    d = t(lang, "YN_YESNO")
    try:
        ans = input(f"{label} [{d if default else d.swapcase()}]: ").strip().lower()
    except EOFError:
        return default
    if ans in YES_WORDS.get(lang, set()) | YES_WORDS["en"]:
        return True
    if ans in NO_WORDS.get(lang, set()) | NO_WORDS["en"]:
        return False
    return default

def prompt_int(label: str, default: int, min_v: int=None, max_v: int=None) -> int:
    try:
        s = input(f"{label} [{default}]: ").strip()
    except EOFError:
        return default
    if not s: return default
    try:
        v = int(s)
        if min_v is not None and v < min_v: v = min_v
        if max_v is not None and v > max_v: v = max_v
        return v
    except Exception:
        return default

def prompt_str(label: str, default: str) -> str:
    try:
        s = input(f"{label} [{default}]: ").strip()
    except EOFError:
        return default
    return s if s else default

def print_summary(findings: List[Finding], lang: str):
    if not findings:
        print(t(lang, "SUMMARY_NONE"))
        return
    print(t(lang, "SUMMARY_FOUND", count=len(findings)))
    by_file = {}
    for x in findings: by_file.setdefault(x.file_path, 0); by_file[x.file_path] += 1
    for fp, cnt in sorted(by_file.items()):
        print(f"  - {fp}: {cnt}")
    shown = 0
    for f in findings:
        if shown >= 10: break
        print(t(lang, "SUMMARY_PREVIEW", file=f.file_path, where=f.location, issuer=f.issuer, length=f.length, preview=f.masked_preview))
        shown += 1

def make_namespace(settings: dict):
    ns = argparse.Namespace()
    for k,v in settings.items(): setattr(ns, k, v)
    ns.exclude_system_paths = set() if ns.no_exclude_system else set(DEFAULT_EXCLUDE_SYSTEM_PATHS)
    return ns

def default_settings(lang: str) -> dict:
    return {
        "path": ".",
        "backup": True,
        "scan_all": True,
        "binary_replace": False,
        "rewrite_archives": True,
        "follow_symlinks": False,
        "max_file_size_mb": MAX_FILE_SIZE_MB_DEFAULT,
        "mask_char": "X",
        "visible_first": 4,
        "visible_last": 4,
        "log": "",
        "log_format": "ndjson",
        "audit_log": "",
        "exclude_dirs": sorted(DEFAULT_EXCLUDE_DIRS),
        "no_exclude_system": False,
        "dry_run": True,
        "lang": lang,
        "profile": "none",
        "allow_paths": [],
        "base_root": None,
    }

def edit_settings(s: dict):
    lang = s.get("lang","en")
    clear()
    print(t(lang, "SETTINGS_TITLE"))
    print(f"{t(lang,'SETTINGS_CURRENT_PATH')}: {os.path.abspath(s['path'])}")
    s["path"] = prompt_str(t(lang,"SET_PATH"), s["path"])
    s["visible_first"] = prompt_int(t(lang,"SET_FIRST"), s["visible_first"], 0, 6)
    s["visible_last"]  = prompt_int(t(lang,"SET_LAST"),  s["visible_last"], 0, 6)
    s["mask_char"]     = (prompt_str(t(lang,"SET_MASKCHAR"), s["mask_char"]) or "X")[:1]
    s["rewrite_archives"] = prompt_bool(lang, t(lang,"SET_REWRITE_ARCH"), s["rewrite_archives"])
    s["scan_all"] = prompt_bool(lang, t(lang,"SET_SCAN_ALL"), s["scan_all"])
    s["binary_replace"] = prompt_bool(lang, t(lang,"SET_BIN_REPLACE"), s["binary_replace"])
    s["backup"] = prompt_bool(lang, t(lang,"SET_BACKUP"), s["backup"])
    s["follow_symlinks"] = prompt_bool(lang, t(lang,"SET_SYMLINKS"), s["follow_symlinks"])
    s["max_file_size_mb"] = prompt_int(t(lang,"SET_MAX_MB"), s["max_file_size_mb"], 1, 10000)
    s["no_exclude_system"] = not prompt_bool(lang, t(lang,"SET_EXCLUDE_SYS"), not s["no_exclude_system"])
    s["log"] = prompt_str(t(lang,"SET_LOG_PATH"), s["log"])
    s["log_format"] = prompt_str(t(lang,"SET_LOG_FMT"), s["log_format"])
    allow_in = prompt_str(t(lang,"SET_ALLOW_PATHS"), ",".join(s.get("allow_paths",[])))
    s["allow_paths"] = [x.strip() for x in allow_in.split(",") if x.strip()]
    s["profile"] = prompt_str(t(lang,"PROFILE_SELECT"), s.get("profile","none")).strip().lower()
    s = apply_profile(s)
    lang_in = prompt_str(t(lang,"SET_LANG"), s["lang"]).lower()
    if lang_in in LOCALES: s["lang"] = lang_in
    return s

def do_logging(findings: List[Finding], args):
    if args.log and findings:
        try: write_log(findings, args.log, args.log_format)
        except Exception as e: print(f"[!] cannot write log '{args.log}': {e}", file=sys.stderr)

def run_scan_only(settings: dict):
    lang = settings.get("lang","en")
    clear(); print(t(lang,"HEADING_SCAN")); print(f"v{VERSION}")
    args = make_namespace(settings | {"dry_run": True})
    args.lang = lang
    findings = scan_target(args, lang)
    unique_files = []
    seen = set()
    for f in findings:
        if f.file_path not in seen:
            unique_files.append(f.file_path); seen.add(f.file_path)
    for pth in unique_files:
        collect_file_meta(pth)
        AUDIT_EVENTS.append({"event":"detect","path":pth,"count": sum(1 for x in findings if x.file_path==pth)})
    print_summary(findings, lang)
    do_logging(args=findings and args or args, findings=findings)
    return findings

def _interactive_mark_fp(files_order: List[str], lang: str):
    for i,p in enumerate(files_order, start=1):
        print(f"  {i}. {p}")
    try:
        sel = input(t(lang,"PROMPT_ENTER_INDEXES") + " ").strip()
    except EOFError:
        sel = ""
    chosen = set()
    if sel:
        parts = [x.strip() for x in sel.split(",") if x.strip()]
        for part in parts:
            if "-" in part:
                a,b = part.split("-",1)
                try:
                    a=int(a); b=int(b)
                    for k in range(min(a,b), max(a,b)+1):
                        chosen.add(k)
                except:
                    pass
            else:
                try:
                    chosen.add(int(part))
                except:
                    pass
    marked = 0
    for i,p in enumerate(files_order, start=1):
        if i in chosen:
            fp_add(p, strict=False); marked += 1
    print(t(lang,"MARKED_N_FILES", n=marked))

def run_scan_then_ask_mask(settings: dict):
    lang = settings.get("lang","en")
    clear(); print(t(lang,"HEADING_SCAN_ASK")); print(f"v{VERSION}")
    preview = run_scan_only(settings)
    if not preview:
        return
    files_order, seen = [], set()
    for f in preview:
        if f.file_path not in seen:
            files_order.append(f.file_path); seen.add(f.file_path)
    print("\n" + t(lang,"PROMPT_POST_SCAN"))
    try:
        act = input(">> ").strip().lower()
    except EOFError:
        act = "s"
    if act.startswith("f"):
        _interactive_mark_fp(files_order, lang)
        preview = run_scan_only(settings)
        if not preview:
            return
        if not prompt_bool(lang, t(lang,"PROMPT_MASK_NOW"), False):
            print(t(lang, "INFO_NO_CHANGES")); return
    elif not act.startswith("m"):
        print(t(lang, "INFO_NO_CHANGES"))
        return
    print("\n" + t(lang,"HEADING_MASK_DONE"))
    apply_args = make_namespace(settings | {"dry_run": False})
    apply_args.lang = lang
    findings_apply = scan_target(apply_args, lang)
    print_summary(findings_apply, lang)
    do_logging(args=apply_args, findings=findings_apply)

def run_auto_mask(settings: dict):
    lang = settings.get("lang","en")
    clear(); print(t(lang,"HEADING_AUTOMASK")); print(f"v{VERSION}")
    preview = run_scan_only(settings)
    if not preview:
        return
    print("\n[i] " + t(lang,"INFO_AUTOMASKING"))
    apply_args = make_namespace(settings | {"dry_run": False})
    apply_args.lang = lang
    findings_apply = scan_target(apply_args, lang)
    print("\n" + t(lang,"HEADING_MASK_DONE"))
    print_summary(findings_apply, lang)
    do_logging(args=apply_args, findings=findings_apply)

def fp_menu(lang: str):
    while True:
        clear()
        print(t(lang, "FP_TITLE")); print(f"v{VERSION}")
        items = fp_list()
        if not items:
            print(t(lang, "FP_LIST_EMPTY"))
        else:
            print(t(lang, "FP_LIST_HEADER"))
            for i,(p,meta) in enumerate(items, start=1):
                ts = meta.get("ts"); 
                when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "?"
                strict = "strict" if meta.get("strict") else "loose"
                print(f"  {i}. {p}  ({when}, {strict})")
        print("\n1) Add  2) Remove  3) Clear  4) Back")
        try:
            ch = input(">> ").strip()
        except EOFError:
            ch = "4"
        if ch == "1":
            pth = input(t(lang,"FP_ADD_PROMPT") + " ").strip()
            if pth:
                strict = prompt_bool(lang, t(lang,"FP_STRICT_PROMPT"), False)
                fp_add(pth, strict=strict)
                print(t(lang,"FP_ADDED", path=os.path.abspath(pth)))
        elif ch == "2":
            pth = input(t(lang,"FP_REMOVE_PROMPT") + " ").strip()
            if pth:
                ok = fp_remove(pth)
                print(t(lang,"FP_REMOVED", path=os.path.abspath(pth)) if ok else "…")
        elif ch == "3":
            fp_clear(); print(t(lang,"FP_CLEARED"))
        elif ch == "4":
            break
        else:
            print("…")

def apply_profile(settings: dict):
    prof = settings.get("profile","none")
    if prof == "pci-strict":
        settings["visible_first"] = min(settings.get("visible_first",4), 6)
        settings["visible_last"]  = min(settings.get("visible_last",4), 4)
        settings["backup"] = True
        settings["binary_replace"] = False
        settings["scan_all"] = True
        settings["rewrite_archives"] = True
        settings["log_format"] = settings.get("log_format","ndjson")
        settings["base_root"] = os.path.abspath(settings["path"])
    elif prof == "safe-detect":
        settings["dry_run"] = True
        settings["binary_replace"] = False
        settings["backup"] = False
        settings["base_root"] = None
    else:
        settings.setdefault("base_root", None)
    return settings

def show_menu(initial_lang: str):
    settings = default_settings(initial_lang)
    while True:
        lang = settings.get("lang","en")
        print("\n" + t(lang,"MENU_HEADER")); print(f"v{VERSION}")
        print(f"{t(lang,'LABEL_PATH')}: {os.path.abspath(settings['path'])}")
        on,off = t(lang,'LABEL_ON'), t(lang,'LABEL_OFF')
        print(f"{t(lang,'LABEL_POLICY')}: first{settings['visible_first']} + last{settings['visible_last']}, mask='{settings['mask_char']}'")
        print(f"{t(lang,'LABEL_ARCHIVES')}: {on if settings['rewrite_archives'] else off} | {t(lang,'LABEL_BINARIES')}: {on if settings['scan_all'] else off} (byte_replace: {on if settings['binary_replace'] else off})")
        print(f"{t(lang,'LABEL_BACKUPS')}: {on if settings['backup'] else off} | {t(lang,'LABEL_LIMIT')}: {settings['max_file_size_mb']}")
        log_label = settings['log'] or '(none)'
        print(f"{t(lang,'LABEL_LOGS')}: {log_label} [{settings['log_format']}] | {t(lang,'LABEL_LANG')}: {t(lang, 'LANG_UK') if lang=='uk' else t(lang,'LANG_EN')} | {t(lang,'LABEL_PROFILE')}: {settings.get('profile','none')}")
        print("-----------------------------------")
        print("1) " + t(lang,"MENU_ITEM_SCAN"))
        print("2) " + t(lang,"MENU_ITEM_SCAN_ASK"))
        print("3) " + t(lang,"MENU_ITEM_AUTOMASK"))
        print("4) " + t(lang,"MENU_ITEM_SETTINGS"))
        print("4.1) " + t(lang,"MENU_ITEM_PROFILE"))
        print("5) " + t(lang,"MENU_ITEM_SEAL_VERIFY"))
        print("6) " + t(lang,"MENU_ITEM_SEAL_CREATE"))
        print("7) " + t(lang,"MENU_ITEM_FP"))
        print("8) " + t(lang,"MENU_ITEM_EXIT"))
        try:
            choice = input(t(lang,"PROMPT_CHOICE")).strip()
        except EOFError:
            choice = "8"
        if choice == "1":
            run_scan_only(settings)
        elif choice == "2":
            run_scan_then_ask_mask(settings)
        elif choice == "3":
            run_auto_mask(settings)
        elif choice == "4":
            settings = edit_settings(settings)
        elif choice == "4.1":
            prof = input(t(lang,"PROFILE_SELECT") + " ").strip().lower()
            if prof in ("none","pci-strict","safe-detect"):
                settings["profile"] = prof
                settings = apply_profile(settings)
                print(t(lang,"WARN_PROFILE_ENFORCED"))
            else:
                print("…")
        elif choice == "5":
            seal_verify(os.path.abspath(__file__), lang)
        elif choice == "6":
            seal_create(os.path.abspath(__file__), lang)
        elif choice == "7":
            fp_menu(lang)
        elif choice == "8":
            break
        else:
            print("…")

# ----------------------------- CLI -----------------------------

def parse_args():
    p = argparse.ArgumentParser(description="PAN Guard Pro — menu/CLI (first4+last4), bilingual (uk/en).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--version", action="store_true", help="Print version and exit")
    p.add_argument("--no-menu", action="store_true", help="Run without menu (classic CLI)")
    p.add_argument("--lang", choices=["uk","en"], help="UI language")
    p.add_argument("--path", default=".", help="Base directory or file")
    p.add_argument("--backup", action="store_true", help="Create .bak before changes")
    p.add_argument("--scan-all", action="store_true", help="Scan binary files")
    p.add_argument("--binary-replace", action="store_true", help="Byte-level masking in binaries (risky)")
    p.add_argument("--rewrite-archives", action="store_true", help="Rewrite ZIP/OOXML with masking inside")
    p.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks")
    p.add_argument("--max-file-size-mb", type=int, default=MAX_FILE_SIZE_MB_DEFAULT, help="Max file size in MB")
    p.add_argument("--mask-char", default="X", help="Mask character (ASCII)")
    p.add_argument("--visible-first", type=int, default=4, help="How many first digits to keep")
    p.add_argument("--visible-last",  type=int, default=4, help="How many last digits to keep")
    p.add_argument("--log", default="", help="Log path (optional)")
    p.add_argument("--log-format", choices=["csv","json","ndjson"], default="ndjson", help="Log format")
    p.add_argument("--audit-log", default="", help="Append-only audit log (NDJSON with HMAC chain)")
    p.add_argument("--verify-log", default="", help="Verify audit log and exit")
    p.add_argument("--exclude-dirs", nargs="*", default=sorted(DEFAULT_EXCLUDE_DIRS), help="Exclude directories")
    p.add_argument("--no-exclude-system", action="store_true", help="Do not exclude system paths")
    p.add_argument("--allow-path", dest="allow_paths", nargs="*", default=[], help="Allow-list of paths/globs")
    p.add_argument("--auto-mask", action="store_true", help="Auto-mask without prompt")
    p.add_argument("--no-mask",   action="store_true", help="Scan only, never mask")
    p.add_argument("--dry-run",   action="store_true", help="Compatibility: same as --no-mask")
    p.add_argument("--profile", choices=["none","pci-strict","safe-detect"], default="none", help="Compliance profile")
    p.add_argument("--fp-add", nargs="*", help="Mark given file paths as FP (skip in future)")
    p.add_argument("--fp-add-strict", nargs="*", help="Mark given file paths as STRICT FP (skip only if sha matches)")
    p.add_argument("--fp-remove", nargs="*", help="Remove given file paths from FP list")
    p.add_argument("--fp-list", action="store_true", help="List FP entries and exit")
    p.add_argument("--fp-clear", action="store_true", help="Clear FP list and exit")
    p.add_argument("--seal", choices=["create","verify"], help="SEAL create/verify and exit")
    return p.parse_args()

def print_sha(lang: str):
    with open(os.path.abspath(__file__), "rb") as f:
        print(t(lang,"INFO_SHA", sha=hashlib.sha256(f.read()).hexdigest()))

def main():
    args = parse_args()
    if getattr(args, "version", False):
        print(f"PAN Guard Pro v{VERSION}")
        return

    lang = choose_lang(args.lang)

    if args.fp_list:
        for i,(p,meta) in enumerate(fp_list(), start=1):
            ts = meta.get("ts"); when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "?"
            strict = "strict" if meta.get("strict") else "loose"
            print(f"{i}. {p}  ({when}, {strict})")
        return
    if args.fp_clear:
        fp_clear(); print("FP cleared."); return
    if args.fp_add:
        for pth in args.fp_add:
            fp_add(pth, strict=False); print(f"FP add: {os.path.abspath(pth)}")
    if args.fp_add_strict:
        for pth in args.fp_add_strict:
            fp_add(pth, strict=True); print(f"FP add STRICT: {os.path.abspath(pth)}")
    if args.fp_remove:
        for pth in args.fp_remove:
            ok = fp_remove(pth); print(("FP removed: " + os.path.abspath(pth)) if ok else ("Not in FP: " + os.path.abspath(pth)))

    if args.verify_log:
        rc = verify_audit_log(args.verify_log)
        if rc == 0:
            print(t(lang,"VERIFYLOG_OK")); return
        elif rc > 0:
            print(t(lang,"VERIFYLOG_FAIL", i=rc)); sys.exit(2)
        else:
            print("Cannot verify audit log (missing key or error)."); sys.exit(3)

    if args.seal == "create": seal_create(os.path.abspath(__file__), lang); return
    if args.seal == "verify": seal_verify(os.path.abspath(__file__), lang); return

    if os.path.exists(seal_path(os.path.abspath(__file__))):
        seal_verify(os.path.abspath(__file__), lang)

    if not args.no_menu:
        show_menu(lang)
        print_sha(lang)
        sys.exit(0)

    settings = {
        "path": args.path,
        "backup": args.backup,
        "scan_all": args.scan_all,
        "binary_replace": args.binary_replace,
        "rewrite_archives": args.rewrite_archives,
        "follow_symlinks": args.follow_symlinks,
        "max_file_size_mb": args.max_file_size_mb,
        "mask_char": args.mask_char[:1] if args.mask_char else "X",
        "visible_first": args.visible_first,
        "visible_last": args.visible_last,
        "log": args.log,
        "log_format": args.log_format,
        "audit_log": args.audit_log,
        "exclude_dirs": args.exclude_dirs,
        "no_exclude_system": args.no_exclude_system,
        "dry_run": True if (args.no_mask or args.dry_run) else False,
        "lang": lang,
        "profile": args.profile,
        "allow_paths": args.allow_paths,
        "base_root": None,
    }
    settings = apply_profile(settings)
    ns = argparse.Namespace(**settings)
    ns.exclude_system_paths = set() if ns.no_exclude_system else set(DEFAULT_EXCLUDE_SYSTEM_PATHS)

    if settings["dry_run"]:
        findings = scan_target(ns, lang)
        print_summary(findings, lang)
        do_logging(findings=findings, args=ns)
        print_sha(lang); sys.exit(2 if findings else 0)

    if args.auto_mask:
        prev = scan_target(ns, lang)
        print_summary(prev, lang)
        if prev:
            ns.dry_run = False
            found2 = scan_target(ns, lang)
            print("\n" + t(lang,"HEADING_MASK_DONE"))
            print_summary(found2, lang)
            do_logging(findings=found2, args=ns)
        print_sha(lang); sys.exit(0)

    prev = scan_target(ns, lang)
    print_summary(prev, lang)
    do_logging(findings=prev, args=ns)
    if prev and prompt_bool(lang, t(lang,"PROMPT_MASK_NOW"), False):
        ns.dry_run = False
        found2 = scan_target(ns, lang)
        print("\n" + t(lang,"HEADING_MASK_DONE"))
        print_summary(found2, lang)
        do_logging(findings=found2, args=ns)
        print_sha(lang); sys.exit(0)
    print_sha(lang); sys.exit(2 if prev else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr); sys.exit(130)
