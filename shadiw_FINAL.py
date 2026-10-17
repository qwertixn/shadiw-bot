import re
import asyncio
import logging
import sqlite3
import html
import json
import os
import ssl
import time
import tempfile
import shutil
import urllib.request
import urllib.parse
import random
import string
from datetime import date, datetime, timedelta
from collections import Counter
from io import BytesIO

try:
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    pass

import aiohttp
_old_connector_init = aiohttp.TCPConnector.__init__
def _patched_connector_init(self, *args, **kwargs):
    kwargs['ssl'] = False
    _old_connector_init(self, *args, **kwargs)
aiohttp.TCPConnector.__init__ = _patched_connector_init

from aiogram import Bot, Dispatcher, F, types
from aiogram.dispatcher.event.bases import SkipHandler
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton,
    LabeledPrice, PreCheckoutQuery, ReplyKeyboardMarkup,
)
from aiogram.client.session.aiohttp import AiohttpSession

try:
    from search_core import find_in_bases
except Exception:
    def find_in_bases(q, limit=5): return []
try:
    from uploads import init_upload_db, register_upload_handlers
except Exception:
    def init_upload_db(): pass
    def register_upload_handlers(*a): pass
try:
    from ip_core import ip_all, format_ip_result
    from phone_core import phone_all, format_phone_result, phone_search_in_bases, format_phone_bases_result
    from ip_bot_addon import register_ip_handlers
except Exception:
    def ip_all(i): return {}
    def format_ip_result(r): return "❌"
    def register_ip_handlers(*a): pass
try:
    from email_core import email_all, format_email_result
    from email_bot_addon import register_email_handlers
except Exception:
    def email_all(e): return {}
    def format_email_result(r): return "❌"
    def register_email_handlers(*a): pass
try:
    from vk_core import vk_all, format_vk_result
    from vk_bot_addon import register_vk_handlers
except Exception:
    def vk_all(q): return {}
    def format_vk_result(r): return "❌"
    def register_vk_handlers(*a): pass


# ────────── НАСТРОЙКИ ──────────
# ═══ TOKENS_LOCKED — не трогать! ═══
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHANNEL_ID     = os.getenv("CHANNEL_ID", "@Milocerdia")
CHANNEL_URL    = os.getenv("CHANNEL_URL", "https://t.me/Milocerdia")
ADMIN_ID       = int(os.getenv("ADMIN_ID", "8961339709"))
TRUSTED_IDS    = {ADMIN_ID}

def is_trusted(user_id):
    return user_id in TRUSTED_IDS
PROXY_URL = ""

BIGBASE_COOKIES = os.getenv("BIGBASE_COOKIES", "")
VK_TOKEN = os.getenv("VK_TOKEN", "")
SHODAN_KEY  = os.getenv("SHODAN_KEY", "")
OCR_SPACE_KEY = os.getenv("OCR_SPACE_KEY", "")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMP_DIR = tempfile.gettempdir()
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "osint_bases"), exist_ok=True)
DB_PATH = os.getenv("DB_PATH", os.path.join(DATA_DIR, "bot_data.db"))
BASES_DB_PATH = os.getenv("BASES_DB", os.path.join(DATA_DIR, "bases.db"))

BASES_DIR = os.getenv("BASES_DIR", os.path.join(DATA_DIR, "osint_bases"))
TELEGRAM_FILE = os.getenv("TELEGRAM_FILE", os.path.join(DATA_DIR, "telegram_70m.txt"))

logging.basicConfig(level=logging.INFO)


def save_leaks_to_file(email, leak_data):
    """Сохраняет утечки LeakCheck в TXT."""
    from datetime import datetime
    safe = email.replace("@", "_at_").replace(".", "_")
    filename = f"leaks_{safe}_{int(datetime.now().timestamp())}.txt"
    paths = ["/storage/emulated/0/Download/", "/storage/emulated/0/Documents/", os.path.expanduser("~") + "/", "./"]
    L = []
    L.append("=" * 60)
    L.append(f"УТЕЧКИ LEAKCHECK: {email}")
    L.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("=" * 60)
    L.append(f"\nНайдено в {leak_data.get('found', 0)} утечках\n")
    fields = leak_data.get("fields", [])
    if fields:
        names = {"name": "ФИО", "password": "Пароль", "phone": "Телефон", "email": "Email",
                 "address": "Адрес", "city": "Город", "dob": "Дата рождения", "username": "Username"}
        L.append("ЧТО УТЕКЛО:")
        for f in fields:
            L.append(f"  • {names.get(f, f)}")
        L.append("")
    sources = leak_data.get("sources", [])
    if sources:
        L.append(f"ИСТОЧНИКИ ({len(sources)}):")
        for i, s in enumerate(sources, 1):
            if isinstance(s, dict):
                nm = s.get("name", "—")
                dt = s.get("date", "")
                L.append(f"  {i}. {nm}" + (f" ({dt})" if dt else ""))
            else:
                L.append(f"  {i}. {s}")
        L.append("")
    L.append("ПОЛНЫЕ ДАННЫЕ (JSON):")
    try:
        L.append(json.dumps(leak_data, ensure_ascii=False, indent=2))
    except Exception:
        L.append(str(leak_data))
    text = "\n".join(L)
    for path in paths:
        try:
            os.makedirs(path, exist_ok=True)
            fp = os.path.join(path, filename)
            with open(fp, "w", encoding="utf-8") as f:
                f.write(text)
            return fp
        except Exception:
            continue
    return None




def safe_truncate(text, max_len=4000):
    """Обрезает текст, не ломая HTML-теги."""
    if len(text) <= max_len:
        return text
    # Обрезаем
    cut = text[:max_len - 30]
    # Открытые теги
    open_b = cut.count("<b>") - cut.count("</b>")
    open_i = cut.count("<i>") - cut.count("</i>")
    open_code = cut.count("<code>") - cut.count("</code>")
    open_a = cut.count("<a ") - cut.count("</a>")
    # Закрываем
    close = ""
    if open_b > 0: close += "</b>" * open_b
    if open_i > 0: close += "</i>" * open_i
    if open_code > 0: close += "</code>" * open_code
    if open_a > 0: close += "</a>" * open_a
    return cut + close + chr(10) + chr(10) + "<i>...обрезано</i>"





# ═══════════════════════════════════════════
# ЗАЩИТА ЮЗЕРСКИХ ФАЙЛОВ
# ═══════════════════════════════════════════
USER_MAX_FILE_SIZE = 50 * 1024 * 1024       # 50 МБ
USER_MAX_ARCHIVE_SIZE = 100 * 1024 * 1024   # 100 МБ
USER_MAX_FILES_IN_ARCHIVE = 100
USER_ALLOWED_EXT = ("csv", "txt", "zip", "html", "htm")
USER_MAX_UPLOADS_PER_DAY = 5
USER_ALLOWED_INSIDE = ("csv", "txt", "html", "htm")

USER_DANGEROUS_PATTERNS = [
    "<script", "javascript:", "onerror=", "eval(",
    "exec(", "__import__", "os.system", "subprocess",
    "DROP TABLE", "DELETE FROM", "INSERT INTO",
]


def is_safe_filename(fname):
    """Проверка имени файла."""
    if not fname:
        return False
    fname_lower = fname.lower()
    # Опасные символы
    for s in ["..", "/", "\\", "$", "~", "|", "&", ";"]:
        if s in fname_lower:
            return False
    # Длина
    if len(fname) > 200:
        return False
    return True


def is_safe_content(text):
    """Проверка содержимого на опасные паттерны."""
    if not text:
        return (True, "")
    text_lower = text.lower()
    for pattern in USER_DANGEROUS_PATTERNS:
        if pattern.lower() in text_lower:
            return (False, f"Найдено: {pattern[:30]}")
    return (True, "")


def check_user_upload_limit(user_id):
    """Дневной лимит загрузок."""
    if user_id == ADMIN_ID:
        return (True, 0)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT COUNT(*) FROM user_uploads_protected WHERE user_id=? AND date(created_at)=?",
            (user_id, today)
        )
        count = cursor.fetchone()[0]
        conn.close()
        return (count < USER_MAX_UPLOADS_PER_DAY, count)
    except Exception:
        return (True, 0)


def log_user_upload(user_id, fname, fsize, fhash, status, reason=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO user_uploads_protected (user_id, file_name, file_size, file_hash, status, reason, created_at) VALUES (?,?,?,?,?,?,?)",
            (user_id, fname, fsize, fhash, status, reason[:300],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def html_to_csv_safe(html_path, csv_path):
    """HTML → CSV безопасно."""
    import csv
    import html as _html
    try:
        content = ""
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try:
                with open(html_path, "r", encoding=enc, errors="ignore") as f:
                    content = f.read()
                break
            except Exception:
                continue
        if not content:
            return (0, "Не прочитать файл")
        tables = re.findall(r"<table[^>]*>(.*?)</table>", content, re.DOTALL | re.IGNORECASE)
        if not tables:
            tables = [content]
        all_rows = []
        for table in tables:
            rows = re.findall(r"<tr[^>]*>(.*?)</tr>", table, re.DOTALL | re.IGNORECASE)
            for row in rows:
                cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.DOTALL | re.IGNORECASE)
                cleaned = []
                for cell in cells:
                    cell = re.sub(r"<[^>]+>", "", cell)
                    cell = _html.unescape(cell)
                    cell = " ".join(cell.split())
                    cleaned.append(cell)
                if any(cleaned):
                    all_rows.append(cleaned)
        if not all_rows:
            return (0, "Таблиц нет")
        max_cols = max(len(r) for r in all_rows)
        for row in all_rows:
            while len(row) < max_cols:
                row.append("")
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerows(all_rows)
        return (len(all_rows), None)
    except Exception as e:
        return (0, str(e)[:200])


def extract_archive_safe(filepath, extract_dir, password=None):
    """Распаковка с проверкой безопасности."""
    ext = filepath.lower().rsplit(".", 1)[-1] if "." in filepath else ""
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        if ext == "zip":
            logging.info(f"[ZIP] Открываю {filepath}")
            with zipfile.ZipFile(filepath, 'r') as archive:
                if password:
                    archive.setpassword(password.encode())
                archive.extractall(path=extract_dir)
            logging.info(f"[ZIP] Распаковано в {extract_dir}")
        else:
            return (False, [], f"формат .{ext} не поддерживается (только zip)")

        files = []
        total_size = 0
        for root, dirs, fs in os.walk(extract_dir):
            for f in fs:
                full = os.path.join(root, f)
                f_ext = f.lower().rsplit(".", 1)[-1] if "." in f else ""
                
                # Безопасность: только разрешённые
                if f_ext not in USER_ALLOWED_INSIDE:
                    logging.warning(f"Пропущен файл: {f} (.{f_ext})")
                    continue
                
                # Безопасное имя
                if not is_safe_filename(f):
                    logging.warning(f"Опасное имя: {f}")
                    continue
                
                # Авто-конвертация HTML → CSV
                if f_ext in ("html", "htm"):
                    csv_path = full.rsplit(".", 1)[0] + ".csv"
                    try:
                        rows, err = html_to_csv_safe(full, csv_path)
                        if rows > 0:
                            files.append(csv_path)
                            logging.info(f"HTML→CSV: {f} → {rows} строк")
                        else:
                            logging.warning(f"HTML→CSV failed: {f}: {err}")
                    except Exception as e:
                        logging.warning(f"HTML→CSV error {f}: {e}")
                    continue

                # Обычные CSV/TXT добавляем как есть
                fsize = os.path.getsize(full)
                total_size += fsize
                if total_size > USER_MAX_ARCHIVE_SIZE:
                    return (False, [], "Архив слишком большой")
                
                if len(files) >= USER_MAX_FILES_IN_ARCHIVE:
                    return (False, [], f"Больше {USER_MAX_FILES_IN_ARCHIVE} файлов")
                
                files.append(full)
        
        return (True, files, None)
    except Exception as e:
        err = str(e).lower()
        if "password" in err or "encrypted" in err:
            return (False, [], "password_required")
        return (False, [], str(e)[:200])



# ═══════════════════════════════════════════
# НАСТРОЙКИ ЗАЩИТЫ
# ═══════════════════════════════════════════

RATE_LIMITS = {
    "search": 20,
    "promo_attempt": 5,
    "upload": 3,
    "command": 30,
    "callback": 60,
    "message": 50,
}

MAX_FILE_SIZE_MB = 50
MAX_USER_UPLOADS_PER_DAY = 5

DANGEROUS_PATTERNS = [
    "drop table", "delete from", "truncate",
    "or 1=1", "or '1'='1'",
    "eval(", "exec(", "__import__",
    "<script", "javascript:", "onerror=",
]

# ═══════════ ПРОКСИ ═══════════
PROXY_BOT = os.getenv("PROXY_BOT", "")

if PROXY_BOT:
    session = AiohttpSession(proxy=PROXY_BOT)
    bot = Bot(token=BOT_TOKEN, session=session)
    print(f"🌐 Прокси: {PROXY_BOT[:35]}...")
else:
    bot = Bot(token=BOT_TOKEN)
    print("🌐 Без прокси")
dp = Dispatcher(storage=MemoryStorage())


DEF_CODES = {
    "900": "МТС", "901": "МТС", "902": "МТС", "903": "МТС", "904": "МТС",
    "905": "МТС", "906": "МТС", "908": "МТС", "909": "МТС", "910": "МТС",
    "911": "МТС", "912": "МТС", "913": "МТС", "914": "МТС", "915": "МТС",
    "916": "МТС", "917": "МТС", "918": "МТС", "919": "МТС", "950": "МТС",
    "951": "МТС", "952": "МТС", "953": "МТС", "958": "МТС", "977": "МТС",
    "978": "МТС", "980": "МТС", "981": "МТС", "982": "МТС", "983": "МТС",
    "984": "МТС", "985": "МТС", "986": "МТС", "987": "МТС", "988": "МТС",
    "989": "МТС",
    "920": "МегаФон", "921": "МегаФон", "922": "МегаФон", "923": "МегаФон",
    "924": "МегаФон", "925": "МегаФон", "926": "МегаФон", "927": "МегаФон",
    "928": "МегаФон", "929": "МегаФон", "930": "МегаФон", "931": "МегаФон",
    "932": "МегаФон", "933": "МегаФон", "934": "МегаФон", "936": "МегаФон",
    "937": "МегаФон", "938": "МегаФон", "939": "МегаФон", "995": "МегаФон",
    "960": "Билайн", "961": "Билайн", "962": "Билайн", "963": "Билайн",
    "964": "Билайн", "965": "Билайн", "966": "Билайн", "967": "Билайн",
    "968": "Билайн", "969": "Билайн", "999": "Билайн",
}

_antiflood_cache = {}
_subscription_cache = {}
ANTIFLOOD_LIMIT = 5
ANTIFLOOD_WINDOW = 10
_autopost_task = None
_auto_broadcast_task = None

ACHIEVEMENTS = {
    "first_search":  ("🥇", "Первый поиск"),
    "ten_searches":  ("🔟", "10 поисков"),
    "hundred":       ("💯", "100 поисков"),
    "phone_hunter":  ("📱", "Phone-OSINT"),
    "username_hunt": ("🔎", "Username-OSINT"),
    "ip_hunter":     ("🌍", "IP-OSINT"),
    "vk_hunter":     ("🆔", "VK-OSINT"),
    "email_hunter":  ("📧", "Email-OSINT"),
    "vip_member":    ("👑", "VIP-статус"),
    "referrer":      ("🤝", "Пригласил друга"),
    "level_5":       ("⭐", "Уровень 5"),
    "night_owl":     ("🦉", "Ночной поиск"),
    "gift_hunter":   ("🎁", "Telegram Gifts"),
}


# ────────── HTTP HELPERS ──────────
def _pget(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e)}


def _pget_raw(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return f"error: {e}"


# ────────── БАЗА ──────────
# ═══════════════════════════════════════════
# ЕДИНАЯ БАЗА ДАННЫХ
# ═══════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT,
        subscription_tier TEXT DEFAULT 'Free', requests_today INTEGER DEFAULT 0,
        last_request_date TEXT, referred_by INTEGER, total_stars_spent INTEGER DEFAULT 0,
        vip_until TEXT, xp INTEGER DEFAULT 0, level INTEGER DEFAULT 1)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS promocodes (
        code TEXT PRIMARY KEY, type TEXT DEFAULT 'VIP',
        max_uses INTEGER DEFAULT 1, used_count INTEGER DEFAULT 0)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS promo_activations (
        user_id INTEGER, code TEXT, activated_at TEXT,
        PRIMARY KEY (user_id, code))""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT, phone TEXT,
        department TEXT, status TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS bans (
        user_id INTEGER PRIMARY KEY, username TEXT, reason TEXT,
        banned_at TEXT, banned_by INTEGER)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS search_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
        query TEXT, search_type TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS achievements (
        user_id INTEGER, code TEXT, unlocked_at TEXT,
        PRIMARY KEY (user_id, code))""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS autopost (
        id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT, text TEXT,
        photo TEXT, interval_min INTEGER, last_sent TEXT, enabled INTEGER DEFAULT 1)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS autobroadcast (
        id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, interval_min INTEGER,
        last_sent TEXT, enabled INTEGER DEFAULT 1)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS anon_mailboxes (
        session_id TEXT PRIMARY KEY,
        email TEXT, password TEXT, login TEXT, domain TEXT,
        token TEXT, created_at TEXT, expires_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS anon_mail_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT, direction TEXT, from_email TEXT, to_email TEXT,
        subject TEXT, body TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS anon_favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT, msg_id TEXT, from_email TEXT, subject TEXT,
        body TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS rate_limits (
        user_id INTEGER, action TEXT, count INTEGER DEFAULT 0,
        window_start TEXT, PRIMARY KEY (user_id, action))""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, event_type TEXT, details TEXT,
        ip_info TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS file_uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, file_name TEXT, file_size INTEGER,
        file_hash TEXT, status TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS patch_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patch_name TEXT, changes TEXT, size_before INTEGER,
        size_after INTEGER, applied_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_uploads_protected (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, file_name TEXT, file_size INTEGER,
        file_hash TEXT, status TEXT, reason TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS file_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, file_name TEXT, scan_result TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT, user_id INTEGER, username TEXT,
        message TEXT, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT,
        message TEXT, status TEXT DEFAULT 'open', created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        referred_id INTEGER UNIQUE, created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS prizes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, prize_type TEXT,
        prize_value TEXT, status TEXT DEFAULT 'pending',
        created_at TEXT, given_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS prize_thresholds (
        friends_count INTEGER PRIMARY KEY, prize_type TEXT,
        prize_value TEXT, enabled INTEGER DEFAULT 1)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS base_uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, file_name TEXT,
        rows_count INTEGER, status TEXT DEFAULT 'pending', uploaded_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        queries_added INTEGER,
        stars_paid INTEGER,
        charge_id TEXT,
        created_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_queries (
        user_id INTEGER PRIMARY KEY,
        extra_queries INTEGER DEFAULT 0,
        quota_fio INTEGER DEFAULT 0,
        quota_phone INTEGER DEFAULT 0,
        quota_ip INTEGER DEFAULT 0,
        quota_email INTEGER DEFAULT 0,
        quota_vk INTEGER DEFAULT 0,
        quota_username INTEGER DEFAULT 0,
        quota_bigbase INTEGER DEFAULT 0)""")
    cursor.execute("""INSERT OR IGNORE INTO prize_thresholds (friends_count, prize_type, prize_value)
        VALUES (10, 'VIP', '1 месяц'), (25, 'Premium', '3 месяца'),
               (50, 'Stars', '50'), (100, 'Bot', 'подписка на другой бот')""")
    conn.commit()
    conn.close()


def _get_setting(key, default=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default


def _set_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()


def get_bigbase_cookies():
    try:
        with open("bigbase_cookies.txt", "r", encoding="utf-8") as f:
            cookies = f.read().strip()
            if cookies:
                return cookies
    except Exception:
        pass
    return BIGBASE_COOKIES


def save_bigbase_cookies(cookies_str):
    with open("bigbase_cookies.txt", "w", encoding="utf-8") as f:
        f.write(cookies_str.strip())


def generate_promo(length=10):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def save_promo(code, p_type="VIP", max_uses=1):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO promocodes (code, type, max_uses, used_count) VALUES (?, ?, ?, 0)",
                   (code, p_type, max_uses))
    conn.commit()
    conn.close()


def redeem_promo(user_id, code):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM promo_activations WHERE user_id = ? AND code = ?", (user_id, code))
    if cursor.fetchone():
        conn.close()
        return False, "already_activated"
    cursor.execute("SELECT type, max_uses, used_count FROM promocodes WHERE code = ?", (code,))
    res = cursor.fetchone()
    if not res:
        conn.close()
        return False, "not_found"
    p_type, max_uses, used_count = res
    if used_count >= max_uses:
        conn.close()
        return False, "limit_exceeded"
    cursor.execute("UPDATE promocodes SET used_count = used_count + 1 WHERE code = ?", (code,))
    cursor.execute("INSERT INTO promo_activations (user_id, code, activated_at) VALUES (?, ?, ?)",
                   (user_id, code, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    update_subscription(user_id, p_type)
    return True, p_type


def get_users_for_promo_broadcast():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    users = cursor.execute("SELECT user_id FROM users").fetchall()
    conn.close()
    return [u[0] for u in users]


async def notify_admin_new_user(user_id, username, first_name):
    try:
        await bot.send_message(
            ADMIN_ID,
            f"🔔 <b>Новый пользователь:</b>\n├ 🆔 <code>{user_id}</code>\n"
            f"├ 👤 @{username or '—'}\n└ 👋 {first_name or '—'}",
            parse_mode="HTML"
        )
    except Exception:
        pass


async def notify_admin_cookies_expired():
    """Сообщает админу, что куки BigBase протухли."""
    try:
        await bot.send_message(
            ADMIN_ID,
            "🔑 <b>Куки BigBase протухли!</b>\n\n"
            "Обнови их:\n"
            "1️⃣ Открой bigbase.site в браузере\n"
            "2️⃣ DevTools → Console → введи <code>document.cookie</code>\n"
            "3️⃣ Скопируй всю строку\n"
            "4️⃣ Отправь её сюда: <code>/setcookies СТРОКА</code>",
            parse_mode="HTML"
        )
    except Exception as e:
        logging.warning(f"notify cookies error: {e}")


def mask_fio(fio):
    if not fio:
        return ""
    parts = fio.split()
    masked = []
    for p in parts:
        if len(p) >= 1:
            masked.append(p[0] + "***")
    return " ".join(masked)


def add_or_update_user(user_id, username, first_name, ref_by=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users (user_id, username, first_name, referred_by) VALUES (?, ?, ?, ?)",
                       (user_id, username, first_name, ref_by))
        try:
            log_admin_event("new_user", user_id, username,
                           f"{first_name} | ref: {ref_by or '—'}")
        except Exception:
            pass
        if ref_by:
            give_referral_bonus(ref_by)
    else:
        cursor.execute("UPDATE users SET username=?, first_name=? WHERE user_id=?",
                       (username, first_name, user_id))
    conn.commit()
    conn.close()


def get_user_subscription(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT subscription_tier FROM users WHERE user_id = ?", (user_id,))
    res = cursor.fetchone()
    conn.close()
    return res[0] if res else "Free"


def update_subscription(user_id, tier, stars=0):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET subscription_tier = ?, total_stars_spent = total_stars_spent + ? WHERE user_id = ?",
                   (tier, stars, user_id))
    conn.commit()
    conn.close()
    if tier != "Free":
        unlock_achievement(user_id, "vip_member")


def check_and_add_user(user_id, username, first_name, ref_by=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    is_new = cursor.fetchone() is None
    conn.close()
    add_or_update_user(user_id, username, first_name, ref_by)
    return is_new


def give_referral_bonus(inviter_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    until = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d")
    cursor.execute("UPDATE users SET subscription_tier='VIP', vip_until=? WHERE user_id=?",
                   (until, inviter_id))
    conn.commit()
    conn.close()
    unlock_achievement(inviter_id, "referrer")


def add_referral(user_id, referred_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO referrals (user_id, referred_id, created_at) VALUES (?, ?, ?)",
                       (user_id, referred_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    except Exception:
        pass
    conn.close()


def get_referral_count(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM referrals WHERE user_id = ?", (user_id,))
    n = cursor.fetchone()[0]
    conn.close()
    return n


def get_prize_thresholds():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT friends_count, prize_type, prize_value FROM prize_thresholds WHERE enabled=1 ORDER BY friends_count ASC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_next_prize(user_id):
    count = get_referral_count(user_id)
    thresholds = get_prize_thresholds()
    for friends, ptype, pvalue in thresholds:
        if count < friends:
            return friends, ptype, pvalue
    return None, None, None


def create_prize_request(user_id, ptype, pvalue):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM prizes WHERE user_id=? AND prize_type=? AND prize_value=? AND status='pending'",
                   (user_id, ptype, pvalue))
    if cursor.fetchone():
        conn.close()
        return False
    cursor.execute("INSERT INTO prizes (user_id, prize_type, prize_value, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                   (user_id, ptype, pvalue, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return True


def check_and_create_prizes(user_id):
    count = get_referral_count(user_id)
    thresholds = get_prize_thresholds()
    created = []
    for friends, ptype, pvalue in thresholds:
        if count >= friends:
            if create_prize_request(user_id, ptype, pvalue):
                created.append((ptype, pvalue))
    return created


def get_user_prizes(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, prize_type, prize_value, status, created_at FROM prizes WHERE user_id=? ORDER BY id DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_pending_prizes(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""SELECT p.id, p.user_id, u.username, p.prize_type, p.prize_value, p.created_at
                      FROM prizes p LEFT JOIN users u ON u.user_id = p.user_id
                      WHERE p.status='pending' ORDER BY p.id DESC LIMIT ?""", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def mark_prize_given(prize_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE prizes SET status='given', given_at=? WHERE id=?",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), prize_id))
    conn.commit()
    conn.close()


def check_and_update_limit(user_id, qtype="fio"):
    """
    Проверяет и списывает лимит.
    Приоритет: квота по типу → общие доп.запросы → тариф.
    """
    if user_id == ADMIN_ID:
        return True, 999

    # 1) Квота по типу
    if get_quota(user_id, qtype) > 0:
        spend_quota(user_id, qtype)
        return True, get_quota(user_id, qtype)

    # 2) Общие доп. запросы
    extra = get_extra_queries(user_id)
    if extra > 0:
        spend_extra_query(user_id)
        return True, extra - 1

    # 3) Тариф
    tier = get_user_subscription(user_id)
    if tier != "Free":
        return True, 999

    # Free — 3 запроса в день
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    today = date.today().isoformat()
    cursor.execute("SELECT requests_today, last_request_date FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row is None or row[1] != today:
        cursor.execute("UPDATE users SET requests_today = 1, last_request_date = ? WHERE user_id = ?",
                       (today, user_id))
        conn.commit()
        conn.close()
        return True, 2
    requests_today, _ = row
    if requests_today < 3:
        new_count = requests_today + 1
        cursor.execute("UPDATE users SET requests_today = ? WHERE user_id = ?", (new_count, user_id))
        conn.commit()
        conn.close()
        return True, 3 - new_count
    conn.close()
    return False, 0


def get_extra_queries(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT extra_queries FROM user_queries WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0


def add_extra_queries(user_id, amount):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO user_queries (user_id, extra_queries)
        VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET extra_queries = extra_queries + ?
    """, (user_id, amount, amount))
    conn.commit()
    conn.close()
    
QUOTA_TYPES = {
    "fio": "👤 Поиск по ФИО",
    "phone": "📱 Phone-OSINT",
    "ip": "🌍 IP-OSINT",
    "email": "📧 Email-OSINT",
    "vk": "🆔 VK-OSINT",
    "username": "🔎 Username OSINT",
    "bigbase": "🔓 Закрытые базы",
}


def _ensure_quota_row(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO user_queries (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()


def add_quota(user_id, qtype, amount):
    if qtype not in QUOTA_TYPES:
        return False
    _ensure_quota_row(user_id)
    col = f"quota_{qtype}"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"UPDATE user_queries SET {col} = {col} + ? WHERE user_id = ?", (amount, user_id))
    conn.commit()
    conn.close()
    return True


def get_quota(user_id, qtype):
    if qtype not in QUOTA_TYPES:
        return 0
    col = f"quota_{qtype}"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT {col} FROM user_queries WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row and row[0] else 0


def spend_quota(user_id, qtype):
    if qtype not in QUOTA_TYPES:
        return False
    col = f"quota_{qtype}"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT {col} FROM user_queries WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row and row[0] and row[0] > 0:
        cursor.execute(f"UPDATE user_queries SET {col} = {col} - 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def get_all_quotas(user_id):
    _ensure_quota_row(user_id)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cols = ", ".join(f"quota_{k}" for k in QUOTA_TYPES)
    cursor.execute(f"SELECT {cols} FROM user_queries WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {k: 0 for k in QUOTA_TYPES}
    return {k: (row[i] or 0) for i, k in enumerate(QUOTA_TYPES)}

def spend_extra_query(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT extra_queries FROM user_queries WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    if row and row[0] > 0:
        cursor.execute("UPDATE user_queries SET extra_queries = extra_queries - 1 WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def search_in_contacts(criterion, query):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if criterion == "fio":
        cursor.execute("SELECT full_name, phone, department, status FROM contacts WHERE full_name LIKE ?",
                       (f"%{query}%",))
    else:
        cursor.execute("SELECT full_name, phone, department, status FROM contacts WHERE phone LIKE ?",
                       (f"%{query}%",))
    results = cursor.fetchall()
    conn.close()
    return results


def add_ban(user_id, username, reason, banned_by):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO bans (user_id, username, reason, banned_at, banned_by) VALUES (?, ?, ?, ?, ?)",
                   (user_id, username or "", reason or "",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"), banned_by))
    conn.commit()
    conn.close()


def remove_ban(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def is_banned(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT reason FROM bans WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def get_all_bans(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, reason, banned_at FROM bans ORDER BY banned_at DESC LIMIT ?",
                   (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows




def log_admin_event(event_type, user_id=None, username=None, message=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO admin_logs (event_type, user_id, username, message, created_at) "
            "VALUES (?,?,?,?,?)",
            (event_type, user_id, username or "", str(message)[:500],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def log_search(user_id, username, query, search_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO search_logs (user_id, username, query, search_type, created_at) VALUES (?, ?, ?, ?, ?)",
                   (user_id, username or "", query, search_type,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def get_search_logs(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, query, search_type, created_at FROM search_logs ORDER BY id DESC LIMIT ?",
                   (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_top_queries(limit=5):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT query, COUNT(*) as c FROM search_logs GROUP BY query ORDER BY c DESC LIMIT ?",
                   (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, first_name, subscription_tier, requests_today FROM users WHERE username = ?",
                   (username.lstrip("@"),))
    row = cursor.fetchone()
    conn.close()
    return row


def get_recent_users(limit=20):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, first_name, subscription_tier FROM users ORDER BY user_id DESC LIMIT ?",
                   (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_vip_users(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, first_name, subscription_tier FROM users WHERE subscription_tier != 'Free' ORDER BY user_id DESC LIMIT ?",
                   (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    total_users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    subs = cursor.execute("SELECT COUNT(*) FROM users WHERE subscription_tier != 'Free'").fetchone()[0]
    stars = cursor.execute("SELECT SUM(total_stars_spent) FROM users").fetchone()[0] or 0
    bans_count = cursor.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
    conn.close()
    return total_users, subs, stars, bans_count


def get_top_users(limit=10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, xp, level FROM users ORDER BY xp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_search_types():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT search_type, COUNT(*) FROM search_logs GROUP BY search_type ORDER BY COUNT(*) DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_top_referrers(limit=10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""SELECT u.user_id, u.username, COUNT(r.id) as cnt
                      FROM users u JOIN referrals r ON r.user_id = u.user_id
                      GROUP BY u.user_id ORDER BY cnt DESC LIMIT ?""", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_week_growth():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    cursor.execute("SELECT COUNT(*) FROM users WHERE last_request_date >= ?", (week_ago,))
    n = cursor.fetchone()[0]
    conn.close()
    return n


def get_stats_by_days():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT substr(created_at, 1, 10) as d, COUNT(*) FROM search_logs GROUP BY d ORDER BY d DESC LIMIT 7")
    rows = cursor.fetchall()
    conn.close()
    return rows


def clear_old_logs(days=30):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("DELETE FROM search_logs WHERE created_at < ?", (cutoff,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected


def get_user_xp(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT xp, level FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else (0, 1)




# ═══════════════════════════════════════════
# ПРОГРЕССИВНАЯ СИСТЕМА XP
# ═══════════════════════════════════════════

def xp_for_level(level):
    """XP для перехода с уровня level на level+1."""
    if level < 1:
        level = 1
    if level <= 10:
        return level * level * 100
    elif level <= 20:
        return level * level * 200
    elif level <= 30:
        return level * level * 500
    else:
        return level * level * 1000


def get_level_info(user_id):
    xp, level = get_user_xp(user_id)
    need = xp_for_level(level)
    pct = int((xp / need) * 100) if need > 0 else 0
    return {
        "xp": xp, "level": level, "need": need,
        "to_next": max(0, need - xp),
        "progress": pct, "next_level": level + 1,
    }


def add_xp_advanced(user_id, amount=10):
    """Прогрессивный add_xp. Возвращает (old_lvl, new_lvl, уровни)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT xp, level FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return (1, 1, 0)

    xp, level = row
    old_level = level
    xp += amount

    while xp >= xp_for_level(level) and level < 100:
        xp -= xp_for_level(level)
        level += 1

    cursor.execute("UPDATE users SET xp = ?, level = ? WHERE user_id = ?", (xp, level, user_id))
    conn.commit()
    conn.close()
    return (old_level, level, level - old_level)


# ═══════════════════════════════════════════
# НАГРАДЫ
# ═══════════════════════════════════════════
ACHIEVEMENT_REWARDS = {
    "first_search":  {"type": "queries", "amount": 3,  "desc": "+3 запроса"},
    "ten_searches":  {"type": "queries", "amount": 5,  "desc": "+5 запросов"},
    "hundred":       {"type": "premium", "days": 3,    "desc": "Premium 3 дня"},
    "phone_hunter":  {"type": "queries", "amount": 10, "desc": "+10 запросов"},
    "username_hunt": {"type": "queries", "amount": 10, "desc": "+10 запросов"},
    "ip_hunter":     {"type": "queries", "amount": 5,  "desc": "+5 запросов"},
    "vk_hunter":     {"type": "queries", "amount": 5,  "desc": "+5 запросов"},
    "email_hunter":  {"type": "queries", "amount": 10, "desc": "+10 запросов"},
    "night_owl":     {"type": "queries", "amount": 5,  "desc": "+5 запросов"},
    "gift_hunter":   {"type": "queries", "amount": 3,  "desc": "+3 запроса"},
    "level_5":       {"type": "queries", "amount": 50, "desc": "+50 запросов"},
    "referrer":      {"type": "vip",     "days": 3,    "desc": "VIP 3 дня"},
}

LEVEL_REWARDS = {
    3:  {"type": "queries", "amount": 10, "desc": "+10 запросов"},
    5:  {"type": "queries", "amount": 50, "desc": "+50 запросов"},
    7:  {"type": "premium", "days": 1,    "desc": "Premium 1 день"},
    10: {"type": "premium", "days": 3,    "desc": "Premium 3 дня"},
    15: {"type": "premium", "days": 7,    "desc": "Premium 7 дней"},
    20: {"type": "vip",     "days": 3,    "desc": "VIP 3 дня"},
    30: {"type": "vip",     "days": 7,    "desc": "VIP 7 дней"},
}


def _apply_reward(user_id, reward):
    """Применяет награду. Возвращает текст."""
    rtype = reward.get("type")
    desc = reward.get("desc", "")

    try:
        if rtype == "queries":
            add_extra_queries(user_id, reward.get("amount", 0))
            return f"🎟 {desc}"

        elif rtype == "premium":
            days = reward.get("days", 1)
            until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT subscription_tier FROM users WHERE user_id=?", (user_id,))
            row = cursor.fetchone()
            current = row[0] if row else "Free"
            if current != "VIP":
                cursor.execute(
                    "UPDATE users SET subscription_tier='Premium', vip_until=? WHERE user_id=?",
                    (until, user_id)
                )
            conn.commit()
            conn.close()
            unlock_achievement(user_id, "vip_member")
            return f"💎 {desc}"

        elif rtype == "vip":
            days = reward.get("days", 1)
            until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET subscription_tier='VIP', vip_until=? WHERE user_id=?",
                (until, user_id)
            )
            conn.commit()
            conn.close()
            unlock_achievement(user_id, "vip_member")
            return f"👑 {desc}"
    except Exception as e:
        logging.warning(f"_apply_reward error: {e}")
    return None


def _ensure_rewards_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS given_rewards (
        user_id INTEGER, reward_key TEXT, given_at TEXT,
        PRIMARY KEY (user_id, reward_key)
    )""")
    conn.commit()
    conn.close()


def _is_reward_given(user_id, key):
    _ensure_rewards_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM given_rewards WHERE user_id=? AND reward_key=?", (user_id, key))
    ok = cursor.fetchone() is not None
    conn.close()
    return ok


def _mark_reward_given(user_id, key):
    _ensure_rewards_table()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO given_rewards (user_id, reward_key, given_at) VALUES (?,?,?)",
        (user_id, key, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def check_and_give_rewards(user_id):
    """Проверяет и выдаёт все награды. Возвращает список."""
    rewards_text = []

    # Достижения
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT code FROM achievements WHERE user_id=?", (user_id,))
    unlocked = {row[0] for row in cursor.fetchall()}
    conn.close()

    for code in unlocked:
        if code in ACHIEVEMENT_REWARDS:
            key = f"ach_{code}"
            if not _is_reward_given(user_id, key):
                text = _apply_reward(user_id, ACHIEVEMENT_REWARDS[code])
                if text:
                    rewards_text.append(f"🏆 {text}")
                    _mark_reward_given(user_id, key)

    # Уровни
    _, level = get_user_xp(user_id)
    for lvl in sorted(LEVEL_REWARDS.keys()):
        if level >= lvl:
            key = f"lvl_{lvl}"
            if not _is_reward_given(user_id, key):
                text = _apply_reward(user_id, LEVEL_REWARDS[lvl])
                if text:
                    rewards_text.append(text)
                    _mark_reward_given(user_id, key)

    return rewards_text


def get_user_rewards(user_id):
    _ensure_rewards_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT reward_key, given_at FROM given_rewards WHERE user_id=? ORDER BY given_at DESC",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()

    result = []
    for key, dt in rows:
        if key.startswith("ach_"):
            code = key[4:]
            if code in ACHIEVEMENT_REWARDS:
                r = ACHIEVEMENT_REWARDS[code]
                name = ACHIEVEMENTS.get(code, ("", "Достижение"))[1]
                result.append((f"🏆 {name}", r.get("desc", ""), dt))
        elif key.startswith("lvl_"):
            lvl = int(key[4:])
            if lvl in LEVEL_REWARDS:
                r = LEVEL_REWARDS[lvl]
                result.append((f"⭐ Уровень {lvl}", r.get("desc", ""), dt))
    return result


def add_xp(user_id, amount=10):
    """Обёртка — прогрессивная формула."""
    return add_xp_advanced(user_id, amount)



def get_search_count(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM search_logs WHERE user_id=?", (user_id,))
    n = cursor.fetchone()[0]
    conn.close()
    return n


def unlock_achievement(user_id, code):
    if code not in ACHIEVEMENTS:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM achievements WHERE user_id=? AND code=?", (user_id, code))
    if cursor.fetchone():
        conn.close()
        return False
    cursor.execute("INSERT INTO achievements (user_id, code, unlocked_at) VALUES (?,?,?)",
                   (user_id, code, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return True


def get_user_achievements(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT code, unlocked_at FROM achievements WHERE user_id=?", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def check_and_award(user_id, kind):
    unlocked = []
    n = get_search_count(user_id)
    if n >= 1 and unlock_achievement(user_id, "first_search"):
        unlocked.append("first_search")
    if n >= 10 and unlock_achievement(user_id, "ten_searches"):
        unlocked.append("ten_searches")
    if n >= 100 and unlock_achievement(user_id, "hundred"):
        unlocked.append("hundred")
    kind_map = {
        "phone": "phone_hunter", "username": "username_hunt",
        "ip": "ip_hunter", "vk": "vk_hunter", "email": "email_hunter",
        "gift": "gift_hunter",
    }
    if kind in kind_map and unlock_achievement(user_id, kind_map[kind]):
        unlocked.append(kind_map[kind])
    _, lvl = get_user_xp(user_id)
    if lvl >= 5 and unlock_achievement(user_id, "level_5"):
        unlocked.append("level_5")
    h = datetime.now().hour
    if 0 <= h < 5 and unlock_achievement(user_id, "night_owl"):
        unlocked.append("night_owl")
    return unlocked


def antiflood_check(user_id):
    if _get_setting("antiflood", "0") != "1":
        return True
    if user_id == ADMIN_ID:
        return True
    now = time.time()
    arr = _antiflood_cache.setdefault(user_id, [])
    arr[:] = [t for t in arr if now - t < ANTIFLOOD_WINDOW]
    arr.append(now)
    return len(arr) <= ANTIFLOOD_LIMIT


def ip_flag(code):
    if not code or len(code) != 2:
        return "🏳️"
    code = code.upper()
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


def pretty_search(query, limit=5):
    results = find_in_bases(query, limit=limit)
    if not results:
        return None, 0
    cards = []
    for i, card_text in enumerate(results, 1):
        lines = card_text.split("\n")
        body = []
        for line in lines:
            if ":" in line and not line.startswith("📁"):
                k, v = line.split(":", 1)
                k = k.strip(); v = v.strip()
                if v:
                    body.append(f"├─ <b>{html.escape(k)}</b>: <code>{html.escape(v)}</code>")
            else:
                body.insert(0, f"<b>{html.escape(line)}</b>")
        cards.append(f"📇 <b>Карточка #{i}</b>\n" + "\n".join(body))
    return cards, len(cards)


def get_db_count():
    try:
        conn = sqlite3.connect(BASES_DB_PATH)
        n = conn.execute("SELECT COUNT(*) FROM r").fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0
        


import csv

import zipfile

# ЕДИНАЯ БАЗА ДАННЫХ
# DB_PATH уже определён выше

try:
    import py7zr
    SEVEN_ZIP_SUPPORT = True
except ImportError:
    SEVEN_ZIP_SUPPORT = False

try:
    import rarfile
    RAR_SUPPORT = True
except ImportError:
    RAR_SUPPORT = False


def count_rows_in_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def save_upload_to_db(user_id, username, file_name, file_id, rows_count):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO base_uploads (user_id, username, file_name, file_id, rows_count, status, uploaded_at) "
        "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
        (user_id, username or "", file_name, file_id, rows_count,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    upload_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return upload_id


def get_upload(upload_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, username, file_name, file_id, rows_count, status FROM base_uploads WHERE id=?",
                   (upload_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_pending_uploads(limit=20):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""SELECT id, user_id, username, file_name, rows_count, uploaded_at
                      FROM base_uploads WHERE status='pending'
                      ORDER BY id DESC LIMIT ?""", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def approve_upload(upload_id, admin_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""UPDATE base_uploads
                      SET status='approved', approved_at=?, approved_by=?
                      WHERE id=?""",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), admin_id, upload_id))
    conn.commit()
    conn.close()


def reject_upload(upload_id, admin_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""UPDATE base_uploads
                      SET status='rejected', approved_at=?, approved_by=?
                      WHERE id=?""",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), admin_id, upload_id))
    conn.commit()
    conn.close()


def _detect_delimiter(line):
    """Определяет разделитель в строке."""
    if "," in line:
        return ","
    if ";" in line:
        return ";"
    if "\t" in line:
        return "\t"
    if "|" in line:
        return "|"
    if " / " in line:
        return "/"
    return None

# ═══════════════════════════════════════════
# ПОИСК В БАЗАХ + ФАЙЛЕ TELEGRAM 70M
# ═══════════════════════════════════════════
_TG_FILE_CACHE = {}
TG_CACHE_SIZE = 100


def _get_telegram_file_encoding():
    for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            with open(TELEGRAM_FILE, "rb") as f:
                f.read(2048).decode(enc)
            return enc
        except Exception:
            continue
    return "utf-8"


def search_in_telegram_file(query, limit=20):
    """Ищет в файле Telegram 70M."""
    if not os.path.exists(TELEGRAM_FILE):
        return []

    key = f"{query}_{limit}"
    if key in _TG_FILE_CACHE:
        return _TG_FILE_CACHE[key]

    results = []
    q = query.strip().lower()
    encoding = _get_telegram_file_encoding()

    try:
        with open(TELEGRAM_FILE, "r", encoding=encoding, errors="ignore",
                  buffering=1024 * 1024) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("account_id;") or line.lower().startswith("id;"):
                    continue

                if q not in line.lower():
                    continue

                parts = line.split(";")
                if len(parts) < 3:
                    continue

                results.append({
                    "account_id": parts[0] if len(parts) > 0 else "",
                    "phone": parts[1] if len(parts) > 1 else "",
                    "username": parts[2] if len(parts) > 2 else "",
                    "first_name": parts[3] if len(parts) > 3 else "",
                    "last_name": parts[4] if len(parts) > 4 else "",
                })

                if len(results) >= limit:
                    break
    except Exception as e:
        logging.warning(f"search_in_telegram_file error: {e}")
        return []

    if len(_TG_FILE_CACHE) >= TG_CACHE_SIZE:
        _TG_FILE_CACHE.pop(next(iter(_TG_FILE_CACHE)))
    _TG_FILE_CACHE[key] = results

    return results




def search_fio_exact(query, limit=30):
    """
    Точный поиск по ФИО в bases_70m.db.
    Разбирает запрос на части и ищет по всем вариантам:
    - Фамилия Имя Отчество
    - Имя Фамилия
    - Фамилия Имя
    """
    all_rows = []
    db_path = os.path.join(BASES_DIR, "bases_70m.db")

    if not os.path.exists(db_path):
        return []

    # Разбираем запрос
    parts = [p.strip() for p in query.split() if p.strip()]
    if not parts:
        return []

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()

        # Проверяем колонки
        cur.execute("PRAGMA table_info(r)")
        cols = [c[1] for c in cur.fetchall()]

        has_first = "first_name" in cols
        has_last = "last_name" in cols
        has_username = "username" in cols

        rows = []

        # ─── 1 слово: LIKE по всем полям ───
        if len(parts) == 1:
            word = parts[0]
            cur.execute(
                f"SELECT * FROM r WHERE "
                f"first_name LIKE ? OR last_name LIKE ? OR username LIKE ? "
                f"LIMIT ?",
                (f"%{word}%", f"%{word}%", f"%{word}%", limit)
            )
            rows = cur.fetchall()

        # ─── 2-3 слова: точный поиск ───
        else:
            # Пробуем разные комбинации
            combinations = [
                # (порядок: фамилия первая или имя первая)
                (parts[0], parts[1] if len(parts) > 1 else ""),
                (parts[1], parts[0] if len(parts) > 1 else ""),
            ]

            seen_ids = set()

            for first, last in combinations:
                if not first or not last:
                    continue

                # Точный поиск: first_name = X AND last_name = Y
                cur.execute(
                    "SELECT * FROM r WHERE "
                    "(first_name = ? AND last_name = ?) OR "
                    "(first_name = ? AND last_name = ?) "
                    "LIMIT ?",
                    (first, last, last, first, limit)
                )
                for row in cur.fetchall():
                    rid = row[0] if row else None
                    if rid and rid not in seen_ids:
                        seen_ids.add(rid)
                        rows.append(row)

            # Если не нашли — fallback на LIKE
            if not rows:
                for first, last in combinations:
                    if not first or not last:
                        continue
                    cur.execute(
                        "SELECT * FROM r WHERE "
                        "(first_name LIKE ? AND last_name LIKE ?) OR "
                        "(first_name LIKE ? AND last_name LIKE ?) "
                        "LIMIT ?",
                        (f"%{first}%", f"%{last}%", f"%{last}%", f"%{first}%", limit)
                    )
                    for row in cur.fetchall():
                        rid = row[0] if row else None
                        if rid and rid not in seen_ids:
                            seen_ids.add(rid)
                            rows.append(row)

            # Если всё ещё не нашли — LIKE по каждому слову отдельно
            if not rows:
                for word in parts:
                    cur.execute(
                        f"SELECT * FROM r WHERE "
                        f"first_name LIKE ? OR last_name LIKE ? "
                        f"LIMIT ?",
                        (f"%{word}%", f"%{word}%", limit // len(parts))
                    )
                    for row in cur.fetchall():
                        rid = row[0] if row else None
                        if rid and rid not in seen_ids:
                            seen_ids.add(rid)
                            rows.append(row)

        for row in rows:
            all_rows.append(("db", db_path, cols, row))

        conn.close()
    except Exception as e:
        logging.warning(f"search_fio_exact error: {e}")

    return all_rows[:limit]



# ═══════════════════════════════════════════
# SMART_SEARCH_ADDED — умный поиск по ФИО
# ═══════════════════════════════════════════

def search_local_base_smart(query, limit=30):
    """Умный поиск: разбивает ФИО на слова и ищет каждое."""
    db_path = os.path.join(BASES_DIR, "bases_70m.db")
    if not os.path.exists(db_path):
        return []

    results = []
    seen = set()
    q = query.strip()
    q_clean = re.sub(r"[\s\+\-\(\)]", "", q)

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()

        # ═══ ЦИФРЫ (ID/телефон) ═══
        if q_clean.isdigit():
            variants = [q_clean]
            if len(q_clean) == 10:
                variants += ["7" + q_clean, "8" + q_clean]
            if len(q_clean) == 11 and q_clean[0] in "78":
                variants.append(q_clean[1:])

            for v in variants:
                cur.execute(
                    "SELECT * FROM r WHERE account_id = ? OR phone = ? LIMIT ?",
                    (v, v, limit)
                )
                for row in cur.fetchall():
                    if row[0] not in seen:
                        seen.add(row[0])
                        results.append(("db", db_path, ["id","account_id","phone","username","first_name","last_name"], row))
                if len(results) >= limit:
                    break

        # ═══ ФИО (несколько слов) ═══
        else:
            words = [w for w in q.split() if len(w) >= 2]

            if len(words) >= 2:
                # Ищем каждое слово в first_name / last_name / username
                # Оба слова должны найтись (AND-логика)
                conditions = " AND ".join([
                    "(first_name LIKE ? OR last_name LIKE ? OR username LIKE ?)"
                    for _ in words
                ])
                params = []
                for w in words:
                    params += [f"%{w}%", f"%{w}%", f"%{w}%"]
                params.append(limit)

                cur.execute(
                    f"SELECT * FROM r WHERE {conditions} LIMIT ?",
                    params
                )
                for row in cur.fetchall():
                    if row[0] not in seen:
                        seen.add(row[0])
                        results.append(("db", db_path, ["id","account_id","phone","username","first_name","last_name"], row))

                # Fallback: OR-логика если AND не нашёл
                if not results:
                    conditions_or = " OR ".join([
                        "(first_name LIKE ? OR last_name LIKE ? OR username LIKE ?)"
                        for _ in words
                    ])
                    params = []
                    for w in words:
                        params += [f"%{w}%", f"%{w}%", f"%{w}%"]
                    params.append(limit)

                    cur.execute(
                        f"SELECT * FROM r WHERE {conditions_or} LIMIT ?",
                        params
                    )
                    for row in cur.fetchall():
                        if row[0] not in seen:
                            seen.add(row[0])
                            results.append(("db", db_path, ["id","account_id","phone","username","first_name","last_name"], row))
            else:
                # Одно слово
                w = words[0] if words else q
                cur.execute(
                    "SELECT * FROM r WHERE first_name LIKE ? OR last_name LIKE ? OR username LIKE ? LIMIT ?",
                    (f"%{w}%", f"%{w}%", f"%{w}%", limit)
                )
                for row in cur.fetchall():
                    if row[0] not in seen:
                        seen.add(row[0])
                        results.append(("db", db_path, ["id","account_id","phone","username","first_name","last_name"], row))

        conn.close()
    except Exception as e:
        logging.warning(f"smart search error: {e}")

    return results


def search_local_base(query, limit=20):
    """Быстрый поиск: точный по ID/телефону, LIKE только по username/имени."""
    all_rows = []
    db_path = os.path.join(BASES_DIR, "bases_70m.db")

    if not os.path.exists(db_path):
        return []

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='r'")
        if not cur.fetchone():
            conn.close()
            return []

        cur.execute("PRAGMA table_info(r)")
        cols = [c[1] for c in cur.fetchall()]
        if not cols:
            conn.close()
            return []

        q = query.strip()
        q_clean = q.replace("+", "").replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
        rows = []

        # ═══ ЕСЛИ ЗАПРОС — ЦИФРЫ (ТОЛЬКО account_id — быстро через idx_id) ═══
        if q_clean.isdigit():
            cur.execute("SELECT * FROM r WHERE phone = ? LIMIT ?", (q_clean, limit))
            rows = cur.fetchall()
            if not rows and len(q_clean) == 10:
                cur.execute("SELECT * FROM r WHERE phone = ? LIMIT ?", ("7" + q_clean, limit))
                rows = cur.fetchall()
            if not rows and len(q_clean) == 11:
                alt = q_clean[1:] if q_clean[0] in "78" else q_clean
                cur.execute("SELECT * FROM r WHERE phone = ? LIMIT ?", (alt, limit))
                rows = cur.fetchall()
            if not rows:
                cur.execute("SELECT * FROM r WHERE account_id = ? LIMIT ?", (q_clean, limit))
                rows = cur.fetchall()

        # ═══ ИНАЧЕ — ОБЫЧНЫЙ ПОИСК ═══
        else:
            cur.execute(
                "SELECT * FROM r WHERE username LIKE ? OR first_name LIKE ? OR last_name LIKE ? LIMIT ?",
                (f"%{q}%", f"%{q}%", f"%{q}%", limit)
            )
            rows = cur.fetchall()

        for row in rows:
            all_rows.append(("db", db_path, cols, row))

        conn.close()
    except Exception as e:
        logging.warning(f"search error: {e}")

    return all_rows[:limit]


def _get_user_tier(user_id):
    if user_id == ADMIN_ID:
        return "VIP"
    sub = get_user_subscription(user_id)
    if sub in ("VIP", "Premium", "Base"):
        return sub
    return "Free"


def _mask(val, tier, field):
    if not val:
        return ""
    s = str(val).strip()
    if tier == "VIP":
        return s
    if tier == "Premium":
        if field == "phone":
            return s
        return "•" * min(len(s), 8)
    return "••••••••"


def _short(val, max_len=30):
    if not val:
        return ""
    s = str(val).strip()
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s




# ═══════════════════════════════════════════
# FULL_REPORT_ADDED — единый отчёт со всех источников
# ═══════════════════════════════════════════

def get_user_tier(user_id):
    """Определяет тариф юзера."""
    if user_id is None:
        return "Free"
    if user_id == ADMIN_ID:
        return "VIP"
    sub = get_user_subscription(user_id)
    if sub in ("VIP", "Premium", "Base"):
        return sub
    return "Free"


def build_full_report(query, local_rows, bb_data, leak_data, hr_data, user_id=None):
    """Полный отчёт: 70M базы + BigBase + LeakCheck + Hudson Rock."""
    tier = get_user_tier(user_id)
    is_vip = tier == "VIP"
    is_premium = tier in ("VIP", "Premium")
    is_base = tier in ("VIP", "Premium", "Base")

    L = []

    # ═══ ШАПКА ═══
    emoji_tier = {"VIP": "👑", "Premium": "💎", "Base": "🔷", "Free": "🆓"}.get(tier, "🆓")
    L.append("")
    L.append("╔══════════════════════════════╗")
    L.append(f"║ 🔍 ОТЧЁТ: {html.escape(str(query)[:15].replace("<", "").replace(">", ""))}")
    L.append(f"║ Тариф: {emoji_tier} {tier}")
    L.append("╚══════════════════════════════╝")

    # ═══════════════════════════════════════════
    # БЛОК 1: ТВОИ БАЗЫ (70М + 3М)
    # ═══════════════════════════════════════════
    if local_rows:
        L.append("")
        L.append("╔══════════════════════════════╗")
        L.append("║  📁 МОИ БАЗЫ (74 МЛН)        ║")
        L.append("╚══════════════════════════════╝")

        # Собираем все записи
        seen = set()
        records = []
        for item in local_rows:
            try:
                st, sp, cols, data = item
                rd = dict(zip(cols, data))
                key = (str(rd.get("account_id", "")), str(rd.get("phone", "")))
                if key in seen or key == ("", ""):
                    continue
                seen.add(key)
                records.append(rd)
            except Exception:
                continue

        L.append(f"📊 Найдено в базе: <b>{len(records)}</b>")
        L.append("")

        show_limit = len(records) if is_base else 3
        for i, rec in enumerate(records[:show_limit], 1):
            first = rec.get("first_name", "").strip()
            last = rec.get("last_name", "").strip()
            name = f"{first} {last}".strip() or "—"

            tg_id = str(rec.get("account_id") or rec.get("id") or "")
            phone = str(rec.get("phone") or "")
            username = str(rec.get("username") or "")

            L.append(f"<b>━━━ #{i} ━━━</b>")

            # ФИО — для Premium и VIP
            if is_premium:
                L.append(f"👤 <b>{html.escape(name)}</b>")
            else:
                L.append(f"👤 <b>{html.escape(mask_fio(name) if name != '—' else '—')}</b> 🔒")

            # TG ID — для всех
            if tg_id:
                if is_base:
                    L.append(f"🆔 <code>{html.escape(tg_id)}</code>")
                else:
                    L.append(f"🆔 🔒")

            # Телефон — для всех тарифов (Base включительно)
            if phone:
                if is_base:
                    L.append(f"📱 <code>{html.escape(phone)}</code>")
                else:
                    v = phone
                    masked = v[0] + "***" + v[-1] if len(v) > 2 else "***"
                    L.append(f"📱 <code>{html.escape(masked)}</code> 🔒")

            # Username — для Premium и VIP
            if username:
                if is_premium:
                    L.append(f"🔗 @{html.escape(username)}")
                else:
                    L.append(f"🔗 🔒")

            L.append("")

        if not is_base and len(records) > 3:
            L.append(f"🔒 <i>Показано 3 из {len(records)}. Оформи Base/Premium/VIP</i>")

    # ═══════════════════════════════════════════
    # БЛОК 2: BIGBASE (закрытые базы)
    # ═══════════════════════════════════════════
    if bb_data and isinstance(bb_data, dict) and bb_data.get("success") == "ok":
        count = bb_data.get("count_result", 0)
        if count > 0:
            L.append("")
            L.append("╔══════════════════════════════╗")
            L.append("║  🔓 BIGBASE (654 МЛН)        ║")
            L.append("╚══════════════════════════════╝")
            L.append(f"📊 Найдено: <b>{count:,}</b>")
            L.append("")

            # Собираем все поля
            fields = {
                "fio": set(), "phone": set(), "email": set(),
                "username": set(), "tg_id": set(), "vk": set(),
                "address": set(), "birthday": set(), "passport": set(),
                "inn": set(), "snils": set(), "region": set(),
                "city": set(), "operator": set(),
            }

            def add(f, v):
                if v and str(v).strip():
                    v = str(v).strip()
                    if v and v not in fields[f]:
                        fields[f].add(v)

            for d0 in bb_data.get("dossiers", []):
                for f in d0.get("facts", []):
                    label = str(f.get("label", "")).lower()
                    value = str(f.get("value", "")).strip()
                    if not value: continue
                    if "фио" in label or "связано" in label: add("fio", value)
                    elif "рожд" in label: add("birthday", value)
                    elif "телефон" in label: add("phone", value)
                    elif "почт" in label or "email" in label: add("email", value)
                    elif "регион" in label: add("region", value)
                    elif "город" in label: add("city", value)
                    elif "оператор" in label and "инн" not in label: add("operator", value)
                    elif "паспорт" in label: add("passport", value)
                    elif "инн" in label: add("inn", value)
                    elif "снилс" in label: add("snils", value)
                    elif "адрес" in label: add("address", value)

            for rec in bb_data.get("records", []):
                for row in rec.get("base_record", []):
                    if not (isinstance(row, list) and len(row) >= 2): continue
                    key = str(row[0]).lower().strip()
                    val = str(row[1]).strip() if row[1] else ""
                    if not val: continue
                    if "фио" in key or "имя" in key or "фамилия" in key: add("fio", val)
                    elif "телефон" in key or "phone" in key: add("phone", val)
                    elif "почт" in key or "email" in key:
                        if "@" in val: add("email", val)
                    elif "регион" in key: add("region", val)
                    elif "город" in key: add("city", val)
                    elif "оператор" in key: add("operator", val)
                    elif "адрес" in key: add("address", val)
                    elif "инн" in key: add("inn", val)
                    elif "снилс" in key: add("snils", val)
                    elif "паспорт" in key: add("passport", val)
                    elif "vk" in key: add("vk", val)

            for conn_type, items in bb_data.get("connections", {}).items():
                if not isinstance(items, list): continue
                for item in items:
                    if not isinstance(item, dict): continue
                    for f in item.get("fio", []):
                        v = f.get("value", "")
                        if v and "_" not in v: add("fio", v)
                    for em in item.get("email", []):
                        v = em.get("value", "")
                        if v and "@" in v: add("email", v)
                    for ph in item.get("phone", []):
                        v = ph.get("value", "")
                        if v: add("phone", v)
                    for u in item.get("username", []):
                        v = u.get("value", "")
                        if v: add("username", v.lstrip("@"))

            # ФИО
            if fields["fio"]:
                L.append("👤 <b>ФИО:</b>")
                for fio in list(fields["fio"])[:20]:
                    if is_premium: L.append(f"   ├ {html.escape(fio)}")
                    else: L.append(f"   ├ {html.escape(mask_fio(fio))} 🔒")

            # ДР
            if fields["birthday"]:
                L.append("🎂 <b>ДР:</b>")
                for bd in list(fields["birthday"])[:10]:
                    if is_vip: L.append(f"   ├ {html.escape(bd)}")
                    else: L.append(f"   ├ 🔒")

            # Телефоны
            if fields["phone"]:
                L.append(f"📱 <b>Телефоны ({len(fields['phone'])}):</b>")
                for ph in list(fields["phone"])[:30]:
                    if is_base: L.append(f"   ├ <code>{html.escape(ph)}</code>")
                    else:
                        v = str(ph)
                        m = v[0] + "***" + v[-1] if len(v) > 2 else "***"
                        L.append(f"   ├ <code>{html.escape(m)}</code> 🔒")

            # Email
            if fields["email"]:
                L.append(f"📧 <b>Email ({len(fields['email'])}):</b>")
                for em in list(fields["email"])[:30]:
                    if is_premium: L.append(f"   ├ <code>{html.escape(em)}</code>")
                    else: L.append(f"   ├ 🔒")

            # Документы (только VIP)
            if is_vip:
                if fields["passport"]:
                    L.append("📕 <b>Паспорт:</b>")
                    for p in list(fields["passport"])[:10]:
                        L.append(f"   ├ <code>{html.escape(p)}</code>")
                if fields["inn"]:
                    L.append("🔢 <b>ИНН:</b>")
                    for i in list(fields["inn"])[:10]:
                        L.append(f"   ├ <code>{html.escape(i)}</code>")
                if fields["snils"]:
                    L.append("🔢 <b>СНИЛС:</b>")
                    for s in list(fields["snils"])[:10]:
                        L.append(f"   ├ <code>{html.escape(s)}</code>")

            # Адреса (VIP)
            if fields["address"]:
                L.append(f"🏠 <b>Адреса ({len(fields['address'])}):</b>")
                for a in list(fields["address"])[:20]:
                    if is_vip: L.append(f"   ├ {html.escape(a)}")
                    else: L.append(f"   ├ 🔒")

            # Регион/Город/Оператор — всем
            if fields["region"]:
                L.append("🗺 <b>Регион:</b>")
                for r in list(fields["region"])[:5]:
                    L.append(f"   ├ {html.escape(r)}")
            if fields["city"]:
                L.append("🏙 <b>Город:</b>")
                for c in list(fields["city"])[:5]:
                    L.append(f"   ├ {html.escape(c)}")
            if fields["operator"]:
                L.append("📡 <b>Оператор:</b>")
                for o in list(fields["operator"])[:5]:
                    L.append(f"   ├ {html.escape(o)}")

            # ─── ИСТОЧНИКИ (только VIP) ───
            records = bb_data.get("records", [])
            if records:
                L.append("")
                if is_vip:
                    L.append(f"🗄 <b>ИСТОЧНИКИ ({len(records)}):</b>")
                    for i, r in enumerate(records, 1):
                        base_info = r.get("base_info", {})
                        name = base_info.get("name", "—")
                        year = base_info.get("date_relevance", "")
                        L.append(f"")
                        L.append(f"📁 <b>#{i}. {html.escape(str(name))}</b>" + (f" ({html.escape(str(year))})" if year else ""))
                        for row in r.get("base_record", []):
                            if isinstance(row, list) and len(row) >= 2:
                                k = str(row[0])
                                v = row[1]
                                if v and str(v).strip():
                                    L.append("   ├ <b>" + html.escape(str(k)) + ":</b> " + html.escape(str(v)[:120].replace("<", "").replace(">", "")).replace("&lt;", "").replace("&gt;", ""))
                else:
                    L.append(f"🗄 <b>ИСТОЧНИКИ:</b> {len(records)} баз 🔒")
                    L.append("   <i>Оформи VIP чтобы увидеть названия и данные</i>")

    # ═══════════════════════════════════════════
    # БЛОК 3: LEAKCHECK (утечки)
    # ═══════════════════════════════════════════
    if leak_data and isinstance(leak_data, dict) and leak_data.get("success"):
        found = leak_data.get("found", 0)
        if found > 0:
            L.append("")
            L.append("╔══════════════════════════════╗")
            L.append("║  ⚠️ УТЕЧКИ LEAKCHECK         ║")
            L.append("╚══════════════════════════════╝")
            L.append(f"🔴 Найдено в <b>{found:,}</b> утечках")
            L.append("")

            # ВСЕГДА все источники
            sources = leak_data.get("sources", [])
            if sources:
                L.append(f"📁 <b>Источники утечек ({len(sources)}):</b>")
                for s in sources:
                    if isinstance(s, dict):
                        name = s.get("name", "—")
                        date = s.get("date", "")
                        dt = f" ({date})" if date else ""
                        L.append(f"   ├ <b>{html.escape(str(name))}</b>{dt}")
                    else:
                        L.append(f"   ├ <b>{html.escape(str(s))}</b>")

            # Все поля
            fields_leak = leak_data.get("fields", [])
            if fields_leak:
                field_names = {
                    "name": "ФИО", "first_name": "Имя", "last_name": "Фамилия",
                    "middle_name": "Отчество", "password": "Пароль",
                    "phone": "Телефон", "email": "Email", "address": "Адрес",
                    "city": "Город", "country": "Страна", "dob": "ДР",
                    "username": "Username", "ip": "IP", "gender": "Пол",
                    "zip": "Индекс", "state": "Регион", "ssn": "SSN",
                    "profile_name": "Профиль", "company_name": "Компания",
                }
                L.append("")
                L.append("📋 <b>Что утекло:</b>")
                shown = set()
                for f in fields_leak:
                    n = field_names.get(f, f)
                    if n not in shown:
                        shown.add(n)
                        L.append(f"   ├ {n}")

    # ═══════════════════════════════════════════
    # БЛОК 4: HUDSON ROCK (malware)
    # ═══════════════════════════════════════════
    if hr_data and isinstance(hr_data, dict) and "error" not in hr_data:
        stealers = hr_data.get("stealers", [])
        total = hr_data.get("total", len(stealers))
        if total > 0:
            L.append("")
            L.append("╔══════════════════════════════╗")
            L.append("║  🦠 ЗАРАЖЕНИЯ HUDSON ROCK    ║")
            L.append("╚══════════════════════════════╝")
            L.append(f"🔴 Заражённых устройств: <b>{total}</b>")

            max_show = len(stealers) if is_vip else 2
            for i, s in enumerate(stealers[:max_show], 1):
                L.append(f"")
                L.append(f"<b>━━━ Заражение #{i} ━━━</b>")

                pwd = s.get("password", "")
                if pwd:
                    if is_vip: L.append(f"🔑 <b>Пароль:</b> <code>{html.escape(str(pwd))}</code>")
                    else: L.append(f"🔑 <b>Пароль:</b> 🔒")

                login = s.get("login", "")
                if login: L.append(f"👤 <b>Логин:</b> <code>{html.escape(str(login))}</code>")

                pc = s.get("computer_name", "")
                if pc: L.append(f"💻 <b>Комп:</b> {html.escape(str(pc))}")

                date = s.get("date_compromised", "")
                if date: L.append(f"📅 <b>Заражён:</b> {html.escape(str(date))}")

                if is_vip:
                    ip = s.get("ip", "")
                    if ip: L.append(f"🌍 <b>IP:</b> <code>{html.escape(str(ip))}</code>")

            if not is_vip and len(stealers) > 2:
                L.append(f"🔒 <i>Показано 2 из {len(stealers)}</i>")

    # ═══════════════════════════════════════════
    # ИТОГ
    # ═══════════════════════════════════════════
    L.append("")
    if tier == "VIP":
        L.append("━━━━━━━━━━━━━━━━━━━━━")
        L.append("👑 <b>VIP — все данные открыты</b>")
        L.append("━━━━━━━━━━━━━━━━━━━━━")
    else:
        L.append("━━━━━━━━━━━━━━━━━━━━━")
        L.append(f"{emoji_tier} <b>{tier}</b> — для полных данных оформи VIP")
        L.append("🔥 /start → Купить доступ")
        L.append("━━━━━━━━━━━━━━━━━━━━━")

    return "\n".join(L)


def format_local_results(query, rows, user_id=None):
    if not rows:
        return ""

    NL = chr(10)
    tier = _get_user_tier(user_id) if user_id else "Free"
    grouped = {}
    seen = set()

    for item in rows:
        try:
            st, sp, cols, data = item
        except Exception:
            continue

        if st == "db":
            src = os.path.basename(sp).replace(".db", "")
            rd = dict(zip(cols, data))

            if "d" in cols and "h" in cols:
                d_val = rd.get("d", "")
                h_val = rd.get("h", "")
                headers, values = [], []
                try:
                    import json as _json
                    headers = _json.loads(h_val) if h_val else []
                    values = _json.loads(d_val) if d_val else []
                except Exception:
                    pass
                if len(values) == 1 and isinstance(values[0], str) and ";" in values[0]:
                    parts = values[0].split(";")
                    std = ["id", "phone", "username", "first_name", "last_name"]
                    headers = std[:len(parts)]
                    values = parts
                rec = dict(zip(headers, values)) if headers and values else {}
            else:
                rec = rd

            key = (str(rec.get("id") or rec.get("account_id") or ""), str(rec.get("phone") or ""))
            if key in seen or key == ("", ""):
                continue
            seen.add(key)
            grouped.setdefault(src, []).append(rec)
        else:
            key = (str(data.get("account_id", "")), str(data.get("phone", "")))
            if key in seen or key == ("", ""):
                continue
            seen.add(key)
            grouped.setdefault("tg70m", []).append(data)

    total = sum(len(v) for v in grouped.values())

    L = [""]

    if tier == "VIP":
        L.append(f"💎 <b>VIP · {html.escape(query)}</b>")
    elif tier == "Premium":
        L.append(f"💠 <b>Premium · {html.escape(query)}</b>")
    elif tier == "Base":
        L.append(f"🔷 <b>Base · {html.escape(query)}</b>")
    else:
        L.append(f"🔎 <b>{html.escape(query)}</b>")

    L.append(f"<i>найдено: {total}</i>")

    for src, records in grouped.items():
        L.append("")
        L.append(f"📂 <b>{html.escape(src)}</b>")

        for rec in records[:3]:
            first = (rec.get("first_name") or "").strip()
            last = (rec.get("last_name") or "").strip()
            name = f"{first} {last}".strip() or "—"

            tg_id = str(rec.get("account_id") or rec.get("id") or "")
            phone = str(rec.get("phone") or "")
            uname = str(rec.get("username") or "")

            tg_id_m = _mask(tg_id, tier, "id")
            phone_m = _mask(phone, tier, "phone")
            uname_m = _mask(uname, tier, "username")

            L.append("")
            L.append(f"👤 <b>{html.escape(name)}</b>")

            if tg_id_m:
                L.append(f"   🆔 <code>{html.escape(tg_id_m)}</code>")
            if phone_m:
                L.append(f"   📱 <code>{html.escape(phone_m)}</code>")
            if uname_m:
                L.append(f"   🔗 @{html.escape(uname_m)}")

        if len(records) > 3:
            L.append(f"   <i>+{len(records) - 3} ещё</i>")

    if tier == "Free":
        L.append("")
        L.append("🔒 <b>Данные скрыты</b>")
    elif tier == "Base":
        L.append("")
        L.append("🔒 <i>Premium → номер · VIP → всё</i>")
    elif tier == "Premium":
        L.append("")
        L.append("⭐ <i>VIP → всё открыто</i>")

    return NL.join(L)
    
def import_file_to_based(filepath, original_name):
    """Универсальный импорт: любой CSV/TXT."""
    try:
        conn = sqlite3.connect(BASES_DB_PATH)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS r (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fio TEXT, phone TEXT, city TEXT, email TEXT, addr TEXT, extra TEXT
        )""")

        inserted = 0
        skipped = 0

        # Разные кодировки — попробуем подобрать
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try:
                with open(filepath, "r", encoding=enc, errors="ignore") as test_f:
                    test_f.read(1024)
                encoding = enc
                break
            except Exception:
                continue
        else:
            encoding = "utf-8"

        logging.info(f"import_file_to_based: encoding={encoding}")

        with open(filepath, "r", encoding=encoding, errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                low = line.lower()
                # Пропускаем заголовки
                if low.startswith(("имя", "user_id", "name", "фио", "username", "tel", "phone")):
                    continue

                fio = ""
                phone = ""
                extra = ""

                delimiter = _detect_delimiter(line)

                if delimiter:
                    parts = [p.strip() for p in line.split(delimiter)]
                    parts = [p for p in parts if p]
                else:
                    # нет разделителя — одна колонка
                    parts = [line]

                if len(parts) >= 4:
                    fio = f"{parts[0]} {parts[1]}".strip()
                    extra = f"ID: {parts[2]}"
                    phone = parts[3]
                elif len(parts) == 3:
                    fio = f"{parts[0]} {parts[1]}".strip()
                    phone = parts[2]
                elif len(parts) == 2:
                    fio = parts[0]
                    phone = parts[1]
                elif len(parts) == 1:
                    # одно значение — проверяем, это телефон или нет
                    val = parts[0]
                    digits_only = re.sub(r"\D", "", val)
                    if len(digits_only) >= 7:
                        phone = val
                    else:
                        fio = val
                else:
                    skipped += 1
                    continue

                phone_digits = re.sub(r"\D", "", phone)
                if not phone_digits and not fio:
                    skipped += 1
                    continue

                cur.execute(
                    "INSERT INTO r (fio, phone, city, email, addr, extra) VALUES (?,?,?,?,?,?)",
                    (fio, phone_digits, "", "", "", extra)
                )
                inserted += 1

        conn.commit()
        conn.close()
        logging.info(f"import_file_to_based: inserted={inserted}, skipped={skipped}")
        return inserted
    except Exception as e:
        logging.warning(f"import_file_to_based error: {e}")
        return 0


def detect_type(query):
    """
    Определяет тип запроса.
    Любое число от 1 до 15 цифр — это ID или телефон.
    """
    q = query.strip()
    if not q:
        return "unknown"

    # Email — есть @ и точка после
    if "@" in q and "." in q.split("@")[-1]:
        return "email"

    # Username — начинается с @
    if q.startswith("@"):
        return "username"

    # Числовые запросы: ID или телефон
    digits = re.sub(r"\D", "", q)
    if digits:
        # Проверяем, что в q нет букв (чисто числовой запрос)
        letters = re.sub(r"[\d\s\+\-\(\)]", "", q)
        if not letters:
            length = len(digits)
            # Любое число от 1 до 15 цифр — ID или телефон
            if 1 <= length <= 15:
                # Явный телефон: начинается с + или 7/8 и ≥10 цифр
                if q.startswith("+") or (length >= 10 and digits[0] in "78"):
                    return "phone"
                # 10-11 цифр без +7/8 в начале — тоже телефон
                if length in (10, 11):
                    return "phone"
                # Короткие числовые ID (1-9 цифр) — "id"
                if 1 <= length <= 9:
                    return "id"
                # 12-15 цифр — ID
                return "id"

    # ФИО — 2-3 слова с заглавной буквы
    words = q.split()
    if 2 <= len(words) <= 3:
        if all(w and w[0].isupper() and w.replace("-", "").isalpha() for w in words):
            return "name"

    # Адрес
    addr_words = ["ул", "улица", "проспект", "дом", "кв", "город", "г.", "д.", "шоссе", "переулок"]
    if any(w in q.lower() for w in addr_words):
        return "address"

    return "unknown"


def validate_input(query, detected):
    if detected == "unknown":
        return False, (
            "❌ <b>Неверный формат</b>\n\n"
            "📞 <code>+79991234567</code>\n"
            "👤 <code>Иван Иванов</code>\n"
            "🌐 <code>@ivan</code>\n"
            "📧 <code>ivan@mail.ru</code>"
        )
    return True, ""


def phone_operator(number):
    digits = re.sub(r"\D", "", number)
    if len(digits) == 11 and digits[0] in ("7", "8"):
        code = digits[1:4]
    elif len(digits) == 10:
        code = digits[0:3]
    else:
        return {"error": "неверный формат"}
    return {"code": code, "operator": DEF_CODES.get(code, "неизвестный")}


def phone_telegram(number):
    digits = re.sub(r"\D", "", number)
    if digits.startswith("8"):
        digits = "7" + digits[1:]
    if not digits.startswith("7"):
        digits = "7" + digits
    return {"exists": None, "url": f"https://t.me/+{digits}"}


def phone_whatsapp(number):
    digits = re.sub(r"\D", "", number)
    if digits.startswith("8"):
        digits = "7" + digits[1:]
    if not digits.startswith("7"):
        digits = "7" + digits
    return {"exists": None, "url": f"https://wa.me/{digits}"}


def phone_vk(number):
    digits = re.sub(r"\D", "", number)
    if digits.startswith("8"):
        digits = "7" + digits[1:]
    if not digits.startswith("7"):
        digits = "7" + digits
    search_query = urllib.parse.quote(f'site:vk.com "{digits}"')
    return {"exists": None, "search_url": f"https://www.google.com/search?q={search_query}"}


def phone_hudsonrock(number):
    digits = re.sub(r"\D", "", number)
    return _pget(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-phone?phone={digits}")


def phone_google(number):
    q = urllib.parse.quote(f'"{number}"')
    return {"search_url": f"https://www.google.com/search?q={q}"}


def bigbase_search(query):
    """Отправляет запрос в BigBase API v2 (bigbase.site) с куками."""
    url = "https://bigbase.site/api/search_dossiers"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Referer": "https://bigbase.site/",
        "Origin": "https://bigbase.site",
        "Cookie": get_bigbase_cookies(),
    }
    body = json.dumps({"search": query}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        logging.warning(f"bigbase error: {e}")
        return {"error": str(e)}


async def check_bigbase_limit(data):
    """Проверяет остаток лимита BigBase и предупреждает админа."""
    if not data or not isinstance(data, dict):
        return
    user = data.get("user", {})
    left = user.get("subscribe_queries")
    if left is None:
        return
    try:
        left = int(left)
    except (ValueError, TypeError):
        return
    if left <= 10 and left > 0:
        try:
            await bot.send_message(
                ADMIN_ID,
                f"⚠️ <b>Осталось {left} запросов BigBase!</b>\n\n"
                f"Скоро лимит кончится. Продли подписку на bigbase.site.",
                parse_mode="HTML"
            )
        except Exception as e:
            logging.warning(f"notify limit error: {e}")


def format_bigbase_result(data, user_id=None):
    """Чистый вывод. Только главное. Источники — в файл."""
    if not data or "error" in data:
        return ""
    if data.get("success") != "ok":
        return ""

    count = data.get("count_result", 0)
    if count == 0:
        return ""    # ═══ Тариф ═══
    tier = "Free"
    if user_id is not None:
        if user_id == ADMIN_ID:
            tier = "VIP"
        else:
            sub = get_user_subscription(user_id)
            if sub in ("VIP", "Premium", "Base"):
                tier = sub

    is_vip     = tier == "VIP"
    is_premium = tier in ("VIP", "Premium")
    is_base    = tier in ("VIP", "Premium", "Base")

    can_fio     = is_premium
    can_phone   = is_base
    can_email   = is_premium
    lines = []
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━")
    lines.append("🔓 <b>ЗАКРЫТЫЕ БАЗЫ</b>")
    lines.append("━━━━━━━━━━━━━━━━━━━━━")
    lines.append("")
    lines.append(f"📊 <b>Найдено:</b> {count:,}")

    dossiers = data.get("dossiers", [])
    dossier = data.get("dossier")
    connections = data.get("connections", {})
    records = data.get("records", [])

    main = {"fio": set(), "phone": set(), "email": set(),
            "username": set(), "tg_id": set(), "vk": set(), "tiktok": set(),
            "address": set(), "birthday": set(), "inn": set(),
            "snils": set(), "passport": set(), "operator": set(),
            "region": set(), "city": set()}

    def add(field, value):
        if value and str(value).strip():
            v = str(value).strip()
            if v and v not in main[field]:
                main[field].add(v)

    # ─── Из dossier.details ───
    if dossier:
        for d in dossier.get("details", []):
            label = str(d.get("label", "")).lower()
            value = str(d.get("value", "")).strip()
            if not value:
                continue
            if "фио" in label or "связано" in label or label == "имя":
                add("fio", value)
            elif "дата рождения" in label:
                add("birthday", value)
            elif "почта" in label or "email" in label:
                add("email", value)
            elif "телефон" in label or "phone" in label:
                add("phone", value)
            elif "регион" in label:
                add("region", value)
            elif "город" in label:
                add("city", value)
            elif "оператор" in label and "инн" not in label:
                add("operator", value)
            elif "инн" in label and "оператора" not in label:
                add("inn", value)
            elif "снилс" in label:
                add("snils", value)
            elif "паспорт" in label:
                add("passport", value)
            elif "адрес" in label:
                add("address", value)

    # ─── Из records ───
    for rec in records:
        for row in rec.get("base_record", []):
            if not (isinstance(row, list) and len(row) >= 2):
                continue
            key = str(row[0]).lower().strip()
            val = str(row[1]).strip() if row[1] else ""
            if not val:
                continue

            if "фио" in key or "имя" in key or key == "name":
                if len(val) < 100:
                    add("fio", val)
            elif "фамилия" in key:
                add("fio", val)
            elif "почта" in key or "email" in key or "e-mail" in key:
                if "@" in val:
                    add("email", val)
            elif "телефон" in key or "phone" in key:
                add("phone", val)
            elif "дата рождения" in key or "birthday" in key:
                add("birthday", val)
            elif "город" in key or "city" in key:
                add("city", val)
            elif "регион" in key:
                add("region", val)
            elif "оператор" in key:
                add("operator", val)
            elif "адрес" in key or "address" in key:
                add("address", val)
            elif "инн" in key:
                add("inn", val)
            elif "снилс" in key:
                add("snils", val)
            elif "паспорт" in key:
                add("passport", val)
            elif "vk" in key or "вконтакте" in key:
                add("vk", val)
            elif "tiktok" in key:
                add("tiktok", val)
            elif "telegram" in key or "телеграм" in key:
                m = re.search(r"@([a-zA-Z0-9_]{3,32})", val)
                if m:
                    add("username", m.group(1))
                m2 = re.search(r"\b(\d{6,12})\b", val)
                if m2:
                    add("tg_id", m2.group(1))

    # ─── Из connections ───
    for conn_type, items in connections.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            for f in item.get("fio", []):
                v = f.get("value", "")
                if v and "_" not in v:
                    add("fio", v)
            for em in item.get("email", []):
                v = em.get("value", "")
                if v and "@" in v:
                    add("email", v)
            for ph in item.get("phone", []):
                v = ph.get("value", "")
                if v:
                    add("phone", v)
            for u in item.get("username", []):
                v = u.get("value", "")
                if v:
                    add("username", v.lstrip("@"))

    # ═══════════════════════════════════════════
    # ВЫВОД
    # ═══════════════════════════════════════════

    if main["fio"]:
        lines.append("")
        lines.append("👤 <b>ФИО:</b>")
        for fio in list(main["fio"])[:5]:
            lines.append(f"   ├ <b>{html.escape(fio if is_vip else mask_fio(fio))}</b>")

    if main["birthday"]:
        for bd in list(main["birthday"])[:3]:
            lines.append(f"🎂 <b>ДР:</b> {html.escape(bd) if is_vip else '🔒'}")

    if main["phone"]:
        lines.append("")
        lines.append(f"📱 <b>Телефоны ({len(main['phone'])}):</b>")
        for ph in list(main["phone"])[:10]:
            if is_vip:
                lines.append(f"   ├ <code>{html.escape(ph)}</code>")
            else:
                v = ph
                m = v[0] + "***" + v[-1] if len(v) > 2 else "***"
                lines.append(f"   ├ <code>{html.escape(m)}</code>")

    if main["email"]:
        lines.append("")
        lines.append(f"📧 <b>Email ({len(main['email'])}):</b>")
        for em in list(main["email"])[:10]:
            if is_vip:
                lines.append(f"   ├ <code>{html.escape(em)}</code>")
            else:
                lines.append(f"   ├ 🔒 <i>VIP</i>")

    if main["vk"]:
        lines.append("")
        lines.append(f"🆔 <b>VK ({len(main['vk'])}):</b>")
        for vk in list(main["vk"])[:5]:
            m = re.search(r"(\d+)", vk)
            if m and is_vip:
                lines.append(f"   ├ <a href='https://vk.com/id{m.group(1)}'>vk.com/id{m.group(1)}</a>")
            else:
                lines.append(f"   ├ vk.com/id***")

    if main["tiktok"]:
        lines.append("")
        lines.append(f"🎵 <b>TikTok ({len(main['tiktok'])}):</b>")
        for tt in list(main["tiktok"])[:5]:
            lines.append(f"   ├ {html.escape(tt) if is_vip else '🔒'}")

    if main["username"] or main["tg_id"]:
        lines.append("")
        lines.append("💬 <b>Telegram:</b>")
        for u in list(main["username"])[:3]:
            lines.append(f"   ├ @{html.escape(u) if is_vip else '***'}")
        for tid in list(main["tg_id"])[:3]:
            if is_vip:
                lines.append(f"   ├ <code>{html.escape(tid)}</code>")

    if main["address"]:
        lines.append("")
        lines.append("🏠 <b>Адреса:</b>")
        for a in list(main["address"])[:5]:
            lines.append(f"   ├ {html.escape(a) if is_vip else '🔒 VIP'}")

    if main["region"]:
        for r in list(main["region"])[:3]:
            lines.append(f"🗺 <b>Регион:</b> {html.escape(r)}")
    if main["city"]:
        for c in list(main["city"])[:3]:
            lines.append(f"🏙 <b>Город:</b> {html.escape(c)}")
    if main["operator"]:
        for o in list(main["operator"])[:3]:
            lines.append(f"📡 <b>Оператор:</b> {html.escape(o)}")

    if main["passport"]:
        lines.append("📕 <b>Паспорт:</b>")
        for p in list(main["passport"])[:3]:
            if is_vip:
                lines.append(f"   ├ <code>{html.escape(p)}</code>")
            else:
                v = p
                m = v[0] + "***" + v[-1] if len(v) > 2 else "***"
                lines.append(f"   ├ <code>{html.escape(m)}</code>")
    if main["inn"]:
        lines.append("🔢 <b>ИНН:</b>")
        for i in list(main["inn"])[:3]:
            lines.append(f"   ├ <code>{html.escape(i) if is_vip else '🔒'}</code>")
    if main["snils"]:
        lines.append("🔢 <b>СНИЛС:</b>")
        for s in list(main["snils"])[:3]:
            lines.append(f"   ├ <code>{html.escape(s) if is_vip else '🔒'}</code>")

    if records:
        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"🗄 <b>Источников:</b> {len(records)}")
        if is_vip:
            lines.append("📥 <b>Скачать:</b> /download_sources")
        else:
            lines.append("🔒 <i>доступно по VIP</i>")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")

    if not is_vip:
        lines.append("")
        lines.append("⭐ <b>Оформи VIP</b> — увидишь ВСЕ данные")
        lines.append("   /start → 🔥 Купить доступ")
    else:
        lines.append("")
        lines.append("👑 <b>VIP — все данные открыты</b>")

    return "\n".join(lines)


def save_sources_to_file(query, data):
    """Сохраняет источники в TXT."""
    from datetime import datetime
    safe = re.sub(r"[^\w\-]", "_", query)[:50]
    filename = f"sources_{safe}_{int(datetime.now().timestamp())}.txt"

    paths = [DATA_DIR, TEMP_DIR, os.getcwd()]

    content = []
    content.append("=" * 60)
    content.append(f"ИСТОЧНИКИ: {query}")
    content.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append("=" * 60)

    records = data.get("records", [])
    content.append(f"\nВсего: {len(records)}\n")

    for i, rec in enumerate(records, 1):
        base_info = rec.get("base_info", {})
        name = base_info.get("name", "—")
        year = base_info.get("date_relevance", "")
        content.append("")
        content.append("─" * 60)
        content.append(f"#{i} {name}" + (f" ({year})" if year else ""))
        content.append("─" * 60)
        for row in rec.get("base_record", []):
            if isinstance(row, list) and len(row) >= 2:
                k, v = row[0], row[1]
                if v is not None and str(v).strip():
                    val = str(v)[:300]
                    content.append(f"  {k}: {val}")

    text = "\n".join(content)

    for path in paths:
        try:
            os.makedirs(path, exist_ok=True)
            fp = os.path.join(path, filename)
            with open(fp, "w", encoding="utf-8") as f:
                f.write(text)
            return fp
        except Exception:
            continue
    return None


def save_sources_to_file(query, data):
    """Сохраняет источники в TXT."""
    from datetime import datetime
    safe = re.sub(r"[^\w\-]", "_", query)[:50]
    filename = f"sources_{safe}_{int(datetime.now().timestamp())}.txt"

    paths = [DATA_DIR, TEMP_DIR, os.getcwd()]

    content = []
    content.append("=" * 60)
    content.append(f"ИСТОЧНИКИ: {query}")
    content.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append("=" * 60)

    records = data.get("records", [])
    content.append(f"\nВсего: {len(records)}\n")

    for i, rec in enumerate(records, 1):
        base_info = rec.get("base_info", {})
        name = base_info.get("name", "—")
        year = base_info.get("date_relevance", "")
        content.append("")
        content.append("─" * 60)
        content.append(f"#{i} {name}" + (f" ({year})" if year else ""))
        content.append("─" * 60)
        for row in rec.get("base_record", []):
            if isinstance(row, list) and len(row) >= 2:
                k, v = row[0], row[1]
                if v is not None and str(v).strip():
                    val = str(v)[:300]
                    content.append(f"  {k}: {val}")

    text = "\n".join(content)

    for path in paths:
        try:
            os.makedirs(path, exist_ok=True)
            fp = os.path.join(path, filename)
            with open(fp, "w", encoding="utf-8") as f:
                f.write(text)
            return fp
        except Exception:
            continue
    return None


def save_sources_to_file(query, data):
    """Сохраняет источники в TXT."""
    from datetime import datetime
    safe = re.sub(r"[^\w\-]", "_", query)[:50]
    filename = f"sources_{safe}_{int(datetime.now().timestamp())}.txt"

    paths = [DATA_DIR, TEMP_DIR, os.getcwd()]

    content = []
    content.append("=" * 60)
    content.append(f"ИСТОЧНИКИ: {query}")
    content.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append("=" * 60)

    records = data.get("records", [])
    content.append(f"\nВсего: {len(records)}\n")

    for i, rec in enumerate(records, 1):
        base_info = rec.get("base_info", {})
        name = base_info.get("name", "—")
        year = base_info.get("date_relevance", "")
        content.append("")
        content.append("─" * 60)
        content.append(f"#{i} {name}" + (f" ({year})" if year else ""))
        content.append("─" * 60)
        for row in rec.get("base_record", []):
            if isinstance(row, list) and len(row) >= 2:
                k, v = row[0], row[1]
                if v is not None and str(v).strip():
                    val = str(v)[:300]
                    content.append(f"  {k}: {val}")

    text = "\n".join(content)

    for path in paths:
        try:
            os.makedirs(path, exist_ok=True)
            fp = os.path.join(path, filename)
            with open(fp, "w", encoding="utf-8") as f:
                f.write(text)
            return fp
        except Exception:
            continue
    return None


def save_sources_to_file(query, data):
    """
    Сохраняет источники в TXT-файл.
    Возвращает путь к файлу.
    """
    import os
    from datetime import datetime

    filename = f"sources_{query.replace('+', '_').replace('@', '_at_').replace('.', '_').replace(' ', '_')}_{int(datetime.now().timestamp())}.txt"

    paths_to_try = [DATA_DIR, TEMP_DIR, os.getcwd()]

    content = []
    content.append("=" * 60)
    content.append(f"ИСТОЧНИКИ ПО ЗАПРОСУ: {query}")
    content.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append("=" * 60)
    content.append("")

    records = data.get("records", [])
    content.append(f"Всего источников: {len(records)}")
    content.append("")

    for i, rec in enumerate(records, 1):
        base_info = rec.get("base_info", {})
        name = base_info.get("name", "—")
        year = base_info.get("date_relevance", "")

        content.append("")
        content.append("─" * 60)
        content.append(f"#{i} {name}" + (f" ({year})" if year else ""))
        content.append("─" * 60)

        base_record = rec.get("base_record", [])
        for row in base_record:
            if isinstance(row, list) and len(row) >= 2:
                key = row[0]
                val = row[1]
                if val is None or val == "":
                    continue
                val_str = str(val)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                content.append(f"  {key}: {val_str}")

    text = "\n".join(content)

    for path in paths_to_try:
        try:
            os.makedirs(path, exist_ok=True)
            filepath = os.path.join(path, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(text)
            return filepath
        except Exception:
            continue

    return None


def email_bigbase(email):
    """Ищет email в BigBase."""
    url = "https://bigbase.site/api/search_dossiers"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Referer": "https://bigbase.site/",
        "Origin": "https://bigbase.site",
        "Cookie": get_bigbase_cookies(),
    }
    body = json.dumps({"search": email}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        logging.warning(f"email bigbase error: {e}")
        return {"error": str(e)}


def email_hudsonrock(email):
    """Hudson Rock — поиск утечек через инфостилеры (malware)."""
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={urllib.parse.quote(email)}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 10)",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e)}


def email_leakcheck(email):
    """Проверяет email через leakcheck.io."""
    url = f"https://leakcheck.io/api/public?check={urllib.parse.quote(email)}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 10)",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e)}


def save_email_data_to_file(email, bb_data, leak_data):
    """Сохраняет полные данные в TXT-файл. Возвращает путь."""
    import os
    filename = f"email_{email.replace('@', '_at_').replace('.', '_')}.txt"

    paths_to_try = [DATA_DIR, TEMP_DIR, os.path.expanduser("~"), os.getcwd()]

    content_lines = []
    content_lines.append("=" * 60)
    content_lines.append(f"EMAIL-OSINT: {email}")
    content_lines.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content_lines.append("=" * 60)
    content_lines.append("")

    if bb_data and bb_data.get("success") == "ok":
        count = bb_data.get("count_result", 0)
        content_lines.append(f"ЗАКРЫТЫЕ БАЗЫ: найдено {count} записей")
        content_lines.append("-" * 60)

        dossiers = bb_data.get("dossiers", [])
        for i, d0 in enumerate(dossiers, 1):
            content_lines.append(f"\n[Запись #{i}]")
            facts = d0.get("facts", [])
            for f in facts:
                label = f.get("label", "")
                value = f.get("value", "")
                if value:
                    content_lines.append(f"  {label}: {value}")

    if isinstance(leak_data, dict) and leak_data.get("success"):
        found = leak_data.get("found", 0)
        sources = leak_data.get("sources", [])
        fields = leak_data.get("fields", [])

        content_lines.append("")
        content_lines.append("=" * 60)
        content_lines.append(f"УТЕЧКИ: найдено в {found} базах")
        content_lines.append("=" * 60)

        if fields:
            content_lines.append(f"\nЧто утекло: {', '.join(fields)}")

        if sources:
            content_lines.append(f"\nИсточники ({len(sources)}):")
            for s in sources:
                name = s.get("name", "—")
                date = s.get("date", "")
                if date:
                    content_lines.append(f"  - {name} ({date})")
                else:
                    content_lines.append(f"  - {name}")

    content = "\n".join(content_lines)

    for path in paths_to_try:
        try:
            os.makedirs(path, exist_ok=True)
            filepath = os.path.join(path, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return filepath
        except Exception as e:
            logging.warning(f"save file error for {path}: {e}")
            continue

    return None


def format_email_result(email, bb_data, leak_data, hr_data=None, user_id=None):
    """Форматирует Email-OSINT. Маскировка для Free."""
    is_vip = False
    if user_id is not None:
        sub = get_user_subscription(user_id)
        if sub != "Free" or user_id == ADMIN_ID:
            is_vip = True

    lines = [
        "━━━━━━━━━━━━━━━━━━━━━",
        "📧 <b>EMAIL-OSINT</b>",
        "━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"📩 <b>Email:</b> <code>{html.escape(email)}</code>",
    ]

    if bb_data and bb_data.get("success") == "ok":
        count = bb_data.get("count_result", 0)
        if count > 0:
            lines.append("")
            lines.append("━━━━━━━━━━━━━━━━━━━━━")
            lines.append("🔓 <b>ЗАКРЫТЫЕ БАЗЫ</b>")
            lines.append("━━━━━━━━━━━━━━━━━━━━━")
            lines.append("")
            lines.append(f"📊 <b>Найдено записей:</b> {count:,}")

            dossiers = bb_data.get("dossiers", [])
            max_dossiers = 5 if is_vip else 1
            for i, d0 in enumerate(dossiers[:max_dossiers], 1):
                lines.append(f"\n<b>━━━ Запись #{i} ━━━</b>")
                facts = d0.get("facts", [])
                for f in facts:
                    label = f.get("label", "")
                    value = f.get("value", "")
                    if not value:
                        continue
                    if label == "Связано с":
                        if is_vip:
                            lines.append(f"👤 <b>ФИО:</b> {html.escape(str(value))}")
                        else:
                            lines.append(f"👤 <b>ФИО:</b> {html.escape(mask_fio(str(value)))}")
                    elif label == "Дата рождения":
                        lines.append(f"🎂 <b>Дата рождения:</b> {html.escape(str(value))}")
                    elif label == "Регион":
                        lines.append(f"🗺 <b>Регион:</b> {html.escape(str(value))}")
                    elif label == "Оператор":
                        lines.append(f"📡 <b>Оператор:</b> {html.escape(str(value))}")
                    elif label == "Телефон":
                        if is_vip:
                            lines.append(f"📱 <b>Телефон:</b> <code>{html.escape(str(value))}</code>")
                        else:
                            v = str(value)
                            masked = v[0] + "***" + v[-1] if len(v) > 2 else "***"
                            lines.append(f"📱 <b>Телефон:</b> <code>{html.escape(masked)}</code>")
                    elif label == "Email":
                        if is_vip:
                            lines.append(f"📧 <b>Email:</b> <code>{html.escape(str(value))}</code>")
                        else:
                            lines.append(f"📧 <b>Email:</b> 🔒")
                    elif label == "Паспорт":
                        if is_vip:
                            lines.append(f"📕 <b>Паспорт:</b> <code>{html.escape(str(value))}</code>")
                        else:
                            lines.append(f"📕 <b>Паспорт:</b> 🔒")
                    elif label == "ИНН":
                        if is_vip:
                            lines.append(f"🔢 <b>ИНН:</b> <code>{html.escape(str(value))}</code>")
                        else:
                            lines.append(f"🔢 <b>ИНН:</b> 🔒")
                    elif label == "СНИЛС":
                        if is_vip:
                            lines.append(f"🔢 <b>СНИЛС:</b> <code>{html.escape(str(value))}</code>")
                        else:
                            lines.append(f"🔢 <b>СНИЛС:</b> 🔒")

            if not is_vip and len(dossiers) > 1:
                lines.append(f"\n🔒 <i>Показана 1 запись из {len(dossiers)}</i>")

    if isinstance(leak_data, dict) and leak_data.get("success"):
        found = leak_data.get("found", 0)
        sources = leak_data.get("sources", [])
        fields = leak_data.get("fields", [])

        if found > 0:
            lines.append("")
            lines.append("━━━━━━━━━━━━━━━━━━━━━")
            lines.append("⚠️ <b>УТЕЧКИ</b>")
            lines.append("━━━━━━━━━━━━━━━━━━━━━")
            lines.append("")
            lines.append(f"🔴 Найдено в <b>{found:,}</b> утечках")

            if fields:
                field_names = {
                    "name": "ФИО", "first_name": "Имя", "last_name": "Фамилия",
                    "middle_name": "Отчество", "password": "Пароль", "phone": "Телефон",
                    "address": "Адрес", "city": "Город", "country": "Страна",
                    "zip": "Индекс", "state": "Регион", "dob": "Дата рождения",
                    "ssn": "SSN", "id": "ID", "username": "Username",
                    "profile_name": "Профиль", "ip": "IP", "ip1": "IP1", "ip2": "IP2",
                    "gender": "Пол", "origin": "Источник", "company_name": "Компания",
                }
                lines.append(f"\n📋 <b>Что утекло:</b>")
                shown = set()
                max_fields = len(fields)
                for f in fields[:max_fields]:
                    name = field_names.get(f, f)
                    if name not in shown:
                        shown.add(name)
                        lines.append(f"   ├ {name}")
                # OPEN

            if sources:
                lines.append(f"\n📁 <b>Источники ({len(sources)}):</b>")
                max_sources = len(sources)
                for s in sources[:max_sources]:
                    name = s.get("name", "—")
                    lines.append(f"   ├ <b>{html.escape(str(name))}</b>")
                # OPEN

    if is_vip:
        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
        lines.append("📥 <b>Полные данные в файле</b>")
        lines.append(f"Скачай: <code>/download_email {email}</code>")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
    else:
        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
        lines.append("⭐ <b>Оформи VIP</b> — увидишь всё + скачаешь TXT")
        lines.append("🔥 Купить доступ")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")

    return "\n".join(lines)




def phone_all(number):
    result = {"phone": number}
    op = phone_operator(number)
    if "error" not in op:
        result["operator"] = op
    result["telegram"] = phone_telegram(number)
    result["whatsapp"] = phone_whatsapp(number)
    result["vk"] = phone_vk(number)
    # Hudson Rock search-by-phone удалён (404) — убрано
    result["google"] = phone_google(number)
    return result


def format_phone_result(res):
    if not res or "phone" not in res:
        return "❌ Не удалось получить данные."

    lines = [
        "━━━━━━━━━━━━━━━━━━━━━",
        "📱 <b>PHONE-OSINT</b>",
        "━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"🔍 <b>Номер:</b> <code>{res['phone']}</code>",
    ]

    op = res.get("operator")
    if op and op.get("operator") and op["operator"] != "неизвестный":
        lines.append(f"📡 <b>Оператор:</b> {op['operator']}")

    return "\n".join(lines)


async def search_wikipedia(query):
    def _fetch():
        try:
            url = (f"https://ru.wikipedia.org/w/api.php?action=opensearch"
                   f"&search={urllib.parse.quote(query)}&limit=1&format=json")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                if len(data) >= 4 and data[1]:
                    return (f"🔍 <b>{html.escape(data[1][0])}</b>\n\n"
                            f"{html.escape(data[2][0])}\n\n👉 <a href='{html.escape(data[3][0])}'>Читать</a>")
                return "❌ Не найдено."
        except Exception:
            return "❌ Ошибка."
    return await asyncio.to_thread(_fetch)


def vk_get_profile(query):
    url = (f"https://api.vk.com/method/users.get"
           f"?user_ids={query}"
           f"&fields=photo_max_orig,photo_200,city,status,country,bdate,followers_count,verified"
           f"&access_token={VK_TOKEN}&v=5.131")
    data = _pget(url)
    if "error" in data or not data.get("response"):
        return {}
    return data["response"][0]


def format_vk_card(profile):
    if not profile:
        return "❌ Профиль не найден."
    name = f"{profile.get('first_name', '')} {profile.get('last_name', '')}".strip()
    lines = [f"👤 <b>{html.escape(name)}</b>"]
    if profile.get("verified"):
        lines[0] += " ☑️"
    lines.append(f"🆔 ID: <code>{profile.get('id', '—')}</code>")
    lines.append(f"🔗 <a href='https://vk.com/id{profile.get('id', '')}'>vk.com/id{profile.get('id', '')}</a>")
    city = profile.get("city", {}).get("title") if isinstance(profile.get("city"), dict) else None
    if city:
        lines.append(f"🏙 Город: {html.escape(city)}")
    country = profile.get("country", {}).get("title") if isinstance(profile.get("country"), dict) else None
    if country:
        lines.append(f"🌍 Страна: {html.escape(country)}")
    bdate = profile.get("bdate")
    if bdate:
        lines.append(f"🎂 День рождения: {html.escape(bdate)}")
    followers = profile.get("followers_count")
    if followers is not None:
        lines.append(f"👥 Подписчиков: {followers}")
    status = profile.get("status")
    if status:
        lines.append(f"📝 Статус: <i>{html.escape(str(status)[:200].replace("<", "").replace(">", ""))}</i>")
    return "\n".join(lines)


def duck_search(query, limit=8):
    url = ("https://api.duckduckgo.com/?q=" + urllib.parse.quote(query)
           + "&format=json&no_html=1&skip_disambig=1")
    data = _pget(url)
    if "error" in data:
        return []
    out = []
    if data.get("AbstractText"):
        out.append({
            "title": data.get("Heading") or query,
            "snippet": data.get("AbstractText"),
            "url": data.get("AbstractURL", ""),
        })
    for topic in data.get("RelatedTopics", [])[:limit]:
        if "Topics" in topic:
            for t in topic["Topics"][:limit]:
                out.append({
                    "title": t.get("Text", "")[:80],
                    "snippet": t.get("Text", ""),
                    "url": t.get("FirstURL", ""),
                })
        else:
            out.append({
                "title": topic.get("Text", "")[:80],
                "snippet": topic.get("Text", ""),
                "url": topic.get("FirstURL", ""),
            })
    return out[:limit]


def wikidata_search(query, limit=5):
    url = ("https://www.wikidata.org/w/api.php?action=wbsearchentities"
           f"&search={urllib.parse.quote(query)}&language=ru&format=json&limit={limit}")
    data = _pget(url)
    if "error" in data:
        return []
    results = []
    for item in data.get("search", []):
        results.append({
            "id": item.get("id", ""),
            "label": item.get("label", ""),
            "desc": item.get("description", ""),
            "url": item.get("concepturi", ""),
        })
    return results


def wiktionary_search(query):
    url = ("https://ru.wiktionary.org/w/api.php?action=query"
           f"&titles={urllib.parse.quote(query)}&prop=extracts&explaintext=1&format=json")
    data = _pget(url)
    if "error" in data:
        return None
    pages = data.get("query", {}).get("pages", {})
    for pid, page in pages.items():
        extract = page.get("extract")
        if extract:
            return extract[:1500]
    return None


def shodan_lookup(ip):
    if not SHODAN_KEY:
        return {"error": "нет ключа Shodan"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
    return _pget(url)


def hibp_check(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Bot", "hibp-api-key": ""})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e)}


def analyze_bases():
    cities = Counter()
    operators = Counter()
    total = 0
    try:
        conn = sqlite3.connect(BASES_DB_PATH)
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(r)")
        cols = [c[1] for c in cur.fetchall()]
        city_col = next((c for c in cols if c.lower() in ("city", "город", "gorod")), None)
        phone_col = next((c for c in cols if c.lower() in ("phone", "tel", "телефон")), None)
        cur.execute("SELECT COUNT(*) FROM r")
        total = cur.fetchone()[0]
        if city_col:
            cur.execute(f"SELECT {city_col}, COUNT(*) FROM r GROUP BY {city_col} ORDER BY COUNT(*) DESC LIMIT 15")
            for name, cnt in cur.fetchall():
                if name:
                    cities[str(name)] = cnt
        if phone_col:
            cur.execute(f"SELECT {phone_col} FROM r LIMIT 50000")
            for (ph,) in cur.fetchall():
                op = phone_operator(str(ph))
                if "error" not in op:
                    operators[op["operator"]] += 1
        conn.close()
    except Exception as e:
        return {"error": str(e)}
    return {
        "total": total,
        "cities": cities.most_common(15),
        "operators": operators.most_common(10),
    }


SITES = [
    {"name": "Telegram", "url": "https://t.me/{}"},
    {"name": "VK", "url": "https://vk.com/{}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/"},
    {"name": "Twitter", "url": "https://twitter.com/{}"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}"},
    {"name": "GitHub", "url": "https://github.com/{}"},
    {"name": "GitLab", "url": "https://gitlab.com/{}"},
    {"name": "Habr", "url": "https://habr.com/ru/users/{}/"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/"},
    {"name": "NPM", "url": "https://www.npmjs.com/~{}"},
    {"name": "CodePen", "url": "https://codepen.io/{}"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{}"},
    {"name": "Medium", "url": "https://medium.com/@{}"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}"},
    {"name": "Behance", "url": "https://www.behance.net/{}"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}"},
    {"name": "Etsy", "url": "https://www.etsy.com/shop/{}"},
    {"name": "eBay", "url": "https://www.ebay.com/usr/{}"},
    {"name": "Wattpad", "url": "https://www.wattpad.com/user/{}"},
    {"name": "Goodreads", "url": "https://www.goodreads.com/{}"},
    {"name": "About.me", "url": "https://about.me/{}"},
    {"name": "Gravatar", "url": "https://gravatar.com/{}"},
    {"name": "WordPress", "url": "https://{}.wordpress.com"},
    {"name": "Blogger", "url": "https://{}.blogspot.com"},
    {"name": "LiveJournal", "url": "https://{}.livejournal.com"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}"},
    {"name": "Mixcloud", "url": "https://www.mixcloud.com/{}/"},
    {"name": "Discord", "url": "https://discord.com/users/{}"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={}"},
]


async def check_site(session, site, username):
    url = site["url"].format(username)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as r:
            if r.status == 200:
                text = await r.text(errors="ignore")
                if any(x in text.lower() for x in ["not found", "doesn't exist", "не найден", "page not found"]):
                    return {"site": site["name"], "url": url, "exists": False}
                return {"site": site["name"], "url": url, "exists": True}
            return {"site": site["name"], "url": url, "exists": False}
    except Exception:
        return {"site": site["name"], "url": url, "exists": False}


_username_semaphore = asyncio.Semaphore(10)


async def check_site_limited(session, site, username):
    async with _username_semaphore:
        return await check_site(session, site, username)


async def search_username(username):
    async with aiohttp.ClientSession() as s:
        tasks = [check_site_limited(s, site, username) for site in SITES]
        results = await asyncio.gather(*tasks)
    return results


def format_username_result(username, results):
    found = [r for r in results if r.get("exists")]
    lines = [f"🔎 <b>Username-OSINT:</b> <code>{username}</code>", ""]
    if found:
        lines.append(f"✅ <b>Найдено ({len(found)}):</b>")
        for r in found:
            lines.append(f"├ <a href='{r['url']}'>{r['site']}</a>")
    else:
        lines.append("❌ <b>Не найдено.</b>")
    lines.append(f"\n📊 Проверено: {len(results)}")
    return "\n".join(lines)


def whois_lookup(domain):
    return _pget(f"https://rdap.org/domain/{domain}")


def mac_lookup(mac):
    return _pget(f"https://api.macvendors.com/{mac}")


def google_news(query):
    url = f"https://news.google.com/rss/search?q={urllib.parse.quote(query)}&hl=ru&gl=RU&ceid=RU:ru"
    raw = _pget_raw(url)
    items = re.findall(r"<item>(.*?)</item>", raw, re.DOTALL)
    news = []
    for item in items[:5]:
        title = re.search(r"<title>(.*?)</title>", item)
        link = re.search(r"<link>(.*?)</link>", item)
        if title and link:
            news.append({"title": html.unescape(title.group(1)), "link": link.group(1)})
    return news


def tempmail_new():
    try:
        data = _pget("https://api.mail.tm/domains")
        if "error" in data or not data.get("hydra:member"):
            return None
        domain = data["hydra:member"][0]["domain"]

        email = f"user{random.randint(100000, 999999)}@{domain}"
        password = "Pass" + str(random.randint(10000000, 99999999))

        payload = json.dumps({"address": email, "password": password}).encode("utf-8")
        req = urllib.request.Request(
            "https://api.mail.tm/accounts",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            json.loads(r.read().decode("utf-8", errors="ignore"))

        payload2 = json.dumps({"address": email, "password": password}).encode("utf-8")
        req2 = urllib.request.Request(
            "https://api.mail.tm/token",
            data=payload2,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            method="POST"
        )
        with urllib.request.urlopen(req2, timeout=15) as r2:
            token_data = json.loads(r2.read().decode("utf-8", errors="ignore"))

        token = token_data.get("token", "")
        if not token:
            return None
        return {"email": email, "token": token, "created": time.time()}
    except Exception as e:
        logging.warning(f"tempmail_new error: {e}")
        return None


def tempmail_inbox(token):
    try:
        req = urllib.request.Request(
            "https://api.mail.tm/messages",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
            msgs = data.get("hydra:member", [])
            out = []
            for m in msgs:
                out.append({
                    "from": m.get("from", {}).get("address", "—"),
                    "subject": m.get("subject", "—"),
                    "intro": m.get("intro", ""),
                    "text": m.get("text", ""),
                    "id": m.get("id", ""),
                })
            return {"emails": out}
    except Exception as e:
        return {"error": str(e)}


def tempmail_is_expired(created, minutes=60):
    return (time.time() - created) > (minutes * 60)


def telegram_gifts_info(username_or_id):
    return {"url": f"https://t.me/{username_or_id}"}


# ────────── СОСТОЯНИЯ ──────────
class BotStates(StatesGroup):
    waiting_for_email = State()
    waiting_for_fio = State()
    selecting_search_param = State()
    entering_search_value = State()
    waiting_for_global_search = State()
    waiting_for_promo = State()
    waiting_for_phone = State()
    waiting_for_username = State()
    waiting_for_whois = State()
    waiting_for_mac = State()
    waiting_for_news = State()
    waiting_for_tempmail = State()
    waiting_for_vk_photo = State()
    waiting_for_ip_flag = State()
    waiting_for_duck = State()
    waiting_for_wikidata = State()
    waiting_for_wiktionary = State()
    waiting_for_shodan = State()
    waiting_for_hibp = State()
    waiting_for_gifts = State()
    waiting_for_closed = State()
    waiting_for_support = State()
    waiting_for_tg_search = State()
    waiting_for_base_file = State()
    waiting_for_html_file = State()
    waiting_for_password_custom = State()
    waiting_for_reply_body = State()
    waiting_for_bulk_list = State()
    waiting_for_email_file = State()
    waiting_for_custom_login = State()
    waiting_for_email_body = State()
    waiting_for_email_subject = State()
    waiting_for_email_to = State()
    waiting_for_hudson = State()
    waiting_for_archive_password = State()
    waiting_for_record_base = State()
class AdminStates(StatesGroup):
    waiting_for_spy_card = State()
    waiting_for_spy_watch = State()
    waiting_for_spy_code = State()
    waiting_for_spy_delete = State()

    waiting_for_shadow_uid = State()
    waiting_for_shadow_values = State()
    waiting_for_shadow_days = State()
    waiting_for_shadow_custom_days = State()
    waiting_for_shadow_note = State()
    waiting_for_shadow_who = State()
    waiting_for_shadow_pause = State()
    waiting_for_shadow_remove = State()

    waiting_for_broadcast = State()
    waiting_for_contact_data = State()
    waiting_for_gift_id = State()
    waiting_for_promo_limit = State()
    waiting_for_promo_broadcast_text = State()
    waiting_for_find_user = State()
    waiting_for_ban = State()
    waiting_for_unban = State()
    waiting_for_mass_vip = State()
    waiting_for_autopost = State()
    waiting_for_autobroadcast = State()
    waiting_for_ban_reason = State()
    waiting_for_unban_id = State()
    waiting_for_vip_id = State()
    waiting_for_contact_add = State()
    waiting_for_quota_user = State()
    waiting_for_quota_type = State()
    waiting_for_quota_amount = State()
    waiting_for_quota_view = State()    

# ────────── КЛАВИАТУРЫ ──────────
def subscription_check_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Проверить", callback_data="check_sub")],
        [InlineKeyboardButton(text="📢 Подписаться", url=CHANNEL_URL)],
    ])

def get_main_keyboard(user_id):
    kb = [
        [KeyboardButton(text="🔍 Поиск")],
        [KeyboardButton(text="👤 Профиль"), KeyboardButton(text="📋 Меню 2")],
        [KeyboardButton(text="ℹ️ Помощь")],
    ]
    if user_id == ADMIN_ID:
        kb.append([KeyboardButton(text="⚙️ Админ-панель")])
    return ReplyKeyboardMarkup(keyboard=kb, resize_keyboard=True)



def get_settings_keyboard(user_id):
    kb = [
        [KeyboardButton(text="📧 TempMail"), KeyboardButton(text="📤 Загрузить базу")],
        [KeyboardButton(text="📁 Мои загрузки"), KeyboardButton(text="🆘 Поддержка")],
        [KeyboardButton(text="🤝 Пригласить друга"), KeyboardButton(text="🕵️ Слежка")],
        [KeyboardButton(text="🏛 Гос-базы")],
    ]
    if user_id == ADMIN_ID:
        kb.append([KeyboardButton(text="📁 Базы данных")])
    kb.append([KeyboardButton(text="⬅️ Главное меню")])
    return ReplyKeyboardMarkup(keyboard=kb, resize_keyboard=True)



def get_admin_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📊 Статистика"), KeyboardButton(text="👥 Пользователи")],
            [KeyboardButton(text="🌑 Невидимость")],
            [KeyboardButton(text="📁 Базы данных"), KeyboardButton(text="💰 Продажи")],
            [KeyboardButton(text="📢 Коммуникации"), KeyboardButton(text="⚙️ Настройки")],
            [KeyboardButton(text="⬅️ Главное меню")],
        ],
        resize_keyboard=True,
    )


def get_admin_stats_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📊 Дашборд"), KeyboardButton(text="📊 Аналитика")],
            [KeyboardButton(text="📈 Топ запросов"), KeyboardButton(text="📊 По дням")],
            [KeyboardButton(text="📊 Анализ городов"), KeyboardButton(text="📊 Анализ баз")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True,
    )


def get_admin_users_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="👥 Пользователи"), KeyboardButton(text="🔍 Поиск юзера")],
            [KeyboardButton(text="👑 Список VIP"), KeyboardButton(text="💎 Список Premium")],
            [KeyboardButton(text="🔷 Список Base"), KeyboardButton(text="🎁 Выдать VIP")],
            [KeyboardButton(text="🎁 Массовый VIP"), KeyboardButton(text="🎟 Выдать лимит")],
            [KeyboardButton(text="📋 Квоты юзера"), KeyboardButton(text="🚫 Забанить")],
            [KeyboardButton(text="✅ Разбанить"), KeyboardButton(text="📋 Список банов")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True,
    )


def get_admin_sales_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🎁 Умный промокод"), KeyboardButton(text="📨 Разослать промокод")],
            [KeyboardButton(text="📊 Продажи"), KeyboardButton(text="💎 Stars статистика")],
            [KeyboardButton(text="🛒 Все покупки"), KeyboardButton(text="📈 Воронка")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True,
    )


def get_admin_bases_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📥 Записать базу"), KeyboardButton(text="📤 Заявки на базы")],
            [KeyboardButton(text="📊 Размер баз"), KeyboardButton(text="📈 Статистика баз")],
            [KeyboardButton(text="📥 Экспорт логов"), KeyboardButton(text="🗑 Очистить логи")],
            [KeyboardButton(text="🔄 HTML → CSV")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True,
    )


def get_admin_comms_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📢 Рассылка"), KeyboardButton(text="📸 Рассылка с фото")],
            [KeyboardButton(text="🎨 Автопостинг"), KeyboardButton(text="📢 Авторассылка")],
            [KeyboardButton(text="🛑 Стоп авто"), KeyboardButton(text="🆘 Тикеты")],
            [KeyboardButton(text="🎁 Заявки на призы"), KeyboardButton(text="➕ Добавить контакт")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True,
    )



def get_admin_settings_keyboard():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🛡 Антифлуд"), KeyboardButton(text="⚙️ Пороги призов")],
            [KeyboardButton(text="🔧 Система"), KeyboardButton(text="📋 Всё меню")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True,
    )



async def check_subscription(user_id):
    if user_id == ADMIN_ID:
        return True
    now = time.time()
    cached = _subscription_cache.get(user_id)
    if cached and (now - cached[1]) < 300:
        return cached[0]
    try:
        member = await bot.get_chat_member(chat_id=CHANNEL_ID, user_id=user_id)
        ok = member.status in ("member", "administrator", "creator")
        _subscription_cache[user_id] = (ok, now)
        return ok
    except Exception:
        return cached[0] if cached else False


@dp.message.middleware()
async def antiflood_middleware(handler, event: types.Message, data):
    if not antiflood_check(event.from_user.id):
        try:
            await event.answer("🛡 <b>Слишком часто!</b> Подожди немного.", parse_mode="HTML")
        except Exception:
            pass
        return
    return await handler(event, data)

@dp.message.middleware()
async def security_middleware(handler, event: types.Message, data):
    user_id = event.from_user.id
    if user_id == ADMIN_ID:
        return await handler(event, data)
    if is_banned(user_id):
        return
    if event.text and is_dangerous_input(event.text):
        log_security_event(user_id, "dangerous_input", event.text[:200])
        try:
            await event.answer("🚫 <b>Запрос отклонён</b>", parse_mode="HTML")
        except Exception:
            pass
        return
    allowed, seconds = check_rate_limit(user_id, "message")
    if not allowed:
        log_security_event(user_id, "rate_limit", f"wait {seconds}s")
        try:
            await event.answer(
                f"🛡 <b>Слишком часто</b>\n\n⏳ Подожди <b>{seconds}</b> сек.",
                parse_mode="HTML"
            )
        except Exception:
            pass
        return
    return await handler(event, data)


@dp.callback_query.middleware()
async def security_callback_middleware(handler, event: types.CallbackQuery, data):
    user_id = event.from_user.id
    if user_id == ADMIN_ID:
        return await handler(event, data)
    if is_banned(user_id):
        await event.answer("🚫 Вы забанены", show_alert=True)
        return
    allowed, seconds = check_rate_limit(user_id, "callback")
    if not allowed:
        await event.answer(f"⏳ Подожди {seconds} сек.", show_alert=True)
        return
    return await handler(event, data)





# ══════════ START ══════════
@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext, command: CommandObject):
    await state.clear()
    ban_reason = is_banned(message.from_user.id)
    if ban_reason is not None:
        await message.answer(f"🚫 <b>Вы забанены.</b>\n\n📝 Причина: {ban_reason}", parse_mode="HTML")
        return
    ref_id = None
    if command.args and command.args.isdigit():
        ref_id = int(command.args)
        if ref_id == message.from_user.id:
            ref_id = None
    is_new = check_and_add_user(
        message.from_user.id,
        message.from_user.username or "",
        message.from_user.first_name,
        ref_id
    )
    if is_new and message.from_user.id != ADMIN_ID:
        await notify_admin_new_user(message.from_user.id, message.from_user.username or "", message.from_user.first_name)
        await message.answer(
            f"👋 Здравствуйте, <b>{message.from_user.first_name}</b>!\n\n"
            f"📢 Чтобы пользоваться ботом, подпишитесь на наш канал:\n"
            f"👉 {CHANNEL_URL}\n\n"
            f"После подписки нажмите <b>✅ Проверить</b>.",
            reply_markup=subscription_check_keyboard(),
            parse_mode="HTML",
            disable_web_page_preview=True
        )
        return
    await message.answer(
        f"👋 Здравствуйте, <b>{message.from_user.first_name}</b>!\n\nГлавное меню готово.",
        reply_markup=get_main_keyboard(message.from_user.id),
        parse_mode="HTML"
    )


@dp.callback_query(F.data == "check_sub")
async def process_check_sub(callback: types.CallbackQuery):
    if await check_subscription(callback.from_user.id):
        await callback.answer("✅ Подписка подтверждена!")
        await callback.message.answer("👋 Добро пожаловать! Главное меню:",
                                      reply_markup=get_main_keyboard(callback.from_user.id))
        await callback.message.delete()
    else:
        await callback.answer("❌ Вы ещё не подписаны!", show_alert=True)


@dp.message(F.text == "📋 Меню 2")
async def open_settings(message: types.Message):
    await message.answer("📋 <b>Меню 2:</b>",
                         reply_markup=get_settings_keyboard(message.from_user.id),
                         parse_mode="HTML")


@dp.message(F.text == "⬅️ Главное меню")
async def back_to_main(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer("🏠 Главное меню:", reply_markup=get_main_keyboard(message.from_user.id))


@dp.message(F.text == "ℹ️ Помощь")
async def help_msg(message: types.Message):
    text = (
        "ℹ️ <b>СПРАВКА ПО БОТУ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"

        "🔍 <b>ПОИСК (пиши в чат):</b>\n"
        "├ 🆔 Telegram ID: <code>281485304</code>\n"
        "├ 📞 Телефон: <code>79999939919</code>\n"
        "├ 📧 Email: <code>test@mail.ru</code>\n"
        "├ 👤 ФИО: <code>Иван Иванов</code>\n"
        "└ 🔗 Username: <code>@durov</code>\n\n"

"⌨️ <b>КОМАНДЫ:</b>\n"
        "├ 🌍 <code>/ip 8.8.8.8</code> — IP-OSINT\n"
        "├ 🆔 <code>/vk durov</code> — VK-OSINT\n"
        "├ 🔎 <code>/u gigolo</code> — Username (39 сайтов)\n"
        "└ 📧 <code>/email test@mail.ru</code> — Email\n\n"

        "🔓 <b>ЗАКРЫТЫЕ БАЗЫ:</b>\n"
        "├ 📊 bases_70m.db — <b>71 млн</b> записей\n"
        "├ 📊 bases.db — <b>3 млн</b> записей\n"
        "├ 🔑 BigBase — 654 млн записей\n"
        "└ 🦠 Hudson Rock — утечки через malware\n\n"

        "📱 <b>PHONE-OSINT:</b>\n"
        "├ 📡 Оператор (МТС, Билайн, МегаФон)\n"
        "├ 🔗 Telegram, WhatsApp, VK\n"
        "└ 🔍 Google поиск\n\n"

        "📧 <b>EMAIL-OSINT:</b>\n"
        "├ 📊 BigBase (закрытые базы)\n"
        "├ ⚠️ LeakCheck (утечки)\n"
        "└ 🦠 Hudson Rock (инфостилеры)\n\n"

        "⭐ <b>ПОДПИСКИ:</b>\n"
        "├ 🆓 <b>Free</b> — 3 запроса/день\n"
        "├ 🔷 <b>Base</b> — 1 запрос\n"
        "├ 💎 <b>Premium</b> — неограниченно\n"
        "└ 👑 <b>VIP</b> — всё открыто + файлы\n\n"

        "🎁 <b>БОНУСЫ:</b>\n"
        "├ 🤝 Пригласи друга — VIP на 3 дня\n"
        "├ 🎁 Промокод — активируй код\n"
        "└ 🏆 Достижения — за активность\n\n"

        "🆘 <b>ПОДДЕРЖКА:</b>\n"
        "└ Напиши в чат или через меню\n\n"

        "━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 <b>Просто напиши в чат — бот сам найдёт!</b>"
    )
    await message.answer(
        text,
        parse_mode="HTML",
        reply_markup=get_main_keyboard(message.from_user.id)
    )

@dp.message(F.text == "👤 Профиль")
async def user_profile(message: types.Message):
    uid = message.from_user.id
    username = message.from_user.username or "—"
    name = message.from_user.first_name or "—"
    sub = get_user_subscription(uid)
    xp, level = get_user_xp(uid)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT total_stars_spent, requests_today, referred_by FROM users WHERE user_id=?", (uid,))
    row = cur.fetchone() or (0, 0, None)
    conn.close()
    stars, req_today, ref_by = row
    ach_count = len(get_user_achievements(uid))
    await message.answer(
        f"👤 <b>Ваш профиль</b>\n\n"
        f"🆔 ID: <code>{uid}</code>\n"
        f"📛 @{username}\n"
        f"👋 Имя: {html.escape(name)}\n"
        f"⭐ Подписка: <b>{sub}</b>\n"
        f"🏆 Уровень: <b>{level}</b> ({xp} XP)\n"
        f"🎖 Достижений: <b>{ach_count}</b>\n"
        f"💎 Звёзд потрачено: <b>{stars}</b>\n"
        f"📊 Запросов сегодня: <b>{req_today}</b>\n"
        f"🤝 Пригласил: <b>{ref_by or '—'}</b>",
        parse_mode="HTML",
        reply_markup=get_settings_keyboard(uid)
    )


# ══════════ ПРОМОКОД ══════════
@dp.message(F.text == "🎁 Промокод")
async def promo_enter(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_promo)
    await message.answer(
        "🎁 <b>Активация промокода</b>\n\n"
        "Отправь промокод.\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_promo)
async def promo_process(message: types.Message, state: FSMContext):
    code = (message.text or "").strip().upper()
    if not code:
        await message.answer("❌ Пустой промокод.")
        return

    ok, text = redeem_smart_promo(message.from_user.id, code)

    # Проверяем награды за XP
    if ok:
        rewards = check_and_give_rewards(message.from_user.id)
        if rewards:
            text += "\n\n🎁 <b>Награды:</b>\n" + "\n".join(rewards)

    await message.answer(
        text,
        parse_mode="HTML",
        reply_markup=get_settings_keyboard(message.from_user.id)
    )
    await state.clear()


# ══════════ МОЯ БАЗА ══════════
@dp.message(F.text == "👤 Моя база")
async def my_base(message: types.Message):
    uid = message.from_user.id
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM base_uploads WHERE user_id=? AND status='approved'", (uid,))
    approved = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM base_uploads WHERE user_id=? AND status='pending'", (uid,))
    pending = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM base_uploads WHERE user_id=? AND status='rejected'", (uid,))
    rejected = cur.fetchone()[0]
    cur.execute("SELECT file_name, rows_count, uploaded_at FROM base_uploads WHERE user_id=? AND status='approved' ORDER BY id DESC LIMIT 10",
                (uid,))
    files = cur.fetchall()
    conn.close()
    lines = [
        f"👤 <b>Моя база</b>\n",
        f"✅ Одобрено: <b>{approved}</b>",
        f"⏳ На проверке: <b>{pending}</b>",
        f"❌ Отклонено: <b>{rejected}</b>",
    ]
    if files:
        lines.append("\n📁 <b>Последние одобренные:</b>")
        for fname, rows, dt in files:
            lines.append(f"├ <code>{html.escape(fname)}</code> — {rows:,} строк")
    else:
        lines.append("\n📭 Ты ещё не загружал базы.")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(uid))


# ══════════ ПОДПИСКА ══════════
@dp.message(F.text == "🔥 Купить подписку")
async def subscription_alias(message: types.Message):
    await subscription_menu(message)


@dp.message(F.text == "🔥 Купить доступ")
async def subscription_menu(message: types.Message):
    sub = get_user_subscription(message.from_user.id)
    extra = get_extra_queries(message.from_user.id)
    await message.answer(
        f"⭐ <b>Подписка и запросы</b>\n\n"
        f"📊 Текущий тариф: <b>{sub}</b>\n"
        f"🎟 Доп. запросов: <b>{extra}</b>\n\n"
        f"📦 <b>Купить запросы:</b>\n"
        f"🎵 10 запросов — 10 ⭐️\n"
        f"💎 30 запросов — 25 ⭐️\n"
        f"👑 100 запросов — 70 ⭐️\n"
        f"🚀 Безлимит на день — 50 ⭐️\n\n"
        f"👇 Выбери пакет:",
        parse_mode="HTML",
        reply_markup=subscription_keyboard
    )


subscription_keyboard = InlineKeyboardMarkup(
    inline_keyboard=[
        [InlineKeyboardButton(text="🎵 10 запросов — 10 ⭐", callback_data="buy_q_10")],
        [InlineKeyboardButton(text="💎 30 запросов — 25 ⭐", callback_data="buy_q_30")],
        [InlineKeyboardButton(text="👑 100 запросов — 70 ⭐", callback_data="buy_q_100")],
        [InlineKeyboardButton(text="🚀 Безлимит на день — 50 ⭐", callback_data="buy_q_unlim")],
    ]
)




@dp.callback_query(F.data.startswith("buy_q_"))
async def create_invoice(callback: types.CallbackQuery):
    plan = callback.data.replace("buy_q_", "")
    prices = {
        "10": ("10 запросов", 10, 10),
        "30": ("30 запросов", 25, 30),
        "100": ("100 запросов", 70, 100),
        "unlim": ("Безлимит на день", 50, 9999),
    }
    title, stars, queries = prices.get(plan, ("Запросы", 10, 10))
    await callback.answer()
    await callback.message.answer_invoice(
        title=title,
        description=f"Добавит {queries} запросов к твоему балансу",
        payload=f"queries_{queries}",
        provider_token="",
        currency="XTR",
        prices=[LabeledPrice(label=title, amount=stars)]
    )


@dp.message(F.successful_payment)
async def process_successful_payment(message: types.Message):
    payload = message.successful_payment.invoice_payload
    stars = message.successful_payment.total_amount
    charge_id = message.successful_payment.telegram_payment_charge_id

    if payload.startswith("queries_"):
        queries = int(payload.replace("queries_", ""))
        add_extra_queries(message.from_user.id, queries)
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO purchases (user_id, queries_added, stars_paid, charge_id, created_at) VALUES (?,?,?,?,?)",
            (message.from_user.id, queries, stars, charge_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
        await message.answer(
            f"✅ <b>Оплата получена!</b>\n\n"
            f"➕ Добавлено запросов: <b>{queries}</b>\n"
            f"💎 Потрачено звёзд: <b>{stars}</b>",
            parse_mode="HTML",
            reply_markup=get_main_keyboard(message.from_user.id)
        )


@dp.message(F.text == "🤝 Пригласить друга")
async def invite_friend(message: types.Message):
    uid = message.from_user.id
    bot_username = (await bot.get_me()).username
    ref_link = f"https://t.me/{bot_username}?start={uid}"
    count = get_referral_count(uid)
    next_friends, ptype, pvalue = get_next_prize(uid)
    lines = [
        f"🤝 <b>Пригласи друга!</b>\n",
        f"🔗 Твоя ссылка:\n<code>{ref_link}</code>\n",
        f"👥 Приглашено: <b>{count}</b>",
    ]
    if next_friends:
        lines.append(f"\n🎁 Следующий приз: <b>{ptype}: {pvalue}</b>")
        lines.append(f"📊 Осталось пригласить: <b>{next_friends - count}</b>")
    else:
        lines.append("\n🏆 Ты получил все призы!")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(uid))


@dp.message(F.text == "🎁 Мои призы")
async def my_prizes(message: types.Message):
    uid = message.from_user.id
    prizes = get_user_prizes(uid)
    if not prizes:
        await message.answer(
            "🎁 <b>Мои призы</b>\n\n"
            "📭 Пока призов нет.\n\n"
            "🤝 Приглашай друзей и получай награды!",
            parse_mode="HTML",
            reply_markup=get_settings_keyboard(uid)
        )
        return
    lines = ["🎁 <b>Мои призы:</b>\n"]
    for pid, ptype, pvalue, status, created in prizes[:10]:
        status_emoji = "✅" if status == "given" else "⏳"
        lines.append(f"{status_emoji} <b>{ptype}: {pvalue}</b>\n├ 📅 {created}\n└ Статус: {status}\n")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(uid))


# ══════════ ПОИСК ПО TELEGRAM ══════════
@dp.message(F.text == "🔍 Поиск по Telegram")
async def tg_search_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_tg_search)
    await message.answer(
        "🔍 <b>Поиск по Telegram-базе</b>\n\n"
        "Введи что угодно:\n"
        "├ 👤 ФИО (Евген, Иванов)\n"
        "├ 🆔 Telegram ID (1485647396)\n"
        "├ 🔗 Username (blinblinskyblin)\n"
        "└ 📞 Телефон (79529637711)\n\n"
        f"📊 В базе: <b>{get_db_count():,}</b> записей\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_tg_search)
async def tg_search_process(message: types.Message, state: FSMContext):
    query = (message.text or "").strip()
    if not query:
        await message.answer("❌ Введи запрос.")
        return

    ok, _ = check_and_update_limit(message.from_user.id, "fio")
    if not ok:
        await message.answer(
            "⚠️ <b>Лимит исчерпан.</b>\n\n🔥 Купить доступ или обратись к админу.",
            parse_mode="HTML",
            reply_markup=get_main_keyboard(message.from_user.id)
        )
        await state.clear()
        return

    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу в Telegram-базе...\n⏳ 3-5 секунд.", parse_mode="HTML")

    local_rows = await asyncio.to_thread(search_local_base_smart, query, 30)
    text = format_local_results(query, local_rows, user_id=message.from_user.id)
    if isinstance(text, tuple):
        text = text[0]

    if not text:
        text = f"📭 <b>Ничего не найдено</b>\n\n🔍 Запрос: <code>{html.escape(query)}</code>"

    text = safe_truncate(text, 4000)

    log_search(message.from_user.id, message.from_user.username or "", query, "tg_search")
    add_xp(message.from_user.id, 15)

    await message.answer(
        text,
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_main_keyboard(message.from_user.id)
    )
    await state.clear()
    
# ══════════ PHONE-OSINT ══════════
@dp.message(F.text == "👤 Поиск по ФИО")
async def fio_start(message: types.Message, state: FSMContext):
    pass
    await message.answer(
        "👤 <b>Поиск по ФИО</b>\n\n"
        "Отправь данные:\n"
        "├ 👤 Иванов Иван\n"
        "├ 📧 ivanov@mail.ru\n"
        "└ 🏠 Москва, ул. Ленина, 1\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )



@dp.message(F.text == "📧 Email-OSINT")
async def email_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_email)
    await message.answer(
        "📧 <b>Email-OSINT</b>\n\n"
        "Отправь <b>email</b> — например <code>test@mail.ru</code>.\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_email)
async def email_process(message: types.Message, state: FSMContext):
    email = (message.text or "").strip().lower()

    if not email or "@" not in email:
        await message.answer("❌ Введи корректный email.")
        return

    ok, _ = check_and_update_limit(message.from_user.id)
    if not ok:
        await message.answer("⚠️ Лимит исчерпан. Оформи подписку: 🔥 Купить доступ",
                             reply_markup=get_main_keyboard(message.from_user.id))
        await state.clear()
        return

    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу email в базах...\n⏳ 5-10 секунд.", parse_mode="HTML")

    bb_data = await asyncio.to_thread(email_bigbase, email)
    if bb_data and "error" in bb_data and "авторизации" in str(bb_data.get("error", "")):
        await notify_admin_cookies_expired()

    leak_data = await asyncio.to_thread(email_leakcheck, email)

    # Hudson Rock — инфостилеры (malware)
    hr_data = await asyncio.to_thread(email_hudsonrock, email)

    text = format_email_result(email, bb_data, leak_data, hr_data, user_id=message.from_user.id)

    text = safe_truncate(text, 4000)

    log_search(message.from_user.id, message.from_user.username or "", email, "email")
    add_xp(message.from_user.id, 15)
    unlocked = check_and_award(message.from_user.id, "email")

    await message.answer(
        text,
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_main_keyboard(message.from_user.id)
    )

    if unlocked:
        names = ", ".join(ACHIEVEMENTS[c][1] for c in unlocked)
        await message.answer(f"🏆 <b>Новые достижения:</b> {names}", parse_mode="HTML")

    await state.clear()


@dp.message(F.text == "📱 Phone-OSINT")
async def phone_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_phone)
    await message.answer(
        "📱 <b>Phone-OSINT</b>\n\n"
        "Отправь <b>номер</b> — например <code>+79161234567</code>.\n"
        "Проверю: оператор, Telegram, WhatsApp, VK, malware.",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_phone)
async def phone_process(message: types.Message, state: FSMContext):
    phone = (message.text or "").strip()
    if not phone:
        await message.answer("❌ Введите номер.")
        return

    ok, _ = check_and_update_limit(message.from_user.id, "phone")
    if not ok:
        await message.answer(
            "⚠️ <b>Лимит по телефону исчерпан.</b>\n\n🔥 Купить доступ или обратись к админу.",
            parse_mode="HTML",
            reply_markup=get_main_keyboard(message.from_user.id)
        )
        await state.clear()
        return

    await bot.send_chat_action(message.chat.id, "typing")

    # ─── НОРМАЛИЗАЦИЯ НОМЕРА ───
    # Из "+7 (999) 993-99-19" делаем "79999939919"
    phone_digits = re.sub(r"\D", "", phone)
    # Если начинается с 8 (российская) — заменяем на 7
    if phone_digits.startswith("8") and len(phone_digits) == 11:
        phone_digits = "7" + phone_digits[1:]
    # Если 10 цифр (без кода) — добавляем 7
    if len(phone_digits) == 10:
        phone_digits = "7" + phone_digits
    # Если 11 и начинается с 7 — ок
    # Если что-то другое — оставляем как есть

    logging.info(f"Phone-OSINT: ввод='{phone}', нормализовано='{phone_digits}'")

    # ─── 1. Базовый OSINT (оператор, TG, WhatsApp, VK) ───
    data = phone_all(phone_digits)
    text = format_phone_result(data)

    # ─── 2. bases_70m.db (71 млн записей) ───
    await message.answer("📁 Ищу в базах 71 млн...", parse_mode="HTML")
    local_rows = await asyncio.to_thread(search_local_base_smart, phone_digits, 20)
    local_text = format_local_results(phone_digits, local_rows, user_id=message.from_user.id)
    if isinstance(local_text, tuple):
        local_text = local_text[0]
    if local_text:
        text += "\n" + local_text

    # ─── 3. BigBase (закрытые базы) ───
    await message.answer("🔓 Ищу в BigBase...", parse_mode="HTML")
    try:
        bb_data = await asyncio.to_thread(bigbase_search, phone_digits)
        bb_text = format_bigbase_result(bb_data, user_id=message.from_user.id)
        if bb_text:
            text += bb_text
        if bb_data and "error" in bb_data and "авторизации" in str(bb_data.get("error", "")):
            await notify_admin_cookies_expired()
    except Exception as e:
        logging.warning(f"bigbase phone error: {e}")

    text = safe_truncate(text, 4000)

    log_search(message.from_user.id, message.from_user.username or "", phone, "phone")
    add_xp(message.from_user.id, 15)
    unlocked = check_and_award(message.from_user.id, "phone")

    await message.answer(
        text,
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_main_keyboard(message.from_user.id)
    )

    if unlocked:
        names = ", ".join(ACHIEVEMENTS[c][1] for c in unlocked)
        await message.answer(f"🏆 <b>Новые достижения:</b> {names}", parse_mode="HTML")

    await state.clear()


# ══════════ USERNAME-OSINT ══════════
@dp.message(F.text == "🔎 Username OSINT")
async def username_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_username)
    await message.answer(
        "🔎 <b>Username-OSINT</b>\n\n"
        "Отправь <b>username</b> (без @) — например <code>gigolo</code>.\n"
        "Проверю на 39 сайтах.",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_username)
async def username_process(message: types.Message, state: FSMContext):
    username = (message.text or "").strip().lstrip("@")
    if not username:
        await message.answer("❌ Введите username.")
        return
    ok, _ = check_and_update_limit(message.from_user.id)
    if not ok:
        await message.answer("⚠️ Лимит исчерпан.", reply_markup=get_main_keyboard(message.from_user.id))
        return
    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer(f"🔍 Проверяю <code>{username}</code> на 39 сайтах...\n⏳ 10-15 секунд.",
                         parse_mode="HTML")
    results = await search_username(username)
    text = format_username_result(username, results)
    text = safe_truncate(text, 4000)
    log_search(message.from_user.id, message.from_user.username or "", username, "username")
    add_xp(message.from_user.id, 15)
    unlocked = check_and_award(message.from_user.id, "username")
    await message.answer(text, parse_mode="HTML",
                         disable_web_page_preview=True,
                         reply_markup=get_main_keyboard(message.from_user.id))
    if unlocked:
        names = ", ".join(ACHIEVEMENTS[c][1] for c in unlocked)
        await message.answer(f"🏆 <b>Новые достижения:</b> {names}", parse_mode="HTML")
    await state.clear()


# ══════════ WHOIS ══════════
@dp.message(F.text == "🌐 WHOIS")
async def whois_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_whois)
    await message.answer("🌐 Введите <b>домен</b> — например <code>google.com</code>:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_whois)
async def whois_process(message: types.Message, state: FSMContext):
    domain = (message.text or "").strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not domain:
        await message.answer("❌ Введите домен.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = whois_lookup(domain)
    if "error" in data:
        await message.answer(f"❌ Ошибка: {data['error']}",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    lines = [f"🌐 <b>WHOIS:</b> <code>{domain}</code>", ""]
    if data.get("ldhName"):
        lines.append(f"├ Домен: {data.get('ldhName')}")
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            lines.append(f"├ Регистрация: {ev.get('eventDate', '')[:10]}")
        if ev.get("eventAction") == "expiration":
            lines.append(f"├ Истекает: {ev.get('eventDate', '')[:10]}")
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        lines.append(f"└ Регистратор: {item[3]}")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ MAC ══════════
@dp.message(F.text == "📱 MAC-адрес")
async def mac_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_mac)
    await message.answer("📱 Введите <b>MAC-адрес</b> — например <code>00:1A:2B:3C:4D:5E</code>:",
                         parse_mode="HTML")


@dp.message(BotStates.waiting_for_mac)
async def mac_process(message: types.Message, state: FSMContext):
    mac = (message.text or "").strip()
    if not mac:
        await message.answer("❌ Введите MAC.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = _pget(f"https://api.macvendors.com/{mac}")
    if "error" in data:
        await message.answer(f"❌ Ошибка: {data['error']}",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    await message.answer(f"📱 <b>MAC:</b> <code>{mac}</code>\n\n└ Производитель: <b>{data}</b>",
                         parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ НОВОСТИ ══════════
@dp.message(F.text == "📰 Новости")
async def news_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_news)
    await message.answer("📰 Введите <b>запрос</b> для новостей:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_news)
async def news_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip()
    if not q:
        await message.answer("❌ Введите запрос.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    news = google_news(q)
    if not news:
        await message.answer("❌ Новостей не найдено.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    lines = [f"📰 <b>Новости: {q}</b>", ""]
    for i, n in enumerate(news, 1):
        lines.append(f"{i}. <a href='{n['link']}'>{n['title']}</a>")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         disable_web_page_preview=True,
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ TEMPMAIL ══════════
@dp.message(F.text == "📧 TempMail")
async def tempmail_start(message: types.Message, state: FSMContext):
    """Главное меню TempMail (анонимно)."""
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

    # Удаляем старые
    await asyncio.to_thread(delete_expired_mailboxes)

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🎲 Случайный email", callback_data="tm_random")],
        [InlineKeyboardButton(text="✏️ Свой логин", callback_data="tm_custom")],
        [InlineKeyboardButton(text="🔐 Сложный пароль", callback_data="tm_strong")],
        [InlineKeyboardButton(text="🌐 Сменить домен", callback_data="tm_domains")],
    ])

    await message.answer(
        "📧 <b>АНОНИМНАЯ ПОЧТА</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔒 <b>Полная анонимность:</b>\n"
        "├ Не привязана к Telegram\n"
        "├ Не сохраняется кто ты\n"
        "├ Удаляется через 60 минут\n"
        "└ Рандомные данные\n\n"

        "Выбери тип:",
        parse_mode="HTML",
        reply_markup=kb
    )


@dp.callback_query(F.data == "tm_random")
async def tm_random(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("⏳ Создаю...")
    await _create_anon_mail(callback.message, state, None, None, None)


@dp.callback_query(F.data == "tm_custom")
async def tm_custom(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    await state.set_state(BotStates.waiting_for_custom_login)
    await callback.message.answer(
        "✏️ <b>Свой логин</b>\n\n"
        "Введи логин (без @):\n"
        "├ Например: secret\n"
        "└ Только латиница\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )



# [DELETED DUP] tm_custom_login

@dp.callback_query(F.data == "tm_strong")
async def tm_strong(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("🔐 Генерирую...")
    pwd = generate_strong_password(20)
    await _create_anon_mail(callback.message, state, None, None, pwd)


@dp.callback_query(F.data == "tm_domains")
async def tm_domains(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    domains = await asyncio.to_thread(mailtm_get_domains)

    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb_rows = []
    for d in domains[:8]:
        kb_rows.append([InlineKeyboardButton(text=f"@{d}", callback_data=f"tm_domain_{d}")])

    await callback.message.answer(
        "🌐 <b>Домены:</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows)
    )



# [DELETED DUP] tm_set_domain

async def _create_anon_mail(message, state, login=None, domain=None, password=None):
    """Общая функция создания анонимной почты."""
    await message.answer("⏳ Создаю анонимную почту...")

    data = await asyncio.to_thread(mailtm_create_anon, login, domain, password)

    if not data:
        await message.answer("❌ Не удалось. Попробуй позже.")
        return

    if isinstance(data, dict) and data.get("error") == "login_taken":
        await message.answer("❌ Логин занят.")
        return

    # Сохраняем анонимно
    await asyncio.to_thread(save_anon_mailbox, data)

    await state.update_data(tempmail=data)
    await state.set_state(BotStates.waiting_for_tempmail)

    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🌐 Открыть в браузере", url="https://mail.tm/ru/")],
        [InlineKeyboardButton(text="📥 Входящие", callback_data="tm_check")],
        [InlineKeyboardButton(text="⭐ Избранное", callback_data="tm_fav")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="tm_stats")],
        [InlineKeyboardButton(text="🕐 История", callback_data="tm_history")],
    ])

    await message.answer(
        f"🔒 <b>АНОНИМНАЯ ПОЧТА</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"

        f"📩 <b>Email:</b>\n"
        f"<code>{data['email']}</code>\n\n"

        f"🔑 <b>Пароль:</b>\n"
        f"<code>{data['password']}</code>\n\n"

        f"🆔 <b>Сессия:</b> <code>{data['session_id'][:8]}...</code>\n\n"

        f"⏳ Удалится через 60 минут\n"
        f"🔒 Никто не знает что это ты",
        parse_mode="HTML",
        reply_markup=kb
    )


# ═══════════════════════════════════════════
# INBOX — входящие
# ═══════════════════════════════════════════


# [DELETED DUP] tm_check

@dp.callback_query(F.data == "tm_fav")
async def tm_fav(callback: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await callback.answer("❌")
        return

    favs = await asyncio.to_thread(get_favorites, tm.get("session_id", ""))

    if not favs:
        await callback.message.answer("⭐ <b>Избранное пусто</b>", parse_mode="HTML")
        return

    lines = ["⭐ <b>Избранное:</b>\n"]
    for i, (mid, frm, subj) in enumerate(favs, 1):
        lines.append(f"{i}. От: <code>{html.escape(str(frm))}</code>")
        lines.append(f"   📝 {html.escape(str(subj)[:60].replace("<", "").replace(">", ""))}")
        lines.append(f"   📖 /tmread {mid}")
        lines.append("")

    await callback.message.answer("\n".join(lines), parse_mode="HTML")


@dp.callback_query(F.data == "tm_stats")
async def tm_stats(callback: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await callback.answer("❌")
        return

    stats = await asyncio.to_thread(get_mail_stats, tm.get("session_id", ""))

    await callback.message.answer(
        f"📊 <b>СТАТИСТИКА ПОЧТЫ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📥 Получено: <b>{stats['received']}</b>\n"
        f"📤 Отправлено: <b>{stats['sent']}</b>\n"
        f"⭐ Избранных: <b>{stats['favorites']}</b>",
        parse_mode="HTML"
    )


@dp.callback_query(F.data == "tm_history")
async def tm_history(callback: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await callback.answer("❌")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT direction, from_email, to_email, subject, created_at
            FROM anon_mail_history WHERE session_id=?
            ORDER BY id DESC LIMIT 20
        """, (tm.get("session_id", ""),))
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        rows = []

    if not rows:
        await callback.message.answer("🕐 <b>История пуста</b>", parse_mode="HTML")
        return

    lines = ["🕐 <b>История:</b>\n"]
    for direction, frm, to, subj, dt in rows:
        icon = "📤" if direction == "out" else "📥"
        lines.append(f"{icon} {html.escape(str(subj)[:50].replace("<", "").replace(">", ""))}")
        lines.append(f"   {dt[11:16]}")
        lines.append("")

    await callback.message.answer("\n".join(lines), parse_mode="HTML")


@dp.callback_query(F.data == "tm_create_random")
async def tm_create_random(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("⏳ Создаю...")
    await _create_tempmail(callback.message, state, None, None, None)


@dp.callback_query(F.data == "tm_create_custom")
async def tm_create_custom(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    await state.set_state(BotStates.waiting_for_custom_login)
    await callback.message.answer(
        "✏️ <b>Свой email</b>\n\n"
        "Введи <b>логин</b> (без @ и домена):\n"
        "├ Например: mymail\n"
        "├ Или: boss2026\n"
        "└ Только латиница и цифры\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_custom_login)
async def tm_custom_login(message: types.Message, state: FSMContext):
    login = (message.text or "").strip().lower()

    if not login or len(login) < 3:
        await message.answer("❌ Логин минимум 3 символа")
        return

    login = re.sub(r"[^a-z0-9._-]", "", login)
    if not login:
        await message.answer("❌ Только латиница и цифры")
        return

    await _create_tempmail(message, state, login, None, None)


@dp.callback_query(F.data == "tm_create_strong")
async def tm_create_strong(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("🔐 Генерирую...")
    password = generate_strong_password(16)
    await _create_tempmail(callback.message, state, None, None, password)


@dp.callback_query(F.data == "tm_change_domain")
async def tm_change_domain(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()

    domains = await asyncio.to_thread(mailtm_get_domains)

    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb_rows = []
    for d in domains[:8]:
        kb_rows.append([InlineKeyboardButton(text=f"@{d}", callback_data=f"tm_domain_{d}")])

    kb = InlineKeyboardMarkup(inline_keyboard=kb_rows)

    await callback.message.answer(
        "🌐 <b>Выбери домен</b>",
        parse_mode="HTML",
        reply_markup=kb
    )


@dp.callback_query(F.data.startswith("tm_domain_"))
async def tm_set_domain(callback: types.CallbackQuery, state: FSMContext):
    domain = callback.data.replace("tm_domain_", "")
    await callback.answer(f"🌐 {domain}")
    await _create_tempmail(callback.message, state, None, domain, None)


async def _create_tempmail(message, state, login=None, domain=None, password=None):
    """Общая функция создания."""
    await message.answer("⏳ Создаю почту...")

    data = await asyncio.to_thread(mailtm_create_custom, login, domain, password)

    if not data:
        await message.answer("❌ Не удалось создать. Попробуй позже.")
        return

    if isinstance(data, dict) and data.get("error") == "login_taken":
        await message.answer("❌ Логин занят. Попробуй другой.")
        return

    await state.update_data(tempmail=data)
    await state.set_state(BotStates.waiting_for_tempmail)

    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🌐 Открыть mail.tm", url="https://mail.tm/ru/")],
        [InlineKeyboardButton(text="📥 Входящие", callback_data="tm_check")],
        [InlineKeyboardButton(text="⭐ Избранное", callback_data="tm_favorites")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="tm_stats")],
    ])

    await message.answer(
        f"📧 <b>Почта создана</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"

        f"📩 <b>Email:</b>\n"
        f"<code>{data['email']}</code>\n\n"

        f"🔑 <b>Пароль:</b>\n"
        f"<code>{data['password']}</code>\n\n"

        f"⏳ Живёт: 60 минут",
        parse_mode="HTML",
        reply_markup=kb
    )


@dp.message(BotStates.waiting_for_tempmail, F.text == "🔄 Проверить")
async def tempmail_check(message: types.Message, state: FSMContext):
    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await message.answer("❌ Нет email.")
        return
    if tempmail_is_expired(tm.get("created", 0)):
        new_tm = tempmail_new()
        if not new_tm:
            await message.answer("❌ Не удалось создать новый.")
            return
        await state.update_data(tempmail=new_tm)
        await message.answer(f"📧 <b>Новый email:</b>\n<code>{new_tm['email']}</code>", parse_mode="HTML")
        return
    inbox = tempmail_inbox(tm.get("token", ""))
    if "error" in inbox:
        await message.answer(f"❌ Ошибка: {inbox['error']}")
        return
    emails = inbox.get("emails", [])
    if not emails:
        left = int(60 - (time.time() - tm.get("created", 0)) / 60)
        await message.answer(f"📭 Писем нет.\n📧 <code>{tm.get('email', '')}</code>\n⏳ Осталось: {left} мин.",
                             parse_mode="HTML")
        return
    text = f"📬 <b>Входящие ({len(emails)}):</b>\n\n"
    for i, e in enumerate(emails[-5:], 1):
        text += f"<b>#{i}</b> От: {e.get('from', '—')}\n"
        text += f"📝 Тема: {e.get('subject', '—')}\n"
        body = e.get('text', '') or e.get('intro', '')
        if body:
            body = body[:300]
            text += f"💬 <code>{body}</code>\n"
        text += "\n"
    await message.answer(text, parse_mode="HTML")


# ══════════ XP ПРОФИЛЬ ══════════
@dp.message(F.text == "🏆 Профиль XP")
async def profile_xp(message: types.Message):
    try:
        info = get_level_info(message.from_user.id)
    except NameError:
        xp, level = get_user_xp(message.from_user.id)
        need = level * 100
        info = {"xp": xp, "level": level, "need": need,
                "progress": int(xp / need * 100) if need else 0,
                "to_next": need - xp, "next_level": level + 1}

    pct = info["progress"]
    filled = int(pct / 10)
    bar = "█" * filled + "░" * (10 - filled)

    await message.answer(
        f"🏆 <b>Ваш прогресс</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"⭐ <b>Уровень:</b> {info['level']}\n"
        f"📊 <b>XP:</b> <code>{info['xp']:,} / {info['need']:,}</code>\n"
        f"📈 <b>Прогресс:</b> [{bar}] {pct}%\n\n"
        f"🎯 До уровня {info['next_level']}: <b>{info['to_next']:,} XP</b>",
        parse_mode="HTML",
        reply_markup=get_settings_keyboard(message.from_user.id)
    )


@dp.message(F.text == "🏆 Награды")
async def my_rewards_alias(message: types.Message, state: FSMContext):
    await my_rewards(message)


@dp.message(F.text == "🎁 Мои награды")
async def my_rewards(message: types.Message):
    rewards = get_user_rewards(message.from_user.id)
    if not rewards:
        await message.answer(
            "🎁 <b>Твои награды</b>\n\n"
            "📭 Пока наград нет.\n\n"
            "🏆 Делай поиски → достижения → награды!",
            parse_mode="HTML",
            reply_markup=get_settings_keyboard(message.from_user.id)
        )
        return

    lines = [f"🎁 <b>Твои награды</b> ({len(rewards)})\n"]
    for name, desc, dt in rewards[:30]:
        lines.append(f"✅ <b>{name}</b>")
        lines.append(f"   ├ {desc}")
        lines.append(f"   └ 📅 {dt[:10]}\n")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))


# ══════════ ДОСТИЖЕНИЯ ══════════
@dp.message(F.text == "🏆 Достижения")
async def achievements_view(message: types.Message):
    rows = get_user_achievements(message.from_user.id)
    unlocked = {c for c, _ in rows}
    lines = ["🏆 <b>Ваши достижения:</b>\n"]
    for code, (emoji, title) in ACHIEVEMENTS.items():
        if code in unlocked:
            lines.append(f"{emoji} ✅ {title}")
        else:
            lines.append(f"🔒 ❌ {title}")
    lines.append(f"\n📊 Открыто: {len(unlocked)}/{len(ACHIEVEMENTS)}")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))


# ══════════ ФОТО VK ══════════
@dp.message(F.text == "🎨 Фото VK")
async def vk_photo_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_vk_photo)
    await message.answer("🎨 Введите <b>VK ID</b> или <b>username</b> — например <code>1</code> или <code>durov</code>:",
                         parse_mode="HTML")


@dp.message(BotStates.waiting_for_vk_photo)
async def vk_photo_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip().lstrip("@")
    if not q:
        await message.answer("❌ Введите ID/username.")
        return
    await bot.send_chat_action(message.chat.id, "upload_photo")
    profile = vk_get_profile(q)
    if not profile:
        await message.answer("❌ Профиль не найден.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    photo = profile.get("photo_max_orig") or profile.get("photo_200")
    caption = format_vk_card(profile)
    log_search(message.from_user.id, message.from_user.username or "", q, "vk")
    add_xp(message.from_user.id, 20)
    if photo:
        try:
            await message.answer_photo(photo, caption=caption, parse_mode="HTML",
                                       reply_markup=get_settings_keyboard(message.from_user.id))
        except Exception:
            await message.answer(caption + f"\n\n🔗 <a href='{photo}'>Фото</a>",
                                 parse_mode="HTML",
                                 reply_markup=get_settings_keyboard(message.from_user.id))
    else:
        await message.answer(caption, parse_mode="HTML",
                             reply_markup=get_settings_keyboard(message.from_user.id))
    unlocked = check_and_award(message.from_user.id, "vk")
    if unlocked:
        names = ", ".join(ACHIEVEMENTS[c][1] for c in unlocked)
        await message.answer(f"🏆 <b>Новые достижения:</b> {names}", parse_mode="HTML")

    rewards = check_and_give_rewards(message.from_user.id)
    if rewards:
        rewards_msg = "🎁 <b>Ты получил награды!</b>\n\n" + "\n".join(rewards)
        await message.answer(rewards_msg, parse_mode="HTML")
    await state.clear()


# ══════════ ФЛАГ IP ══════════
@dp.message(F.text == "🌍 Флаг IP")
async def ip_flag_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_ip_flag)
    await message.answer("🌍 Введите <b>IP-адрес</b> или <b>код страны</b> (RU, US, DE):",
                         parse_mode="HTML")


@dp.message(BotStates.waiting_for_ip_flag)
async def ip_flag_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip()
    if not q:
        await message.answer("❌ Введите IP или код страны.")
        return
    if len(q) == 2 and q.isalpha():
        cc = q.upper()
        await message.answer(f"🏴 Флаг <b>{cc}</b>: {ip_flag(cc)}", parse_mode="HTML",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = _pget(f"http://ip-api.com/json/{q}?fields=status,country,countryCode,city,isp,query")
    if data.get("status") == "success":
        cc = data.get("countryCode", "")
        log_search(message.from_user.id, message.from_user.username or "", q, "ip")
        add_xp(message.from_user.id, 10)
        await message.answer(
            f"{ip_flag(cc)} <b>{data.get('country')}</b>\n"
            f"🏙 {data.get('city')}\n"
            f"🌐 {data.get('isp')}\n"
            f"🔢 <code>{data.get('query')}</code>\n"
            f"🏴 Флаг: {ip_flag(cc)}",
            parse_mode="HTML",
            reply_markup=get_settings_keyboard(message.from_user.id)
        )
        unlocked = check_and_award(message.from_user.id, "ip")
        if unlocked:
            names = ", ".join(ACHIEVEMENTS[c][1] for c in unlocked)
            await message.answer(f"🏆 <b>Новые достижения:</b> {names}", parse_mode="HTML")
    else:
        await message.answer("❌ Не удалось определить.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ DUCKDUCKGO ══════════
@dp.message(F.text == "🦆 DuckDuckGo")
async def duck_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_duck)
    await message.answer("🦆 Введите <b>поисковый запрос</b>:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_duck)
async def duck_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip()
    if not q:
        await message.answer("❌ Введите запрос.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    results = await asyncio.to_thread(duck_search, q, 8)
    if not results:
        await message.answer("❌ Ничего не найдено.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    lines = [f"🦆 <b>DuckDuckGo:</b> <i>{html.escape(q)}</i>\n"]
    for i, r in enumerate(results, 1):
        title = html.escape(r.get("title") or "—")[:80]
        snippet = html.escape(r.get("snippet") or "")[:180]
        url = r.get("url", "")
        lines.append(f"<b>{i}.</b> {title}")
        if snippet:
            lines.append(f"   <i>{snippet}</i>")
        if url:
            lines.append(f"   🔗 <a href='{url}'>Открыть</a>")
        lines.append("")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         disable_web_page_preview=True,
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ WIKIDATA ══════════
@dp.message(F.text == "📚 Wikidata")
async def wikidata_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_wikidata)
    await message.answer("📚 Введите <b>запрос</b> для Wikidata:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_wikidata)
async def wikidata_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip()
    if not q:
        await message.answer("❌ Введите запрос.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    results = await asyncio.to_thread(wikidata_search, q, 5)
    if not results:
        await message.answer("❌ Ничего не найдено.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    lines = [f"📚 <b>Wikidata:</b> <i>{html.escape(q)}</i>\n"]
    for r in results:
        lines.append(f"🆔 <code>{r['id']}</code> — <b>{html.escape(r['label'])}</b>")
        if r.get("desc"):
            lines.append(f"   <i>{html.escape(r['desc'])}</i>")
        lines.append(f"   🔗 <a href='{r['url']}'>Открыть</a>\n")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         disable_web_page_preview=True,
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ WIKTIONARY ══════════
@dp.message(F.text == "📖 Wiktionary")
async def wiktionary_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_wiktionary)
    await message.answer("📖 Введите <b>слово</b> для Wiktionary:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_wiktionary)
async def wiktionary_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip()
    if not q:
        await message.answer("❌ Введите слово.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    text = await asyncio.to_thread(wiktionary_search, q)
    if not text:
        await message.answer("❌ Не найдено.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    msg = f"📖 <b>{html.escape(q)}</b>\n\n{html.escape(text)}"
    msg = safe_truncate(msg, 4000)
    await message.answer(msg, parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ SHODAN ══════════
@dp.message(F.text == "🛡 Shodan")
async def shodan_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_shodan)
    await message.answer("🛡 Введите <b>IP</b> для проверки в Shodan:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_shodan)
async def shodan_process(message: types.Message, state: FSMContext):
    ip = (message.text or "").strip()
    if not ip:
        await message.answer("❌ Введите IP.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = await asyncio.to_thread(shodan_lookup, ip)
    if "error" in data:
        await message.answer(
            f"❌ {data['error']}\n\n🔗 <a href='https://www.shodan.io/host/{ip}'>Смотреть на Shodan</a>",
            parse_mode="HTML",
            reply_markup=get_settings_keyboard(message.from_user.id))
        await state.clear()
        return
    lines = [f"🛡 <b>Shodan:</b> <code>{ip}</code>", ""]
    if data.get("org"):
        lines.append(f"├ Организация: {data['org']}")
    if data.get("country_name"):
        lines.append(f"├ Страна: {data['country_name']}")
    if data.get("os"):
        lines.append(f"├ ОС: {data['os']}")
    ports = data.get("ports", [])
    if ports:
        lines.append(f"└ Портов: {len(ports)} — {', '.join(map(str, ports[:15]))}")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ HIBP ══════════
@dp.message(F.text == "📧 HIBP")
async def hibp_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_hibp)
    await message.answer("📧 Введите <b>email</b> для проверки утечек:", parse_mode="HTML")


@dp.message(BotStates.waiting_for_hibp)
async def hibp_process(message: types.Message, state: FSMContext):
    email = (message.text or "").strip()
    if not email:
        await message.answer("❌ Введите email.")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = await asyncio.to_thread(hibp_check, email)
    if isinstance(data, list):
        lines = [f"📧 <b>HIBP:</b> <code>{html.escape(email)}</code>",
                 f"\n⚠️ Найден в <b>{len(data)}</b> утечках:\n"]
        for b in data[:10]:
            lines.append(f"├ <b>{html.escape(b.get('Name', '—'))}</b> — {b.get('BreachDate', '—')}")
        await message.answer("\n".join(lines), parse_mode="HTML",
                             reply_markup=get_settings_keyboard(message.from_user.id))
    elif isinstance(data, dict) and data.get("error"):
        await message.answer("✅ Утечек не найдено.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
    else:
        await message.answer("❌ Ошибка проверки.",
                             reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()


# ══════════ TG GIFTS ══════════
@dp.message(F.text == "🎁 TG Gifts")
async def gifts_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_gifts)
    await message.answer("🎁 Введите <b>username</b> или <b>ID</b> юзера (без @):", parse_mode="HTML")


@dp.message(BotStates.waiting_for_gifts)
async def gifts_process(message: types.Message, state: FSMContext):
    q = (message.text or "").strip().lstrip("@")
    if not q:
        await message.answer("❌ Введите username.")
        return
    info = telegram_gifts_info(q)
    await message.answer(
        f"🎁 <b>Telegram Gifts</b>\n\n"
        f"🔗 <a href='{info['url']}'>Открыть профиль</a>\n\n"
        f"<i>Функция в разработке — скоро будет полный список подарков.</i>",
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_settings_keyboard(message.from_user.id)
    )
    add_xp(message.from_user.id, 5)
    unlock_achievement(message.from_user.id, "gift_hunter")
    await state.clear()


# ══════════ АНАЛИЗ БАЗ ══════════
@dp.message(F.text == "📊 Анализ баз")
async def user_analyze_bases(message: types.Message):
    await bot.send_chat_action(message.chat.id, "typing")
    data = await asyncio.to_thread(analyze_bases)
    if "error" in data:
        await message.answer(f"❌ Ошибка: {data['error']}",
                             reply_markup=get_settings_keyboard(message.from_user.id))
        return
    lines = [f"📊 <b>Анализ баз</b>\n├ Всего записей: <b>{data['total']}</b>\n"]
    if data["cities"]:
        lines.append("\n🏙 <b>Топ городов:</b>")
        for city, cnt in data["cities"][:10]:
            lines.append(f"├ {html.escape(str(city))}: {cnt}")
    if data["operators"]:
        lines.append("\n📱 <b>Операторы:</b>")
        for op, cnt in data["operators"]:
            lines.append(f"├ {html.escape(str(op))}: {cnt}")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))


# ══════════════════ АДМИН-ПАНЕЛЬ ══════════════════
@dp.message(F.text == "⚙️ Админ-панель")
async def admin_panel(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "⚙️ <b>АДМИН-ПАНЕЛЬ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери категорию:",
        parse_mode="HTML",
        reply_markup=get_admin_keyboard()
    )


@dp.message(F.text == "⚙️ Настройки админки")
async def admin_settings_panel(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("⚙️ <b>Настройки админ-панели:</b>",
                         reply_markup=get_admin_settings_keyboard(),
                         parse_mode="HTML")


@dp.message(F.text == "⬅️ Админ-панель")
async def back_to_admin(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("⚙️ <b>Админ-панель:</b>", reply_markup=get_admin_keyboard(), parse_mode="HTML")


@dp.message(F.text == "🆘 Тикеты")
async def admin_tickets_view(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, username, message, status, created_at FROM support_tickets ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        await message.answer("📭 Обращений нет.", reply_markup=get_admin_settings_keyboard())
        return
    lines = ["🆘 <b>Последние 20 тикетов:</b>\n"]
    for r in rows:
        tid, uid, uname, msg, status, created = r
        lines.append(
            f"<b>#{tid}</b> [{status}] — <code>{uid}</code>\n"
            f"💬 {html.escape(str(msg)[:120].replace("<", "").replace(">", ""))}\n"
            f"↩️ <code>/reply {uid} текст</code>\n"
        )
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_settings_keyboard())


@dp.message(F.text == "⚙️ Пороги призов")
async def admin_prize_thresholds(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    thresholds = get_prize_thresholds()
    if not thresholds:
        await message.answer("📭 Порогов нет.", reply_markup=get_admin_settings_keyboard())
        return
    lines = ["⚙️ <b>Пороги призов:</b>\n"]
    for friends, ptype, pvalue in thresholds:
        lines.append(f"🎁 <b>{friends} друзей</b> → {ptype}: {pvalue}")
    lines.append("\n📝 Для изменения — пиши в поддержку.")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_settings_keyboard())



# [DELETED DUP] admin_stats

@dp.message(F.text == "📊 Аналитика")
async def admin_analytics(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await bot.send_chat_action(message.chat.id, "typing")
    total, subs, stars, bans = get_stats()
    growth = get_week_growth()
    top_users = get_top_users(5)
    search_types = get_search_types()
    top_refs = get_top_referrers(5)
    lines = ["📊 <b>Аналитика бота:</b>\n"]
    lines.append(f"👥 Всего юзеров: <b>{total}</b>")
    lines.append(f"📈 За неделю: <b>+{growth}</b>")
    lines.append(f"⭐ Платных: <b>{subs}</b>")
    lines.append(f"💎 Stars: <b>{stars}</b>")
    if search_types:
        lines.append("\n🔍 <b>Типы поисков:</b>")
        emoji_map = {"phone": "📱", "ip": "🌍", "vk": "🆔", "email": "📧",
                     "username": "🔎", "bigbase": "🔓", "name": "👤"}
        for t, c in search_types[:8]:
            e = emoji_map.get(t, "🔍")
            lines.append(f"├ {e} {t or '—'}: <b>{c}</b>")
    if top_users:
        lines.append("\n🏆 <b>Топ-5 по XP:</b>")
        for i, u in enumerate(top_users, 1):
            uname = f"@{u[1]}" if u[1] else f"id{u[0]}"
            lines.append(f"{i}. {html.escape(uname)} — <b>{u[2]}</b> XP (ур. {u[3]})")
    if top_refs:
        lines.append("\n🤝 <b>Топ-5 рефереров:</b>")
        for i, r in enumerate(top_refs, 1):
            uname = f"@{r[1]}" if r[1] else f"id{r[0]}"
            lines.append(f"{i}. {html.escape(uname)} — <b>{r[2]}</b> друзей")
    text = "\n".join(lines)
    text = safe_truncate(text, 4000)
    await message.answer(text, parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "🎁 Заявки на призы")
async def admin_prize_requests(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    rows = get_pending_prizes(50)
    if not rows:
        await message.answer("📭 Заявок нет.", reply_markup=get_admin_keyboard())
        return
    lines = ["🎁 <b>Заявки на призы:</b>\n"]
    for pid, uid, uname, ptype, pvalue, created in rows:
        uname_str = f"@{uname}" if uname else f"id{uid}"
        lines.append(f"<b>#{pid}</b> — {html.escape(uname_str)} (<code>{uid}</code>)\n"
                     f"├ 🎁 {ptype}: {pvalue}\n├ 📅 {created}\n└ ✍️ <code>/give {pid}</code>\n")
    text = "\n".join(lines)
    text = safe_truncate(text, 4000)
    await message.answer(text, parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(Command("give"))
async def admin_give_prize(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args.isdigit():
        await message.answer("❌ Формат: <code>/give ID</code>", parse_mode="HTML")
        return
    pid = int(args)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, prize_type, prize_value FROM prizes WHERE id=?", (pid,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        await message.answer("❌ Заявка не найдена.")
        return
    uid, ptype, pvalue = row
    mark_prize_given(pid)
    conn.close()
    try:
        await bot.send_message(uid, f"🎉 <b>Ваш приз выдан!</b>\n\n🎁 {ptype}: {pvalue}\n\nСпасибо за активность!",
                               parse_mode="HTML")
    except Exception:
        pass
    await message.answer(f"✅ Приз #{pid} выдан юзеру <code>{uid}</code>.",
                         parse_mode="HTML", reply_markup=get_admin_keyboard())



# [DELETED DUP] admin_users

@dp.message(F.text == "🔍 Поиск юзера")
async def admin_find_user(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("🔍 Введите <b>username</b> (без @):")
    await state.set_state(AdminStates.waiting_for_find_user)


@dp.message(AdminStates.waiting_for_find_user)
async def admin_find_user_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    u = get_user_by_username((message.text or "").strip())
    if not u:
        await message.answer("❌ Не найден.", reply_markup=get_admin_keyboard())
        await state.clear()
        return
    await message.answer(
        f"👤 <b>Найден:</b>\n"
        f"🆔 <code>{u[0]}</code>\n"
        f"📛 @{u[1] or '—'}\n"
        f"👋 {u[2] or '—'}\n"
        f"⭐ {u[3]}\n"
        f"📊 Запросов сегодня: {u[4]}",
        parse_mode="HTML",
        reply_markup=get_admin_keyboard()
    )
    await state.clear()


@dp.message(F.text == "🚫 Забанить")
async def admin_ban_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("🚫 Введите <b>ID</b> юзера для бана:")
    await state.set_state(AdminStates.waiting_for_ban)


@dp.message(AdminStates.waiting_for_ban)
async def admin_ban_id(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ ID должен быть числом.")
        return
    await state.update_data(ban_id=int(message.text.strip()))
    await message.answer("📝 Введите <b>причину</b> бана:")
    await state.set_state(AdminStates.waiting_for_ban_reason)


@dp.message(AdminStates.waiting_for_ban_reason)
async def admin_ban_reason(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    data = await state.get_data()
    ban_id = data.get("ban_id")
    reason = (message.text or "").strip() or "без причины"
    add_ban(ban_id, "", reason, ADMIN_ID)
    try:
        await bot.send_message(
            ban_id,
            f"🚫 <b>Вы забанены в боте.</b>\n\n"
            f"📝 Причина: {html.escape(reason)}\n\n"
            f"Если считаете это ошибкой — напишите в поддержку канала.",
            parse_mode="HTML"
        )
    except Exception as e:
        logging.warning(f"ban notify error: {e}")
    await message.answer(
        f"✅ Юзер <code>{ban_id}</code> забанен.\n📝 Причина: {reason}",
        parse_mode="HTML",
        reply_markup=get_admin_keyboard()
    )
    await state.clear()


@dp.message(F.text == "✅ Разбанить")
async def admin_unban_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("✅ Введите <b>ID</b> юзера для разбана:")
    await state.set_state(AdminStates.waiting_for_unban)


@dp.message(AdminStates.waiting_for_unban)
async def admin_unban_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ ID должен быть числом.")
        return
    uid = int(message.text.strip())
    if remove_ban(uid):
        try:
            await bot.send_message(uid, "✅ <b>Вы разбанены!</b>\n\nМожете снова пользоваться ботом.",
                                   parse_mode="HTML")
        except Exception as e:
            logging.warning(f"unban notify error: {e}")
        await message.answer(f"✅ Юзер <code>{uid}</code> разбанен.",
                             parse_mode="HTML", reply_markup=get_admin_keyboard())
    else:
        await message.answer(f"❌ Юзер <code>{uid}</code> не в бане.",
                             parse_mode="HTML", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "📋 Список банов")
async def admin_bans_list(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    bans = get_all_bans(50)
    if not bans:
        await message.answer("📭 Банов нет.", reply_markup=get_admin_keyboard())
        return
    lines = ["📋 <b>Список банов:</b>\n"]
    for b in bans:
        lines.append(f"🆔 <code>{b[0]}</code> — {b[2]}\n   📅 {b[3]}")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "📈 Логи поиска")
async def admin_logs(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    logs = get_search_logs(50)
    if not logs:
        await message.answer("📭 Логов нет.", reply_markup=get_admin_keyboard())
        return
    lines = ["📈 <b>Последние 50 запросов:</b>\n"]
    for l in logs:
        lines.append(f"🆔 <code>{l[0]}</code> [{l[3]}] <code>{html.escape(str(l[2]))}</code>\n   📅 {l[4]}")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "📢 Рассылка")
async def admin_broadcast_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("📢 Отправьте <b>текст</b> для рассылки:")
    await state.set_state(AdminStates.waiting_for_broadcast)


@dp.message(AdminStates.waiting_for_broadcast)
async def admin_broadcast_send(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    text = message.text or ""
    users = get_users_for_promo_broadcast()
    sent = 0
    for uid in users:
        try:
            await bot.send_message(uid, text)
            sent += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass
    await message.answer(f"✅ Разослано: {sent}/{len(users)}", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "🎁 Умный промокод")
async def admin_create_promo(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👑 VIP:30 дней", callback_data="promo_type_vip")],
        [InlineKeyboardButton(text="💎 Premium:30 дней", callback_data="promo_type_premium")],
        [InlineKeyboardButton(text="🔷 Base:30 дней", callback_data="promo_type_base")],
        [InlineKeyboardButton(text="🎟 +100 запросов", callback_data="promo_type_queries")],
        [InlineKeyboardButton(text="⭐ +500 XP", callback_data="promo_type_xp")],
        [InlineKeyboardButton(text="🏆 Достижение", callback_data="promo_type_achievement")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="promo_cancel")],
    ])
    await state.set_state(AdminStates.waiting_for_promo_limit)
    await message.answer(
        "🎁 <b>СОЗДАНИЕ УМНОГО ПРОМОКОДА</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "1️⃣ Выбери <b>тип награды</b>:\n\n"
        "├ 👑 <b>VIP</b> — подписка VIP\n"
        "├ 💎 <b>Premium</b> — подписка Premium\n"
        "├ 🔷 <b>Base</b> — подписка Base\n"
        "├ 🎟 <b>Queries</b> — доп. запросы\n"
        "├ ⭐ <b>XP</b> — опыт\n"
        "└ 🏆 <b>Achievement</b> — достижение",
        parse_mode="HTML", reply_markup=kb
    )


@dp.callback_query(F.data.startswith("promo_type_"))
async def promo_type_choice(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        return
    ptype = callback.data.replace("promo_type_", "")
    await state.update_data(promo_type=ptype)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="1️⃣ 1 активация", callback_data="promo_uses_1")],
        [InlineKeyboardButton(text="5️⃣ 5 активаций", callback_data="promo_uses_5")],
        [InlineKeyboardButton(text="🔟 10 активаций", callback_data="promo_uses_10")],
        [InlineKeyboardButton(text="💯 100 активаций", callback_data="promo_uses_100")],
        [InlineKeyboardButton(text="✏️ Своё число", callback_data="promo_uses_custom")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="promo_cancel")],
    ])
    await callback.message.edit_text(
        f"🎁 Тип: <b>{ptype.upper()}</b>\n\n2️⃣ Сколько <b>активаций</b>?",
        parse_mode="HTML", reply_markup=kb
    )
    await callback.answer()


@dp.callback_query(F.data.startswith("promo_uses_"))
async def promo_uses_choice(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        return
    val = callback.data.replace("promo_uses_", "")
    if val == "custom":
        await callback.message.edit_text("✏️ Введи <b>число</b> активаций:", parse_mode="HTML")
        await state.set_state(AdminStates.waiting_for_promo_broadcast_text)
        return
    max_uses = int(val)
    await state.update_data(promo_uses=max_uses)
    data = await state.get_data()
    ptype = data.get("promo_type", "vip")

    # Умный формат
    smart_types = {
        "vip": "VIP:30",
        "premium": "PREMIUM:30",
        "base": "BASE:30",
        "queries": "QUERIES:100",
        "xp": "XP:500",
        "achievement": "ACHIEVEMENT:phone_hunter",
    }
    smart_type = smart_types.get(ptype.lower(), "VIP:30")

    code = generate_promo(10)
    save_promo(code, smart_type, max_uses)
    await callback.message.edit_text(
        f"✅ <b>Промокод создан!</b>\n\n"
        f"🔑 Код: <code>{code}</code>\n\n"
        f"📦 Тип: <b>{ptype.upper()}</b>\n"
        f"🔢 Активаций: <b>{max_uses}</b>\n\n"
        f"Отправь его пользователю.",
        parse_mode="HTML"
    )
    await state.clear()
    await callback.answer()


@dp.message(AdminStates.waiting_for_promo_broadcast_text)
async def promo_custom_uses(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ Введи число.")
        return
    max_uses = int(message.text.strip())
    data = await state.get_data()
    ptype = data.get("promo_type", "vip")
    code = generate_promo(10)
    save_promo(code, ptype.upper(), max_uses)
    await message.answer(
        f"✅ <b>Промокод создан!</b>\n\n"
        f"🔑 Код: <code>{code}</code>\n\n"
        f"📦 Тип: <b>{ptype.upper()}</b>\n"
        f"🔢 Активаций: <b>{max_uses}</b>",
        parse_mode="HTML",
        reply_markup=get_admin_keyboard()
    )
    await state.clear()


@dp.callback_query(F.data == "promo_cancel")
async def promo_cancel(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        return
    await state.clear()
    await callback.message.edit_text("❌ Отменено.")
    await callback.answer()


@dp.message(F.text == "📨 Разослать промокод")
async def admin_send_promo(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    code = generate_promo(10)
    save_promo(code, "VIP", 1000)
    users = get_users_for_promo_broadcast()
    text = f"🎁 <b>Новый промокод!</b>\n\n<code>{code}</code>\n\nАктивируй: /start → 🎁 Промокод"
    sent = 0
    for uid in users:
        try:
            await bot.send_message(uid, text, parse_mode="HTML")
            sent += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass
    await message.answer(f"✅ Промокод <code>{code}</code> разослан {sent} юзерам.",
                         parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "➕ Добавить контакт")
async def admin_add_contact(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("➕ Отправьте в формате:\n<code>ФИО | Телефон | Отдел</code>", parse_mode="HTML")
    await state.set_state(AdminStates.waiting_for_contact_add)


@dp.message(AdminStates.waiting_for_contact_add)
async def admin_add_contact_save(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    parts = [p.strip() for p in (message.text or "").split("|")]
    if len(parts) < 3:
        await message.answer("❌ Формат: ФИО | Телефон | Отдел")
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO contacts (full_name, phone, department, status) VALUES (?, ?, ?, ?)",
                 (parts[0], parts[1], parts[2], "active"))
    conn.commit()
    conn.close()
    await message.answer("✅ Контакт добавлен.", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "🎁 Выдать VIP")
async def admin_give_vip(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("🎁 Введите <b>ID</b> юзера:")
    await state.set_state(AdminStates.waiting_for_vip_id)


@dp.message(AdminStates.waiting_for_vip_id)
async def admin_give_vip_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ ID должен быть числом.")
        return
    uid = int(message.text.strip())
    until = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET subscription_tier='VIP', vip_until=? WHERE user_id=?", (until, uid))
    conn.commit()
    conn.close()
    unlock_achievement(uid, "vip_member")
    await message.answer(f"✅ Юзеру <code>{uid}</code> выдан VIP на 30 дней.",
                         parse_mode="HTML", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "📊 Анализ базы")
async def admin_analyze(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT department, COUNT(*) FROM contacts GROUP BY department ORDER BY COUNT(*) DESC LIMIT 5")
    deps = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM contacts")
    total = cursor.fetchone()[0]
    conn.close()
    lines = [f"📊 <b>Анализ базы:</b>\n", f"├ Всего: {total}"]
    for d, c in deps:
        lines.append(f"├ {d or '—'}: {c}")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "📊 Анализ городов")
async def admin_city_analysis(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = await asyncio.to_thread(analyze_bases)
    if "error" in data:
        await message.answer(f"❌ Ошибка: {data['error']}", reply_markup=get_admin_keyboard())
        return
    lines = [f"📊 <b>Анализ баз</b>\n├ Всего: <b>{data['total']}</b>\n"]
    if data["cities"]:
        lines.append("🏙 <b>Топ городов:</b>")
        for city, cnt in data["cities"]:
            lines.append(f"├ {html.escape(str(city))}: {cnt}")
    if data["operators"]:
        lines.append("\n📱 <b>Операторы:</b>")
        for op, cnt in data["operators"]:
            lines.append(f"├ {html.escape(str(op))}: {cnt}")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "📈 Топ запросов")
async def admin_top_queries(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    tops = get_top_queries(5)
    if not tops:
        await message.answer("📭 Логов нет.", reply_markup=get_admin_keyboard())
        return
    lines = ["📈 <b>Топ-5 запросов:</b>\n"]
    for i, (q, c) in enumerate(tops, 1):
        lines.append(f"{i}. <code>{html.escape(q)}</code> — {c} раз")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "📊 По дням")
async def admin_stats_days(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    days = get_stats_by_days()
    if not days:
        await message.answer("📭 Нет данных.", reply_markup=get_admin_keyboard())
        return
    lines = ["📊 <b>Статистика по дням:</b>\n"]
    for d, c in days:
        lines.append(f"├ {d}: {c} поисков")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "👑 Список VIP")
async def admin_vip_list(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    vips = get_vip_users(50)
    if not vips:
        await message.answer("📭 VIP нет.", reply_markup=get_admin_keyboard())
        return
    lines = ["👑 <b>VIP-пользователи:</b>\n"]
    for u in vips:
        lines.append(f"🆔 <code>{u[0]}</code> @{html.escape(str(u[1] or '—'))} — {u[3]}")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=get_admin_keyboard())


@dp.message(F.text == "🎁 Массовый VIP")
async def admin_mass_vip(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("Введите количество дней:")
    await state.set_state(AdminStates.waiting_for_mass_vip)


@dp.message(AdminStates.waiting_for_mass_vip)
async def admin_mass_vip_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ Число.")
        return
    days = int(message.text.strip())
    until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET subscription_tier='VIP', vip_until=?", (until,))
    n = cursor.rowcount
    conn.commit()
    conn.close()
    await message.answer(f"✅ Выдано VIP: {n} юзерам на {days} дней.", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "🗑 Очистить логи")
async def admin_clear_logs(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    n = clear_old_logs(30)
    await message.answer(f"🗑 Удалено логов: {n}", reply_markup=get_admin_keyboard())


@dp.message(F.text == "📥 Экспорт логов")
async def admin_export_logs(message: types.Message):
    """Экспорт логов в CSV (правильно через FSInputFile)."""
    if message.from_user.id != ADMIN_ID:
        return

    logs = get_search_logs(1000)
    if not logs:
        await message.answer("📭 Логов нет.", reply_markup=get_admin_keyboard())
        return

    # Формируем CSV
    csv = "user_id,username,query,type,date\n"
    for l in logs:
        # Экранируем запятые
        query = str(l[2]).replace(",", " ")
        username = str(l[1]).replace(",", " ")
        csv += f"{l[0]},{username},{query},{l[3]},{l[4]}\n"

    # Сохраняем в файл
    import time as _time
    filename = os.path.join(TEMP_DIR, f"logs_{int(_time.time())}.csv")
    try:
        with open(filename, "w", encoding="utf-8-sig") as f:
            f.write(csv)
    except Exception as e:
        await message.answer(f"❌ Ошибка записи: {e}")
        return

    # Отправляем через FSInputFile
    try:
        from aiogram.types import FSInputFile
        file = FSInputFile(filename)
        await message.answer_document(
            file,
            caption=f"📥 <b>Логи</b>\n\n📊 Записей: <b>{len(logs):,}</b>",
            parse_mode="HTML",
            reply_markup=get_admin_keyboard()
        )
    except Exception as e:
        await message.answer(f"❌ Ошибка отправки: {e}")
        return

    # Удаляем временный
    try:
        os.remove(filename)
    except Exception:
        pass


@dp.message(F.text == "🛡 Антифлуд")
async def admin_antiflood(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    current = _get_setting("antiflood", "0")
    new = "0" if current == "1" else "1"
    _set_setting("antiflood", new)
    status = "✅ вкл" if new == "1" else "❌ выкл"
    await message.answer(f"🛡 Антифлуд: {status}", reply_markup=get_admin_keyboard())


# ══════════ АВТОПОСТИНГ ══════════
async def _autopost_worker():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT id, chat_id, text, photo, interval_min, last_sent FROM autopost WHERE enabled=1")
            rows = cur.fetchall()
            conn.close()
            now = datetime.now()
            for rid, chat_id, text, photo, interval, last_sent in rows:
                send = False
                if not last_sent:
                    send = True
                else:
                    try:
                        last = datetime.strptime(last_sent, "%Y-%m-%d %H:%M:%S")
                        if (now - last).total_seconds() >= interval * 60:
                            send = True
                    except Exception:
                        send = True
                if send:
                    try:
                        if photo:
                            await bot.send_photo(chat_id, photo, caption=text or "")
                        else:
                            await bot.send_message(chat_id, text or "")
                        conn = sqlite3.connect(DB_PATH)
                        conn.execute("UPDATE autopost SET last_sent=? WHERE id=?",
                                     (now.strftime("%Y-%m-%d %H:%M:%S"), rid))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        logging.warning(f"autopost error: {e}")
        except Exception as e:
            logging.warning(f"autopost loop: {e}")
        await asyncio.sleep(60)


async def _autobroadcast_worker():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT id, text, interval_min, last_sent FROM autobroadcast WHERE enabled=1")
            rows = cur.fetchall()
            conn.close()
            now = datetime.now()
            for rid, text, interval, last_sent in rows:
                send = False
                if not last_sent:
                    send = True
                else:
                    try:
                        last = datetime.strptime(last_sent, "%Y-%m-%d %H:%M:%S")
                        if (now - last).total_seconds() >= interval * 60:
                            send = True
                    except Exception:
                        send = True
                if send:
                    users = get_users_for_promo_broadcast()
                    for uid in users:
                        try:
                            await bot.send_message(uid, text)
                            await asyncio.sleep(0.05)
                        except Exception:
                            pass
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("UPDATE autobroadcast SET last_sent=? WHERE id=?",
                                 (now.strftime("%Y-%m-%d %H:%M:%S"), rid))
                    conn.commit()
                    conn.close()
        except Exception as e:
            logging.warning(f"autobroadcast: {e}")
        await asyncio.sleep(60)


@dp.message(F.text == "🎨 Автопостинг")
async def admin_autopost(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "🎨 <b>Автопостинг</b>\n\n"
        "Отправьте в формате:\n"
        "<code>chat_id | интервал_мин | текст | [url_фото]</code>\n\n"
        "Пример:\n"
        "<code>@mychannel | 60 | Привет! | https://i.imgur.com/x.jpg</code>",
        parse_mode="HTML"
    )
    await state.set_state(AdminStates.waiting_for_autopost)


@dp.message(AdminStates.waiting_for_autopost)
async def admin_autopost_save(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    parts = [p.strip() for p in (message.text or "").split("|")]
    if len(parts) < 3:
        await message.answer("❌ Формат: chat_id | interval | text | [photo]")
        return
    chat_id = parts[0]
    try:
        interval = int(parts[1])
    except ValueError:
        await message.answer("❌ Интервал — число минут.")
        return
    text = parts[2]
    photo = parts[3] if len(parts) > 3 else ""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO autopost (chat_id, text, photo, interval_min, last_sent, enabled) VALUES (?,?,?,?,?,1)",
        (chat_id, text, photo, interval, None)
    )
    conn.commit()
    conn.close()
    global _autopost_task
    if _autopost_task is None or _autopost_task.done():
        _autopost_task = asyncio.create_task(_autopost_worker())
    await message.answer("✅ Автопост добавлен.", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "📢 Авторассылка")
async def admin_autobroadcast(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "📢 <b>Авторассылка</b>\n\n"
        "Отправьте в формате:\n"
        "<code>интервал_мин | текст</code>\n\n"
        "Пример:\n"
        "<code>1440 | Не забудьте про бота! 🚀</code>",
        parse_mode="HTML"
    )
    await state.set_state(AdminStates.waiting_for_autobroadcast)


@dp.message(AdminStates.waiting_for_autobroadcast)
async def admin_autobroadcast_save(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    parts = [p.strip() for p in (message.text or "").split("|", 1)]
    if len(parts) < 2:
        await message.answer("❌ Формат: interval | text")
        return
    try:
        interval = int(parts[0])
    except ValueError:
        await message.answer("❌ Интервал — число минут.")
        return
    text = parts[1]
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO autobroadcast (text, interval_min, last_sent, enabled) VALUES (?,?,?,1)",
                 (text, interval, None))
    conn.commit()
    conn.close()
    global _auto_broadcast_task
    if _auto_broadcast_task is None or _auto_broadcast_task.done():
        _auto_broadcast_task = asyncio.create_task(_autobroadcast_worker())
    await message.answer("✅ Авторассылка добавлена.", reply_markup=get_admin_keyboard())
    await state.clear()


@dp.message(F.text == "🛑 Стоп авто")
async def admin_stop_auto(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE autopost SET enabled=0")
    conn.execute("UPDATE autobroadcast SET enabled=0")
    conn.commit()
    conn.close()
    await message.answer("🛑 Все авто-задачи остановлены.", reply_markup=get_admin_keyboard())


# ══════════ ЗАКРЫТЫЕ БАЗЫ ══════════
@dp.message(F.text == "🔓 Закрытые базы")
async def closed_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_closed)
    await message.answer(
        "🔓 <b>Закрытые базы</b>\n\n"
        "Введи запрос:\n"
        "├ 📞 +79991234567\n"
        "├ 👤 Иванов Иван\n"
        "├ 📧 ivanov@mail.ru\n"
        "└ 🏠 Москва, ул. Ленина, 1\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_closed)
async def closed_process(message: types.Message, state: FSMContext):
    query = (message.text or "").strip()
    if not query:
        await message.answer("❌ Введи запрос.")
        return

    ok, _ = check_and_update_limit(message.from_user.id, "bigbase")
    if not ok:
        await message.answer(
            "⚠️ <b>Лимит исчерпан.</b>\n\n🔥 Купить доступ или обратись к админу.",
            parse_mode="HTML",
            reply_markup=get_settings_keyboard(message.from_user.id)
        )
        await state.clear()
        return

    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу в базах...\n⏳ 3-5 секунд.", parse_mode="HTML")

    # 1) Локальные базы
    local_rows = await asyncio.to_thread(search_local_base_smart, query, 20)
    local_text = format_local_results(query, local_rows, user_id=message.from_user.id)
    if isinstance(local_text, tuple):
        local_text = local_text[0]

    # 2) BigBase
    data = await asyncio.to_thread(bigbase_search, query)
    bb_text = format_bigbase_result(data, user_id=message.from_user.id)

    # 3) Объединяем
    parts = []
    if local_text:
        parts.append(local_text)
    if bb_text:
        parts.append(bb_text)

    if parts:
        text = "\n".join(parts)
    elif "error" in data:
        text = f"❌ <b>Ошибка:</b> {html.escape(str(data['error']))}"
    else:
        text = f"📭 <b>Ничего не найдено</b>\n\n🔍 Запрос: <code>{html.escape(query)}</code>"

    text = safe_truncate(text, 4000)

    log_search(message.from_user.id, message.from_user.username or "", query, "bigbase")
    add_xp(message.from_user.id, 15)

    await message.answer(
        text,
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_settings_keyboard(message.from_user.id)
    )
    await state.clear()


# ══════════ ПОДДЕРЖКА ══════════
@dp.message(F.text == "🆘 Поддержка")
async def support_start(message: types.Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_support)
    await message.answer(
        "🆘 <b>Поддержка</b>\n\n"
        "Опиши проблему, отзыв или предложение.\n"
        "Сообщение уйдёт администратору.\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )



@dp.message(BotStates.waiting_for_support)
async def support_process(message: types.Message, state: FSMContext):
    text = (message.text or "").strip()
    if not text:
        await message.answer("❌ Пустое сообщение.")
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO support_tickets (user_id, username, message, created_at) VALUES (?,?,?,?)",
        (message.from_user.id, message.from_user.username or "", text,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    tid = cursor.lastrowid
    conn.commit()
    conn.close()
    try:
        await bot.send_message(
            ADMIN_ID,
            f"🆘 <b>Новое обращение #{tid}</b>\n\n"
            f"👤 От: <a href='tg://user?id={message.from_user.id}'>{html.escape(message.from_user.first_name or '—')}</a>\n"
            f"🆔 ID: <code>{message.from_user.id}</code>\n"
            f"📛 @{message.from_user.username or '—'}\n\n"
            f"💬 <b>Сообщение:</b>\n{html.escape(text)}\n\n"
            f"↩️ Ответ: <code>/reply {message.from_user.id} текст</code>",
            parse_mode="HTML"
        )
    except Exception as e:
        logging.warning(f"support to admin error: {e}")
    await message.answer(
        f"✅ <b>Сообщение отправлено!</b>\n\n"
        f"🆔 Тикет: <code>#{tid}</code>\n"
        f"⏳ Скоро ответим.",
        parse_mode="HTML",
        reply_markup=get_settings_keyboard(message.from_user.id)
    )
    await state.clear()


@dp.message(Command("reply"))
async def admin_reply(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args or " " not in args:
        await message.answer("❌ Формат: <code>/reply user_id текст</code>", parse_mode="HTML")
        return
    parts = args.split(" ", 1)
    if not parts[0].isdigit():
        await message.answer("❌ user_id — число.")
        return
    uid = int(parts[0])
    text = parts[1]
    try:
        await bot.send_message(uid, f"📩 <b>Ответ поддержки:</b>\n\n{html.escape(text)}", parse_mode="HTML")
        await message.answer(f"✅ Ответ отправлен юзеру <code>{uid}</code>.", parse_mode="HTML")
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")


@dp.message(Command("tickets"))
async def admin_tickets(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, username, message, status, created_at FROM support_tickets ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        await message.answer("📭 Обращений нет.")
        return
    lines = ["🆘 <b>Последние 20 обращений:</b>\n"]
    for r in rows:
        tid, uid, uname, msg, status, created = r
        lines.append(
            f"<b>#{tid}</b> [{status}] — <code>{uid}</code> @{uname or '—'}\n"
            f"💬 {html.escape(str(msg)[:120].replace("<", "").replace(">", ""))}\n"
            f"📅 {created}\n"
            f"↩️ <code>/reply {uid} текст</code>\n"
        )
    await message.answer("\n".join(lines), parse_mode="HTML")


@dp.message(Command("setbase"))
async def admin_set_base(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args.isdigit():
        await message.answer("❌ Формат: <code>/setbase ID</code>", parse_mode="HTML")
        return
    uid = int(args)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET subscription_tier='Base' WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    await message.answer(f"✅ Юзеру <code>{uid}</code> выдан <b>Base</b>.", parse_mode="HTML")


@dp.message(Command("setpremium"))
async def admin_set_premium(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args.isdigit():
        await message.answer("❌ Формат: <code>/setpremium ID</code>", parse_mode="HTML")
        return
    uid = int(args)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET subscription_tier='Premium' WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    await message.answer(f"✅ Юзеру <code>{uid}</code> выдан <b>Premium</b>.", parse_mode="HTML")


@dp.message(Command("setvip"))
async def admin_set_vip(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args.isdigit():
        await message.answer("❌ Формат: <code>/setvip ID</code>", parse_mode="HTML")
        return
    uid = int(args)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET subscription_tier='VIP' WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    await message.answer(f"✅ Юзеру <code>{uid}</code> выдан <b>VIP</b>.", parse_mode="HTML")


@dp.message(Command("setfree"))
async def admin_set_free(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args.isdigit():
        await message.answer("❌ Формат: <code>/setfree ID</code>", parse_mode="HTML")
        return
    uid = int(args)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET subscription_tier='Free', vip_until=NULL WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    await message.answer(f"✅ Юзеру <code>{uid}</code> снята подписка (Free).", parse_mode="HTML")



@dp.message(Command("download_email"))
async def download_email_file(message: types.Message, command: CommandObject):
    # Проверка VIP
    sub = get_user_subscription(message.from_user.id)
    if sub == "Free" and message.from_user.id != ADMIN_ID:
        await message.answer(
            "🔒 <b>Только для VIP</b>\n\n"
            "Скачивание файла доступно по подписке VIP.\n\n"
            "🔥 Купить доступ",
            parse_mode="HTML"
        )
        return

    args = (command.args or "").strip().lower()
    if not args or "@" not in args:
        await message.answer(
            "❌ Формат: <code>/download_email test@mail.ru</code>",
            parse_mode="HTML"
        )
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer("⏳ Собираю данные...", parse_mode="HTML")

    bb_data = await asyncio.to_thread(email_bigbase, args)
    leak_data = await asyncio.to_thread(email_leakcheck, args)

    filepath = save_email_data_to_file(args, bb_data, leak_data)

    if not filepath:
        await message.answer("❌ Не удалось сохранить файл. Проверь права доступа.")
        return

    try:
        from aiogram.types import FSInputFile
        file = FSInputFile(filepath)
        await message.answer_document(
            file,
            caption=f"📥 <b>Полные данные</b>\n📩 Email: <code>{args}</code>",
            parse_mode="HTML"
        )
    except Exception as e:
        await message.answer(f"❌ Ошибка отправки: {e}")

@dp.message(Command("setcookies"))
async def admin_set_cookies(message: types.Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args:
        await message.answer(
            "🔑 <b>Обновление куки BigBase</b>\n\n"
            "Отправь строку куки из браузера.\n"
            "Или: <code>/setcookies user_challenge=...; session_token=...</code>",
            parse_mode="HTML"
        )
        return
    if "session_token" not in args:
        await message.answer("❌ В строке нет <code>session_token</code>.", parse_mode="HTML")
        return
    save_bigbase_cookies(args)
    test = await asyncio.to_thread(bigbase_search, "+79999999999")
    if test and test.get("success") == "ok":
        await message.answer(
            f"✅ <b>Куки обновлены и работают!</b>\n\n"
            f"📊 Тест: <b>{test.get('count_result', 0):,}</b> записей",
            parse_mode="HTML"
        )
    else:
        await message.answer(f"⚠️ Сохранены, но не работают: <code>{str(test)[:200]}</code>",
                             parse_mode="HTML")

# ══════════ ВЫДАЧА ЛИМИТОВ ПО ТИПУ ══════════
@dp.message(F.text == "🎟 Выдать лимит")
async def admin_quota_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("🎟 <b>Выдача лимита</b>\n\nВведи <b>ID юзера</b>:", parse_mode="HTML")
    await state.set_state(AdminStates.waiting_for_quota_user)


@dp.message(AdminStates.waiting_for_quota_user)
async def admin_quota_user(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ ID должен быть числом.")
        return
    uid = int(message.text.strip())
    await state.update_data(quota_uid=uid)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👤 ФИО", callback_data="qtype_fio"),
         InlineKeyboardButton(text="📱 Телефон", callback_data="qtype_phone")],
        [InlineKeyboardButton(text="🌍 IP", callback_data="qtype_ip"),
         InlineKeyboardButton(text="📧 Email", callback_data="qtype_email")],
        [InlineKeyboardButton(text="🆔 VK", callback_data="qtype_vk"),
         InlineKeyboardButton(text="🔎 Username", callback_data="qtype_username")],
        [InlineKeyboardButton(text="🔓 BigBase", callback_data="qtype_bigbase")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="qtype_cancel")],
    ])
    await message.answer(f"👤 Юзер: <code>{uid}</code>\n\n🎯 <b>Выбери тип:</b>",
                         parse_mode="HTML", reply_markup=kb)
    await state.set_state(AdminStates.waiting_for_quota_type)


@dp.callback_query(F.data.startswith("qtype_"))
async def admin_quota_type(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        return
    qtype = callback.data.replace("qtype_", "")
    if qtype == "cancel":
        await state.clear()
        await callback.message.edit_text("❌ Отменено.")
        await callback.answer()
        return
    await state.update_data(quota_type=qtype)
    await callback.message.edit_text(
        f"🎯 Тип: <b>{QUOTA_TYPES.get(qtype, qtype)}</b>\n\n🔢 Введи <b>количество</b>:",
        parse_mode="HTML")
    await state.set_state(AdminStates.waiting_for_quota_amount)
    await callback.answer()


@dp.message(AdminStates.waiting_for_quota_amount)
async def admin_quota_amount(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ Введи число.")
        return
    amount = int(message.text.strip())
    data = await state.get_data()
    uid = data.get("quota_uid")
    qtype = data.get("quota_type")
    add_quota(uid, qtype, amount)
    left = get_quota(uid, qtype)
    await message.answer(
        f"✅ <b>Лимит выдан!</b>\n\n"
        f"👤 Юзер: <code>{uid}</code>\n"
        f"🎯 Тип: <b>{QUOTA_TYPES.get(qtype, qtype)}</b>\n"
        f"➕ Добавлено: <b>{amount}</b>\n"
        f"📊 Остаток: <b>{left}</b>",
        parse_mode="HTML",
        reply_markup=get_admin_settings_keyboard())
    await state.clear()


@dp.message(F.text == "📋 Квоты юзера")
async def admin_quota_view_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("📋 Введи <b>ID юзера</b>:")
    await state.set_state(AdminStates.waiting_for_quota_view)


@dp.message(AdminStates.waiting_for_quota_view)
async def admin_quota_view(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    if not (message.text or "").strip().isdigit():
        await message.answer("❌ ID должен быть числом.")
        return
    uid = int(message.text.strip())
    quotas = get_all_quotas(uid)
    extra = get_extra_queries(uid)
    sub = get_user_subscription(uid)
    lines = [
        f"📋 <b>Квоты юзера</b> <code>{uid}</code>\n",
        f"⭐ Тариф: <b>{sub}</b>",
        f"🎟 Общих доп. запросов: <b>{extra}</b>\n",
    ]
    for k, name in QUOTA_TYPES.items():
        lines.append(f"├ {name}: <b>{quotas.get(k, 0)}</b>")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_admin_settings_keyboard())
    await state.clear()

@dp.message(F.text.contains("session_token="))
async def auto_set_cookies(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    save_bigbase_cookies(message.text)
    test = await asyncio.to_thread(bigbase_search, "+79999999999")
    if test and test.get("success") == "ok":
        await message.answer(
            f"✅ <b>Куки обновлены!</b>\n📊 Тест: <b>{test.get('count_result', 0):,}</b> записей",
            parse_mode="HTML"
        )
    else:
        await message.answer(f"⚠️ Не работают: <code>{str(test)[:150]}</code>", parse_mode="HTML")

# ══════════ ЗАГРУЗКА БАЗ ══════════

@dp.message(BotStates.waiting_for_base_file, F.document)
async def upload_base_file(message: types.Message, state: FSMContext):
    doc = message.document
    if not doc:
        await message.answer("❌ Это не файл.")
        return

    fname = doc.file_name or "base.txt"
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""
    if ext not in ("txt", "csv"):
        await message.answer(
            "❌ Поддерживаются только <code>.txt</code> и <code>.csv</code>",
            parse_mode="HTML"
        )
        return

    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await message.answer("❌ Файл больше 20 МБ. Раздели на части.")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer("⏳ Скачиваю и обрабатываю...", parse_mode="HTML")

    tmp_path = os.path.join(os.path.join(TEMP_DIR, "", f"upload_{message.from_user.id}_{int(time.time())}_{fname}"))
    try:
        await bot.download(doc, destination=tmp_path)
    except Exception as e:
        await message.answer(f"❌ Ошибка скачивания: {e}")
        await state.clear()
        return

    rows = count_rows_in_file(tmp_path)
    upload_id = save_upload_to_db(
        message.from_user.id,
        message.from_user.username or "",
        fname,
        doc.file_id,
        rows
    )

    try:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Одобрить", callback_data=f"upl_ok_{upload_id}"),
             InlineKeyboardButton(text="❌ Отклонить", callback_data=f"upl_no_{upload_id}")]
        ])
        await bot.send_document(
            ADMIN_ID,
            doc.file_id,
            caption=(
                f"📤 <b>Новая база на проверку #{upload_id}</b>\n\n"
                f"👤 От: <a href='tg://user?id={message.from_user.id}'>"
                f"{html.escape(message.from_user.first_name or '—')}</a>\n"
                f"🆔 <code>{message.from_user.id}</code>\n"
                f"📛 @{message.from_user.username or '—'}\n"
                f"📁 Файл: <code>{html.escape(fname)}</code>\n"
                f"📊 Строк: <b>{rows:,}</b>"
            ),
            parse_mode="HTML",
            reply_markup=kb
        )
    except Exception as e:
        logging.warning(f"upload notify admin error: {e}")

    await message.answer(
        f"✅ <b>Файл отправлен на проверку!</b>\n\n"
        f"📁 <code>{html.escape(fname)}</code>\n"
        f"📊 Строк: <b>{rows:,}</b>\n"
        f"🆔 Заявка: <b>#{upload_id}</b>\n\n"
        f"⏳ Жди одобрения админа.",
        parse_mode="HTML",
        reply_markup=get_main_keyboard(message.from_user.id)
    )
    await state.clear()




# [DELETED DUP] upload_approve


# [DELETED DUP] upload_reject

@dp.message(BotStates.waiting_for_base_file, F.document)
async def upload_base_file(message: types.Message, state: FSMContext):
    doc = message.document
    if not doc:
        await message.answer("❌ Это не файл.")
        return

    fname = doc.file_name or "base.txt"
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""
    if ext not in ("txt", "csv"):
        await message.answer(
            "❌ Поддерживаются только <code>.txt</code> и <code>.csv</code>",
            parse_mode="HTML"
        )
        return

    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await message.answer("❌ Файл больше 20 МБ. Раздели на части.")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer("⏳ Скачиваю и обрабатываю...", parse_mode="HTML")

    tmp_path = f"/tmp/upload_{message.from_user.id}_{int(time.time())}_{fname}"
    try:
        await bot.download(doc, destination=tmp_path)
    except Exception as e:
        await message.answer(f"❌ Ошибка скачивания: {e}")
        await state.clear()
        return

    rows = count_rows_in_file(tmp_path)
    upload_id = save_upload_to_db(
        message.from_user.id,
        message.from_user.username or "",
        fname,
        doc.file_id,
        rows
    )

    try:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Одобрить", callback_data=f"upl_ok_{upload_id}"),
             InlineKeyboardButton(text="❌ Отклонить", callback_data=f"upl_no_{upload_id}")]
        ])
        await bot.send_document(
            ADMIN_ID,
            doc.file_id,
            caption=(
                f"📤 <b>Новая база на проверку #{upload_id}</b>\n\n"
                f"👤 От: <a href='tg://user?id={message.from_user.id}'>"
                f"{html.escape(message.from_user.first_name or '—')}</a>\n"
                f"🆔 <code>{message.from_user.id}</code>\n"
                f"📛 @{message.from_user.username or '—'}\n"
                f"📁 Файл: <code>{html.escape(fname)}</code>\n"
                f"📊 Строк: <b>{rows:,}</b>"
            ),
            parse_mode="HTML",
            reply_markup=kb
        )
    except Exception as e:
        logging.warning(f"upload notify admin error: {e}")

    await message.answer(
        f"✅ <b>Файл отправлен на проверку!</b>\n\n"
        f"📁 <code>{html.escape(fname)}</code>\n"
        f"📊 Строк: <b>{rows:,}</b>\n"
        f"🆔 Заявка: <b>#{upload_id}</b>\n\n"
        f"⏳ Жди одобрения админа.",
        parse_mode="HTML",
        reply_markup=get_main_keyboard(message.from_user.id)
    )
    await state.clear()



@dp.callback_query(F.data.startswith("upl_ok_"))
async def upload_approve(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        return
    upload_id = int(callback.data.replace("upl_ok_", ""))
    row = get_upload(upload_id)
    if not row:
        await callback.answer("❌ Заявка не найдена", show_alert=True)
        return

    uid, uname, fname, file_id, rows = row[1], row[2], row[3], row[4], row[5]

    await callback.answer("⏳ Импортирую...")
    tmp_path = f"/tmp/import_{upload_id}_{fname}"
    try:
        file = await bot.get_file(file_id)
        await bot.download_file(file.file_path, tmp_path)
        inserted = import_to_bases_70m(tmp_path, fname.rsplit('.', 1)[-1] if '.' in fname else 'txt')
    except Exception as e:
        logging.warning(f"import error: {e}")
        inserted = 0

    approve_upload(upload_id, ADMIN_ID)

    try:
        await bot.send_message(
            uid,
            f"✅ <b>Твоя база одобрена!</b>\n\n"
            f"📁 <code>{html.escape(fname)}</code>\n"
            f"📊 Записей добавлено: <b>{inserted:,}</b>\n\n"
            f"Спасибо за вклад! 🤝",
            parse_mode="HTML"
        )
    except Exception:
        pass

    try:
        await callback.message.edit_caption(
            caption=(callback.message.caption or "") + f"\n\n✅ <b>ОДОБРЕНО</b>\n📊 Добавлено: {inserted:,}",
            parse_mode="HTML"
        )
    except Exception:
        pass


@dp.callback_query(F.data.startswith("upl_no_"))
async def upload_reject(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        return
    upload_id = int(callback.data.replace("upl_no_", ""))
    row = get_upload(upload_id)
    if not row:
        await callback.answer("❌ Заявка не найдена", show_alert=True)
        return

    uid, fname = row[1], row[3]
    reject_upload(upload_id, ADMIN_ID)

    try:
        await bot.send_message(
            uid,
            f"❌ <b>Твоя база отклонена.</b>\n\n"
            f"📁 <code>{html.escape(fname)}</code>\n\n"
            f"📌 Причины: неверный формат, дубли, мусор.\n"
            f"Проверь и загрузи снова.",
            parse_mode="HTML"
        )
    except Exception:
        pass

    try:
        await callback.message.edit_caption(
            caption=(callback.message.caption or "") + "\n\n❌ <b>ОТКЛОНЕНО</b>",
            parse_mode="HTML"
        )
    except Exception:
        pass


@dp.message(F.text == "📤 Заявки на базы")
async def admin_uploads_view(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    rows = get_pending_uploads(20)
    if not rows:
        await message.answer("📭 Заявок нет.", reply_markup=get_admin_settings_keyboard())
        return
    lines = ["📤 <b>Заявки на базы:</b>\n"]
    for r in rows:
        lines.append(
            f"<b>#{r[0]}</b> — <code>{r[1]}</code> @{r[2] or '—'}\n"
            f"├ 📁 {html.escape(r[3])}\n"
            f"├ 📊 {r[4]:,} строк\n"
            f"└ 📅 {r[5]}"
        )
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_admin_settings_keyboard())

@dp.message(F.text == "🔍 Поиск")
async def search_menu(message: types.Message, state: FSMContext):
    NL = chr(10)
    text = (
        "🔍 <b>Поиск</b>" + NL + NL +
        "💡 <b>Напиши в чат:</b>" + NL +
        "├ 📱 <code>79999939919</code>" + NL +
        "├ 👤 <code>Иванов Иван</code>" + NL +
        "├ 📧 <code>test@mail.ru</code>" + NL +
        "└ 🔗 <code>@durov</code>" + NL + NL +
        "⌨️ <b>Команды:</b>" + NL +
        "├ <code>/phone</code> — телефон" + NL +
        "├ <code>/email</code> — email" + NL +
        "├ <code>/fio</code> — ФИО" + NL +
        "├ <code>/vk</code> — VK" + NL +
        "├ <code>/ip</code> — IP" + NL +
        "├ <code>/u</code> — username" + NL +
        "└ <code>/closed</code> — закрытые базы"
    )
    await message.answer(text, parse_mode="HTML",
                         reply_markup=get_main_keyboard(message.from_user.id))

@dp.message(Command("vk"))
async def cmd_vk(message: types.Message, command: CommandObject):
    q = (command.args or "").strip().lstrip("@")
    if not q:
        await message.answer("❌ Формат: <code>/vk durov</code>", parse_mode="HTML")
        return
    ok, _ = check_and_update_limit(message.from_user.id, "vk")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    profile = vk_get_profile(q)
    if not profile:
        await message.answer(f"❌ VK <code>{html.escape(q)}</code> не найден.", parse_mode="HTML",
                             reply_markup=get_main_keyboard(message.from_user.id))
        return
    photo = profile.get("photo_max_orig") or profile.get("photo_200")
    caption = format_vk_card(profile)
    log_search(message.from_user.id, message.from_user.username or "", q, "vk")
    if photo:
        try:
            await message.answer_photo(photo, caption=caption, parse_mode="HTML",
                                       reply_markup=get_main_keyboard(message.from_user.id))
        except Exception:
            await message.answer(caption + f"\n\n🔗 <a href='{photo}'>Фото</a>",
                                 parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))
    else:
        await message.answer(caption, parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))


@dp.message(Command("ip"))
async def cmd_ip(message: types.Message, command: CommandObject):
    q = (command.args or "").strip()
    if not q:
        await message.answer("❌ Формат: <code>/ip 8.8.8.8</code>", parse_mode="HTML")
        return
    ok, _ = check_and_update_limit(message.from_user.id, "ip")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    data = _pget(f"http://ip-api.com/json/{q}?fields=status,country,countryCode,city,isp,query")
    if data.get("status") == "success":
        cc = data.get("countryCode", "")
        await message.answer(
            f"{ip_flag(cc)} <b>{data.get('country')}</b>\n"
            f"🏙 {data.get('city')}\n"
            f"🌐 {data.get('isp')}\n"
            f"🔢 <code>{data.get('query')}</code>\n"
            f"🏴 {ip_flag(cc)}",
            parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id)
        )
    else:
        await message.answer("❌ Не удалось определить.", reply_markup=get_main_keyboard(message.from_user.id))


@dp.message(Command("u"))
async def cmd_u(message: types.Message, command: CommandObject):
    q = (command.args or "").strip().lstrip("@")
    if not q:
        await message.answer("❌ Формат: <code>/u gigolo</code>", parse_mode="HTML")
        return
    ok, _ = check_and_update_limit(message.from_user.id, "username")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    results = await search_username(q)
    text = format_username_result(q, results)
    await message.answer(text[:4000], parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))


# ══════════ АВТОПОИСК ══════════


# ═══════════════════════════════════════════
# УНИВЕРСАЛЬНЫЙ /cancel + КНОПКА "❌ Отмена"
# ═══════════════════════════════════════════





# ═══════════════════════════════════════════
# УНИВЕРСАЛЬНЫЙ /cancel + КНОПКА "❌ Отмена"
# ═══════════════════════════════════════════

@dp.message(Command("cancel"))
async def universal_cancel_cmd(message: types.Message, state: FSMContext):
    """Команда /cancel — работает ВСЕГДА."""
    current_state = await state.get_state()

    if current_state is None:
        # Нечего отменять — но всё равно показываем меню
        await message.answer(
            "ℹ️ Нечего отменять.\n\n🏠 Главное меню:",
            reply_markup=get_main_keyboard(message.from_user.id)
        )
        return

    # Сбрасываем состояние
    await state.clear()

    await message.answer(
        "❌ <b>Отменено</b>\n\n🏠 Главное меню:",
        parse_mode="HTML",
        reply_markup=get_main_keyboard(message.from_user.id)
    )


@dp.message(F.text == "❌ Отмена")
async def universal_cancel_btn(message: types.Message, state: FSMContext):
    """Кнопка "❌ Отмена" — работает из ЛЮБОГО состояния."""
    current_state = await state.get_state()
    await state.clear()

    if current_state:
        await message.answer(
            "❌ <b>Отменено</b>\n\n🏠 Главное меню:",
            parse_mode="HTML",
            reply_markup=get_main_keyboard(message.from_user.id)
        )
    else:
        await message.answer(
            "🏠 Главное меню:",
            reply_markup=get_main_keyboard(message.from_user.id)
        )



async def _auto_phone(message, state, query):
    hidden, fake = _shadow_check(query, "phone", message.from_user.id, message.from_user.username or "")
    if hidden:
        await message.answer(fake, parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))
        return
    ok, _ = check_and_update_limit(message.from_user.id, "phone")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу...", parse_mode="HTML")
    lr = await asyncio.to_thread(search_local_base_smart, query, 20)
    lt = format_local_results(query, lr, user_id=message.from_user.id)
    if isinstance(lt, tuple): lt = lt[0]
    bt = ""
    try:
        bd = await asyncio.to_thread(bigbase_search, query)
        bt = format_bigbase_result(bd, user_id=message.from_user.id) or ""
    except Exception: pass
    parts = [x for x in (lt, bt) if x]
    text = "\n".join(parts) if parts else f"📭 Ничего не найдено: <code>{html.escape(query)}</code>"
    await message.answer(text[:4000], parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))


async def _auto_email(message, state, query):
    hidden, fake = _shadow_check(query, "email", message.from_user.id, message.from_user.username or "")
    if hidden:
        await message.answer(fake, parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))
        return
    ok, _ = check_and_update_limit(message.from_user.id, "email")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу...", parse_mode="HTML")
    bd = await asyncio.to_thread(email_bigbase, query)
    ld = await asyncio.to_thread(email_leakcheck, query)
    text = format_email_result(query, bd, ld, user_id=message.from_user.id)
    await message.answer(text[:4000], parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))

    if ld and isinstance(ld, dict) and ld.get("success") and ld.get("found", 0) > 0:
        try:
            fp = await asyncio.to_thread(save_leaks_to_file, query, ld)
            if fp and os.path.exists(fp):
                from aiogram.types import FSInputFile
                await message.answer_document(FSInputFile(fp),
                    caption=f"📥 <b>Все утечки</b>\n📧 {html.escape(query)}\n📊 {ld.get('found', 0)} утечек",
                    parse_mode="HTML")
        except Exception as e:
            logging.warning(f"leaks file: {e}")


async def _auto_tg(message, state, query):
    hidden, fake = _shadow_check(query, "tg", message.from_user.id, message.from_user.username or "")
    if hidden:
        await message.answer(fake, parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))
        return
    ok, _ = check_and_update_limit(message.from_user.id, "fio")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу...", parse_mode="HTML")
    lr = await asyncio.to_thread(search_local_base_smart, query, 30)
    text = format_local_results(query, lr, user_id=message.from_user.id)
    if isinstance(text, tuple): text = text[0]
    if not text: text = f"📭 Ничего не найдено: <code>{html.escape(query)}</code>"
    await message.answer(text[:4000], parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))


async def _auto_fio(message, state, query):
    hidden, fake = _shadow_check(query, "fio", message.from_user.id, message.from_user.username or "")
    if hidden:
        await message.answer(fake, parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))
        return
    ok, _ = check_and_update_limit(message.from_user.id, "fio")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>", parse_mode="HTML")
        return
    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 Ищу...", parse_mode="HTML")
    lr = await asyncio.to_thread(search_local_base_smart, query, 20)
    lt = format_local_results(query, lr, user_id=message.from_user.id)
    if isinstance(lt, tuple): lt = lt[0]
    bt = ""
    try:
        bd = await asyncio.to_thread(bigbase_search, query)
        bt = format_bigbase_result(bd, user_id=message.from_user.id) or ""
    except Exception: pass
    parts = [x for x in (lt, bt) if x]
    text = "\n".join(parts) if parts else f"📭 Ничего не найдено: <code>{html.escape(query)}</code>"
    await message.answer(text[:4000], parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))


# ══════════ ЗАПУСК ══════════


# ═══════════════════════════════════════════
# PDF-ПАРСЕР БЕЗ БИБЛИОТЕК
# ═══════════════════════════════════════════

def _pdf_decompress(data):
    """Распаковывает zlib-потоки в PDF."""
    import zlib
    results = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.DOTALL):
        stream = m.group(1)
        try:
            results.append(zlib.decompress(stream))
        except Exception:
            continue
    return results


def _pdf_extract_strings(data):
    """Извлекает текст из PDF."""
    strings = []
    streams = [data] + _pdf_decompress(data)

    for stream in streams:
        try:
            text = stream.decode("latin-1", errors="ignore")
        except Exception:
            continue

        for m in re.finditer(r"\[((?:\s*\([^)]*\)\s*)+)\]\s*TJ", text):
            parts = re.findall(r"\(([^)]*)\)", m.group(1))
            line = "".join(parts)
            if line.strip():
                strings.append(line)

        for m in re.finditer(r"\(([^)]*)\)\s*Tj", text):
            if m.group(1).strip():
                strings.append(m.group(1))

    return strings


def extract_pdf_text_native(filepath):
    """Извлекает текст из PDF без библиотек."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        logging.warning(f"PDF read error: {e}")
        return []

    if not data.startswith(b"%PDF"):
        return []

    raw = _pdf_extract_strings(data)
    text = " ".join(raw)

    try:
        text = text.encode("latin-1").decode("utf-8", errors="ignore")
    except Exception:
        pass

    lines = []
    for chunk in re.split(r"[\n\r]+", text):
        chunk = chunk.strip()
        if chunk and len(chunk) > 3:
            lines.append(chunk)

    if len(lines) == 1 and len(lines[0]) > 200:
        parts = re.split(r"(?<=[;.!?])\s+(?=[А-ЯA-Z])", lines[0])
        lines = [p.strip() for p in parts if p.strip() and len(p.strip()) > 3]

    return lines




# ═══════════════════════════════════════════
# ИМПОРТ В bases_70m.db
# ═══════════════════════════════════════════

def _detect_csv_delim(line):
    for d in [";", ",", "\t", "|"]:
        if d in line:
            return d
    return None


def import_to_bases_70m(filepath, ext):
    """Импортирует .txt/.csv/.pdf/.jpg/.png в bases_70m.db. С OCR."""
    BASES_70M = os.path.join(BASES_DIR, "bases_70m.db")

    if not os.path.exists(BASES_70M):
        logging.warning(f"bases_70m.db не найден")
        return 0

    # ─── Получаем строки ───
    if ext == "pdf":
        # Сначала пробуем прямой парсинг (текстовый PDF)
        lines = extract_pdf_text_native(filepath)
        if not lines:
            # Скан → OCR
            logging.info("PDF скан — OCR.Space")
            ocr_text = ocr_space_file(filepath)
            lines = [l.strip() for l in ocr_text.split("\n") if l.strip() and len(l.strip()) > 3] if ocr_text else []
    elif ext in ("jpg", "jpeg", "png", "webp", "bmp"):
        # Картинка → OCR
        logging.info(f"{ext} — OCR.Space")
        ocr_text = ocr_space_file(filepath)
        lines = [l.strip() for l in ocr_text.split("\n") if l.strip() and len(l.strip()) > 3] if ocr_text else []
    else:
        # TXT / CSV
        lines = []
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try:
                with open(filepath, "r", encoding=enc, errors="ignore") as f:
                    content = f.read()
                lines = [ln.strip() for ln in content.split("\n") if ln.strip()]
                break
            except Exception:
                continue

    if not lines:
        return 0

    # ─── Импорт в базу ───
    inserted = 0
    skipped = 0

    try:
        conn = sqlite3.connect(BASES_70M)
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='r'")
        if not cur.fetchone():
            cur.execute("""CREATE TABLE IF NOT EXISTS r (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT, phone TEXT, username TEXT,
                first_name TEXT, last_name TEXT
            )""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_id ON r(account_id)")
            print("📋 Таблица r создана")

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            low = line.lower()
            if low.startswith(("id", "account_id", "user_id", "phone",
                              "username", "first_name", "last_name",
                              "фио", "имя", "телефон")):
                skipped += 1
                continue

            account_id = ""
            phone = ""
            username = ""
            first_name = ""
            last_name = ""

            delim = _detect_csv_delim(line)
            if delim:
                parts = [p.strip() for p in line.split(delim) if p.strip()]
                if len(parts) >= 5:
                    account_id = parts[0]
                    phone = re.sub(r"\D", "", parts[1]) if parts[1] else ""
                    username = parts[2].lstrip("@")
                    first_name = parts[3]
                    last_name = parts[4]
                elif len(parts) == 4:
                    account_id = parts[0]
                    phone = re.sub(r"\D", "", parts[1]) if parts[1] else ""
                    username = parts[2].lstrip("@")
                    first_name = parts[3]
                elif len(parts) == 3:
                    account_id = parts[0]
                    phone = re.sub(r"\D", "", parts[1]) if parts[1] else ""
                    username = parts[2].lstrip("@")
                elif len(parts) == 2:
                    account_id = parts[0]
                    phone = re.sub(r"\D", "", parts[1]) if parts[1] else ""
                elif len(parts) == 1:
                    val = parts[0]
                    if val.isdigit():
                        account_id = val
                    elif "@" in val:
                        username = val.lstrip("@")
                    else:
                        first_name = val
            else:
                # Свободный текст / OCR
                ids = re.findall(r"\b(\d{5,12})\b", line)
                if ids:
                    account_id = ids[0]

                phones = re.findall(r"\b(7\d{10}|8\d{10}|\d{11,15})\b", line)
                if phones:
                    p = phones[0]
                    if p.startswith("8") and len(p) == 11:
                        p = "7" + p[1:]
                    phone = p

                unames = re.findall(r"@([a-zA-Z0-9_]{3,32})", line)
                if unames:
                    username = unames[0]

                fio_match = re.search(
                    r"([А-ЯІЇЄҐA-Z][а-яіїєґa-z']+\s+[А-ЯІЇЄҐA-Z][а-яіїєґa-z']+"
                    r"(?:\s+[А-ЯІЇЄҐA-Z][а-яіїєґa-z']+)?)",
                    line
                )
                if fio_match:
                    parts = fio_match.group(1).split()
                    if len(parts) >= 1:
                        last_name = parts[0]
                    if len(parts) >= 2:
                        first_name = parts[1]

            if not (account_id or phone or username or first_name or last_name):
                skipped += 1
                continue

            try:
                cur.execute(
                    "INSERT INTO r (account_id, phone, username, first_name, last_name) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (account_id, phone, username, first_name, last_name)
                )
                inserted += 1
            except Exception as e:
                logging.warning(f"INSERT error: {e}")
                skipped += 1

        conn.commit()
        conn.close()
        logging.info(f"import_to_bases_70m: +{inserted}, skipped={skipped}")
    except Exception as e:
        logging.warning(f"import_to_bases_70m error: {e}")
        return 0

    return inserted



def count_rows_any(filepath, ext):
    """Считает строки для любого формата, включая OCR."""
    if ext == "pdf":
        lines = extract_pdf_text_native(filepath)
        if not lines:
            ocr_text = ocr_space_file(filepath)
            return len([l for l in ocr_text.split("\n") if l.strip() and len(l.strip()) > 3]) if ocr_text else 0
        return len(lines)
    elif ext in ("jpg", "jpeg", "png", "webp", "bmp"):
        ocr_text = ocr_space_file(filepath)
        return len([l for l in ocr_text.split("\n") if l.strip() and len(l.strip()) > 3]) if ocr_text else 0
    else:
        try:
            for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
                try:
                    with open(filepath, "r", encoding=enc, errors="ignore") as f:
                        return sum(1 for _ in f)
                except Exception:
                    continue
            return 0
        except Exception:
            return 0



@dp.message(F.text == "📥 Записать базу")
async def admin_record_base_start(message: types.Message, state: FSMContext):
    """Только админ может записать базу."""
    if message.from_user.id != ADMIN_ID:
        return

    await state.set_state(BotStates.waiting_for_record_base)
    await message.answer(
        "📥 <b>ЗАПИСЬ БАЗЫ</b> (только админ)\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📤 Отправь файл:\n"
        "├ 📄 .txt — текстовый\n"
        "├ 📊 .csv — через <code>;</code>, <code>,</code>, таб\n"
        "├ 📕 .pdf — текстовый (не скан)\n\n"
        "🎯 <b>Куда:</b> bases_70m.db\n"
        "⚡ <b>Скорость:</b> напрямую, без проверки\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_record_base, F.document)
async def admin_record_base_file(message: types.Message, state: FSMContext):
    """Запись базы: .txt / .csv / .html / .pdf / .jpg / .7z / .zip / .rar."""
    if not is_trusted(message.from_user.id):
        await state.clear()
        return

    doc = message.document
    if not doc:
        await message.answer("❌ Это не файл")
        return

    fname = doc.file_name or "base.txt"
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""

    allowed = ("txt", "csv", "html", "htm", "pdf", "jpg", "jpeg", "png", "webp",
               "7z", "rar", "xlsx", "xls", "db", "sqlite", "sqlite3")

    if ext not in allowed:
        await message.answer(
            "❌ Поддерживаются:\n"
            "├ 📄 .txt / .csv\n"
            "├ 🌐 .html (автоконвертация в CSV)\n"
            "├ 📕 .pdf\n"
            "├ 🖼 .jpg / .png\n"
            "└ 📦 .7z / .zip / .rar",
            parse_mode="HTML"
        )
        return

    if doc.file_size and doc.file_size > 100 * 1024 * 1024:
        await message.answer("❌ Файл > 100 МБ")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer(f"⏳ Скачиваю <code>{html.escape(fname)}</code>...",
                         parse_mode="HTML")

    tmp_path = os.path.join(TEMP_DIR, f"rec_{int(time.time())}_{fname}")
    try:
        await bot.download(doc, destination=tmp_path)
    except Exception as e:
        await message.answer(f"❌ Скачивание: {e}")
        await state.clear()
        return

    # ═══ ZIP / 7z / RAR — с защитой и предпросмотром ═══
    if ext in ("7z", "rar", "xlsx", "xls"):
        if ext != "zip":
            await message.answer("❌ Только .zip поддерживается", parse_mode="HTML")
            await state.clear()
            return

        await message.answer("🛡 <b>Сканирую архив...</b>", parse_mode="HTML")

        # ═══ 1. Проверка безопасности ═══
        scan = await asyncio.to_thread(scan_zip_safe, tmp_path)

        if scan.get("error"):
            await message.answer(
                "❌ <b>Ошибка архива:</b>" + chr(10) + chr(10) +
                html.escape(str(scan["error"])),
                parse_mode="HTML"
            )
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            await state.clear()
            return

        # ═══ 2. Информация об архиве ═══
        info = await asyncio.to_thread(get_zip_info, tmp_path)
        info_lines = []
        if "error" not in info:
            info_lines.append("📦 <b>Файлов:</b> " + str(info["files"]))
            info_lines.append("📊 <b>Размер:</b> " + f"{info['total_size']/1024/1024:.1f} МБ")
            info_lines.append("🗜 <b>Сжато:</b> " + f"{info['compressed']/1024/1024:.1f} МБ")
            if info.get("ratio"):
                info_lines.append("📉 <b>Сжатие:</b> " + f"{info['ratio']:.1f}x")

        # ═══ 3. Отчёт безопасности ═══
        sec_lines = []
        if scan["safe"]:
            sec_lines.append("✅ <b>Архив БЕЗОПАСЕН</b>")
        else:
            sec_lines.append("⚠️ <b>ОБНАРУЖЕНЫ УГРОЗЫ!</b>")

        if scan.get("zip_bomb"):
            sec_lines.append("💣 <b>ZIP-БОМБА!</b> Распаковка запрещена")

        if scan["dangerous"]:
            sec_lines.append("")
            sec_lines.append("🚫 <b>Опасные файлы:</b>")
            for d in scan["dangerous"][:10]:
                sec_lines.append("  ❌ " + html.escape(str(d.get("file", "?"))) + " — " + html.escape(str(d.get("reason", "?"))))

        if scan["suspicious"]:
            sec_lines.append("")
            sec_lines.append("⚠️ <b>Подозрительные:</b>")
            for s in scan["suspicious"][:10]:
                sec_lines.append("  ⚠️ " + html.escape(str(s.get("file", "?"))) + " (." + html.escape(str(s.get("ext", "?"))) + ")")

        if scan["safe_files"]:
            sec_lines.append("")
            sec_lines.append("✅ <b>Безопасные файлы (" + str(len(scan["safe_files"])) + "):</b>")
            for sf in scan["safe_files"][:10]:
                sz_mb = sf.get("size", 0) / 1024 / 1024
                sec_lines.append("  📄 " + html.escape(str(sf.get("file", "?"))) + " (" + f"{sz_mb:.1f} МБ)")

        # ═══ 4. Отправляем отчёт ═══
        report = (
            "🛡 <b>ПРОВЕРКА АРХИВА</b>" + chr(10) + chr(10) +
            chr(10).join(info_lines) + chr(10) + chr(10) +
            chr(10).join(sec_lines)
        )

        # ═══ 5. Предпросмотр содержимого ═══
        if scan["safe"]:
            previews = await asyncio.to_thread(preview_zip, tmp_path, 3, 10)
            if previews:
                report += chr(10) + chr(10) + "📋 <b>ПРЕДПРОСМОТР:</b>"
                for p in previews:
                    if "error" in p:
                        continue
                    report += chr(10) + chr(10) + "📄 <b>" + html.escape(str(p["file"])) + "</b>"
                    for ln in p.get("lines", [])[:5]:
                        report += chr(10) + "  <code>" + html.escape(str(ln)[:80]) + "</code>"

        # Отправляем отчёт
        try:
            if len(report) > 4000:
                for i in range(0, len(report), 4000):
                    await message.answer(report[i:i+4000], parse_mode="HTML")
            else:
                await message.answer(report, parse_mode="HTML")
        except Exception as e:
            logging.warning("preview error: " + str(e))

        # ═══ 6. Если НЕ безопасен — НЕ ИМПОРТИРУЕМ ═══
        if not scan["safe"]:
            await message.answer(
                "🚫 <b>Импорт ОТМЕНЁН</b>" + chr(10) + chr(10) +
                "Архив содержит опасные файлы." + chr(10) +
                "Свяжись с отправителем или пересобери архив.",
                parse_mode="HTML",
                reply_markup=get_admin_settings_keyboard()
            )
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            await state.clear()
            return

        # ═══ 7. Распаковка и импорт ═══
        await message.answer("✅ <b>Безопасен. Распаковываю...</b>", parse_mode="HTML")

        extract_dir = os.path.join(TEMP_DIR, "arch_" + str(int(time.time())))
        success, files, error = await asyncio.to_thread(
            extract_archive, tmp_path, extract_dir, None
        )

        if not success and error == "password_required":
            await state.update_data(archive_path=tmp_path, extract_dir=extract_dir)
            await state.set_state(BotStates.waiting_for_archive_password)
            await message.answer(
                "🔐 <b>Архив защищён паролем</b>" + chr(10) + chr(10) +
                "Отправь пароль в чат." + chr(10) + chr(10) + "❌ /cancel",
                parse_mode="HTML"
            )
            return

        if not success:
            await message.answer("❌ " + html.escape(str(error)), parse_mode="HTML")
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            await state.clear()
            return

        if not files:
            await message.answer("❌ Архив пустой")
            await state.clear()
            return

        await message.answer(
            "✅ Распаковано: <b>" + str(len(files)) + "</b> файлов" + chr(10) + "⏳ Импорт...",
            parse_mode="HTML"
        )

        # ═══ 8. Импорт ═══
        total = 0
        notes = []
        for i, f in enumerate(files, 1):
            f_ext = f.lower().rsplit(".", 1)[-1] if "." in f else ""
            try:
                if f_ext in ("db", "sqlite", "sqlite3"):
                    cnt, note = await asyncio.to_thread(import_zip_db, f)
                    total += cnt
                    if note: notes.append(note)
                elif f_ext in ("csv", "txt"):
                    cnt, note = await asyncio.to_thread(import_zip_csv, f, f_ext)
                    total += cnt if cnt else 0
                    if note: notes.append(note)
            except Exception as e:
                logging.warning("import err: " + str(e))
            if i % 10 == 0:
                try:
                    await message.answer("⏳ " + str(i) + "/" + str(len(files)) + "...")
                except Exception:
                    pass

        try:
            os.remove(tmp_path)
        except Exception:
            pass

        result_msg = (
            "✅ <b>Архив импортирован!</b>" + chr(10) + chr(10) +
            "📦 Файлов: <b>" + str(len(files)) + "</b>" + chr(10) +
            "➕ Обработано: <b>" + str(total) + "</b>"
        )
        if notes:
            result_msg += chr(10) + chr(10) + "📋 " + " | ".join(notes[:3])

        await message.answer(result_msg, parse_mode="HTML",
                             reply_markup=get_admin_settings_keyboard())
        await state.clear()
        return


    # ═══ XLSX / XLS ═══
    if ext in ("xlsx", "xls"):
        if not OPENPYXL_OK:
            await message.answer(
                "❌ <b>openpyxl не установлен</b>" + chr(10) + chr(10) +
                "Установи: <code>pip install openpyxl</code>",
                parse_mode="HTML"
            )
            await state.clear()
            return

        await message.answer("📊 <b>Читаю Excel...</b>", parse_mode="HTML")

        try:
            inserted = await asyncio.to_thread(import_xlsx_to_70m, tmp_path)
        except Exception as e:
            await message.answer(
                "❌ <b>Ошибка:</b> " + html.escape(str(e)[:300]),
                parse_mode="HTML"
            )
            await state.clear()
            return

        try:
            os.remove(tmp_path)
        except Exception:
            pass

        await message.answer(
            "✅ <b>Excel импортирован!</b>" + chr(10) + chr(10) +
            "📁 " + html.escape(fname) + chr(10) +
            "➕ Записей: <b>" + str(inserted) + "</b>",
            parse_mode="HTML",
            reply_markup=get_admin_settings_keyboard()
        )
        await state.clear()
        return

    # ═══ ОБЫЧНЫЕ ФАЙЛЫ ═══
    await message.answer("🔄 Обрабатываю...", parse_mode="HTML")

    inserted, err = await asyncio.to_thread(import_file_smart, tmp_path, ext)

    # Определяем что было
    note = ""
    if ext in ("html", "htm"):
        note = " (HTML → CSV)"

    try:
        os.remove(tmp_path)
    except Exception:
        pass

    if err:
        await message.answer(
            f"❌ <b>Ошибка:</b>\n<code>{html.escape(err)}</code>",
            parse_mode="HTML",
            reply_markup=get_admin_settings_keyboard()
        )
    else:
        await message.answer(
            f"✅ <b>База записана!</b>{note}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📁 <code>{html.escape(fname)}</code>\n"
            f"➕ Добавлено: <b>{inserted:,}</b>\n\n"
            f"🎯 База: <code>bases_70m.db</code>",
            parse_mode="HTML",
            reply_markup=get_admin_settings_keyboard()
        )

    await state.clear()


def ocr_space_file(filepath, language="rus"):
    """
    Отправляет файл (PDF/JPG/PNG) в OCR.Space.
    Возвращает распознанный текст.
    """
    import urllib.request
    import mimetypes
    import uuid

    if not os.path.exists(filepath):
        logging.warning(f"OCR: файл не найден {filepath}")
        return ""

    api_key = OCR_SPACE_KEY
    if not api_key:
        logging.warning("OCR: ключ не задан")
        return ""

    # Multipart form data
    boundary = uuid.uuid4().hex
    mime = mimetypes.guess_type(filepath)[0] or "application/octet-stream"

    with open(filepath, "rb") as f:
        file_data = f.read()

    # Собираем multipart
    parts = []

    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"apikey\"\r\n\r\n{api_key}".encode())
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\n{language}".encode())
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"isTable\"\r\n\r\ntrue".encode())
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"OCREngine\"\r\n\r\n3".encode())
    parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{os.path.basename(filepath)}\"\r\n"
        f"Content-Type: {mime}\r\n\r\n".encode()
    )
    parts.append(file_data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())

    body = b"".join(parts)

    req = urllib.request.Request(
        "https://api.ocr.space/parse/image",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )

    try:
        t = time.time()
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read().decode("utf-8", errors="ignore"))
        dt = time.time() - t

        if resp.get("IsErroredOnProcessing"):
            err = resp.get("ErrorMessage")
            logging.warning(f"OCR error: {err}")
            return ""

        results = resp.get("ParsedResults", [])
        text = "\n".join(r.get("ParsedText", "") for r in results)
        logging.info(f"OCR: {len(text)} символов за {dt:.1f} сек")
        return text

    except Exception as e:
        logging.warning(f"OCR ошибка: {e}")
        return ""


def extract_text_from_image(filepath):
    """Извлекает текст из картинки через OCR."""
    text = ocr_space_file(filepath, language="rus")
    if not text:
        return []

    lines = []
    for chunk in text.split("\n"):
        chunk = chunk.strip()
        if chunk and len(chunk) > 3:
            lines.append(chunk)
    return lines


def extract_text_from_scan_pdf(filepath):
    """OCR для скана PDF (через OCR.Space)."""
    # OCR.Space сам принимает PDF
    return extract_text_from_image(filepath)





def import_lines_to_based(lines):
    """Импортирует готовые строки в BASES_DB_PATH."""
    if not lines:
        return 0

    inserted = 0
    try:
        conn = sqlite3.connect(BASES_DB_PATH)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS r (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fio TEXT, phone TEXT, city TEXT, email TEXT, addr TEXT, extra TEXT
        )""")

        for line in lines:
            low = line.lower()
            if low.startswith(("имя", "фио", "name", "телефон", "phone", "user_id")):
                continue

            fio_match = re.search(
                r"([А-ЯІЇЄҐA-Z][а-яіїєґa-z']+\s+[А-ЯІЇЄҐA-Z][а-яіїєґa-z']+(?:\s+[А-ЯІЇЄҐA-Z][а-яіїєґa-z']+)?)",
                line
            )
            fio = fio_match.group(1) if fio_match else ""

            phones = re.findall(r"(?:\+?\d[\d\s\-()]{8,}\d)", line)
            phone_str = ""
            if phones:
                p = re.sub(r"\D", "", phones[0])
                if len(p) >= 10:
                    phone_str = p

            ids = re.findall(r"\b(\d{5,12})\b", line)
            extra = f"ID: {ids[0]}" if ids else ""

            if fio or phone_str or extra:
                cur.execute(
                    "INSERT INTO r (fio, phone, city, email, addr, extra) VALUES (?,?,?,?,?,?)",
                    (fio, phone_str, "", "", "", extra[:200])
                )
                inserted += 1

        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"import_lines_to_based error: {e}")

    return inserted





# ═══════════════════════════════════════════
# УМНЫЕ ПРОМОКОДЫ
# ═══════════════════════════════════════════
# Типы промокодов:
# - VIP: даёт VIP на N дней
# - PREMIUM: даёт Premium на N дней
# - BASE: даёт Base на N дней
# - QUERIES: +N запросов
# - XP: +N опыта
# - ACHIEVEMENT: открывает достижение
# ═══════════════════════════════════════════

PROMO_TYPES = {
    "vip":        "👑 VIP",
    "premium":    "💎 Premium",
    "base":       "🔷 Base",
    "queries":    "🎟 Запросы",
    "xp":         "⭐ Опыт",
    "achievement": "🏆 Достижение",
}


def redeem_smart_promo(user_id, code):
    """
    Активирует умный промокод.
    Возвращает (success, message).
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Уже активирован?
    cursor.execute("SELECT 1 FROM promo_activations WHERE user_id=? AND code=?", (user_id, code))
    if cursor.fetchone():
        conn.close()
        return (False, "❌ Ты уже активировал этот промокод")

    # Ищем промокод
    cursor.execute("SELECT type, max_uses, used_count FROM promocodes WHERE code=?", (code,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return (False, "❌ Промокод не найден")

    ptype, max_uses, used_count = row
    if used_count >= max_uses:
        conn.close()
        return (False, "❌ Лимит использований исчерпан")

    # Помечаем активированным
    cursor.execute("UPDATE promocodes SET used_count = used_count + 1 WHERE code=?", (code,))
    cursor.execute(
        "INSERT INTO promo_activations (user_id, code, activated_at) VALUES (?,?,?)",
        (user_id, code, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

    # ─── Применяем ───
    # Формат type: "VIP:30", "PREMIUM:7", "QUERIES:50", "XP:100", "ACHIEVEMENT:phone_hunter"
    parts = ptype.split(":", 1)
    base_type = parts[0].lower()
    value = parts[1] if len(parts) > 1 else ""

    msg_parts = []

    if base_type == "vip":
        days = int(value) if value.isdigit() else 30
        until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET subscription_tier='VIP', vip_until=? WHERE user_id=?", (until, user_id))
        conn.commit()
        conn.close()
        msg_parts.append(f"👑 VIP на {days} дней")

    elif base_type == "premium":
        days = int(value) if value.isdigit() else 7
        until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET subscription_tier='Premium', vip_until=? WHERE user_id=?", (until, user_id))
        conn.commit()
        conn.close()
        msg_parts.append(f"💎 Premium на {days} дней")

    elif base_type == "base":
        days = int(value) if value.isdigit() else 30
        until = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET subscription_tier='Base', vip_until=? WHERE user_id=?", (until, user_id))
        conn.commit()
        conn.close()
        msg_parts.append(f"🔷 Base на {days} дней")

    elif base_type == "queries":
        amount = int(value) if value.isdigit() else 10
        add_extra_queries(user_id, amount)
        msg_parts.append(f"🎟 +{amount} запросов")

    elif base_type == "xp":
        amount = int(value) if value.isdigit() else 100
        add_xp_advanced(user_id, amount)
        msg_parts.append(f"⭐ +{amount} XP")

    elif base_type == "achievement":
        code_ach = value
        if code_ach and code_ach in ACHIEVEMENTS:
            if unlock_achievement(user_id, code_ach):
                msg_parts.append(f"🏆 Достижение: {ACHIEVEMENTS[code_ach][1]}")

    if not msg_parts:
        return (True, "✅ Промокод активирован")

    return (True, "✅ <b>Промокод активирован!</b>\n\n🎁 " + "\n🎁 ".join(msg_parts))




def collect_dashboard():
    """Собирает данные для дашборда."""
    data = {}
    now = datetime.now()
    hour_ago = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    day_ago = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Юзеры
    data["users_total"] = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    data["users_vip"] = cursor.execute(
        "SELECT COUNT(*) FROM users WHERE subscription_tier='VIP'").fetchone()[0]
    data["users_premium"] = cursor.execute(
        "SELECT COUNT(*) FROM users WHERE subscription_tier='Premium'").fetchone()[0]
    data["users_base"] = cursor.execute(
        "SELECT COUNT(*) FROM users WHERE subscription_tier='Base'").fetchone()[0]
    data["users_free"] = cursor.execute(
        "SELECT COUNT(*) FROM users WHERE subscription_tier='Free'").fetchone()[0]
    data["users_new_24h"] = cursor.execute(
        "SELECT COUNT(*) FROM users WHERE last_request_date >= ?",
        (day_ago[:10],)).fetchone()[0]

    # Поиски
    data["searches_total"] = cursor.execute("SELECT COUNT(*) FROM search_logs").fetchone()[0]
    data["searches_24h"] = cursor.execute(
        "SELECT COUNT(*) FROM search_logs WHERE created_at >= ?", (day_ago,)).fetchone()[0]
    data["searches_1h"] = cursor.execute(
        "SELECT COUNT(*) FROM search_logs WHERE created_at >= ?", (hour_ago,)).fetchone()[0]

    # Топ типов за 24ч
    data["top_types"] = cursor.execute("""
        SELECT search_type, COUNT(*) as c FROM search_logs
        WHERE created_at >= ? GROUP BY search_type
        ORDER BY c DESC LIMIT 5
    """, (day_ago,)).fetchall()

    # Топ юзеров за 24ч
    data["top_users"] = cursor.execute("""
        SELECT user_id, username, COUNT(*) as c FROM search_logs
        WHERE created_at >= ? GROUP BY user_id
        ORDER BY c DESC LIMIT 5
    """, (day_ago,)).fetchall()

    # Последние 5 поисков
    data["last_searches"] = cursor.execute("""
        SELECT user_id, username, query, search_type, created_at
        FROM search_logs ORDER BY id DESC LIMIT 5
    """).fetchall()

    # Новые юзеры за 24ч (последние 5)
    try:
        data["new_users"] = cursor.execute("""
            SELECT user_id, username, message, created_at
            FROM admin_logs WHERE event_type='new_user' AND created_at >= ?
            ORDER BY id DESC LIMIT 5
        """, (day_ago,)).fetchall()
    except Exception:
        data["new_users"] = []

    conn.close()
    return data


def format_dashboard(data):
    """Форматирует дашборд."""
    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    L = []

    L.append(f"📊 <b>ДАШБОРД</b>")
    L.append(f"<i>{now}</i>")
    L.append("━━━━━━━━━━━━━━━━━━━━━")

    # Юзеры
    L.append("")
    L.append("👥 <b>ЮЗЕРЫ</b>")
    L.append(f"├ Всего: <b>{data['users_total']:,}</b>")
    L.append(f"├ 👑 VIP: <b>{data['users_vip']}</b>")
    L.append(f"├ 💎 Premium: <b>{data['users_premium']}</b>")
    L.append(f"├ 🔷 Base: <b>{data['users_base']}</b>")
    L.append(f"├ 🆓 Free: <b>{data['users_free']:,}</b>")
    L.append(f"└ 🆕 За 24ч: <b>{data['users_new_24h']}</b>")

    # Поиски
    L.append("")
    L.append("🔍 <b>ПОИСКИ</b>")
    L.append(f"├ Всего: <b>{data['searches_total']:,}</b>")
    L.append(f"├ За 24ч: <b>{data['searches_24h']:,}</b>")
    L.append(f"└ За час: <b>{data['searches_1h']:,}</b>")

    # Топ типов
    if data["top_types"]:
        L.append("")
        L.append("📊 <b>ТОП ТИПОВ (24ч)</b>")
        emoji_map = {
            "phone": "📱", "ip": "🌍", "vk": "🆔", "email": "📧",
            "username": "🔎", "bigbase": "🔓", "tg_search": "🔍",
            "fio": "👤", "name": "👤",
        }
        for i, (t, c) in enumerate(data["top_types"]):
            pre = "└" if i == len(data["top_types"]) - 1 else "├"
            e = emoji_map.get(t, "🔍")
            L.append(f"{pre} {e} {t or '—'}: <b>{c}</b>")

    # Топ юзеров
    if data["top_users"]:
        L.append("")
        L.append("🏆 <b>ТОП ЮЗЕРОВ (24ч)</b>")
        for i, (uid, uname, c) in enumerate(data["top_users"]):
            pre = "└" if i == len(data["top_users"]) - 1 else "├"
            name = f"@{uname}" if uname else f"id{uid}"
            L.append(f"{pre} {html.escape(name)}: <b>{c}</b>")

    # Последние поиски
    if data["last_searches"]:
        L.append("")
        L.append("🕐 <b>ПОСЛЕДНИЕ ПОИСКИ</b>")
        for i, (uid, uname, q, t, dt) in enumerate(data["last_searches"]):
            pre = "└" if i == len(data["last_searches"]) - 1 else "├"
            name = f"@{uname}" if uname else f"id{uid}"
            tm = dt[11:16] if len(dt) > 15 else dt
            L.append(f"{pre} {html.escape(name)} [{t}] · {tm}")
            L.append(f"│  <code>{html.escape(str(q)[:50].replace("<", "").replace(">", ""))}</code>")

    # Новые юзеры
    if data["new_users"]:
        L.append("")
        L.append(f"🆕 <b>НОВЫЕ ЗА 24Ч ({len(data['new_users'])})</b>")
        for i, (uid, uname, msg, dt) in enumerate(data["new_users"]):
            pre = "└" if i == len(data["new_users"]) - 1 else "├"
            name = f"@{uname}" if uname else f"id{uid}"
            tm = dt[11:16] if len(dt) > 15 else dt
            L.append(f"{pre} {html.escape(name)} · {tm}")

    return "\n".join(L)




@dp.message(F.text == "📊 Дашборд")
async def admin_dashboard(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    await bot.send_chat_action(message.chat.id, "typing")
    try:
        data = await asyncio.to_thread(collect_dashboard)
        text = format_dashboard(data)

        if len(text) > 4000:
            # Разбиваем
            for i in range(0, len(text), 4000):
                await message.answer(text[i:i+4000], parse_mode="HTML",
                                     reply_markup=get_admin_keyboard() if i + 4000 >= len(text) else None)
        else:
            await message.answer(text, parse_mode="HTML",
                                 reply_markup=get_admin_keyboard())
    except Exception as e:
        logging.warning(f"dashboard error: {e}")
        await message.answer(
            f"❌ Ошибка: <code>{html.escape(str(e)[:200].replace("<", "").replace(">", ""))}</code>",
            parse_mode="HTML",
            reply_markup=get_admin_keyboard()
        )




@dp.message(Command("download_sources"))
async def download_sources_cmd(message: types.Message, command: CommandObject):
    """Скачать источники по запросу (только VIP)."""
    # Проверка VIP
    sub = get_user_subscription(message.from_user.id)
    if sub != "VIP" and message.from_user.id != ADMIN_ID:
        await message.answer(
            "🔒 <b>Только для VIP</b>\n\n"
            "Скачивание источников — по подписке VIP.\n\n"
            "🔥 Купить доступ",
            parse_mode="HTML"
        )
        return

    query = (command.args or "").strip()
    if not query:
        await message.answer(
            "❌ Формат: <code>/download_sources 79962330074</code>",
            parse_mode="HTML"
        )
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer(f"⏳ Собираю источники по <code>{html.escape(query)}</code>...",
                         parse_mode="HTML")

    # Нормализуем
    bb_query = query
    digits = re.sub(r"\D", "", query)
    if digits and len(digits) >= 10:
        bb_query = digits
        if bb_query.startswith("8") and len(bb_query) == 11:
            bb_query = "7" + bb_query[1:]
        elif len(bb_query) == 10:
            bb_query = "7" + bb_query

    data = await asyncio.to_thread(bigbase_search, bb_query)

    if not data or data.get("success") != "ok":
        await message.answer("❌ Не удалось получить данные")
        return

    filepath = save_sources_to_file(query, data)

    if not filepath:
        await message.answer("❌ Не удалось сохранить файл")
        return

    try:
        from aiogram.types import FSInputFile
        file = FSInputFile(filepath)
        await message.answer_document(
            file,
            caption=f"📥 <b>Источники</b>\n📌 Запрос: <code>{html.escape(query)}</code>",
            parse_mode="HTML"
        )
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")




def extract_archive(filepath, extract_dir=None, password=None):
    """
    Универсальная распаковка: .7z, .zip, .rar
    Возвращает (success, files, error_msg)
    """
    if extract_dir is None:
        extract_dir = filepath + "_extracted"

    os.makedirs(extract_dir, exist_ok=True)

    ext = filepath.lower().rsplit(".", 1)[-1] if "." in filepath else ""

    try:
        if ext == "zip":
            logging.info(f"[ZIP admin] Открываю {filepath}")
            with zipfile.ZipFile(filepath, 'r') as archive:
                if password:
                    archive.setpassword(password.encode())
                archive.extractall(path=extract_dir)
            logging.info(f"[ZIP admin] Распаковано в {extract_dir}")
        else:
            return (False, [], f"формат .{ext} не поддерживается (только zip)")

        # Собираем файлы
        extracted = []
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                full_path = os.path.join(root, f)
                f_ext = f.lower().rsplit(".", 1)[-1] if "." in f else ""
                if f_ext in ("txt", "csv", "pdf", "jpg", "jpeg", "png", "webp", "bmp"):
                    extracted.append(full_path)

        return (True, extracted, None)

    except Exception as e:
        err = str(e).lower()
        # Пароль?
        if "password" in err or "пароль" in err or "encrypted" in err or "зашифрован" in err:
            return (False, [], "password_required")
        return (False, [], str(e)[:200])


def cleanup_dir(dir_path):
    try:
        import shutil
        shutil.rmtree(dir_path, ignore_errors=True)
    except Exception:
        pass




@dp.message(BotStates.waiting_for_archive_password)
async def archive_password_input(message: types.Message, state: FSMContext):
    """Получает пароль и распаковывает архив."""
    if message.from_user.id != ADMIN_ID:
        return

    password = (message.text or "").strip()

    if not password:
        await message.answer("❌ Пустой пароль. Попробуй снова.")
        return

    data = await state.get_data()
    archive_path = data.get("archive_path")
    archive_name = data.get("archive_name", "archive")

    if not archive_path or not os.path.exists(archive_path):
        await message.answer("❌ Архив потерян. Загрузи заново.")
        await state.clear()
        return

    await message.answer("🔓 Распаковываю с паролем...")

    extract_dir = os.path.join(TEMP_DIR, f"arch_{int(time.time())}")
    success, files, error = await asyncio.to_thread(
        extract_archive, archive_path, extract_dir, password
    )

    if not success:
        if error == "password_required":
            await message.answer("❌ Пароль не подошёл. Попробуй другой.")
            return
        await message.answer(f"❌ Ошибка: <code>{html.escape(str(error))}</code>",
                             parse_mode="HTML")
        await state.clear()
        return

    if not files:
        await message.answer("❌ Архив пустой или нет подходящих файлов.")
        await state.clear()
        return

    await message.answer(
        f"✅ Распаковано: <b>{len(files)}</b> файлов\n"
        f"⏳ Импортирую в базу...",
        parse_mode="HTML"
    )

    total_inserted = 0
    total_files = len(files)
    for i, f in enumerate(files, 1):
        f_ext = f.lower().rsplit(".", 1)[-1] if "." in f else ""
        try:
            ins = await asyncio.to_thread(import_to_bases_70m, f, f_ext)
            total_inserted += ins
        except Exception as e:
            logging.warning(f"import error {f}: {e}")

        if i % 10 == 0 or i == total_files:
            try:
                await message.answer(f"⏳ {i}/{total_files}...")
            except Exception:
                pass

    # Чистим
    try:
        os.remove(archive_path)
    except Exception:
        pass
    try:
        await asyncio.to_thread(cleanup_dir, extract_dir)
    except Exception:
        pass

    await message.answer(
        f"✅ <b>Готово!</b>\n\n"
        f"📦 Файлов: <b>{total_files}</b>\n"
        f"➕ Добавлено записей: <b>{total_inserted:,}</b>",
        parse_mode="HTML",
        reply_markup=get_admin_settings_keyboard()
    )
    await state.clear()




# ═══════════════════════════════════════════
# КАТЕГОРИИ АДМИНКИ
# ═══════════════════════════════════════════

@dp.message(F.text == "📊 Статистика")
async def admin_cat_stats(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "📊 <b>СТАТИСТИКА</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери раздел:",
        parse_mode="HTML",
        reply_markup=get_admin_stats_keyboard()
    )


@dp.message(F.text == "👥 Пользователи")
async def admin_cat_users(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "👥 <b>ПОЛЬЗОВАТЕЛИ</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери раздел:",
        parse_mode="HTML",
        reply_markup=get_admin_users_keyboard()
    )


@dp.message(F.text == "💰 Продажи")
async def admin_cat_sales(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "💰 <b>ПРОДАЖИ</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери раздел:",
        parse_mode="HTML",
        reply_markup=get_admin_sales_keyboard()
    )


@dp.message(F.text == "📁 Базы данных")
async def admin_cat_bases(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "📁 <b>БАЗЫ ДАННЫХ</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери раздел:",
        parse_mode="HTML",
        reply_markup=get_admin_bases_keyboard()
    )


@dp.message(F.text == "📢 Коммуникации")
async def admin_cat_comms(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "📢 <b>КОММУНИКАЦИИ</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери раздел:",
        parse_mode="HTML",
        reply_markup=get_admin_comms_keyboard()
    )


@dp.message(F.text == "⚙️ Настройки")
async def admin_cat_settings(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "⚙️ <b>НАСТРОЙКИ</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выбери раздел:",
        parse_mode="HTML",
        reply_markup=get_admin_settings_keyboard()
    )


# ═══════════════════════════════════════════
# ПРОДВИНУТЫЕ ПРОДАЖИ
# ═══════════════════════════════════════════

@dp.message(F.text == "📊 Продажи")
async def admin_sales_stats(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    day_ago = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

    try:
        total_purchases = cursor.execute("SELECT COUNT(*) FROM purchases").fetchone()[0]
        stars_total = cursor.execute("SELECT COALESCE(SUM(stars_paid),0) FROM purchases").fetchone()[0]
        purchases_24h = cursor.execute(
            "SELECT COUNT(*) FROM purchases WHERE created_at >= ?", (day_ago,)
        ).fetchone()[0]
    except Exception:
        total_purchases = 0
        stars_total = 0
        purchases_24h = 0

    # Юзеры по тарифам
    vip = cursor.execute("SELECT COUNT(*) FROM users WHERE subscription_tier='VIP'").fetchone()[0]
    prem = cursor.execute("SELECT COUNT(*) FROM users WHERE subscription_tier='Premium'").fetchone()[0]
    base = cursor.execute("SELECT COUNT(*) FROM users WHERE subscription_tier='Base'").fetchone()[0]

    conn.close()

    await message.answer(
        f"📊 <b>ПРОДАЖИ</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"

        f"💎 <b>Всего покупок:</b> {total_purchases:,}\n"
        f"⭐ <b>Звёзд получено:</b> {stars_total:,}\n"
        f"📈 <b>За 24ч:</b> {purchases_24h}\n\n"

        f"👥 <b>ТЕКУЩИЕ ПОДПИСЧИКИ:</b>\n"
        f"├ 👑 VIP: <b>{vip:,}</b>\n"
        f"├ 💎 Premium: <b>{prem:,}</b>\n"
        f"└ 🔷 Base: <b>{base:,}</b>",
        parse_mode="HTML",
        reply_markup=get_admin_sales_keyboard()
    )


@dp.message(F.text == "💎 Stars статистика")
async def admin_stars_stats(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT queries_added, COUNT(*), SUM(stars_paid)
            FROM purchases GROUP BY queries_added ORDER BY queries_added
        """)
        rows = cursor.fetchall()
    except Exception:
        rows = []

    conn.close()

    if not rows:
        await message.answer("📭 Покупок пока нет.", reply_markup=get_admin_sales_keyboard())
        return

    lines = ["💎 <b>STARS СТАТИСТИКА</b>\n━━━━━━━━━━━━━━━━━━━━━\n"]
    for queries, cnt, stars in rows:
        lines.append(f"├ <b>{queries} запросов</b>")
        lines.append(f"│  Куплено: {cnt} раз")
        lines.append(f"│  Stars: {stars}")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_admin_sales_keyboard())


@dp.message(F.text == "🛒 Все покупки")
async def admin_all_purchases(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT p.user_id, u.username, p.queries_added, p.stars_paid, p.created_at
            FROM purchases p LEFT JOIN users u ON u.user_id = p.user_id
            ORDER BY p.id DESC LIMIT 30
        """)
        rows = cursor.fetchall()
    except Exception:
        rows = []

    conn.close()

    if not rows:
        await message.answer("📭 Покупок нет.", reply_markup=get_admin_sales_keyboard())
        return

    lines = [f"🛒 <b>Последние покупки</b> ({len(rows)})\n"]
    for uid, uname, q, stars, dt in rows:
        name = f"@{uname}" if uname else f"id{uid}"
        lines.append(f"├ <b>{html.escape(name)}</b>")
        lines.append(f"│  +{q} запросов за {stars}⭐")
        lines.append(f"│  {dt[11:16]}")
    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_admin_sales_keyboard())


@dp.message(F.text == "📈 Воронка")
async def admin_funnel(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    total = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    paid = cursor.execute("SELECT COUNT(*) FROM users WHERE subscription_tier != 'Free'").fetchone()[0]
    vip = cursor.execute("SELECT COUNT(*) FROM users WHERE subscription_tier = 'VIP'").fetchone()[0]

    active_24h = cursor.execute("""
        SELECT COUNT(DISTINCT user_id) FROM search_logs
        WHERE created_at >= ?
    """, ((datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),)).fetchone()[0]

    conn.close()

    conv1 = (active_24h / total * 100) if total else 0
    conv2 = (paid / total * 100) if total else 0

    await message.answer(
        f"📈 <b>ВОРОНКА</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"

        f"1️⃣ <b>Всего юзеров:</b> {total:,}\n"
        f"   └ Активны 24ч: <b>{active_24h:,}</b> ({conv1:.1f}%)\n\n"

        f"2️⃣ <b>Платных:</b> {paid:,} ({conv2:.1f}%)\n"
        f"   ├ 👑 VIP: {vip:,}\n"
        f"   └ Остальные: {paid - vip:,}\n\n"

        f"💡 <b>Совет:</b> Конверсия {'высокая' if conv2 > 5 else 'низкая'}",
        parse_mode="HTML",
        reply_markup=get_admin_sales_keyboard()
    )


# ═══════════════════════════════════════════
# БАЗЫ ДАННЫХ
# ═══════════════════════════════════════════

@dp.message(F.text == "📊 Размер баз")
async def admin_bases_size(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    sizes = []

    paths = [
        ("bases_70m.db", os.path.join(BASES_DIR, "bases_70m.db")),
        ("bases.db", BASES_DB_PATH),
        ("bot_data.db", "bot_data.db"),
    ]

    total_mb = 0
    for name, path in paths:
        try:
            if os.path.exists(path):
                mb = os.path.getsize(path) / 1024 / 1024
                sizes.append((name, mb))
                total_mb += mb
        except Exception:
            pass

    lines = ["💾 <b>РАЗМЕР БАЗ</b>\n━━━━━━━━━━━━━━━━━━━━━\n"]
    for name, mb in sizes:
        lines.append(f"├ <b>{name}</b>: {mb:,.1f} МБ")
    lines.append(f"\n📊 <b>Всего:</b> {total_mb:,.1f} МБ")

    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_admin_bases_keyboard())


@dp.message(F.text == "📈 Статистика баз")
async def admin_bases_stats(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    await bot.send_chat_action(message.chat.id, "typing")

    lines = ["📈 <b>СТАТИСТИКА БАЗ</b>\n━━━━━━━━━━━━━━━━━━━━━\n"]

    # bases_70m
    try:
        conn = sqlite3.connect("file:/storage/emulated/0/Download/osint_bases/bases_70m.db?mode=ro", uri=True)
        cur = conn.cursor()
        n = cur.execute("SELECT COUNT(*) FROM r").fetchone()[0]
        conn.close()
        lines.append(f"📁 <b>bases_70m.db</b>: {n:,} записей")
    except Exception as e:
        lines.append(f"❌ bases_70m: {e}")

    # bases.db
    try:
        conn = sqlite3.connect("file:/storage/emulated/0/Download/bases.db?mode=ro", uri=True)
        cur = conn.cursor()
        n = cur.execute("SELECT COUNT(*) FROM r").fetchone()[0]
        conn.close()
        lines.append(f"📁 <b>bases.db</b>: {n:,} записей")
    except Exception as e:
        lines.append(f"❌ bases.db: {e}")

    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_admin_bases_keyboard())


# ═══════════════════════════════════════════
# СИСТЕМА
# ═══════════════════════════════════════════

@dp.message(F.text == "🔧 Система")
async def admin_system(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return

    import platform
    import sys

    await message.answer(
        f"🔧 <b>СИСТЕМА</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"

        f"🐍 Python: {sys.version.split()[0]}\n"
        f"💻 OS: {platform.system()} {platform.release()}\n"
        f"🕐 Время: {datetime.now().strftime('%H:%M:%S')}\n\n"

        f"✅ <b>Модули:</b>\n"
        f"├ zipfile: ✅\n"
        f"├ py7zr: {'✅' if SEVEN_ZIP_SUPPORT else '❌'}\n"
        f"├ rarfile: {'✅' if RAR_SUPPORT else '❌'}\n"
        f"└ sqlite3: ✅",
        parse_mode="HTML",
        reply_markup=get_admin_settings_keyboard()
    )


@dp.message(F.text == "📋 Всё меню")
async def admin_all_menu(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "📋 <b>ВСЕ РАЗДЕЛЫ</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📊 Статистика\n"
        "👥 Пользователи\n"
        "💰 Продажи\n"
        "📁 Базы данных\n"
        "📢 Коммуникации\n"
        "⚙️ Настройки",
        parse_mode="HTML",
        reply_markup=get_admin_keyboard()
    )





def collect_all_buttons():
    """Динамически собирает ВСЕ кнопки из клавиатур в БД."""
    buttons = set()

    # Из таблицы-справочника (заполняется при старте)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS bot_buttons (
            button_text TEXT PRIMARY KEY)""")
        cursor = conn.execute("SELECT button_text FROM bot_buttons")
        for row in cursor.fetchall():
            buttons.add(row[0])
        conn.close()
    except Exception:
        pass

    return buttons


def register_all_buttons():
    """Собирает ВСЕ кнопки — правильно определяет аргументы."""
    import inspect

    buttons = set()

    keyboard_names = [
        "get_main_keyboard",
        "get_settings_keyboard",
        "get_admin_keyboard",
        "get_admin_stats_keyboard",
        "get_admin_users_keyboard",
        "get_admin_sales_keyboard",
        "get_admin_bases_keyboard",
        "get_admin_comms_keyboard",
        "get_admin_settings_keyboard",
    ]

    logging.info(f"═══ register_all_buttons: {len(keyboard_names)} клавиатур ═══")

    for name in keyboard_names:
        kb_func = globals().get(name)
        if not kb_func:
            logging.warning(f"  ⚠️ {name} — нет")
            continue

        try:
            sig = inspect.signature(kb_func)
            params = list(sig.parameters.keys())
            kb = kb_func(ADMIN_ID) if params else kb_func()
        except Exception as e:
            logging.warning(f"  ❌ {name}: {e}")
            continue

        try:
            if not hasattr(kb, "keyboard"):
                continue
            count = 0
            for row in kb.keyboard:
                for btn in row:
                    if hasattr(btn, "text"):
                        text = btn.text
                        if text and not text.startswith("/"):
                            buttons.add(text)
                            count += 1
            logging.info(f"  ✅ {name}: {count}")
        except Exception as e:
            logging.warning(f"  ❌ {name}: {e}")

    # Сохраняем в БД
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS bot_buttons (
            button_text TEXT PRIMARY KEY)""")
        conn.execute("DELETE FROM bot_buttons")
        for b in buttons:
            try:
                conn.execute("INSERT OR IGNORE INTO bot_buttons (button_text) VALUES (?)", (b,))
            except Exception:
                pass
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"register save error: {e}")

    logging.info(f"═══ ИТОГО: {len(buttons)} кнопок ═══")
    return buttons


def is_registered_button(text):
    """Проверка: это кнопка?"""
    if not text:
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS bot_buttons (
            button_text TEXT PRIMARY KEY)""")
        row = conn.execute(
            "SELECT 1 FROM bot_buttons WHERE button_text = ?", (text,)
        ).fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False



def is_registered_button(text):
    """Проверяет: это кнопка? (для auto_search)"""
    if not text:
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS bot_buttons (
            button_text TEXT PRIMARY KEY)""")
        row = conn.execute(
            "SELECT 1 FROM bot_buttons WHERE button_text = ?",
            (text,)
        ).fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False





# ═══════════════════════════════════════════
# HUDSON ROCK — отдельная кнопка
# ═══════════════════════════════════════════

@dp.message(F.text == "🦠 Hudson Rock")
async def hudson_start(message: types.Message, state: FSMContext):
    """Запрос email для проверки."""
    await state.set_state(BotStates.waiting_for_hudson)
    await message.answer(
        "🦠 <b>HUDSON ROCK</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Проверяет заражённые устройства (инфостилеры).\n\n"
        "📧 Отправь <b>email</b> или <b>username</b>:\n"
        "├ test@mail.ru\n"
        "├ @durov\n"
        "└ user123\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_hudson)
async def hudson_process(message: types.Message, state: FSMContext):
    """Обработка Hudson Rock."""
    query = (message.text or "").strip().lower()

    if not query:
        await message.answer("❌ Введи email или username.")
        return

    # Проверка лимита
    ok, _ = check_and_update_limit(message.from_user.id, "email")
    if not ok:
        await message.answer(
            "⚠️ <b>Лимит исчерпан.</b>\n\n🔥 Купить доступ",
            parse_mode="HTML",
            reply_markup=get_main_keyboard(message.from_user.id)
        )
        await state.clear()
        return

    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer(f"🔍 Проверяю <code>{html.escape(query)}</code>...", parse_mode="HTML")

    # Запрос
    try:
        data = await asyncio.to_thread(email_hudsonrock, query)
    except Exception as e:
        await message.answer(f"❌ Ошибка: {html.escape(str(e)[:200].replace("<", "").replace(">", ""))}",
                             parse_mode="HTML")
        await state.clear()
        return

    # Проверка VIP
    is_vip = False
    sub = get_user_subscription(message.from_user.id)
    if sub == "VIP" or message.from_user.id == ADMIN_ID:
        is_vip = True

    # Форматируем
    text = format_hudson_result(query, data, is_vip)

    text = safe_truncate(text, 4000)

    log_search(message.from_user.id, message.from_user.username or "", query, "hudson")

    await message.answer(
        text,
        parse_mode="HTML",
        reply_markup=get_main_keyboard(message.from_user.id)
    )
    await state.clear()


def format_hudson_result(query, data, is_vip=False):
    """Форматирует результат Hudson Rock."""
    lines = [
        "🦠 <b>HUDSON ROCK</b>",
        "━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"🔍 <b>Запрос:</b> <code>{html.escape(query)}</code>",
    ]

    if not data or not isinstance(data, dict):
        lines.append("")
        lines.append("❌ Нет данных")
        return "\n".join(lines)

    if "error" in data:
        err = str(data.get("error", ""))
        if "404" in err:
            lines.append("")
            lines.append("✅ <b>Не найден в базе Hudson Rock</b>")
            lines.append("<i>Это хорошо — значит устройство не заражено</i>")
        else:
            lines.append("")
            lines.append(f"❌ Ошибка: <code>{html.escape(str(err)[:200].replace("<", "").replace(">", ""))}</code>")
        return "\n".join(lines)

    # Сообщение — есть данные
    msg = data.get("message", "")
    if msg:
        # Извлекаем количество
        stealers = data.get("stealers", [])
        total = data.get("total", len(stealers))

        lines.append("")
        lines.append("🔴 <b>ЗАРАЖЁННЫЕ УСТРОЙСТВА</b>")
        lines.append(f"📊 Найдено: <b>{total}</b>")
        lines.append("")

        if stealers:
            max_show = 10 if is_vip else 3
            for i, s in enumerate(stealers[:max_show], 1):
                lines.append(f"<b>━━━ Заражение #{i} ━━━</b>")

                # Пароль
                pwd = s.get("password", "")
                if pwd:
                    if is_vip:
                        lines.append(f"🔑 <b>Пароль:</b> <code>{html.escape(str(pwd))}</code>")
                    else:
                        lines.append(f"🔑 <b>Пароль:</b> 🔒")

                # Логин
                login = s.get("login", "")
                if login:
                    lines.append(f"👤 <b>Логин:</b> <code>{html.escape(str(login))}</code>")

                # Компьютер
                pc = s.get("computer_name", "")
                if pc:
                    lines.append(f"💻 <b>Компьютер:</b> {html.escape(str(pc))}")

                # ОС
                os_ = s.get("operating_system", "")
                if os_:
                    lines.append(f"🖥 <b>ОС:</b> {html.escape(str(os_))}")

                # Дата
                date = s.get("date_compromised", "")
                if date:
                    lines.append(f"📅 <b>Заражён:</b> {html.escape(str(date))}")

                # Malware
                malware = s.get("malware_path", "")
                if malware:
                    lines.append(f"🦠 <b>Malware:</b> <code>{html.escape(str(malware)[:100].replace("<", "").replace(">", ""))}</code>")

                # IP
                ip = s.get("ip", "")
                if ip and is_vip:
                    lines.append(f"🌍 <b>IP:</b> <code>{html.escape(str(ip))}</code>")

                # Антивирусы
                av = s.get("antiviruses", "")
                if av and is_vip:
                    lines.append(f"🛡 <b>Антивирус:</b> {html.escape(str(av)[:80].replace("<", "").replace(">", ""))}")

                lines.append("")

            if not is_vip and len(stealers) > 3:
                lines.append(f"🔒 <i>Показано 3 из {len(stealers)}</i>")
                lines.append("")
        else:
            lines.append("<i>Детали недоступны без ключа API</i>")
            lines.append("")
    else:
        lines.append("")
        lines.append("✅ <b>Не найден</b>")
        lines.append("<i>Устройство не заражено инфостилерами</i>")

    # Итог
    if not is_vip:
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
        lines.append("⭐ <b>VIP</b> — пароли, IP, все заражения")
        lines.append("🔥 Купить доступ")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
    else:
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
        lines.append("👑 <b>VIP — все данные открыты</b>")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")

    return "\n".join(lines)




# ═══════════════════════════════════════════
# MAIL.TM — создание, чтение, ОТПРАВКА
# ═══════════════════════════════════════════

def mailtm_create():
    """Создаёт email + пароль на mail.tm."""
    import random
    import string

    try:
        req = urllib.request.Request(
            "https://api.mail.tm/domains",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        domains = data.get("hydra:member", [])
        if not domains:
            logging.warning("mailtm: нет доменов")
            return None
        domain = domains[0].get("domain", "mail.tm")
    except Exception as e:
        logging.warning(f"mailtm domain error: {e}")
        return None

    login = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{login}@{domain}"
    password = "Pass" + "".join(random.choices(string.digits, k=10))

    # Создание
    try:
        payload = json.dumps({"address": email, "password": password}).encode()
        req = urllib.request.Request(
            "https://api.mail.tm/accounts",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        logging.info(f"mailtm: создан {email}")
    except Exception as e:
        logging.warning(f"mailtm create error: {e}")
        return None

    # Токен
    token = ""
    try:
        payload = json.dumps({"address": email, "password": password}).encode()
        req = urllib.request.Request(
            "https://api.mail.tm/token",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            token_data = json.loads(r.read().decode("utf-8", errors="ignore"))
        token = token_data.get("token", "")
    except Exception as e:
        logging.warning(f"mailtm token error: {e}")

    return {
        "email": email,
        "password": password,
        "login": login,
        "domain": domain,
        "token": token,
        "created": time.time(),
        "session_id": "".join(__import__("random").choices(__import__("string").ascii_lowercase + __import__("string").digits, k=24)),
    }


def mailtm_inbox(token):
    """Список писем."""
    if not token:
        return []
    try:
        req = urllib.request.Request(
            "https://api.mail.tm/messages",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "Mozilla/5.0"
            }
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        return data.get("hydra:member", [])
    except Exception as e:
        logging.warning(f"mailtm inbox error: {e}")
        return []


def mailtm_read(token, msg_id):
    """Читает письмо."""
    try:
        req = urllib.request.Request(
            f"https://api.mail.tm/messages/{msg_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "Mozilla/5.0"
            }
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        logging.warning(f"mailtm read error: {e}")
        return {}


def mailtm_send(token, from_email, to_email, subject, body):
    """
    Отправляет письмо через mail.tm.
    mail.tm НЕ имеет публичного API для отправки.
    Используем резервный способ — SMTP через внешний сервис (не работает на mail.tm).
    Поэтому — возвращаем ошибку с пояснением.
    """
    return (False, "mail.tm не поддерживает отправку через API. Используй веб-интерфейс.")




@dp.callback_query(F.data == "tm_check")
async def tm_check_inbox(callback: types.CallbackQuery, state: FSMContext):
    """Проверяет входящие TempMail."""
    data = await state.get_data()
    tm = data.get("tempmail")

    if not tm:
        await callback.answer("❌ Сначала создай почту", show_alert=True)
        return

    await callback.answer("📥 Проверяю...")

    msgs = await asyncio.to_thread(mailtm_inbox, tm.get("token", ""))

    if not msgs:
        await callback.message.answer(
            f"📭 <b>Входящие пусты</b>\n\n"
            f"📩 <code>{tm['email']}</code>\n"
            f"⏳ Ожидай письма",
            parse_mode="HTML"
        )
        return

    lines = [f"📬 <b>Входящие ({len(msgs)}):</b>\n"]

    for i, m in enumerate(msgs[:10], 1):
        m_from = m.get("from", {}).get("address", "—")
        m_subj = m.get("subject", "—")
        m_intro = m.get("intro", "")
        m_date = m.get("createdAt", "")[:16]
        m_id = m.get("id", "")

        lines.append(f"<b>{i}.</b> От: <code>{html.escape(str(m_from))}</code>")
        lines.append(f"📝 {html.escape(str(m_subj))}")
        lines.append(f"📅 {m_date}")

        if m_intro:
            lines.append(f"💬 {html.escape(str(m_intro)[:100].replace("<", "").replace(">", ""))}")

        lines.append(f"📖 <code>/tmread {m_id}</code>")
        lines.append("")

    await callback.message.answer("\n".join(lines), parse_mode="HTML")


@dp.message(Command("tmread"))
async def tm_read(message: types.Message, command: CommandObject, state: FSMContext):
    """Читает письмо по ID."""
    msg_id = (command.args or "").strip()
    if not msg_id:
        await message.answer("❌ /tmread ID")
        return

    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await message.answer("❌ Сначала создай почту")
        return

    await bot.send_chat_action(message.chat.id, "typing")
    full = await asyncio.to_thread(mailtm_read, tm.get("token", ""), msg_id)

    if not full:
        await message.answer("❌ Не удалось прочитать")
        return

    m_from = full.get("from", {}).get("address", "—")
    subj = full.get("subject", "—")
    date = full.get("createdAt", "")[:16]
    text = full.get("text", "") or full.get("intro", "")

    if not text:
        html_body = full.get("html", [])
        if html_body:
            text = re.sub(r"<[^>]+>", "", " ".join(html_body))

    msg_text = (
        f"📖 <b>Письмо</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👤 <b>От:</b> <code>{html.escape(str(m_from))}</code>\n"
        f"📝 <b>Тема:</b> {html.escape(str(subj))}\n"
        f"📅 <b>Дата:</b> {date}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"{html.escape(str(text)[:3500].replace("<", "").replace(">", ""))}"
    )

    msg_text = safe_truncate(msg_text, 4000)

    await message.answer(msg_text, parse_mode="HTML", disable_web_page_preview=True)




# ═══════════════════════════════════════════
# MAIL.TM — с параметрами
# ═══════════════════════════════════════════

def mailtm_get_domains():
    """Возвращает список доступных доменов."""
    try:
        req = urllib.request.Request(
            "https://api.mail.tm/domains",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        return [d.get("domain") for d in data.get("hydra:member", [])]
    except Exception:
        return ["mail.tm"]


def generate_strong_password(length=16):
    """Генерирует сложный пароль."""
    import random
    import string

    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choices(chars, k=length))


def mailtm_create_custom(login=None, domain=None, password=None):
    """
    Создаёт email с параметрами.
    Если login не указан — генерирует.
    Если password не указан — генерирует.
    """
    import random
    import string

    # Домены
    domains = mailtm_get_domains()
    if not domains:
        logging.warning("mailtm: нет доменов")
        return None

    if not domain or domain not in domains:
        domain = domains[0]

    # Логин
    if not login:
        login = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    else:
        # Чистим от недопустимых символов
        login = re.sub(r"[^a-zA-Z0-9._-]", "", login)[:30]

    if not password:
        password = "Pass" + "".join(random.choices(string.digits, k=10))

    email = f"{login}@{domain}"

    # Создаём аккаунт
    try:
        payload = json.dumps({"address": email, "password": password}).encode()
        req = urllib.request.Request(
            "https://api.mail.tm/accounts",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            acc = json.loads(r.read().decode("utf-8", errors="ignore"))
        logging.info(f"mailtm: создан {email}")
    except urllib.error.HTTPError as e:
        if e.code == 422:
            logging.warning(f"mailtm: логин {login} занят")
            return {"error": "login_taken"}
        logging.warning(f"mailtm create error: {e}")
        return None
    except Exception as e:
        logging.warning(f"mailtm create error: {e}")
        return None

    # Токен
    token = ""
    try:
        payload = json.dumps({"address": email, "password": password}).encode()
        req = urllib.request.Request(
            "https://api.mail.tm/token",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            token_data = json.loads(r.read().decode("utf-8", errors="ignore"))
        token = token_data.get("token", "")
    except Exception as e:
        logging.warning(f"mailtm token error: {e}")

    return {
        "email": email,
        "password": password,
        "login": login,
        "domain": domain,
        "token": token,
        "created": time.time(),
        "session_id": "".join(__import__("random").choices(__import__("string").ascii_lowercase + __import__("string").digits, k=24)),
    }





# ═══════════════════════════════════════════
# ОТПРАВКА ПИСЕМ
# ═══════════════════════════════════════════

@dp.message(Command("send"))
async def send_mail_cmd(message: types.Message, command: CommandObject, state: FSMContext):
    """Быстрая отправка: /send email | тема | текст"""
    args = (command.args or "").strip()
    if not args or "|" not in args:
        await message.answer(
            "❌ Формат:\n<code>/send email | тема | текст</code>",
            parse_mode="HTML"
        )
        return

    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await message.answer("❌ Сначала создай почту: 📧 TempMail")
        return

    parts = [p.strip() for p in args.split("|", 2)]
    if len(parts) < 3:
        await message.answer("❌ Нужно: email | тема | текст")
        return

    to_email, subject, body = parts[0], parts[1], parts[2]

    await message.answer(
        f"📤 <b>Отправка письма</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📧 От: <code>{tm['email']}</code>\n"
        f"📩 Кому: <code>{html.escape(to_email)}</code>\n"
        f"📝 Тема: {html.escape(subject)}\n\n"
        f"⚠️ mail.tm не поддерживает отправку через API.\n"
        f"Отправь вручную через:\n"
        f"🌐 <a href='https://mail.tm/ru/'>mail.tm</a>\n\n"
        f"📋 Данные для входа:\n"
        f"├ Email: <code>{tm['email']}</code>\n"
        f"└ Пароль: <code>{tm['password']}</code>",
        parse_mode="HTML",
        disable_web_page_preview=True
    )

    # Логируем попытку
    await asyncio.to_thread(
        log_anon_mail,
        tm.get("session_id", ""), "out", tm["email"], to_email, subject, body
    )





# ═══════════════════════════════════════════
# HTML → CSV (без pip)
# ═══════════════════════════════════════════

def html_to_csv(html_path, output_path, delimiter=";"):
    """
    Конвертирует HTML-таблицу в CSV.
    Возвращает (rows_count, error).
    """
    import csv

    try:
        # Читаем HTML
        content = ""
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try:
                with open(html_path, "r", encoding=enc, errors="ignore") as f:
                    content = f.read()
                break
            except Exception:
                continue

        if not content:
            return (0, "Не удалось прочитать файл")

        # Ищем ВСЕ таблицы
        tables = re.findall(
            r"<table[^>]*>(.*?)</table>",
            content,
            re.DOTALL | re.IGNORECASE
        )

        # Если таблиц нет — ищем все tr
        if not tables:
            tables = [content]

        all_rows = []

        for table in tables:
            # Ищем строки tr
            rows = re.findall(
                r"<tr[^>]*>(.*?)</tr>",
                table,
                re.DOTALL | re.IGNORECASE
            )

            for row in rows:
                # Ищем ячейки td / th
                cells = re.findall(
                    r"<t[dh][^>]*>(.*?)</t[dh]>",
                    row,
                    re.DOTALL | re.IGNORECASE
                )

                # Очищаем ячейки от HTML-тегов
                cleaned = []
                for cell in cells:
                    # Убираем все теги
                    cell = re.sub(r"<[^>]+>", "", cell)
                    # Декодируем HTML-сущности
                    import html as _html
                    cell = _html.unescape(cell)
                    # Убираем лишние пробелы
                    cell = " ".join(cell.split())
                    cleaned.append(cell)

                # Пропускаем пустые строки
                if any(cleaned):
                    all_rows.append(cleaned)

        if not all_rows:
            return (0, "В файле не найдено таблиц")

        # Определяем максимальное число колонок
        max_cols = max(len(r) for r in all_rows)
        # Выравниваем
        for row in all_rows:
            while len(row) < max_cols:
                row.append("")

        # Сохраняем CSV
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=delimiter)
            writer.writerows(all_rows)

        logging.info(f"html_to_csv: {len(all_rows)} строк → {output_path}")
        return (len(all_rows), None)

    except Exception as e:
        logging.warning(f"html_to_csv error: {e}")
        return (0, str(e)[:200])




@dp.message(F.text == "🔄 HTML → CSV")
async def html_csv_start(message: types.Message, state: FSMContext):
    """Начало конвертации."""
    if message.from_user.id != ADMIN_ID:
        return

    await state.set_state(BotStates.waiting_for_html_file)
    await message.answer(
        "🔄 <b>HTML → CSV</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📁 Отправь <b>.html</b> файл с таблицей.\n\n"
        "📌 Что делает:\n"
        "├ Находит все &lt;table&gt;\n"
        "├ Извлекает строки\n"
        "├ Очищает HTML-теги\n"
        "└ Сохраняет как CSV\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_html_file, F.document)
async def html_csv_process(message: types.Message, state: FSMContext):
    """Обработка HTML-файла."""
    if message.from_user.id != ADMIN_ID:
        return

    doc = message.document
    if not doc:
        await message.answer("❌ Это не файл")
        return

    fname = doc.file_name or "table.html"
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""

    if ext not in ("html", "htm"):
        await message.answer(
            "❌ Нужен <code>.html</code> или <code>.htm</code>",
            parse_mode="HTML"
        )
        return

    if doc.file_size and doc.file_size > 50 * 1024 * 1024:
        await message.answer("❌ Файл > 50 МБ")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer(f"⏳ Скачиваю <code>{html.escape(fname)}</code>...",
                         parse_mode="HTML")

    # Скачиваем
    tmp_html = os.path.join(TEMP_DIR, f"html_{int(time.time())}_{fname}")
    try:
        await bot.download(doc, destination=tmp_html)
    except Exception as e:
        await message.answer(f"❌ Скачивание: {e}")
        await state.clear()
        return

    # Конвертируем
    await message.answer("🔄 Конвертирую...")

    output_name = fname.rsplit(".", 1)[0] + ".csv"
    tmp_csv = os.path.join(TEMP_DIR, f"csv_{int(time.time())}_{output_name}")

    rows, error = await asyncio.to_thread(html_to_csv, tmp_html, tmp_csv, ";")

    if error:
        await message.answer(f"❌ Ошибка: <code>{html.escape(error)}</code>",
                             parse_mode="HTML")
        try:
            os.remove(tmp_html)
        except Exception:
            pass
        await state.clear()
        return

    if rows == 0:
        await message.answer("❌ В файле не найдено таблиц")
        try:
            os.remove(tmp_html)
        except Exception:
            pass
        await state.clear()
        return

    # Отправляем
    try:
        from aiogram.types import FSInputFile
        file = FSInputFile(tmp_csv)
        await message.answer_document(
            file,
            caption=(
                f"✅ <b>Готово!</b>\n\n"
                f"📁 <code>{html.escape(output_name)}</code>\n"
                f"📊 Строк: <b>{rows:,}</b>\n"
                f"🔤 Разделитель: <code>;</code>"
            ),
            parse_mode="HTML"
        )
    except Exception as e:
        await message.answer(f"❌ Отправка: {e}")

    # Удаляем временные
    try:
        os.remove(tmp_html)
    except Exception:
        pass
    try:
        os.remove(tmp_csv)
    except Exception:
        pass

    await state.clear()




def import_file_smart(filepath, ext):
    """
    Умный импорт:
    - .html → .csv → импорт в bases_70m
    - .csv / .txt → импорт в bases_70m
    """
    actual_ext = ext

    # ═══ HTML → CSV ═══
    if ext in ("html", "htm"):
        csv_path = filepath.rsplit(".", 1)[0] + ".csv"
        rows, err = html_to_csv(filepath, csv_path, ";")
        if err or rows == 0:
            logging.warning(f"[IMPORT] html_to_csv failed: {err}")
            return (0, f"Ошибка HTML→CSV: {err}")
        filepath = csv_path
        actual_ext = "csv"
        logging.info(f"[IMPORT] HTML→CSV: {rows} строк")

    # ═══ Импорт в bases_70m ═══
    logging.info(f"[IMPORT] Импортирую {filepath} ({actual_ext})")
    inserted = import_to_bases_70m(filepath, actual_ext)
    logging.info(f"[IMPORT] Добавлено: {inserted}")
    return (inserted, None)




@dp.callback_query(F.data == "tm_qr")
async def tm_qr(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    data = await state.get_data()
    tm = data.get("tempmail", {})
    if not tm.get("email"):
        await callback.message.answer("❌ Сначала создай почту")
        return
    qr = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={urllib.parse.quote(tm['email'])}"
    await callback.message.answer_photo(qr, caption=f"📱 {html.escape(tm['email'])}")



@dp.callback_query(F.data == "tm_send_start")
async def tm_send_start(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer()
    data = await state.get_data()
    tm = data.get("tempmail")
    if not tm:
        await callback.answer("❌ Создай почту", show_alert=True)
        return
    await state.set_state(BotStates.waiting_for_email_to)
    await callback.message.answer(
        f"✉️ Кому отправить?\n\nОт: <code>{html.escape(tm['email'])}</code>",
        parse_mode="HTML"
    )




# ═══════════════════════════════════════════
# ФУНКЦИИ ЗАЩИТЫ
# ═══════════════════════════════════════════

def check_rate_limit(user_id, action):
    if user_id == ADMIN_ID:
        return (True, 0)
    limit = RATE_LIMITS.get(action, 30)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now()
        cursor.execute("SELECT count, window_start FROM rate_limits WHERE user_id=? AND action=?",
                       (user_id, action))
        row = cursor.fetchone()
        if not row:
            cursor.execute("INSERT INTO rate_limits (user_id, action, count, window_start) VALUES (?,?,?,?)",
                           (user_id, action, 1, now.strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            return (True, 0)
        count, ws = row
        try:
            ws_dt = datetime.strptime(ws, "%Y-%m-%d %H:%M:%S")
            if (now - ws_dt).total_seconds() > 60:
                cursor.execute("UPDATE rate_limits SET count=1, window_start=? WHERE user_id=? AND action=?",
                               (now.strftime("%Y-%m-%d %H:%M:%S"), user_id, action))
                conn.commit()
                conn.close()
                return (True, 0)
        except Exception:
            pass
        if count >= limit:
            left = 60 - int((now - ws_dt).total_seconds()) if ws_dt else 60
            conn.close()
            return (False, max(1, left))
        cursor.execute("UPDATE rate_limits SET count = count + 1 WHERE user_id=? AND action=?",
                       (user_id, action))
        conn.commit()
        conn.close()
        return (True, 0)
    except Exception as e:
        logging.warning(f"rate_limit error: {e}")
        return (True, 0)


def log_security_event(user_id, event_type, details=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO security_logs (user_id, event_type, details, created_at) VALUES (?,?,?,?)",
            (user_id, event_type, str(details)[:500],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def is_dangerous_input(text):
    if not text:
        return False
    text_lower = text.lower()
    for pattern in DANGEROUS_PATTERNS:
        if pattern in text_lower:
            return True
    if len(text) > 5000:
        return True
    if len(set(text)) < 3 and len(text) > 20:
        return True
    return False


def validate_file(doc):
    if not doc:
        return (False, "Не файл")
    if doc.file_size and doc.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return (False, f"Файл больше {MAX_FILE_SIZE_MB} МБ")
    fname = doc.file_name or ""
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""
    allowed_ext = ("txt", "csv", "html", "htm", "pdf",
                   "jpg", "jpeg", "png", "webp", "7z", "rar", "xlsx", "xls")
    if ext not in allowed_ext:
        return (False, f"Формат .{ext} не поддерживается")
    fname_lower = fname.lower()
    for s in ["..", "/", "\\", "$"]:
        if s in fname_lower:
            return (False, "Подозрительное имя файла")
    return (True, "")


def check_user_upload_limit(user_id):
    if user_id == ADMIN_ID:
        return (True, 0)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT COUNT(*) FROM file_uploads WHERE user_id=? AND date(created_at)=?",
            (user_id, today)
        )
        count = cursor.fetchone()[0]
        conn.close()
        return (count < MAX_USER_UPLOADS_PER_DAY, count)
    except Exception:
        return (True, 0)


def log_file_upload(user_id, file_name, file_size, file_hash, status):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO file_uploads (user_id, file_name, file_size, file_hash, status, created_at) VALUES (?,?,?,?,?,?)",
            (user_id, file_name, file_size, file_hash, status,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def log_patch(patch_name, changes, size_before, size_after):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO patch_history (patch_name, changes, size_before, size_after, applied_at) VALUES (?,?,?,?,?)",
            (patch_name, changes, size_before, size_after,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass




# ═══════════════════════════════════════════
# БЕЗОПАСНАЯ ЗАГРУЗКА ДЛЯ ЮЗЕРОВ
# ═══════════════════════════════════════════


@dp.message(BotStates.waiting_for_base_file, F.document)
async def secure_upload_file(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    doc = message.document

    # Проверка файла
    ok, err = validate_file(doc)
    if not ok:
        log_security_event(user_id, "invalid_file", err)
        await message.answer(f"❌ {err}", parse_mode="HTML")
        return

    # Дневной лимит
    allowed, count = check_user_upload_limit(user_id)
    if not allowed:
        await message.answer(
            f"⚠️ <b>Лимит: {MAX_USER_UPLOADS_PER_DAY}/день</b>",
            parse_mode="HTML"
        )
        return

    # Rate limit
    allowed, seconds = check_rate_limit(user_id, "upload")
    if not allowed:
        await message.answer(f"🛡 Слишком часто. Подожди {seconds} сек.")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer("⏳ Загружаю...")

    # Скачиваем
    tmp = os.path.join(TEMP_DIR, f"user_{int(time.time())}_{doc.file_name}")
    try:
        await bot.download(doc, destination=tmp)
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")
        await state.clear()
        return

    # Хеш файла
    import hashlib
    try:
        with open(tmp, "rb") as f:
            file_hash = hashlib.md5(f.read()).hexdigest()[:16]
    except Exception:
        file_hash = "unknown"

    # Сохраняем заявку
    upload_id = save_upload_to_db(
        user_id, message.from_user.username or "",
        doc.file_name or "base", doc.file_id, 0
    )
    log_file_upload(user_id, doc.file_name or "base", doc.file_size or 0, file_hash, "pending")

    # Отправляем админу
    try:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Одобрить", callback_data=f"upl_ok_{upload_id}"),
             InlineKeyboardButton(text="❌ Отклонить", callback_data=f"upl_no_{upload_id}")]
        ])
        await bot.send_document(
            ADMIN_ID,
            doc.file_id,
            caption=(
                f"📤 <b>База от юзера #{upload_id}</b>\n\n"
                f"👤 <a href='tg://user?id={user_id}'>"
                f"{html.escape(message.from_user.first_name or '—')}</a>\n"
                f"🆔 <code>{user_id}</code>\n"
                f"📛 @{message.from_user.username or '—'}\n"
                f"📁 <code>{html.escape(doc.file_name or 'base')}</code>\n"
                f"📊 Размер: <b>{(doc.file_size or 0) / 1024:.1f} КБ</b>\n"
                f"🔒 MD5: <code>{file_hash}</code>"
            ),
            parse_mode="HTML",
            reply_markup=kb
        )
    except Exception as e:
        logging.warning(f"notify error: {e}")

    await message.answer(
        f"✅ <b>Файл отправлен на проверку</b>\n\n"
        f"📁 <code>{html.escape(doc.file_name or 'base')}</code>\n"
        f"🆔 Заявка: <b>#{upload_id}</b>\n\n"
        f"⏳ Ожидай одобрения",
        parse_mode="HTML",
        reply_markup=get_main_keyboard(user_id)
    )

    try:
        os.remove(tmp)
    except Exception:
        pass

    await state.clear()





# ═══════════════════════════════════════════
# АДМИН-КОМАНДЫ ЗАЩИТЫ
# ═══════════════════════════════════════════

@dp.message(Command("security_logs"))
async def admin_security_logs(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, event_type, details, created_at
            FROM security_logs ORDER BY id DESC LIMIT 30
        """)
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        rows = []

    if not rows:
        await message.answer("📭 Событий нет")
        return

    lines = ["🛡 <b>События безопасности</b>\n"]
    for uid, etype, det, dt in rows:
        emoji = {"dangerous_input": "⚠️", "rate_limit": "🕐",
                 "invalid_file": "📁", "sql_attempt": "💉"}.get(etype, "•")
        lines.append(f"{emoji} <code>{uid}</code> [{etype}]")
        lines.append(f"   {html.escape(str(det)[:80].replace("<", "").replace(">", ""))}")
        lines.append(f"   {dt[11:16]}\n")

    await message.answer("\n".join(lines), parse_mode="HTML")


@dp.message(Command("patch_history"))
async def admin_patch_history(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT patch_name, size_before, size_after, applied_at
            FROM patch_history ORDER BY id DESC LIMIT 30
        """)
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        rows = []

    if not rows:
        await message.answer("📭 Патчей нет")
        return

    lines = ["📦 <b>История патчей</b>\n"]
    for name, sb, sa, dt in rows:
        diff = sa - sb
        lines.append(f"📦 <b>{html.escape(name)}</b>")
        lines.append(f"   {sb} → {sa} ({diff:+d})")
        lines.append(f"   {dt}\n")

    await message.answer("\n".join(lines), parse_mode="HTML")





@dp.message(F.text == "🦠 Заражение")
async def infection_start(message: types.Message, state: FSMContext):
    """Hudson Rock — проверка заражений."""
    await state.set_state(BotStates.waiting_for_hudson)
    await message.answer(
        "🦠 <b>ЗАРАЖЕНИЕ (Hudson Rock)</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Проверка заражённых устройств.\n\n"
        "📧 Отправь <b>email</b>:\n"
        "├ test@mail.ru\n"
        "└ любой@email.com\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_hudson)
async def infection_process(message: types.Message, state: FSMContext):
    query = (message.text or "").strip().lower()
    if not query or "@" not in query:
        await message.answer("❌ Введи email")
        return

    ok, _ = check_and_update_limit(message.from_user.id, "email")
    if not ok:
        await message.answer("⚠️ Лимит исчерпан")
        await state.clear()
        return

    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer(f"🔍 Проверяю <code>{html.escape(query)}</code>...",
                         parse_mode="HTML")

    try:
        data = await asyncio.to_thread(email_hudsonrock, query)
    except Exception as e:
        await message.answer(f"❌ {html.escape(str(e)[:200].replace("<", "").replace(">", ""))}", parse_mode="HTML")
        await state.clear()
        return

    sub = get_user_subscription(message.from_user.id)
    is_vip = (sub == "VIP" or message.from_user.id == ADMIN_ID)

    text = format_hudson_result(query, data, is_vip=is_vip)
    text = safe_truncate(text, 4000)

    await message.answer(text, parse_mode="HTML",
                         reply_markup=get_settings_keyboard(message.from_user.id))
    await state.clear()





# [DELETED DUP] user_upload_start

@dp.message(BotStates.waiting_for_base_file, F.document)
async def user_upload_file(message: types.Message, state: FSMContext):
    """Обработка юзерского файла — с защитой."""
    user_id = message.from_user.id
    doc = message.document

    # ═══ 1. Проверка файла ═══
    if not doc:
        await message.answer("❌ Не файл")
        return

    fname = doc.file_name or "file"
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""

    # Размер
    if doc.file_size and doc.file_size > USER_MAX_FILE_SIZE:
        await message.answer(f"❌ Файл > {USER_MAX_FILE_SIZE // 1024 // 1024} МБ")
        return

    # Формат
    if ext not in USER_ALLOWED_EXT:
        await message.answer(
            f"❌ Формат .{ext} не поддерживается\n\n"
            f"Разрешено: {', '.join(USER_ALLOWED_EXT)}"
        )
        return

    # Имя файла
    if not is_safe_filename(fname):
        log_user_upload(user_id, fname, doc.file_size or 0, "", "rejected", "Опасное имя")
        await message.answer("❌ Опасное имя файла")
        return

    # Лимит
    allowed, count = check_user_upload_limit(user_id)
    if not allowed:
        await message.answer("⚠️ Лимит загрузок")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer("⏳ Скачиваю и проверяю...")

    # Скачиваем во временную папку
    tmp_dir = os.path.join(TEMP_DIR, f"user_upload_{user_id}_{int(time.time())}")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_file = os.path.join(tmp_dir, fname)

    try:
        await bot.download(doc, destination=tmp_file)
    except Exception as e:
        await message.answer(f"❌ Скачивание: {e}")
        await state.clear()
        return

    # MD5-хеш
    import hashlib
    try:
        with open(tmp_file, "rb") as f:
            file_hash = hashlib.md5(f.read()).hexdigest()[:16]
    except Exception:
        file_hash = "unknown"

    # ═══ 2. Если архив — распаковка ═══
    if ext in ("7z", "zip"):
        extract_dir = os.path.join(tmp_dir, "extracted")
        ok, files, err = await asyncio.to_thread(
            extract_archive_safe, tmp_file, extract_dir, None
        )
        if not ok:
            log_user_upload(user_id, fname, doc.file_size or 0, file_hash, "rejected", err)
            await message.answer(f"❌ {html.escape(str(err))}", parse_mode="HTML")
            try:
                import shutil as _sh
                _sh.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
            await state.clear()
            return

        if not files:
            log_user_upload(user_id, fname, doc.file_size or 0, file_hash, "rejected", "Пустой архив")
            await message.answer("❌ Архив пустой или нет .csv/.txt")
            await state.clear()
            return

        # Отправляем админу архив + файлы
        await message.answer(f"📦 Распаковано: <b>{len(files)}</b> файлов\n⏳ Отправляю админу...",
                             parse_mode="HTML")

    # ═══ 3. Логируем ═══
    log_user_upload(user_id, fname, doc.file_size or 0, file_hash, "pending")

    # ═══ 4. Отправляем админу ═══
    try:
        await bot.send_document(
            ADMIN_ID,
            doc.file_id,
            caption=(
                f"📤 <b>НОВАЯ БАЗА</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"👤 <a href='tg://user?id={user_id}'>"
                f"{html.escape(message.from_user.first_name or '—')}</a>\n"
                f"🆔 <code>{user_id}</code>\n"
                f"📛 @{message.from_user.username or '—'}\n"
                f"📁 <code>{html.escape(fname)}</code>\n"
                f"📊 Размер: <b>{(doc.file_size or 0) / 1024:.1f} КБ</b>\n"
                f"🔒 MD5: <code>{file_hash}</code>\n\n"
                f"📌 Разреши: /approve_user {user_id}"
            ),
            parse_mode="HTML"
        )
    except Exception as e:
        logging.warning(f"notify admin: {e}")

    await message.answer(
        f"✅ <b>Файл отправлен на проверку</b>\n\n"
        f"📁 <code>{html.escape(fname)}</code>\n"
        f"⏳ Жди одобрения админа",
        parse_mode="HTML",
        reply_markup=get_settings_keyboard(user_id)
    )

    # Чистим
    try:
        import shutil as _sh
        _sh.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    await state.clear()





# [DELETED DUP] my_uploads

@dp.message(Command("approve_user"))
async def admin_approve_user(message: types.Message, command: CommandObject):
    """Одобрить загрузку юзера."""
    if message.from_user.id != ADMIN_ID:
        return
    args = (command.args or "").strip()
    if not args.isdigit():
        await message.answer("❌ /approve_user USER_ID")
        return
    uid = int(args)

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE user_uploads_protected SET status='approved' WHERE user_id=? AND status='pending'",
            (uid,)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    try:
        await bot.send_message(
            uid,
            "✅ <b>Твоя база одобрена!</b>\n\n"
            "📊 Добавлена в общую базу",
            parse_mode="HTML"
        )
    except Exception:
        pass

    await message.answer(f"✅ Одобрено для <code>{uid}</code>", parse_mode="HTML")




# ═══════════════════════════════════════════
# ПОИСК ПО КОМАНДЕ (замена auto_search)
# ═══════════════════════════════════════════

@dp.message(Command("поиск"))
@dp.message(Command("search"))
async def cmd_search(message: types.Message, command: CommandObject):
    """Универсальный поиск: /поиск 281485304"""
    query = (command.args or "").strip()
    
    if not query:
        await message.answer(
            "🔍 <b>Формат:</b>\n"
            "├ <code>/поиск 281485304</code>\n"
            "├ <code>/поиск 79999939919</code>\n"
            "├ <code>/поиск test@mail.ru</code>\n"
            "└ <code>/поиск Иванов Иван</code>",
            parse_mode="HTML"
        )
        return
    
    detected = detect_type(query)
    ok, _ = check_and_update_limit(message.from_user.id, "fio")
    if not ok:
        await message.answer(
            "⚠️ <b>Лимит исчерпан.</b>",
            parse_mode="HTML"
        )
        return
    
    await bot.send_chat_action(message.chat.id, "typing")
    
    type_emoji = {
        "name": "👤", "id": "🆔", "phone": "📱",
        "email": "📧", "username": "🔗", "address": "🏠",
    }.get(detected, "🔍")
    
    await message.answer(
        f"{type_emoji} <b>Ищу:</b> <code>{html.escape(str(query)[:100].replace("<", "").replace(">", ""))}</code>",
        parse_mode="HTML"
    )
    
    parts = []
    
    # bases_70m.db
    try:
        if detected == "name":
            local_rows = await asyncio.to_thread(search_fio_exact, query, 30)
        else:
            local_rows = await asyncio.to_thread(search_local_base_smart, query, 20)
        
        local_text = format_local_results(query, local_rows, user_id=message.from_user.id)
        if isinstance(local_text, tuple):
            local_text = local_text[0]
        if local_text:
            parts.append(local_text)
    except Exception as e:
        logging.warning(f"local: {e}")
    
    # BigBase
    try:
        bb_query = query
        digits = re.sub(r"\D", "", query)
        if digits and len(digits) >= 10:
            bb_query = digits
            if bb_query.startswith("8") and len(bb_query) == 11:
                bb_query = "7" + bb_query[1:]
            elif len(bb_query) == 10:
                bb_query = "7" + bb_query
        
        bb_data = await asyncio.to_thread(bigbase_search, bb_query)
        bb_text = format_bigbase_result(bb_data, user_id=message.from_user.id)
        if bb_text:
            parts.append(bb_text)
    except Exception as e:
        logging.warning(f"bb: {e}")
    
    # Hudson Rock (для email)
    if detected == "email":
        try:
            hr_data = await asyncio.to_thread(email_hudsonrock, query)
            sub = get_user_subscription(message.from_user.id)
            is_vip = (sub == "VIP" or message.from_user.id == ADMIN_ID)
            hr_text = format_hudson_result(query, hr_data, is_vip=is_vip)
            if hr_text:
                parts.append(hr_text)
        except Exception as e:
            logging.warning(f"hudson: {e}")
    
    # Итог
    if parts:
        final = "\n".join(parts)
    else:
        final = f"📭 <b>Ничего не найдено</b>\n\n🔍 <code>{html.escape(query)}</code>"
    
    final = safe_truncate(final, 4000)
    
    log_search(message.from_user.id, message.from_user.username or "", query, detected)
    
    await message.answer(
        final,
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=get_main_keyboard(message.from_user.id)
    )




def delete_expired_mailboxes():
    """Удаляет старые временные почты."""
    try:
        conn = sqlite3.connect(DB_PATH)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("DELETE FROM anon_mailboxes WHERE expires_at < ?", (now,))
        conn.commit()
        conn.close()
    except Exception:
        pass




# ═══════════════════════════════════════════
# АНОНИМНЫЕ ФУНКЦИИ TEMPMAIL
# ═══════════════════════════════════════════

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 13; Mobile) AppleWebKit/537.36",
]


def _anon_headers():
    """Рандомные заголовки для анонимности."""
    import random
    return {
        "User-Agent": random.choice(_UA_POOL),
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        "DNT": "1",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }


def _anon_request(url, data=None, method="GET", token=None, timeout=20):
    """Анонимный запрос."""
    headers = _anon_headers()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=data.encode() if isinstance(data, str) else data,
        headers=headers,
        method=method
    )

    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


def generate_session_id():
    """Анонимный ID сессии."""
    import random
    import string
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=24))


def save_anon_mailbox(data):
    """Сохраняет mailbox в БД."""
    try:
        conn = sqlite3.connect(DB_PATH)
        expires = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("""
            INSERT OR REPLACE INTO anon_mailboxes
            (session_id, email, password, login, domain, token, created_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            data.get("session_id", ""),
            data.get("email", ""),
            data.get("password", ""),
            data.get("login", ""),
            data.get("domain", ""),
            data.get("token", ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            expires
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logging.warning(f"save_anon_mailbox: {e}")
        return False


def log_anon_mail(session_id, direction, from_email, to_email, subject, body=""):
    """Анонимно логирует письмо."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO anon_mail_history
            (session_id, direction, from_email, to_email, subject, body, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (session_id, direction, from_email, to_email, subject, body[:500],
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception:
        pass


def add_to_favorites(session_id, msg_id, from_email, subject, body=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO anon_favorites
            (session_id, msg_id, from_email, subject, body, created_at)
            VALUES (?,?,?,?,?,?)
        """, (session_id, msg_id, from_email, subject, body[:1000],
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_favorites(session_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT msg_id, from_email, subject FROM anon_favorites WHERE session_id=? ORDER BY id DESC LIMIT 20",
            (session_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def get_mail_stats(session_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        received = cursor.execute(
            "SELECT COUNT(*) FROM anon_mail_history WHERE session_id=? AND direction='in'",
            (session_id,)
        ).fetchone()[0]
        sent = cursor.execute(
            "SELECT COUNT(*) FROM anon_mail_history WHERE session_id=? AND direction='out'",
            (session_id,)
        ).fetchone()[0]
        favs = cursor.execute(
            "SELECT COUNT(*) FROM anon_favorites WHERE session_id=?",
            (session_id,)
        ).fetchone()[0]
        conn.close()
        return {"received": received, "sent": sent, "favorites": favs}
    except Exception:
        return {"received": 0, "sent": 0, "favorites": 0}




# ═══════════════════════════════════════════
# УМНАЯ ЗАЩИТА ФАЙЛОВ
# ═══════════════════════════════════════════

def scan_file_smart(filepath, ext):
    """
    Умная проверка файла на вредоносное содержимое.
    Возвращает (safe, reason, details).
    """
    import hashlib

    try:
        # 1. Размер
        fsize = os.path.getsize(filepath)
        if fsize > USER_MAX_FILE_SIZE:
            return (False, f"Файл больше {USER_MAX_FILE_SIZE // 1024 // 1024} МБ", "")

        if fsize == 0:
            return (False, "Пустой файл", "")

        # 2. Хеш
        with open(filepath, "rb") as f:
            data = f.read()
        file_hash = hashlib.sha256(data).hexdigest()[:16]

        # 3. Если бинарный — проверка на вирусы
        if ext in ("7z", "zip"):
            # Проверяем что это реально архив
            if ext == "zip":
                try:
                    import zipfile
                    if not zipfile.is_zipfile(filepath):
                        return (False, "Не ZIP-архив", file_hash)
                except Exception:
                    return (False, "Повреждённый ZIP", file_hash)
            elif ext == "7z":
                # Проверка сигнатуры 7z
                if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
                    return (False, "Не 7z-архив", file_hash)
            return (True, "OK", file_hash)

        # 4. Текстовые файлы — проверка содержимого
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            try:
                text = data.decode("cp1251", errors="ignore")
            except Exception:
                return (False, "Не читается", file_hash)

        # Опасные паттерны
        text_lower = text.lower()
        for pattern in USER_DANGEROUS_PATTERNS:
            if pattern.lower() in text_lower:
                return (False, f"Найдено: {pattern[:30]}", file_hash)

        # Слишком много подозрительных символов
        if text.count("\x00") > 10:
            return (False, "Много нулевых байт", file_hash)

        # Очень длинные строки (типично для эксплойтов)
        for line in text.split("\n")[:100]:
            if len(line) > 10000:
                return (False, "Подозрительно длинная строка", file_hash)

        return (True, "OK", file_hash)

    except Exception as e:
        return (False, f"Ошибка проверки: {str(e)[:100]}", "")


def is_safe_filename(fname):
    """Проверка имени файла."""
    if not fname:
        return (False, "Пустое имя")

    if len(fname) > 200:
        return (False, "Слишком длинное имя")

    fname_lower = fname.lower()

    for s in USER_DANGEROUS_NAMES:
        if s in fname_lower:
            return (False, f"Опасный символ: {s}")

    # Проверка расширения
    ext = fname_lower.rsplit(".", 1)[-1] if "." in fname_lower else ""
    if ext not in USER_ALLOWED_EXT:
        return (False, f"Формат .{ext} не разрешён")

    return (True, "OK")


def check_user_upload_limit(user_id):
    """Дневной лимит."""
    if user_id == ADMIN_ID:
        return (True, 0)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT COUNT(*) FROM file_uploads WHERE user_id=? AND date(created_at)=?",
            (user_id, today)
        )
        count = cursor.fetchone()[0]
        conn.close()
        return (count < USER_MAX_UPLOADS_PER_DAY, count)
    except Exception:
        return (True, 0)


def log_user_upload(user_id, fname, fsize, fhash, status, reason=""):
    """Логирование."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO file_uploads (user_id, file_name, file_size, file_hash, status, created_at) VALUES (?,?,?,?,?,?)",
            (user_id, fname, fsize, fhash, status + ":" + reason[:100],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass





# ═══════════════════════════════════════════
# ЗАГРУЗКА ОТ ЮЗЕРОВ (с проверкой)
# ═══════════════════════════════════════════

@dp.message(F.text == "📤 Загрузить базу")
async def user_upload_start(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    allowed, count = check_user_upload_limit(user_id)
    if not allowed:
        await message.answer(
            f"⚠️ <b>Лимит загрузок</b>\n\n"
            f"📊 Сегодня: <b>{count}/{USER_MAX_UPLOADS_PER_DAY}</b>",
            parse_mode="HTML"
        )
        return

    await state.set_state(BotStates.waiting_for_base_file)
    await message.answer(
        "📤 <b>ЗАГРУЗКА БАЗЫ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📁 Сегодня: <b>{count}/{USER_MAX_UPLOADS_PER_DAY}</b>\n\n"
        "📌 Форматы:\n"
        "├ 📊 .csv\n"
        "├ 📄 .txt\n"
        "├ 🌐 .html\n"
        "└ 📦 .7z / .zip\n\n"
        "📏 Максимум: <b>50 МБ</b>\n"
        "🛡 Файл пройдёт проверку\n\n"
        "❌ Отмена — /cancel",
        parse_mode="HTML"
    )


@dp.message(BotStates.waiting_for_base_file, F.document)
async def user_upload_file(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    doc = message.document

    if not doc:
        await message.answer("❌ Не файл")
        return

    fname = doc.file_name or "file"
    ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""

    # ═══ 1. Имя ═══
    safe, err = is_safe_filename(fname)
    if not safe:
        log_user_upload(user_id, fname, doc.file_size or 0, "", "rejected", err)
        await message.answer(f"❌ {err}", parse_mode="HTML")
        return

    # ═══ 2. Размер ═══
    if doc.file_size and doc.file_size > USER_MAX_FILE_SIZE:
        await message.answer(f"❌ Файл > {USER_MAX_FILE_SIZE // 1024 // 1024} МБ")
        return

    await bot.send_chat_action(message.chat.id, "upload_document")
    await message.answer("⏳ Скачиваю и проверяю...")

    # Скачиваем
    tmp = os.path.join(TEMP_DIR, f"tmp_user_{user_id}_{int(time.time())}_{fname}")
    try:
        await bot.download(doc, destination=tmp)
    except Exception as e:
        await message.answer(f"❌ Скачивание: {e}")
        await state.clear()
        return

    # ═══ 3. Проверка содержимого ═══
    safe, reason, fhash = await asyncio.to_thread(scan_file_smart, tmp, ext)

    if not safe:
        log_user_upload(user_id, fname, doc.file_size or 0, fhash, "rejected", reason)
        await message.answer(
            f"🛡 <b>Файл отклонён</b>\n\n"
            f"📌 {html.escape(reason)}",
            parse_mode="HTML"
        )
        try:
            os.remove(tmp)
        except Exception:
            pass
        await state.clear()
        return

    # ═══ 4. Логируем ═══
    log_user_upload(user_id, fname, doc.file_size or 0, fhash, "pending", "")

    # Сохраняем в БД
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO base_uploads (user_id, username, file_name, rows_count, status, uploaded_at) VALUES (?,?,?,?,?,?)",
            (user_id, message.from_user.username or "", fname, 0, "pending",
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        upload_id = cursor.lastrowid
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"save upload: {e}")
        upload_id = 0

    # ═══ 5. Отправляем админу С ПОДТВЕРЖДЕНИЕМ ═══
    try:
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(
                text="✅ ПОДТВЕРДИТЬ И ДОБАВИТЬ",
                callback_data=f"user_ok_{upload_id}"
            )],
            [InlineKeyboardButton(
                text="❌ ОТКЛОНИТЬ",
                callback_data=f"user_no_{upload_id}"
            )],
        ])

        await bot.send_document(
            ADMIN_ID,
            doc.file_id,
            caption=(
                f"🛡 <b>НОВЫЙ ФАЙЛ ОТ ЮЗЕРА</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"👤 <a href='tg://user?id={user_id}'>"
                f"{html.escape(message.from_user.first_name or '—')}</a>\n"
                f"🆔 <code>{user_id}</code>\n"
                f"📛 @{message.from_user.username or '—'}\n\n"
                f"📁 <code>{html.escape(fname)}</code>\n"
                f"📊 Размер: <b>{(doc.file_size or 0) / 1024:.1f} КБ</b>\n"
                f"🔒 SHA256: <code>{fhash}</code>\n"
                f"🛡 Проверка: <b>✅ ПРОЙДЕНА</b>\n"
                f"🆔 Заявка: <b>#{upload_id}</b>\n\n"
                f"📌 Нажми кнопку чтобы добавить в базу"
            ),
            parse_mode="HTML",
            reply_markup=kb
        )
    except Exception as e:
        logging.warning(f"notify: {e}")

    try:
        os.remove(tmp)
    except Exception:
        pass

    await message.answer(
        f"✅ <b>Файл проверен и отправлен</b>\n\n"
        f"📁 <code>{html.escape(fname)}</code>\n"
        f"🛡 Статус: <b>Ожидает подтверждения</b>\n"
        f"⏳ Админ проверит и одобрит",
        parse_mode="HTML",
        reply_markup=get_settings_keyboard(user_id)
    )

    await state.clear()


# ═══════════════════════════════════════════
# CALLBACK: ПОДТВЕРЖДЕНИЕ
# ═══════════════════════════════════════════

@dp.callback_query(F.data.startswith("user_ok_"))
async def user_upload_approve(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только админ", show_alert=True)
        return

    upload_id = int(callback.data.replace("user_ok_", ""))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE base_uploads SET status='approved' WHERE id=?",
            (upload_id,)
        )
        conn.commit()
        conn.close()
        changes_count = 1
    except Exception as e:
        changes_count = 0
        logging.warning(f"approve: {e}")

    # Отправляем уведомление юзеру
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id, file_name FROM base_uploads WHERE id=?",
            (upload_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            uid, fname = row
            await bot.send_message(
                uid,
                f"✅ <b>Твоя база одобрена!</b>\n\n"
                f"📁 <code>{html.escape(fname)}</code>\n"
                f"📊 Добавлена в базу",
                parse_mode="HTML"
            )
    except Exception:
        pass

    await callback.answer("✅ Одобрено")
    try:
        await callback.message.edit_caption(
            caption=(callback.message.caption or "") + "\n\n✅ <b>ОДОБРЕНО</b>",
            parse_mode="HTML"
        )
    except Exception:
        pass


@dp.callback_query(F.data.startswith("user_no_"))
async def user_upload_reject(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только админ", show_alert=True)
        return

    upload_id = int(callback.data.replace("user_no_", ""))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE base_uploads SET status='rejected' WHERE id=?",
            (upload_id,)
        )
        cursor.execute(
            "SELECT user_id, file_name FROM base_uploads WHERE id=?",
            (upload_id,)
        )
        row = cursor.fetchone()
        conn.commit()
        conn.close()

        if row:
            uid, fname = row
            await bot.send_message(
                uid,
                f"❌ <b>Твоя база отклонена</b>\n\n"
                f"📁 <code>{html.escape(fname)}</code>",
                parse_mode="HTML"
            )
    except Exception:
        pass

    await callback.answer("❌ Отклонено")
    try:
        await callback.message.edit_caption(
            caption=(callback.message.caption or "") + "\n\n❌ <b>ОТКЛОНЕНО</b>",
            parse_mode="HTML"
        )
    except Exception:
        pass




@dp.message(F.text == "📁 Мои загрузки")
async def my_uploads_safe(message: types.Message):
    """Только свои загрузки."""
    uid = message.from_user.id

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, file_name, rows_count, status, uploaded_at
            FROM base_uploads WHERE user_id=?
            ORDER BY id DESC LIMIT 15
        """, (uid,))
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        rows = []

    if not rows:
        await message.answer(
            "📭 Ты ещё не загружал базы",
            reply_markup=get_settings_keyboard(uid)
        )
        return

    emoji_map = {"pending": "⏳", "approved": "✅", "rejected": "❌"}
    lines = ["📁 <b>Мои загрузки:</b>\n"]
    for r in rows:
        e = emoji_map.get(r[3], "❔")
        lines.append(f"{e} <b>#{r[0]}</b> <code>{html.escape(r[1])}</code>")
        lines.append(f"   └ 📅 {r[4]}")

    await message.answer("\n".join(lines), parse_mode="HTML",
                         reply_markup=get_settings_keyboard(uid))






# ═══════════════════════════════════════════
# INVISIBLE_MODULE_ADDED
# МОДУЛЬ «НЕВИДИМОСТЬ»
# ═══════════════════════════════════════════

import random as _rand
import string as _str

def init_invisible_tables():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS shadow_users (
        user_id INTEGER PRIMARY KEY,
        hidden_values TEXT,
        until_date TEXT,
        note TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS shadow_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shadow_user_id INTEGER,
        searcher_id INTEGER,
        searcher_username TEXT,
        query TEXT,
        query_type TEXT,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()


def shadow_create(user_id, hidden_values, until_date, note=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""INSERT OR REPLACE INTO shadow_users
        (user_id, hidden_values, until_date, note, active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)""",
        (user_id, hidden_values, until_date, note,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def shadow_remove(user_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM shadow_users WHERE user_id = ?", (user_id,))
    n = cur.rowcount
    conn.commit()
    conn.close()
    return n > 0


def shadow_get(user_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, hidden_values, until_date, note, active FROM shadow_users WHERE user_id = ?",
                (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def shadow_list():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, hidden_values, until_date, note, active FROM shadow_users ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def shadow_get_all_hidden():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    today = datetime.now().strftime("%Y-%m-%d")
    cur.execute("""SELECT user_id, hidden_values FROM shadow_users
                   WHERE active = 1 AND (until_date = 'forever' OR until_date >= ?)""",
                (today,))
    rows = cur.fetchall()
    conn.close()
    result = []
    for uid, hv in rows:
        if not hv:
            continue
        for val in hv.split("|"):
            val = val.strip().lower()
            if val:
                result.append((uid, val))
    return result


def shadow_find_owner_by_value(text):
    if not text:
        return None
    t = str(text).lower()
    for uid, val in shadow_get_all_hidden():
        if val and val in t:
            return uid
    return None


def shadow_log_search(shadow_user_id, searcher_id, searcher_username, query, qtype):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""INSERT INTO shadow_log
            (shadow_user_id, searcher_id, searcher_username, query, query_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (shadow_user_id, searcher_id, searcher_username,
             query[:200], qtype,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception:
        pass


def shadow_fake_result(query):
    fake_email = "".join(_rand.choices(_str.ascii_lowercase, k=8)) + "@gmail.com"
    fake_phone = "+7" + "".join(_rand.choices(_str.digits, k=10))
    fake_id = "".join(_rand.choices(_str.digits, k=9))
    fake_name = _rand.choice(["Алексей", "Дмитрий", "Сергей", "Иван", "Андрей"])
    fake_last = _rand.choice(["Смирнов", "Иванов", "Кузнецов", "Попов", "Соколов"])
    return (
        "🔍 <b>Результаты поиска</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "👤 <b>ФИО:</b> " + fake_name + " " + fake_last + "\n"
        "🆔 <b>ID:</b> <code>" + fake_id + "</code>\n"
        "📱 <b>Телефон:</b> <code>" + fake_phone + "</code>\n"
        "📧 <b>Email:</b> <code>" + fake_email + "</code>\n\n"
        "🔍 <b>Запрос:</b> <code>" + html.escape(str(query)[:100].replace("<", "").replace(">", "")) + "</code>\n\n"
        "<i>Данные могут быть неполными. Попробуй другой запрос.</i>"
    )


def shadow_cleanup_expired():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")
        cur.execute("""UPDATE shadow_users SET active = 0
                       WHERE until_date != 'forever' AND until_date < ?""",
                    (today,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _shadow_check(text, query_type, user_id, username):
    owner = shadow_find_owner_by_value(text)
    if owner:
        shadow_log_search(owner, user_id, username, text, query_type)
        return (True, shadow_fake_result(text))
    return (False, None)


def shadow_admin_kb():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🌑 Выдать тень"), KeyboardButton(text="📋 Список теней")],
            [KeyboardButton(text="👁 Кто искал")],
            [KeyboardButton(text="⏸ Пауза"), KeyboardButton(text="🗑 Снять тень")],
            [KeyboardButton(text="⬅️ Админ-панель")],
        ],
        resize_keyboard=True
    )


@dp.message(F.text == "🌑 Невидимость")
async def admin_invisible_panel(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    shadow_cleanup_expired()
    await message.answer(
        "🌑 <b>НЕВИДИМОСТЬ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Тень = юзер не находится ни в одном поиске.\n"
        "Вместо данных — фейк.\n\n"
        "Выбери действие:",
        parse_mode="HTML",
        reply_markup=shadow_admin_kb()
    )


@dp.message(F.text == "🌑 Выдать тень")
async def shadow_issue_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_shadow_uid)
    await message.answer(
        "🌑 <b>Выдача тени — Шаг 1/4</b>\n\n"
        "Введи <b>TG ID</b> юзера (или @username):",
        parse_mode="HTML"
    )


@dp.message(AdminStates.waiting_for_shadow_uid)
async def shadow_issue_uid(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip().lstrip("@")
    if txt.isdigit():
        uid = int(txt)
    else:
        row = get_user_by_username(txt)
        if not row:
            await message.answer("❌ Не найден. Введи TG ID числом.")
            return
        uid = row[0]
    await state.update_data(shadow_uid=uid)
    await message.answer(
        f"✅ ID: <code>{uid}</code>\n\n"
        f"<b>Шаг 2/4</b> — введи данные для скрытия через запятую:\n\n"
        f"Пример: <code>test@mail.com, +79991234567, @durov</code>",
        parse_mode="HTML"
    )
    await state.set_state(AdminStates.waiting_for_shadow_values)


@dp.message(AdminStates.waiting_for_shadow_values)
async def shadow_issue_values(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt:
        await message.answer("❌ Введи хотя бы одно значение.")
        return
    values = [v.strip() for v in txt.replace(",", "|").split("|") if v.strip()]
    if not values:
        await message.answer("❌ Пусто.")
        return
    await state.update_data(shadow_values=values)
    await message.answer(
        f"📋 Сохранено: <b>{len(values)}</b>\n\n"
        f"<b>Шаг 3/4</b> — выбери срок:",
        parse_mode="HTML",
        reply_markup=ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="10 дней"), KeyboardButton(text="20 дней")],
                [KeyboardButton(text="30 дней"), KeyboardButton(text="1 месяц")],
                [KeyboardButton(text="1 год"), KeyboardButton(text="♾ Навсегда")],
                [KeyboardButton(text="✏️ Свой срок")],
                [KeyboardButton(text="❌ Отмена")],
            ],
            resize_keyboard=True
        )
    )
    await state.set_state(AdminStates.waiting_for_shadow_days)


@dp.message(AdminStates.waiting_for_shadow_days)
async def shadow_issue_days(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if txt == "❌ Отмена":
        await state.clear()
        await message.answer("❌ Отменено.", reply_markup=get_admin_keyboard())
        return
    days_map = {"10 дней": 10, "20 дней": 20, "30 дней": 30,
                "1 месяц": 30, "1 год": 365, "♾ Навсегда": -1}
    if txt in days_map:
        days = days_map[txt]
    elif txt == "✏️ Свой срок":
        await message.answer("✏️ Введи число дней (0 = навсегда):")
        await state.set_state(AdminStates.waiting_for_shadow_custom_days)
        return
    else:
        await message.answer("❌ Выбери из кнопок.")
        return
    until = "forever" if days in (-1, 0) else (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    await state.update_data(shadow_until=until)
    await message.answer(
        f"📅 До: <b>{'бессрочно' if until == 'forever' else until}</b>\n\n"
        f"<b>Шаг 4/4</b> — заметка для себя. Или <code>-</code>:",
        parse_mode="HTML",
        reply_markup=ReplyKeyboardMarkup(
            keyboard=[[KeyboardButton(text="-")], [KeyboardButton(text="❌ Отмена")]],
            resize_keyboard=True
        )
    )
    await state.set_state(AdminStates.waiting_for_shadow_note)


@dp.message(AdminStates.waiting_for_shadow_custom_days)
async def shadow_custom_days(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ Введи число.")
        return
    days = int(txt)
    until = "forever" if days == 0 else (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    await state.update_data(shadow_until=until)
    await message.answer(
        f"📅 До: <b>{'бессрочно' if until == 'forever' else until}</b>\n\n"
        f"<b>Шаг 4/4</b> — заметка. Или <code>-</code>:",
        parse_mode="HTML",
        reply_markup=ReplyKeyboardMarkup(
            keyboard=[[KeyboardButton(text="-")], [KeyboardButton(text="❌ Отмена")]],
            resize_keyboard=True
        )
    )
    await state.set_state(AdminStates.waiting_for_shadow_note)


@dp.message(AdminStates.waiting_for_shadow_note)
async def shadow_issue_note(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if txt == "❌ Отмена":
        await state.clear()
        await message.answer("❌ Отменено.", reply_markup=get_admin_keyboard())
        return
    note = "" if txt == "-" else txt[:200]
    data = await state.get_data()
    uid = data.get("shadow_uid")
    until = data.get("shadow_until", "forever")
    values = data.get("shadow_values", [])
    hidden_values = "|".join(values)[:3000]
    shadow_create(uid, hidden_values, until, note)
    await message.answer(
        f"✅ <b>Тень выдана!</b>\n\n"
        f"🆔 Юзер: <code>{uid}</code>\n"
        f"📅 До: <b>{'бессрочно' if until == 'forever' else until}</b>\n"
        f"📋 Скрыто: <b>{len(values)}</b> значений\n"
        f"📝 {html.escape(note) if note else '—'}",
        parse_mode="HTML",
        reply_markup=shadow_admin_kb()
    )
    await state.clear()


@dp.message(F.text == "📋 Список теней")
async def shadow_list_view(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    shadow_cleanup_expired()
    rows = shadow_list()
    if not rows:
        await message.answer("📭 Теней нет.", reply_markup=shadow_admin_kb())
        return
    lines = ["🌑 <b>Тени:</b>\n"]
    for uid, hv, until, note, active in rows:
        status = "🟢" if active else "⏸"
        until_txt = "бессрочно" if until == "forever" else until
        vals = hv.split("|")[:3] if hv else []
        vals_txt = ", ".join(f"<code>{html.escape(v)}</code>" for v in vals)
        lines.append(f"{status} <code>{uid}</code>\n   📅 До: {until_txt}\n   📌 {vals_txt}\n   📝 {html.escape(note) if note else '—'}\n")
    text = "\n".join(lines)
    text = safe_truncate(text, 4000)
    await message.answer(text, parse_mode="HTML", reply_markup=shadow_admin_kb())


@dp.message(F.text == "👁 Кто искал")
async def shadow_who_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_shadow_who)
    await message.answer("👁 Введи <b>TG ID</b> юзера:", parse_mode="HTML")


@dp.message(AdminStates.waiting_for_shadow_who)
async def shadow_who_result(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ ID — число.")
        return
    uid = int(txt)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""SELECT searcher_id, searcher_username, query, query_type, created_at
                   FROM shadow_log WHERE shadow_user_id = ?
                   ORDER BY id DESC LIMIT 30""", (uid,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await message.answer("📭 Никто не искал.", reply_markup=shadow_admin_kb())
        await state.clear()
        return
    lines = [f"👁 <b>Кто искал</b> <code>{uid}</code>:\n"]
    for sid, sun, q, qt, dt in rows:
        name = f"@{sun}" if sun else f"id{sid}"
        lines.append(f"├ <code>{name}</code> · {qt} · {dt[5:16]}\n│  <code>{html.escape(str(q)[:60].replace("<", "").replace(">", ""))}</code>")
    text = "\n".join(lines)
    text = safe_truncate(text, 4000)
    await message.answer(text, parse_mode="HTML", reply_markup=shadow_admin_kb())
    await state.clear()


@dp.message(F.text == "⏸ Пауза")
async def shadow_pause_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_shadow_pause)
    await message.answer("⏸ Введи <b>TG ID</b> юзера:", parse_mode="HTML")


@dp.message(AdminStates.waiting_for_shadow_pause)
async def shadow_pause_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ ID — число.")
        return
    uid = int(txt)
    row = shadow_get(uid)
    if not row:
        await message.answer("❌ Тень не найдена.", reply_markup=shadow_admin_kb())
        await state.clear()
        return
    current = row[4]
    new_active = 0 if current == 1 else 1
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE shadow_users SET active = ? WHERE user_id = ?", (new_active, uid))
    conn.commit()
    conn.close()
    status = "⏸ На паузе" if new_active == 0 else "🟢 Активна"
    await message.answer(f"✅ Тень <code>{uid}</code>: <b>{status}</b>",
                         parse_mode="HTML", reply_markup=shadow_admin_kb())
    await state.clear()


@dp.message(F.text == "🗑 Снять тень")
async def shadow_remove_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_shadow_remove)
    await message.answer("🗑 Введи <b>TG ID</b> юзера:", parse_mode="HTML")


@dp.message(AdminStates.waiting_for_shadow_remove)
async def shadow_remove_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ ID — число.")
        return
    uid = int(txt)
    if shadow_remove(uid):
        await message.answer(f"✅ Тень <code>{uid}</code> снята.",
                             parse_mode="HTML", reply_markup=shadow_admin_kb())
    else:
        await message.answer(f"❌ Тень <code>{uid}</code> не найдена.",
                             parse_mode="HTML", reply_markup=shadow_admin_kb())
    await state.clear()

# ═══ КОНЕЦ БЛОКА НЕВИДИМОСТИ ═══


# ═══════════════════════════════════════════
# AUTO_SEARCH_V2 — единый поиск через build_full_report
# ═══════════════════════════════════════════

@dp.message(F.text & ~F.text.startswith("/"))
async def auto_search_handler(message: types.Message, state: FSMContext):
    """Любое сообщение → полный отчёт со всех источников."""
    # FSM?
    if await state.get_state() is not None:
        return
    # Кнопка?
    if is_registered_button(message.text):
        return

    text = (message.text or "").strip()
    if not text:
        return

    if is_banned(message.from_user.id):
        return

    kind = detect_type(text)

    if kind == "unknown":
        await message.answer(
            "🤔 <b>Не понял формат.</b>\n\n"
            "Попробуй:\n"
            "├ 📱 <code>79999939919</code>\n"
            "├ 👤 <code>Иванов Иван</code>\n"
            "├ 📧 <code>test@mail.ru</code>\n"
            "├ 🆔 <code>281485304</code>\n"
            "├ 🔗 <code>@durov</code>\n"
            "└ 🌐 <code>8.8.8.8</code>",
            parse_mode="HTML",
            reply_markup=get_main_keyboard(message.from_user.id)
        )
        return

    # Shadow-проверка
    hidden, fake = _shadow_check(text, kind, message.from_user.id, message.from_user.username or "")
    if hidden:
        await message.answer(fake, parse_mode="HTML", reply_markup=get_main_keyboard(message.from_user.id))
        return

    # Лимит
    ok, _ = check_and_update_limit(message.from_user.id, kind if kind != "id" else "fio")
    if not ok:
        await message.answer("⚠️ <b>Лимит исчерпан.</b>\n\n🔥 Купить доступ", parse_mode="HTML",
                             reply_markup=get_main_keyboard(message.from_user.id))
        return

    await bot.send_chat_action(message.chat.id, "typing")
    await message.answer("🔍 <b>Ищу по всем источникам...</b>\n⏳ 5-15 секунд", parse_mode="HTML")

    # ═══ 70M база ═══
    local_rows = []
    try:
        if kind == "name":
            local_rows = await asyncio.to_thread(search_fio_exact, text, 50)
        else:
            local_rows = await asyncio.to_thread(search_local_base_smart, text, 50)
    except Exception as e:
        logging.warning(f"local base error: {e}")

    # ═══ BigBase ═══
    bb_data = {}
    try:
        bb_query = text
        digits = re.sub(r"\D", "", text)
        if digits and len(digits) >= 10:
            bb_query = digits
            if bb_query.startswith("8") and len(bb_query) == 11:
                bb_query = "7" + bb_query[1:]
            elif len(bb_query) == 10:
                bb_query = "7" + bb_query
        bb_data = await asyncio.to_thread(bigbase_search, bb_query)
    except Exception as e:
        logging.warning(f"bigbase error: {e}")

    # ═══ LeakCheck ═══
    leak_data = {}
    if kind == "email":
        try:
            leak_data = await asyncio.to_thread(email_leakcheck, text)
        except Exception as e:
            logging.warning(f"leakcheck error: {e}")

    # ═══ Hudson Rock ═══
    hr_data = {}
    if kind == "email":
        try:
            hr_data = await asyncio.to_thread(email_hudsonrock, text)
        except Exception as e:
            logging.warning(f"hudson error: {e}")

    # ═══ Username дополнительно проверяем на сайтах ═══
    if kind == "username":
        try:
            username_clean = text.lstrip("@")
            site_results = await search_username(username_clean)
            # Добавляем в отчёт
        except Exception:
            site_results = []

    # ═══ Строим полный отчёт ═══
    final = build_full_report(text, local_rows, bb_data, leak_data, hr_data,
                              user_id=message.from_user.id)

    # Username-дополнение (39 сайтов + VK)
    if kind == "username":
        try:
            extra = ""
            # 39 сайтов
            found_sites = [r for r in site_results if r.get("exists")]
            if found_sites:
                extra += "\n\n╔══════════════════════════════╗\n║  🔎 НАЙДЕНО НА САЙТАХ      ║\n╚══════════════════════════════╝\n"
                for r in found_sites:
                    extra += f"├ <a href='{r['url']}'>{r['site']}</a>\n"
            # VK
            vk_profile = await asyncio.to_thread(vk_get_profile, username_clean)
            if vk_profile:
                extra += "\n🆔 <b>VK</b>\n" + format_vk_card(vk_profile)
            if extra:
                final += extra
        except Exception as e:
            logging.warning(f"username extra error: {e}")

    # Обрезка
    final = safe_truncate(final, 4000)

    log_search(message.from_user.id, message.from_user.username or "", text, kind)
    add_xp(message.from_user.id, 15)

    await message.answer(final, parse_mode="HTML",
                         disable_web_page_preview=True,
                         reply_markup=get_main_keyboard(message.from_user.id))


@dp.message(Command("phone"))
async def cmd_phone(message: types.Message, command: CommandObject):
    q = (command.args or "").strip()
    if not q:
        await message.answer("❌ Формат: <code>/phone +79999999999</code>", parse_mode="HTML")
        return
    await _auto_phone(message, None, q)


@dp.message(Command("email"))
async def cmd_email(message: types.Message, command: CommandObject):
    q = (command.args or "").strip().lower()
    if not q or "@" not in q:
        await message.answer("❌ Формат: <code>/email test@mail.ru</code>", parse_mode="HTML")
        return
    await _auto_email(message, None, q)


@dp.message(Command("closed"))
async def cmd_closed(message: types.Message, command: CommandObject):
    q = (command.args or "").strip()
    if not q:
        await message.answer("❌ Формат: <code>/closed +79999999999</code>", parse_mode="HTML")
        return
    await _auto_phone(message, None, q)






# ═══════════════════════════════════════════
# GOV_APIS_FULL — государственные базы РФ
# ═══════════════════════════════════════════

GOV_BASES = [
    {
        "name": "🔴 Террористы и экстремисты",
        "url": "http://fedsfm.ru/documents/terrorists-catalog-portal-act",
        "desc": "Официальный список ФСФМ",
    },
    {
        "name": "🚔 Федеральный розыск МВД",
        "url": "https://mvd.ru/wanted",
        "desc": "Официальный розыск МВД РФ",
    },
    {
        "name": "🌐 Международный розыск (Интерпол)",
        "url": "https://www.interpol.int/notice/search/wanted",
        "desc": "База Интерпола",
    },
    {
        "name": "⚖️ ФССП — долги",
        "url": "https://fssprus.ru/iss/ip_search",
        "desc": "Исполнительные производства",
    },
    {
        "name": "🚫 Розыск ФСИН",
        "url": "http://fsin.su/criminal/",
        "desc": "Сбежавшие заключённые",
    },
    {
        "name": "📕 Действительность паспорта",
        "url": "http://сервисы.гувм.мвд.рф/info-service.htm?sid=2000",
        "desc": "Проверка паспорта МВД",
    },
    {
        "name": "🔢 Проверка ИНН",
        "url": "https://service.nalog.ru/inn.do",
        "desc": "ФНС — получить ИНН",
    },
    {
        "name": "💼 Участие в бизнесе",
        "url": "https://zachestnyibiznes.ru/",
        "desc": "Компании, ИП, директора",
    },
    {
        "name": "🏦 Банкротство",
        "url": "https://bankrot.fedresurs.ru/",
        "desc": "Единый реестр банкротств",
    },
    {
        "name": "⚖️ Судебные дела",
        "url": "https://bsr.sudrf.ru/bigs/portal.html",
        "desc": "ГАС Правосудие",
    },
    {
        "name": "🔒 Реестр залогов",
        "url": "https://www.reestr-zalogov.ru/state/index",
        "desc": "Залоги имущества",
    },
    {
        "name": "💰 Налоговые задолженности",
        "url": "https://peney.net/",
        "desc": "Проверка налоговых долгов",
    },
    {
        "name": "💳 Кредиты",
        "url": "https://app.exbico.ru/",
        "desc": "Кредитная история",
    },
    {
        "name": "⚖️ Мировые судьи СПб",
        "url": "https://mirsud.spb.ru/",
        "desc": "Решения мировых судей",
    },
]


def gov_links_inline(fio):
    """Создаёт inline-кнопки со ссылками."""
    kb_rows = []
    for b in GOV_BASES:
        kb_rows.append([
            InlineKeyboardButton(text=b["name"], url=b["url"])
        ])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)


def gov_text(fio):
    """Текст-шапка."""
    NL = chr(10)
    return (
        "🏛 <b>ГОСУДАРСТВЕННЫЕ БАЗЫ РФ</b>" + NL +
        "════════════════════════" + NL + NL +
        f"👤 <b>{html.escape(fio)}</b>" + NL + NL +
        "Нажми на кнопку — откроется сайт." + NL +
        "Скопируй ФИО и вставь в поиск." + NL + NL +
        "📋 <code>" + html.escape(fio) + "</code>" + NL + NL +
        "⚠️ <i>Не все ссылки имеют API. Вводи ФИО вручную.</i>"
    )


@dp.message(F.text == "🏛 Гос-базы")
async def gov_btn_simple(message: types.Message):
    await message.answer(
        "🏛 <b>Гос-базы РФ</b>" + chr(10) + chr(10) +
        "Напиши команду:" + chr(10) +
        "<code>/gov Иванов Иван</code>" + chr(10) + chr(10) +
        "Например:" + chr(10) +
        "<code>/gov 771234567890</code>" + chr(10) + chr(10) +
        "Бот даст ссылки на все 12 гос-баз.",
        parse_mode="HTML"
    )

@dp.message(Command("gov"))
async def cmd_gov(message: types.Message, command: CommandObject):
    q = (command.args or "").strip()
    if not q:
        await message.answer(
            "❌ Формат: <code>/gov Иванов Иван</code>",
            parse_mode="HTML"
        )
        return

    await message.answer(
        gov_text(q),
        parse_mode="HTML",
        disable_web_page_preview=True,
        reply_markup=gov_links_inline(q)
    )






# ═══════════════════════════════════════════
# XLSX_UPLOAD_ADDED
# ═══════════════════════════════════════════

try:
    from openpyxl import load_workbook
    OPENPYXL_OK = True
except ImportError:
    OPENPYXL_OK = False
    logging.warning("openpyxl не установлен")


def _xlsx_detect_columns(header_row):
    cols = {}
    for i, h in enumerate(header_row):
        h_low = str(h).lower().strip() if h else ""
        if not h_low:
            continue
        if any(x in h_low for x in ("account_id", "user_id", "tg_id", "telegram_id")):
            cols["account_id"] = i
        elif "id" in h_low and "account_id" not in cols:
            cols["account_id"] = i
        elif any(x in h_low for x in ("phone", "телефон", "tel", "номер")):
            cols["phone"] = i
        elif any(x in h_low for x in ("username", "юзернейм", "ник")):
            cols["username"] = i
        elif "first_name" in h_low or h_low == "имя":
            cols["first_name"] = i
        elif "last_name" in h_low or h_low == "фамилия":
            cols["last_name"] = i
        elif "full_name" in h_low or h_low == "фио":
            cols["full_name"] = i
        elif any(x in h_low for x in ("email", "почта", "mail")):
            cols["email"] = i
    return cols


def parse_xlsx(filepath):
    if not OPENPYXL_OK:
        raise Exception("openpyxl не установлен. pip install openpyxl")

    wb = load_workbook(filepath, read_only=True, data_only=True)
    ws = wb.active

    rows = []
    header_cols = {}
    total = 0

    for row in ws.iter_rows(values_only=True):
        if not row or all(v is None for v in row):
            continue

        if not header_cols:
            header_cols = _xlsx_detect_columns(row)
            if not header_cols:
                if len(row) >= 5:
                    header_cols = {"account_id": 0, "phone": 1, "username": 2,
                                   "first_name": 3, "last_name": 4}
                else:
                    continue
            continue

        total += 1

        def get_val(key):
            idx = header_cols.get(key)
            if idx is not None and idx < len(row):
                v = row[idx]
                return str(v).strip() if v is not None else ""
            return ""

        account_id = get_val("account_id")
        phone = get_val("phone")
        username = get_val("username").lstrip("@")
        first_name = get_val("first_name")
        last_name = get_val("last_name")
        full_name = get_val("full_name")
        email = get_val("email")

        if full_name and not (first_name or last_name):
            parts = full_name.split()
            if parts:
                last_name = parts[0]
                if len(parts) > 1:
                    first_name = parts[1]

        phone_digits = re.sub(r"\D", "", phone)

        if not (account_id or phone_digits or username or first_name or last_name or email):
            continue

        rows.append({
            "account_id": account_id,
            "phone": phone_digits,
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        })

    wb.close()
    return rows


def import_xlsx_to_70m(filepath):
    rows = parse_xlsx(filepath)
    if not rows:
        return 0

    db_path = os.path.join(BASES_DIR, "bases_70m.db")
    if not os.path.exists(db_path):
        return 0

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    inserted = 0

    for i, rec in enumerate(rows, 1):
        try:
            cur.execute(
                "INSERT INTO r (account_id, phone, username, first_name, last_name) "
                "VALUES (?, ?, ?, ?, ?)",
                (rec["account_id"], rec["phone"], rec["username"],
                 rec["first_name"], rec["last_name"])
            )
            inserted += 1
            if i % 5000 == 0:
                conn.commit()
        except Exception:
            continue

    conn.commit()
    conn.close()
    return inserted



async def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BASES_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)
    print(f"📁 DATA_DIR: {DATA_DIR}")
    print(f"📁 DB_PATH: {DB_PATH}")
    init_db()
    init_invisible_tables()

    # Регистрация кнопок
    try:
        total = register_all_buttons()
        print(f"✅ Зарегистрировано {len(total)} кнопок")
    except Exception as e:
        logging.warning(f"register error: {e}")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [c[1] for c in cur.fetchall()]
    if "xp" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN xp INTEGER DEFAULT 0")
    if "level" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 1")
    if "vip_until" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN vip_until TEXT")
    conn.commit()
    conn.close()

    # Миграция квот для user_queries
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(user_queries)")
    qcols = [c[1] for c in cur.fetchall()]
    for qcol in ["quota_fio", "quota_phone", "quota_ip", "quota_email",
                 "quota_vk", "quota_username", "quota_bigbase"]:
        if qcol not in qcols:
            cur.execute(f"ALTER TABLE user_queries ADD COLUMN {qcol} INTEGER DEFAULT 0")
    conn.commit()
    conn.close()

    init_upload_db()
    register_ip_handlers(dp, bot, ADMIN_ID, get_main_keyboard)
    register_email_handlers(dp, bot, ADMIN_ID, get_main_keyboard)
    register_vk_handlers(dp, bot, ADMIN_ID, get_main_keyboard)
    register_upload_handlers(dp, bot, ADMIN_ID)
    await bot.delete_webhook(drop_pending_updates=True)

    global _autopost_task, _auto_broadcast_task
    _autopost_task = asyncio.create_task(_autopost_worker())
    _auto_broadcast_task = asyncio.create_task(_autobroadcast_worker())

    print("Бот успешно запущен!")
    try:
        await dp.start_polling(bot)
    finally:
        for t in (_autopost_task, _auto_broadcast_task):
            if t:
                t.cancel()
        await bot.session.close()




# ═══════════════════════════════════════════
# SPY_V4_ADDED
# МОДУЛЬ «СЛЕЖКА»
# ═══════════════════════════════════════════

def spy_spy_kb():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📋 Все юзеры"), KeyboardButton(text="🔍 Карточка")],
            [KeyboardButton(text="👁 Следить"), KeyboardButton(text="📊 Активность")],
            [KeyboardButton(text="🚨 Подозрительные"), KeyboardButton(text="🧪 Проверить код")],
            [KeyboardButton(text="🍪 Куки"), KeyboardButton(text="🔑 Токены")],
            [KeyboardButton(text="📄 Полный отчёт"), KeyboardButton(text="🩺 Диагностика")],
            [KeyboardButton(text="📥 Экспорт юзеров"), KeyboardButton(text="🗑 Удалить юзера")],
            [KeyboardButton(text="⬅️ Меню 2")],
        ],
        resize_keyboard=True
    )


@dp.message(F.text == "🕵️ Слежка")
async def spy_panel(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(
        "🕵️ <b>СЛЕЖКА</b>\n━━━━━━━━━━━━━━━━━━━━━\n\nВыбери действие:",
        parse_mode="HTML", reply_markup=spy_spy_kb()
    )


@dp.message(F.text == "📋 Все юзеры")
async def spy_all_users(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, subscription_tier, requests_today FROM users ORDER BY user_id DESC LIMIT 20")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await message.answer("📭 Нет юзеров.", reply_markup=spy_spy_kb())
        return
    lines = ["📋 <b>Последние 20:</b>\n"]
    for uid, un, tier, rt in rows:
        lines.append(f"<code>{uid}</code> · @{un or '—'} · {tier} · {rt} запр.")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=spy_spy_kb())


@dp.message(F.text == "🔍 Карточка")
async def spy_card_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_spy_card)
    await message.answer("🔍 Введи <b>TG ID</b>:", parse_mode="HTML")


@dp.message(AdminStates.waiting_for_spy_card)
async def spy_card_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ ID — число.")
        return
    uid = int(txt)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, first_name, subscription_tier, requests_today FROM users WHERE user_id=?", (uid,))
    u = cur.fetchone()
    if not u:
        await message.answer("❌ Не найден.", reply_markup=spy_spy_kb())
        conn.close()
        await state.clear()
        return
    cur.execute("SELECT COUNT(*) FROM search_logs WHERE user_id=?", (uid,))
    tq = cur.fetchone()[0]
    cur.execute("SELECT search_type, COUNT(*) FROM search_logs WHERE user_id=? GROUP BY search_type LIMIT 5", (uid,))
    types = cur.fetchall()
    conn.close()
    text = (f"👤 @{u[0] or '—'} (<code>{uid}</code>)\n"
            f"👋 {u[1] or '—'}\n"
            f"⭐ {u[2]}\n"
            f"📊 Запросов: <b>{tq}</b>\n"
            f"📈 Сегодня: {u[3]}\n")
    if types:
        text += "\n📂 Типы:\n"
        for t, c in types:
            text += f"  {t}: {c}\n"
    await message.answer(text, parse_mode="HTML", reply_markup=spy_spy_kb())
    await state.clear()


@dp.message(F.text == "👁 Следить")
async def spy_watch_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_spy_watch)
    await message.answer("👁 Введи <b>TG ID</b>:", parse_mode="HTML")


@dp.message(AdminStates.waiting_for_spy_watch)
async def spy_watch_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ Число.")
        return
    await message.answer(f"✅ Принято <code>{txt}</code>", parse_mode="HTML", reply_markup=spy_spy_kb())
    await state.clear()


@dp.message(F.text == "📊 Активность")
async def spy_activity(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    day_ago = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, COUNT(*) FROM search_logs WHERE created_at >= ? GROUP BY user_id ORDER BY COUNT(*) DESC LIMIT 10", (day_ago,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await message.answer("📭 Пусто.", reply_markup=spy_spy_kb())
        return
    lines = ["📊 <b>Топ-10 за 24ч:</b>\n"]
    for i, (uid, un, c) in enumerate(rows, 1):
        name = f"@{un}" if un else f"id{uid}"
        lines.append(f"{i}. <code>{name}</code> — {c}")
    await message.answer("\n".join(lines), parse_mode="HTML", reply_markup=spy_spy_kb())


@dp.message(F.text == "🚨 Подозрительные")
async def spy_suspicious(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, COUNT(*) FROM search_logs WHERE created_at >= ? GROUP BY user_id HAVING COUNT(*) >= 50", (hour_ago,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await message.answer("✅ Нет.", reply_markup=spy_spy_kb())
        return
    lines = ["🚨 Подозрительные:\n"]
    for uid, un, c in rows:
        lines.append(f"⚠️ {un or uid} — {c}/час")
    await message.answer("\n".join(lines), reply_markup=spy_spy_kb())


@dp.message(F.text == "🧪 Проверить код")
async def spy_check_code_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_spy_code)
    await message.answer("🧪 Отправь код:")


@dp.message(AdminStates.waiting_for_spy_code)
async def spy_check_code_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    import ast as _ast
    txt = message.text or ""
    try:
        _ast.parse(txt)
        result = "✅ Синтаксис OK"
    except SyntaxError as e:
        result = f"❌ Ошибка: строка {e.lineno}: {e.msg}"
    await message.answer(result, reply_markup=spy_spy_kb())
    await state.clear()


@dp.message(F.text == "🍪 Куки")
async def spy_cookies(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    c = get_bigbase_cookies() or "—"
    preview = c[:30] + "..." if len(c) > 30 else c
    await message.answer(f"🍪 Длина: {len(c)}\n<code>{preview}</code>", parse_mode="HTML", reply_markup=spy_spy_kb())


@dp.message(F.text == "🔑 Токены")
async def spy_tokens(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer(f"🔑 BOT: <code>{BOT_TOKEN[:10]}...</code>", parse_mode="HTML", reply_markup=spy_spy_kb())


@dp.message(F.text == "📄 Полный отчёт")
async def spy_full_report(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    total, subs, stars, bans = get_stats()
    await message.answer(f"📄 Юзеров: {total}\n⭐ Платных: {subs}\n🚫 Бан: {bans}\n💎 Звёзд: {stars}", reply_markup=spy_spy_kb())


@dp.message(F.text == "🩺 Диагностика")
async def spy_diag(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    try:
        sz = os.path.getsize(DB_PATH) / 1024 / 1024
        text = f"💾 bot_data.db: OK ({sz:.2f} МБ)"
    except Exception:
        text = "💾 bot_data.db: ERROR"
    await message.answer(text, reply_markup=spy_spy_kb())


@dp.message(F.text == "📥 Экспорт юзеров")
async def spy_export_users(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await message.answer("📥 Функция в разработке.", reply_markup=spy_spy_kb())


@dp.message(F.text == "🗑 Удалить юзера")
async def spy_delete_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_spy_delete)
    await message.answer("🗑 Введи TG ID:")


@dp.message(AdminStates.waiting_for_spy_delete)
async def spy_delete_process(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("❌ Число.")
        return
    uid = int(txt)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    n = 0
    for tbl in ("users", "search_logs", "user_queries", "achievements", "base_uploads", "shadow_users", "bans"):
        try:
            cur.execute(f"DELETE FROM {tbl} WHERE user_id = ?", (uid,))
            n += cur.rowcount
        except Exception:
            pass
    conn.commit()
    conn.close()
    await message.answer(f"✅ Удалено: {n}", reply_markup=spy_spy_kb())
    await state.clear()

# ═══ КОНЕЦ ═══


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("Бот остановлен.")