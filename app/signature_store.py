import hashlib
import re
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_msg(s: str) -> str:
    if not s:
        return ""
    s = s.lower()
    s = re.sub(r"\d+", "", s)
    s = re.sub(r"[\"'`]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:500]


def make_signature(error_family: str, package_name: str, primary_error_message: str, sources_tasks: str = "") -> str:
    fam = (error_family or "").strip().upper()
    pkg = (package_name or "").strip().lower()
    msg = _normalize_msg(primary_error_message or "")
    src = _normalize_msg(sources_tasks or "")

    raw = f"fam={fam}||pkg={pkg}||msg={msg}||src={src}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SignatureStore:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                sig TEXT PRIMARY KEY,
                count INTEGER NOT NULL,
                first_seen_utc TEXT NOT NULL,
                last_seen_utc TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def bump(self, sig: str) -> None:
        now = _utc_now_iso()
        cur = self.conn.cursor()
        cur.execute("SELECT count FROM signatures WHERE sig = ?", (sig,))
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE signatures SET count = count + 1, last_seen_utc = ? WHERE sig = ?",
                (now, sig),
            )
        else:
            cur.execute(
                "INSERT INTO signatures(sig, count, first_seen_utc, last_seen_utc) VALUES(?, ?, ?, ?)",
                (sig, 1, now, now),
            )
        self.conn.commit()

    def top(self, limit: int = 20):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT sig, count, first_seen_utc, last_seen_utc FROM signatures ORDER BY count DESC, last_seen_utc DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()
