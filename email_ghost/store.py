import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "ghost.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY, created TEXT NOT NULL, run_id TEXT NOT NULL,
                    digest TEXT NOT NULL, raw BLOB NOT NULL, envelope TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS messages_run ON messages(run_id, created);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, created TEXT NOT NULL, action TEXT NOT NULL,
                    message_id TEXT, details TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY, message_id TEXT NOT NULL, provider TEXT NOT NULL,
                    label TEXT NOT NULL, source TEXT NOT NULL, created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audits (
                    id TEXT PRIMARY KEY, message_id TEXT NOT NULL, created TEXT NOT NULL,
                    report TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS audit_message ON audits(message_id, created);
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    def event(self, action, message_id=None, **details):
        with self.connect() as db:
            db.execute("INSERT INTO events(created, action, message_id, details) VALUES(?,?,?,?)",
                       (datetime.now(timezone.utc).isoformat(), action, message_id, json.dumps(details)))

    def add(self, raw, run_id="default", envelope=None):
        ident = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)", (
                ident, datetime.now(timezone.utc).isoformat(), run_id,
                hashlib.sha256(raw).hexdigest(), raw, json.dumps(envelope or {})))
        self.event("message.captured", ident, run_id=run_id)
        return ident

    def get(self, ident):
        with self.connect() as db:
            row = db.execute("SELECT * FROM messages WHERE id=?", (ident,)).fetchone()
        if row is None:
            raise KeyError(ident)
        result = dict(row)
        result["envelope"] = json.loads(result["envelope"])
        return result

    def list(self, run_id=None, limit=50, offset=0):
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT id,created,run_id,digest FROM messages WHERE (? IS NULL OR run_id=?) "
                "ORDER BY created DESC LIMIT ? OFFSET ?", (run_id, run_id, limit, offset))]

    def delete(self, ident):
        with self.connect() as db:
            count = db.execute("DELETE FROM messages WHERE id=?", (ident,)).rowcount
        if not count:
            raise KeyError(ident)
        self.event("message.deleted", ident)

    def events(self, limit=100):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def learning_revision(self):
        with self.connect() as db:
            row = db.execute("SELECT MAX(id) FROM events WHERE action='spam.learning' AND json_extract(details, '$.learned')=1").fetchone()
        return str(row[0] or 0)

    def feedback(self, ident, provider, label, source):
        self.get(ident)
        with self.connect() as db:
            db.execute("INSERT INTO feedback(message_id,provider,label,source,created) VALUES(?,?,?,?,?)",
                       (ident, provider, label, source, datetime.now(timezone.utc).isoformat()))
        self.event("feedback.recorded", ident, provider=provider, label=label)

    def save_audit(self, ident, report):
        audit_id = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("INSERT INTO audits VALUES(?,?,?,?)", (audit_id, ident, datetime.now(timezone.utc).isoformat(), json.dumps(report)))
        return audit_id

    def calibration_examples(self, provider=None, limit=10000):
        with self.connect() as db:
            rows = db.execute("""SELECT f.*, m.digest, m.run_id,
                (SELECT a.report FROM audits a WHERE a.message_id=f.message_id AND a.created<=f.created ORDER BY a.created DESC LIMIT 1) AS report,
                (SELECT a.created FROM audits a WHERE a.message_id=f.message_id AND a.created<=f.created ORDER BY a.created DESC LIMIT 1) AS audited_at
                FROM feedback f JOIN messages m ON m.id=f.message_id
                WHERE (? IS NULL OR f.provider=?) AND f.id=(SELECT MAX(f2.id) FROM feedback f2 WHERE f2.message_id=f.message_id AND f2.provider=f.provider)
                ORDER BY f.created LIMIT ?""", (provider, provider, limit)).fetchall()
        records, omitted = [], 0
        from email.utils import parseaddr
        from .analysis import parse
        for row in rows:
            if not row["report"]:
                omitted += 1
                continue
            parsed = parse(self.get(row["message_id"])["raw"])
            records.append({"label": row["label"], "provider": row["provider"], "source": row["source"],
                "message_digest": row["digest"], "timestamp": row["audited_at"], "campaign_id": row["run_id"],
                "sender_domain": parseaddr(parsed["from"])[1].rpartition("@")[2].lower(),
                "report": json.loads(row["report"])})
        return {"records": records, "omitted_without_contemporaneous_audit": omitted}
