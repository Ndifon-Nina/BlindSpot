import sqlite3

from flask import g
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(Config.DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website_url TEXT NOT NULL,
            score INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            check_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        );
        """
    )
    db.commit()


def create_user(name, email, password):
    password_hash = generate_password_hash(password)
    db = get_db()
    db.execute(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        (name, email, password_hash),
    )
    db.commit()


def get_user_by_email(email):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def check_password(email, password):
    user = get_user_by_email(email)
    if user is None:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def create_scan(user_id, website_url, score):
    db = get_db()
    cursor = db.execute(
        "INSERT INTO scans (user_id, website_url, score) VALUES (?, ?, ?)",
        (user_id, website_url, score),
    )
    db.commit()
    return cursor.lastrowid


def add_finding(scan_id, check_type, severity, title, description, recommendation):
    db = get_db()
    db.execute(
        "INSERT INTO findings (scan_id, check_type, severity, title, description, recommendation) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, check_type, severity, title, description, recommendation),
    )
    db.commit()


def get_scan(scan_id):
    db = get_db()
    return db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def get_findings_for_scan(scan_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
    ).fetchall()


def get_scans_for_user(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()