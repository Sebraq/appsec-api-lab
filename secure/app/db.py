"""Persistencia SQLite y datos ficticios de laboratorio."""
import os
import sqlite3

from . import security

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL
);
"""

# Cuentas y datos ficticios, solo para laboratorio.
SEED_USERS = [
    ("alice", "alice-pass-123", "user"),
    ("bob", "bob-pass-123", "user"),
    ("admin", "admin-pass-123", "admin"),
]
SEED_NOTES = [
    ("alice", "Lista de compras", "Leche, pan, café"),
    ("alice", "Idea de proyecto", "Revisar la API del laboratorio"),
    ("bob", "Nota privada de Bob", "Clave del wifi de la oficina: lab-only-1234"),
    ("admin", "Nota confidencial", "Plan de rotación de claves (dato ficticio)"),
]


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(os.environ.get("DB_PATH", "app.db"), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            for username, password, role in SEED_USERS:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, security.hash_password(password), role),
                )
            for owner, title, content in SEED_NOTES:
                conn.execute(
                    "INSERT INTO notes (owner_id, title, content) "
                    "VALUES ((SELECT id FROM users WHERE username = ?), ?, ?)",
                    (owner, title, content),
                )
            conn.commit()
    finally:
        conn.close()
