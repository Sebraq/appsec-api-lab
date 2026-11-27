import sqlite3


def vulnerable_fstring(conn, q):
    # ruleid: appsec-lab.sqli-dynamic-query
    conn.execute(f"SELECT * FROM notes WHERE title LIKE '%{q}%'")


def vulnerable_via_variable(conn, q, uid):
    query = (
        "SELECT * FROM notes "
        f"WHERE owner_id = {uid} AND title LIKE '%{q}%'"
    )
    # ruleid: appsec-lab.sqli-dynamic-query
    return conn.execute(query).fetchall()


def vulnerable_concat(conn, name):
    # ruleid: appsec-lab.sqli-dynamic-query
    conn.execute("SELECT * FROM users WHERE username = '" + name + "'")


def safe_parameterized(conn, q, uid):
    # ok: appsec-lab.sqli-dynamic-query
    return conn.execute(
        "SELECT * FROM notes WHERE owner_id = ? AND title LIKE ?", (uid, f"%{q}%")
    ).fetchall()


def safe_constant(conn):
    # ok: appsec-lab.sqli-dynamic-query
    return conn.execute("SELECT id, username FROM users").fetchall()
