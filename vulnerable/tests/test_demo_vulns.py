"""Reproducciones del estado ANTES de la remediación. Estas pruebas PASAN porque
la vulnerabilidad existe; no se incluyen en el pipeline de la versión corregida."""
from conftest import auth


def test_bola_alice_reads_bobs_note(client):
    alice = auth(client, "alice", "alice-pass-123")
    bob = auth(client, "bob", "bob-pass-123")
    bob_note = client.get("/notes", headers=bob).json()[0]["id"]
    r = client.get(f"/notes/{bob_note}", headers=alice)
    assert r.status_code == 200  # debería ser 403


def test_sqli_search_returns_other_users_notes(client):
    alice = auth(client, "alice", "alice-pass-123")
    r = client.get("/notes/search", params={"q": "' OR 1=1 --"}, headers=alice)
    assert len(r.json()) == 4  # alice tiene 2; devuelve las 4 de la BD


def test_regular_user_lists_admin_users(client):
    alice = auth(client, "alice", "alice-pass-123")
    r = client.get("/admin/users", headers=alice)
    assert r.status_code == 200  # debería ser 403


def test_forged_admin_token_with_hardcoded_secret(client):
    import jwt

    forged = jwt.encode({"sub": "3"}, "secret123", algorithm="HS256")  # sub 3 = admin
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 200  # sin conocer la contraseña de admin
