"""Pruebas de humo de la Fase 0. Las pruebas formales (3.3) se arman en la Fase 3."""
from conftest import auth


def test_login_and_own_note(client):
    h = auth(client, "alice", "alice-pass-123")
    notes = client.get("/notes", headers=h).json()
    assert len(notes) == 2
    assert client.get(f"/notes/{notes[0]['id']}", headers=h).status_code == 200


def test_other_users_note_denied(client):
    alice = auth(client, "alice", "alice-pass-123")
    bob = auth(client, "bob", "bob-pass-123")
    bob_note = client.get("/notes", headers=bob).json()[0]["id"]
    assert client.get(f"/notes/{bob_note}", headers=alice).status_code == 403


def test_no_token_is_401(client):
    assert client.get("/notes").status_code == 401


def test_admin_endpoint_requires_admin(client):
    alice = auth(client, "alice", "alice-pass-123")
    admin = auth(client, "admin", "admin-pass-123")
    assert client.get("/admin/users", headers=alice).status_code == 403
    assert client.get("/admin/users", headers=admin).status_code == 200


def test_search_injection_stays_scoped(client):
    alice = auth(client, "alice", "alice-pass-123")
    r = client.get("/notes/search", params={"q": "' OR 1=1 --"}, headers=alice)
    assert r.status_code == 200 and r.json() == []
