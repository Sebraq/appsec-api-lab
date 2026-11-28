"""Pruebas de regresión de los defectos remediados en la Fase 4 (D1 a D4).

Cada defecto tiene al menos una prueba negativa (el abuso ya no es posible) y una
positiva (el uso legítimo se conserva). Si alguien reintroduce el defecto, fallan.
"""
import jwt
import pytest

from conftest import auth

ALICE = ("alice", "alice-pass-123")
BOB = ("bob", "bob-pass-123")


def _all_note_ids(client):
    """IDs de todas las notas que existen, consultando como cada dueño."""
    ids = {}
    for user in (ALICE, BOB, ("admin", "admin-pass-123")):
        h = auth(client, *user)
        for n in client.get("/notes", headers=h).json():
            ids[n["id"]] = user[0]
    return ids


# ---------- D1: BOLA/IDOR en /notes/{id} ----------
def test_d1_negative_no_note_of_another_owner_is_readable(client):
    """Entrada: alice pide TODAS las notas que no son suyas. Esperado: 403 en cada una."""
    alice = auth(client, *ALICE)
    foreign = {i: o for i, o in _all_note_ids(client).items() if o != "alice"}
    assert len(foreign) == 2  # nota de bob y nota de admin
    for note_id in foreign:
        assert client.get(f"/notes/{note_id}", headers=alice).status_code == 403


def test_d1_positive_owner_reads_every_own_note(client):
    """Entrada: alice pide cada nota propia. Esperado: 200 en todas."""
    alice = auth(client, *ALICE)
    own = [i for i, o in _all_note_ids(client).items() if o == "alice"]
    assert len(own) == 2
    for note_id in own:
        assert client.get(f"/notes/{note_id}", headers=alice).status_code == 200


# ---------- D2: inyección SQL en /notes/search ----------
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "%' OR '1'='1",
    "' UNION SELECT 1,username,role FROM users--",
    "'; DROP TABLE notes; --",
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_d2_negative_payload_is_treated_as_text(client, payload):
    """Entrada: cargas típicas de SQLi. Esperado: 200, lista vacía, sin error 500."""
    alice = auth(client, *ALICE)
    r = client.get("/notes/search", params={"q": payload}, headers=alice)
    assert r.status_code == 200
    assert r.json() == []


def test_d2_negative_tables_survive_the_drop_payload(client):
    """Entrada: payload DROP TABLE y luego lectura normal. Esperado: los datos siguen ahí."""
    alice = auth(client, *ALICE)
    client.get("/notes/search", params={"q": "'; DROP TABLE notes; --"}, headers=alice)
    assert len(client.get("/notes", headers=alice).json()) == 2


def test_d2_positive_legitimate_search_still_works(client):
    """Entrada: búsqueda normal 'compras'. Esperado: exactamente la nota propia."""
    alice = auth(client, *ALICE)
    r = client.get("/notes/search", params={"q": "compras"}, headers=alice)
    assert r.status_code == 200
    assert [n["title"] for n in r.json()] == ["Lista de compras"]


# ---------- D3: acceso por función en /admin/users ----------
def test_d3_negative_regular_user_cannot_list_users(client):
    alice = auth(client, *ALICE)
    assert client.get("/admin/users", headers=alice).status_code == 403


def test_d3_positive_admin_can_list_users(client):
    admin = auth(client, "admin", "admin-pass-123")
    assert client.get("/admin/users", headers=admin).status_code == 200


# ---------- D4: secreto JWT hardcodeado ----------
def test_d4_negative_token_signed_with_old_hardcoded_secret_is_rejected(client):
    forged = jwt.encode({"sub": "3"}, "secret123", algorithm="HS256")
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401
