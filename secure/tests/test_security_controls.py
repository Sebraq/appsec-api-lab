"""Pruebas automatizadas de controles de seguridad (Fase 3, sección 3.3b).

Cada prueba indica: condiciones de entrada, comportamiento esperado y el requisito
(R1 a R5, ver docs/fase1-caracterizacion.md) que comprueba. Las aserciones son
códigos HTTP y valores concretos, sin interpretación subjetiva.
"""
import base64
import json
import os
import time

import jwt
import pytest

from conftest import auth

ALICE = ("alice", "alice-pass-123")
BOB = ("bob", "bob-pass-123")
ADMIN = ("admin", "admin-pass-123")


def _first_note_id(client, headers):
    return client.get("/notes", headers=headers).json()[0]["id"]


# ---------- 1. Acceso legítimo a un recurso propio (R1, prueba positiva) ----------
def test_01_owner_can_read_own_note(client):
    """Entrada: alice con token propio pide una nota suya.
    Esperado: 200 y owner_id coincide con el id de alice."""
    h = auth(client, *ALICE)
    me = client.get("/me", headers=h).json()
    note_id = _first_note_id(client, h)
    r = client.get(f"/notes/{note_id}", headers=h)
    assert r.status_code == 200
    assert r.json()["owner_id"] == me["id"]


# ---------- 2. Denegación de acceso a un recurso ajeno (R1, prueba negativa) ----------
def test_02_user_cannot_read_other_users_note(client):
    """Entrada: alice pide una nota de bob. Esperado: 403 y sin contenido de la nota."""
    alice = auth(client, *ALICE)
    bob = auth(client, *BOB)
    bob_note = client.get("/notes", headers=bob).json()[0]
    r = client.get(f"/notes/{bob_note['id']}", headers=alice)
    assert r.status_code == 403
    assert bob_note["content"] not in r.text


def test_02b_nonexistent_note_is_404(client):
    """Entrada: id que no existe. Esperado: 404."""
    h = auth(client, *ALICE)
    assert client.get("/notes/999999", headers=h).status_code == 404


# ---------- 3. Solicitud sin autenticación válida (R4) ----------
def test_03_no_token_is_401(client):
    """Entrada: sin cabecera Authorization. Esperado: 401 con WWW-Authenticate."""
    r = client.get("/notes")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_03b_tampered_token_is_401(client):
    """Entrada: token firmado con otra clave. Esperado: 401."""
    forged = jwt.encode(
        {"sub": "3", "exp": int(time.time()) + 600}, "otra-clave-" * 5, algorithm="HS256"
    )
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_03c_expired_token_is_401(client):
    """Entrada: token con la clave correcta pero expirado. Esperado: 401."""
    expired = jwt.encode(
        {"sub": "1", "exp": int(time.time()) - 10},
        os.environ["APP_SECRET_KEY"],
        algorithm="HS256",
    )
    r = client.get("/notes", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


def test_03d_token_without_exp_is_401(client):
    """Entrada: token con la clave correcta pero sin exp. Esperado: 401."""
    no_exp = jwt.encode({"sub": "1"}, os.environ["APP_SECRET_KEY"], algorithm="HS256")
    r = client.get("/notes", headers={"Authorization": f"Bearer {no_exp}"})
    assert r.status_code == 401


def test_03e_alg_none_token_is_401(client):
    """Entrada: token sin firma (alg none) que pide ser admin. Esperado: 401."""
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': '3', 'exp': int(time.time()) + 600})}."
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_03f_login_error_does_not_reveal_which_part_failed(client):
    """Entrada: usuario inexistente vs. clave incorrecta. Esperado: misma respuesta."""
    a = client.post("/auth/login", json={"username": "nadie", "password": "x"})
    b = client.post("/auth/login", json={"username": "alice", "password": "mala"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


# ---------- 4. Validación de entradas inesperadas (R3, R5) ----------
@pytest.mark.parametrize(
    "payload",
    [
        {"title": "", "content": "x"},              # título vacío
        {"title": "t" * 101, "content": "x"},       # título demasiado largo
        {"title": "ok", "content": "c" * 2001},     # contenido demasiado largo
        {"title": "ok"},                            # falta content
        {"title": ["no", "es", "texto"], "content": "x"},  # tipo incorrecto
    ],
)
def test_04_invalid_note_is_422(client, payload):
    """Entrada: cuerpos inválidos al crear nota. Esperado: 422."""
    h = auth(client, *ALICE)
    assert client.post("/notes", json=payload, headers=h).status_code == 422


def test_04b_non_numeric_id_is_422(client):
    """Entrada: id no numérico en la ruta. Esperado: 422."""
    h = auth(client, *ALICE)
    assert client.get("/notes/abc", headers=h).status_code == 422


@pytest.mark.parametrize("q", ["", "a" * 51])
def test_04c_search_length_limits_are_422(client, q):
    """Entrada: búsqueda vacía o de más de 50 caracteres. Esperado: 422."""
    h = auth(client, *ALICE)
    assert client.get("/notes/search", params={"q": q}, headers=h).status_code == 422


def test_04d_sql_injection_payload_is_treated_as_data(client):
    """Entrada: ' OR 1=1 -- en la búsqueda. Esperado: 200 y lista vacía (no devuelve
    notas de otros usuarios ni notas propias)."""
    h = auth(client, *ALICE)
    r = client.get("/notes/search", params={"q": "' OR 1=1 --"}, headers=h)
    assert r.status_code == 200
    assert r.json() == []


def test_04e_search_only_returns_own_notes(client):
    """Entrada: búsqueda de 'Nota' como alice. Esperado: ninguna nota de bob/admin."""
    h = auth(client, *ALICE)
    me = client.get("/me", headers=h).json()["id"]
    client.post("/notes", json={"title": "Nota propia", "content": "x"}, headers=h)
    r = client.get("/notes/search", params={"q": "Nota"}, headers=h)
    assert r.status_code == 200
    ids_owned = {n["id"] for n in client.get("/notes", headers=h).json()}
    assert {n["id"] for n in r.json()} <= ids_owned
    assert len(r.json()) >= 1


# ---------- 5. Restricción de una operación según rol (R2) ----------
def test_05_admin_endpoint_by_role(client):
    """Entrada: /admin/users como admin, como alice y sin token.
    Esperado: 200, 403 y 401. La respuesta de admin no incluye hashes."""
    admin = auth(client, *ADMIN)
    alice = auth(client, *ALICE)
    ok = client.get("/admin/users", headers=admin)
    assert ok.status_code == 200
    assert {u["username"] for u in ok.json()} == {"alice", "bob", "admin"}
    assert "password_hash" not in ok.text
    assert client.get("/admin/users", headers=alice).status_code == 403
    assert client.get("/admin/users").status_code == 401


# ---------- Uso legítimo preservado ----------
def test_06_user_can_create_and_list_own_note(client):
    """Entrada: alice crea una nota válida. Esperado: 201 y aparece en su listado."""
    h = auth(client, *ALICE)
    r = client.post("/notes", json={"title": "Nueva", "content": "contenido"}, headers=h)
    assert r.status_code == 201
    assert r.json()["id"] in {n["id"] for n in client.get("/notes", headers=h).json()}


# ---------- Cabeceras de respuesta (alertas ZAP 10049, 10021 y 90004) ----------
@pytest.mark.parametrize("path,status", [("/health", 200), ("/ruta-que-no-existe", 404)])
def test_07_security_headers_present(client, path, status):
    """Entrada: respuestas 200 y 404. Esperado: las tres cabeceras de seguridad."""
    r = client.get(path)
    assert r.status_code == status
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
