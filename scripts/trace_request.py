"""Traza local de una solicitud desde la entrada HTTP hasta la decisión de acceso.

Instrumentación propia con sys.setprofile: registra las llamadas a funciones del
paquete `app` mientras se atiende UNA solicitud. No es IAST; es una traza local
para documentar el recorrido interno (guía 3.3c).

Uso (desde la carpeta secure/):  python ../scripts/trace_request.py
"""
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.getcwd())
os.environ.setdefault("APP_SECRET_KEY", "k" * 48)
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "trace.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

APP_DIR = os.path.join(os.getcwd(), "app") + os.sep
events = []
recording = False


def profiler(frame, event, arg):
    path = frame.f_code.co_filename
    if recording and event == "call" and path.startswith(APP_DIR):
        name = os.path.relpath(path, os.getcwd())
        events.append((name, frame.f_lineno, frame.f_code.co_name))


# El perfilador debe instalarse ANTES de crear el cliente para que lo hereden los
# hilos que atienden la solicitud; `recording` limita el registro a una solicitud.
threading.setprofile(profiler)
sys.setprofile(profiler)


def start():
    global recording
    recording = True


def stop():
    global recording
    recording = False


def login(client, user, pwd):
    r = client.post("/auth/login", json={"username": user, "password": pwd})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


with TestClient(app) as client:
    alice = login(client, "alice", "alice-pass-123")
    bob = login(client, "bob", "bob-pass-123")
    bob_note = client.get("/notes", headers=bob).json()[0]["id"]

    for titulo, headers in (("alice pide la nota de bob", alice), ("bob pide su propia nota", bob)):
        events.clear()
        start()
        r = client.get(f"/notes/{bob_note}", headers=headers)
        stop()
        print(f"\n=== Solicitud: GET /notes/{bob_note} — {titulo} ===")
        for i, (f, line, fn) in enumerate(events, 1):
            print(f"{i:>2}. {f}:{line}  {fn}()")
        print(f"Respuesta: HTTP {r.status_code}")
