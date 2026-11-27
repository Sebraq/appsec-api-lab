import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", "x" * 48)  # clave de prueba, no real
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    with TestClient(app) as c:
        yield c


def auth(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
