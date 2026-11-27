"""API REST de notas por usuario — VERSIÓN CORREGIDA."""
from contextlib import asynccontextmanager

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from . import db, security


@asynccontextmanager
async def lifespan(app: FastAPI):
    security.check_config()
    db.init_db()
    yield


app = FastAPI(title="Notes API (secure)", version="1.0.0", lifespan=lifespan)
bearer = HTTPBearer(auto_error=False)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    content: str = Field(max_length=2000)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    conn=Depends(db.get_db),
):
    if creds is None:
        raise _unauthorized("Autenticación requerida")
    try:
        user_id = int(security.decode_token(creds.credentials)["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _unauthorized("Token inválido o expirado")
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        raise _unauthorized("Token inválido o expirado")
    return user


def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Se requiere rol admin")
    return user


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login(body: LoginIn, conn=Depends(db.get_db)):
    user = conn.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (body.username,)
    ).fetchone()
    if user is None or not security.verify_password(body.password, user["password_hash"]):
        raise _unauthorized("Credenciales inválidas")
    return {"access_token": security.create_token(user["id"]), "token_type": "bearer"}


@app.get("/me")
def me(user=Depends(current_user)):
    return dict(user)


@app.get("/notes")
def list_notes(user=Depends(current_user), conn=Depends(db.get_db)):
    rows = conn.execute(
        "SELECT id, title, content FROM notes WHERE owner_id = ?", (user["id"],)
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/notes", status_code=201)
def create_note(body: NoteIn, user=Depends(current_user), conn=Depends(db.get_db)):
    cur = conn.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (user["id"], body.title, body.content),
    )
    conn.commit()
    return {"id": cur.lastrowid, "title": body.title, "content": body.content}


# Debe declararse antes de /notes/{note_id}
@app.get("/notes/search")
def search_notes(
    q: str = Query(min_length=1, max_length=50),
    user=Depends(current_user),
    conn=Depends(db.get_db),
):
    rows = conn.execute(
        "SELECT id, title, content FROM notes WHERE owner_id = ? AND title LIKE ?",
        (user["id"], f"%{q}%"),
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user), conn=Depends(db.get_db)):
    note = conn.execute(
        "SELECT id, owner_id, title, content FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if note is None:
        raise HTTPException(404, "Nota no encontrada")
    if note["owner_id"] != user["id"]:
        raise HTTPException(403, "No tienes acceso a este recurso")
    return dict(note)


@app.get("/admin/users")
def admin_list_users(_=Depends(require_admin), conn=Depends(db.get_db)):
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    return [dict(r) for r in rows]
