"""⚠️ API DELIBERADAMENTE VULNERABLE — SOLO LABORATORIO LOCAL, NUNCA EXPONER A INTERNET ⚠️"""
from contextlib import asynccontextmanager

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from . import db, security


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="Notes API (VULNERABLE - LAB ONLY)", version="0.1.0", lifespan=lifespan)
bearer = HTTPBearer(auto_error=False)


class LoginIn(BaseModel):
    username: str
    password: str


class NoteIn(BaseModel):
    title: str
    content: str


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    conn=Depends(db.get_db),
):
    if creds is None:
        raise HTTPException(401, "Autenticación requerida")
    try:
        user_id = int(security.decode_token(creds.credentials)["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(401, "Token inválido")
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        raise HTTPException(401, "Token inválido")
    return user


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login(body: LoginIn, conn=Depends(db.get_db)):
    user = conn.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (body.username,)
    ).fetchone()
    if user is None:
        raise HTTPException(401, "Usuario no existe")  # DEFECTO: enumeración de usuarios
    if not security.verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Contraseña incorrecta")
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


@app.get("/notes/search")
def search_notes(q: str, user=Depends(current_user), conn=Depends(db.get_db)):
    # DEFECTO (inyección SQL): la entrada del cliente se concatena en la consulta
    query = (
        "SELECT id, title, content FROM notes "
        f"WHERE owner_id = {user['id']} AND title LIKE '%{q}%'"
    )
    rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user), conn=Depends(db.get_db)):
    note = conn.execute(
        "SELECT id, owner_id, title, content FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if note is None:
        raise HTTPException(404, "Nota no encontrada")
    # DEFECTO (BOLA/IDOR): no se verifica que note.owner_id == user.id
    return dict(note)


@app.get("/admin/users")
def admin_list_users(user=Depends(current_user), conn=Depends(db.get_db)):
    # DEFECTO (autorización por función): cualquier usuario autenticado accede
    rows = conn.execute("SELECT id, username, role, password_hash FROM users").fetchall()
    return [dict(r) for r in rows]
