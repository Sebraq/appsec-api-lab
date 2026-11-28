"""Reproduce los defectos confirmados contra una API en ejecución y emite un veredicto.

Se ejecuta con las MISMAS solicitudes y los MISMOS datos contra la versión vulnerable
(antes) y la corregida (después), para que la comparación sea en condiciones equivalentes.

Uso: python scripts/repro_defects.py http://127.0.0.1:9000
Solo para el laboratorio local.
"""
import sys

import httpx
import jwt

base = sys.argv[1].rstrip("/")
c = httpx.Client(base_url=base, timeout=10)


def login(user, pwd):
    r = c.post("/auth/login", json={"username": user, "password": pwd})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


alice = login("alice", "alice-pass-123")
bob = login("bob", "bob-pass-123")
bob_note = c.get("/notes", headers=bob).json()[0]
alice_note = c.get("/notes", headers=alice).json()[0]
rows = []


def record(defect, request, status, observation, vulnerable):
    if "positiva" in defect:
        verdict = "ROTO" if vulnerable else "FUNCIONA"
    else:
        verdict = "VULNERABLE" if vulnerable else "CORREGIDO"
    rows.append((defect, request, status, observation, verdict))


# D1 BOLA/IDOR: alice pide la nota de bob
r = c.get(f"/notes/{bob_note['id']}", headers=alice)
leak = bob_note["content"] in r.text
record("D1 BOLA", f"alice GET /notes/{bob_note['id']} (nota de bob)", r.status_code,
       "devuelve el contenido de bob" if leak else "sin contenido de bob", leak)
# uso legítimo preservado
r = c.get(f"/notes/{alice_note['id']}", headers=alice)
record("D1 positiva", f"alice GET /notes/{alice_note['id']} (nota propia)", r.status_code,
       "uso legítimo", r.status_code != 200)

# D2 Inyección SQL en /notes/search
payload = "' OR 1=1 --"
r = c.get("/notes/search", params={"q": payload}, headers=alice)
n = len(r.json()) if r.status_code == 200 else 0
foreign = r.status_code == 200 and any(bob_note["content"] in x.get("content", "") for x in r.json())
record("D2 SQLi", f"alice GET /notes/search?q={payload}", r.status_code,
       f"{n} notas, incluye notas ajenas" if foreign else f"{n} notas devueltas", foreign)
r = c.get("/notes/search", params={"q": "compras"}, headers=alice)
ok = r.status_code == 200 and len(r.json()) == 1
record("D2 positiva", "alice GET /notes/search?q=compras", r.status_code,
       "1 nota propia" if ok else "resultado inesperado", not ok)

# D3 Acceso por función: usuario normal llama /admin/users
r = c.get("/admin/users", headers=alice)
record("D3 BFLA", "alice GET /admin/users", r.status_code,
       "lista usuarios" if r.status_code == 200 else "acceso denegado", r.status_code == 200)

# D4 Secreto JWT hardcodeado: token de admin firmado con la clave del código vulnerable
forged = jwt.encode({"sub": "3"}, "secret123", algorithm="HS256")
r = c.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
record("D4 JWT", "GET /admin/users con token forjado", r.status_code,
       "acepta el token forjado" if r.status_code == 200 else "token rechazado", r.status_code == 200)

print(f"Objetivo: {base}\n")
print(f"{'Defecto':<12}{'Solicitud':<52}{'HTTP':<6}{'Observación':<34}Veredicto")
for d, req, st, obs, v in rows:
    print(f"{d:<12}{req:<52}{st:<6}{obs:<34}{v}")
