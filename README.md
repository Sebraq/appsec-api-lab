# AppSec API Lab

API REST de notas (FastAPI + SQLite) para la Actividad Integradora de Seguridad en Aplicaciones (MASI, UMG).
Todo corre en local con cuentas y datos ficticios.

```
appsec-api-lab/
├── secure/        # versión corregida (la que se evalúa y se libera)
└── vulnerable/    # ⚠️ versión deliberadamente vulnerable, solo laboratorio
```

> ⚠️ `vulnerable/` es solo para demostrar el "antes" de la remediación. Se ejecuta únicamente en `127.0.0.1`, nunca se expone a Internet.

## Requisitos
Linux, Python 3.11+, git.

## Instalación (desde la raíz del repo)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r secure/requirements-dev.txt
```

## Ejecutar la versión segura
```bash
cd secure
export APP_SECRET_KEY=$(openssl rand -hex 32)
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Docs interactivas: http://127.0.0.1:8000/docs

## Ejecutar la versión vulnerable (aislada)
```bash
cd vulnerable
uvicorn app.main:app --host 127.0.0.1 --port 9000
```

## Pruebas
```bash
cd secure && python -m pytest -q        # controles de la versión corregida
cd ../vulnerable && python -m pytest -q # reproduce los defectos (pasan = vulnerabilidad presente)
```

## Usuarios ficticios
| Usuario | Contraseña | Rol |
|---|---|---|
| alice | alice-pass-123 | user |
| bob | bob-pass-123 | user |
| admin | admin-pass-123 | admin |

## Endpoints
| Método | Ruta | Acceso |
|---|---|---|
| POST | /auth/login | público |
| GET | /health | público |
| GET | /me | autenticado |
| GET, POST | /notes | autenticado (solo notas propias) |
| GET | /notes/search?q= | autenticado (entrada del cliente) |
| GET | /notes/{id} | autenticado, solo dueño |
| GET | /admin/users | solo rol admin |

## Defectos sembrados en `vulnerable/`
BOLA/IDOR en `/notes/{id}`, inyección SQL en `/notes/search`, falta de control de rol en `/admin/users`, secreto JWT hardcodeado, MD5 sin sal, tokens sin expiración y enumeración de usuarios en login.

## Fase 2: SAST, SCA y SBOM
```bash
pip install -r requirements-tools.txt
./scripts/run_semgrep.sh        # prueba las reglas y escanea ambas versiones
./scripts/run_sca_sbom.sh       # pip-audit + SBOM CycloneDX validado
python scripts/sbom_who_uses.py sbom/sbom-secure.cdx.json starlette
```
Resultados en `reports/` y `sbom/`; análisis en `docs/fase2-sast-sca-sbom.md`.
