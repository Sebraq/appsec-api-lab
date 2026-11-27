#!/usr/bin/env bash
# DAST: OWASP ZAP Baseline (pasivo) contra la versión segura, solo en local.
# Requisitos: Docker funcionando y el entorno virtual del proyecto activo. Ejecutar desde la raíz del repo.
set -euo pipefail
OUT="$(pwd)/reports/zap"
mkdir -p "$OUT" && chmod 777 "$OUT"      # el contenedor escribe como otro usuario

export APP_SECRET_KEY="$(openssl rand -hex 32)"
export DB_PATH="$(mktemp -d)/zap.db"
(cd secure && uvicorn app.main:app --host 127.0.0.1 --port 8000 >"$OUT/api.log" 2>&1) &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT

for i in $(seq 1 20); do
  curl -fs http://127.0.0.1:8000/health >/dev/null && break
  sleep 1
done

# --network host: el contenedor ve el 127.0.0.1 del equipo. -I: no falla por advertencias.
docker run --rm --network host -v "$OUT":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://127.0.0.1:8000 -I \
  -r zap-baseline-secure.html -J zap-baseline-secure.json -w zap-baseline-secure.md \
  | tee "$OUT/zap-baseline-console.txt"
