#!/usr/bin/env bash
# DAST pasivo con la definición OpenAPI (zap-api-scan.py -S: sin escaneo activo).
# Alcanza todas las rutas declaradas, no solo las enlazadas desde la raíz. Solo contra el laboratorio local.
set -euo pipefail
OUT="$(pwd)/reports/zap"
mkdir -p "$OUT" && chmod 777 "$OUT"

export APP_SECRET_KEY="$(openssl rand -hex 32)"
export DB_PATH="$(mktemp -d)/zap.db"
(cd secure && uvicorn app.main:app --host 127.0.0.1 --port 8000 >"$OUT/api-openapi.log" 2>&1) &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT

for i in $(seq 1 20); do
  curl -fs http://127.0.0.1:8000/health >/dev/null && break
  sleep 1
done

docker run --rm --network host -v "$OUT":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t http://127.0.0.1:8000/openapi.json -f openapi -S -I \
  -r zap-api-passive-secure.html -J zap-api-passive-secure.json -w zap-api-passive-secure.md \
  | tee "$OUT/zap-api-passive-console.txt"
