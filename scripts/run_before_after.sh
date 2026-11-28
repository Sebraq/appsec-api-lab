#!/usr/bin/env bash
# Retest antes/después: misma reproducción contra vulnerable (puerto 9000) y secure (puerto 8000).
# Ejecutar desde la raíz del repo con el entorno virtual activo. Solo local.
set -euo pipefail
mkdir -p reports/remediation
TMP="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

(cd vulnerable && DB_PATH="$TMP/vuln.db" uvicorn app.main:app --host 127.0.0.1 --port 9000 >"$TMP/vuln.log" 2>&1) &
PIDS+=($!)
(cd secure && APP_SECRET_KEY="$(openssl rand -hex 32)" DB_PATH="$TMP/secure.db" uvicorn app.main:app --host 127.0.0.1 --port 8000 >"$TMP/secure.log" 2>&1) &
PIDS+=($!)

for port in 9000 8000; do
  for i in $(seq 1 20); do curl -fs "http://127.0.0.1:$port/health" >/dev/null && break; sleep 1; done
done

python scripts/repro_defects.py http://127.0.0.1:9000 | tee reports/remediation/antes-vulnerable.txt
echo
python scripts/repro_defects.py http://127.0.0.1:8000 | tee reports/remediation/despues-secure.txt
