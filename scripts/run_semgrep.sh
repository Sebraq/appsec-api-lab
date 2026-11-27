#!/usr/bin/env bash
# Pruebas de las reglas propias y escaneo de ambas versiones. Ejecutar desde la raíz del repo.
set -euo pipefail
mkdir -p reports
OPTS="--metrics=off --disable-version-check"
echo "== Pruebas de las reglas (casos que incumplen y que cumplen) =="
semgrep --test $OPTS --config semgrep/rules semgrep/tests
for v in vulnerable secure; do
  echo "== Escaneo: $v =="
  semgrep scan $OPTS --config semgrep/rules --json  -o reports/semgrep-$v.json  $v/app || true
  semgrep scan $OPTS --config semgrep/rules --sarif -o reports/semgrep-$v.sarif $v/app || true
done
# Puerta de bloqueo: la versión segura no debe tener hallazgos
semgrep scan $OPTS --config semgrep/rules --error secure/app
