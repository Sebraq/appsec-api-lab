#!/usr/bin/env bash
# Pruebas de regresión de la Fase 4: deben PASAR en secure/ y las negativas deben FALLAR en vulnerable/
# (así se demuestra que las pruebas realmente detectan los defectos). Ejecutar desde la raíz del repo.
set -uo pipefail
mkdir -p reports/remediation
echo "== secure: suite completa =="
(cd secure && APP_SECRET_KEY="$(openssl rand -hex 32)" python -m pytest -v -p no:cacheprovider) | tee reports/remediation/regresion-secure.txt | tail -3
echo "== vulnerable: mismas pruebas de regresión (se esperan fallos) =="
cp secure/tests/test_regression_defects.py vulnerable/tests/test_regression_tmp.py
(cd vulnerable && python -m pytest -v -p no:cacheprovider tests/test_regression_tmp.py) | tee reports/remediation/regresion-sobre-vulnerable.txt | tail -3
rm -f vulnerable/tests/test_regression_tmp.py
