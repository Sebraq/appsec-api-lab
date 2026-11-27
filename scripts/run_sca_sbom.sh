#!/usr/bin/env bash
# SCA con pip-audit y SBOM CycloneDX de la versión segura. Ejecutar desde la raíz del repo.
set -euo pipefail
mkdir -p reports sbom
pip-audit -r secure/requirements.txt --no-deps --disable-pip -f json -o reports/pip-audit-secure.json
pip-audit -r secure/requirements.txt --no-deps --disable-pip
python3 -m venv /tmp/runtime-venv
/tmp/runtime-venv/bin/pip install -q -r secure/requirements.txt
cyclonedx-py environment /tmp/runtime-venv --mc-type application --of JSON --sv 1.6 -o sbom/sbom-secure.cdx.json
python3 scripts/validate_sbom.py sbom/sbom-secure.cdx.json
