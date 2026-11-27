"""Valida un SBOM CycloneDX JSON contra el esquema 1.6."""
import sys
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

path = sys.argv[1]
error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(open(path).read())
if error is not None:
    print(f"SBOM inválido: {error}")
    sys.exit(1)
print(f"SBOM válido (CycloneDX 1.6): {path}")
