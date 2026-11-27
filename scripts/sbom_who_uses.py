"""Dado un paquete, muestra su versión en el SBOM y qué componentes dependen de él.
Uso: python scripts/sbom_who_uses.py sbom/sbom-secure.cdx.json starlette"""
import json
import sys

sbom = json.load(open(sys.argv[1]))
target = sys.argv[2].lower().replace("_", "-")
norm = lambda s: s.lower().replace("_", "-")

found = [c for c in sbom["components"] if norm(c["name"]) == target]
if not found:
    print(f"{target}: no está en el SBOM")
    sys.exit(0)
for c in found:
    print(f"Presente: {c['name']} {c['version']} ({c.get('purl')})")
    users = [d["ref"] for d in sbom["dependencies"] if c["bom-ref"] in d.get("dependsOn", [])]
    print("Lo usan:", ", ".join(users) if users else "ningún otro componente (dependencia directa o suelta)")
