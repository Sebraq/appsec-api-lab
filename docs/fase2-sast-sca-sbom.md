# Fase 2: análisis de código, dependencias, SBOM y cadena de suministro

Fecha de ejecución: 26 de noviembre de 2026. Todo se reproduce desde la raíz del repo con `scripts/run_semgrep.sh` y `scripts/run_sca_sbom.sh`.

## 1. Herramientas y versiones

| Herramienta | Versión | Uso |
|---|---|---|
| Semgrep | 1.187.0 | SAST con reglas propias |
| pip-audit | 2.10.1 | SCA contra la base de vulnerabilidades de PyPI |
| cyclonedx-bom (`cyclonedx-py`) | 9.0.0 | Generación del SBOM |
| cyclonedx-python-lib | 11.13.0 | Validación del SBOM contra el esquema |

Versiones fijadas en `requirements-tools.txt`.

## 2. SAST con Semgrep

**Configuración.** Dos reglas propias en `semgrep/rules/`, sin conjuntos externos, para que el resultado se repita igual en cualquier equipo.

| Regla | Qué busca | CWE |
|---|---|---|
| `appsec-lab.sqli-dynamic-query` (regla propia principal) | Texto armado con f-string, `+`, `%` o `format()` que llega como consulta a `execute()`. Usa análisis de flujo, así que también detecta la consulta guardada antes en una variable | CWE-89 |
| `appsec-lab.jwt-hardcoded-secret` | Clave de `jwt.encode/decode` escrita en el código, directa o por constante | CWE-798 |

**Demostración de la regla propia.** El archivo `semgrep/tests/sqli-dynamic-query.py` marca con `# ruleid:` los tres casos que incumplen (f-string directo, consulta armada en variable, concatenación) y con `# ok:` los dos que cumplen (consulta con `?` y valores aparte, consulta constante). `semgrep --test` terminó con `2/2: All tests passed` para las dos reglas.

**Resultados por versión.**

| Versión | Hallazgos de Semgrep | Detalle |
|---|---|---|
| `vulnerable/` | 3 | SQLi en `main.py` (línea 97); clave hardcodeada en `security.py` (líneas 19 y 23) |
| `secure/` | 0 | Sin hallazgos |

**Herramienta contra riesgo confirmado.** Un hallazgo de la herramienta no es todavía una vulnerabilidad demostrada.

| Hallazgo | Confirmado | Cómo se confirmó |
|---|---|---|
| SQLi en `/notes/search` | Sí | `test_sqli_search_returns_other_users_notes`: `alice` recibe las 4 notas de la BD con `' OR 1=1 --` |
| Clave JWT hardcodeada | Sí | `test_forged_admin_token_with_hardcoded_secret`: token firmado con la clave del código da acceso a `/admin/users` |

**Lo que Semgrep no vio.** BOLA en `/notes/{id}` y falta de control de rol en `/admin/users` son fallas de lógica: el código es sintácticamente normal y ninguna regla de patrón las marca. Se confirmaron por revisión manual y con las pruebas `test_bola_alice_reads_bobs_note` y `test_regular_user_lists_admin_users`. Tampoco hay regla para MD5 ni para el mensaje distinto en el login; se documentan como hallazgos de revisión manual, no de herramienta.

## 3. SCA con pip-audit

Entrada: `secure/requirements.txt`, con las 21 dependencias fijadas (3 directas en `requirements.in`: `fastapi`, `uvicorn`, `pyjwt`; las otras 18 son transitivas).

Resultado real: **0 vulnerabilidades conocidas** en las 21. Reporte en `reports/pip-audit-secure.json`. No se agregó ningún paquete vulnerable para producir alertas.

Dos limitaciones. pip-audit consulta la información de PyPI en el momento de la corrida, así que el resultado vale para ese día y debe repetirse en cada ejecución del CI. Además, avisa que las dependencias no tienen hashes; eso se retoma en el control C2 de la sección 5.

**Tratamiento si apareciera una alerta:**

1. Actualizar a la versión que indique `fix_versions`, correr las pruebas y volver a auditar.
2. Si no hay versión corregida, buscar si la función afectada se usa; si no se usa, documentarlo y aceptar el riesgo con fecha de revisión.
3. Reemplazar el paquete o fijar una versión anterior no afectada.
4. Excluir una alerta (`--ignore-vuln`) solo con justificación escrita; nunca para que el pipeline pase.

## 4. SBOM CycloneDX

Archivo: `sbom/sbom-secure.cdx.json`. Formato CycloneDX 1.6 JSON, generado con `cyclonedx-py environment` sobre un entorno limpio con solo las dependencias de ejecución y validado con `scripts/validate_sbom.py` (resultado: válido).

Contiene 22 componentes: las 21 dependencias y `pip`, que viene dentro del entorno virtual.

| Parte | Para qué sirve |
|---|---|
| `metadata` | Fecha, herramienta que lo generó y el componente principal (la aplicación) |
| `components` | Nombre, versión y `purl` (por ejemplo `pkg:pypi/starlette@1.10.0`) de cada paquete |
| `dependencies` | Grafo: qué paquete depende de cuál, lo que permite separar directas de transitivas |

**Cómo se usa ante una alerta posterior.** Si sale un aviso sobre `starlette`, no hace falta revisar el código: se busca el paquete en el SBOM.

```bash
python scripts/sbom_who_uses.py sbom/sbom-secure.cdx.json starlette
# Presente: starlette 1.10.0 (pkg:pypi/starlette@1.10.0)
# Lo usan: fastapi==0.165.0
```

El resultado dice si la versión afectada está presente y por qué camino llegó (aquí, a través de `fastapi`). Para una sola corrida el `purl` sirve para cruzar con el aviso del proveedor.

Limitación: el SBOM generado no incluye hashes de los paquetes, así que identifica versiones pero no verifica la integridad del archivo instalado.

## 5. Incidente de cadena de suministro: ultralytics en PyPI (diciembre de 2024)

**Qué pasó.** El 4 de diciembre de 2024 se publicó en PyPI la versión 8.3.41 de `ultralytics`, una librería de visión por computadora con unos 60 millones de descargas, con un descargador del minero de criptomonedas XMRig. Siguieron la 8.3.42 y, el 7 de diciembre, la 8.3.45 y la 8.3.46. El código malicioso estaba en los paquetes de PyPI pero no en el repositorio de GitHub.

**Mecanismo.** Los atacantes no tocaron PyPI: comprometieron el proceso de construcción en GitHub Actions. Las fuentes difieren en el detalle del primer paso. ReversingLabs lo atribuye a una inyección de scripts en un workflow (un pull request con la carga maliciosa en el título de la rama), un problema ya reportado en agosto de 2024 y que reapareció por una regresión; el análisis de PyPI y Socket hablan de envenenamiento del caché de Actions que alimentó al workflow legítimo de publicación. En ambos casos, la publicación salió del flujo oficial y las dos primeras versiones llevaban atestaciones válidas. La segunda tanda se publicó con un token de API que seguía activo, aunque el proyecto ya había adoptado Trusted Publishers. PyPI concluyó que no se explotó ninguna falla de PyPI.

**Dos controles aplicables a este proyecto** (aquí somos consumidores y también construimos con GitHub Actions):

| Control | Qué se hace | Qué habría frenado |
|---|---|---|
| C1. Endurecer los workflows | Fijar cada `uses:` a un commit completo (SHA), declarar `permissions: contents: read` por defecto, no interpolar datos controlados por terceros (`${{ github.event.* }}`) dentro de `run:` y revisar los workflows con `zizmor` en el CI | La inyección por títulos de PR y el uso de permisos amplios en el build |
| C2. Dependencias con hash y revisión continua | Generar `requirements.txt` con hashes (`pip-compile --generate-hashes`), instalar con `pip install --require-hashes` y mantener `pip-audit` como puerta de bloqueo | Que una versión nueva o reemplazada de un paquete entre sin que alguien la apruebe; las versiones 8.3.41 a 8.3.46 no habrían entrado a un proyecto fijado en 8.3.40 |

C2 se implementa en la Fase 5 y C1 en el mismo workflow.

**Fuentes** (revisar que abran antes de entregar):

- PyPI Blog, "Supply-chain attack analysis: Ultralytics", 11 de diciembre de 2024: https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/
- ReversingLabs, "Compromised ultralytics PyPI package delivers crypto coinminer": https://www.reversinglabs.com/blog/compromised-ultralytics-pypi-package-delivers-crypto-coinminer
- Socket, "Ultralytics PyPI package compromised through GitHub Actions cache poisoning": https://socket.dev/blog/ultralytics-pypi-package-compromised-through-github-actions-cache-poisoning
- CSO Online, "Supply chain compromise of Ultralytics AI library results in trojanized versions", 6 de diciembre de 2024.
