# Fase 3: pruebas dinámicas, controles de acceso y traza

## 0. Preparar Docker y ZAP (Ubuntu)

ZAP se usa desde su imagen oficial de Docker; no hace falta instalarlo aparte. Docker también se necesita en la Fase 6 (Trivy y Dockerfile).

```bash
sudo apt update && sudo apt install -y docker.io curl
sudo usermod -aG docker $USER && newgrp docker
docker run --rm hello-world
docker pull ghcr.io/zaproxy/zaproxy:stable
```

## 1. Pruebas automatizadas (3.3b)

Archivo: `secure/tests/test_security_controls.py`. 23 pruebas, todas pasan sobre `secure/`. Cada una declara en su docstring la entrada, el resultado esperado y el requisito (R1 a R5) que comprueba.

| Tipo exigido | Pruebas | Entrada | Aserción |
|---|---|---|---|
| Acceso legítimo a recurso propio | `test_01`, `test_06` | `alice` lee y crea notas propias | 200 / 201; `owner_id` igual al id de alice |
| Denegación a recurso ajeno | `test_02`, `test_02b` | `alice` pide la nota de `bob`; id inexistente | 403 sin el contenido de la nota; 404 |
| Sin autenticación válida | `test_03` a `test_03f` | sin token; token con otra clave; expirado; sin `exp`; `alg: none`; login con error | 401 en todos; mismo mensaje para usuario inexistente y clave mala |
| Entrada inesperada | `test_04` a `test_04e` | título vacío o de 101 caracteres, contenido de 2001, tipo equivocado, id `abc`, búsqueda vacía o de 51 caracteres, `' OR 1=1 --` | 422; la inyección devuelve 200 con lista vacía |
| Restricción por rol | `test_05` | `/admin/users` como admin, como alice y sin token | 200, 403 y 401; la respuesta no trae `password_hash` |

Trazabilidad con los requisitos: R1 (`test_01`, `test_02`), R2 (`test_05`), R3 (`test_04d`, `test_04e`), R4 (`test_03b` a `test_03e`), R5 (`test_04` a `test_04c`). `test_07` comprueba las tres cabeceras de seguridad agregadas por las alertas de ZAP (sección 3).

Ejecución:

```bash
cd secure && APP_SECRET_KEY=$(openssl rand -hex 32) python -m pytest -v | tee ../reports/pytest-secure.txt
```

## 2. Recorrido interno de una solicitud (3.3c)

Script: `scripts/trace_request.py`. Es una traza local con `sys.setprofile` que registra las funciones de `app/` que se ejecutan mientras se atiende una sola solicitud. **No es IAST**: no analiza flujo de datos ni detecta vulnerabilidades, solo muestra el camino.

Solicitud trazada: `GET /notes/3` (nota de bob) con el token de alice.

| Paso | Función | Qué hace |
|---|---|---|
| 1 | `main.security_headers()` | Middleware: deja pasar la solicitud y, al volver, agrega `Cache-Control`, `X-Content-Type-Options` y `Cross-Origin-Resource-Policy` a la respuesta |
| 2 | `db.get_db()` y `db.connect()` | Abre la conexión a SQLite para esta solicitud |
| 3 | `main.current_user()` | Dependencia de autenticación; lee el token de la cabecera |
| 4 | `security.decode_token()` y `_secret()` | Verifica firma, algoritmo permitido, `exp` y `sub`, con la clave de `APP_SECRET_KEY` |
| 5 | `main.get_note()` | Busca la nota y compara `note["owner_id"]` con `user["id"]` (línea 129); si no coinciden, lanza 403 en la línea 130 |
| 6 | `db.get_db()` (cierre) y `security_headers()` | Cierra la conexión y la respuesta sale con la cabecera |

Resultado: HTTP 403 para alice; el mismo recorrido con el token de bob termina en HTTP 200. Las funciones llamadas son las mismas en ambos casos, y lo que cambia es el resultado de la comparación de la línea 129. Eso confirma que el control de propiedad vive en la capa de servicio y no depende del cliente.

## 3. DAST con OWASP ZAP (3.3a)

ZAP Baseline es **pasivo**: rastrea con su spider (1 minuto por defecto) y analiza las respuestas sin enviar ataques.

### 3.1 Corrida 1: Baseline contra la raíz

```bash
./scripts/run_zap_baseline.sh
```

Resultado (`reports/zap/zap-baseline-console.txt`, ejecución propia): ZAP rastreó **3 URLs**: `/`, `/robots.txt` y `/sitemap.xml`. Las tres respondieron 404 y el spider avisó que esperaba 200 en la raíz. Resumen: 67 reglas sin hallazgo (PASS), 1 advertencia (WARN) y 0 fallos.

| Alerta | Riesgo | URLs | Análisis | Acción |
|---|---|---|---|---|
| 10049 Storable and Cacheable Content | Informativo | las 3 respuestas 404 | La API no indicaba si sus respuestas podían guardarse en caché. En las 3 URLs afectadas solo hay errores 404 sin datos de usuarios, pero una respuesta autenticada (`/notes`) con el mismo defecto sí podría quedar en un caché compartido | Se agregó `Cache-Control: no-store` a todas las respuestas (middleware `security_headers` en `main.py`). Se confirma en la corrida 2 |

Que no haya hallazgos de las otras 67 reglas **no significa que la API esté libre de fallas**: la corrida no llegó a ninguna ruta de la API (ver limitaciones).

### 3.2 Corrida 2: definición OpenAPI en modo pasivo

Como la raíz no existe, el spider casi no ve la API. FastAPI publica su definición en `/openapi.json`; `zap-api-scan.py -S` la importa y analiza cada ruta declarada, también sin ataques (el modo `-S` omite el escaneo activo).

```bash
./scripts/run_zap_api_passive.sh
```

Resultado (`reports/zap/zap-api-passive-console.txt`, ejecución propia del 27 de noviembre de 2026): se importaron **11 URLs**. Resumen: 117 reglas sin hallazgo, 2 advertencias y 0 fallos.

| Alerta | Riesgo | URLs | Análisis | Acción |
|---|---|---|---|---|
| 10021 X-Content-Type-Options Header Missing | Bajo | `/health`, `/openapi.json` (200) | Sin `nosniff`, un navegador podría interpretar como otro tipo el JSON de la API. El riesgo real en una API es bajo, pero la corrección cuesta una línea | Cabecera `X-Content-Type-Options: nosniff` en todas las respuestas |
| 90004 Cross-Origin-Resource-Policy Header Missing or Invalid | Bajo | `/health`, `/openapi.json` (200) | Falta aislamiento entre orígenes (mitigación contra ataques tipo Spectre). La API no se consume desde otros sitios | Cabecera `Cross-Origin-Resource-Policy: same-origin` en todas las respuestas |

**Seguimiento de la alerta de la corrida 1.** La regla 10049 (*Content Cacheability*), que había dado advertencia sobre los 404, aparece ahora como PASS. Es una comparación aproximada, porque las dos corridas no vieron las mismas URLs.

**Las reglas activas en PASS no son evidencia.** La consola lista como PASS reglas como *SQL Injection* o *Cross Site Scripting*. Con `-S` el escaneo activo se omite, así que esas reglas no se ejecutaron; la lista solo indica que no generaron alertas. La inyección SQL se verifica con las pruebas pytest, no con este reporte.

**Rutas alcanzadas.** Para listarlas con el código de respuesta de cada una, usar el registro de la API durante el escaneo:

```bash
grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS) [^ ]+ HTTP/1.1" [0-9]+' reports/zap/api-openapi.log | sort | uniq -c
```

**PENDIENTE: pegar aquí la salida de ese comando** (ruta, método y código) y repetir el escaneo después de las cabeceras nuevas para confirmar que las dos advertencias desaparecen (ver "antes y después" abajo).

### 3.3 Antes y después de las cabeceras

Antes de repetir el escaneo, guardar la corrida anterior:

```bash
cd reports/zap
for f in zap-api-passive-secure.html zap-api-passive-secure.json zap-api-passive-secure.md zap-api-passive-console.txt; do mv "$f" "${f%.*}-antes.${f##*.}"; done
cd ../.. && ./scripts/run_zap_api_passive.sh
```

**PENDIENTE: comparar** las advertencias de la corrida anterior (2) contra la nueva.

### 3.4 Limitaciones de cobertura

Salen de lo observado:

1. **La corrida 1 solo vio 3 URLs, todas 404.** La raíz no existe y una API JSON no tiene enlaces HTML que seguir. La corrida 2 con OpenAPI importó 11 URLs.
2. **Sin autenticación.** ZAP no tenía token, así que `/notes`, `/notes/{id}` y `/admin/users` solo se ven como respuestas de error 401. No se evalúa lo que la API devuelve a un usuario autenticado, y los alertas de cabeceras solo salieron en las dos rutas públicas que dan 200.
3. **Pasivo.** Ni el baseline ni `-S` envían ataques, así que no prueban inyección ni control de acceso entre usuarios; esos riesgos (SQLi, BOLA) los cubren las pruebas pytest y Semgrep.
4. **Valores de ejemplo.** La importación de OpenAPI usa valores genéricos (como `string`) en parámetros y cuerpos; no recorre flujos con datos reales, por ejemplo pedir una nota que sí existe.
