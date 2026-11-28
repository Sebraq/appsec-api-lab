# Fase 4: remediación y pruebas de regresión

Se confirmaron cuatro defectos en `vulnerable/`. Los dos que exige la guía (D1, una falla de autorización por objeto, y D2, una inyección) se documentan completos. D3 y D4 se resumen en la sección 4 porque se corrigen con el mismo método.

**Cómo se hizo el retest.** `scripts/run_before_after.sh` levanta las dos versiones con los mismos datos de laboratorio y ejecuta `scripts/repro_defects.py` con las mismas solicitudes contra cada una. Salidas en `reports/remediation/antes-vulnerable.txt` y `despues-secure.txt`.

## 1. Comparación antes y después

| Defecto | Solicitud | Antes (vulnerable) | Después (secure) |
|---|---|---|---|
| D1 BOLA | `alice` pide `GET /notes/3` (nota de bob) | 200, devuelve el contenido de bob | 403, sin contenido |
| D1 positiva | `alice` pide `GET /notes/1` (suya) | 200 | 200 |
| D2 SQLi | `alice` busca `' OR 1=1 --` | 200, 4 notas (incluye las ajenas) | 200, 0 notas |
| D2 positiva | `alice` busca `compras` | 200, 1 nota | 200, 1 nota |
| D3 acceso por función | `alice` pide `GET /admin/users` | 200 | 403 |
| D4 secreto JWT | token de admin firmado con la clave del código | 200 | 401 |

## 2. D1: autorización por objeto (BOLA/IDOR) en `GET /notes/{id}`

| Campo | Detalle |
|---|---|
| Recurso afectado | `GET /notes/{note_id}`, tabla `notes` |
| Condiciones de reproducción | Dos usuarios autenticados (`alice`, `bob`); alice conoce o adivina el ID de una nota de bob (los IDs son números consecutivos) |
| Respuesta observada | `alice` envía `GET /notes/3` con su token y recibe 200 con el título y el contenido de la nota de bob |
| Causa raíz | La función verifica que el token sea válido, pero nunca compara `owner_id` de la nota con el `id` del usuario autenticado. La autenticación se confundió con la autorización |
| Impacto | Alto en confidencialidad: cualquier usuario puede leer las notas de todos recorriendo IDs |
| Cambio aplicado | Una comparación en `get_note`: si `note["owner_id"] != user["id"]` responde 403 |
| Requisito | R1 (ASVS v5.0.0-8.2.2) |

```diff
     if note is None:
         raise HTTPException(404, "Nota no encontrada")
-    # DEFECTO (BOLA/IDOR): no se verifica que note.owner_id == user.id
+    if note["owner_id"] != user["id"]:
+        raise HTTPException(403, "No tienes acceso a este recurso")
     return dict(note)
```

**Retest.** Prueba negativa `test_d1_negative_no_note_of_another_owner_is_readable`: alice pide todas las notas que no son suyas (la de bob y la de admin) y recibe 403 en cada una. Prueba positiva `test_d1_positive_owner_reads_every_own_note`: alice lee sus dos notas con 200. Se conserva también `test_02` de la Fase 3.

Una nota sobre la elección del código: se responde 403 y no 404. Eso permite saber que un ID existe, pero los IDs ya son consecutivos y fáciles de adivinar, así que ocultar su existencia aportaba poco. Si el riesgo de enumeración preocupara, el siguiente paso sería usar identificadores no secuenciales.

## 3. D2: inyección SQL en `GET /notes/search`

| Campo | Detalle |
|---|---|
| Recurso afectado | `GET /notes/search?q=`, tablas `notes` y `users` (a través de la consulta) |
| Condiciones de reproducción | Un usuario autenticado cualquiera envía en `q` una comilla seguida de una condición siempre verdadera |
| Respuesta observada | `q=' OR 1=1 --` devuelve 200 con las 4 notas de la base de datos, incluidas las de bob y admin. Semgrep marcó la línea 97 con la regla propia `appsec-lab.sqli-dynamic-query` |
| Causa raíz | El texto del cliente se inserta con un f-string dentro de la consulta. Los caracteres `'` y `--` cierran el literal y comentan el resto, incluida la condición `owner_id` |
| Impacto | Alto: lectura de notas de cualquier usuario. Una consulta con `UNION` podría llegar a otras tablas, como los hashes de `users` |
| Cambio aplicado | Consulta con marcadores `?` y valores aparte; `q` limitado a 1-50 caracteres |
| Requisitos | R3 (ASVS v5.0.0-1.2.4) y R5 (v5.0.0-2.2.1) |

```diff
-def search_notes(q: str, user=Depends(current_user), conn=Depends(db.get_db)):
-    query = (
-        "SELECT id, title, content FROM notes "
-        f"WHERE owner_id = {user['id']} AND title LIKE '%{q}%'"
-    )
-    rows = conn.execute(query).fetchall()
+def search_notes(
+    q: str = Query(min_length=1, max_length=50),
+    user=Depends(current_user),
+    conn=Depends(db.get_db),
+):
+    rows = conn.execute(
+        "SELECT id, title, content FROM notes WHERE owner_id = ? AND title LIKE ?",
+        (user["id"], f"%{q}%"),
+    ).fetchall()
```

**Retest.** Prueba negativa `test_d2_negative_payload_is_treated_as_text`, con cuatro cargas: la condición siempre verdadera, `%' OR '1'='1`, un `UNION SELECT` y un `DROP TABLE`. Todas devuelven 200 con lista vacía. `test_d2_negative_tables_survive_the_drop_payload` confirma que las tablas siguen intactas. Prueba positiva `test_d2_positive_legitimate_search_still_works`: buscar `compras` devuelve exactamente la nota propia. Semgrep ya no reporta hallazgos sobre `secure/` (Fase 2).

El límite de 50 caracteres cambia el comportamiento para quien buscaba textos más largos o vacíos (ahora recibe 422). Es un cambio deliberado, documentado en el requisito R5.

## 4. D3 y D4

| | D3: acceso por función | D4: secreto JWT hardcodeado |
|---|---|---|
| Recurso | `GET /admin/users` | Firma de tokens en `security.py` |
| Causa raíz | La ruta solo exige estar autenticado, no tener rol admin; además devolvía `password_hash` | La clave `secret123` está en el código y los tokens no expiran |
| Impacto | Alto: cualquier usuario lista cuentas, roles y hashes | Alto: quien lea el código puede fabricar un token de admin sin conocer su contraseña |
| Cambio | Dependencia `require_admin` y respuesta sin hashes | Clave desde `APP_SECRET_KEY` (mínimo 32 caracteres), expiración de 15 minutos y `exp` obligatorio |
| Prueba negativa | `test_d3_negative_regular_user_cannot_list_users` | `test_d4_negative_token_signed_with_old_hardcoded_secret_is_rejected` |
| Prueba positiva | `test_d3_positive_admin_can_list_users` | `test_01` y `test_05` de la Fase 3 (login y uso normal con tokens nuevos) |
| Requisito | R2 (v5.0.0-8.2.1) | R4 (v5.0.0-9.1.1, 9.2.1) |

## 5. Pruebas de regresión

Archivo: `secure/tests/test_regression_defects.py`. Se ejecutan con `scripts/run_regression_check.sh`.

| Ejecución | Resultado |
|---|---|
| Suite completa sobre `secure/` | 34 pruebas, todas pasan (`reports/remediation/regresion-secure.txt`) |
| Las mismas pruebas de regresión sobre `vulnerable/` | 8 fallan (las negativas de D1, D2, D3 y D4) y 3 pasan (las positivas) (`regresion-sobre-vulnerable.txt`) |

El segundo resultado es la evidencia de que las pruebas detectan los defectos: no son pruebas que pasen sin importar el código. Si alguien reintroduce cualquiera de los cuatro, el pipeline de la Fase 5 las verá fallar.

## 6. Qué no se hizo

No se suprimió ninguna alerta, no se desactivó ningún control ni se retiró ninguna función: `/admin/users` y la búsqueda siguen funcionando para quien corresponde, como muestran las pruebas positivas. Los diffs de las tres funciones están en `reports/remediation/diff-funciones.patch`. La versión vulnerable se mantiene aislada en `vulnerable/`.
