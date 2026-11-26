# Registro de triage de hallazgos · CenfoPay

> Una fila por hallazgo revisado. La **huella** es la columna `huella` de
> `reportes/hallazgos-normalizados.csv` (la genera `tools/security_gate.py`).
> Decisión: **VP** verdadero positivo · **FP** falso positivo · **RA** riesgo aceptado (con excepción y vencimiento).

| # | Huella | Herramienta | Regla / CVE | Ubicación | Severidad | Decisión | Justificación (contexto, explotabilidad, evidencia) | Acción | Responsable | Fecha |
|---|--------|-------------|-------------|-----------|-----------|----------|-----------------------------------------------------|--------|-------------|-------|
| 1 | `c27a6d8095bcb454` | Semgrep | cenfopay-sql-injection | `__init__.py:60` · `login()` | ALTA | **VP** | El usuario y la contraseña los controla cualquiera desde `/api/login` (público) y llegaban sin filtro a la consulta SQL: con `admin' --` se entraba sin contraseña. | Corregido: consulta parametrizada (`?`). Prueba: `test_login_resiste_inyeccion_sql` ✅ | Larry Castillo | 26/11/2026 |
| 2 | `c27a6d8095bcb454-1` | Semgrep | cenfopay-sql-injection | `__init__.py:74` · `movimientos()` | ALTA | **VP** | La fecha del filtro viene del usuario y se pegaba en la consulta SQL. | Corregido: se valida la fecha y se usa `?`. Prueba: `test_movimientos_resisten_inyeccion_sql` ✅ | Larry Castillo | 26/11/2026 |
| 3 | `4a6064cc8e121da5` | Semgrep | subprocess-injection | `__init__.py:85` · `resolver()` | ALTA | **VP** | El parámetro `host` lo controla el usuario y llegaba a una orden del sistema con `shell=True`: permitía ejecutar comandos en el servidor. | Corregido: lista blanca de caracteres y `socket`, sin terminal. Prueba: `test_resolver_no_ejecuta_comandos` ✅ | Larry Castillo | 26/11/2026 |
| 4 | `af614d250c0ac104` | Semgrep | avoid-pyyaml-load | `__init__.py:95` · `importar()` | ALTA | **VP** | El archivo YAML lo envía el usuario y `yaml.load(Loader=yaml.Loader)` puede crear objetos de Python (ejecutar código). Coincide con CVE-2020-14343 del Top 5 del Lab 2. | Corregido: `yaml.safe_load` + validación del contenido. Prueba: `test_importar_rechaza_objetos_python` ✅ | Larry Castillo | 26/11/2026 |
| 5 | `3d09d086c21b1f74` | Bandit | B324 (MD5) | `__init__.py:54` · `login()` | ALTA | **VP** | Las contraseñas se guardaban con MD5 sin sal: se descifran en segundos con tablas precalculadas. (Semgrep lo vio también: `92b142158358594e`, `52480c03db5b3dec`.) | Corregido: `auth.py` usa *scrypt*. Prueba: `test_contrasenas_con_hash_robusto` ✅ | Larry Castillo | 26/11/2026 |
| 6 | — (archivo nuevo) | Bandit / Semgrep | B324 · insecure-hash-algorithm-md5 | `auth.py:29-30` | ALTA | **RA** | MD5 se conserva solo para **reconocer** contraseñas viejas en el primer inicio de sesión y cambiarlas de inmediato a *scrypt*. No se usa para guardar contraseñas nuevas. Control compensatorio: la migración es automática. | Silenciado con `# nosemgrep` y `# nosec B324` con su motivo. Revisar cuando no queden hashes viejos. | Larry Castillo | 26/11/2026 |
| 7 | `7f98ccdb1da06cc1` | Bandit | B108 (`/tmp`) | `config.py:26` (hoy `:28`) | MEDIA | **FP** | `/tmp/cenfopay.db` es solo el valor por defecto de la base de datos de pruebas; la ruta real llega por la variable de entorno `SQLITE_PATH`. Un atacante no controla ese dato. | Silenciado con `# nosec B108` con su motivo en `config.py`. | Larry Castillo | 26/11/2026 |
| 8 | `ae7b29afa644087f` (-1, -2) · `3a9c31bb89babd15` (-1) | Semgrep / Bandit | cenfopay-secreto-embebido · B105 | `config.py:10, 13, 25` | MEDIA / BAJA | **RA** | Es real (CWE-798): `SECRET_KEY`, `TOKEN_TIPO_CAMBIO` y `DB_PASSWORD` están escritos en el código. Se acepta hasta la semana 4: son valores ficticios del laboratorio y no detienen la compuerta (WARNING / LOW). La prueba `test_secret_key_se_inyecta_desde_el_entorno` falla a propósito como recordatorio. | Se corrige en la semana 4 (secretos inyectados desde el entorno / Vault). El código los marca con `# VULN (CWE-798)`. Vence: 31/12/2026. | Larry Castillo | 26/11/2026 |
| 9 | — (semana 2) | Endurecimiento | END-02 | Imagen de Python (`GPG_KEY`) | ALTA | **FP** | `GPG_KEY` es la huella de la llave PÚBLICA con la que Python firma su código; el script la marca solo porque el nombre contiene «KEY». | Excepción en `security/politica-umbrales.yml` con motivo, responsable y vencimiento 31/12/2026. | Larry Castillo | 26/11/2026 |
| 10 | — (PR #5, corrida #15) | Trivy (dependencias) | CVE-2026-114613 · GHSA-6v7p-g79w-8964 (msgpack) · CVE-2025-47273 (setuptools) · CVE-2026-97687 · CVE-2026-97689 (urllib3) | Imagen final: copias internas de **pip** (`/usr/local` y `/opt/venv`) | ALTA | **VP** | Reales y con arreglo publicado; detuvieron la compuerta («trivy-dependencias HIGH: 5 > 0»). No los usa la app: son librerías empaquetadas dentro de pip, que solo sirve para construir la imagen. Las librerías de la app (`/opt/venv`) estaban en 0. | Corregido de raíz: se desinstaló pip de la imagen final (`app/Dockerfile`), lo que además reduce la superficie de ataque. Trivy local: 0; corrida #16 en verde. | Larry Castillo | 26/11/2026 |
| 11 | `01becae49feaa30f` `e848b5611090f838` | Gitleaks | generic-api-key | `docs/inventario-imagen.md:93` y `:99` (commits `d8dbe86e`, `47cc6c7a`) | CRITICA | **FP** | La cadena marcada es `E3FF2839…10250568`, la huella de la llave PÚBLICA de Python que se citó al justificar END-02. Gitleaks la confunde con una llave secreta por ser larga y aleatoria. No da acceso a nada. | Gitleaks se activa en la semana 4: se registrará allí como excepción (huellas permitidas) con este motivo. No detiene la compuerta hoy. | Larry Castillo | 26/11/2026 |

**Resumen:** 11 filas revisadas · 6 VP (corregidos y comprobados) · 3 FP · 2 RA (una fila de RA agrupa los 5 avisos de secretos de `config.py`; la fila 10 agrupa 5 CVE de pip).

**Nota:** la guía (7.3 y 7.5) menciona la falsa alarma `useless-inner-function` como excepción en la política. En este repositorio `semana.sh 3` no la registró, y Semgrep (`p/python`) sobre el código corregido da **0 hallazgos**: no aparece, por lo que no se registró una excepción innecesaria.

## Criterios de decisión usados
- **FP**: la regla dispara pero el flujo de datos no es explotable en este contexto (explica por qué).
- **RA**: es real, pero se acepta temporalmente: existe un control compensatorio y una fecha de vencimiento.
- Todo FP o RA se refleja en el código (`# nosemgrep: <regla>` / `# nosec <id>`) **o** en
  `security/politica-umbrales.yml > excepciones`, nunca solo en este documento.

## Comparación de reglas: generales vs. propias (semana 3, paso 7.1)

Revisión del código **antes de las correcciones** (rama `semana-3`, 25/11/2026) con dos juegos de reglas de Semgrep:

- **Reglas generales** (`semgrep scan --config p/python app/`): **10 hallazgos** (5 ERROR, 5 WARNING).
- **Reglas propias** (`semgrep scan --config security/semgrep/reglas-cenfopay.yml app/`): **9 hallazgos** (6 ERROR, 3 WARNING).

| Línea / función | Reglas generales | Reglas propias | Quién lo detecta |
|---|---|---|---|
| `__init__.py:44` · `saludo()` | `raw-html-format` ×2 (WARNING, posible XSS) | `cenfopay-ssti-render-template-string` (ERROR) | Ambas; las propias la clasifican correctamente como inyección de plantillas (más grave) |
| `__init__.py:52` · `login()` | — | `cenfopay-secreto-en-logs` (ERROR) | Solo propias |
| `__init__.py:54` · `login()` | `insecure-hash-algorithm-md5`, `md5-used-as-password` (WARNING) | — | Solo generales |
| `__init__.py:60` · `login()` | — | `cenfopay-sql-injection` (ERROR) | Solo propias |
| `__init__.py:74` · `movimientos()` | — | `cenfopay-sql-injection` (ERROR) | Solo propias |
| `__init__.py:85-86` · `resolver()` | `subprocess-injection`, `dangerous-subprocess-use`, `subprocess-shell-true` (ERROR) | — | Solo generales |
| `__init__.py:95` · `importar()` | `avoid-insecure-deserialization`, `avoid-pyyaml-load` (ERROR) | — | Solo generales |
| `__init__.py:105` · `reportes()` | — | `cenfopay-path-traversal` (ERROR) | Solo propias |
| `config.py:10, 13, 25` | — | `cenfopay-secreto-embebido` ×3 (WARNING) | Solo propias |
| `run.py:9` | `avoid_app_run_with_bad_host` (WARNING, `host="0.0.0.0"`) | `cenfopay-flask-debug-activo` (ERROR, `debug=True`) | Ambas en la misma línea, pero cada una señala un problema distinto |

**Conclusiones:**
1. Las reglas generales **no detectan las dos inyecciones SQL** (líneas 60 y 74): no conocen la función propia `db.consultar` / `db.consultar_uno` con la que CenfoPay habla con la base de datos.
2. Las reglas propias **no cubren** los errores típicos de Python (inyección de comandos, YAML inseguro, MD5): de eso se encargan las generales.
3. **Ninguna basta por sí sola**: juntas señalan 15 lugares distintos del código. Por eso, desde la semana 3, el pipeline ejecuta ambas.
4. En la línea 44 las reglas propias dan el contexto correcto: no es solo HTML armado a mano (WARNING), sino inyección de plantillas (ERROR), que puede ejecutar código en el servidor.
5. Los valores de `config.py` (líneas 10, 13 y 25) son datos de prueba del curso; se tratan en la semana 4 (gestión de secretos).

## Comparativo antes → después (semana 3, paso 7.7)

`docs/comparativo.md` (generado con `bash scripts/comparar.sh`): **14 035 → 243 hallazgos** (−13 792, ≈ 98 %).

| Lista | Total | Por herramienta | Explicación |
|---|---|---|---|
| **Corregidos** | 13 842 | trivy-so 13 744 · trivy-dependencias 49 · semgrep 16 · hadolint 9 · bandit 8 · trivy-config 7 · zap 6 · endurecimiento 3 | Imagen slim + parches (semana 2) y código corregido (semana 3). Endurecimiento incluye END-04: la imagen pasó de 312 MB a 226 MB (meta 250 MB). |
| **Nuevos** | 50 | trivy-so 47 · gitleaks 2 · zap 1 | No son regresiones del código. trivy-so: CVE propios de Debian 13 *trixie* (la nueva base de Python 3.13) **sin arreglo publicado**; no detienen la compuerta (`solo_con_correccion`). gitleaks: falso positivo de la fila 11. zap: aviso informativo nuevo, dentro del umbral (Medium ≤ 3). |
| **Persistentes** | 193 | trivy-so 175 · gitleaks 6 · zap 5 · semgrep 3 · bandit 2 · endurecimiento 2 | trivy-so: sin arreglo publicado (riesgo residual, vigilado por la corrida semanal). gitleaks 6, semgrep 3 y bandit 2: secretos en el historial y en `config.py` → **semana 4** (fila 8). endurecimiento 2: END-02 (FP, excepción) y END-05 (`apt-get`, riesgo residual aceptado en el Lab 2). zap 5: avisos Medium/Bajo/Info dentro del umbral. |
