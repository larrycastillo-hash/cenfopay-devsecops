# Inventario y clasificación de vulnerabilidades del contenedor · CenfoPay (semana 2)

## 1. Inventario (SBOM)
- Archivo: `reportes/sbom-cyclonedx.json` · Componentes totales: **512** (foto del antes: `reportes/antes/sbom-cyclonedx.json`)
- Imagen base: `python:3.9` (imagen completa) · Digest: **no fijado** (se usa solo la etiqueta `python:3.9`, que puede cambiar sin aviso; se fija por digest en el paso 6.4)
- Sistema operativo y versión: **Debian 13.1** · Paquetes del SO: **478** · Librerías Python: **33** (+1 componente que describe el sistema operativo)

## 2. Clasificación (antes / después del endurecimiento)
| Origen | Severidad | Antes | Después | Con corrección | Sin corrección | En CISA KEV |
|--------|-----------|------:|--------:|---------------:|---------------:|------------:|
| SO (trivy-so) | CRITICAL | 235 | | 224 | 11 | 1 |
| SO (trivy-so) | HIGH | 2603 | | 2206 | 397 | 4 |
| Dependencias (trivy-dependencias) | CRITICAL | 1 | | 1 | 0 | 0 |
| Dependencias (trivy-dependencias) | HIGH | 16 | | 16 | 0 | 0 |
| Configuración (trivy-config / hadolint) | ALTA | 5 (trivy-config: 2 CRITICAL + 3 HIGH) · hadolint: 2 error | | — | — | — |

**Notas del «antes»:**
- Las columnas «Con corrección», «Sin corrección» y «En CISA KEV» corresponden a la imagen original (antes).
- Trivy cuenta cada falla por cada paquete afectado: los 235 hallazgos CRITICAL del sistema operativo son **40 CVE distintos**, y los 2603 HIGH son **1115 CVE distintos**.
- El cruce con el catálogo CISA KEV (1786 fallas, descargado el 19/11/2026) encontró **5 fallas del sistema operativo que ya se usan en ataques reales**: CVE-2026-111497 (CRITICAL) y CVE-2026-31431, CVE-2026-46300, CVE-2026-53266 y CVE-2026-53362 (HIGH). Son la máxima prioridad.
- La mayoría de los hallazgos vienen de la imagen base completa (`python:3.9`, ~1 GB), con cientos de paquetes que la aplicación no necesita. Las librerías de la app (33) tienen pocos hallazgos y todos con corrección disponible.
- Total de hallazgos del sistema operativo en el antes: 13 919 (todas las severidades); de librerías: 49.

## 3. Top 5 para priorizar
| # | CVE | Paquete | CVSS | EPSS | ¿KEV? | ¿Arreglo? | ¿Se usa la función vulnerable? | Prioridad y acción |
|---|-----|---------|------|------|-------|-----------|--------------------------------|--------------------|
| 1 | CVE-2026-111497 (CRITICAL) · escritura fuera de límites en el decodificador Brotli | libbrotli1 / libbrotli-dev 1.1.0-2+b7 | 9.8 | 82.37 % | **Sí** (agregada 27/10/2026, plazo 10/11/2026) | Sí: 1.1.0-2+deb13u1 | No directamente: llega como dependencia de otras piezas de la imagen completa | **Urgente:** corregir ya (actualizar con `apt-get upgrade` o quitar la pieza con la base slim) |
| 2 | CVE-2026-31431 (HIGH) · kernel: crypto algif_aead | linux-libc-dev 6.12.48-1 | 7.8 | 98.11 % | **Sí** (agregada 01/05/2026) | Sí: 6.12.85-1 | **No:** son cabeceras del núcleo para compilar; el contenedor usa el núcleo del servidor anfitrión | **Urgente → quitar** la pieza de la imagen; el riesgo real está en el núcleo del anfitrión (responsable: plataforma) |
| 3 | CVE-2026-123158 (LOW según Debian) · OpenSSH: omisión de autenticación por contraseña | openssh-client 1:10.0p1-7 | 9.8 | 18.9 % | **Sí** (agregada 09/11/2026, plazo 12/11/2026) | **No** | **No:** la app no usa SSH | **Urgente → quitar** la pieza (la base slim no trae cliente SSH). Ejemplo de por qué no basta un solo número: Debian la marca LOW, pero tiene CVSS 9.8 y está en KEV |
| 4 | CVE-2020-14343 (CRITICAL) · PyYAML: corrección incompleta de CVE-2020-1747 (ejecución de código al cargar YAML) | PyYAML 5.3.1 | 9.8 | 6.24 % | No | Sí: 5.4 | **Sí:** `importar()` usa `yaml.load` inseguro (hallazgo de Semgrep `avoid-pyyaml-load`) | **Alta:** actualizar la librería y usar `yaml.safe_load` (semana 3, responsable: desarrollo) |
| 5 | CVE-2026-44172 (CRITICAL) · MariaDB: inyección SQL con el juego de caracteres big5 | libmariadb-dev 1:11.8.3-0+deb13u1 | 9.1 | 1.04 % | No | **No** | **No:** la app usa PostgreSQL, no MariaDB | **Quitar** la pieza de la imagen (si no se pudiera quitar: vigilar y documentar como riesgo residual) |

**Criterio aplicado (clase, diapositiva 13):** primero KEV, luego gravedad (CVSS), luego probabilidad de ataque (EPSS ≥ 10 % como criterio del curso), luego si existe arreglo y si la pieza se usa. Cuatro de las cinco fallas están en piezas que la aplicación **no usa**: la mejor corrección es quitarlas, y eso lo logra el cambio a la imagen base slim. La única que afecta código que sí se ejecuta es la de PyYAML (#4).

**Fuentes:** NVD (CVSS), FIRST EPSS API (consulta del 19/11/2026), catálogo CISA KEV (descargado el 19/11/2026) y reportes de Trivy de la foto del antes.

## 4. Selección de la imagen base
| Criterio | Opción A | Opción B | Opción C |
|----------|----------|----------|----------|
| Imagen | `python:3.9` (actual) | **`python:3.9-slim-bookworm` (elegida)** | `python:3.9-alpine` / distroless |
| Mantenida / con soporte | Imagen oficial, pero Python 3.9 sin soporte desde octubre de 2025 | Imagen oficial; mismo riesgo de Python 3.9 (se resuelve en la semana 3 con 3.13-slim) | Alpine: igual que B. Distroless: solo trae el Python de su versión de Debian, no 3.9 |
| Tamaño (MB) | ≈ 1 000 | ≈ 150 | ≈ 55 (alpine) / ≈ 50 (distroless) |
| Vulnerabilidades C/H | 235 / 2603 (foto del antes) | Se mide con la tarea «Contenedor» del pipeline (paso 6.6) | No medido |
| Tiene shell / gestor de paquetes | Sí / Sí (apt), más compiladores y herramientas | Sí / Sí (apt): por eso END-05 puede marcar `apt-get` | Alpine: sí (sh / apk). Distroless: no |
| Origen verificado (oficial, firmado) | Docker Official Image | Docker Official Image, fijada por digest (paso 6.4) | Alpine: oficial. Distroless: Google |
| Compatibilidad con la app | Total | Total: las librerías se instalan en la etapa de construcción y se copian ya listas | Alpine usa musl: algunas librerías hay que compilarlas. Distroless no es compatible con Python 3.9 |
| **Decisión y justificación** | Descartada: cientos de piezas que la app no usa (4 de las 5 fallas del Top 5 están en piezas no usadas) | **Elegida:** reduce la imagen de ~1 GB a ~150 MB y elimina las herramientas de compilación, sin romper la compatibilidad con Python 3.9 que exigen PyYAML 5.3.1 y psycopg2-binary 2.9.3 | Más pequeñas, pero con riesgo de incompatibilidad; se pueden reevaluar al actualizar a Python 3.13 |

### 4.1 Cambios del Dockerfile y riesgo que elimina
| # | Antes (`FROM python:3.9`, 28 líneas) | Después (versión protegida, 36 líneas) | Riesgo que elimina |
|---|---------------------------------------|----------------------------------------|--------------------|
| 1 | Una sola etapa con la imagen completa | **Dos etapas:** `construccion` (instala las librerías en `/opt/venv`) y una final `slim` que solo recibe el resultado | Las herramientas de compilación y las piezas de más no llegan a la imagen que se ejecuta: menos fallas y menos herramientas para un atacante |
| 2 | `FROM python:3.9` (≈ 1 GB) | `ARG IMAGEN_EJECUCION=python:3.9-slim-bookworm` (≈ 150 MB) | Cientos de paquetes menos (Brotli de desarrollo, cabeceras del kernel, MariaDB…) y sus fallas |
| 3 | `apt-get install -y curl vim netcat-openbsd iputils-ping`, sin versión fija ni limpieza de caché | Sin herramientas extra; `apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*` | Un atacante que entre no encuentra curl, netcat ni ping listos para usar; se aplican los parches disponibles del SO; la caché no queda en la imagen |
| 4 | `ADD . /app`: copia toda la carpeta, sin `.dockerignore` | `COPY` solo de `cenfopay/` y `run.py`, más un `.dockerignore` | El `.env`, las pruebas y los archivos ocultos ya no entran en la imagen |
| 5 | `ENV DB_PASSWORD=…` y `ENV SECRET_KEY=…` | Sin contraseñas en la imagen | Las claves dejan de verse con `docker inspect` o `docker history` (CWE-798) |
| 6 | Sin `USER`: la app corre como **root** | `useradd --system --uid 10001 … --shell /usr/sbin/nologin` y `USER 10001:10001` | Mínimo privilegio: si alguien toma la app, no es administrador del contenedor ni puede iniciar sesión |
| 7 | Archivos de la app modificables | `COPY --chown=root:root --chmod=0755/0644`: el código pertenece a root y el usuario de la app solo lo lee | La app no puede modificar su propio código, aunque sea comprometida |
| 8 | `pip install` sin `--no-cache-dir` | `pip install --no-cache-dir` en la etapa de construcción | La caché de pip no ocupa espacio ni queda dentro de una capa |
| 9 | Sin `HEALTHCHECK` | `HEALTHCHECK` cada 30 s contra `/salud` | Docker detecta si la app se colgó y puede reiniciarla |
| 10 | `CMD python run.py` (servidor de desarrollo de Flask, forma shell) | `CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", …]` (forma JSON) | Servidor preparado para usuarios reales; la forma JSON evita pasar por una terminal intermedia |
| 11 | — | `# hadolint ignore=DL3005` | Excepción documentada: Hadolint desaconseja `apt-get upgrade`, pero aquí se usa a propósito para aplicar parches de seguridad del SO |

**Riesgo residual:** se mantiene Python 3.9, sin parches desde octubre de 2025, porque las librerías heredadas lo necesitan. Se elimina en la semana 3 al pasar a Python 3.13. La imagen slim todavía incluye `apt-get`, que la verificación END-05 puede reportar.

## 5. Verificación post-endurecimiento
Salida de `bash scripts/verificar-endurecimiento.sh cenfopay:local cenfopay-app-1` (19/11/2026):

```
[i] Imagen: cenfopay:local
✅ END-01 La imagen define un usuario no root (USER)       USER=10001:10001
❌ END-02 Sin secretos en variables ENV de la imagen       variables: GPG_KEY
✅ END-03 HEALTHCHECK definido                             presente
❌ END-04 Tamaño de la imagen <= 250 MB                    312 MB (superficie de ataque mayor)
❌ END-05 Sin herramientas innecesarias en runtime         encontradas: apt-get __sin_shell__
[i] Contenedor en ejecución: cenfopay-app-1
✅ END-06 Sistema de archivos raíz de solo lectura         read_only: true
✅ END-07 Capacidades Linux eliminadas (cap_drop ALL)      [ALL]
✅ END-08 no-new-privileges activo                         activo
✅ END-09 Contenedor no privilegiado                       privileged=false
✅ END-10 Puertos publicados solo en 127.0.0.1             127.0.0.1:8000
✅ END-11 El proceso corre con UID distinto de 0           uid=10001
✅ END-12 Límite de memoria definido                       256 MB
[✓] Resultados en reportes/endurecimiento.json
```

**Resultado: 9 de 12 comprobaciones aprobadas.** Las protecciones de mínimo privilegio, que son las más importantes, pasaron todas: la app corre con UID 10001 (END-01, END-11), no puede escribir en su sistema de archivos (END-06), no tiene capacidades especiales ni puede ascender a administrador (END-07, END-08), no es privilegiada (END-09), solo se publica en 127.0.0.1 (END-10) y tiene tope de memoria (END-12).

**Análisis de las 3 comprobaciones que no pasaron:**

| ID | Hallazgo | Análisis (verificado) | Decisión |
|----|----------|------------------------|----------|
| END-02 | Variable `GPG_KEY` | **Falso positivo.** `docker image inspect` muestra `GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568`: es la huella de la llave **pública** OpenPGP del gestor de versiones de Python (Łukasz Langa), que la imagen oficial usa para verificar la firma del código fuente de Python. No es un secreto. El script la marca porque su regla busca cualquier variable cuyo nombre contenga `KEY` (`(PASSWORD\|SECRET\|TOKEN\|KEY)`). | Documentar como falso positivo. Si la compuerta la bloquea (END-02 es de gravedad ALTA), registrar una excepción con motivo, responsable y vencimiento. |
| END-04 | 312 MB (meta ≤ 250 MB) | Mejora de ≈ 70 % frente a la imagen completa (≈ 1 GB). `docker history` muestra las capas propias: parches del SO (`apt-get upgrade`) **59.5 MB** y librerías de Python (`/opt/venv`) **43.3 MB**; el resto es la imagen base slim. | Riesgo aceptado (gravedad MEDIA) hasta la semana 3: la base nueva (Python 3.13) necesita menos parches. |
| END-05 | `apt-get` presente | **Hallazgo real:** la imagen slim conserva el gestor de paquetes. La marca `__sin_shell__` es un efecto del script: su lista de herramientas termina en `gcc`, que no existe en la imagen, y ese último fallo activa el mensaje `__sin_shell__` aunque la imagen sí tiene shell. | Riesgo bajo, documentado. Se elimina con una imagen sin gestor de paquetes (por ejemplo, distroless) cuando la app use una versión de Python compatible. |
