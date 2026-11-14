# Justificación de umbrales de bloqueo y riesgos residuales · CenfoPay

> Este documento acompaña a `security/politica-umbrales.yml`. Cada número de la
> política debe tener aquí su razón. Se evalúa en el criterio 4 de la rúbrica del proyecto.

## 1. Contexto de riesgo de la aplicación
- Tipo de datos que maneja (ficticios en el curso, pero tratados como si fueran reales): datos personales y financieros de una billetera digital: usuarios, contraseñas, cuentas, saldos, movimientos y transferencias.
- Exposición (Internet / red interna / solo laboratorio): solo laboratorio (codespace y máquinas temporales de GitHub Actions). Se analiza como si fuera a publicarse en Internet, porque ese sería su uso real.
- Marco de referencia aplicable (p. ej. PCI-DSS 6.2-6.3, Ley 8968, normativa SUGEF de TI): PCI-DSS v4.0, requisitos 6.2 (desarrollo seguro) y 6.3 (identificar y atender vulnerabilidades); Ley 8968 de Protección de la Persona frente al Tratamiento de sus Datos Personales (Costa Rica); y la normativa de gestión de TI de SUGEF para entidades financieras.

## 2. Umbrales por herramienta
| Herramienta | Severidad | Umbral | Modo | Por qué este número (impacto, explotabilidad, ruido, costo de bloquear) |
|------------|----------|-------:|------|--------------------------------------------------------------------------|
| semgrep | ERROR | 5 | bloquear | Límite de tolerancia: igual a los 5 hallazgos ERROR abiertos hoy en el pipeline (inyección de comandos en `resolver()` y deserialización YAML insegura en `importar()`). Son explotables de forma remota y las reglas tienen confianza HIGH (poco ruido). Un umbral 0 bloquearía todo cambio hasta la semana 3; con 5, ninguna falla grave nueva puede entrar. Comprobado con el PR #1: 8 > 5, bloqueado. Baja a 0 en la semana 3. |
| zap | High | 0 | bloquear | No hay ninguna hoy y su impacto sería alto: tolerancia cero. |
| zap | Medium | 3 | bloquear | Igual a las 3 alertas actuales (falta de CSP, de protección anti-clickjacking y de tokens anti-CSRF). El umbral bajó de 10 a 3. Son defensas del navegador que faltan, no fallas explotables por sí solas, pero no se permite agregar nuevas. Se corrigen en la semana 3. |
| hadolint | error | — | — | Se activa en la semana 2. |
| trivy-so | CRITICAL / HIGH | — | — | Se activa en la semana 2. |
| trivy-dependencias | CRITICAL / HIGH | — | — | Se activa en la semana 2 (solo reporta) y detiene desde la semana 3. |
| bandit | HIGH | — | — | Se activa en la semana 3. |
| gitleaks | SECRETO | 0 | — | Se activa en la semana 4. |
| endurecimiento | ALTA | — | — | Se activa en la semana 2. |
| registros | ALTA | 0 | — | Se activa en la semana 4. |

**Criterios usados:** gravedad (ERROR = vulnerabilidad explotable con evidencia de flujo de datos), facilidad de aprovechamiento, tasa de falsos positivos de cada regla y costo de detener el trabajo.

**Por qué 5 y no 11:** la foto local (`foto.sh antes`) reportó 11 ERROR de Semgrep porque incluye las reglas propias de CenfoPay, que en el pipeline se activan en la semana 3. El pipeline de la semana 1 evalúa 5 ERROR con las reglas generales de Python. El umbral se fijó con el número del pipeline, que es el que evalúa la compuerta.

**Trazabilidad:** el paso a modo bloquear se hizo con `bash scripts/tolerancia.sh 5 3` (commit `0d53267`). La corrida #4 quedó APROBADA en modo bloquear.

## 3. Disparadores
| Evento | Qué corre | Por qué |
|--------|-----------|---------|
| pull_request a main | Todas las etapas activas de la semana y la compuerta, que es un check obligatorio del ruleset `proteger-main` | Revisar cada cambio ANTES de integrarlo: si supera un umbral, el PR no se puede fusionar. |
| push a main | Todas las etapas activas de la semana y la compuerta | Confirmar que lo integrado sigue cumpliendo la política y guardar la evidencia (90 días). |
| schedule semanal | El pipeline completo, cada lunes a las 3:17 a.m. de Costa Rica (`cron: "17 9 * * 1"`, en UTC) | Detectar fallas nuevas publicadas (CVE) aunque el código no cambie, en un horario de baja actividad. |
| workflow_dispatch | El pipeline bajo demanda, con modo elegible (politica, auditar o bloquear) | Volver a ejecutar tras cambiar un secreto o para una auditoría. Riesgo: en modo auditar solo avisa; se mitiga porque main exige PR con compuerta. |

El pipeline solo tiene permiso de lectura (`contents: read`, mínimo privilegio) y usa acciones de terceros fijadas por su SHA, no por etiqueta, para protegerse de ataques a la cadena de suministro.

## 4. Riesgos residuales (lo que queda abierto después de corregir)
| # | Riesgo | Origen (hallazgo/huella) | Por qué no se corrige ahora | Control compensatorio | Dueño | Revisión |
|---|--------|--------------------------|-----------------------------|-----------------------|-------|----------|
| 1 | Inyección de comandos y deserialización insegura (5 ERROR) | Semgrep: subprocess-injection, dangerous-subprocess-use, subprocess-shell-true (`__init__.py:85-86`), avoid-insecure-deserialization y avoid-pyyaml-load (`__init__.py:95`) | Las correcciones del código se aplican en la semana 3 | Límite de tolerancia: no puede entrar ninguna falla nueva; la app corre solo en laboratorio | Larry Castillo | Semana 3 |
| 2 | Faltan cabeceras de seguridad (CSP, anti-clickjacking, anti-CSRF) | ZAP: 3 alertas Medium | Se corrigen en la semana 3 | Umbral 3: no se aceptan alertas Medium nuevas | Larry Castillo | Semana 3 |
| 3 | Fallas que el pipeline de la semana 1 aún no detecta: inyección SQL, XSS, SSTI, path traversal | Foto local (11 ERROR con reglas propias) y pruebas de `test_seguridad.py` | Las reglas propias se activan en el pipeline en la semana 3 | La línea base de pruebas (11 failed) las documenta; el XSS se verificó manualmente | Larry Castillo | Semana 3 |
| 4 | Sin revisión humana obligatoria (0 aprobaciones) | Ruleset `proteger-main` | Trabajo individual: GitHub no permite aprobar el PR propio | Compuerta obligatoria y lista de excepciones (bypass) vacía | Larry Castillo | Al trabajar en equipo |
| 5 | Ejecución manual en modo auditar | `workflow_dispatch` del pipeline | Es útil para auditorías | Main protegida: solo entra código por PR con la compuerta | Larry Castillo | Semana 4 |
| 6 | Python 3.9 ya no recibe parches | Imagen base de la aplicación | Las librerías actuales lo requieren | Se actualiza en la semana 3 | Larry Castillo | Semana 3 |
| 7 | Credenciales de QA en el historial de git (commit `e31dd2c`) | Gitleaks: 6 hallazgos críticos en la foto del antes | Se atiende en la semana 4 (incidente INC-001) | Repositorio de laboratorio con datos ficticios | Larry Castillo | Semana 4 |

## 5. Excepciones aprobadas
| Herramienta | ID | Justificación | Responsable | Vence |
|------------|----|---------------|-------------|-------|
| — | — | Ninguna en la semana 1. | — | — |
