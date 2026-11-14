# Bitácora de uso de inteligencia artificial · CenfoPay

> Requisito del proyecto (criterio 5 de la rúbrica): documenta **cada** aporte de una
> herramienta de IA (ChatGPT, Claude, Copilot, Gemini, DiálogoX, etc.) y **cómo lo verificaste**.
> Nunca pegues en una IA secretos, tokens ni datos reales: en este curso solo existen datos de prueba.

**Herramienta usada:** Claude (Anthropic), como tutor paso a paso. **Datos compartidos con la IA:** solo la guía del curso, capturas de pantalla, salidas de la terminal y reportes de las herramientas. Nunca se compartieron contraseñas, tokens ni el contenido de `.env`.

| # | Fecha | Herramienta de IA | Semana / tarea | Qué le pediste (resumen del prompt) | Qué aportó | Cómo lo verificaste (prueba, escaneo, documentación oficial) | ¿Lo usaste? ¿Qué cambiaste? |
|---|-------|-------------------|----------------|-------------------------------------|------------|----------------------------------------------------------------|------------------------------|
| 1 | 12/11/2026 | Claude | Antes de empezar · revisión de la guía | Revisar si la guía tenía instrucciones ambiguas o mal formuladas | Lista de inconsistencias: falta el «después» de la imagen en la semana 2, conteos de pruebas que no coinciden, modalidad y forma de entrega sin definir, Vault en memoria para la demo | Leí las secciones citadas (5.4, 6.1, 6.7, 7.3, 8.6, 9.2 y 9.3) y consulté al docente la modalidad y la entrega | Sí. El docente confirmó: individual, entrega por el sitio de la Universidad |
| 2 | 12/11/2026 | Claude | Antes de empezar · formato | Qué formato de documento exige la guía | Solo la sección 9.2 define formato (Arial o Times 11-12, interlineado 1.5, APA 7, PDF); no define bordes ni colores | Leí la sección 9.2 de la guía | Sí. Usé además el estilo de un laboratorio anterior aprobado |
| 3 | 12/11/2026 | Claude | 4.1 · cuenta de GitHub | Por qué mi página de GitHub se veía distinta a la del profesor | Eran páginas distintas (Dashboard vs. perfil → Repositories) y temas distintos (oscuro vs. claro) | Abrí avatar → Repositories y vi la misma estructura | Sí, sin cambios |
| 4 | 12/11/2026 | Claude | 4.2 · repositorio | Cómo crear el repositorio desde la plantilla | Pasos: Use this template → Create a new repository, nombre `cenfopay-devsecops`, Public, sin «Include all branches» | El repositorio muestra «Generated from ccantero-cyber/cib665-devsecops-kit» y 1 rama | Sí, sin cambios |
| 5 | 12/11/2026 | Claude | 4.3 · codespace | Por qué aparecían 21 cambios (`main*`) que yo no hice | Revisar antes de subir: `git diff --summary` mostró `mode change 100644 => 100755` en `scripts/*.sh` (permisos). Solución: `git config core.fileMode false` | `git status` respondió «nothing to commit, working tree clean» | Sí. No se subió ningún cambio innecesario |
| 6 | 12/11/2026 | Claude | 4.4 · iniciar el proyecto | Qué hace `iniciar.sh` | Explicó sus 4 acciones, incluida la fuga simulada de credenciales en el historial | La terminal mostró solo [✓] y GitHub mostró 3 commits; la fuga está en el commit `e31dd2c` | Sí, sin cambios |
| 7 | 12/11/2026 | Claude | 5.1 · encender el pipeline | Diferencia entre `proyecto.yml` y `devsecops.yml` | `proyecto.yml` solo indica la semana; `devsecops.yml` es el pipeline, que no se edita | Abrí ambos archivos y vi `semana: 1` y las condiciones por semana | Sí, sin cambios |
| 8 | 13/11/2026 | Claude | 5.2 · conocer el pipeline | Si mi repositorio era visible para el profesor (el perfil decía «no public repositories») | Probar en una ventana de incógnito | En incógnito el repositorio abrió como Public, sin sesión iniciada | Sí, sin cambios |
| 9 | 13/11/2026 | Claude | 5.2 · conocer el pipeline | Dónde encontrar las partes del pipeline | Abrir `devsecops.yml` (o «Workflow file» en Actions) y buscar con Ctrl+F: `on:`, `permissions:`, `uses:`, `config:`, `compuerta:` | Encontré cada parte; verifiqué el cron `"17 9 * * 1"` = lunes 3:17 a.m. en Costa Rica (UTC-6) | Sí, sin cambios |
| 10 | 13/11/2026 | Claude | 5.4 · foto del antes | Cómo leer los reportes y elegir los 3 hallazgos | Propuso SQLi (Semgrep), CSP (ZAP) y XSS (no detectado), relacionando cada uno con las pruebas que fallan | CWE-89 en `security/semgrep/reglas-cenfopay.yml`; CWE-693 en el reporte de ZAP; XSS verificado en el navegador con `/saludo?nombre=<i>Larry</i>` (salió en cursiva) | Sí. Elegí esos 3 después de verificarlos |
| 11 | 13/11/2026 | Claude | 5.5 · límite de tolerancia | Qué números usar para la tolerancia | Tomar los de la compuerta en Actions, no los de la foto local | Actions mostró semgrep ERROR = 5 (la foto local mostraba 11 porque incluye reglas propias). Usé 5 y 3 y la corrida #4 quedó APROBADA | Sí. La IA esperaba 11; el dato real del pipeline fue 5 |
| 12 | 13/11/2026 | Claude | 5.6 · proteger main | Cómo configurar el ruleset de main | Active, lista de excepciones vacía, PR obligatorio y «Compuerta de seguridad» como check requerido | El PR de prueba quedó con «Required» y el botón Merge deshabilitado | Sí, sin cambios |
| 13 | 13/11/2026 | Claude | 5.7 · prueba de la compuerta | Si el resultado del PR de prueba era el esperado | Confirmó el bloqueo (8 > 5) y explicó los dos controles que fallaron | Revisé el resumen de la compuerta y el panel «Merge status» | Sí, sin cambios |
| 14 | 13/11/2026 | Claude | 5.8-5.9 · documentación | Organizar capturas, armar el borrador del Laboratorio 1 y redactar `umbrales-y-riesgo-residual.md` | Capturas sin repetidas, borrador en Word y texto de umbrales y riesgos con mis datos | Comparé cada número y enlace con GitHub Actions y con mis capturas | Sí. Revisé la redacción antes de subirla |

## Reflexión final (5-10 líneas)
- ¿En qué te ayudó la IA y en qué se equivocó?
- ¿Qué aprendiste a verificar que antes darías por bueno?

*(Se completa al cierre del curso, sección 8.10.)*

**Avance semana 1:** la IA me ayudó a entender cada paso y a detectar a tiempo problemas que no eran míos (los 21 cambios de permisos). Se equivocó al suponer que el umbral de Semgrep sería 11: el pipeline mostraba 5. Aprendí a tomar siempre el dato de la fuente oficial (la compuerta en Actions) y a comprobar cada hallazgo antes de reportarlo, como hice con el XSS.
