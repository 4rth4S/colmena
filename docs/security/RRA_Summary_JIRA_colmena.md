🔴 RRA → "Nivel de Riesgo: Alto"

**Caso:** Colmena — Trust Firewall + Approval Hub para orquestación multi-agente de Claude Code

**Datos Manejados:**
- Payloads de tool invocations de Claude Code (tool_name, tool_input con contenido de archivos, comandos bash, rutas)
- Configuración de reglas de trust (trust-firewall.yaml con patrones regex, rutas permitidas, exclusiones)
- Runtime delegations (escalaciones de trust temporal/permanente con TTL, tool scope, agent scope)
- Queue de aprobaciones pendientes (tool_input completo, agent_id, timestamps, decisiones)
- Paths del filesystem del usuario (directorio HOME, rutas de proyecto, ubicación de binarios)
- agent_id y session_id de sesiones de Claude Code
- Contenido de system prompts y configuraciones de roles para agentes
- Configuración de ~/.claude/settings.json (hooks, plugins, permisos)

**Exposición:** Alta.

- **Vector 1: Auto-escalación via MCP delegate** — Cualquier agente puede invocar el tool MCP `delegate` para auto-aprobarse herramientas restringidas, incluyendo Bash. Sin control de acceso ni confirmación humana. (DREAD: 9.4)
- **Vector 2: Delegaciones permanentes sin expiración** — El flag `--permanent` crea trust infinito que persiste entre sesiones y reinicios. No existe mecanismo de revocación programática. (DREAD: 8.8)
- **Vector 3: Cadenas de agentes autónomos** — Agent spawning auto-aprobado permite crear enjambres de sub-agentes que heredan trust rules y delegaciones. Sin límite de profundidad ni rate-limiting. (DREAD: 8.8)
- **Vector 4: Ausencia total de audit trail** — Operaciones auto-aprobadas (mayoría del tráfico) no dejan rastro. Delegaciones se crean/modifican sin logging. Impossible realizar incident response. (DREAD: 8.8)

**Impacto:** Alto.

**Financiero:**
- Ejecución de comandos destructivos auto-aprobados podría resultar en pérdida de datos, corrupción de repositorios y downtime de desarrollo
- Compromiso de credenciales almacenadas en queue entries en texto plano
- Costo de incident response sin audit trail (horas de análisis manual)

**Seguridad:**
- Auto-escalación de privilegios permite bypass completo del firewall de trust
- Delegaciones cross-session filtran trust entre contextos no relacionados
- Regex de blocked incompleto permite variaciones de comandos destructivos
- Fallback de HOME a /tmp en containers expone config y queue a todos los usuarios del sistema

**Fraude/AML:**
- Bajo riesgo directo — herramienta interna de desarrollo
- Riesgo indirecto si agentes comprometidos manipulan código de sistemas financieros

**Reputacional:**
- Compromiso de herramienta de seguridad interna erosiona confianza en el equipo de AppSec
- Si Colmena se distribuye externamente, vulnerabilidades en trust escalation son de alto impacto reputacional

**Operacional:**
- Queue sin pruning ya tiene 180+ archivos acumulados
- Config reload en cada hook invocation impacta latencia (<100ms target)
- stdin sin límite de tamaño puede causar OOM del hook process
- Ausencia de logging impide troubleshooting y capacidad operativa

**Probabilidad:** Alta.

Los vectores principales no requieren exploits externos — son funcionalidades del propio sistema que pueden ser abusadas por agentes autónomos. La herramienta MCP `delegate` es invocable por cualquier agente sin restricciones (DREAD Exploitability: 9/10). Las delegaciones permanentes persisten indefinidamente por diseño. La falta de audit trail es un problema sistémico presente en el 100% de operaciones auto-aprobadas.

---

**Resultado:**
🔴 **Riesgo Alto** → Requiere remediación de controles de acceso en delegaciones y audit trail completo antes de uso en producción.

---

**Acciones:**

**Inmediatas (Sprint Actual):**
1. **[P0]** Implementar ACL en tool MCP `delegate`: requerir confirmación humana explícita antes de crear delegaciones. Nunca permitir que un agente se auto-delegue trust. (`colmena-mcp/src/main.rs:L151-180`)
2. **[P0]** Eliminar opción `--permanent` o imponer TTL máximo configurable (ej: 24h). Requerir re-confirmación periódica para delegaciones de larga duración. (`colmena-cli/src/main.rs:L248-252`)
3. **[P0]** Implementar audit log para TODAS las decisiones (auto-approve, ask, block) con timestamp, session_id, agent_id, tool, action y hash de tool_input. Formato append-only. (`colmena-cli/src/main.rs:L176`)
4. **[P0]** Agregar rate-limiting o depth-limit para Agent spawning. Considerar cambiar Agent de auto-approve a ask en trust-firewall.yaml. (`config/trust-firewall.yaml:L70-72`)
5. **[P0]** Implementar `colmena delegate list` y `colmena delegate revoke --tool X [--agent Y]` para revocación programática. (`colmena-core/src/delegate.rs`)

**Corto Plazo (2-4 semanas):**
6. **[P1]** Implementar filtrado de session_id en `check_delegations`: delegaciones deben ser scoped a la sesión que las creó. (`colmena-core/src/firewall.rs:L76-95`)
7. **[P1]** Agregar límite de lectura de stdin (ej: 10MB) usando BufReader con take(). (`colmena-cli/src/main.rs:L144-147`)
8. **[P1]** Cachear config compilada con hash de archivo. Solo recompilar si el hash cambia. (`colmena-cli/src/main.rs:L157-158`)
9. **[P1]** Implementar pruning automático de queue: TTL de 7 días para entries, mover decididas a `queue/decided/`. (`colmena-core/src/queue.rs`)
10. **[P1]** Expandir blocked patterns en trust-firewall.yaml: `rm -rf /` → `rm\s+-rf\s+/`, agregar variaciones (shred, dd, find -delete). (`config/trust-firewall.yaml:L98`)

**Threat Modeling (Sesión Dedicada — 2 semanas):**
11. Programar sesión de Threat Modeling STRIDE con foco en:
    - **Spoofing:** Validación de session_id y agent_id en delegaciones. Identidad MCP hardcoded.
    - **Tampering:** Integridad de config, delegaciones, queue entries y settings.json. Race conditions en load-modify-save.
    - **Repudiation:** Audit trail completo para auto-approve y delegaciones. Integridad de logs forenses.
    - **Information Disclosure:** Sanitización de error messages. Cifrado de queue entries at rest. Redacción de tool_input sensible.
    - **Denial of Service:** Límites de stdin, config caching, queue pruning, ReDoS protection.
    - **Elevation of Privilege:** ACL en delegate, Agent spawning limits, path_not_match scope expansion, restricted pattern completeness.

**Validaciones Técnicas Específicas:**
12. Eliminar fallback de HOME a `/tmp` en `paths.rs:L22` e `install.rs:L135`. Fallar con error explícito si HOME no está definido.
13. Sanitizar mensajes de error antes de enviar a stdout del hook — usar mensajes genéricos para CC, detalles solo en error log. (`main.rs:L135`)
14. Extender `glob_match` para operar sobre path completo además de filename. Agregar opción `path_not_contains` para directorios. (`firewall.rs:L217-233`)
15. Generar session_id y tool_use_id únicos por invocación MCP evaluate. (`colmena-mcp/src/main.rs:L193-197`)
16. Implementar file locking (flock) en el patrón load-modify-save de delegaciones. (`delegate.rs:L44-58`)

**Compliance y Monitoreo:**
17. Implementar structured logging (JSON) con:
    - Todas las decisiones de firewall (approve/ask/block)
    - Creación, uso y expiración de delegaciones
    - Errores de evaluación y config
    - Spawning de agentes (parent_agent → child_agent)
18. Agregar checksums por línea en error log para integridad forense. Considerar integración con syslog. (`main.rs:L544-556`)

**Documentación:**
19. Documentar modelo de amenazas de Colmena: qué protege, qué NO protege, supuestos de trust.
20. Documentar riesgos de `--permanent` en delegaciones y cuándo es apropiado usarlo.
21. Agregar security hardening guide: permisos de directorio, configuración segura, mejores prácticas.

---

**Owner/Responsables:**
- **Security Team:** Items 1, 2, 3, 4, 5, 10, 12, 16, 19, 20, 21 (controles de acceso, patrones de trust, documentación)
- **Backend Team:** Items 6, 7, 8, 9, 13, 14, 15, 16 (código core, performance, integridad)
- **DevOps:** Items 12, 17, 18 (infraestructura, logging, monitoreo)

---

**KPIs de Éxito:**
- ✅ 0 herramientas MCP que permitan auto-escalación de trust sin confirmación humana
- ✅ 100% de decisiones de firewall (approve/ask/block) registradas en audit log
- ✅ TTL máximo para delegaciones ≤ 24 horas (sin opción permanent sin confirmación explícita)
- ✅ Tiempo de respuesta del hook < 100ms en p99 con config cacheada
- ✅ Queue pruning automático: 0 entries > 7 días en pending/
- ✅ 0 fallbacks a /tmp en resolución de directorios
- ✅ Cobertura de blocked patterns: rm, shred, dd, find-delete, git reset hard, git push force
- ✅ File locking implementado en operaciones de delegación (0 race conditions)
- ✅ Session-scoped delegations: 0 filtración de delegaciones entre sesiones
- ✅ Error messages sanitizados: 0 rutas internas expuestas en respuestas del hook

---

**Fecha Target de Remediación Completa:** 6 semanas (2 sprints)

- Sprint 1 (semanas 1-3): Items P0 (1-5) + validaciones críticas (12, 13)
- Sprint 2 (semanas 4-6): Items P1 (6-10) + compliance (17-18) + documentación (19-21)

**Revisión de Seguimiento:** Quincenal — verificar progreso de KPIs y nuevas amenazas identificadas.

---

*built with ❤️‍🔥 by AppSec*
