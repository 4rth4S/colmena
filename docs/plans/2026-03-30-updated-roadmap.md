# Colmena — Roadmap Actualizado (2026-03-30)

> Reemplaza la seccion M2/M3 del roadmap original (2026-03-29-full-roadmap.md).
> El roadmap original sigue siendo valido para M0, M0.5 y M1.

---

## Estado actual

| Milestone | Que | Estado | MR | Tests |
|-----------|-----|--------|-----|-------|
| **M0** | Trust Firewall + Approval Hub | DONE | pre-MR | 40+ |
| **M0.5** | Workspace refactor + MCP server | DONE | pre-MR | 77 |
| **M1** | Wisdom Library + Pattern Selector + RRA hardening | DONE | !1, !2 | 104 |
| **M2** | Peer Review Protocol + ELO Engine + Findings Store | DONE | !3 | 133 |
| **M3** | Dynamic Trust Calibration | NEXT | - | - |

---

## Que cambio respecto al roadmap original

| Original | Ahora | Por que |
|----------|-------|---------|
| M2 = Knowledge Bus + Agent Spawn | M2 = Peer Review + ELO + Findings | CC ya tiene SendMessage (sync) y Agent tool. Bus async tiene mas contras que pros. |
| M3 = ELO Engine + dynamic trust | M3 = Dynamic Trust Calibration (solo) | ELO se absorbio en M2 porque peer review sin ELO no tiene sentido. |
| Knowledge Bus con PostToolUse hook | Descartado | CC no soporta PostToolUse hooks. |
| mission_launch MCP tool | Descartado | CC Agent tool + worktrees cubre esto. |

---

## M3 — Dynamic Trust Calibration

**Goal:** ELO scores influyen en las reglas del firewall. Agentes con ELO alto obtienen trust rules mas permisivas. Agentes con ELO bajo quedan mas restringidos.

**Depends on:** M2 (ELO Engine funcionando con datos reales de peer review)

**Prerequisite:** Usar M2 en produccion lo suficiente para tener datos ELO reales. Sin datos, calibrar trust es prematuro.

### Scope

1. **ELO-based agent_overrides** — Firewall genera agent_overrides automaticamente basado en ELO brackets:
   - ELO >= 1600: trust expandido (mas auto-approve)
   - ELO 1400-1599: trust default
   - ELO < 1400: trust restringido (mas ask)

2. **ELO-weighted reviewer assignment** — Al asignar reviewer en peer review, preferir agentes con ELO mas alto (actualmente es "first available").

3. **ELO-weighted pattern selector** — library_select sugiere agentes con mejor ELO para roles lead.

4. **K-factor** — Agentes con pocas reviews reciben ajustes grandes, agentes establecidos reciben ajustes chicos.

### Lo que NO es M3

- No es un web dashboard (post-M3)
- No es review protocol como lib independiente (post-M3)
- No es ELO por categoria (post-M3, solo global por ahora)

---

## Post-MVP (anotado, sin spec)

| Item | Contexto | Prioridad |
|------|----------|-----------|
| Web dashboard | Visualizacion de ELO, findings, reviews | Alta — el usuario lo pidio |
| K-factor en ELO | Calibracion rapida para agentes nuevos | Media — pocas reviews por ahora |
| ELO por categoria | Rating por dominio (web_vuln, compliance, etc) | Media — requiere datos |
| Review protocol como lib | Extraer a proyecto independiente | Baja — solo si hay adopcion externa |
| ELO per-category en pattern selector | Selector sugiere por ELO de categoria | Baja — depende de ELO por categoria |

---

## Docs de referencia

| Documento | Que cubre |
|-----------|-----------|
| `docs/plans/2026-03-29-full-roadmap.md` | Roadmap original (M0-M1 sigue valido, M2-M3 superseded) |
| `docs/specs/2026-03-29-hivemind-design.md` | Design spec original (M0-M1 sigue valido) |
| `docs/specs/2026-03-30-m2-peer-review-elo-design.md` | Design spec M2 (vigente) |
| `docs/plans/2026-03-30-m2-peer-review-elo.md` | Implementation plan M2 (ejecutado) |
| `docs/dark-corners.md` | Edge cases M0 |
| `docs/dark-corners-m1.md` | Edge cases M1 |

---

*built with ❤️‍🔥 by AppSec*
