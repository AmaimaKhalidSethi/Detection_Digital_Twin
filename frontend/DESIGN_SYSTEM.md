# Design System — Detection Digital Twin

Status: **migrating**. Old tokens (`graphite-*`, `signal-*`, `amber-*`, `alert-*`) stay
active until every page below is checked off. Never remove an old token while any page
still references it.

## Palette

### New (target)
| Token | Source | Hex | Meaning |
|---|---|---|---|
| `bg-950` | custom | `#0a0e16` | app background |
| `bg-900` | custom | `#111a29` | panel background |
| `bg-800` | custom | `#1a2740` | raised surface / hover |
| `cyan-400` | Tailwind built-in | `#22d3ee` | verified / confirmed / "twin proved this" |
| `cyan-500` | Tailwind built-in | `#06b6d4` | cyan, stronger (borders, active states) |
| `fuchsia-400` | Tailwind built-in | `#e879f9` | drift / blind spot / needs attention |
| `fuchsia-500` | Tailwind built-in | `#d946ef` | fuchsia, stronger |
| `rose-500` | Tailwind built-in | `#f43f5e` | genuine alerts ONLY — never reused for drift |
| `slate-300` | Tailwind built-in | `#cbd5e1` | body text |
| `slate-500` | Tailwind built-in | `#64748b` | muted/secondary text |

### Old (being phased out — do not add new usages)
`graphite-950/900/800/700/600/500/400/300/200/100`, `signal-500/400/600`,
`amber-500/400`, `alert-500/400` — see `src/index.css`.

## Typography
Unchanged: `font-mono` for anything copy-pasteable (technique IDs, rule titles, command
lines, log-style output). `font-sans` for everything else. This was correct before and
stays correct — real SOC tools do this too.

## Components (`src/components/ui.jsx`)

| Component | Old classes | New target classes | Migrated? |
|---|---|---|---|
| `Panel` | `border-graphite-700 bg-graphite-900` | `border-bg-800 bg-bg-900` | ☐ |
| `Badge` tone="signal" | `bg-signal-500/15 text-signal-400 border-signal-500/30` | `bg-cyan-500/15 text-cyan-400 border-cyan-500/30` | ☐ |
| `Badge` tone="amber" | `bg-amber-500/15 text-amber-400 border-amber-500/30` | `bg-fuchsia-500/15 text-fuchsia-400 border-fuchsia-500/30` | ☐ |
| `Badge` tone="alert" | `bg-alert-500/15 text-alert-400 border-alert-500/30` | `bg-rose-500/15 text-rose-400 border-rose-500/30` | ☐ |
| `Button` variant="primary" | `bg-signal-500 text-graphite-950 hover:bg-signal-400` | `bg-cyan-500 text-bg-950 hover:bg-cyan-400` | ☐ |
| `Button` variant="danger" | `bg-alert-500/15 text-alert-400 border-alert-500/40` | `bg-rose-500/15 text-rose-400 border-rose-500/40` | ☐ |
| `EmptyState` | `border-graphite-600`, `text-graphite-300/500` | `border-bg-800`, `text-slate-300/500` | ☐ |
| `ErrorNote` | `border-alert-500/40 bg-alert-500/10 text-alert-400` | `border-rose-500/40 bg-rose-500/10 text-rose-400` | ☐ |

## Pages migrated
☐ RulesLibraryPage · ☐ RuleEditorPage · ☐ RuleTestingPage · ☐ CoveragePage ·
☐ DriftPage · ☐ AlertsPage · ☐ Overview (new)

## Signature element
ATT&CK-Navigator-style coverage heatmap — grid of technique cells grouped by tactic
column, 4-state cell color:
- both (twin verified + Wazuh active): solid `cyan-500`
- twin-only blind spot: solid `fuchsia-500`
- production-only (twin untested): `cyan-500` at 10% opacity, outline only
- neither: `bg-800`, near-invisible

## Motion
One deliberate moment only: `.console-bg` grid pulses subtly while a background job's
status is `running`. Static otherwise. `prefers-reduced-motion` respected (already handled
globally in `index.css`).