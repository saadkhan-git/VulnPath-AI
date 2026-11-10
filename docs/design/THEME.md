# VulnPath AI — Design System & Analyst Workbench Tokens

## 1. Visual Identity Principles

The VulnPath AI frontend embodies a high-performance, dark-themed cybersecurity analyst workbench. It uses deep obsidian surfaces, sharp borders, high-contrast typography, and purposeful semantic color coding to highlight critical security alerts without eye strain.

### Core Color Palette

| Token | Hex Value | Application |
| :--- | :--- | :--- |
| `surface-ground` | `#070A11` | Primary background canvas |
| `surface-panel` | `#0D1322` | Card and container panels |
| `surface-overlay` | `#162035` | Modals, popovers, dropdowns |
| `border-subtle` | `#1E293B` | Structural dividing borders |
| `border-accent` | `#334155` | Focused and highlighted borders |
| `accent-cyan` | `#00E5FF` | Primary active accent, telemetry graphs |
| `accent-blue` | `#3B82F6` | Interactive buttons, navigation active states |
| `accent-purple` | `#8B5CF6` | Flow nodes, deep-learning indicators |

### Severity Token Hierarchy

| Severity | Color | Hex | Visual Purpose |
| :--- | :--- | :--- | :--- |
| **Critical** | Carmine Red | `#EF4444` | Immediate exploitation risk, shell / RCE |
| **High** | Vivid Orange | `#F97316` | Direct injection (SQLi, SSRF, Deserialization) |
| **Medium** | Amber Yellow | `#F59E0B` | Information disclosure, path traversal |
| **Low** | Cyber Cyan | `#06B6D4` | Security misconfigurations, weak crypto |
| **Info** | Slate Muted | `#64748B` | Hardening suggestions, audit trails |

---

## 2. Typography

- **Headings & UI Text:** Inter / system-ui (`sans-serif`), clean sans-serif with geometric precision.
- **Code, Sinks & Evidence:** JetBrains Mono / Fira Code (`monospace`), clear ligatures and distinction between symbols (`0` vs `O`, `1` vs `l`).

---

## 3. UI Component Standards

- **Metric Cards:** Crisp dark card surfaces with subtle outer borders (`border border-slate-800 bg-slate-900/60 backdrop-blur`), glowing accent indicators.
- **Vulnerability Path Flow:** Powered by `@xyflow/react` with custom styled nodes:
  - Source Node (Amber / Blue indicator)
  - Transformation Node (Slate / Purple indicator)
  - Sink Node (Red / Orange indicator)
- **Code Context Viewer:** Line numbering, vulnerable line highlight (`bg-red-500/20 border-l-2 border-red-500`), and syntax-highlighted tokens.
