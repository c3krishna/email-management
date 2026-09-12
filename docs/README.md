# Email Infra Management — Documentation

Worktual **Email Management** is the dual-mail operations and security console for:

| Platform | Domain | Role |
|----------|--------|------|
| **App Mail** | `mail.worktual.tech` | Transactional, CCaaS, AI CCaaS, client-From via Worktual |
| **Campaign** | `mail.worktual.pl` | Bulk sending, bounce/complaint reporting |

Dashboard: [https://email-management.worktual.tech](https://email-management.worktual.tech)

## Documents in this folder

| Document | Description |
|----------|-------------|
| [Email-Infra-Management-Application.md](./Email-Infra-Management-Application.md) | Complete application overview — purpose, modules, roles, APIs, AI |
| [Architecture.md](./Architecture.md) | System architecture diagrams (Mermaid) — topology, data flows, DBs |
| [App-Platform.md](./App-Platform.md) | App Mail platform — hosts, agents, policies, data path |
| [Campaign-Platform.md](./Campaign-Platform.md) | Campaign platform — hosts, agents, policies, data path |

## Related ops docs (repo root)

| Document | Description |
|----------|-------------|
| [../DEPLOY.md](../DEPLOY.md) | Dual-server deployment checklist |
| [../agents-app/README.md](../agents-app/README.md) | Agents on App MTA |
| [../agents-campaign/README.md](../agents-campaign/README.md) | Agents on Campaign MTA |
| [../backend/platform-services/README.md](../backend/platform-services/README.md) | Dashboard-host platform pollers |

## Quick mental model

```text
                    ┌─────────────────────────────────┐
                    │  email-management.worktual.tech │
                    │  React SPA + Express API :5200  │
                    │  Topbar: App Mail | Campaign    │
                    └────────────┬────────────────────┘
           ┌─────────────────────┼─────────────────────┐
           ▼                     ▼                     ▼
   App MTA 10.180.0.84    Campaign MTA 10.180.0.89   MiniAI Ollama
   mail.worktual.tech     mail.worktual.pl           miniai.worktual.tech
   agents-app             agents-campaign            :11434
   MariaDB (email KPIs)   MariaDB @ 10.180.0.203     threat_platform @ App DB host
```
