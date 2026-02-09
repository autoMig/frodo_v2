# Frodo - Firewall Operations & Definition Orchestration

## Current Phase: Phase 2 - Illumio Details

---

## Purpose

Frodo enables application teams to view and manage firewall policies for their applications across varied infrastructure (on-prem physical/virtual, AWS, GCP, Azure). Teams receive applications as managed services but remain responsible for firewall rules—Frodo closes this visibility and control gap.

**Core capabilities**: List applications by AD group membership, view firewall applicability per application, inspect rulesets and traffic flows per platform (Illumio, NSX, Checkpoint), and propose rules for traffic not currently permitted.

---

## Key Concepts

| Term | Definition |
|------|-------------|
| **Application** | Unique combination of Business Application Name + Environment (e.g. "App-X Production" vs "App-X UAT") |
| **Business Application Name** | Stripped of suffixes (-DEV, -UAT, -CONT, -OAT); use server properties for env |
| **Environment** | From Unicorn `environment.code` (e.g. production, uat) |

---

## Authentication and Authorization

- **Auth**: ADFS (SAML 2.0 / OIDC as per org standard)
- **Authorization**: AD group membership determines which applications a user can manage
- **Mapping**: Naming convention—e.g. AD group `APP-X-Prod-Owners` maps to Application "APP-X" + Environment "Production"

---

## Platform Integrations

| Platform | Purpose | Auth |
|----------|---------|------|
| **Unicorn** | Central inventory: Application ownership, server lifecycle, server metadata | X-API-User, X-API-Key |
| **Illumio** | Host-based firewall on Windows/Linux | API key/secret (illumio library) |
| **NSX** | Distributed firewall (internal cloud) | TBD Phase 3 |
| **Checkpoint** | Physical firewall (perimeter + internal zones) | TBD Phase 4 |

**Server-to-platform matching**: Primarily by hostname across all platforms.

---

## Firewall Applicability Rules (per server)

| Condition | Firewall |
|-----------|----------|
| `osVersion.operatingSystem.name` is WINDOWS or LINUX | Illumio |
| `networkIdentifier.code` in {IDMZ, EMDZ, EXTRANET} | External Checkpoint |
| `networkSubzone` present, not blank, not "HERITAGE" | Internal Checkpoint |
| `hostingPlatform.name` starts with "ICP-2" | NSX |

---

## Phased Implementation

### Phase 1 - Application Summary (Read-only)

**Goal**: Application teams see which firewalls apply to their applications.

- Integrations: Unicorn, Illumio (for enforcement status only)
- UI: Application cards list; each card shows app name + environment, server count, pill icons for applicable firewalls, Illumio pill colour (Fully/Partially/Not Enforced)
- Data flow: Unicorn servers → group by app+env → determine firewall applicability; Illumio VENs → match by hostname → compute enforcement status per app+env

**Phase 1 Checklist**

- [x] Unicorn client with mock data for dev
- [x] Illumio client (illumio Python library)
- [x] Application aggregation service
- [x] FastAPI /api/applications endpoint
- [x] React application cards with pill icons
- [x] Illumio enforcement status (Fully/Partially/Not Enforced)
- [x] Configurable logging
- [x] Docker setup

### Phase 2 - Illumio Details (Read-only) [CURRENT]

- Application details view (click card to open)
- Overview tab: hosts, firewalls (from cache)
- Illumio tab with Workloads, Ruleset, Traffic sub-tabs
- Traffic query builder: source, destination, port, duration, action
- NSX and Checkpoint placeholder tabs

**Phase 2 Checklist**

- [x] GET /api/applications/{app}/{env} (overview from cache)
- [x] GET /api/applications/{app}/{env}/illumio/workloads (real-time API, label-filtered, max 500)
- [x] GET /api/applications/{app}/{env}/illumio/rulesets
- [x] POST /api/applications/{app}/{env}/illumio/traffic (query builder)
- [x] React Router with /applications/:app/:env
- [x] Application details view with tabs
- [x] Overview tab, Illumio tab (Workloads/Ruleset/Traffic), NSX/Checkpoint placeholders

### Phase 3 - NSX Details (Read-only)

- View NSX ruleset for the application
- View NSX traffic report for the application

### Phase 4 - Checkpoint Details (Read-only)

- View Checkpoint ruleset for the application (External and/or Internal)
- View Checkpoint traffic report for the application

### Phase 5 - Rule Writing (Proposal only)

- Users can propose rules for traffic not currently permitted
- Provisioning and Change management remain **outside** Frodo

---

## Technical Architecture

| Layer | Technology |
|-------|------------|
| Frontend | React (Vite) |
| Backend | Python (FastAPI) |
| Auth | ADFS |
| Container | Docker |
| Caching | Configurable; TTL-based per data type |
| Logging | LOG_LEVEL env var and .env |

---

## Integration Specs

### Unicorn

- **Auth**: X-API-User, X-API-Key headers
- **Endpoint**: GET /servers?pageIndex={n}&pageSize=10000
- **Pagination**: Query params (not headers). Increment pageIndex until results count < pageSize.
- **Lifecycle filter**: Repeated `LifecycleState` query param per state (e.g. `LifecycleState=Registered&LifecycleState=Live&LifecycleState=Configure`). Configurable via `UNICORN_LIFECYCLE_STATES` (comma-separated).
- **Response**: JSON object with results array (server objects: hostname, environment, osVersion, networkIdentifier, networkSubzone, hostingPlatform, services)

### Illumio

- **Auth**: API key/secret via illumio Python library
- **Library**: illumio (PyPI)
- **Workloads**: Match by hostname; labels for app/env
- **Labels cache**: Labels fetched during cache refresh (parallel with workloads); used for workloads, ruleset, and traffic label resolution. New labels created in Illumio between refreshes are not available until next refresh.
- **Workloads tab**: Real-time API with label filter (app+env); max 500 workloads per application; both managed and unmanaged workloads returned.

---

## Open Items

- Exact AD group naming convention
- Illumio label names for app and env (default: app, env)
- API base URLs and credentials management per environment
- Cache TTL values per data type
