# Frodo - Firewall Operations & Definition Orchestration

Frodo enables application teams to view and manage firewall policies for their applications across Illumio, NSX, and Checkpoint platforms.

## Quick Start

### Development

**Backend** (Python FastAPI):

```bash
cd backend
pip install -r requirements.txt
# Windows PowerShell:
$env:PYTHONPATH = "."
uvicorn frodo.main:app --reload --port 8000
# Leave UNICORN_API_USER and UNICORN_API_KEY unset for mock data
```

**Frontend** (React):

```bash
cd frontend
npm install
npm run dev
```

The frontend proxies `/api` to the backend. Open http://localhost:5173

### Docker

```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000

## Configuration

Configuration is via environment variables. Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

- **LOG_LEVEL**: Logging level (DEBUG, INFO, WARNING, ERROR). Default: INFO
- **Unicorn**: `UNICORN_BASE_URL`, `UNICORN_API_USER`, `UNICORN_API_KEY` for production; `UNICORN_LIFECYCLE_STATES` (comma-separated, e.g. `Registered,Live,Configure`) to filter out demised servers
- **Illumio**: `ILLUMIO_PCE_HOST`, `ILLUMIO_ORG_ID`, `ILLUMIO_API_KEY`, `ILLUMIO_API_SECRET` for enforcement status

Without Unicorn credentials, mock data is used for development. Docker Compose loads from `.env` via `env_file`.

## Project Structure

```
frodo_v2/
├── backend/           # Python FastAPI
│   ├── frodo/
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── config.py
│   │   ├── unicorn/
│   │   ├── illumio_client/
│   │   └── services/
│   └── requirements.txt
├── frontend/          # React (Vite)
├── .env.example       # Template for environment variables
└── docs/
    └── SPECIFICATION.md
```

## Specification

See [docs/SPECIFICATION.md](docs/SPECIFICATION.md) for the full specification and phased implementation plan.
