# Sentinel-AI XDR Architecture

## Overview

Sentinel-AI XDR is an enterprise Extended Detection and Response platform combining SIEM, UEBA, IDS/IPS, Threat Intelligence, and SOC operations.

```mermaid
flowchart TB
    subgraph DataSources["Real-Time Data Sources"]
        WE[Windows Events]
        LS[Linux Syslog]
        EP[Endpoint psutil]
        NW[Network ARP/Scapy]
        CL[Cloud APIs]
        EDR[EDR APIs]
    end

    subgraph Ingestion["Ingestion Layer"]
        COL[Collectors]
        CEL[Celery Workers]
        WS[WebSocket Stream]
    end

    subgraph Processing["Detection Engines"]
        IDS[IDS/IPS Engine]
        UEBA[UEBA Engine]
        ML[ML Ensemble]
        PT[Pentest Monitor]
        TI[Threat Intel]
    end

    subgraph Storage["Data Layer"]
        PG[(PostgreSQL)]
        RD[(Redis Cache)]
    end

    subgraph Presentation["SOC Interface"]
        API[FastAPI REST]
        DASH[Streamlit Dashboard]
    end

    DataSources --> COL
    COL --> CEL
    CEL --> Processing
    Processing --> PG
    Processing --> RD
    PG --> API
    RD --> WS
    API --> DASH
    WS --> DASH
```

## Components

| Layer | Technology | Purpose |
|-------|------------|---------|
| API | FastAPI | REST, JWT, RBAC, WebSockets |
| Database | PostgreSQL | Users, alerts, events, assets, IOCs |
| Cache | Redis | Sessions, IOC cache, pub/sub, rate limits |
| Workers | Celery | Real-time collection every 30s |
| ML | scikit-learn, XGBoost, PyTorch | 6-model ensemble |
| Dashboard | Streamlit, Plotly, PyVis | 20 SOC modules |
| Deploy | Docker Compose, Nginx | Production stack |

## Data Flow

1. **Collectors** gather live data from the host OS, network interfaces, and configured APIs
2. **Event Pipeline** normalizes events into `security_events` table
3. **Detection Engines** analyze and create alerts with MITRE mapping
4. **Redis** publishes real-time updates to WebSocket subscribers
5. **Dashboard** polls API and auto-refreshes every 10-60 seconds

## Security Controls

- RBAC with 7 roles
- MFA (TOTP)
- JWT session management
- IPS prevention requires approval
- Network discovery audit logging
- Asset approval workflow

## Database Schema

See `docs/DATABASE_SCHEMA.md`

## Redis Design

See `backend/app/core/redis_cache.py` for key patterns
