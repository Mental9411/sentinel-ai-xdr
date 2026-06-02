# Production Deployment Guide (Ubuntu Server)

## Prerequisites

- Ubuntu 22.04/24.04 LTS
- Docker 24+ and Docker Compose v2
- 8GB+ RAM, 4 CPU cores
- Authorized network monitoring scope documented

## Quick Deploy

```bash
git clone <repository>
cd sentinel-ai-xdr
cp .env.example .env
# Edit .env - change SECRET_KEY, passwords, API keys
docker compose up -d
```

## Services

| Service | Port | URL |
|---------|------|-----|
| Nginx | 80 | http://your-server/ |
| API | 8000 | http://your-server/api/docs |
| Dashboard | 8501 | http://your-server:8501 |
| MLflow | 5000 | http://your-server:5000 |

## Post-Deploy

1. Login: `admin@sentinel.local` / `Sentinel@Admin2024!`
2. **Change default password immediately**
3. Enable MFA for admin accounts
4. Configure threat intel API keys in `.env`
5. Approve network assets after discovery

## TLS

Place certificates in `docker/nginx/ssl/` and enable TLS in nginx.conf.

## Windows Development

```powershell
.\scripts\run_local.ps1
```

## Backup & Recovery

```bash
# PostgreSQL backup
docker exec sentinel-postgres pg_dump -U sentinel sentinel_xdr > backup.sql

# Redis (optional)
docker exec sentinel-redis redis-cli BGSAVE
```

## Monitoring

- Health: `GET /health`
- Celery: check `sentinel-worker` logs
- Disk: `/var/lib/sentinel/captures`, model artifacts

## Security Hardening

See `docs/SECURITY_HARDENING.md`
