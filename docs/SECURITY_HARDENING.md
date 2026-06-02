# Security Hardening Guide

## Authentication

- Change default admin credentials on first login
- Enable MFA for all privileged accounts
- Use invitation tokens for user registration
- Configure password policy (12+ chars, complexity)

## Network

- Run discovery only on authorized subnets
- Require asset approval before monitoring
- IPS prevention mode requires SOC Manager approval
- Run API behind Nginx with TLS in production

## Secrets

- Store API keys in `.env` or HashiCorp Vault
- Never commit `.env` to version control
- Rotate `SECRET_KEY` periodically

## Database

- Use strong PostgreSQL passwords
- Restrict port 5432 to internal network only
- Enable connection pooling limits

## Container

- Drop unnecessary capabilities except NET_RAW for capture
- Run workers with read-only root where possible
- Keep images updated

## Compliance Logging

All actions logged to `audit_logs`:
- Login/logout
- Network discovery
- Asset approval
- IPS actions
- User invitations
