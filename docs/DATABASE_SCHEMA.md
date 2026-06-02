# PostgreSQL Schema

## Core Tables

### users
- id (UUID PK), email, username, hashed_password
- role (enum), mfa_enabled, mfa_secret
- failed_login_attempts, locked_until

### security_events
- SIEM event store with source enum (30+ sources)
- normalized_data (JSONB), fingerprint for dedup

### alerts
- title, severity, status, threat_category
- risk_score, confidence_score, MITRE fields
- evidence (JSONB), incident_id FK

### incidents / investigations
- IR workflow with timeline JSONB

### assets / network_devices
- IP inventory from live discovery
- discovery_approved, is_authorized flags

### iocs / threat_feeds
- Threat intelligence storage

### risk_scores / ueba_baselines
- UEBA entity analytics

### ips_rules / ips_actions
- IDS/IPS with approval workflow

### pentest_detections
- Offensive tool detections

### ml_model_metadata / ml_predictions
- MLOps tracking

### audit_logs
- Compliance audit trail

## Indexes

- events: timestamp, source, username, hostname
- alerts: created_at, severity
- iocs: value, type, feed_source

## Redis (not PostgreSQL)

- Session cache, IOC enrichment, pub/sub streams
- Rate limiting counters
