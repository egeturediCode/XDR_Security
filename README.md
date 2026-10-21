# XDR Security

A multi-tenant security monitoring and incident response application. It turns security events from CrowdStrike, Active Directory, Fortinet, and Nessus into a shared data model, evaluates them with rules and threat intelligence indicators, links detections to incidents, and helps analysts review them in a web dashboard.

> **Project status:** This repository is a development prototype. Do not assume it is ready for production use. Review deployment security, integration credentials, Celery/Redis setup, and test coverage before using it.

## Features

- Company/tenant-level data separation. Each company has its own API key and asset inventory.
- Company API keys are stored as SHA-256 hashes and shown in plain text only when a new company is created.
- Ingest and normalization for event formats from CrowdStrike Falcon, Microsoft Active Directory, Fortinet FortiOS, and Tenable Nessus.
- Normalized events use OCSF 1.1.0 fields.
- Rule-based detection using criteria such as event type, status, Windows Event ID, protocol, process name, message patterns, time windows and thresholds, and CVSS score.
- Models and synchronization commands for MITRE ATT&CK techniques and ThreatFox IOC records.
- Correlation of detections into incidents within a 24-hour window, based on asset, user, and time proximity.
- A Django web dashboard for event logs, detections, and incidents.
- Audit records for analyst action history and session/incident management.
- Integration payloads for response actions in Active Directory, CrowdStrike, Nessus, and Fortinet.
- Client simulators that generate sample events for Alpha Corp and Beta Lojistik.

## Technologies

| Area | Technology |
| --- | --- |
| Backend and web UI | Python, Django, Django templates, CSS |
| API | Django REST Framework |
| Database | PostgreSQL 16 |
| Configuration | `python-decouple` and environment variables |
| Background tasks / cache | Celery and Redis configuration is present in the code |
| Local services | Docker Compose, PostgreSQL, and pgAdmin |
| Security data | OCSF-normalized event fields, MITRE ATT&CK, and ThreatFox |

Python packages are listed in `requirements.txt`. The code uses Celery tasks and Redis settings, but the current Compose file does not start Redis or a Celery service. The project also appears to be missing a Celery application bootstrap file. This infrastructure must be configured separately to run asynchronous detection and response workflows.

## Architecture and data flow

```text
Integration / simulator
        │  POST /api/v1/ingest/ + X-API-KEY
        ▼
Tenant verification using the API key
        ▼
Source-specific parser ──► Match or create a tenant-owned asset
        ▼
SecurityEvent normalized with OCSF fields
        ▼
Celery task: detection engine
        ├── configured DetectionRule rules
        ├── direct findings from the source event
        └── ThreatFox IOC matches
        ▼
Detection ──► 24-hour correlation ──► Incident
        ▼
Django dashboard: logs, detections, incidents, and action history
```

1. **Ingest:** A `POST /api/v1/ingest/` request uses the key in the `X-API-KEY` header to identify a company. Inactive companies are rejected. Supported `source` values are `crowdstrike`, `active_directory`, `fortinet`, and `nessus`.
2. **Asset matching and normalization:** A source-specific parser matches the event to an asset owned by the company or creates an asset record. It keeps the raw data in `SecurityEvent.metadata` and produces common OCSF fields.
3. **Detection:** An asynchronous task calls the detection engine. The engine evaluates matching events against rules, creates direct findings for some EDR, vulnerability, firewall, and Active Directory events, and links matching IOCs to detections.
4. **Incident correlation:** The system looks for active incidents linked to the same asset or user within the last 24 hours. If none is found, it creates a new incident. Otherwise, it adds the detection to the matching incident and raises its severity when needed.
5. **Analyst workflow:** The dashboard provides company selection, an overview, log, detection, and incident pages. Analysts can investigate, assign, reopen, resolve, close, or mark incidents as false positives. Integration response actions can be triggered while an incident is being investigated.
6. **Auditing:** Authentication events such as successful logins, logouts, and failed logins, as well as some incident changes, are written to the `AuditLog` model. Integration actions are tracked with `IncidentAction`; sensitive token fields are removed from the recorded action parameters.

## Repository structure

```text
.
├── client_simulator_alpha_corp.py
├── client_simulator_beta_lojistik.py
├── compose.yaml
├── requirements.txt
└── XDR_Security/
    ├── XDR_Security/          # Django project settings, URLs, WSGI/ASGI
    ├── api/                   # Ingest and incident-action API endpoints
    ├── ingest/                # Tenant, asset, and event models; parsers
    ├── analytics/             # Rules, detection engine, MITRE/ThreatFox
    ├── incident_management/   # Incident correlation and response actions
    ├── dashboard/             # Web UI, templates, and static CSS
    └── audit/                 # Audit records and authentication signals
```

## Requirements

- Python 3.10 or newer (Python 3.12 recommended)
- Docker and the Docker Compose plugin
- PostgreSQL available at `127.0.0.1:5433` when running the application locally
- Redis available at `127.0.0.1:6379` for the cache and Celery broker settings in the code

`compose.yaml` starts PostgreSQL 16 and pgAdmin, but does not start Redis. It also requires pgAdmin environment variables to be set.

## Local setup

Run these commands from the repository root:

1. Create a virtual environment and install dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

   To activate the virtual environment in Windows PowerShell:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

2. Create a `.env` file in the repository root. This example is for local development; change the values for your environment:

   ```dotenv
   SECRET_KEY=replace-with-a-long-random-secret

   DB_NAME=xdr_security
   DB_USER=xdr_user
   DB_PASSWORD=replace-with-a-local-database-password
   DB_HOST=127.0.0.1
   DB_PORT=5433

   PGADMIN_DEFAULT_EMAIL=admin@example.local
   PGADMIN_DEFAULT_PASSWORD=replace-with-a-pgadmin-password
   PGADMIN_PORT=5050

   # Optional: only needed for the related sync/response integrations
   THREATFOX_AUTH_KEY=
   MS_GRAPH_TOKEN=
   CROWDSTRIKE_TOKEN=
   FORTINET_URL=
   FORTINET_TOKEN=
   NESSUS_URL=
   NESSUS_TOKEN=

   # Optional: raw API keys for the sample simulators
   ALPHA_CORP_API_KEY=
   BETA_LOJISTIK_API_KEY=
   ```

3. Start the database and pgAdmin:

   ```bash
   docker compose up -d db pgadmin
   ```

4. Apply migrations and create an admin account:

   ```bash
   python XDR_Security/manage.py migrate
   python XDR_Security/manage.py createsuperuser
   ```

5. Optionally, add sample tenants and assets:

   ```bash
   python XDR_Security/manage.py registry_company
   ```

   The command prints the API keys for the companies it creates. Treat these as secrets: do not put them in source code, screenshots, or public posts.

6. Start the Django development server:

   ```bash
   python XDR_Security/manage.py runserver
   ```

   Dashboard: <http://127.0.0.1:8000/dashboard/>  
   Django admin: <http://127.0.0.1:8000/admin/>

### Optional data synchronization commands

```bash
python XDR_Security/manage.py mitre_syn
python XDR_Security/manage.py threatfox_syn
```

`threatfox_syn` requires a valid `THREATFOX_AUTH_KEY` in `.env`. These commands make HTTP requests to external data sources.

## Ingest API

Endpoint:

```text
POST http://127.0.0.1:8000/api/v1/ingest/
Content-Type: application/json
X-API-KEY: <company API key>
```

Example Fortinet event:

```json
{
  "source": "fortinet",
  "hostname": "edge-fw-01",
  "srcip": "192.0.2.10",
  "dstip": "198.51.100.20",
  "srcport": 51514,
  "dstport": 443,
  "proto": "TCP",
  "level": "warning",
  "action": "block",
  "msg": "Example firewall event"
}
```

Use an environment variable for the key instead of putting it directly in a command or a shared example:

The client sends the original API key; the server hashes it before looking up the stored hash.

```bash
export XDR_API_KEY='company-api-key'
curl -X POST http://127.0.0.1:8000/api/v1/ingest/ \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ${XDR_API_KEY}" \
  -d '{"source":"fortinet","hostname":"edge-fw-01","srcip":"192.0.2.10","dstip":"198.51.100.20","level":"warning","action":"block","msg":"Example firewall event"}'
```

A successful response includes `message`, `event_id`, and `detection_ids`. Since detection runs asynchronously, `detection_ids` may be empty before processing finishes. An invalid API key returns `401`, an inactive company returns `403`, and an unsupported source returns `400`. Tenant ingest requests have a configured throttle rate of `100/sec`.

Client simulators:

```bash
python client_simulator_alpha_corp.py
python client_simulator_beta_lojistik.py
```

**Simulator note:** Set the matching raw API key in `.env` before running a simulator. Clients send the raw key; the server hashes it before comparing it with the database value. Do not put the database hash in the client configuration.

## Incident response

The `POST /api/v1/incident-action/` API endpoint is restricted to authenticated users in the `Analysts` or `Admin` groups. Available response actions include disabling a user or forcing a password reset in Active Directory; isolating a device, killing a process, or quarantining a file in CrowdStrike; blocking an IP, port, or domain in Fortinet; and starting a Nessus scan.

These actions can affect real systems. Only provide integration tokens and target parameters in authorized test environments. Celery/Redis infrastructure and Celery application configuration must also be set up for tasks triggered by the API.

## Tests

Run the Django tests with:

```bash
python XDR_Security/manage.py test
```

PostgreSQL connection settings are also required for the test database. The existence of tests does not mean that every end-to-end flow or external service integration is covered.

## Known limitations and safe use

- `compose.yaml` includes PostgreSQL and pgAdmin only; it does not define a Redis/Celery worker. Although the project has Celery tasks and broker settings, do not assume that tasks will run until Celery application bootstrap configuration is added.
- `settings.py` uses development defaults (`DEBUG=True`, an empty `ALLOWED_HOSTS`, and a development SSL setting). Do not use these settings for an internet-facing production deployment.
- The simulators read API keys from `ALPHA_CORP_API_KEY` and `BETA_LOJISTIK_API_KEY`. If their former hard-coded keys were committed, rotate those keys before using the repository publicly; removing them from the current files does not remove them from Git history.
- Do not add `.env` files, API keys, or integration tokens to the repository. Scan the full Git history for secrets before sharing the project.
- The PostgreSQL/pgAdmin defaults in Compose are for local development only. Use strong, separate credentials in real environments.

## Configuration and development notes

- Django project settings: `XDR_Security/XDR_Security/settings.py`
- API URLs: `XDR_Security/api/urls.py`
- Source parsers: `XDR_Security/ingest/parsers/`
- Detection engine and rules: `XDR_Security/analytics/`
- Incident correlation and response: `XDR_Security/incident_management/`
- Dashboard pages: `XDR_Security/dashboard/`

### Warning (Legal Disclaimer)

This is a cybersecurity project developed for security research and testing modern encryption architectures (Zero-Trust and Backend Encryption). Before using it in a production environment, make sure the system is configured according to your own server infrastructure and security standards.

The developer cannot be held responsible for data loss or security breaches resulting from misconfiguration.

### LICENSE

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

If you have any questions or suggestions, feel free to reach out:

[GitHub Profile](https://github.com/egeturediCode)
