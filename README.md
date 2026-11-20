# Variant 404 — Security Assurance Web

A hosted-ready React + FastAPI web application that ports the 12 modules in the supplied **Variant404 Desktop v1.0** package into a browser-based workspace and adds an API identity / inconsistency monitor.

> **Scope and safety:** this project is calibrated to the supplied synthetic CRIMEATHON’26 case evidence. The supplied evidence is copied into the application as read-only source material. Workflow actions are simulations; they do not log in to, scan, change, block, or revoke access in real company systems. Connect only authorized audit-metadata feeds to the ingestion endpoint. Never submit real passwords, API key values, authorization headers, or request bodies.

## What is included

### The 12 Variant 404 modules

1. **Payment Interlock** — hold unapproved or high-risk vendor bank-detail changes; record independent callback and approver checks before a simulated release.
2. **Identity Lifecycle** — reconcile leavers with SSO sign-in history; simulate offboarding and test-login verification.
3. **Integration Security** — review credential owners, scopes, expiry and IP restrictions; simulate staged rotation and old-key revocation.
4. **Export Controls** — request, approve, expire and delete controlled export artifacts.
5. **Sensitive Data** — scan supplied content for sensitive key-like references and redact findings in the report.
6. **Time Integrity** — normalize timezone-aware timestamps and preserve warnings for unsynchronized or ambiguous source clocks.
7. **Vendor & Notices** — track third-party notices and simulate owner/recipient routing.
8. **Audit & Risk** — manage control findings, remediation tasks, evidence references and risk review state.
9. **Evidence Vault** — create evidence manifests with SHA-256 file hashes and verify the hash-linked action ledger.
10. **Company Workspace** — import a company's audit-event CSV with a JSON field map; ambiguous timestamps are not silently treated as UTC.
11. **Scenario Lab** — evaluate unseen payment-change variations without changing source evidence or payment workflow state.
12. **Weekly Assurance Brief** — generate a management / Audit Committee control-status brief.

### Additional API Monitor

- Review API request and service-credential activity from E01/E18 and the E04 integration registry.
- Compare each integration's observed source hosts against its own history rather than a single global allow-list.
- Correlate E19 vendor changes to E01/E18 API requests using request ID, credential, source IP, timestamp, status, method and vendor endpoint.
- Alert on unknown service credentials, configuration gaps, non-baseline hosts, cross-source request-ID mismatches, repeated authentication denials and repeated 429 throttling.
- Convert alerts into Audit & Risk remediation tasks.
- Receive live **metadata-only** audit events at `POST /api/monitor/ingest` with `X-Ingest-Key` authentication.

The sample case evidence is not a complete interactive API-login log. The historical E01/E18 data records API requests, not explicit human/API authentication outcomes. Therefore a zero historical 401/403 count is not evidence that no failed logins occurred. To monitor API login attempts, connect the authorized API gateway / identity-provider audit stream and forward each authentication outcome with an offset-aware timestamp.

## Technology

- React 19 + Vite frontend
- FastAPI + Pydantic backend
- SQLite application state and user database (persistent disk required for the configured Render deployment)
- Docker multi-stage build; FastAPI serves the compiled React app from the same origin
- Original Variant 404 analysis/control engine retained in `backend/variant404_core.py`

## Run locally with Docker

1. Copy `.env.example` to `.env` and replace every example secret/password with unique values. For example, create high-entropy secrets with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
2. Start the service:

   ```bash
   docker compose up --build
   ```

3. Open `http://localhost:10000` and sign in with the administrator values in `.env`.
4. Add named users from **Workspace access**. Give approval roles only to people authorized to approve simulated control actions.

The local compose file uses `COOKIE_SECURE=false` because it runs on plain localhost HTTP. The hosted configuration sets secure cookies and HTTPS requirements.

## Run the backend and frontend separately (developer mode)

Python 3.12+ and Node 22+ are recommended.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Set the variables in `.env` in your shell, then run the backend:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 10000 --reload
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Vite proxies `/api` and `/company_template` to `127.0.0.1:10000`. Open the development URL printed by Vite (normally `http://localhost:5173`). For local dev set `CORS_ORIGINS=http://localhost:5173` and `COOKIE_SECURE=false`.

## API telemetry ingestion

Configure a long random `INGEST_SECRET` in the host's secret manager. The UI shows a copyable endpoint and example payload under **API Monitor → Ingestion setup**. The endpoint accepts batches of up to 1,000 events. Timestamps must contain an explicit timezone (`Z` or a numeric UTC offset); naive timestamps are rejected and reported rather than guessed.

Example:

```bash
curl -X POST "https://YOUR-HOST/api/monitor/ingest" \
  -H "Content-Type: application/json" \
  -H "X-Ingest-Key: $INGEST_SECRET" \
  -d '{"events":[{"event_id":"gw-evt-1001","timestamp":"2026-11-20T00:15:12Z","system":"API Gateway","credential_id":"svc-invoice-sync","actor_type":"integration","action":"token.accepted","endpoint":"/v1/invoices","method":"GET","source_ip":"203.0.113.10","status_code":200,"auth_result":"accepted","request_id":"req-1001","outcome":"success"}]}'
```

Send a stable, non-secret credential identifier (for example, `svc-invoice-sync`), never the actual token/key. Use `auth_result=denied` and HTTP `401`/`403` for failed authentication/authorization outcomes; `429` is classified as rate limiting, not failed authentication. The monitor raises a repeated-denial alert at 3 events per credential/source-IP in 10 minutes, and a throttling alert at 5 in 10 minutes. Tune those thresholds to the real service baseline before operational use.

The sample endpoint records the event timestamp, receipt time, system, credential identifier, actor type, action, endpoint/method, source IP, status, auth outcome and request ID. It intentionally does **not** accept or persist raw credentials, authorization headers or request bodies.

## Security controls included

- Scrypt password hashing with per-password random salt; 12-character minimum for newly provisioned passwords.
- HMAC-signed eight-hour sessions; `HttpOnly`, `SameSite=Strict` cookies; `Secure` cookies in production.
- CSRF double-submit token checks and same-origin/HTTPS validation for state-changing browser requests.
- Server-side RBAC: `admin`, `approver`, and `analyst`; high-impact approval/remediation endpoints require `admin` or `approver`.
- Login attempt throttling; API telemetry ingestion requires a separate secret.
- CSP, HSTS (production), `X-Frame-Options`, `nosniff`, strict referrer policy and reduced browser permissions.
- Non-root application user in the Docker runtime; secrets are environment variables and are excluded from Git.
- File import is CSV-only, capped at 15 MB; field maps are JSON-only, capped at 256 KB; exports are selected from an allow-list.
- Evidence source files remain read-only; every application action is appended to the integrity-checkable action ledger.

## Deploy publicly (not localhost)

See [DEPLOYMENT.md](DEPLOYMENT.md). The repository includes a Render Blueprint (`render.yaml`) and a Dockerfile. The supplied blueprint uses a paid web-service plan and paid persistent disk because the app must retain accounts and workflow state across restarts. Once deployed, the web service is reachable on its public HTTPS service URL. No public deployment has been created by this build because an authorized hosting account and Git repository are not connected in this session.

## Validation

Run:

```bash
python -m unittest discover -s tests -v
```

The suite currently passes **21 tests** covering the original Variant 404 controls plus the web API, authentication, RBAC and telemetry tests. The JSX source also passes a TypeScript parser check. An npm package install timed out in this sandbox, so a local Vite production bundle was not generated here; the Docker build runs `npm install` and `npm run build` on the hosting builder.

## Important production limitations

- The supplied `Variant404_Desktop_v1.0.zip` is a desktop simulation, not a complete live enterprise integration. This port retains the 12 module workflows and adds a secure metadata intake interface, but does not connect directly to LedgerOne, HelpDeskr, SSO, BlueVault, a bank, or an API gateway. A company must deliberately configure a trusted log forwarder and secret to send authorized telemetry.
- Remediation buttons update the simulated Variant 404 workflow only. They do not rotate real API keys, disable real staff accounts, release funds, block IP addresses, or alter vendor records.
- Current alerts are explainable rules / case-calibrated heuristics, not an ML model or a certified SIEM. Alert thresholds and host baselines require validation on each real environment.
- Render's included SQLite + persistent-disk design is intentionally single-instance. Before horizontal scaling, high availability, or multiple concurrent production instances, migrate state and auth to managed PostgreSQL, use a shared session/rate-limit store, and add backup/restore and migration procedures.
- MFA / SSO federation, external alert delivery (email/SMS/ChatOps), formal secrets-vault integration, centralized log retention, independent penetration testing and security certification are not included. Add these before handling real production-sensitive data.
- Protect the hosted instance with HTTPS, unique credentials, least-privilege user roles, routine updates and backups. Do not publish the synthetic evidence with any non-synthetic company data or secrets.
