from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from urllib.parse import urlparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .variant404_core import Variant404Engine, read_csv, read_json, utc_iso

APP_ROOT = Path(__file__).resolve().parents[1]
BUNDLED_EVIDENCE = APP_ROOT / "demo_data" / "evidence"
STATE_ROOT = Path(os.getenv("DATA_DIR", str(APP_ROOT / "runtime_data"))).resolve()
ENGINE_ROOT = STATE_ROOT / "variant404"
AUTH_DB = STATE_ROOT / "auth.sqlite3"
COOKIE_NAME = "v404_session"
CSRF_COOKIE = "v404_csrf"
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PROD = ENVIRONMENT == "production"
APP_SECRET = os.getenv("APP_SECRET", "")
INGEST_SECRET = os.getenv("INGEST_SECRET", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true" if IS_PROD else "false").lower() == "true"
SESSION_SECONDS = 8 * 60 * 60

if IS_PROD and len(APP_SECRET) < 32:
    raise RuntimeError("APP_SECRET must be set to a random value of at least 32 characters in production.")
if not APP_SECRET:
    APP_SECRET = secrets.token_urlsafe(48)

STATE_ROOT.mkdir(parents=True, exist_ok=True)
(ENGINE_ROOT / "demo_data" / "evidence").mkdir(parents=True, exist_ok=True)
for src in BUNDLED_EVIDENCE.glob("*"):
    dst = ENGINE_ROOT / "demo_data" / "evidence" / src.name
    if src.is_file() and not dst.exists():
        shutil.copy2(src, dst)
engine = Variant404Engine(ENGINE_ROOT)

app = FastAPI(title="Variant404 Security Assurance API", version="2.0.0", docs_url=None, redoc_url=None)
allowed_origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-Ingest-Key"],
)

# ------------------------- Auth database and helpers -------------------------

@contextmanager
def auth_connect():
    con = sqlite3.connect(AUTH_DB, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=20000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_auth_db():
    with auth_connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','approver','analyst')),
            is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS api_events (
            event_id TEXT PRIMARY KEY, received_at TEXT NOT NULL, event_time TEXT NOT NULL,
            event_time_utc TEXT NOT NULL DEFAULT '', time_reliability TEXT NOT NULL,
            system TEXT NOT NULL, credential_id TEXT NOT NULL, actor_type TEXT NOT NULL,
            action TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL,
            source_ip TEXT NOT NULL, status_code INTEGER NOT NULL,
            auth_result TEXT NOT NULL, request_id TEXT NOT NULL, outcome TEXT NOT NULL,
            source_label TEXT NOT NULL DEFAULT 'external-ingest'
        );
        CREATE INDEX IF NOT EXISTS idx_api_events_time ON api_events(received_at);
        CREATE INDEX IF NOT EXISTS idx_api_events_credential ON api_events(credential_id);
        CREATE INDEX IF NOT EXISTS idx_api_events_request ON api_events(request_id);
        """)
        con.commit()
    with auth_connect() as con:
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            email = os.getenv("INITIAL_ADMIN_EMAIL", "").strip().lower()
            password = os.getenv("INITIAL_ADMIN_PASSWORD", "")
            name = os.getenv("INITIAL_ADMIN_NAME", "Workspace Administrator").strip()
            if not email or not password:
                if IS_PROD:
                    raise RuntimeError("Set INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD to bootstrap the first workspace administrator.")
                email, password = "admin@variant404.test", "Variant404-Demo-Only-ChangeMe!"
                name = "Demo Administrator"
            _create_user_record(con, email, name, password, "admin")
            con.commit()


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = __import__("hashlib").scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return "scrypt$16384$8$1$" + salt.hex() + "$" + derived.hex()


def _verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        calculated = __import__("hashlib").scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                                                    n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(digest_hex)))
        return hmac.compare_digest(calculated.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _create_user_record(con, email: str, display_name: str, password: str, role: str):
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    user_id = "usr_" + secrets.token_hex(12)
    con.execute("INSERT INTO users(user_id,email,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
                (user_id, email, display_name, _password_hash(password), role, utc_iso(datetime.now(timezone.utc))))
    return user_id


def _b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _make_session(user: dict[str, Any], csrf: str) -> str:
    now = int(time.time())
    payload = {"sub": user["user_id"], "email": user["email"], "role": user["role"],
               "name": user["display_name"], "iat": now, "exp": now + SESSION_SECONDS, "csrf": csrf}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(APP_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return body + "." + sig


def _read_session(token: str | None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    try:
        body, signature = token.split(".", 1)
        expected = _b64(hmac.new(APP_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_unb64(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


login_attempts: dict[str, list[float]] = defaultdict(list)


def rate_limit_login(ip: str):
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 900]
    if len(login_attempts[ip]) >= 8:
        raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.")


async def current_user(request: Request) -> dict[str, Any]:
    payload = _read_session(request.cookies.get(COOKIE_NAME))
    if not payload:
        raise HTTPException(401, "Sign in to continue.")
    with auth_connect() as con:
        row = con.execute("SELECT user_id,email,display_name,role,is_active FROM users WHERE user_id=?", (payload["sub"],)).fetchone()
    if not row or not row["is_active"]:
        raise HTTPException(401, "Your account is disabled.")
    return dict(row) | {"csrf": payload.get("csrf", "")}


def require_roles(*roles: str):
    async def dependency(user: dict[str, Any] = Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Your role does not permit this action.")
        return user
    return dependency


def require_csrf_roles(*roles: str):
    async def dependency(request: Request, user: dict[str, Any] = Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Your role does not permit this action.")
        return require_csrf(request, user)
    return dependency


def require_csrf(request: Request, user: dict[str, Any] = Depends(current_user)):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return user
    header = request.headers.get("X-CSRF-Token", "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not header or not cookie or not hmac.compare_digest(header, cookie) or not hmac.compare_digest(header, user.get("csrf", "")):
        raise HTTPException(403, "CSRF validation failed. Refresh the page and try again.")
    origin = request.headers.get("origin")
    if origin:
        parsed_origin = urlparse(origin)
        request_host = request.headers.get("host", "").lower()
        if parsed_origin.netloc.lower() != request_host:
            allowed = {urlparse(x).netloc.lower() for x in allowed_origins}
            if parsed_origin.netloc.lower() not in allowed:
                raise HTTPException(403, "Origin not allowed.")
        if IS_PROD and parsed_origin.scheme != "https":
            raise HTTPException(403, "Secure origin required.")
    return user


def record_actor_action(user: dict[str, Any], action: str, object_ref: str, detail: str):
    engine.log_action(user["email"], action, object_ref, detail[:2000])


def clean_dict(value: Any):
    if isinstance(value, dict):
        return {k: clean_dict(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [clean_dict(v) for v in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, Counter):
        return dict(value)
    return value


@app.on_event("startup")
def startup():
    init_auth_db()


# ------------------------------- Models --------------------------------------

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)

class CreateUserRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern="^(admin|approver|analyst)$")

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)

class PaymentRelease(BaseModel):
    callback_verified: bool
    approver: str = Field(min_length=2, max_length=100)
    approval_ref: str = Field(min_length=2, max_length=100)

class OffboardRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)

class IntegrationRemediation(BaseModel):
    new_scope: str = Field(min_length=3, max_length=250)
    owner_approval: bool

class OwnerApproval(BaseModel):
    owner_approval: bool

class ExportRequest(BaseModel):
    requester: str = Field(min_length=2, max_length=100)
    data_class: str = Field(min_length=2, max_length=100)
    purpose: str = Field(min_length=5, max_length=500)
    row_count: int = Field(ge=1, le=10000000)

class ApproveExport(BaseModel):
    approver: str = Field(min_length=2, max_length=100)

class ScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)

class RouteNotice(BaseModel):
    recipients: list[str] = Field(min_length=1, max_length=20)

class CloseTask(BaseModel):
    evidence: str = Field(min_length=5, max_length=1000)

class ScenarioRequest(BaseModel):
    change_id: str = Field(default="SCENARIO-NEW", max_length=100)
    vendor_id: str = Field(default="V-TEST", max_length=100)
    vendor_name: str = Field(default="Scenario vendor", max_length=150)
    changed_by: str = Field(min_length=1, max_length=100)
    field: str = Field(default="bank_account", max_length=100)
    approval_ref: str = Field(default="", max_length=100)
    source_ip: str = Field(default="", max_length=100)
    request_id: str = Field(default="", max_length=120)
    ts_utc: str = Field(default="2026-09-07T10:00:00Z", max_length=60)

class IngestEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default="", max_length=120)
    timestamp: str = Field(min_length=1, max_length=80)
    system: str = Field(default="API", max_length=80)
    credential_id: str = Field(min_length=1, max_length=120)
    actor_type: str = Field(default="integration", max_length=40)
    action: str = Field(default="api.request", max_length=120)
    endpoint: str = Field(default="", max_length=300)
    method: str = Field(default="GET", max_length=12)
    source_ip: str = Field(default="", max_length=64)
    status_code: int = Field(default=0, ge=0, le=999)
    auth_result: str = Field(default="unknown", max_length=30)
    request_id: str = Field(default="", max_length=120)
    outcome: str = Field(default="", max_length=120)

class IngestBatch(BaseModel):
    events: list[IngestEvent] = Field(min_length=1, max_length=1000)

    @field_validator("events")
    @classmethod
    def max_payload(cls, events):
        return events


# ------------------------------- Auth routes ---------------------------------

@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    rate_limit_login(ip)
    email = body.email.strip().lower()
    with auth_connect() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        valid = bool(row and row["is_active"] and _verify_password(body.password, row["password_hash"]))
        if not valid:
            login_attempts[ip].append(time.time())
            raise HTTPException(401, "Email or password is incorrect.")
        con.execute("UPDATE users SET last_login=? WHERE user_id=?", (utc_iso(datetime.now(timezone.utc)), row["user_id"]))
        con.commit()
    login_attempts.pop(ip, None)
    user = dict(row)
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(COOKIE_NAME, _make_session(user, csrf), httponly=True, secure=COOKIE_SECURE,
                        samesite="strict", max_age=SESSION_SECONDS, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=COOKIE_SECURE,
                        samesite="strict", max_age=SESSION_SECONDS, path="/")
    return {"user": {"email": user["email"], "display_name": user["display_name"], "role": user["role"]}}

@app.post("/api/auth/logout")
async def logout(response: Response, _user=Depends(require_csrf)):
    response.delete_cookie(COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=COOKIE_SECURE, samesite="strict")
    return {"ok": True}

@app.get("/api/auth/me")
async def me(user=Depends(current_user)):
    return {"user": {k: user[k] for k in ("email", "display_name", "role")}}

@app.get("/api/users")
async def list_users(_user=Depends(require_roles("admin"))):
    with auth_connect() as con:
        rows = [dict(r) for r in con.execute("SELECT user_id,email,display_name,role,is_active,created_at,last_login FROM users ORDER BY created_at")]
    return {"users": rows}

@app.post("/api/users")
async def create_user(body: CreateUserRequest, user=Depends(require_csrf)):
    if user["role"] != "admin":
        raise HTTPException(403, "Only workspace administrators can add accounts.")
    email = body.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(422, "Enter a valid email address.")
    try:
        with auth_connect() as con:
            uid = _create_user_record(con, email, body.display_name.strip(), body.password, body.role)
            con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with this email already exists.")
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    record_actor_action(user, "USER_ACCOUNT_CREATED", email, f"role={body.role}")
    return {"ok": True, "user_id": uid}

@app.post("/api/auth/change-password")
async def change_password(body: ChangePasswordRequest, response: Response, user=Depends(require_csrf)):
    with auth_connect() as con:
        row = con.execute("SELECT password_hash FROM users WHERE user_id=?", (user["user_id"],)).fetchone()
        if not row or not _verify_password(body.current_password, row["password_hash"]):
            raise HTTPException(400, "Current password is incorrect.")
        con.execute("UPDATE users SET password_hash=? WHERE user_id=?", (_password_hash(body.new_password), user["user_id"]))
        con.commit()
    record_actor_action(user, "ACCOUNT_PASSWORD_CHANGED", user["email"], "Password hash updated; current session ended")
    response.delete_cookie(COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=COOKIE_SECURE, samesite="strict")
    return {"ok": True, "message": "Password updated. Sign in again with the new password."}


# -------------------------- API monitor and alerts ---------------------------

def _registered_integrations():
    register = read_json(engine.file("E04"), {}).get("integrations", [])
    return {x.get("credential_id"): x for x in register if x.get("credential_id")}


def _static_api_rows():
    return engine._api_rows()


def _monitored_rows():
    rows = []
    for r in _static_api_rows():
        rows.append({"event_id": r.get("request_id", ""), "timestamp": r.get("ts_utc", ""),
                     "credential_id": r.get("api_key_id", ""), "actor_type": "service" if str(r.get("api_key_id", "")).startswith("key-") else "human",
                     "action": "api.request", "endpoint": r.get("endpoint", ""), "method": r.get("method", ""),
                     "source_ip": r.get("caller_ip", ""), "status_code": int(r.get("status", 0) or 0),
                     "auth_result": "accepted" if str(r.get("status", "")).startswith(("2", "3")) else "rate_limited" if r.get("status") == "429" else "unknown",
                     "request_id": r.get("request_id", ""), "source_label": "case evidence E01/E18"})
    with auth_connect() as con:
        for r in con.execute("SELECT * FROM api_events ORDER BY received_at DESC LIMIT 50000"):
            rows.append({"event_id": r["event_id"], "timestamp": r["event_time"], "credential_id": r["credential_id"],
                         "actor_type": r["actor_type"], "action": r["action"], "endpoint": r["endpoint"], "method": r["method"],
                         "source_ip": r["source_ip"], "status_code": r["status_code"], "auth_result": r["auth_result"],
                         "request_id": r["request_id"], "source_label": r["source_label"]})
    return rows


def _build_api_monitor():
    register = _registered_integrations()
    api_rows = _monitored_rows()
    service_rows = [r for r in api_rows if r["actor_type"] in ("service", "integration") or r["credential_id"].startswith(("key-", "sim-key"))]
    auth_failures = [r for r in api_rows if r["auth_result"].lower() in {"denied", "failed", "failure", "rejected"} or r["status_code"] in (401, 403)]
    throttled = [r for r in api_rows if r["status_code"] == 429 or r["auth_result"].lower() in {"rate_limited", "throttled"}]
    credential_counts = Counter(r["credential_id"] for r in service_rows)
    host_counts: dict[str, Counter] = defaultdict(Counter)
    request_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in service_rows:
        if r["source_ip"]:
            host_counts[r["credential_id"]][r["source_ip"]] += 1
        if r["request_id"]:
            request_groups[r["request_id"]].append(r)

    # Per-credential baseline uses only that credential's own request population.
    normal_hosts = {credential: {ip for ip, n in counts.items() if n / max(1, sum(counts.values())) >= 0.05}
                    for credential, counts in host_counts.items()}
    alerts: list[dict[str, Any]] = []
    def add_alert(key, severity, title, detail, recommendation, evidence=""):
        alerts.append({"alert_id": hashlib.sha256(key.encode()).hexdigest()[:14], "severity": severity,
                      "title": title, "detail": detail, "recommendation": recommendation,
                      "evidence": evidence, "source": "Case evidence / ingested telemetry"})

    # Configuration risks from the connected-software register are elevated into the monitor
    # so API identity issues and credential-control gaps are visible together.
    for credential, item in register.items():
        ip_restricted = bool(item.get("ip_restriction"))
        token_days = item.get("token_lifetime_days")
        if not ip_restricted and not token_days:
            add_alert(f"config:{credential}:ip-expiry", "high" if credential == "key-tb-07" else "medium",
                      "API integration has no IP restriction or token expiry",
                      f"{credential} ({item.get('integration', 'connected integration')}) has neither an IP restriction nor a token lifetime in E04.",
                      "Confirm owner and dependencies; stage a least-privilege replacement with an IP allow-list and short-lived tokens, then verify before revoking the old key.", "E04 connected software register; E10 policy")

    # Surface high-risk API-driven changes, including positive cross-source corroboration.
    # Exact corroboration strengthens the timeline; it does not establish intent.
    for change in engine.payment_analysis():
        if change.get("threshold_crossed"):
            join_text = "Exact API request corroboration is present." if change.get("exact_api_join") else "An exact API request join was not established."
            add_alert(f"payment:{change.get('change_id')}", "critical" if change.get("risk_score", 0) >= 8 else "high",
                      "High-risk API-driven vendor bank-detail change",
                      f"{change.get('vendor_name')} ({change.get('change_id')}) scored {change.get('risk_score')} against the case threshold. {join_text}",
                      "Keep the change on hold until independent supplier callback, Finance approval and approval-reference checks are recorded. Do not label the event as fraud based on this score alone.", "E19 joined to E01/E18")

    # Registry mismatch: only unknown service credential identifiers, not human API callers.
    unknown = sorted({r["credential_id"] for r in service_rows if r["credential_id"] not in register})
    for credential in unknown:
        add_alert(f"unknown:{credential}", "high", "Unregistered API credential observed",
                  f"Credential {credential} appears in API activity but is absent from E04 connected-software register.",
                  "Confirm the owning system and business purpose. Quarantine or revoke only after owner/dependency verification.", "E01/E18 + E04")

    # Host deviation from baseline; report distinct source addresses rather than every request.
    for credential, counts in host_counts.items():
        baseline = normal_hosts.get(credential, set())
        unusual = [(ip, n) for ip, n in counts.items() if baseline and ip not in baseline]
        for ip, n in unusual:
            # Only surface material outliers to keep alerts actionable.
            if n >= 3 or credential == "key-tb-07":
                add_alert(f"host:{credential}:{ip}", "high" if n >= 10 else "medium",
                          "API credential used from a non-baseline host",
                          f"{credential} generated {n:,} request(s) from {ip}, which is outside its own >=5% observed-host baseline.",
                          "Validate the network path with the integration owner; add allow-list controls and rotate the credential if unauthorized.", "E01/E18 host baseline")

    # Failed authentication / authorization and rate-limit patterns for actual ingested telemetry.
    live_rows = [r for r in api_rows if r["source_label"] == "external-ingest"]
    failures_by_actor: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    throttles_by_actor: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in live_rows:
        key = (r["credential_id"], r["source_ip"])
        if r["status_code"] in (401, 403) or r["auth_result"].lower() in {"denied", "failed", "failure", "rejected"}:
            failures_by_actor[key].append(r)
        if r["status_code"] == 429 or r["auth_result"].lower() in {"rate_limited", "throttled"}:
            throttles_by_actor[key].append(r)
    def peak_window(group, threshold_minutes=10):
        parsed = []
        for item in group:
            try:
                dt = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
                if dt.tzinfo is not None:
                    parsed.append((dt.astimezone(timezone.utc), item))
            except (ValueError, AttributeError):
                continue
        parsed.sort(key=lambda x: x[0])
        left = 0
        best = (0, None, None)
        span = timedelta(minutes=threshold_minutes)
        for right, (dt, _) in enumerate(parsed):
            while dt - parsed[left][0] > span:
                left += 1
            count = right - left + 1
            if count > best[0]:
                best = (count, parsed[left][0], dt)
        return best

    for (credential, ip), group in failures_by_actor.items():
        peak, start, end = peak_window(group)
        if peak >= 3:
            add_alert(f"authfail:{credential}:{ip}:{start.isoformat() if start else 'unknown'}", "critical" if peak >= 10 else "high",
                      "Repeated API authentication failures",
                      f"{peak} failed/denied requests for {credential} from {ip} occurred within a 10-minute window ({utc_iso(start) if start else 'time unavailable'} to {utc_iso(end) if end else 'time unavailable'}).",
                      "Check credential rotation history and source ownership. Temporarily block the source at the API gateway only under an approved incident process.", "Ingested API audit events")
    for (credential, ip), group in throttles_by_actor.items():
        peak, start, end = peak_window(group)
        if peak >= 5:
            add_alert(f"throttle:{credential}:{ip}:{start.isoformat() if start else 'unknown'}", "medium", "Repeated API rate limiting",
                      f"{peak} rate-limited requests for {credential} from {ip} occurred within a 10-minute window.",
                      "Review caller retry/backoff behaviour and gateway quota settings; do not disable rate limits as a workaround.", "Ingested API audit events")

    # Request IDs that disagree across separate observations are a strong correlation warning.
    for request_id, group in request_groups.items():
        if len(group) > 1:
            fingerprints = {(r["credential_id"], r["source_ip"], r["timestamp"], r["method"].upper()) for r in group}
            if len(fingerprints) > 1:
                add_alert(f"request-mismatch:{request_id}", "high", "Request ID correlation mismatch",
                          f"Request ID {request_id} is associated with inconsistent credential, source IP, timestamp or method values.",
                          "Preserve the source records and compare gateway, application and business-system request traces before attributing the action.", "Cross-source request ID join")

    # E19 vendor changes joined to E01/E18 API logs. An exact match is corroboration; mismatch is an alert.
    api_by_req = {r.get("request_id"): r for r in _static_api_rows() if r.get("request_id")}
    mismatches = 0
    unmatched = 0
    for change in read_csv(engine.file("E19")):
        if change.get("field") != "bank_account" or not str(change.get("changed_by", "")).startswith("key-"):
            continue
        req = change.get("request_id", "")
        api = api_by_req.get(req)
        if not api:
            unmatched += 1
            continue
        same = (api.get("api_key_id") == change.get("changed_by") and api.get("caller_ip") == change.get("source_ip")
                and api.get("ts_utc") == change.get("ts_utc") and api.get("status") == "200"
                and api.get("method", "").upper() in {"PATCH", "PUT"}
                and change.get("vendor_id", "") in api.get("endpoint", ""))
        if not same:
            mismatches += 1
            add_alert(f"e19-join:{change.get('change_id')}", "critical", "Vendor change does not match its API request record",
                      f"{change.get('change_id')} references request {req}, but credential/IP/time/status/method/vendor endpoint checks are inconsistent.",
                      "Keep the payment/change on hold. Reconcile the vendor master audit trail and API gateway record; require independent callback and approver evidence.", "E19 joined to E01/E18")
    if unmatched:
        add_alert("vendor-api-unmatched", "medium", "API evidence missing for integration vendor changes",
                  f"{unmatched} integration bank-detail change(s) could not be joined to an API request by request ID.",
                  "Check request ID propagation and retention gaps. Do not interpret a missing log record alone as proof of malicious activity.", "E19 joined to E01/E18")

    # Sort severity and calculate summary. The supplied API logs do not contain explicit auth login outcomes;
    # 429 counts are therefore shown as throttling, not failed authentication.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda x: (severity_rank.get(x["severity"], 4), x["title"]))
    credential_inventory = []
    for key in sorted(set(credential_counts) | set(register)):
        item = register.get(key, {})
        credential_inventory.append({"credential_id": key, "request_count": credential_counts.get(key, 0),
                                     "known_in_register": key in register,
                                     "source_count": len(host_counts.get(key, {})),
                                     "baseline_hosts": sorted(normal_hosts.get(key, set())),
                                     "registry_owner": item.get("owner", "Not in register"),
                                     "registry_system": item.get("integration", "Unknown")})
    credential_inventory.sort(key=lambda x: (-x["request_count"], x["credential_id"]))
    return {
        "summary": {"total_requests": len(api_rows), "service_requests": len(service_rows),
                    "credentials_seen": len(credential_counts), "auth_failures": len(auth_failures),
                    "rate_limited": len(throttled), "alert_count": len(alerts),
                    "ingested_events": len(live_rows), "registered_credentials": len(register)},
        "credentials": credential_inventory,
        "alerts": alerts[:250],
        "recent_events": sorted(api_rows, key=lambda x: x.get("timestamp", ""), reverse=True)[:30],
        "notes": ["Supplied E01/E18 records show API request activity, not a complete interactive API-login audit trail.",
                  "The API host baseline is per credential and learned from the supplied request history; it is a triage signal, not a blocklist.",
                  "No real API key is stored or replayed. External ingestion accepts credential identifiers and audit metadata only."],
    }

@app.get("/api/monitor")
async def api_monitor(_user=Depends(current_user)):
    return _build_api_monitor()

@app.post("/api/monitor/ingest")
async def ingest_events(batch: IngestBatch, x_ingest_key: str = Header(default="")):
    if not INGEST_SECRET or not hmac.compare_digest(x_ingest_key, INGEST_SECRET):
        raise HTTPException(401, "Invalid telemetry ingestion key.")
    received = utc_iso(datetime.now(timezone.utc))
    added = 0
    rejected = []
    with auth_connect() as con:
        for index, event in enumerate(batch.events):
            raw_time = event.timestamp.strip()
            parsed = None
            try:
                parsed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except ValueError:
                pass
            if parsed is None or parsed.tzinfo is None:
                rejected.append({"index": index, "reason": "timestamp must be ISO-8601 with an explicit timezone offset"})
                continue
            event_id = event.event_id.strip() or hashlib.sha256(f"{received}|{index}|{raw_time}|{event.credential_id}".encode()).hexdigest()[:32]
            values = (event_id, received, raw_time, utc_iso(parsed), "TIMEZONE_EXPLICIT", event.system.strip(),
                      event.credential_id.strip(), event.actor_type.strip().lower(), event.action.strip(),
                      event.endpoint.strip(), event.method.strip().upper(), event.source_ip.strip(), event.status_code,
                      event.auth_result.strip().lower(), event.request_id.strip(), event.outcome.strip(), "external-ingest")
            cur = con.execute("""INSERT OR IGNORE INTO api_events(event_id,received_at,event_time,event_time_utc,time_reliability,system,
                credential_id,actor_type,action,endpoint,method,source_ip,status_code,auth_result,request_id,outcome,source_label)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", values)
            added += cur.rowcount
        con.commit()
    if added:
        engine.log_action("API Telemetry Ingest", "API_EVENTS_INGESTED", "EXTERNAL-API-LOGS",
                          f"Accepted {added} metadata event(s); rejected {len(rejected)}; raw request bodies and credential values are not stored")
    return {"accepted": added, "rejected": rejected, "note": "Metadata only; no credentials or request bodies are stored."}

@app.post("/api/monitor/alerts/{alert_id}/task")
async def alert_to_task(alert_id: str, user=Depends(require_csrf)):
    data = _build_api_monitor()
    alert = next((x for x in data["alerts"] if x["alert_id"] == alert_id), None)
    if not alert:
        raise HTTPException(404, "Alert not found. Refresh the monitor view.")
    engine.add_task("API MONITOR", f"{alert['severity'].upper()}: {alert['title']}", "API / System Owner", "2026-09-14", "OPEN", evidence=alert.get("evidence", "API monitor") + "; " + alert["alert_id"])
    record_actor_action(user, "API_ALERT_CONVERTED_TO_TASK", alert_id, alert["recommendation"])
    return {"ok": True, "message": "An accountable remediation task has been added to Audit & Risk."}


# ------------------------------- Dashboard -----------------------------------

@app.get("/api/overview")
async def overview(_user=Depends(current_user)):
    payments = engine.payment_rows()
    offboarding = engine.offboarding_rows()
    integrations = engine.integration_rows()
    governance = engine.task_rows()
    monitor = _build_api_monitor()
    notices = engine.route_notices()
    vault_ok, vault_text = engine.verify_action_chain()
    return {
        "kpis": {"requests": monitor["summary"]["total_requests"],
                 "api_alerts": monitor["summary"]["alert_count"],
                 "payment_holds": sum(1 for x in payments if x["status"].startswith("HELD")),
                 "identity_reviews": sum(1 for x in offboarding if not x["verified"]),
                 "integration_gaps": sum(1 for x in integrations if not x["compliant"]),
                 "open_tasks": sum(1 for x in governance if not x["status"].startswith("CLOSED"))},
        "monitor": monitor["summary"],
        "highlights": monitor["alerts"][:5],
        "notices": notices,
        "action_chain": {"valid": vault_ok, "message": vault_text},
        "scope": "Synthetic CRIMEATHON evidence plus explicitly labelled local simulation and authorized metadata ingestion.",
    }


# ------------------------------ Module routes --------------------------------

@app.get("/api/payments")
async def payments(_user=Depends(current_user)):
    return {"rows": engine.payment_rows(), "analysis": engine.payment_analysis()}

@app.post("/api/payments/{change_id}/release")
async def release_payment(change_id: str, body: PaymentRelease, user=Depends(require_csrf_roles("admin", "approver"))):
    if user["role"] not in ("admin", "approver"):
        raise HTTPException(403, "Only Finance approvers or workspace administrators may release a simulated hold.")
    ok, message = engine.release_payment(change_id, body.callback_verified, body.approver, body.approval_ref)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_PAYMENT_RELEASE_SIMULATED", change_id, f"callback={body.callback_verified}; approver={body.approver}; ref={body.approval_ref}")
    return {"ok": True, "message": message}

@app.get("/api/identity")
async def identity(_user=Depends(current_user)):
    return {"rows": engine.offboarding_rows()}

@app.post("/api/identity/{username}/offboard")
async def offboard(username: str, user=Depends(require_csrf_roles("admin", "approver"))):
    if user["role"] not in ("admin", "approver"):
        raise HTTPException(403, "Administrator or approver role required.")
    ok, message = engine.run_offboarding(username)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_OFFBOARDING_SIMULATED", username, "SSO disable/session revoke/app removal simulated")
    return {"ok": True, "message": message}

@app.post("/api/identity/{username}/test-login")
async def test_login(username: str, user=Depends(require_csrf)):
    allowed, message = engine.simulate_login(username)
    record_actor_action(user, "WEB_IDENTITY_TEST_LOGIN", username, message)
    return {"allowed": allowed, "message": message}

@app.get("/api/integrations")
async def integrations(_user=Depends(current_user)):
    return {"rows": engine.integration_rows()}

@app.post("/api/integrations/{credential_id}/rotate")
async def rotate_integration(credential_id: str, body: IntegrationRemediation, user=Depends(require_csrf_roles("admin", "approver"))):
    if user["role"] not in ("admin", "approver"):
        raise HTTPException(403, "Administrator or approver role required.")
    ok, message = engine.remediate_integration(credential_id, body.new_scope, body.owner_approval)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_CREDENTIAL_ROTATION_SIMULATED", credential_id, body.new_scope)
    return {"ok": True, "message": message}

@app.post("/api/integrations/{credential_id}/revoke")
async def revoke_integration(credential_id: str, body: OwnerApproval, user=Depends(require_csrf_roles("admin", "approver"))):
    if user["role"] not in ("admin", "approver"):
        raise HTTPException(403, "Administrator or approver role required.")
    ok, message = engine.revoke_stale_integration(credential_id, body.owner_approval)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_CREDENTIAL_REVOKE_SIMULATED", credential_id, "owner approval and dependency check recorded")
    return {"ok": True, "message": message}

@app.get("/api/exports")
async def exports(_user=Depends(current_user)):
    return {"rows": engine.export_workflow_rows(), "stats": engine.export_history_stats()}

@app.post("/api/exports")
async def create_export(body: ExportRequest, user=Depends(require_csrf)):
    eid = engine.create_export_request(user["email"], body.data_class, body.purpose, body.row_count)
    record_actor_action(user, "WEB_EXPORT_REQUEST_CREATED", eid, f"{body.data_class}; {body.row_count} rows; {body.purpose}")
    return {"ok": True, "export_id": eid, "message": "Request submitted for approval."}

@app.post("/api/exports/{export_id}/approve")
async def approve_export(export_id: str, body: ApproveExport, user=Depends(require_csrf_roles("admin", "approver"))):
    if user["role"] not in ("admin", "approver"):
        raise HTTPException(403, "Approver role required.")
    ok, message = engine.approve_export(export_id, body.approver)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_EXPORT_APPROVED_SIMULATED", export_id, body.approver)
    return {"ok": True, "message": message}

@app.post("/api/exports/{export_id}/delete")
async def delete_export(export_id: str, user=Depends(require_csrf_roles("admin", "approver"))):
    ok, message = engine.delete_export(export_id)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_EXPORT_DELETE_VERIFIED", export_id, "artifact deleted and absence verified")
    return {"ok": True, "message": message}

@app.get("/api/sensitive")
async def sensitive(_user=Depends(current_user)):
    return {"findings": engine.sensitive_data_findings()}

@app.post("/api/sensitive/scan")
async def sensitive_scan(body: ScanRequest, _user=Depends(require_csrf)):
    found, message = engine.scan_generic_ticket(body.text)
    return {"found": found, "message": message}

@app.get("/api/time")
async def time_data(_user=Depends(current_user)):
    return {"sources": [{"id": "E01", "label": "LedgerOne API", "zone": "UTC", "reliability": "UTC timestamp source"},
                        {"id": "E02", "label": "HelpDeskr audit", "zone": "Asia/Kolkata", "reliability": "Known tenant local time"},
                        {"id": "E03", "label": "SSO sign-in", "zone": "UTC", "reliability": "Device field missing before 20 Jun 2026"},
                        {"id": "E05", "label": "BlueVault access", "zone": "UNSYNCHRONIZED", "reliability": "Clock was not synchronized; conversion does not repair drift"},
                        {"id": "E15", "label": "Private-link flow", "zone": "UTC", "reliability": "Host labels unverified"},
                        {"id": "E18", "label": "LedgerOne API continued", "zone": "UTC", "reliability": "UTC timestamp source"},
                        {"id": "E19", "label": "Vendor record changes", "zone": "UTC", "reliability": "UTC timestamp source"}]}

@app.post("/api/time/normalize")
async def normalize_time(user=Depends(require_csrf)):
    path, stats = engine.normalize_evidence()
    record_actor_action(user, "WEB_EVIDENCE_TIME_NORMALIZED", "E01-E20", json.dumps(stats))
    return {"ok": True, "stats": stats, "download": "/api/downloads/variant404_normalized_evidence.csv"}

@app.get("/api/notices")
async def notices(_user=Depends(current_user)):
    return {"rows": engine.route_notices()}

@app.post("/api/notices/{notice_id}/route")
async def route_notice(notice_id: str, body: RouteNotice, user=Depends(require_csrf_roles("admin", "approver"))):
    ok, message = engine.reroute_notice(notice_id, body.recipients)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_NOTICE_ROUTED_SIMULATED", notice_id, "; ".join(body.recipients))
    return {"ok": True, "message": message}

@app.get("/api/governance")
async def governance(_user=Depends(current_user)):
    return {"findings": engine.audit_findings(), "risks": engine.risk_rows(), "tasks": engine.task_rows()}

@app.post("/api/governance/tasks/{task_id}/close")
async def close_task(task_id: str, body: CloseTask, user=Depends(require_csrf_roles("admin", "approver"))):
    ok, message = engine.close_task(task_id, body.evidence)
    if not ok: raise HTTPException(400, message)
    record_actor_action(user, "WEB_GOVERNANCE_TASK_CLOSED", task_id, body.evidence)
    return {"ok": True, "message": message}

@app.get("/api/evidence")
async def evidence_vault(_user=Depends(current_user)):
    manifest = []
    for p in sorted(engine.data_dir.glob("*")):
        if p.is_file():
            manifest.append({"file": p.name, "bytes": p.stat().st_size,
                             "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    ok, message = engine.verify_action_chain()
    return {"files": manifest, "action_chain": {"valid": ok, "message": message}, "actions": engine.action_log_rows(100)}

@app.post("/api/evidence/manifest")
async def create_manifest(user=Depends(require_csrf)):
    path, manifest = engine.create_evidence_manifest()
    record_actor_action(user, "WEB_EVIDENCE_MANIFEST_CREATED", "E01-E20", f"Hashed {len(manifest)} items")
    return {"ok": True, "count": len(manifest), "download": "/api/downloads/evidence_manifest_sha256.json"}

@app.get("/api/action-ledger")
async def action_ledger(_user=Depends(current_user)):
    ok, message = engine.verify_action_chain()
    return {"valid": ok, "message": message, "rows": engine.action_log_rows(250)}

@app.post("/api/action-ledger/verify")
async def verify_ledger(user=Depends(require_csrf)):
    ok, message = engine.verify_action_chain()
    record_actor_action(user, "WEB_ACTION_LEDGER_VERIFIED", "ACTION-CHAIN", message)
    return {"valid": ok, "message": message}

@app.post("/api/company/import")
async def company_import(user=Depends(require_csrf), file: UploadFile = File(...), mapping: UploadFile | None = File(default=None)):
    if not file.filename or Path(file.filename).suffix.lower() != ".csv":
        raise HTTPException(400, "Upload a CSV file.")
    file_bytes = await file.read(15 * 1024 * 1024 + 1)
    if len(file_bytes) > 15 * 1024 * 1024:
        raise HTTPException(413, "CSV file exceeds the 15 MB upload limit.")
    mapping_bytes = await mapping.read(256 * 1024 + 1) if mapping else b""
    if len(mapping_bytes) > 256 * 1024:
        raise HTTPException(413, "Mapping JSON exceeds 256 KB.")
    with tempfile.TemporaryDirectory() as td:
        csv_path = Path(td) / "company_events.csv"
        csv_path.write_bytes(file_bytes)
        mapping_path = None
        if mapping_bytes:
            try:
                parsed = json.loads(mapping_bytes.decode("utf-8-sig"))
                if not isinstance(parsed, dict): raise ValueError("Mapping must be a JSON object.")
                mapping_path = Path(td) / "field_mapping.json"
                mapping_path.write_text(json.dumps(parsed), encoding="utf-8")
            except Exception as exc:
                raise HTTPException(400, f"Invalid mapping JSON: {exc}")
        try:
            count, message = engine.import_company_csv(csv_path, mapping_path)
        except (UnicodeDecodeError, csv.Error) as exc:
            raise HTTPException(400, f"Unable to parse CSV: {exc}")
    record_actor_action(user, "WEB_COMPANY_EVENTS_IMPORTED", file.filename, f"{count} rows")
    return {"ok": True, "count": count, "message": message}

@app.get("/api/company")
async def company_data(_user=Depends(current_user)):
    with engine._connect() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM company_events ORDER BY rowid DESC LIMIT 250")]
        total = con.execute("SELECT COUNT(*) FROM company_events").fetchone()[0]
    return {"rows": rows, "total": total, "template": "/company_template/sample_company_events.csv", "mapping": "/company_template/field_mapping.json"}

@app.post("/api/scenario/evaluate")
async def scenario(body: ScenarioRequest, user=Depends(require_csrf)):
    change = body.model_dump()
    result = engine.evaluate_payment_change(change)
    # The scenario is evaluated without writing to the evidence or payment workflow tables.
    record_actor_action(user, "WEB_SCENARIO_EVALUATED", body.change_id, f"score={result['risk_score']}; hold={result['hold_required']}")
    return clean_dict({"result": result, "note": "Unseen variation evaluation only; no evidence or payment state was changed."})

@app.get("/api/brief")
async def brief_preview(_user=Depends(current_user)):
    return {"ready": (engine.exports_dir / "weekly_security_assurance_brief.txt").exists(),
            "download": "/api/downloads/weekly_security_assurance_brief.txt"}

@app.post("/api/brief/generate")
async def generate_brief(user=Depends(require_csrf)):
    path = engine.weekly_brief()
    record_actor_action(user, "WEB_WEEKLY_BRIEF_GENERATED", path.name, "Management and Audit Committee brief generated")
    return {"ok": True, "download": "/api/downloads/weekly_security_assurance_brief.txt",
            "preview": path.read_text(encoding="utf-8")[:12000]}

@app.get("/company_template/{filename}")
async def company_template(filename: str, _user=Depends(current_user)):
    if filename not in {"sample_company_events.csv", "field_mapping.json"}:
        raise HTTPException(404, "Template not found.")
    path = (APP_ROOT / "company_template" / filename).resolve()
    if path.parent != (APP_ROOT / "company_template").resolve() or not path.is_file():
        raise HTTPException(404, "Template not found.")
    return FileResponse(path, filename=filename)

@app.get("/api/downloads/{filename}")
async def download_file(filename: str, _user=Depends(current_user)):
    allowed = {"variant404_normalized_evidence.csv", "evidence_manifest_sha256.json", "weekly_security_assurance_brief.txt"}
    if filename.startswith("simulated_export_EXP-") and filename.endswith(".csv"):
        allowed.add(filename)
    if filename not in allowed:
        raise HTTPException(404, "File not found.")
    path = (engine.exports_dir / filename).resolve()
    if path.parent != engine.exports_dir.resolve() or not path.is_file():
        raise HTTPException(404, "File not found.")
    return FileResponse(path, filename=filename)

@app.get("/api/health")
async def health():
    try:
        with engine._connect() as con:
            con.execute("SELECT 1").fetchone()
        with auth_connect() as con:
            con.execute("SELECT 1").fetchone()
        return {"status": "ok", "service": "variant404"}
    except Exception:
        raise HTTPException(503, "Storage check failed.")

# ----------------------------- Security headers ------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    if IS_PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ------------------------------- Static React --------------------------------

FRONTEND_DIST = APP_ROOT / "frontend" / "dist"
ASSETS_DIR = FRONTEND_DIST / "assets"
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")

@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(404, "API route not found.")
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    return JSONResponse({"message": "Variant404 API is running. Build the React frontend to enable the web interface."}, status_code=200)
