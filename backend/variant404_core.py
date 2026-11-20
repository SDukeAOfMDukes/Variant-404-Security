"""Variant404 core business security control engine.

All control actions run against a local simulation database. The application does
not connect to production ERP, SSO, storage, payment, email or cloud services.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import uuid
import zipfile
from contextlib import contextmanager
from collections import Counter, defaultdict
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

APP_NAME = "Variant404"
CASE_AS_OF = date(2026, 9, 7)
RISK_EXPORT_DATE = date(2026, 9, 2)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return {} if default is None else default
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return default


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Variant404Engine:
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.data_dir = self.base_dir / "demo_data" / "evidence"
        self.exports_dir = self.base_dir / "exports"
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "variant404_state.sqlite3"
        self._init_db()
        default_profile = {
            "organization": "Harbor & Finch Freight Pvt. Ltd. (demo profile)",
            "payment_hold_missing_approval": True,
            "payment_score_threshold": 5,
            "integration_ip_restriction_required": True,
            "integration_max_token_days": 90,
            "stale_credential_days": 180,
            "bulk_export_approval_required": True,
            "export_expiry_hours": 24,
            "notice_recipients": ["IT Security", "Legal", "Finance", "System Owner"],
            "timezone": "Asia/Kolkata"
        }
        profile_path = self.base_dir / "company_profile.json"
        if not profile_path.exists():
            profile_path.write_text(json.dumps(default_profile, indent=2), encoding="utf-8")
        self.profile = read_json(profile_path, default_profile)
        self.files = self._file_map()
        self._seed_payment_holds()
        self._seed_offboarding()

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_db(self):
        with self._connect() as con:
            con.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS payments(
              change_id TEXT PRIMARY KEY, vendor_id TEXT, vendor_name TEXT, field TEXT,
              old_value TEXT, new_value TEXT, changed_by TEXT, ts_utc TEXT, risk_score INTEGER,
              reasons TEXT, status TEXT, callback_verified INTEGER DEFAULT 0,
              approver TEXT DEFAULT '', approval_ref TEXT DEFAULT '', updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS offboarding(
              username TEXT PRIMARY KEY, full_name TEXT, termination_date TEXT, roster_status TEXT,
              post_term_logins INTEGER, status TEXT, sso_disabled INTEGER DEFAULT 0,
              sessions_revoked INTEGER DEFAULT 0, apps_removed INTEGER DEFAULT 0,
              verified INTEGER DEFAULT 0, updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks(
              task_id TEXT PRIMARY KEY, category TEXT, title TEXT, owner TEXT, due_date TEXT,
              status TEXT, evidence TEXT DEFAULT '', notes TEXT DEFAULT '', updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS notices(
              notice_id TEXT PRIMARY KEY, subject TEXT, received TEXT, source TEXT,
              recipients TEXT, acknowledged TEXT, status TEXT, notes TEXT
            );
            CREATE TABLE IF NOT EXISTS exports(
              export_id TEXT PRIMARY KEY, requester TEXT, data_class TEXT, purpose TEXT,
              row_count INTEGER, status TEXT, approver TEXT DEFAULT '', expires_at TEXT DEFAULT '',
              artifact_name TEXT DEFAULT '', created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS integrations(
              credential_id TEXT PRIMARY KEY, simulated_ip_restriction INTEGER,
              simulated_token_days INTEGER, simulated_scope TEXT, rotated INTEGER DEFAULT 0,
              revoked INTEGER DEFAULT 0, verified INTEGER DEFAULT 0,
              replacement_id TEXT DEFAULT '', updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS action_log(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT, actor TEXT,
              action TEXT, object_ref TEXT, detail TEXT, prev_hash TEXT, event_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS company_events(
              event_id TEXT PRIMARY KEY, ts_utc TEXT, system TEXT, actor TEXT, action TEXT,
              object_id TEXT, source_ip TEXT, result TEXT, approval_ref TEXT, request_id TEXT,
              original_timestamp TEXT, time_reliability TEXT
            );
            CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY, value TEXT);
            """)
            integration_columns = {r[1] for r in con.execute("PRAGMA table_info(integrations)")}
            if "replacement_id" not in integration_columns:
                con.execute("ALTER TABLE integrations ADD COLUMN replacement_id TEXT DEFAULT ''")

    def _file_map(self) -> dict[str, Path]:
        mapping = {}
        for p in self.data_dir.glob("*"):
            name = p.name
            m = re.match(r"(E\d{2})_", name)
            if m:
                mapping[m.group(1)] = p
        return mapping

    def file(self, evidence_id: str) -> Path:
        return self.files.get(evidence_id, self.data_dir / "missing")

    def _api_rows(self) -> list[dict[str, str]]:
        return read_csv(self.file("E01")) + read_csv(self.file("E18"))

    def _normal_hosts(self) -> dict[str, set[str]]:
        rows = self._api_rows()
        counts: dict[str, Counter] = defaultdict(Counter)
        totals: Counter = Counter()
        for row in rows:
            key, ip = row.get("api_key_id", ""), row.get("caller_ip", "")
            if key.startswith("key-") and ip:
                counts[key][ip] += 1
                totals[key] += 1
        normal = {}
        for key, counter in counts.items():
            total = totals[key]
            normal[key] = {ip for ip, count in counter.items() if count / total >= 0.05}
        return normal

    def evaluate_payment_change(self, change: dict[str, Any], api_by_req=None, hosts=None) -> dict[str, Any]:
        """Score one bank-detail change and apply the preventive hold policy."""
        if api_by_req is None:
            api_by_req = {r.get("request_id", ""): r for r in self._api_rows() if r.get("request_id")}
        if hosts is None:
            hosts = self._normal_hosts()
        reasons = []
        score = 0
        actor = str(change.get("changed_by", ""))
        field_name = str(change.get("field", "")).lower()
        if actor.startswith("key-"):
            score += 2
            reasons.append("Integration credential performed the change (+2)")
        if field_name == "bank_account":
            score += 3
            reasons.append("Sensitive financial field: bank_account (+3)")
        missing_approval = not str(change.get("approval_ref", "") or "").strip()
        if missing_approval:
            score += 1
            reasons.append("No approval reference (+1)")
        ip = str(change.get("source_ip", ""))
        trusted = hosts.get(actor, set()) if actor.startswith("key-") else set()
        baseline_mature = bool(trusted)
        if actor.startswith("key-") and baseline_mature and ip not in trusted:
            score += 3
            reasons.append("Source host outside the integration's >=5% baseline (+3)")
        elif actor.startswith("key-") and not baseline_mature:
            reasons.append("Insufficient established host baseline; source location is not scored")
        req_id = str(change.get("request_id", "") or "")
        api = api_by_req.get(req_id) if req_id else None
        exact_join = bool(api and api.get("caller_ip") == ip and api.get("api_key_id") == actor
                          and api.get("ts_utc") == change.get("ts_utc")
                          and str(api.get("status")) == "200"
                          and str(api.get("method", "")).upper() in {"PATCH", "PUT"}
                          and str(change.get("vendor_id", "")) in str(api.get("endpoint", "")))
        threshold = int(self.profile.get("payment_score_threshold", 5))
        threshold_crossed = score >= threshold
        hold = ((self.profile.get("payment_hold_missing_approval", True) and missing_approval)
                or threshold_crossed)
        return {**change, "risk_score": score, "risk_reasons": reasons,
                "api_record": api, "exact_api_join": exact_join,
                "trusted_hosts": sorted(trusted), "baseline_mature": baseline_mature,
                "hold_required": hold, "threshold_crossed": threshold_crossed,
                "status": "HELD — verification required" if hold else "No hold — policy checks passed"}

    def payment_analysis(self) -> list[dict[str, Any]]:
        changes = read_csv(self.file("E19"))
        api_by_req = {r.get("request_id", ""): r for r in self._api_rows() if r.get("request_id")}
        hosts = self._normal_hosts()
        return [self.evaluate_payment_change(c, api_by_req, hosts) for c in changes if c.get("field") == "bank_account"]

    def _seed_payment_holds(self):
        items = self.payment_analysis()
        with self._connect() as con:
            for x in items:
                con.execute("""INSERT OR IGNORE INTO payments
                (change_id,vendor_id,vendor_name,field,old_value,new_value,changed_by,ts_utc,risk_score,
                 reasons,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (x["change_id"], x["vendor_id"], x["vendor_name"], x["field"], x["old_value"],
                 x["new_value"], x["changed_by"], x["ts_utc"], x["risk_score"],
                 json.dumps(x["risk_reasons"]), "HELD" if x["hold_required"] else "CLEAR", utc_iso(datetime.now(timezone.utc))))

    def payment_rows(self) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = [dict(r) for r in con.execute("SELECT * FROM payments ORDER BY ts_utc DESC")]
        analysis = {r["change_id"]: r for r in self.payment_analysis()}
        for r in rows:
            r["analysis"] = analysis.get(r["change_id"], {})
        return rows

    def payment_detail(self, change_id: str) -> dict[str, Any] | None:
        return next((x for x in self.payment_rows() if x["change_id"] == change_id), None)

    def release_payment(self, change_id: str, callback_verified: bool, approver: str, approval_ref: str) -> tuple[bool, str]:
        if not callback_verified:
            return False, "Independent supplier callback must be verified first."
        if not approver.strip() or not approval_ref.strip():
            return False, "An independent Finance approver and approval reference are required."
        with self._connect() as con:
            row = con.execute("SELECT status FROM payments WHERE change_id=?", (change_id,)).fetchone()
            if not row:
                return False, "Payment change not found."
            con.execute("UPDATE payments SET status='RELEASED (SIMULATED)',callback_verified=1,approver=?,approval_ref=?,updated_at=? WHERE change_id=?",
                        (approver.strip(), approval_ref.strip(), utc_iso(datetime.now(timezone.utc)), change_id))
        self.log_action("Finance approver", "PAYMENT_RELEASE_SIMULATED", change_id,
                        f"Supplier callback verified; approver={approver}; approval_ref={approval_ref}")
        return True, "Change released in the local simulation. No real payment system was modified."

    def _seed_offboarding(self):
        roster = read_csv(self.file("E14"))
        signins = read_csv(self.file("E03"))
        for person in roster:
            term = person.get("termination_date", "")
            if not term:
                continue
            post = 0
            for event in signins:
                if event.get("user") == person.get("username") and event.get("result", "").lower() == "success":
                    dt = parse_dt(event.get("ts_utc"))
                    if dt and dt.date() > date.fromisoformat(term):
                        post += 1
            with self._connect() as con:
                con.execute("""INSERT OR IGNORE INTO offboarding
                (username,full_name,termination_date,roster_status,post_term_logins,status,updated_at)
                VALUES(?,?,?,?,?,'PENDING',?)""",
                (person.get("username"), person.get("full_name"), term, person.get("status"), post,
                 utc_iso(datetime.now(timezone.utc))))

    def offboarding_rows(self):
        with self._connect() as con:
            return [dict(r) for r in con.execute("SELECT * FROM offboarding ORDER BY post_term_logins DESC,termination_date")]

    def run_offboarding(self, username: str) -> tuple[bool, str]:
        with self._connect() as con:
            row = con.execute("SELECT * FROM offboarding WHERE username=?", (username,)).fetchone()
            if not row:
                return False, "Employee not found."
            # Authorized simulation: no real identity provider is contacted.
            con.execute("""UPDATE offboarding SET status='COMPLETED (SIMULATED)',sso_disabled=1,
                sessions_revoked=1,apps_removed=1,verified=1,updated_at=? WHERE username=?""",
                (utc_iso(datetime.now(timezone.utc)), username))
        self.log_action("HR/IT administrator", "OFFBOARDING_SIMULATED", username,
                        "SSO disabled; sessions revoked; connected-app access removed; verification passed")
        return True, "Offboarding simulated and all three post-action checks passed."

    def simulate_login(self, username: str) -> tuple[bool, str]:
        with self._connect() as con:
            row = con.execute("SELECT * FROM offboarding WHERE username=?", (username,)).fetchone()
        if row and row["verified"]:
            self.log_action("Identity simulator", "LOGIN_DENIED", username, "Account disabled by verified offboarding")
            return False, "DENIED — account is disabled in the simulation."
        return True, "LOGIN WOULD BE ALLOWED — offboarding has not been completed in this simulation."

    def integration_rows(self) -> list[dict[str, Any]]:
        source = read_json(self.file("E04"), {}).get("integrations", [])
        source_by_id = {x.get("credential_id"): x for x in source}
        with self._connect() as con:
            sim_rows = {r["credential_id"]: dict(r) for r in con.execute("SELECT * FROM integrations")}
        rows = []
        displayed = set()
        for item in source:
            credential = item.get("credential_id", "")
            sim = sim_rows.get(credential)
            ip_ok = bool(item.get("ip_restriction"))
            days = item.get("token_lifetime_days")
            scope = item.get("scope", "")
            last_used = date.fromisoformat(item["last_used"]) if item.get("last_used") else None
            stale_days = (RISK_EXPORT_DATE - last_used).days if last_used else None
            revoked = bool(sim and sim["revoked"])
            if sim:
                ip_ok = bool(sim["simulated_ip_restriction"])
                days = sim["simulated_token_days"]
                scope = sim["simulated_scope"] or scope
            violations = []
            if not revoked:
                if not ip_ok: violations.append("2.1 IP restriction missing")
                if days is None or safe_int(days, 99999) > int(self.profile["integration_max_token_days"]): violations.append("2.2 expiry exceeds 90 days or is absent")
                if any(token in scope.lower() for token in ("all-modules", "all-folders", "read:all", "admin")):
                    violations.append("2.3 broad scope needs least-privilege justification")
                if stale_days is not None and stale_days > int(self.profile["stale_credential_days"]): violations.append(f"Unused for {stale_days} days")
            rows.append({**item, "effective_ip_restriction": ip_ok, "effective_token_days": days,
                         "effective_scope": scope, "stale_days": None if revoked else stale_days,
                         "violations": violations, "compliant": revoked or len(violations) == 0,
                         "simulated": bool(sim), "revoked": revoked,
                         "replacement_id": sim.get("replacement_id", "") if sim else "",
                         "state": "REVOKED (SIMULATED)" if revoked else ("ACTIVE — SIMULATED CONFIG" if sim else item.get("status", "ACTIVE"))})
            displayed.add(credential)
        # Surface replacement credentials so the staged rotation can be inspected in the UI.
        for old_id, sim in sim_rows.items():
            new_id = sim.get("replacement_id")
            if not new_id or new_id in displayed:
                continue
            original = source_by_id.get(old_id, {})
            new_sim = sim_rows.get(new_id, {})
            rows.append({
                "integration": f"{original.get('integration', old_id)} — replacement",
                "credential_id": new_id, "system": original.get("system", "Unknown"),
                "vendor": original.get("vendor", "Unknown"), "owner": original.get("owner", "Unknown"),
                "scope": new_sim.get("simulated_scope", ""), "status": "active",
                "ip_restriction": True, "token_lifetime_days": 90,
                "effective_ip_restriction": bool(new_sim.get("simulated_ip_restriction", 1)),
                "effective_token_days": new_sim.get("simulated_token_days", 90),
                "effective_scope": new_sim.get("simulated_scope", ""), "stale_days": None,
                "violations": [], "compliant": True, "simulated": True, "revoked": False,
                "replacement_id": "", "state": "ACTIVE REPLACEMENT (SIMULATED)"})
            displayed.add(new_id)
        return rows

    def remediate_integration(self, credential_id: str, new_scope: str, owner_approval: bool) -> tuple[bool, str]:
        item = next((x for x in self.integration_rows() if x["credential_id"] == credential_id), None)
        if not item: return False, "Credential not found."
        if item.get("revoked"): return False, "Credential is already revoked in the simulation."
        if not owner_approval: return False, "Credential owner approval is required before simulated rotation."
        # Staged local workflow: create/test a replacement, then revoke the old simulated key.
        replacement_id = f"sim-{credential_id}-v2-{uuid.uuid4().hex[:6]}"
        now = utc_iso(datetime.now(timezone.utc))
        with self._connect() as con:
            con.execute("""INSERT INTO integrations(credential_id,simulated_ip_restriction,simulated_token_days,
              simulated_scope,rotated,revoked,verified,replacement_id,updated_at)
              VALUES(?,0,NULL,'',1,1,1,?,?)
              ON CONFLICT(credential_id) DO UPDATE SET rotated=1,revoked=1,verified=1,
              replacement_id=excluded.replacement_id,updated_at=excluded.updated_at""",
              (credential_id,replacement_id,now))
            con.execute("""INSERT INTO integrations(credential_id,simulated_ip_restriction,simulated_token_days,
              simulated_scope,rotated,revoked,verified,replacement_id,updated_at)
              VALUES(?,1,90,?,1,0,1,'',?)""",
              (replacement_id,new_scope.strip(),now))
        self.log_action("Integration owner", "CREDENTIAL_ROTATION_SIMULATED", credential_id,
                        f"Replacement={replacement_id}; scope={new_scope}; 90-day expiry; IP restriction enabled; compatibility test passed; old key revoked")
        return True, f"Staged rotation simulated: replacement {replacement_id} was configured and tested; old credential {credential_id} was revoked in local simulation. No production key was created or changed."

    def revoke_stale_integration(self, credential_id: str, owner_approval: bool) -> tuple[bool, str]:
        item = next((x for x in self.integration_rows() if x["credential_id"] == credential_id), None)
        if not item: return False, "Credential not found."
        if item.get("revoked"): return False, "Credential is already revoked in the simulation."
        if not owner_approval: return False, "Owner approval and dependency check are required."
        with self._connect() as con:
            con.execute("""INSERT INTO integrations(credential_id,simulated_ip_restriction,simulated_token_days,
             simulated_scope,rotated,revoked,verified,updated_at) VALUES(?,0,NULL,'',0,1,1,?)
             ON CONFLICT(credential_id) DO UPDATE SET revoked=1,verified=1,updated_at=excluded.updated_at""",
             (credential_id, utc_iso(datetime.now(timezone.utc))))
        self.log_action("Credential owner", "CREDENTIAL_REVOKE_SIMULATED", credential_id,
                        "Dependency checked and credential revoked in simulation")
        return True, "Credential revoked in simulation and state verified."

    def normalize_evidence(self) -> tuple[Path, dict[str, int]]:
        records = []
        stats = Counter()
        # Already UTC sources, plus their special reliability context.
        files = [("E01", "LedgerOne", "ts_utc", "UTC", "RELIABLE_TIMESTAMP_SOURCE"),
                 ("E18", "LedgerOne", "ts_utc", "UTC", "RELIABLE_TIMESTAMP_SOURCE"),
                 ("E03", "SSO", "ts_utc", "UTC", "UTC_RECORDED_DEVICE_FIELD_MAY_BE_MISSING"),
                 ("E15", "NetworkLink", "ts_utc", "UTC", "HOST_LABEL_UNVERIFIED"),
                 ("E19", "LedgerOneVendorMaster", "ts_utc", "UTC", "RELIABLE_TIMESTAMP_SOURCE"),
                 ("E02", "HelpDeskr", "ts_local", "Asia/Kolkata", "LOCAL_TIME_ZONE_KNOWN"),
                 ("E05", "BlueVault", "epoch_s", "UNSYNCHRONIZED", "CLOCK_UNSYNCHRONIZED")]
        for eid, system, col, zone, reliability in files:
            for row in read_csv(self.file(eid)):
                raw = row.get(col, "")
                dt = None
                if eid == "E05":
                    try: dt = datetime.fromtimestamp(int(raw), tz=timezone.utc)
                    except (ValueError, OSError, OverflowError): pass
                elif eid == "E02":
                    try:
                        local = datetime.strptime(raw, "%d/%m/%Y %H:%M:%S")
                        dt = (local - timedelta(hours=5, minutes=30)).replace(tzinfo=timezone.utc)
                    except ValueError: pass
                else:
                    dt = parse_dt(raw)
                if not dt:
                    stats["unparseable"] += 1
                    continue
                rel = reliability
                if eid == "E03" and dt.date() < date(2026, 6, 20):
                    rel = "DEVICE_CONTEXT_MISSING_BEFORE_2026-06-20"
                if eid == "E05": stats["unsynchronized_clock"] += 1
                records.append({"evidence_id": eid, "system": system, "original_timestamp": raw,
                                "timezone_or_clock": zone, "normalized_utc": utc_iso(dt),
                                "time_reliability": rel, "event_id": row.get("event_id", ""),
                                "actor": row.get("actor") or row.get("principal") or row.get("user") or row.get("api_key_id") or row.get("changed_by", ""),
                                "action": row.get("action") or row.get("method") or row.get("field", ""),
                                "source_ip": row.get("source_ip") or row.get("caller_ip") or row.get("src_ip", ""),
                                "raw_record": json.dumps(row, ensure_ascii=False)})
                stats[eid] += 1
        path = self.exports_dir / "variant404_normalized_evidence.csv"
        if records:
            with path.open("w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
                writer.writeheader(); writer.writerows(records)
        stats["total_normalized"] = len(records)
        return path, dict(stats)

    def export_workflow_rows(self):
        self.expire_due_exports()
        with self._connect() as con:
            return [dict(r) for r in con.execute("SELECT * FROM exports ORDER BY created_at DESC")]

    def expire_due_exports(self):
        """Delete expired synthetic export artifacts and verify their local absence."""
        now = datetime.now(timezone.utc)
        expired = []
        with self._connect() as con:
            rows = [dict(r) for r in con.execute("SELECT * FROM exports WHERE status='APPROVED (SIMULATED)' AND expires_at!=''")]
            for row in rows:
                due = parse_dt(row.get("expires_at"))
                if due and due <= now:
                    if row.get("artifact_name"):
                        target = self.exports_dir / row["artifact_name"]
                        if target.exists(): target.unlink()
                    con.execute("UPDATE exports SET status='EXPIRED — DELETED AND VERIFIED',artifact_name='' WHERE export_id=?", (row["export_id"],))
                    expired.append(row["export_id"])
        for export_id in expired:
            self.log_action("Export expiry engine", "EXPORT_EXPIRED_AND_DELETED", export_id, "Expiry time reached; synthetic artifact removed")
        return expired

    def export_history_stats(self):
        rows = read_csv(self.file("E02"))
        c = Counter(r.get("action", "") for r in rows)
        actor = Counter((r.get("actor", ""), r.get("action", "")) for r in rows if r.get("action", "").startswith("export."))
        return {"created": c["export.create"], "downloaded": c["export.download"],
                "deleted": c["export.delete"], "actor_counts": actor}

    def create_export_request(self, requester: str, data_class: str, purpose: str, row_count: int) -> str:
        export_id = "EXP-" + uuid.uuid4().hex[:8].upper()
        with self._connect() as con:
            con.execute("INSERT INTO exports(export_id,requester,data_class,purpose,row_count,status,created_at) VALUES(?,?,?,?,?,'PENDING APPROVAL',?)",
                        (export_id, requester, data_class, purpose, row_count, utc_iso(datetime.now(timezone.utc))))
        self.log_action(requester, "EXPORT_REQUEST_CREATED", export_id, f"class={data_class}; purpose={purpose}; rows={row_count}")
        return export_id

    def approve_export(self, export_id: str, approver: str) -> tuple[bool, str]:
        if not approver.strip(): return False, "Approver is required."
        expires = datetime.now(timezone.utc) + timedelta(hours=int(self.profile.get("export_expiry_hours", 24)))
        artifact = f"simulated_export_{export_id}.csv"
        p = self.exports_dir / artifact
        with p.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(["simulation_only", "export_id", "notice"]); w.writerow(["true", export_id, "No live company data exported"])
        with self._connect() as con:
            cur = con.execute("UPDATE exports SET status='APPROVED (SIMULATED)',approver=?,expires_at=?,artifact_name=? WHERE export_id=? AND status='PENDING APPROVAL'",
                              (approver, utc_iso(expires), artifact, export_id))
            if cur.rowcount == 0: return False, "Pending export request not found."
        self.log_action(approver, "EXPORT_APPROVED_SIMULATED", export_id, f"expires={utc_iso(expires)}")
        return True, "A synthetic export artifact was created with an expiry time."

    def delete_export(self, export_id: str) -> tuple[bool, str]:
        with self._connect() as con:
            row = con.execute("SELECT * FROM exports WHERE export_id=?", (export_id,)).fetchone()
            if not row: return False, "Export request not found."
            if row["artifact_name"]:
                p = self.exports_dir / row["artifact_name"]
                if p.exists(): p.unlink()
            con.execute("UPDATE exports SET status='DELETED AND VERIFIED',artifact_name='' WHERE export_id=?", (export_id,))
        self.log_action("Export control", "EXPORT_DELETE_VERIFIED", export_id, "Synthetic export artifact deleted")
        return True, "Synthetic export deleted and absence verified."

    def route_notices(self):
        seeded = [
            ("NOTICE-E12", "Precautionary update regarding customer connections", "2026-08-21 19:32 IST", "E12 TallyBridge", "Accounts only; no IT Security or Legal copy", "ROUTING GAP"),
            ("NOTICE-E16", "Investigation findings and next steps", "2026-08-28 18:10 IST", "E16 TallyBridge", "Accounts; IT Security", "LEGAL REVIEW NOT EVIDENCED")]
        with self._connect() as con:
            for item in seeded:
                con.execute("INSERT OR IGNORE INTO notices(notice_id,subject,received,source,recipients,acknowledged,status,notes) VALUES(?,?,?,?,?,?,?,?)",
                            (*item[:5], "", item[5], "Recipient routing is simulated; source notice is preserved."))
            return [dict(r) for r in con.execute("SELECT * FROM notices ORDER BY received DESC")]

    def reroute_notice(self, notice_id: str, recipients: list[str]) -> tuple[bool, str]:
        recipients = [x.strip() for x in recipients if x.strip()]
        if not recipients: return False, "At least one recipient is required."
        with self._connect() as con:
            con.execute("UPDATE notices SET recipients=?,status='ROUTED (SIMULATED)',acknowledged=? WHERE notice_id=?",
                        ("; ".join(recipients), utc_iso(datetime.now(timezone.utc)), notice_id))
        self.log_action("Notice workflow", "NOTICE_ROUTED_SIMULATED", notice_id, "Recipients=" + ", ".join(recipients))
        return True, "Notice routing simulated and recorded. No email was sent."

    def audit_findings(self) -> list[dict[str, Any]]:
        raw = [
          (1,"Staff MFA enforced across all user accounts","Info","Closed","n/a","None required"),
          (2,"11 of 50 sampled tickets contained pasted credentials or keys","High","Open","2025-12-31","Training and secure submission link"),
          (3,"Departed-employee accounts not always disabled promptly","Medium","Open","2025-10-31","HR and IT monthly reconciliation"),
          (4,"Integration keys do not expire; five of eight have no expiry and no IP restriction","High","Open","2025-12-31","Rotation after compatibility check"),
          (5,"Two integration credentials unused for more than six months remain active","Medium","Open","2025-12-31","Review during Q4"),
          (6,"No alerting for bulk exports or integration-account export deletion","High","Open","2026-03-31","Monitoring use cases to be defined"),
          (7,"Vendor risk assessments are not repeated annually","Medium","Open","2025-11-30","Review calendar to be created")]
        out=[]
        for n,title,rating,status,due,action in raw:
            due_date = date.fromisoformat(due) if due != "n/a" else None
            out.append({"finding":n,"title":title,"rating":rating,"status":status,"due":due,
                        "overdue": bool(due_date and due_date < CASE_AS_OF),"action":action,
                        "followup_status":"Not recorded in E11" if status=="Open" else "Closed in E11"})
        return out

    def risk_rows(self):
        # Transcribed from the supplied E09 workbook, retaining its exported-as-of date.
        rows = [
          ("R-004","Ransomware on shared file servers","IT",15,"High","Open","2026-08-10"),
          ("R-009","Warehouse scanner firmware vulnerabilities","Operations IT",9,"Medium","Open","2026-07-20"),
          ("R-012","Loss of key carrier contract","Operations",8,"Medium","Accepted","2027-03-01"),
          ("R-015","Phishing leading to payment fraud","Finance",16,"High","Open","2026-10-18"),
          ("R-018","Staff accounts not disabled after exit","HR / IT",9,"Medium","Open","2026-04-05"),
          ("R-022","Data centre power failure","IT",8,"Medium","Mitigated","2027-05-01"),
          ("R-025","Customer data leak through support tickets","Support Ops",16,"High","Open","2026-03-20"),
          ("R-029","Misuse of storage access key issued to customer partner","Support Ops",12,"Medium","Open","2025-09-30"),
          ("R-031","Vendor connector compromise (TallyBridge)","Finance IT",6,"Low","Accepted","2025-06-30"),
          ("R-033","Cloud billing overspend","Finance",6,"Low","Accepted","2026-12-01"),
          ("R-036","Legacy ERP end of vendor support","Finance IT",8,"Medium","Open","2026-09-15"),
          ("R-040","Key-person dependency in IT","IT",12,"Medium","Open","2026-08-02")]
        return [{"risk_id":x[0],"title":x[1],"owner":x[2],"score":x[3],"rating":x[4],"status":x[5],"next_review_due":x[6],"overdue":date.fromisoformat(x[6]) < RISK_EXPORT_DATE} for x in rows]

    def seed_governance_tasks(self):
        for finding in self.audit_findings():
            if finding["status"] == "Open":
                self.add_task("AUDIT", f"Audit finding {finding['finding']}: {finding['title']}", "Control owner", finding["due"], "OPEN", evidence=f"E11 finding {finding['finding']}")
        for risk in self.risk_rows():
            if risk["overdue"]:
                self.add_task("RISK REVIEW", f"Overdue review: {risk['risk_id']} — {risk['title']}", risk["owner"], risk["next_review_due"], "OPEN", evidence="E09 Risk Register")
        self.add_task("VENDOR REVIEW", "TallyBridge annual security review", "Finance IT / IT Security", "2025-06-05", "OPEN — NO COMPLETION EVIDENCE", evidence="E07; E11 finding 7")
        self.add_task("VENDOR REVIEW", "Customer Document Portal partner annual review", "Support Ops / IT Security", "2026-02-18", "OPEN — NO COMPLETION EVIDENCE", evidence="E04 bvk-7f3a; E10 §3.1; E11 finding 7")

    def add_task(self, category: str, title: str, owner: str, due: str, status: str="OPEN", evidence: str=""):
        task_id = "TASK-" + hashlib.sha1(f"{category}|{title}".encode()).hexdigest()[:8].upper()
        with self._connect() as con:
            con.execute("INSERT OR IGNORE INTO tasks(task_id,category,title,owner,due_date,status,evidence,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (task_id,category,title,owner,due,status,evidence,utc_iso(datetime.now(timezone.utc))))

    def task_rows(self):
        self.seed_governance_tasks()
        with self._connect() as con:
            return [dict(r) for r in con.execute("SELECT * FROM tasks ORDER BY CASE WHEN status LIKE 'CLOSED%' THEN 1 ELSE 0 END,due_date")]

    def close_task(self, task_id: str, evidence: str) -> tuple[bool, str]:
        if len(evidence.strip()) < 5:
            return False, "Closure evidence is required (minimum five characters)."
        with self._connect() as con:
            cur = con.execute("UPDATE tasks SET status='CLOSED — VERIFIED EVIDENCE PROVIDED',evidence=evidence,updated_at=? WHERE task_id=?",
                              (utc_iso(datetime.now(timezone.utc)),task_id))
            if cur.rowcount == 0: return False, "Task not found."
        self.log_action("Control owner", "TASK_CLOSED_WITH_EVIDENCE", task_id, evidence)
        return True, "Task marked closed in the local tracker with an evidence reference recorded. The application has not independently validated the referenced evidence."

    def sensitive_data_findings(self):
        data = read_json(self.file("E13"), {})
        results=[]
        patterns = [r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{8,}",
                    r"(?i)secret\s*[:=]\s*[A-Za-z0-9_\-]{8,}", r"\bbvk-[a-z0-9]{4,}\b"]
        for msg in data.get("messages", []):
            text = msg.get("text", "")
            if any(re.search(p, text) for p in patterns):
                redacted = text
                for p in patterns:
                    redacted = re.sub(p, "[REDACTED CREDENTIAL REFERENCE]", redacted)
                results.append({"timestamp":msg.get("ts_local"),"channel":msg.get("channel"),"author":msg.get("author"),"text":redacted,
                                "action":"Rotate affected credential; secure ticket; restrict access"})
        return results

    def scan_generic_ticket(self, text: str) -> tuple[bool, str]:
        patterns = [r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S{8,}"]
        found = any(re.search(p, text) for p in patterns)
        return found, "Potential credential detected. Redact, restrict ticket access and rotate the credential through an approved workflow." if found else "No supported credential pattern identified. This is not proof that the text is safe."

    def create_evidence_manifest(self):
        manifest=[]
        for p in sorted(self.data_dir.glob("*")):
            if p.is_file():
                manifest.append({"file":p.name,"bytes":p.stat().st_size,"sha256":sha256_file(p)})
        out=self.exports_dir/"evidence_manifest_sha256.json"
        out.write_text(json.dumps({"generated_utc":utc_iso(datetime.now(timezone.utc)),"files":manifest},indent=2),encoding="utf-8")
        self.log_action("Evidence Vault", "EVIDENCE_MANIFEST_CREATED", "E01-E20", f"Hashed {len(manifest)} original evidence files")
        return out,manifest

    def log_action(self, actor: str, action: str, object_ref: str, detail: str):
        ts=utc_iso(datetime.now(timezone.utc))
        with self._connect() as con:
            row=con.execute("SELECT event_hash FROM action_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev=row[0] if row else "GENESIS"
            payload=f"{prev}|{ts}|{actor}|{action}|{object_ref}|{detail}"
            digest=hashlib.sha256(payload.encode()).hexdigest()
            con.execute("INSERT INTO action_log(ts_utc,actor,action,object_ref,detail,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                        (ts,actor,action,object_ref,detail,prev,digest))

    def action_log_rows(self, limit: int=250):
        with self._connect() as con:
            return [dict(r) for r in con.execute("SELECT * FROM action_log ORDER BY seq DESC LIMIT ?", (limit,))]

    def verify_action_chain(self):
        with self._connect() as con:
            rows=[dict(r) for r in con.execute("SELECT * FROM action_log ORDER BY seq")]
        prev="GENESIS"
        for r in rows:
            payload=f"{prev}|{r['ts_utc']}|{r['actor']}|{r['action']}|{r['object_ref']}|{r['detail']}"
            digest=hashlib.sha256(payload.encode()).hexdigest()
            if r["prev_hash"] != prev or r["event_hash"] != digest:
                return False, f"Hash-chain mismatch at event {r['seq']}"
            prev=digest
        return True, f"Verified {len(rows)} action records"

    def weekly_brief(self) -> Path:
        payments=self.payment_rows()
        off=self.offboarding_rows()
        integ=self.integration_rows()
        findings=self.audit_findings()
        risks=self.risk_rows()
        tasks=self.task_rows()
        notices=self.route_notices()
        exports=self.export_history_stats()
        content=[
            "VARIANT404 | WEEKLY SECURITY CONTROL ASSURANCE BRIEF",
            "Prepared for: General Manager and Audit Committee Chair",
            f"Generated: {utc_iso(datetime.now(timezone.utc))}",
            "Scope: CRIMEATHON synthetic evidence and local simulation state only.","",
            "EXECUTIVE SUMMARY",
            f"Payment changes held: {sum(1 for x in payments if x['status'].startswith('HELD'))}",
            f"Offboarding jobs awaiting completion: {sum(1 for x in off if not x['verified'])}",
            f"Integration credentials with policy gaps: {sum(1 for x in integ if not x['compliant'])}",
            f"Audit findings open in E11 snapshot: {sum(1 for x in findings if x['status']=='Open')}",
            f"Overdue risk reviews at E09 export date: {sum(1 for x in risks if x['overdue'])}",
            f"Open remediation tasks: {sum(1 for x in tasks if not x['status'].startswith('CLOSED'))}","",
            "AUDIT FINDINGS (E11 REPORT STATUS; FOLLOW-UP NOT RECORDED)"]
        for x in findings: content.append(f"Finding {x['finding']} | {x['rating']} | {x['status']} | due {x['due']} | {x['title']}")
        content += ["", "KEY CONTROL ITEMS"]
        for x in integ:
            if x["violations"]: content.append(f"{x['credential_id']}: " + "; ".join(x["violations"]))
        content += ["", "PAYMENT INTERLOCK"]
        for x in payments:
            if x["status"].startswith("HELD"): content.append(f"{x['vendor_name']} ({x['change_id']}): held pending independent verification; score={x['risk_score']}")
        content += ["", "EXPORT HISTORY (E02)", f"Create={exports['created']}; download={exports['downloaded']}; delete={exports['deleted']}",
                    "", "NOTICE ROUTING", *[f"{n['notice_id']}: {n['status']} — {n['recipients']}" for n in notices],
                    "", "LIMITATIONS", "Evidence snapshots are synthetic. No production system was connected or changed.",
                    "E09 risk reviews are assessed against its 02 Sep 2026 export date. E11 follow-up status is not present in the supplied report.",
                    "A simulated task closure is not evidence that a real company control was changed."]
        out=self.exports_dir/"weekly_security_assurance_brief.txt"
        out.write_text("\n".join(content),encoding="utf-8")
        return out

    def import_company_csv(self, csv_path: Path, mapping_path: Path | None=None) -> tuple[int,str]:
        """Imports normalized generic events using standard columns or a JSON field map."""
        mapping={}
        if mapping_path and Path(mapping_path).exists():
            mapping=read_json(Path(mapping_path),{})
        rows=read_csv(Path(csv_path))
        count=0
        with self._connect() as con:
            for i,row in enumerate(rows,1):
                def get(k,default=""):
                    return row.get(mapping.get(k,k),default)
                raw_ts=get("timestamp") or get("ts_utc")
                dt=parse_dt(raw_ts)
                normalized=(utc_iso(dt) if dt and dt.tzinfo is not None else "")
                event_id=get("event_id") or f"IMPORTED-{hashlib.sha1((str(csv_path)+str(i)).encode()).hexdigest()[:10]}"
                vals=(event_id,normalized,get("system","Imported"),get("actor"),get("action"),get("object_id"),get("source_ip"),get("result"),get("approval_ref"),get("request_id"),raw_ts,"IMPORTED_TIMEZONE_UNVERIFIED")
                con.execute("INSERT OR REPLACE INTO company_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",vals)
                count+=1
        self.log_action("Company data importer","COMPANY_EVENTS_IMPORTED",Path(csv_path).name,f"Imported {count} normalized events; source timezone metadata requires verification")
        return count,"Imported events. Review timezone and field mapping before treating timestamps as authoritative."
