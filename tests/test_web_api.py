import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

TEST_DATA = tempfile.mkdtemp(prefix="variant404-web-tests-")
os.environ["DATA_DIR"] = TEST_DATA
os.environ["ENVIRONMENT"] = "test"
os.environ["APP_SECRET"] = "test-only-app-secret-value-which-is-long-enough-123456789"
os.environ["INGEST_SECRET"] = "test-only-ingestion-secret-which-is-long-enough-123456"
os.environ["INITIAL_ADMIN_EMAIL"] = "admin@tests.variant404"
os.environ["INITIAL_ADMIN_NAME"] = "Test Administrator"
os.environ["INITIAL_ADMIN_PASSWORD"] = "Test-Only-Strong-Password-2026!"
os.environ["COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient
from backend.main import app


class WebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()
        response = cls.client.post("/api/auth/login", json={
            "email": "admin@tests.variant404",
            "password": "Test-Only-Strong-Password-2026!",
        })
        if response.status_code != 200:
            raise RuntimeError(f"Test admin login failed: {response.text}")

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def csrf(self):
        return {"X-CSRF-Token": self.client.cookies.get("v404_csrf", "")}

    def test_health_and_auth(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)

    def test_case_vendor_payment_cross_join(self):
        response = self.client.get("/api/payments")
        self.assertEqual(response.status_code, 200)
        coastal = next(x for x in response.json()["analysis"] if x["vendor_name"] == "Coastal Packaging Ltd")
        self.assertEqual(coastal["risk_score"], 9)
        self.assertTrue(coastal["exact_api_join"])
        self.assertTrue(coastal["hold_required"])

    def test_api_monitor_includes_case_alerts_and_all_registry_keys(self):
        response = self.client.get("/api/monitor")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(data["summary"]["total_requests"], 30000)
        self.assertGreaterEqual(data["summary"]["alert_count"], 5)
        self.assertEqual(data["summary"]["registered_credentials"], 8)
        self.assertIn("key-tb-07", [x["credential_id"] for x in data["credentials"]])

    def test_ingestion_requires_secret_and_flags_repeated_denials(self):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event = {
            "timestamp": now, "system": "Test Gateway",
            "credential_id": "svc-test-unknown", "actor_type": "integration",
            "action": "token.denied", "endpoint": "/v1/data", "method": "GET",
            "source_ip": "203.0.113.88", "status_code": 401,
            "auth_result": "denied", "outcome": "invalid credential",
        }
        payload = {"events": [event | {"event_id": f"test-denied-{i}", "timestamp": (datetime.now(timezone.utc).replace(second=10+i).isoformat().replace("+00:00", "Z"))} for i in range(3)]}
        denied = self.client.post("/api/monitor/ingest", json=payload)
        self.assertEqual(denied.status_code, 401)
        accepted = self.client.post("/api/monitor/ingest", json=payload,
                                    headers={"X-Ingest-Key": "test-only-ingestion-secret-which-is-long-enough-123456"})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["accepted"], 3)
        monitor = self.client.get("/api/monitor").json()
        self.assertGreaterEqual(monitor["summary"]["auth_failures"], 3)
        self.assertTrue(any("Repeated API authentication failures" == a["title"] for a in monitor["alerts"]))

    def test_ingest_rejects_timezone_naive_timestamp(self):
        payload = {"events": [{"event_id": "naive-time", "timestamp": "2026-11-20 09:00:00",
                               "credential_id": "svc-demo", "status_code": 200}]}
        response = self.client.post("/api/monitor/ingest", json=payload,
                                    headers={"X-Ingest-Key": "test-only-ingestion-secret-which-is-long-enough-123456"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["accepted"], 0)
        self.assertEqual(len(response.json()["rejected"]), 1)

    def test_ingestion_rejects_secret_fields(self):
        event = {"timestamp": datetime.now(timezone.utc).isoformat(),
                 "credential_id": "svc-demo", "status_code": 200,
                 "api_key": "must-not-be-accepted"}
        response = self.client.post("/api/monitor/ingest", json={"events": [event]},
                                    headers={"X-Ingest-Key": "test-only-ingestion-secret-which-is-long-enough-123456"})
        self.assertEqual(response.status_code, 422)

    def test_scenario_does_not_create_payment_record(self):
        before = self.client.get("/api/payments").json()["rows"]
        payload = {"change_id": "SCENARIO-TEST-001", "changed_by": "key-tb-07",
                   "field": "bank_account", "approval_ref": "", "source_ip": "192.0.2.19"}
        response = self.client.post("/api/scenario/evaluate", json=payload, headers=self.csrf())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["result"]["hold_required"])
        after = self.client.get("/api/payments").json()["rows"]
        self.assertEqual(len(before), len(after))

    def test_analyst_cannot_approve_payment_release(self):
        created = self.client.post("/api/users", json={
            "email": "analyst@tests.variant404",
            "display_name": "Test Analyst",
            "password": "Analyst-Only-Strong-Password-2026!",
            "role": "analyst",
        }, headers=self.csrf())
        self.assertEqual(created.status_code, 200)
        analyst = TestClient(app)
        login = analyst.post("/api/auth/login", json={
            "email": "analyst@tests.variant404",
            "password": "Analyst-Only-Strong-Password-2026!",
        })
        self.assertEqual(login.status_code, 200)
        headers = {"X-CSRF-Token": analyst.cookies.get("v404_csrf", "")}
        response = analyst.post("/api/payments/not-a-real-change/release", json={
            "callback_verified": True, "approver": "Test Analyst", "approval_ref": "TEST-REF-01",
        }, headers=headers)
        self.assertEqual(response.status_code, 403)
        analyst.close()

    def test_unauthed_user_cannot_access_module_data(self):
        other = TestClient(app)
        response = other.get("/api/payments")
        self.assertEqual(response.status_code, 401)
        other.close()


if __name__ == "__main__":
    unittest.main()
