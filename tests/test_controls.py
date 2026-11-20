import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from backend.variant404_core import Variant404Engine

PROJECT = Path(__file__).resolve().parents[1]

class Variant404ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        (self.base / "demo_data").mkdir()
        shutil.copytree(PROJECT / "demo_data" / "evidence", self.base / "demo_data" / "evidence")
        self.engine = Variant404Engine(self.base)

    def tearDown(self):
        self.temp.cleanup()

    def test_payment_interlock_holds_all_unapproved_bank_changes(self):
        rows = self.engine.payment_analysis()
        bank = [x for x in rows if x["field"] == "bank_account"]
        held = [x for x in bank if x["hold_required"]]
        self.assertEqual(len(bank), 40)
        self.assertEqual(len(held), 4)
        coastal = next(x for x in bank if x["vendor_name"] == "Coastal Packaging Ltd")
        self.assertEqual(coastal["risk_score"], 9)
        self.assertTrue(coastal["exact_api_join"])
        staff = [x for x in held if x["channel"] == "UI"]
        self.assertEqual(len(staff), 3)
        self.assertTrue(all(x["risk_score"] == 4 for x in staff))
        self.assertEqual(sum(x["threshold_crossed"] for x in bank), 1)

    def test_payment_release_requires_independent_callback_and_approval(self):
        held = next(x for x in self.engine.payment_rows() if x["vendor_name"] == "Coastal Packaging Ltd")
        ok, _ = self.engine.release_payment(held["change_id"], False, "", "")
        self.assertFalse(ok)
        ok, _ = self.engine.release_payment(held["change_id"], True, "", "APR-1")
        self.assertFalse(ok)
        ok, _ = self.engine.release_payment(held["change_id"], True, "Finance Approver", "APR-1")
        self.assertTrue(ok)
        latest = self.engine.payment_detail(held["change_id"])
        self.assertTrue(latest["status"].startswith("RELEASED"))

    def test_offboarding_finds_rohan_and_denies_simulated_login_after_action(self):
        rows = self.engine.offboarding_rows()
        rohan = next(x for x in rows if x["username"] == "r.menon")
        self.assertEqual(rohan["post_term_logins"], 1)
        self.assertFalse(rohan["verified"])
        ok, _ = self.engine.run_offboarding("r.menon")
        self.assertTrue(ok)
        allowed, msg = self.engine.simulate_login("r.menon")
        self.assertFalse(allowed)
        self.assertIn("DENIED", msg)

    def test_integration_policy_gap_counts(self):
        rows = self.engine.integration_rows()
        self.assertEqual(len(rows), 8)
        no_ip_and_no_expiry = [x for x in rows if not x["effective_ip_restriction"] and not x["effective_token_days"]]
        stale = [x for x in rows if x["stale_days"] and x["stale_days"] > 180]
        self.assertEqual(len(no_ip_and_no_expiry), 5)
        self.assertEqual({x["credential_id"] for x in stale}, {"key-tb-03", "key-app-12"})
        tb = next(x for x in rows if x["credential_id"] == "key-tb-07")
        self.assertTrue(any("2.1" in v for v in tb["violations"]))
        self.assertTrue(any("2.2" in v for v in tb["violations"]))
        self.assertTrue(any("2.3" in v for v in tb["violations"]))

    def test_integration_rotation_creates_replacement_then_revokes_old_key(self):
        ok, msg = self.engine.remediate_integration("key-tb-07", "read:invoices,vendor-contact", True)
        self.assertTrue(ok, msg)
        rows = self.engine.integration_rows()
        old = next(x for x in rows if x["credential_id"] == "key-tb-07")
        self.assertTrue(old["revoked"])
        self.assertTrue(old["replacement_id"].startswith("sim-key-tb-07-v2-"))
        new = next(x for x in rows if x["credential_id"] == old["replacement_id"])
        self.assertEqual(new["state"], "ACTIVE REPLACEMENT (SIMULATED)")
        self.assertTrue(new["effective_ip_restriction"])
        self.assertEqual(new["effective_token_days"], 90)
        self.assertTrue(new["compliant"])

    def test_time_normalization_preserves_unsynchronized_warning(self):
        path, stats = self.engine.normalize_evidence()
        self.assertTrue(path.exists())
        self.assertGreater(stats["total_normalized"], 40000)
        self.assertGreater(stats["unsynchronized_clock"], 0)
        with path.open(encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        bluevault = next(x for x in rows if x["evidence_id"] == "E05")
        self.assertEqual(bluevault["time_reliability"], "CLOCK_UNSYNCHRONIZED")

    def test_export_requires_approval_and_deletes_artifact(self):
        eid = self.engine.create_export_request("test.user", "Financial records", "Month end", 20)
        row = next(x for x in self.engine.export_workflow_rows() if x["export_id"] == eid)
        self.assertEqual(row["status"], "PENDING APPROVAL")
        ok, _ = self.engine.approve_export(eid, "Finance Approver")
        self.assertTrue(ok)
        row = next(x for x in self.engine.export_workflow_rows() if x["export_id"] == eid)
        self.assertTrue((self.engine.exports_dir / row["artifact_name"]).exists())
        ok, _ = self.engine.delete_export(eid)
        self.assertTrue(ok)
        row = next(x for x in self.engine.export_workflow_rows() if x["export_id"] == eid)
        self.assertEqual(row["status"], "DELETED AND VERIFIED")

    def test_sensitive_data_detection_redacts_key_reference(self):
        rows = self.engine.sensitive_data_findings()
        self.assertGreaterEqual(len(rows), 1)
        self.assertIn("[REDACTED", rows[0]["text"])
        found, _ = self.engine.scan_generic_ticket("credential token=TESTTOKEN123456789")
        self.assertTrue(found)

    def test_notice_routing_gap_and_simulated_reroute(self):
        rows = self.engine.route_notices()
        e12 = next(x for x in rows if x["notice_id"] == "NOTICE-E12")
        self.assertIn("Accounts only", e12["recipients"])
        ok, _ = self.engine.reroute_notice("NOTICE-E12", ["IT Security", "Legal", "Finance"])
        self.assertTrue(ok)
        latest = next(x for x in self.engine.route_notices() if x["notice_id"] == "NOTICE-E12")
        self.assertIn("Legal", latest["recipients"])

    def test_audit_and_risk_snapshots(self):
        findings = self.engine.audit_findings()
        self.assertEqual(sum(x["status"] == "Open" for x in findings), 6)
        overdue = [x for x in self.engine.risk_rows() if x["overdue"]]
        self.assertEqual(len(overdue), 7)
        self.assertEqual(len(self.engine.task_rows()), 15)

    def test_action_hash_chain_verifies(self):
        self.engine.log_action("test", "TEST_ACTION", "OBJ-1", "first event")
        self.engine.log_action("test", "TEST_ACTION", "OBJ-2", "second event")
        ok, msg = self.engine.verify_action_chain()
        self.assertTrue(ok, msg)

    def test_company_import_does_not_assume_naive_timestamp_is_utc(self):
        sample = self.base / "company.csv"
        sample.write_text("ts,event_id,system,actor,action\n2026-09-01 10:00:00,e1,ERP,user1,vendor.change\n", encoding="utf-8")
        mapping = self.base / "map.json"
        mapping.write_text(json.dumps({"timestamp":"ts","event_id":"event_id","system":"system","actor":"actor","action":"action"}), encoding="utf-8")
        count, _ = self.engine.import_company_csv(sample, mapping)
        self.assertEqual(count, 1)
        with self.engine._connect() as con:
            row = con.execute("SELECT * FROM company_events WHERE event_id='e1'").fetchone()
        self.assertEqual(row["ts_utc"], "")
        self.assertEqual(row["time_reliability"], "IMPORTED_TIMEZONE_UNVERIFIED")

if __name__ == "__main__":
    unittest.main()
