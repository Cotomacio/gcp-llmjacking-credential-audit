#!/usr/bin/env python3
"""Testes unitários para audit_genai_api_keys.py."""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import audit_genai_api_keys as gk  # noqa: E402


class FakeRunner(gk.GcloudRunner):

    def __init__(self, ts_data):
        super().__init__(billing_project="quota-proj", verbose=False)
        self._ts_data = ts_data

    def list_monitoring_timeseries(self, project_id: str, **kwargs):
        return self._ts_data.get(project_id, [])


class AuditGenaiApiKeysTest(unittest.TestCase):

    def test_restrictions_and_monitoring_correlation(self):
        proj_payg = gk.GenAIProjectInfo(
            project_id="p-payg",
            project_number="111",
            genai_enabled=True,
            billing_enabled="TRUE",
        )
        proj_free = gk.GenAIProjectInfo(
            project_id="p-free",
            project_number="222",
            genai_enabled=True,
            billing_enabled="FALSE",
        )

        scope1, _, ctype1, _ = gk.evaluate_key_restrictions({}, proj_payg, False)
        self.assertEqual(scope1, "UNRESTRICTED_ALL_APIS")
        self.assertEqual(ctype1, "OPEN_ANY_IP_OR_APP")

        scope_maps, _, _, _ = gk.evaluate_key_restrictions(
            {"apiTargets": [{"service": "maps-backend.googleapis.com"}]},
            proj_payg,
            False,
        )
        self.assertIsNone(scope_maps)

        records = [
            gk.ApiKeyRecord(
                project_id="p-payg",
                project_number="111",
                uid="uid-leaked-active",
                display_name="Leaked Key",
                create_time="2026-01-01T00:00:00Z",
                update_time="2026-01-01T00:00:00Z",
                api_scope_status="UNRESTRICTED_ALL_APIS",
                target_services=["*"],
                client_restriction_type="OPEN_ANY_IP_OR_APP",
                client_restriction_detail="None",
            ),
            gk.ApiKeyRecord(
                project_id="p-payg",
                project_number="111",
                uid="uid-open-idle",
                display_name="Open Idle",
                create_time="2026-02-01T00:00:00Z",
                update_time="2026-02-01T00:00:00Z",
                api_scope_status="EXPLICIT_GENAI_TARGET",
                target_services=["generativelanguage.googleapis.com"],
                client_restriction_type="OPEN_ANY_IP_OR_APP",
                client_restriction_detail="None",
            ),
            gk.ApiKeyRecord(
                project_id="p-free",
                project_number="222",
                uid="uid-free-tier",
                display_name="Free Tier Key",
                create_time="2026-03-01T00:00:00Z",
                update_time="2026-03-01T00:00:00Z",
                api_scope_status="EXPLICIT_GENAI_TARGET",
                target_services=["generativelanguage.googleapis.com"],
                client_restriction_type="OPEN_ANY_IP_OR_APP",
                client_restriction_detail="None",
            ),
        ]

        runner = FakeRunner({
            "p-payg": [{
                "resource": {
                    "labels": {
                        "credential_id": "apikey:uid-leaked-active",
                        "service": "generativelanguage.googleapis.com",
                        "method": "google.ai.generativelanguage.v1beta.GenerativeService.GenerateContent",
                    }
                },
                "metric": {"labels": {"response_code_class": "2xx"}},
                "points": [{"value": {"int64Value": "25400"}}],
            }]
        })

        tel = gk.enrich_api_keys_with_monitoring(
            runner,
            records,
            lookback_days=14,
            now=datetime(2026, 11, 14, tzinfo=timezone.utc),
        )
        findings = gk.build_api_key_findings(
            {"p-payg": proj_payg, "p-free": proj_free}, records, tel
        )

        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].key_uid, "uid-leaked-active")
        self.assertEqual(
            findings[0].risk_status, "P0_ACTIVE_API_KEY_DOING_INFERENCE"
        )
        self.assertEqual(findings[1].risk_status, "CRITICAL_PAYG_OPEN_KEY")
        self.assertEqual(findings[2].risk_status, "MEDIUM_FREE_TIER_KEY")

    def test_gtig_recon_and_validation_sweep_signals(self):
        ref_now = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        proj = gk.GenAIProjectInfo(
            project_id="p-mixer",
            project_number="333",
            genai_enabled=True,
            billing_enabled="TRUE",
        )
        records = [
            gk.ApiKeyRecord(
                project_id="p-mixer",
                project_number="333",
                uid="uid-sweep-recent",
                display_name="Sweep Key",
                create_time="2026-11-12T10:00:00Z",
                update_time="2026-11-12T10:00:00Z",
                api_scope_status="UNRESTRICTED_ALL_APIS",
                target_services=["*"],
                client_restriction_type="OPEN_ANY_IP_OR_APP",
                client_restriction_detail="None",
            ),
            gk.ApiKeyRecord(
                project_id="p-mixer",
                project_number="333",
                uid="uid-recon-only",
                display_name="Recon Key",
                create_time="2025-05-01T00:00:00Z",
                update_time="2025-05-01T00:00:00Z",
                api_scope_status="EXPLICIT_GENAI_TARGET",
                target_services=["generativelanguage.googleapis.com"],
                client_restriction_type="OPEN_ANY_IP_OR_APP",
                client_restriction_detail="None",
            ),
        ]

        runner = FakeRunner({
            "p-mixer": [
                {
                    "resource": {
                        "labels": {
                            "credential_id": "apikey:uid-sweep-recent",
                            "service": "generativelanguage.googleapis.com",
                            "method": "google.ai.generativelanguage.v1beta.GenerativeService.GenerateContent",
                        }
                    },
                    "metric": {"labels": {"response_code_class": "2xx"}},
                    "points": [{"value": {"int64Value": "2"}}],
                },
                {
                    "resource": {
                        "labels": {
                            "credential_id": "apikey:uid-recon-only",
                            "service": "generativelanguage.googleapis.com",
                            "method": "google.ai.generativelanguage.v1beta.ModelService.ListModels",
                        }
                    },
                    "metric": {"labels": {"response_code_class": "2xx"}},
                    "points": [{"value": {"int64Value": "6"}}],
                },
            ]
        })

        tel = gk.enrich_api_keys_with_monitoring(
            runner, records, lookback_days=14, now=ref_now
        )
        findings = gk.build_api_key_findings(
            {"p-mixer": proj}, records, tel, lookback_days=14, now=ref_now
        )
        by_uid = {f.key_uid: f for f in findings}

        self.assertEqual(
            by_uid["uid-sweep-recent"].inference_activity_status,
            "CONFIRMED_KEY_INFERENCE",
        )
        self.assertIn(
            "POSSIBLE_VALIDATION_SWEEP_1_TO_10_CALLS",
            by_uid["uid-sweep-recent"].gtig_threat_signals,
        )
        self.assertIn(
            "RECENT_API_KEY_CREATED_IN_WINDOW",
            by_uid["uid-sweep-recent"].gtig_threat_signals,
        )

        self.assertEqual(
            by_uid["uid-recon-only"].inference_activity_status,
            "RECON_SCOPING_DETECTED",
        )
        self.assertEqual(by_uid["uid-recon-only"].recon_calls_window, 6)
        self.assertIn(
            "TARGET_SCOPING_RECON(ListModels)",
            by_uid["uid-recon-only"].gtig_threat_signals,
        )


if __name__ == "__main__":
    unittest.main()
