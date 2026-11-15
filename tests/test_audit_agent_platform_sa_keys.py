#!/usr/bin/env python3
"""Testes unitários para audit_agent_platform_sa_keys.py."""

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import audit_agent_platform_sa_keys as audit  # noqa: E402

REF_NOW = datetime(2026, 11, 14, 8, 0, 0, tzinfo=timezone.utc)


class FakeGcloudRunner(audit.GcloudRunner):

    def __init__(self, handler, ts_handler=None):
        super().__init__(billing_project="secops-quota-proj", verbose=False)
        self._handler = handler
        self._ts_handler = ts_handler or (lambda *a, **kw: [])
        self.calls: list[list[str]] = []

    def run_json(self, args: list[str], timeout: int = 300):
        self.calls.append(args)
        return self._handler(args)

    def list_monitoring_timeseries(
        self,
        project_id: str,
        metric_filter: str,
        start_time_iso: str,
        end_time_iso: str,
        group_by_fields: list[str],
        **kwargs,
    ):
        return self._ts_handler(project_id, metric_filter, group_by_fields)


class AuditAgentPlatformSaKeysTest(unittest.TestCase):

    def test_cai_mode_with_zero_dataread_inference_verification(self):
        def handler(args: list[str]):
            joined = " ".join(args)
            if "--asset-types=cloudresourcemanager.googleapis.com/Project" in args:
                return [
                    {
                        "name": "//cloudresourcemanager.googleapis.com/projects/proj-vertex-prod",
                        "project": "projects/111111",
                        "folders": ["folders/200"],
                        "organization": "organizations/900",
                        "versionedResources": [{
                            "resource": {
                                "projectId": "proj-vertex-prod",
                                "projectNumber": "111111",
                            }
                        }],
                    },
                    {
                        "name": "//cloudresourcemanager.googleapis.com/projects/proj-cicd",
                        "project": "projects/222222",
                        "folders": ["folders/300"],
                        "organization": "organizations/900",
                        "versionedResources": [{
                            "resource": {
                                "projectId": "proj-cicd",
                                "projectNumber": "222222",
                            }
                        }],
                    },
                ]

            if "--asset-types=serviceusage.googleapis.com/Service" in args:
                return [{
                    "name": "//serviceusage.googleapis.com/projects/111111/services/aiplatform.googleapis.com",
                    "project": "projects/111111",
                    "state": "ENABLED",
                }]

            if "--asset-types=iam.googleapis.com/ServiceAccount" in args:
                return [
                    {
                        "name": "//iam.googleapis.com/projects/proj-cicd/serviceAccounts/109999",
                        "versionedResources": [{
                            "resource": {
                                "email": "ci-runner@proj-cicd.iam.gserviceaccount.com",
                                "uniqueId": "109999",
                            }
                        }],
                    },
                    {
                        "name": "//iam.googleapis.com/projects/proj-vertex-prod/serviceAccounts/105555",
                        "versionedResources": [{
                            "resource": {
                                "email": "vertex-runtime@proj-vertex-prod.iam.gserviceaccount.com",
                                "uniqueId": "105555",
                            }
                        }],
                    },
                ]

            if "--asset-types=iam.googleapis.com/ServiceAccountKey" in args:
                return [
                    {
                        "name": "//iam.googleapis.com/projects/proj-vertex-prod/serviceAccounts/100001/keys/leakedkey999999",
                        "versionedResources": [{
                            "resource": {
                                "name": "projects/proj-vertex-prod/serviceAccounts/111111-compute@developer.gserviceaccount.com/keys/leakedkey999999",
                                "keyType": "USER_MANAGED",
                                "keyOrigin": "GOOGLE_PROVIDED",
                                "validAfterTime": "2024-01-10T00:00:00Z",
                                "validBeforeTime": "9999-12-31T23:59:59Z",
                            }
                        }],
                    },
                    {
                        "name": "//iam.googleapis.com/projects/proj-vertex-prod/serviceAccounts/100001/keys/idlekey888888",
                        "versionedResources": [{
                            "resource": {
                                "name": "projects/proj-vertex-prod/serviceAccounts/111111-compute@developer.gserviceaccount.com/keys/idlekey888888",
                                "keyType": "USER_MANAGED",
                                "keyOrigin": "GOOGLE_PROVIDED",
                                "validAfterTime": "2023-06-01T00:00:00Z",
                                "validBeforeTime": "9999-12-31T23:59:59Z",
                            }
                        }],
                    },
                    {
                        "name": "//iam.googleapis.com/projects/proj-cicd/serviceAccounts/109999/keys/impkey222222",
                        "additionalAttributes": {"keyType": "USER_MANAGED"},
                        "createTime": "2025-08-01T00:00:00Z",
                    },
                ]

            if "analyze-iam-policy" in joined:
                return {
                    "fullyExplored": True,
                    "mainAnalysis": {
                        "fullyExplored": True,
                        "analysisResults": [{
                            "attachedResourceFullName": "//cloudresourcemanager.googleapis.com/projects/proj-vertex-prod",
                            "iamBinding": {"role": "roles/editor"},
                            "accessControlLists": [{
                                "resources": [{
                                    "fullResourceName": "//cloudresourcemanager.googleapis.com/projects/proj-vertex-prod"
                                }],
                                "accesses": [{"permission": "aiplatform.endpoints.predict"}],
                            }],
                            "identityList": {
                                "identities": [
                                    {"name": "serviceAccount:111111-compute@developer.gserviceaccount.com"},
                                    {"name": "serviceAccount:vertex-runtime@proj-vertex-prod.iam.gserviceaccount.com"},
                                ]
                            },
                        }],
                    },
                    "serviceAccountImpersonationAnalysis": [{
                        "fullyExplored": True,
                        "analysisQuery": {
                            "resourceSelector": {
                                "fullResourceName": "//iam.googleapis.com/projects/proj-vertex-prod/serviceAccounts/vertex-runtime@proj-vertex-prod.iam.gserviceaccount.com"
                            }
                        },
                        "analysisResults": [{
                            "attachedResourceFullName": "//iam.googleapis.com/projects/proj-vertex-prod/serviceAccounts/vertex-runtime@proj-vertex-prod.iam.gserviceaccount.com",
                            "iamBinding": {"role": "roles/iam.serviceAccountTokenCreator"},
                            "identityList": {
                                "identities": [{
                                    "name": "serviceAccount:ci-runner@proj-cicd.iam.gserviceaccount.com"
                                }]
                            },
                        }],
                    }],
                }

            if "policy-intelligence query-activity" in joined:
                return []
            if args[:3] == ["recommender", "insights", "list"]:
                return []
            raise AssertionError(f"Unexpected command: {args}")

        def ts_handler(project_id: str, metric_filter: str, group_by: list[str]):
            if "serviceruntime.googleapis.com/api/request_count" in metric_filter:
                if project_id == "proj-vertex-prod":
                    return [
                        {
                            "resource": {
                                "labels": {
                                    "credential_id": "serviceaccount:100001",
                                    "method": "google.cloud.aiplatform.v1.PredictionService.StreamGenerateContent",
                                }
                            },
                            "metric": {"labels": {"response_code_class": "2xx"}},
                            "points": [{"value": {"int64Value": "185000"}}],
                        },
                        {
                            "resource": {
                                "labels": {
                                    "credential_id": "serviceaccount:105555",
                                    "method": "google.cloud.aiplatform.v1.PredictionService.RawPredict",
                                }
                            },
                            "metric": {"labels": {"response_code_class": "2xx"}},
                            "points": [{"value": {"int64Value": "9500"}}],
                        },
                    ]
                return []

            if "iam.googleapis.com/service_account/key/authn_events_count" in metric_filter:
                if project_id == "proj-vertex-prod":
                    return [{
                        "resource": {"labels": {"unique_id": "100001"}},
                        "metric": {"labels": {"key_id": "leakedkey999999"}},
                        "points": [{"value": {"int64Value": "420"}}],
                    }]
                if project_id == "proj-cicd":
                    return [{
                        "resource": {"labels": {"unique_id": "109999"}},
                        "metric": {"labels": {"key_id": "impkey222222"}},
                        "points": [{"value": {"int64Value": "15"}}],
                    }]
                return []
            return []

        runner = FakeGcloudRunner(handler, ts_handler)
        p_map, k_map, grants, scanned, email_uid = audit.run_cai_discovery(
            runner, scope="organizations/900", include_impersonation=True
        )
        findings = audit.build_findings(
            runner=runner,
            id_to_proj=p_map,
            sa_to_keys=k_map,
            grants=grants,
            scanned_project_ids=scanned,
            email_to_unique_id=email_uid,
            lookback_days=14,
            now=REF_NOW,
        )

        by_key = {f.key_id: f for f in findings}
        self.assertEqual(
            by_key["leakedkey999999"].inference_activity_status,
            "CONFIRMED_KEY_INFERENCE",
        )
        self.assertEqual(
            by_key["impkey222222"].inference_activity_status,
            "CONFIRMED_KEY_INFERENCE",
        )
        self.assertEqual(
            by_key["idlekey888888"].inference_activity_status,
            "SA_INFERENCE_KEY_IDLE",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_file = str(Path(tmpdir) / "out.csv")
            json_file = str(Path(tmpdir) / "out.json")
            audit.write_reports(findings, csv_file, json_file)
            with open(csv_file, encoding="utf-8") as fp:
                self.assertEqual(len(list(csv.DictReader(fp))), 3)
            with open(json_file, encoding="utf-8") as fp:
                self.assertEqual(
                    json.load(fp)["p0_active_keys_doing_inference"], 2
                )

    def test_cai_fallback_on_policy_analyzer_quota_exhausted(self):
        def handler(args: list[str]):
            joined = " ".join(args)
            if "--asset-types=cloudresourcemanager.googleapis.com/Project" in args:
                return [{
                    "name": "//cloudresourcemanager.googleapis.com/projects/p-vtx",
                    "project": "projects/777",
                    "folders": ["folders/888"],
                    "organization": "organizations/900",
                    "versionedResources": [{
                        "resource": {"projectId": "p-vtx", "projectNumber": "777"}
                    }],
                }]
            if "--asset-types=serviceusage.googleapis.com/Service" in args:
                return [{
                    "name": "//serviceusage.googleapis.com/projects/777/services/aiplatform.googleapis.com",
                    "project": "projects/777",
                    "state": "ENABLED",
                }]
            if "--asset-types=iam.googleapis.com/ServiceAccount" in args:
                return []
            if "--asset-types=iam.googleapis.com/ServiceAccountKey" in args:
                return [{
                    "name": "//iam.googleapis.com/projects/p-vtx/serviceAccounts/10777/keys/quotafallbackkey",
                    "versionedResources": [{
                        "resource": {
                            "name": "projects/p-vtx/serviceAccounts/sa@p-vtx.iam.gserviceaccount.com/keys/quotafallbackkey",
                            "keyType": "USER_MANAGED",
                            "validBeforeTime": "9999-12-31T23:59:59Z",
                        }
                    }],
                }]
            if "analyze-iam-policy" in joined:
                raise audit.GcloudError("RESOURCE_EXHAUSTED: 20 free queries/day")
            if "search-all-iam-policies" in joined:
                return [{
                    "resource": "//cloudresourcemanager.googleapis.com/folders/888",
                    "policy": {
                        "bindings": [{
                            "role": "roles/aiplatform.user",
                            "members": ["serviceAccount:sa@p-vtx.iam.gserviceaccount.com"],
                        }]
                    },
                }]
            return []

        runner = FakeGcloudRunner(handler)
        p_map, k_map, grants, scanned, email_uid = audit.run_cai_discovery(
            runner, scope="organizations/900"
        )
        findings = audit.build_findings(
            runner=runner,
            id_to_proj=p_map,
            sa_to_keys=k_map,
            grants=grants,
            scanned_project_ids=scanned,
            email_to_unique_id=email_uid,
            check_last_used=False,
            check_inference_usage=False,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].key_id, "quotafallbackkey")


if __name__ == "__main__":
    unittest.main()
