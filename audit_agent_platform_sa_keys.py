#!/usr/bin/env python3
# Copyright 2026 Marcos Cotomacio
# Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
#
# AVISO: Ferramenta comunitária não oficial ("as-is"), sem garantia ou suporte
# oficial do Google Cloud. Criada para triagem rápida (somente leitura) de
# credenciais estáticas em incidentes de LLMJacking.
"""Auditoria de Service Account Keys com permissão e USO REAL de inferência no Gemini Enterprise Agent Platform (antigo Vertex AI).

Identifica chaves estáticas gerenciadas pelo usuário (USER_MANAGED) associadas
a Service Accounts que possuem permissão efetiva de inferência no Gemini
Enterprise Agent Platform / Vertex AI (`aiplatform.endpoints.predict`,
`aiplatform.batchPredictionJobs.create`) em projetos com a API
`aiplatform.googleapis.com` habilitada — e comprova quais chaves estão DE FATO
realizando chamadas de inferência **SEM precisar habilitar logs DATA_READ**.

Como a comprovação de chamadas de inferência funciona sem DATA_READ:
  1. Cloud Monitoring (`serviceruntime.googleapis.com/api/request_count` em
     `consumed_api` — gratuito e ativo por padrão, retenção de 6 semanas):
     registra o volume exato de chamadas de inferência (`GenerateContent`,
     `StreamGenerateContent`, `RawPredict`, `StreamRawPredict`, `Predict`,
     `CreateBatchPredictionJob`, etc.) por `credential_id`
     (`serviceaccount:<SA_UNIQUE_ID>`).
  2. Cloud Monitoring (`iam.googleapis.com/service_account/key/authn_events_count`
     em `iam_service_account` — gratuito e ativo por padrão): contabiliza
     quantas autenticações cada `key_id` específica daquela SA realizou na
     janela analisada, diferenciando chaves vazadas ativas de chaves dormentes
     ou uso legítimo via Workload Identity na mesma SA.
  3. Policy Analyzer (`serviceAccountKeyLastAuthentication`) + IAM Policy
     Insights (`google.iam.policy.Insight` -> `exercisedPermissions`, janela de
     90 dias): complementam com o timestamp exato da última autenticação da
     chave e histórico de 90 dias da permissão `aiplatform.endpoints.predict`.

Requisitos: Python 3.8+ (apenas biblioteca padrão) e Google Cloud CLI (`gcloud`).
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import json
import re
import shutil
import subprocess
import sys
import threading
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

VERTEX_SERVICE_NAME = "aiplatform.googleapis.com"
GENAI_SERVICE_NAME = "generativelanguage.googleapis.com"

INFERENCE_PERMISSIONS = (
    "aiplatform.endpoints.predict",
    "aiplatform.batchPredictionJobs.create",
)

# Métodos RPC de inferência do Vertex AI registrados em `serviceruntime` (`consumed_api`).
# Exclui métodos administrativos de leitura como GetEndpoint, ListModels, ListLocations.
VERTEX_INFERENCE_METHOD_SUFFIXES = (
    "generatecontent",
    "streamgeneratecontent",
    "asyncgeneratecontent",
    "bidigeneratecontent",
    "predict",
    "rawpredict",
    "streamrawpredict",
    "directpredict",
    "directrawpredict",
    "serverstreamingpredict",
    "predictlongrunning",
    "explain",
    "createbatchpredictionjob",
    "chatcompletions",
    "embedcontent",
    "generatevideo",
)

KNOWN_INFERENCE_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/aiplatform.user",
    "roles/aiplatform.admin",
    "roles/aiplatform.serviceAgent",
    "roles/aiplatform.onlinePredictionServiceAgent",
    "roles/aiplatform.customCodeServiceAgent",
    "roles/aiplatform.extensionExecutionServiceAgent",
    "roles/aiplatform.rapidevalServiceAgent",
    "roles/aiplatform.reasoningEngineServiceAgent",
})

KNOWN_NON_INFERENCE_ROLES = frozenset({
    "roles/viewer",
    "roles/browser",
    "roles/aiplatform.viewer",
    "roles/logging.viewer",
    "roles/logging.admin",
    "roles/monitoring.viewer",
    "roles/monitoring.metricWriter",
    "roles/storage.objectViewer",
    "roles/storage.objectAdmin",
    "roles/bigquery.dataViewer",
    "roles/bigquery.user",
    "roles/iam.securityReviewer",
})

# Domínios de Service Agents internos do Google (não possuem chaves USER_MANAGED de clientes).
# Nota: *-compute@developer.gserviceaccount.com e *@appspot.gserviceaccount.com
# NÃO são filtrados pois pertencem ao cliente e são alvos frequentes de vazamento.
GOOGLE_MANAGED_SA_PATTERNS = (
    re.compile(r"@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com$"),
    re.compile(r"@cloudservices\.gserviceaccount\.com$"),
    re.compile(r"@cloudbuild\.gserviceaccount\.com$"),
    re.compile(r"@container-engine-robot\.iam\.gserviceaccount\.com$"),
    re.compile(r"@serverless-robot-prod\.iam\.gserviceaccount\.com$"),
    re.compile(r"@compute-system\.iam\.gserviceaccount\.com$"),
    re.compile(r"@appspot-prod\.iam\.gserviceaccount\.com$"),
    re.compile(r"@dataflow-service-producer-prod\.iam\.gserviceaccount\.com$"),
    re.compile(r"@dataproc-accounts\.iam\.gserviceaccount\.com$"),
    re.compile(r"@gcf-admin-robot\.iam\.gserviceaccount\.com$"),
    re.compile(r"@dlp-api\.iam\.gserviceaccount\.com$"),
    re.compile(r"@[a-z0-9.-]*\.google\.com\.iam\.gserviceaccount\.com$"),
    re.compile(r"\.google\.com@appspot\.gserviceaccount\.com$"),
    re.compile(r"@gs-project-accounts\.iam\.gserviceaccount\.com$"),
    re.compile(r"@bigquery-encryption\.iam\.gserviceaccount\.com$"),
    re.compile(r"@cloudcomposer-accounts\.iam\.gserviceaccount\.com$"),
    re.compile(r"@firebase-rules\.iam\.gserviceaccount\.com$"),
    re.compile(r"@security-center-api\.iam\.gserviceaccount\.com$"),
    re.compile(r"@remotebuildexecution\.iam\.gserviceaccount\.com$"),
)

SA_KEY_RESOURCE_RE = re.compile(
    r"projects/([^/]+)/serviceAccounts/([^/]+)/keys/([^/]+)"
)
PROJECT_RESOURCE_RE = re.compile(
    r"//cloudresourcemanager\.[^/]+/projects/([^/]+)$"
)
FOLDER_RESOURCE_RE = re.compile(
    r"//cloudresourcemanager\.[^/]+/folders/([^/]+)$"
)
ORG_RESOURCE_RE = re.compile(
    r"//cloudresourcemanager\.[^/]+/organizations/([^/]+)$"
)
CHILD_PROJECT_RESOURCE_RE = re.compile(r"//[^/]+/projects/([^/]+)/")


@dataclass
class ProjectInfo:
    project_id: str
    project_number: str
    folders: list[str] = field(default_factory=list)
    organization: str = ""
    vertex_enabled: bool = False
    genai_enabled: bool = False


@dataclass
class SAKeyInfo:
    sa_email: str
    sa_project_id: str
    key_id: str
    key_type: str
    key_origin: str
    key_algorithm: str
    valid_after_time: str
    valid_before_time: str
    disabled: bool
    status: str  # ACTIVE, DISABLED, EXPIRED
    sa_unique_id: str = ""
    last_authenticated_time: str = ""
    key_authn_events: int = 0


@dataclass
class AccessGrant:
    sa_email: str
    vertex_project_id: str
    role: str
    permissions: list[str]
    attached_resource: str
    access_path: str  # DIRECT_OR_GROUP ou IMPERSONATION-><target_sa>
    condition_expression: str = ""


@dataclass
class SAInferenceTelemetry:
    """Telemetria agregada de chamadas reais ao Vertex AI por Service Account."""

    total_calls: int = 0
    ok_2xx_calls: int = 0
    error_calls: int = 0
    methods: set[str] = field(default_factory=set)
    active_vertex_projects: set[str] = field(default_factory=set)
    iam_insight_exercised_90d: bool = False


@dataclass
class AuditFinding:
    risk_status: str
    inference_activity_status: str
    sa_email: str
    sa_unique_id: str
    sa_home_project: str
    key_id: str
    key_status: str
    key_origin: str
    key_created_at: str
    key_expires_at: str
    last_authenticated_time: str
    key_authn_events_window: int
    sa_vertex_inference_calls_window: int
    sa_vertex_2xx_calls_window: int
    sa_vertex_error_calls_window: int
    sa_vertex_methods_called: list[str]
    active_inference_projects: list[str]
    iam_exercised_predict_90d: bool
    vertex_projects_permitted: list[str]
    access_paths: list[str]
    roles: list[str]
    permissions: list[str]
    binding_resources: list[str]
    conditions: list[str]
    disable_key_command: str


class GcloudError(RuntimeError):
    """Erro ao executar comando gcloud ou API GCP."""


class GcloudRunner:
    """Executor centralizado de comandos `gcloud` e REST Cloud Monitoring v3."""

    def __init__(
        self, billing_project: str | None = None, verbose: bool = False
    ) -> None:
        self.billing_project = billing_project
        self.verbose = verbose
        self.gcloud_bin = shutil.which("gcloud") or "gcloud"
        self._token_lock = threading.Lock()
        self._cached_token: str | None = None

    def run_json(self, args: list[str], timeout: int = 300) -> Any:
        cmd = [self.gcloud_bin, *args, "--quiet", "--format=json"]
        if self.billing_project and not any(
            a.startswith("--billing-project") for a in args
        ):
            cmd.append(f"--billing-project={self.billing_project}")

        if self.verbose:
            print(f"[DEBUG] Executando: {' '.join(cmd)}", file=sys.stderr)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if (
            proc.returncode != 0
            and self.billing_project
            and "SERVICE_DISABLED" in (proc.stderr or "")
        ):
            cmd_no_bp = [
                c for c in cmd if not c.startswith("--billing-project=")
            ]
            proc = subprocess.run(
                cmd_no_bp,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            raise GcloudError(
                f"Falha em `gcloud {' '.join(args[:3])}...`: {stderr}"
            )

        stdout = (proc.stdout or "").strip()
        if not stdout:
            return []
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise GcloudError(
                f"Saída JSON inválida de `gcloud {' '.join(args[:3])}`: {exc}"
            ) from exc

    def get_access_token(self) -> str:
        with self._token_lock:
            if self._cached_token:
                return self._cached_token
            proc = subprocess.run(
                [self.gcloud_bin, "auth", "print-access-token", "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                raise GcloudError(
                    f"Não foi possível obter access token via `gcloud auth print-access-token`: {(proc.stderr or '').strip()}"
                )
            self._cached_token = proc.stdout.strip()
            return self._cached_token

    def list_monitoring_timeseries(
        self,
        project_id: str,
        metric_filter: str,
        start_time_iso: str,
        end_time_iso: str,
        group_by_fields: list[str],
        alignment_period: str = "86400s",
        per_series_aligner: str = "ALIGN_SUM",
        cross_series_reducer: str = "REDUCE_SUM",
        timeout: int = 90,
    ) -> list[dict[str, Any]]:
        """Consulta `monitoring.googleapis.com/v3/projects/{project}/timeSeries`."""
        token = self.get_access_token()
        base_url = (
            f"https://monitoring.googleapis.com/v3/projects/"
            f"{urllib.parse.quote(project_id, safe='')}/timeSeries"
        )
        all_series: list[dict[str, Any]] = []
        page_token = ""

        while True:
            params: dict[str, Any] = {
                "filter": metric_filter,
                "interval.startTime": start_time_iso,
                "interval.endTime": end_time_iso,
                "aggregation.alignmentPeriod": alignment_period,
                "aggregation.perSeriesAligner": per_series_aligner,
                "aggregation.crossSeriesReducer": cross_series_reducer,
                "aggregation.groupByFields": group_by_fields,
                "view": "FULL",
                "pageSize": "500",
            }
            if page_token:
                params["pageToken"] = page_token

            url = f"{base_url}?{urllib.parse.urlencode(params, doseq=True)}"
            if self.verbose:
                print(f"[DEBUG] GET {url}", file=sys.stderr)

            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
            if self.billing_project:
                headers["X-Goog-User-Project"] = self.billing_project

            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                raise GcloudError(
                    f"Cloud Monitoring HTTP {exc.code} em `{project_id}`: {err_body[:300]}"
                ) from exc
            except urllib.error.URLError as exc:
                raise GcloudError(
                    f"Erro de rede ao consultar Cloud Monitoring em `{project_id}`: {exc}"
                ) from exc

            all_series.extend(payload.get("timeSeries") or [])
            page_token = payload.get("nextPageToken") or ""
            if not page_token:
                break

        return all_series


def is_google_managed_agent(sa_email: str) -> bool:
    return any(p.search(sa_email) for p in GOOGLE_MANAGED_SA_PATTERNS)


def is_vertex_inference_method(method_name: str) -> bool:
    if not method_name:
        return False
    short = method_name.rsplit(".", 1)[-1].rsplit("/", 1)[-1].lower()
    return short in VERTEX_INFERENCE_METHOD_SUFFIXES


def short_method_name(method_name: str) -> str:
    return method_name.rsplit(".", 1)[-1].rsplit("/", 1)[-1]


def parse_iso_timestamp(ts: str) -> datetime | None:
    if not ts:
        return None
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def classify_key_status(
    disabled: bool, valid_before_time: str, now: datetime | None = None
) -> str:
    if disabled:
        return "DISABLED"
    ref_now = now or datetime.now(timezone.utc)
    exp = parse_iso_timestamp(valid_before_time)
    if exp is not None and exp <= ref_now:
        return "EXPIRED"
    return "ACTIVE"


def infer_sa_home_project(
    sa_email: str, number_to_id: dict[str, str]
) -> str:
    if sa_email.endswith(".iam.gserviceaccount.com"):
        prefix = sa_email[: -len(".iam.gserviceaccount.com")]
        if "@" in prefix:
            return prefix.split("@", 1)[1]
    if sa_email.endswith("@appspot.gserviceaccount.com"):
        return sa_email[: -len("@appspot.gserviceaccount.com")]
    m = re.match(r"^(\d+)-compute@developer\.gserviceaccount\.com$", sa_email)
    if m:
        proj_num = m.group(1)
        return number_to_id.get(proj_num, f"project-number:{proj_num}")
    return ""


def parse_cai_sa_key(
    item: dict[str, Any],
    unique_id_to_email: dict[str, str],
    email_to_unique_id: dict[str, str],
    now: datetime | None = None,
) -> SAKeyInfo | None:
    """Extrai metadados de `iam.googleapis.com/ServiceAccountKey` do CAI."""
    versioned = item.get("versionedResources") or []
    res = versioned[0].get("resource", {}) if versioned else {}
    add_attrs = item.get("additionalAttributes") or {}

    key_type = res.get("keyType") or add_attrs.get("keyType") or ""
    if key_type and key_type != "USER_MANAGED":
        return None

    candidates = [
        res.get("name", ""),
        item.get("displayName", ""),
        item.get("name", ""),
    ]

    sa_project_id = ""
    sa_email = ""
    sa_unique_id = str(add_attrs.get("uniqueId") or "")
    key_id = ""

    for cand in candidates:
        m = SA_KEY_RESOURCE_RE.search(cand)
        if m:
            proj, sa_ident, kid = m.group(1), m.group(2), m.group(3)
            if not sa_project_id:
                sa_project_id = proj
            if not key_id:
                key_id = kid
            if "@" in sa_ident and not sa_email:
                sa_email = sa_ident
            elif sa_ident.isdigit() and not sa_unique_id:
                sa_unique_id = sa_ident

    if not sa_email:
        attr_email = add_attrs.get("email", "")
        if "@" in str(attr_email):
            sa_email = str(attr_email)

    if not sa_email:
        parent_name = item.get("parentFullResourceName", "")
        pm = re.search(r"/serviceAccounts/([^/]+)$", parent_name)
        if pm and "@" in pm.group(1):
            sa_email = pm.group(1)
        elif pm and pm.group(1) in unique_id_to_email:
            if not sa_unique_id and pm.group(1).isdigit():
                sa_unique_id = pm.group(1)
            sa_email = unique_id_to_email[pm.group(1)]

    if not sa_email and sa_unique_id in unique_id_to_email:
        sa_email = unique_id_to_email[sa_unique_id]

    if not sa_unique_id and sa_email in email_to_unique_id:
        sa_unique_id = email_to_unique_id[sa_email]

    if not key_type or not sa_email or not key_id:
        return None

    disabled = bool(res.get("disabled", False))
    valid_after = res.get("validAfterTime") or item.get("createTime") or ""
    valid_before = res.get("validBeforeTime") or ""
    key_origin = res.get("keyOrigin") or add_attrs.get("keyOrigin") or "UNKNOWN"
    key_alg = res.get("keyAlgorithm") or add_attrs.get("keyAlgorithm") or ""
    status = classify_key_status(disabled, valid_before, now=now)

    return SAKeyInfo(
        sa_email=sa_email,
        sa_project_id=sa_project_id,
        key_id=key_id,
        key_type=key_type,
        key_origin=key_origin,
        key_algorithm=key_alg,
        valid_after_time=valid_after,
        valid_before_time=valid_before,
        disabled=disabled,
        status=status,
        sa_unique_id=sa_unique_id,
    )


def match_resource_to_vertex_projects(
    resource_full_name: str,
    vertex_projects: list[ProjectInfo],
    id_to_proj: dict[str, ProjectInfo],
    num_to_proj: dict[str, ProjectInfo],
) -> list[str]:
    m_org = ORG_RESOURCE_RE.match(resource_full_name)
    if m_org:
        org_tag = f"organizations/{m_org.group(1)}"
        return [
            p.project_id
            for p in vertex_projects
            if p.organization == org_tag or not p.organization
        ]

    m_folder = FOLDER_RESOURCE_RE.match(resource_full_name)
    if m_folder:
        folder_tag = f"folders/{m_folder.group(1)}"
        return [
            p.project_id for p in vertex_projects if folder_tag in p.folders
        ]

    m_proj = PROJECT_RESOURCE_RE.match(resource_full_name)
    if m_proj:
        ident = m_proj.group(1)
        proj = id_to_proj.get(ident) or num_to_proj.get(ident)
        return [proj.project_id] if proj and proj.vertex_enabled else []

    m_child = CHILD_PROJECT_RESOURCE_RE.match(resource_full_name)
    if m_child:
        ident = m_child.group(1)
        proj = id_to_proj.get(ident) or num_to_proj.get(ident)
        return [proj.project_id] if proj and proj.vertex_enabled else []

    return []


def extract_grants_from_cai_analysis(
    analysis_response: dict[str, Any] | list[Any],
    vertex_projects: list[ProjectInfo],
    id_to_proj: dict[str, ProjectInfo],
    num_to_proj: dict[str, ProjectInfo],
) -> tuple[list[AccessGrant], bool]:
    if isinstance(analysis_response, list):
        analysis_response = analysis_response[0] if analysis_response else {}

    fully_explored = bool(analysis_response.get("fullyExplored", True))
    main_analysis = analysis_response.get("mainAnalysis") or {}
    if not main_analysis.get("fullyExplored", True):
        fully_explored = False

    grants: list[AccessGrant] = []
    target_sa_to_projects: dict[str, set[str]] = {}
    target_sa_to_perms: dict[str, set[str]] = {}

    for res in main_analysis.get("analysisResults") or []:
        attached = res.get("attachedResourceFullName", "")
        binding = res.get("iamBinding") or {}
        role = binding.get("role", "")
        cond_expr = (binding.get("condition") or {}).get("expression", "")

        acls = res.get("accessControlLists") or []
        perms: set[str] = set()
        affected_projects: set[str] = set(
            match_resource_to_vertex_projects(
                attached, vertex_projects, id_to_proj, num_to_proj
            )
        )

        all_false = bool(acls)
        for acl in acls:
            cond_eval = (acl.get("conditionEvaluation") or {}).get(
                "evaluationValue", ""
            )
            if cond_eval != "FALSE":
                all_false = False
            for acc in acl.get("accesses") or []:
                p = acc.get("permission") or acc.get("permissions")
                if isinstance(p, str) and p:
                    perms.add(p)
                elif isinstance(p, list):
                    perms.update(x for x in p if x)
                if not role and acc.get("role"):
                    role = acc["role"]
            for r_obj in acl.get("resources") or []:
                r_name = r_obj.get("fullResourceName", "")
                affected_projects.update(
                    match_resource_to_vertex_projects(
                        r_name, vertex_projects, id_to_proj, num_to_proj
                    )
                )

        if all_false or not affected_projects:
            continue

        perm_list = sorted(perms) if perms else list(INFERENCE_PERMISSIONS)
        identities = (res.get("identityList") or {}).get("identities") or []

        for ident in identities:
            name = ident.get("name", "")
            if name.startswith("deleted:"):
                continue
            if name in ("allUsers", "allAuthenticatedUsers"):
                print(
                    f"[ALERTA CRÍTICO] Acesso público (`{name}`) detectado com permissão de inferência em {sorted(affected_projects)} ({attached})!",
                    file=sys.stderr,
                )
                continue
            if name.startswith("serviceAccount:"):
                sa_email = name.split(":", 1)[1]
                target_sa_to_projects.setdefault(sa_email, set()).update(
                    affected_projects
                )
                target_sa_to_perms.setdefault(sa_email, set()).update(perm_list)
                for v_proj in sorted(affected_projects):
                    grants.append(
                        AccessGrant(
                            sa_email=sa_email,
                            vertex_project_id=v_proj,
                            role=role,
                            permissions=perm_list,
                            attached_resource=attached,
                            access_path="DIRECT_OR_GROUP",
                            condition_expression=cond_expr,
                        )
                    )

    for imp_analysis in (
        analysis_response.get("serviceAccountImpersonationAnalysis") or []
    ):
        if not imp_analysis.get("fullyExplored", True):
            fully_explored = False
        query_res = (
            (imp_analysis.get("analysisQuery") or {})
            .get("resourceSelector", {})
            .get("fullResourceName", "")
        )
        m_target = re.search(r"/serviceAccounts/([^/]+)$", query_res)
        target_sa = m_target.group(1) if m_target else ""
        inherited_projs = target_sa_to_projects.get(target_sa, set())
        inherited_perms = sorted(
            target_sa_to_perms.get(target_sa, set(INFERENCE_PERMISSIONS))
        )
        if not inherited_projs:
            continue

        for res in imp_analysis.get("analysisResults") or []:
            attached = res.get("attachedResourceFullName", "")
            binding = res.get("iamBinding") or {}
            role = binding.get("role", "")
            cond_expr = (binding.get("condition") or {}).get("expression", "")
            identities = (res.get("identityList") or {}).get("identities") or []
            for ident in identities:
                name = ident.get("name", "")
                if name.startswith("deleted:") or not name.startswith(
                    "serviceAccount:"
                ):
                    continue
                caller_sa = name.split(":", 1)[1]
                if caller_sa == target_sa:
                    continue
                for v_proj in sorted(inherited_projs):
                    grants.append(
                        AccessGrant(
                            sa_email=caller_sa,
                            vertex_project_id=v_proj,
                            role=role,
                            permissions=inherited_perms,
                            attached_resource=attached,
                            access_path=f"IMPERSONATION->{target_sa}",
                            condition_expression=cond_expr,
                        )
                    )

    return grants, fully_explored


def run_cai_discovery(
    runner: GcloudRunner,
    scope: str,
    include_impersonation: bool = False,
    include_genai_api: bool = False,
) -> tuple[
    dict[str, ProjectInfo],
    dict[str, list[SAKeyInfo]],
    list[AccessGrant],
    set[str],
    dict[str, str],
]:
    """Executa descoberta completa via Cloud Asset Inventory em um escopo."""
    scope_type, scope_id = scope.split("/", 1)
    analyzer_scope_flag = {
        "organizations": f"--organization={scope_id}",
        "folders": f"--folder={scope_id}",
        "projects": f"--project={scope_id}",
    }[scope_type]

    print(
        f"[1/4] Buscando projetos ativos em `{scope}` via Cloud Asset Inventory...",
        file=sys.stderr,
    )
    raw_projects = runner.run_json([
        "asset",
        "search-all-resources",
        f"--scope={scope}",
        "--asset-types=cloudresourcemanager.googleapis.com/Project",
        "--query=state:ACTIVE",
        "--page-size=500",
        "--read-mask=*",
    ])

    id_to_proj: dict[str, ProjectInfo] = {}
    num_to_proj: dict[str, ProjectInfo] = {}
    scanned_project_ids: set[str] = set()

    for item in raw_projects:
        versioned = item.get("versionedResources") or []
        res = versioned[0].get("resource", {}) if versioned else {}
        add_attrs = item.get("additionalAttributes") or {}

        proj_id = (
            res.get("projectId")
            or add_attrs.get("projectId")
            or item.get("name", "").rsplit("/", 1)[-1]
        )
        proj_num_raw = str(
            res.get("projectNumber")
            or item.get("project", "").replace("projects/", "")
        )
        if not proj_id:
            continue
        p_info = ProjectInfo(
            project_id=proj_id,
            project_number=proj_num_raw,
            folders=list(item.get("folders") or []),
            organization=item.get("organization", ""),
        )
        id_to_proj[proj_id] = p_info
        scanned_project_ids.add(proj_id)
        if proj_num_raw:
            num_to_proj[proj_num_raw] = p_info

    if (
        scope_type == "projects"
        and scope_id not in id_to_proj
        and scope_id not in num_to_proj
    ):
        proj_desc = runner.run_json(["projects", "describe", scope_id])
        p_id = proj_desc["projectId"]
        p_num = str(proj_desc["projectNumber"])
        p_info = ProjectInfo(project_id=p_id, project_number=p_num)
        id_to_proj[p_id] = p_info
        num_to_proj[p_num] = p_info
        scanned_project_ids.add(p_id)

    service_query = f"name:{VERTEX_SERVICE_NAME} AND state:ENABLED"
    if include_genai_api:
        service_query = (
            f"(name:{VERTEX_SERVICE_NAME} OR name:{GENAI_SERVICE_NAME}) "
            "AND state:ENABLED"
        )

    print(
        f"[2/4] Identificando projetos com Gemini Enterprise Agent Platform / Vertex AI (`{VERTEX_SERVICE_NAME}`) habilitado...",
        file=sys.stderr,
    )
    raw_services = runner.run_json([
        "asset",
        "search-all-resources",
        f"--scope={scope}",
        "--asset-types=serviceusage.googleapis.com/Service",
        f"--query={service_query}",
        "--page-size=500",
    ])

    for svc in raw_services:
        proj_ref = svc.get("project", "").replace("projects/", "")
        svc_name = svc.get("name", "")
        p_info = num_to_proj.get(proj_ref) or id_to_proj.get(proj_ref)
        if not p_info:
            continue
        if svc_name.endswith(f"/{VERTEX_SERVICE_NAME}"):
            p_info.vertex_enabled = True
        if include_genai_api and svc_name.endswith(f"/{GENAI_SERVICE_NAME}"):
            p_info.genai_enabled = True
            p_info.vertex_enabled = True

    vertex_projects = [p for p in id_to_proj.values() if p.vertex_enabled]
    print(
        f"      -> {len(vertex_projects)} de {len(id_to_proj)} projeto(s) ativo(s) possuem Agent Platform (`{VERTEX_SERVICE_NAME}`) habilitado.",
        file=sys.stderr,
    )
    if not vertex_projects:
        return id_to_proj, {}, [], scanned_project_ids, {}

    print(
        f"[3/4] Inventariando Service Accounts e chaves USER_MANAGED em `{scope}`...",
        file=sys.stderr,
    )
    raw_sas = runner.run_json([
        "asset",
        "search-all-resources",
        f"--scope={scope}",
        "--asset-types=iam.googleapis.com/ServiceAccount",
        "--page-size=500",
        "--read-mask=name,displayName,additionalAttributes,versionedResources",
    ])
    unique_id_to_email: dict[str, str] = {}
    email_to_unique_id: dict[str, str] = {}
    for sa_item in raw_sas:
        v_res = sa_item.get("versionedResources") or []
        sa_res = v_res[0].get("resource", {}) if v_res else {}
        attrs = sa_item.get("additionalAttributes") or {}
        uid = str(sa_res.get("uniqueId") or attrs.get("uniqueId") or "")
        email = str(sa_res.get("email") or attrs.get("email") or "")
        if uid and "@" in email:
            unique_id_to_email[uid] = email
            email_to_unique_id[email] = uid

    raw_keys = runner.run_json([
        "asset",
        "search-all-resources",
        f"--scope={scope}",
        "--asset-types=iam.googleapis.com/ServiceAccountKey",
        "--page-size=500",
        "--read-mask=*",
    ])

    sa_to_keys: dict[str, list[SAKeyInfo]] = {}
    total_user_keys = 0
    for k_item in raw_keys:
        parsed = parse_cai_sa_key(
            k_item, unique_id_to_email, email_to_unique_id
        )
        if parsed:
            if parsed.sa_unique_id:
                email_to_unique_id.setdefault(
                    parsed.sa_email, parsed.sa_unique_id
                )
            sa_to_keys.setdefault(parsed.sa_email, []).append(parsed)
            total_user_keys += 1

    print(
        f"      -> {total_user_keys} chave(s) USER_MANAGED encontrada(s) em {len(sa_to_keys)} Service Account(s) no escopo.",
        file=sys.stderr,
    )

    print(
        "[4/4] Analisando políticas IAM efetivas para inferência no Agent Platform / Vertex AI "
        "(incluindo grupos, custom roles e herança)...",
        file=sys.stderr,
    )
    analyze_args = [
        "asset",
        "analyze-iam-policy",
        analyzer_scope_flag,
        f"--permissions={','.join(INFERENCE_PERMISSIONS)}",
        "--expand-groups",
        "--execution-timeout=300s",
        "--show-response",
    ]
    if include_impersonation:
        analyze_args.append("--analyze-service-account-impersonation")

    try:
        analysis_resp = runner.run_json(analyze_args, timeout=360)
        grants, fully_explored = extract_grants_from_cai_analysis(
            analysis_resp, vertex_projects, id_to_proj, num_to_proj
        )
        if not fully_explored:
            print(
                "[AVISO] A análise IAM reportou `fullyExplored=false` (ambiente muito grande ou timeout parcial). "
                "Considere executar por `--folder` para sub-árvores críticas.",
                file=sys.stderr,
            )
    except GcloudError as exc:
        if "RESOURCE_EXHAUSTED" not in str(exc):
            raise
        print(
            "[AVISO] Cota diária gratuita do Policy Analyzer (20 queries/dia/org sem SCC Premium/Enterprise) "
            "atingida (`RESOURCE_EXHAUSTED`). Acionando fallback automático via `search-all-iam-policies` "
            "(cota gratuita de 400 req/min; herança de Org/Pasta e Custom Roles mantidas; grupos não expandidos)...",
            file=sys.stderr,
        )
        grants = fallback_search_all_iam_policies(
            runner, scope, vertex_projects, id_to_proj, num_to_proj
        )

    return (
        id_to_proj,
        sa_to_keys,
        grants,
        scanned_project_ids,
        email_to_unique_id,
    )


def fallback_search_all_iam_policies(
    runner: GcloudRunner,
    scope: str,
    vertex_projects: list[ProjectInfo],
    id_to_proj: dict[str, ProjectInfo],
    num_to_proj: dict[str, ProjectInfo],
) -> list[AccessGrant]:
    """Fallback gratuito via `gcloud asset search-all-iam-policies` (400 req/min,
    isento do limite de 20 queries/dia sem SCC Premium/Enterprise).
    """
    raw_policies = runner.run_json(
        [
            "asset",
            "search-all-iam-policies",
            f"--scope={scope}",
            "--query=memberTypes:serviceAccount",
            "--page-size=500",
        ],
        timeout=300,
    )
    role_cache = RolePermissionCache(runner)
    grants: list[AccessGrant] = []

    for item in raw_policies:
        attached = item.get("resource", "")
        affected = match_resource_to_vertex_projects(
            attached, vertex_projects, id_to_proj, num_to_proj
        )
        if not affected:
            continue
        pol = item.get("policy") or {}
        for binding in pol.get("bindings") or []:
            role = binding.get("role", "")
            matched_perms = role_cache.get_inference_permissions(role)
            if not matched_perms:
                continue
            cond_expr = (binding.get("condition") or {}).get("expression", "")
            for member in binding.get("members") or []:
                if member.startswith("deleted:") or not member.startswith(
                    "serviceAccount:"
                ):
                    continue
                sa_email = member.split(":", 1)[1]
                for v_proj in affected:
                    grants.append(
                        AccessGrant(
                            sa_email=sa_email,
                            vertex_project_id=v_proj,
                            role=role,
                            permissions=matched_perms,
                            attached_resource=attached,
                            access_path="DIRECT",
                            condition_expression=cond_expr,
                        )
                    )
    return grants


class RolePermissionCache:
    def __init__(self, runner: GcloudRunner) -> None:
        self.runner = runner
        self._cache: dict[str, list[str]] = {}

    def get_inference_permissions(self, role: str) -> list[str]:
        if role in self._cache:
            return self._cache[role]
        if role in KNOWN_INFERENCE_ROLES:
            perms = list(INFERENCE_PERMISSIONS)
            self._cache[role] = perms
            return perms
        if role in KNOWN_NON_INFERENCE_ROLES:
            self._cache[role] = []
            return []

        should_inspect = (
            role.startswith("projects/")
            or role.startswith("organizations/")
            or "aiplatform" in role.lower()
            or "vertex" in role.lower()
            or "ml." in role.lower()
        )
        if not should_inspect:
            self._cache[role] = []
            return []

        cmd = ["iam", "roles", "describe"]
        if role.startswith("projects/"):
            parts = role.split("/")
            if len(parts) == 4:
                cmd.extend([parts[3], f"--project={parts[1]}"])
            else:
                cmd.append(role)
        elif role.startswith("organizations/"):
            parts = role.split("/")
            if len(parts) == 4:
                cmd.extend([parts[3], f"--organization={parts[1]}"])
            else:
                cmd.append(role)
        else:
            cmd.append(role)

        try:
            desc = self.runner.run_json(cmd, timeout=60)
            inc = set(desc.get("includedPermissions") or [])
            matched = [p for p in INFERENCE_PERMISSIONS if p in inc]
        except GcloudError:
            matched = []

        self._cache[role] = matched
        return matched


def fetch_user_managed_keys_for_sa(
    runner: GcloudRunner, sa_email: str, sa_home_project: str
) -> list[SAKeyInfo] | None:
    try:
        args = [
            "iam",
            "service-accounts",
            "keys",
            "list",
            f"--iam-account={sa_email}",
            "--managed-by=user",
        ]
        raw_keys = runner.run_json(args, timeout=60)
    except GcloudError:
        return None

    out: list[SAKeyInfo] = []
    for k in raw_keys:
        name = k.get("name", "")
        m = SA_KEY_RESOURCE_RE.search(name)
        proj = m.group(1) if m else sa_home_project
        kid = m.group(3) if m else name.rsplit("/", 1)[-1]
        disabled = bool(k.get("disabled", False))
        valid_after = k.get("validAfterTime", "")
        valid_before = k.get("validBeforeTime", "")
        out.append(
            SAKeyInfo(
                sa_email=sa_email,
                sa_project_id=proj,
                key_id=kid,
                key_type=k.get("keyType", "USER_MANAGED"),
                key_origin=k.get("keyOrigin", "UNKNOWN"),
                key_algorithm=k.get("keyAlgorithm", ""),
                valid_after_time=valid_after,
                valid_before_time=valid_before,
                disabled=disabled,
                status=classify_key_status(disabled, valid_before),
            )
        )
    return out


def run_direct_discovery(
    runner: GcloudRunner,
    project_ids: list[str],
    include_genai_api: bool = False,
    workers: int = 8,
) -> tuple[
    dict[str, ProjectInfo],
    dict[str, list[SAKeyInfo]],
    list[AccessGrant],
    set[str],
    set[str],
]:
    """Modo fallback direto por projeto (sem exigir Cloud Asset Inventory)."""
    print(
        f"[1/3] Inspecionando {len(project_ids)} projeto(s) em modo direto...",
        file=sys.stderr,
    )
    id_to_proj: dict[str, ProjectInfo] = {}
    num_to_proj: dict[str, ProjectInfo] = {}

    def check_project(pid: str) -> ProjectInfo | None:
        try:
            desc = runner.run_json(["projects", "describe", pid], timeout=60)
            if desc.get("lifecycleState") != "ACTIVE":
                return None
            pnum = str(desc.get("projectNumber", ""))
            filter_expr = f"config.name={VERTEX_SERVICE_NAME}"
            if include_genai_api:
                filter_expr = (
                    f"config.name=({VERTEX_SERVICE_NAME} OR {GENAI_SERVICE_NAME})"
                )
            svcs = runner.run_json(
                [
                    "services",
                    "list",
                    "--enabled",
                    f"--project={pid}",
                    f"--filter={filter_expr}",
                ],
                timeout=90,
            )
            return ProjectInfo(
                project_id=pid,
                project_number=pnum,
                vertex_enabled=bool(svcs),
            )
        except GcloudError as exc:
            print(f"[AVISO] Ignorando projeto `{pid}`: {exc}", file=sys.stderr)
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_project, pid) for pid in project_ids]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                id_to_proj[res.project_id] = res
                if res.project_number:
                    num_to_proj[res.project_number] = res

    vertex_projects = [p for p in id_to_proj.values() if p.vertex_enabled]
    print(
        f"      -> {len(vertex_projects)} projeto(s) possuem Vertex AI habilitado.",
        file=sys.stderr,
    )
    if not vertex_projects:
        return id_to_proj, {}, [], set(), set()

    print(
        "[2/3] Coletando políticas IAM (incluindo ancestrais, se permitido)...",
        file=sys.stderr,
    )
    role_cache = RolePermissionCache(runner)
    grants: list[AccessGrant] = []

    for p_info in vertex_projects:
        pid = p_info.project_id
        policy_entries: list[tuple[str, dict[str, Any]]] = []
        try:
            anc_policies = runner.run_json(
                ["projects", "get-ancestors-iam-policy", pid], timeout=90
            )
            for entry in anc_policies:
                r_type = entry.get("type", "resource")
                r_id = entry.get("id", "")
                attached = (
                    f"//cloudresourcemanager.googleapis.com/{r_type}s/{r_id}"
                )
                policy_entries.append((attached, entry.get("policy") or {}))
        except GcloudError:
            try:
                pol = runner.run_json(
                    ["projects", "get-iam-policy", pid], timeout=60
                )
                attached = (
                    f"//cloudresourcemanager.googleapis.com/projects/{pid}"
                )
                policy_entries.append((attached, pol))
            except GcloudError as exc:
                print(
                    f"[AVISO] Sem permissão para ler IAM de `{pid}`: {exc}",
                    file=sys.stderr,
                )

        for attached, pol in policy_entries:
            for binding in pol.get("bindings") or []:
                role = binding.get("role", "")
                matched_perms = role_cache.get_inference_permissions(role)
                if not matched_perms:
                    continue
                cond_expr = (binding.get("condition") or {}).get(
                    "expression", ""
                )
                for member in binding.get("members") or []:
                    if member.startswith("deleted:"):
                        continue
                    if member.startswith("serviceAccount:"):
                        sa_email = member.split(":", 1)[1]
                        grants.append(
                            AccessGrant(
                                sa_email=sa_email,
                                vertex_project_id=pid,
                                role=role,
                                permissions=matched_perms,
                                attached_resource=attached,
                                access_path="DIRECT",
                                condition_expression=cond_expr,
                            )
                        )
                    elif member.startswith("group:"):
                        print(
                            f"[NOTA] Binding em grupo detectado (`{member}` -> `{role}` em `{pid}`). "
                            "Use `--mode=cai` para expandir membros de Google Groups automaticamente.",
                            file=sys.stderr,
                        )

    candidate_sas = sorted({
        g.sa_email for g in grants if not is_google_managed_agent(g.sa_email)
    })
    print(
        f"[3/3] Verificando chaves USER_MANAGED em {len(candidate_sas)} Service Account(s) com permissão de inferência...",
        file=sys.stderr,
    )

    num_to_id = {
        p.project_number: p.project_id
        for p in id_to_proj.values()
        if p.project_number
    }
    sa_to_keys: dict[str, list[SAKeyInfo]] = {}
    verified_sas: set[str] = set()
    unverified_sas: set[str] = set()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        fut_to_sa = {
            pool.submit(
                fetch_user_managed_keys_for_sa,
                runner,
                sa,
                infer_sa_home_project(sa, num_to_id),
            ): sa
            for sa in candidate_sas
        }
        for fut in as_completed(fut_to_sa):
            sa = fut_to_sa[fut]
            keys = fut.result()
            if keys is None:
                unverified_sas.add(sa)
            else:
                verified_sas.add(sa)
                if keys:
                    sa_to_keys[sa] = keys

    return id_to_proj, sa_to_keys, grants, verified_sas, unverified_sas


def enrich_keys_with_last_used_and_uid(
    runner: GcloudRunner,
    keys_to_enrich: list[SAKeyInfo],
    email_to_unique_id: dict[str, str],
    workers: int = 6,
) -> None:
    """Consulta Policy Analyzer (`serviceAccountKeyLastAuthentication`) e
    resolve `sa_unique_id` faltantes para correlação com Cloud Monitoring.
    """
    projects_to_query = sorted({
        k.sa_project_id
        for k in keys_to_enrich
        if k.sa_project_id and not k.sa_project_id.startswith("project-number:")
    })
    if projects_to_query:
        print(
            f"[+] Consultando último uso das chaves (Policy Analyzer) em {len(projects_to_query)} projeto(s)...",
            file=sys.stderr,
        )

        def query_proj_activity(
            proj_id: str,
        ) -> tuple[dict[str, str], dict[str, str]]:
            try:
                activities = runner.run_json(
                    [
                        "policy-intelligence",
                        "query-activity",
                        "--activity-type=serviceAccountKeyLastAuthentication",
                        f"--project={proj_id}",
                    ],
                    timeout=90,
                )
            except GcloudError:
                return {}, {}

            key_last_auth: dict[str, str] = {}
            key_to_uid: dict[str, str] = {}
            for item in activities:
                act = item.get("activity") or {}
                last_auth = act.get("lastAuthenticatedTime", "")
                sak_obj = act.get("serviceAccountKey") or {}
                sa_uid = str(sak_obj.get("serviceAccountId") or "")
                full_name = (
                    sak_obj.get("fullResourceName")
                    or item.get("fullResourceName")
                    or ""
                )
                m = SA_KEY_RESOURCE_RE.search(full_name)
                if m:
                    kid = m.group(3)
                    if last_auth and last_auth > key_last_auth.get(kid, ""):
                        key_last_auth[kid] = last_auth
                    if sa_uid:
                        key_to_uid[kid] = sa_uid
                    elif m.group(2).isdigit():
                        key_to_uid[kid] = m.group(2)
            return key_last_auth, key_to_uid

        proj_to_activity: dict[str, dict[str, str]] = {}
        proj_to_uid: dict[str, dict[str, str]] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(query_proj_activity, pid): pid
                for pid in projects_to_query
            }
            for fut in as_completed(fut_map):
                pid = fut_map[fut]
                auth_map, uid_map = fut.result()
                proj_to_activity[pid] = auth_map
                proj_to_uid[pid] = uid_map

        for k in keys_to_enrich:
            last_ts = proj_to_activity.get(k.sa_project_id, {}).get(
                k.key_id, ""
            )
            if last_ts:
                k.last_authenticated_time = last_ts
            if not k.sa_unique_id:
                uid = email_to_unique_id.get(k.sa_email) or proj_to_uid.get(
                    k.sa_project_id, {}
                ).get(k.key_id, "")
                if uid:
                    k.sa_unique_id = uid
                    email_to_unique_id[k.sa_email] = uid

    # Fallback: resolve `uniqueId` via `iam service-accounts describe` para SAs ainda sem ID numérico
    missing_uid_sas = sorted({
        k.sa_email
        for k in keys_to_enrich
        if not k.sa_unique_id and k.sa_email not in email_to_unique_id
    })
    for sa_email in missing_uid_sas:
        try:
            desc = runner.run_json(
                ["iam", "service-accounts", "describe", sa_email], timeout=30
            )
            uid = str(desc.get("uniqueId") or "")
            if uid:
                email_to_unique_id[sa_email] = uid
        except GcloudError:
            pass

    for k in keys_to_enrich:
        if not k.sa_unique_id and k.sa_email in email_to_unique_id:
            k.sa_unique_id = email_to_unique_id[k.sa_email]


def _sum_timeseries_points(points: list[dict[str, Any]]) -> int:
    total = 0
    for pt in points:
        val = pt.get("value") or {}
        if "int64Value" in val:
            total += int(val["int64Value"])
        elif "doubleValue" in val:
            total += int(round(float(val["doubleValue"])))
    return total


def enrich_with_inference_telemetry_no_dataread(
    runner: GcloudRunner,
    exposed_keys: list[SAKeyInfo],
    grants_by_sa: dict[str, list[AccessGrant]],
    email_to_unique_id: dict[str, str],
    lookback_days: int = 14,
    check_iam_insights: bool = True,
    now: datetime | None = None,
    workers: int = 6,
) -> dict[str, SAInferenceTelemetry]:
    """Comprova chamadas de inferência SEM precisar de logs DATA_READ.

    1) `serviceruntime.googleapis.com/api/request_count` (`consumed_api`):
       mede chamadas de inferência a `aiplatform.googleapis.com` por
       `credential_id` (`serviceaccount:<uniqueId>`) e método RPC.
    2) `iam.googleapis.com/service_account/key/authn_events_count`:
       mede autenticações por `key_id` específica na mesma janela.
    3) `google.iam.policy.Insight` (`exercisedPermissions`):
       confirma se `aiplatform.endpoints.predict` foi exercida nos últimos 90d.
    """
    ref_now = now or datetime.now(timezone.utc)
    start_dt = ref_now - timedelta(days=lookback_days)
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = ref_now.strftime("%Y-%m-%dT%H:%M:%SZ")

    exposed_sas = sorted({k.sa_email for k in exposed_keys})
    telemetry_by_sa: dict[str, SAInferenceTelemetry] = {
        sa: SAInferenceTelemetry() for sa in exposed_sas
    }

    # Mapeia cadeias IMPERSONATION->target_sa para SAs cujo acesso depende de impersonation
    # (evita que SAs com `roles/editor` ou `roles/owner` herdem chamadas legítimas de outras SAs do projeto).
    impersonated_targets: dict[str, set[str]] = {}
    target_to_callers: dict[str, set[str]] = {}
    for sa in exposed_sas:
        sa_grants = grants_by_sa.get(sa, [])
        has_direct = any(
            not g.access_path.startswith("IMPERSONATION->") for g in sa_grants
        )
        if has_direct:
            continue
        for g in sa_grants:
            if g.access_path.startswith("IMPERSONATION->"):
                target_sa = g.access_path.split("->", 1)[1]
                impersonated_targets.setdefault(sa, set()).add(target_sa)
                target_to_callers.setdefault(target_sa, set()).add(sa)

    for target_sa in sorted(target_to_callers):
        if target_sa not in email_to_unique_id:
            try:
                desc = runner.run_json(
                    ["iam", "service-accounts", "describe", target_sa],
                    timeout=30,
                )
                if desc.get("uniqueId"):
                    email_to_unique_id[target_sa] = str(desc["uniqueId"])
            except GcloudError:
                pass

    uid_to_sas: dict[str, set[str]] = {}
    for sa in exposed_sas:
        uid = email_to_unique_id.get(sa, "")
        if uid:
            uid_to_sas.setdefault(uid, set()).add(sa)
    for target_sa, callers in target_to_callers.items():
        uid = email_to_unique_id.get(target_sa, "")
        if uid:
            uid_to_sas.setdefault(uid, set()).update(callers)

    # Projetos onde as SAs expostas têm permissão de inferência Vertex (+ projetos de origem das SAs)
    target_vertex_projects = sorted({
        g.vertex_project_id
        for sa in exposed_sas
        for g in grants_by_sa.get(sa, [])
        if g.vertex_project_id
    })
    sa_home_projects = sorted({
        k.sa_project_id
        for k in exposed_keys
        if k.sa_project_id and not k.sa_project_id.startswith("project-number:")
    })
    monitoring_api_projects = sorted(
        set(target_vertex_projects) | set(sa_home_projects)
    )

    if monitoring_api_projects and uid_to_sas:
        print(
            f"[+] Verificando chamadas REAIS de inferência Vertex AI (Cloud Monitoring `serviceruntime`, "
            f"últimos {lookback_days}d, sem DATA_READ) em {len(monitoring_api_projects)} projeto(s)...",
            file=sys.stderr,
        )
        api_filter = (
            'metric.type="serviceruntime.googleapis.com/api/request_count" '
            'AND resource.type="consumed_api" '
            f'AND resource.labels.service="{VERTEX_SERVICE_NAME}"'
        )

        def query_vertex_requests(proj_id: str) -> list[dict[str, Any]]:
            try:
                return runner.list_monitoring_timeseries(
                    project_id=proj_id,
                    metric_filter=api_filter,
                    start_time_iso=start_iso,
                    end_time_iso=end_iso,
                    group_by_fields=[
                        "resource.labels.credential_id",
                        "resource.labels.method",
                        "metric.labels.response_code_class",
                    ],
                )
            except GcloudError as exc:
                if runner.verbose:
                    print(
                        f"[DEBUG] Sem métricas serviceruntime em `{proj_id}`: {exc}",
                        file=sys.stderr,
                    )
                return []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(query_vertex_requests, pid): pid
                for pid in monitoring_api_projects
            }
            for fut in as_completed(fut_map):
                pid = fut_map[fut]
                for ts in fut.result():
                    r_labels = (ts.get("resource") or {}).get("labels") or {}
                    m_labels = (ts.get("metric") or {}).get("labels") or {}
                    cred_id = r_labels.get("credential_id", "")
                    method = r_labels.get("method", "")
                    resp_class = m_labels.get("response_code_class", "")

                    if not cred_id.startswith("serviceaccount:"):
                        continue
                    uid = cred_id.split(":", 1)[1]
                    matched_sas = uid_to_sas.get(uid)
                    if not matched_sas or not is_vertex_inference_method(method):
                        continue

                    count = _sum_timeseries_points(ts.get("points") or [])
                    if count <= 0:
                        continue

                    for sa_email in matched_sas:
                        tel = telemetry_by_sa[sa_email]
                        tel.total_calls += count
                        if resp_class == "2xx" or not resp_class:
                            tel.ok_2xx_calls += count
                        else:
                            tel.error_calls += count
                        tel.methods.add(short_method_name(method))
                        tel.active_vertex_projects.add(pid)

    if sa_home_projects:
        print(
            f"[+] Verificando volume de autenticações por `key_id` (Cloud Monitoring IAM, últimos {lookback_days}d) "
            f"em {len(sa_home_projects)} projeto(s)...",
            file=sys.stderr,
        )
        key_filter = (
            'metric.type="iam.googleapis.com/service_account/key/authn_events_count" '
            'AND resource.type="iam_service_account"'
        )

        def query_key_authn(proj_id: str) -> dict[str, int]:
            try:
                series = runner.list_monitoring_timeseries(
                    project_id=proj_id,
                    metric_filter=key_filter,
                    start_time_iso=start_iso,
                    end_time_iso=end_iso,
                    group_by_fields=[
                        "resource.labels.unique_id",
                        "metric.labels.key_id",
                    ],
                )
            except GcloudError:
                return {}

            counts_by_key: dict[str, int] = {}
            for ts in series:
                m_labels = (ts.get("metric") or {}).get("labels") or {}
                kid = m_labels.get("key_id", "")
                if kid:
                    counts_by_key[kid] = counts_by_key.get(
                        kid, 0
                    ) + _sum_timeseries_points(ts.get("points") or [])
            return counts_by_key

        proj_key_counts: dict[str, dict[str, int]] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(query_key_authn, pid): pid
                for pid in sa_home_projects
            }
            for fut in as_completed(fut_map):
                pid = fut_map[fut]
                proj_key_counts[pid] = fut.result()

        for k in exposed_keys:
            k.key_authn_events = proj_key_counts.get(k.sa_project_id, {}).get(
                k.key_id, 0
            )

    if check_iam_insights and target_vertex_projects:
        print(
            f"[+] Consultando histórico de permissões exercidas em 90d (IAM Policy Insights) "
            f"em {len(target_vertex_projects)} projeto(s)...",
            file=sys.stderr,
        )

        def query_insights(proj_id: str) -> set[str]:
            try:
                insights = runner.run_json(
                    [
                        "recommender",
                        "insights",
                        "list",
                        "--insight-type=google.iam.policy.Insight",
                        "--location=global",
                        f"--project={proj_id}",
                        "--page-size=500",
                    ],
                    timeout=90,
                )
            except GcloudError:
                return set()

            exercised_sas: set[str] = set()
            for ins in insights:
                content = ins.get("content") or {}
                member = content.get("member", "")
                if not member.startswith("serviceAccount:"):
                    continue
                sa_m = member.split(":", 1)[1]
                ex_perms = {
                    (p.get("permission") if isinstance(p, dict) else str(p))
                    for p in (content.get("exercisedPermissions") or [])
                }
                if ex_perms & set(INFERENCE_PERMISSIONS):
                    exercised_sas.add(sa_m)
            return exercised_sas

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [
                pool.submit(query_insights, pid)
                for pid in target_vertex_projects
            ]
            for fut in as_completed(futs):
                for sa_m in fut.result():
                    if sa_m in telemetry_by_sa:
                        telemetry_by_sa[sa_m].iam_insight_exercised_90d = True
                    # Propaga também se uma SA exposta impersona essa SA alvo
                    for caller_sa, targets in impersonated_targets.items():
                        if sa_m in targets and caller_sa in telemetry_by_sa:
                            telemetry_by_sa[
                                caller_sa
                            ].iam_insight_exercised_90d = True

    return telemetry_by_sa


def _is_key_used_in_window(
    key: SAKeyInfo, window_start: datetime
) -> bool:
    last_auth_dt = parse_iso_timestamp(key.last_authenticated_time)
    return key.key_authn_events > 0 or (
        last_auth_dt is not None and last_auth_dt >= window_start
    )


def classify_inference_activity(
    key: SAKeyInfo,
    sibling_keys: list[SAKeyInfo],
    tel: SAInferenceTelemetry,
    lookback_days: int,
    now: datetime | None = None,
) -> str:
    """Classifica o status operacional real da chave em relação à inferência Vertex."""
    ref_now = now or datetime.now(timezone.utc)
    window_start = ref_now - timedelta(days=lookback_days)
    key_used_recently = _is_key_used_in_window(key, window_start)
    other_sibling_used = any(
        other.key_id != key.key_id and _is_key_used_in_window(other, window_start)
        for other in sibling_keys
    )
    sa_called_vertex = tel.total_calls > 0 or tel.iam_insight_exercised_90d

    if sa_called_vertex and key_used_recently:
        return "CONFIRMED_KEY_INFERENCE"
    if sa_called_vertex and other_sibling_used:
        return "SA_INFERENCE_KEY_IDLE"
    if sa_called_vertex:
        # A SA tem chamadas reais de inferência em `serviceruntime` (~2 min de latência),
        # mas o IAM ainda não individualizou `key_id` (até 3h de delay p/ chaves recém-usadas)
        # ou o uso veio de credencial anexada (GCE/GKE WIF).
        return "SA_ACTIVE_VERIFY_KEY"
    if key_used_recently:
        return "KEY_AUTH_NO_INFERENCE"
    return "DORMANT_NO_ACTIVITY"


def build_findings(
    runner: GcloudRunner,
    id_to_proj: dict[str, ProjectInfo],
    sa_to_keys: dict[str, list[SAKeyInfo]],
    grants: list[AccessGrant],
    scanned_project_ids: set[str],
    email_to_unique_id: dict[str, str] | None = None,
    verified_sas: set[str] | None = None,
    pre_unverified_sas: set[str] | None = None,
    include_inactive_keys: bool = True,
    check_last_used: bool = True,
    check_inference_usage: bool = True,
    check_iam_insights: bool = True,
    lookback_days: int = 14,
    now: datetime | None = None,
) -> list[AuditFinding]:
    """Correlaciona permissões efetivas, chaves USER_MANAGED e telemetria real de inferência."""
    email_uid_map = dict(email_to_unique_id or {})
    num_to_id = {
        p.project_number: p.project_id
        for p in id_to_proj.values()
        if p.project_number
    }

    grants_by_sa: dict[str, list[AccessGrant]] = {}
    for g in grants:
        if is_google_managed_agent(g.sa_email):
            continue
        grants_by_sa.setdefault(g.sa_email, []).append(g)

    already_verified = verified_sas or set()
    unverified_external_sas: set[str] = set(pre_unverified_sas or set())

    for sa_email in sorted(grants_by_sa):
        if (
            sa_email in sa_to_keys
            or sa_email in already_verified
            or sa_email in unverified_external_sas
        ):
            continue
        home_proj = infer_sa_home_project(sa_email, num_to_id)
        if home_proj and home_proj in scanned_project_ids:
            continue
        keys = fetch_user_managed_keys_for_sa(runner, sa_email, home_proj)
        if keys is None:
            unverified_external_sas.add(sa_email)
        elif keys:
            sa_to_keys[sa_email] = keys

    exposed_keys: list[SAKeyInfo] = [
        k
        for sa, k_list in sa_to_keys.items()
        if sa in grants_by_sa
        for k in k_list
        if include_inactive_keys or k.status == "ACTIVE"
    ]

    if (check_last_used or check_inference_usage) and exposed_keys:
        enrich_keys_with_last_used_and_uid(
            runner, exposed_keys, email_uid_map
        )

    telemetry_by_sa: dict[str, SAInferenceTelemetry] = {}
    if check_inference_usage and exposed_keys:
        telemetry_by_sa = enrich_with_inference_telemetry_no_dataread(
            runner=runner,
            exposed_keys=exposed_keys,
            grants_by_sa=grants_by_sa,
            email_to_unique_id=email_uid_map,
            lookback_days=lookback_days,
            check_iam_insights=check_iam_insights,
            now=now,
        )

    findings: list[AuditFinding] = []

    for sa_email, sa_grants in grants_by_sa.items():
        v_projects = sorted({g.vertex_project_id for g in sa_grants})
        paths = sorted({g.access_path for g in sa_grants})
        roles = sorted({g.role for g in sa_grants if g.role})
        perms = sorted({p for g in sa_grants for p in g.permissions})
        resources = sorted({
            g.attached_resource for g in sa_grants if g.attached_resource
        })
        conditions = sorted({
            g.condition_expression
            for g in sa_grants
            if g.condition_expression
        })
        home_proj = infer_sa_home_project(sa_email, num_to_id)

        if sa_email in unverified_external_sas:
            findings.append(
                AuditFinding(
                    risk_status="EXTERNAL_SA_VERIFY_MANUALLY",
                    inference_activity_status="UNKNOWN_EXTERNAL_SA",
                    sa_email=sa_email,
                    sa_unique_id=email_uid_map.get(sa_email, ""),
                    sa_home_project=home_proj or "EXTERNAL_UNKNOWN",
                    key_id="UNKNOWN_NO_IAM_ACCESS",
                    key_status="UNKNOWN",
                    key_origin="UNKNOWN",
                    key_created_at="",
                    key_expires_at="",
                    last_authenticated_time="",
                    key_authn_events_window=0,
                    sa_vertex_inference_calls_window=0,
                    sa_vertex_2xx_calls_window=0,
                    sa_vertex_error_calls_window=0,
                    sa_vertex_methods_called=[],
                    active_inference_projects=[],
                    iam_exercised_predict_90d=False,
                    vertex_projects_permitted=v_projects,
                    access_paths=paths,
                    roles=roles,
                    permissions=perms,
                    binding_resources=resources,
                    conditions=conditions,
                    disable_key_command=(
                        f"# Verifique a SA externa `{sa_email}` no projeto `{home_proj}` "
                        "ou remova o binding IAM nos projetos Vertex."
                    ),
                )
            )
            continue

        tel = telemetry_by_sa.get(sa_email, SAInferenceTelemetry())
        sa_keys_list = sa_to_keys.get(sa_email, [])
        for k in sa_keys_list:
            if not include_inactive_keys and k.status != "ACTIVE":
                continue

            act_status = (
                classify_inference_activity(
                    k, sa_keys_list, tel, lookback_days, now=now
                )
                if check_inference_usage
                else "NOT_CHECKED"
            )

            if k.status == "ACTIVE":
                risk = (
                    "P0_ACTIVE_KEY_DOING_INFERENCE"
                    if act_status
                    in ("CONFIRMED_KEY_INFERENCE", "SA_ACTIVE_VERIFY_KEY")
                    else "CRITICAL_ACTIVE_KEY"
                )
                disable_cmd = (
                    f"gcloud iam service-accounts keys disable {k.key_id} "
                    f"--iam-account={sa_email} --project={k.sa_project_id}"
                )
            else:
                risk = f"LOW_{k.status}_KEY"
                disable_cmd = f"# Chave {k.key_id} já está {k.status}"

            findings.append(
                AuditFinding(
                    risk_status=risk,
                    inference_activity_status=act_status,
                    sa_email=sa_email,
                    sa_unique_id=k.sa_unique_id,
                    sa_home_project=k.sa_project_id or home_proj,
                    key_id=k.key_id,
                    key_status=k.status,
                    key_origin=k.key_origin,
                    key_created_at=k.valid_after_time,
                    key_expires_at=k.valid_before_time,
                    last_authenticated_time=k.last_authenticated_time,
                    key_authn_events_window=k.key_authn_events,
                    sa_vertex_inference_calls_window=tel.total_calls,
                    sa_vertex_2xx_calls_window=tel.ok_2xx_calls,
                    sa_vertex_error_calls_window=tel.error_calls,
                    sa_vertex_methods_called=sorted(tel.methods),
                    active_inference_projects=sorted(
                        tel.active_vertex_projects
                    ),
                    iam_exercised_predict_90d=tel.iam_insight_exercised_90d,
                    vertex_projects_permitted=v_projects,
                    access_paths=paths,
                    roles=roles,
                    permissions=perms,
                    binding_resources=resources,
                    conditions=conditions,
                    disable_key_command=disable_cmd,
                )
            )

    priority_rank = {
        "P0_ACTIVE_KEY_DOING_INFERENCE": 0,
        "CRITICAL_ACTIVE_KEY": 1,
        "EXTERNAL_SA_VERIFY_MANUALLY": 2,
        "LOW_DISABLED_KEY": 3,
        "LOW_EXPIRED_KEY": 4,
    }
    activity_rank = {
        "CONFIRMED_KEY_INFERENCE": 0,
        "SA_ACTIVE_VERIFY_KEY": 1,
        "SA_INFERENCE_KEY_IDLE": 2,
        "KEY_AUTH_NO_INFERENCE": 3,
        "DORMANT_NO_ACTIVITY": 4,
        "UNKNOWN_EXTERNAL_SA": 5,
        "NOT_CHECKED": 6,
    }

    def sort_key(
        f: AuditFinding,
    ) -> tuple[int, int, int, int, float, str, str]:
        dt = parse_iso_timestamp(f.last_authenticated_time)
        has_auth_rank = 0 if dt is not None else 1
        neg_ts = -dt.timestamp() if dt is not None else 0.0
        return (
            priority_rank.get(f.risk_status, 9),
            activity_rank.get(f.inference_activity_status, 9),
            -f.sa_vertex_inference_calls_window,
            has_auth_rank,
            neg_ts,
            f.sa_email,
            f.key_id,
        )

    findings.sort(key=sort_key)
    return findings


def print_summary_table(findings: list[AuditFinding], lookback_days: int) -> None:
    if not findings:
        print(
            "\n✅ Nenhuma Service Account Key (USER_MANAGED) com permissão de inferência no Gemini Enterprise Agent Platform (Vertex AI) foi encontrada no escopo analisado."
        )
        return

    p0_count = sum(
        1 for f in findings if f.risk_status == "P0_ACTIVE_KEY_DOING_INFERENCE"
    )
    active_count = sum(1 for f in findings if f.key_status == "ACTIVE")
    ext_count = sum(
        1 for f in findings if f.risk_status == "EXTERNAL_SA_VERIFY_MANUALLY"
    )
    print("\n" + "=" * 136)
    print(
        f"🚨 AUDITORIA AGENT PLATFORM (VERTEX AI) LLMJACKING (Janela: {lookback_days}d | Sem exigir DATA_READ): "
        f"{p0_count} chave(s) ATIVA(S) FAZENDO INFERÊNCIA | "
        f"{active_count} chave(s) ativa(s) c/ permissão | "
        f"{ext_count} SA(s) externa(s)"
    )
    print("=" * 136)
    header = (
        f"{'ATIVIDADE INFERÊNCIA':<25} {'SERVICE ACCOUNT':<38} {'KEY ID':<13} "
        f"{'CHAMADAS IA':>15} {'AUTH KEY':>10} {'ÚLTIMO USO (UTC)':<21} {'MÉTODOS / PROJETOS'}"
    )
    print(header)
    print("-" * 136)
    for f in findings:
        short_key = f.key_id[:12] if len(f.key_id) > 12 else f.key_id
        last_used = f.last_authenticated_time or "Sem reg.(90d)/N/D"
        calls_str = f"{f.sa_vertex_inference_calls_window:,}"
        authn_str = f"{f.key_authn_events_window:,}"
        if f.sa_vertex_methods_called:
            detail = f"{','.join(f.sa_vertex_methods_called[:2])} @ {','.join(f.active_inference_projects[:2])}"
        else:
            detail = f"Permissão em: {','.join(f.vertex_projects_permitted[:2])}"
        sa_disp = (
            f.sa_email if len(f.sa_email) <= 36 else f.sa_email[:33] + "..."
        )
        act_disp = f.inference_activity_status
        if f.key_status != "ACTIVE" and f.key_status != "UNKNOWN":
            act_disp = f"{f.key_status}:{act_disp}"[:24]
        print(
            f"{act_disp:<25} {sa_disp:<38} {short_key:<13} "
            f"{calls_str:>15} {authn_str:>10} {last_used:<21} {detail}"
        )
    print("=" * 136)


def write_reports(
    findings: list[AuditFinding], csv_path: str, json_path: str
) -> None:
    if csv_path:
        fieldnames = [
            "risk_status",
            "inference_activity_status",
            "sa_email",
            "sa_unique_id",
            "sa_home_project",
            "key_id",
            "key_status",
            "key_origin",
            "key_created_at",
            "key_expires_at",
            "last_authenticated_time",
            "key_authn_events_window",
            "sa_vertex_inference_calls_window",
            "sa_vertex_2xx_calls_window",
            "sa_vertex_error_calls_window",
            "sa_vertex_methods_called",
            "active_inference_projects",
            "iam_exercised_predict_90d",
            "vertex_projects_permitted",
            "access_paths",
            "roles",
            "permissions",
            "binding_resources",
            "conditions",
            "disable_key_command",
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=fieldnames)
            writer.writeheader()
            for f in findings:
                row = asdict(f)
                for list_col in (
                    "sa_vertex_methods_called",
                    "active_inference_projects",
                    "vertex_projects_permitted",
                    "access_paths",
                    "roles",
                    "permissions",
                    "binding_resources",
                    "conditions",
                ):
                    row[list_col] = "; ".join(row[list_col])
                writer.writerow(row)
        print(f"[+] Relatório CSV salvo em: {csv_path}", file=sys.stderr)

    if json_path:
        payload = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "p0_active_keys_doing_inference": sum(
                1
                for f in findings
                if f.risk_status == "P0_ACTIVE_KEY_DOING_INFERENCE"
            ),
            "active_keys_with_vertex_permission": sum(
                1 for f in findings if f.key_status == "ACTIVE"
            ),
            "findings": [asdict(f) for f in findings],
        }
        with open(json_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, ensure_ascii=False)
        print(f"[+] Relatório JSON salvo em: {json_path}", file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Identifica Service Account Keys (USER_MANAGED) com permissão e USO REAL "
            "de inferência no Gemini Enterprise Agent Platform (antigo Vertex AI) sem exigir logs DATA_READ."
        )
    )
    scope_group = parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument(
        "--org",
        metavar="ORG_ID",
        help="ID numérico da Organização GCP (recomendado para pegar SAs cross-project e herança).",
    )
    scope_group.add_argument(
        "--folder",
        metavar="FOLDER_ID",
        help="ID numérico da Pasta GCP.",
    )
    scope_group.add_argument(
        "--projects",
        metavar="PROJ1,PROJ2",
        help="Lista de Project IDs separados por vírgula.",
    )
    scope_group.add_argument(
        "--all-accessible-projects",
        action="store_true",
        help="Varre todos os projetos ativos visíveis pela credencial atual (`gcloud projects list`).",
    )

    parser.add_argument(
        "--mode",
        choices=("auto", "cai", "direct"),
        default="auto",
        help=(
            "Modo de descoberta: `cai` (Cloud Asset Inventory, padrão p/ --org/--folder) "
            "ou `direct` (APIs diretas por projeto, padrão p/ --projects/--all-accessible-projects)."
        ),
    )
    parser.add_argument(
        "--lookback-days",
        type=int,
        default=14,
        help=(
            "Janela em dias para medir chamadas reais de inferência e autenticações "
            "no Cloud Monitoring (padrão: 14, máximo recomendado: 42)."
        ),
    )
    parser.add_argument(
        "--only-confirmed-inference",
        action="store_true",
        help="Exibe e exporta APENAS chaves com chamadas de inferência confirmadas (`CONFIRMED_KEY_INFERENCE`).",
    )
    parser.add_argument(
        "--skip-inference-usage",
        action="store_true",
        help="Pula a verificação de chamadas reais no Cloud Monitoring / IAM Insights.",
    )
    parser.add_argument(
        "--skip-iam-insights",
        action="store_true",
        help="Pula a consulta complementar de 90 dias ao IAM Policy Insights (`recommender.googleapis.com`).",
    )
    parser.add_argument(
        "--include-impersonation",
        action="store_true",
        help="(Modo CAI) Inclui SAs com chave que podem impersonar outra SA com acesso ao Agent Platform / Vertex AI.",
    )
    parser.add_argument(
        "--include-genai-api",
        action="store_true",
        help="Inclui também projetos com `generativelanguage.googleapis.com` habilitado.",
    )
    parser.add_argument(
        "--active-keys-only",
        action="store_true",
        help="Oculta chaves USER_MANAGED já desabilitadas ou expiradas.",
    )
    parser.add_argument(
        "--skip-last-used",
        action="store_true",
        help="Pula a consulta de último uso no Policy Analyzer.",
    )
    parser.add_argument(
        "--billing-project",
        metavar="PROJECT_ID",
        help="Projeto para cota das APIs (`--billing-project` / `X-Goog-User-Project`).",
    )
    parser.add_argument(
        "--csv",
        default="agent_platform_sa_keys_audit.csv",
        help="Caminho de saída do CSV (padrão: agent_platform_sa_keys_audit.csv; use '' para desativar).",
    )
    parser.add_argument(
        "--json",
        default="agent_platform_sa_keys_audit.json",
        help="Caminho de saída do JSON (padrão: agent_platform_sa_keys_audit.json; use '' para desativar).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Exibe comandos e URLs consultadas no stderr.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lookback = max(1, min(args.lookback_days, 42))
    runner = GcloudRunner(
        billing_project=args.billing_project, verbose=args.verbose
    )

    mode = args.mode
    if mode == "auto":
        mode = "cai" if (args.org or args.folder) else "direct"

    try:
        if mode == "cai":
            if args.org:
                scopes = [
                    f"organizations/{args.org.replace('organizations/', '')}"
                ]
            elif args.folder:
                scopes = [f"folders/{args.folder.replace('folders/', '')}"]
            elif args.projects:
                scopes = [
                    f"projects/{p.strip()}"
                    for p in args.projects.split(",")
                    if p.strip()
                ]
            else:
                raw_list = runner.run_json([
                    "projects",
                    "list",
                    "--filter=lifecycleState:ACTIVE",
                ])
                scopes = [f"projects/{p['projectId']}" for p in raw_list]

            merged_projs: dict[str, ProjectInfo] = {}
            merged_keys: dict[str, list[SAKeyInfo]] = {}
            merged_grants: list[AccessGrant] = []
            merged_scanned: set[str] = set()
            merged_email_uid: dict[str, str] = {}

            for sc in scopes:
                p_map, k_map, g_list, scanned, email_uid = run_cai_discovery(
                    runner,
                    scope=sc,
                    include_impersonation=args.include_impersonation,
                    include_genai_api=args.include_genai_api,
                )
                merged_projs.update(p_map)
                merged_email_uid.update(email_uid)
                for sa, ks in k_map.items():
                    existing_ids = {x.key_id for x in merged_keys.get(sa, [])}
                    for k in ks:
                        if k.key_id not in existing_ids:
                            merged_keys.setdefault(sa, []).append(k)
                merged_grants.extend(g_list)
                merged_scanned.update(scanned)

            findings = build_findings(
                runner=runner,
                id_to_proj=merged_projs,
                sa_to_keys=merged_keys,
                grants=merged_grants,
                scanned_project_ids=merged_scanned,
                email_to_unique_id=merged_email_uid,
                include_inactive_keys=not args.active_keys_only,
                check_last_used=not args.skip_last_used,
                check_inference_usage=not args.skip_inference_usage,
                check_iam_insights=not args.skip_iam_insights,
                lookback_days=lookback,
            )
        else:
            if args.org or args.folder:
                parent_type = "organization" if args.org else "folder"
                parent_id = (args.org or args.folder).split("/")[-1]
                print(
                    f"[*] Listando projetos filhos diretos de `{parent_type}/{parent_id}`...",
                    file=sys.stderr,
                )
                raw_list = runner.run_json([
                    "projects",
                    "list",
                    f"--filter=parent.id={parent_id} AND lifecycleState=ACTIVE",
                ])
                project_ids = [p["projectId"] for p in raw_list]
            elif args.projects:
                project_ids = [
                    p.strip() for p in args.projects.split(",") if p.strip()
                ]
            else:
                raw_list = runner.run_json([
                    "projects",
                    "list",
                    "--filter=lifecycleState:ACTIVE",
                ])
                project_ids = [p["projectId"] for p in raw_list]

            p_map, k_map, g_list, verified_sas, unverified_sas = (
                run_direct_discovery(
                    runner=runner,
                    project_ids=project_ids,
                    include_genai_api=args.include_genai_api,
                )
            )
            findings = build_findings(
                runner=runner,
                id_to_proj=p_map,
                sa_to_keys=k_map,
                grants=g_list,
                scanned_project_ids=set(),
                verified_sas=verified_sas,
                pre_unverified_sas=unverified_sas,
                include_inactive_keys=not args.active_keys_only,
                check_last_used=not args.skip_last_used,
                check_inference_usage=not args.skip_inference_usage,
                check_iam_insights=not args.skip_iam_insights,
                lookback_days=lookback,
            )

        if args.only_confirmed_inference:
            findings = [
                f
                for f in findings
                if f.inference_activity_status
                in ("CONFIRMED_KEY_INFERENCE", "SA_ACTIVE_VERIFY_KEY")
            ]

        print_summary_table(findings, lookback_days=lookback)
        write_reports(findings, csv_path=args.csv, json_path=args.json)
        return 0

    except GcloudError as exc:
        print(f"\n[ERRO] {exc}", file=sys.stderr)
        if mode == "cai":
            print(
                "\nDica: Para o modo `cai`, verifique se `cloudasset.googleapis.com` está habilitada "
                "no seu `--billing-project` e se sua credencial possui `roles/cloudasset.viewer` "
                "(ou use `--mode=direct --all-accessible-projects`).",
                file=sys.stderr,
            )
        return 2


if __name__ == "__main__":
    sys.exit(main())
