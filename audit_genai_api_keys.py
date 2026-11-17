#!/usr/bin/env python3
# Copyright 2026 Marcos Cotomacio
# Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
#
# AVISO: Ferramenta comunitária não oficial ("as-is"), sem garantia ou suporte
# oficial do Google Cloud. Criada para triagem rápida (somente leitura) de
# credenciais estáticas em incidentes de LLMJacking.
"""Auditoria de API Keys (`apikeys.googleapis.com/Key`) expostas ao Gemini (`generativelanguage.googleapis.com`).

Script complementar não oficial para resposta rápida a incidentes de LLMJacking
envolvendo vazamento de API Keys (Google AI Studio / Gemini Developer API e,
opcionalmente, Gemini Enterprise Agent Platform / antigo Vertex AI Express Mode).

O que o script identifica:
  1. Projetos ativos com `generativelanguage.googleapis.com` habilitado (e se
     possuem faturamento ativo `PAYG` vinculado em `ProjectBillingInfo`, onde há
     risco financeiro direto de Denial-of-Wallet).
  2. API Keys que podem invocar inferência nesses projetos:
     - Chaves IRRESTRITAS (`apiTargets` vazio — aceitam qualquer API habilitada
       no projeto, inclusive `generativelanguage.googleapis.com`!).
     - Chaves explicitamente liberadas para `generativelanguage.googleapis.com`
       (ou `aiplatform.googleapis.com` com `--include-vertex-express`).
     - Avalia se a chave possui restrição de rede/aplicação (`allowedIps`,
       `allowedReferrers`, Android/iOS) ou se está aberta para qualquer IP.
     - Identifica chaves vinculadas a Service Account (`serviceAccountEmail` /
       Auth Keys v2).
  3. Comprovação de USO REAL de inferência (`GenerateContent`,
     `StreamGenerateContent`, `BidiGenerateContent`, `EmbedContent`,
     `BatchGenerateContent`, etc.) via Cloud Monitoring
     (`serviceruntime.googleapis.com/api/request_count`, `credential_id =
     "apikey:<KEY_UID>"` ou `serviceaccount:<SA_UID>`), sem exigir logs DATA_READ.

Requisitos: Python 3.8+ (apenas biblioteca padrão) e Google Cloud CLI (`gcloud`).
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import json
import shutil
import subprocess
import sys
import threading
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

GENAI_SERVICE = "generativelanguage.googleapis.com"
VERTEX_SERVICE = "aiplatform.googleapis.com"
VALIDATION_SWEEP_MAX_CALLS = 10

# Métodos RPC de inferência/geração em generativelanguage.googleapis.com (e aiplatform)
GENAI_INFERENCE_METHOD_SUFFIXES = (
    "generatecontent",
    "streamgeneratecontent",
    "asyncgeneratecontent",
    "bidigeneratecontent",
    "batchgeneratecontent",
    "asyncbatchgeneratecontent",
    "generateanswer",
    "generatetext",
    "generateembeddings",
    "embedcontent",
    "batchembedcontents",
    "predict",
    "predictlongrunning",
    "rawpredict",
    "streamrawpredict",
    "chatcompletions",
    "generatevideo",
)

# Métodos RPC de reconhecimento / Target Scoping documentados pelo GTIG / Mandiant (Nov/2026)
GENAI_RECON_METHOD_SUFFIXES = (
    "listmodels",
    "getmodel",
    "listtunedmodels",
    "gettunedmodel",
    "listpublishermodels",
    "getpublishermodel",
    "listendpoints",
    "getendpoint",
)


@dataclass
class GenAIProjectInfo:
    project_id: str
    project_number: str
    genai_enabled: bool = False
    vertex_enabled: bool = False
    billing_enabled: str = "UNKNOWN"  # TRUE, FALSE, UNKNOWN
    billing_account: str = ""


@dataclass
class ApiKeyRecord:
    project_id: str
    project_number: str
    uid: str
    display_name: str
    create_time: str
    update_time: str
    api_scope_status: str  # UNRESTRICTED_ALL_APIS, EXPLICIT_GENAI_TARGET
    target_services: list[str]
    client_restriction_type: str  # OPEN_ANY_IP_OR_APP, IP_RESTRICTED, REFERRER_RESTRICTED, APP_RESTRICTED
    client_restriction_detail: str
    bound_sa_email: str = ""
    bound_sa_unique_id: str = ""


@dataclass
class KeyCallTelemetry:
    total_calls: int = 0
    ok_2xx_calls: int = 0
    error_calls: int = 0
    recon_calls: int = 0
    methods: set[str] = field(default_factory=set)
    recon_methods: set[str] = field(default_factory=set)
    services_used: set[str] = field(default_factory=set)


@dataclass
class ApiKeyFinding:
    risk_status: str
    inference_activity_status: str
    project_id: str
    billing_enabled: str
    key_uid: str
    display_name: str
    api_scope_status: str
    client_restriction_type: str
    client_restriction_detail: str
    bound_sa_email: str
    created_at: str
    inference_calls_window: int
    ok_2xx_calls_window: int
    error_calls_window: int
    methods_called: list[str]
    enabled_ai_apis: list[str]
    containment_command: str
    recon_calls_window: int = 0
    recon_methods_called: list[str] = field(default_factory=list)
    gtig_threat_signals: list[str] = field(default_factory=list)


class GcloudError(RuntimeError):
    """Erro ao executar comando gcloud ou API GCP."""


class GcloudRunner:

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
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        if (
            proc.returncode != 0
            and self.billing_project
            and "SERVICE_DISABLED" in (proc.stderr or "")
        ):
            # Fallback para quota padrão do gcloud SDK caso a API auxiliar (ex: apikeys.googleapis.com)
            # não esteja habilitada no `--billing-project` informado.
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
            raise GcloudError(
                f"Falha em `gcloud {' '.join(args[:3])}...`: {(proc.stderr or '').strip()}"
            )
        out = (proc.stdout or "").strip()
        return json.loads(out) if out else []

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
                    f"Erro em `gcloud auth print-access-token`: {(proc.stderr or '').strip()}"
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
        timeout: int = 90,
    ) -> list[dict[str, Any]]:
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
                "aggregation.perSeriesAligner": "ALIGN_SUM",
                "aggregation.crossSeriesReducer": "REDUCE_SUM",
                "aggregation.groupByFields": group_by_fields,
                "view": "FULL",
                "pageSize": "500",
            }
            if page_token:
                params["pageToken"] = page_token
            url = f"{base_url}?{urllib.parse.urlencode(params, doseq=True)}"
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
                    f"Cloud Monitoring HTTP {exc.code} em `{project_id}`: {err_body[:250]}"
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


def is_genai_inference_method(method_name: str) -> bool:
    if not method_name:
        return False
    short = method_name.rsplit(".", 1)[-1].rsplit("/", 1)[-1].lower()
    return short in GENAI_INFERENCE_METHOD_SUFFIXES


def is_genai_recon_method(method_name: str) -> bool:
    if not method_name:
        return False
    short = method_name.rsplit(".", 1)[-1].rsplit("/", 1)[-1].lower()
    return short in GENAI_RECON_METHOD_SUFFIXES


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


def evaluate_key_restrictions(
    restrictions: dict[str, Any] | None,
    proj: GenAIProjectInfo,
    include_vertex_express: bool,
) -> tuple[str | None, list[str], str, str]:
    """Avalia se a API Key alcança `generativelanguage.googleapis.com` (ou Vertex)
    e qual é o nível de restrição de rede/cliente.

    Retorna `(api_scope_status, target_services, client_type, client_detail)`.
    Se `api_scope_status` for `None`, a chave está restrita a outras APIs não-IA.
    """
    restr = restrictions or {}
    api_targets = restr.get("apiTargets") or []

    allowed_ai_services: set[str] = set()
    if proj.genai_enabled:
        allowed_ai_services.add(GENAI_SERVICE)
    if include_vertex_express and proj.vertex_enabled:
        allowed_ai_services.add(VERTEX_SERVICE)

    if not allowed_ai_services:
        return None, [], "", ""

    if not api_targets:
        api_scope = "UNRESTRICTED_ALL_APIS"
        targets_list = ["* (TODAS AS APIS DO PROJETO)"]
    else:
        targets_list = [
            t.get("service", "") for t in api_targets if t.get("service")
        ]
        matched_ai = False
        for t in api_targets:
            svc = t.get("service", "")
            if svc in allowed_ai_services:
                methods = t.get("methods") or []
                if not methods or any(
                    "*" in m or is_genai_inference_method(m) for m in methods
                ):
                    matched_ai = True
        if not matched_ai:
            return None, targets_list, "", ""
        api_scope = "EXPLICIT_GENAI_TARGET"

    # Avalia restrições de cliente / rede
    server_r = restr.get("serverKeyRestrictions") or {}
    browser_r = restr.get("browserKeyRestrictions") or {}
    android_r = restr.get("androidKeyRestrictions") or {}
    ios_r = restr.get("iosKeyRestrictions") or {}

    if server_r.get("allowedIps"):
        ips = list(server_r["allowedIps"])
        if any(ip in ("0.0.0.0/0", "::/0", "*") for ip in ips):
            return api_scope, targets_list, "OPEN_WILDCARD_IP", ", ".join(ips)
        return api_scope, targets_list, "IP_RESTRICTED", ", ".join(ips)

    if browser_r.get("allowedReferrers"):
        refs = list(browser_r["allowedReferrers"])
        if any(r in ("*", "*/*", "http://*", "https://*") for r in refs):
            return (
                api_scope,
                targets_list,
                "OPEN_WILDCARD_REFERRER",
                ", ".join(refs),
            )
        return api_scope, targets_list, "REFERRER_RESTRICTED", ", ".join(refs)

    if android_r.get("allowedApplications"):
        pkgs = [
            a.get("packageName", "")
            for a in android_r["allowedApplications"]
        ]
        return api_scope, targets_list, "ANDROID_RESTRICTED", ", ".join(pkgs)

    if ios_r.get("allowedBundleIds"):
        bundles = list(ios_r["allowedBundleIds"])
        return api_scope, targets_list, "IOS_RESTRICTED", ", ".join(bundles)

    return api_scope, targets_list, "OPEN_ANY_IP_OR_APP", "Nenhuma restrição de IP/App"


def run_cai_api_key_discovery(
    runner: GcloudRunner,
    scope: str,
    include_vertex_express: bool = False,
) -> tuple[dict[str, GenAIProjectInfo], list[ApiKeyRecord]]:
    print(
        f"[1/4] Buscando projetos ativos e status de faturamento em `{scope}`...",
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

    id_to_proj: dict[str, GenAIProjectInfo] = {}
    num_to_proj: dict[str, GenAIProjectInfo] = {}
    for item in raw_projects:
        versioned = item.get("versionedResources") or []
        res = versioned[0].get("resource", {}) if versioned else {}
        add_attrs = item.get("additionalAttributes") or {}
        pid = (
            res.get("projectId")
            or add_attrs.get("projectId")
            or item.get("name", "").rsplit("/", 1)[-1]
        )
        pnum = str(
            res.get("projectNumber")
            or item.get("project", "").replace("projects/", "")
        )
        if not pid:
            continue
        p_info = GenAIProjectInfo(project_id=pid, project_number=pnum)
        id_to_proj[pid] = p_info
        if pnum:
            num_to_proj[pnum] = p_info

    # Enriquece status de Billing (PAYG vs Free Tier)
    try:
        raw_billing = runner.run_json([
            "asset",
            "search-all-resources",
            f"--scope={scope}",
            "--asset-types=cloudbilling.googleapis.com/ProjectBillingInfo",
            "--page-size=500",
            "--read-mask=*",
        ])
        for b_item in raw_billing:
            v_res = b_item.get("versionedResources") or []
            b_res = v_res[0].get("resource", {}) if v_res else {}
            pid = b_res.get("projectId") or b_item.get(
                "parentFullResourceName", ""
            ).rsplit("/", 1)[-1]
            p_info = id_to_proj.get(pid)
            if p_info:
                enabled = b_res.get("billingEnabled")
                p_info.billing_enabled = "TRUE" if enabled else "FALSE"
                p_info.billing_account = b_res.get("billingAccountName", "")
    except GcloudError:
        pass

    svc_query = f"name:{GENAI_SERVICE} AND state:ENABLED"
    if include_vertex_express:
        svc_query = (
            f"(name:{GENAI_SERVICE} OR name:{VERTEX_SERVICE}) AND state:ENABLED"
        )

    print(
        f"[2/4] Identificando projetos com `{GENAI_SERVICE}` habilitado...",
        file=sys.stderr,
    )
    raw_services = runner.run_json([
        "asset",
        "search-all-resources",
        f"--scope={scope}",
        "--asset-types=serviceusage.googleapis.com/Service",
        f"--query={svc_query}",
        "--page-size=500",
    ])
    for svc in raw_services:
        pnum = svc.get("project", "").replace("projects/", "")
        p_info = num_to_proj.get(pnum) or id_to_proj.get(pnum)
        if not p_info:
            continue
        if svc.get("name", "").endswith(f"/{GENAI_SERVICE}"):
            p_info.genai_enabled = True
        if svc.get("name", "").endswith(f"/{VERTEX_SERVICE}"):
            p_info.vertex_enabled = True

    ai_projects = [
        p
        for p in id_to_proj.values()
        if p.genai_enabled or (include_vertex_express and p.vertex_enabled)
    ]
    print(
        f"      -> {len(ai_projects)} projeto(s) possuem a API habilitada.",
        file=sys.stderr,
    )
    if not ai_projects:
        return id_to_proj, []

    print(
        f"[3/4] Inventariando API Keys (`apikeys.googleapis.com/Key`) em `{scope}`...",
        file=sys.stderr,
    )
    raw_keys = runner.run_json([
        "asset",
        "search-all-resources",
        f"--scope={scope}",
        "--asset-types=apikeys.googleapis.com/Key",
        "--page-size=500",
        "--read-mask=*",
    ])

    # Mapeia uniqueId de SAs caso alguma API key v2 tenha `serviceAccountEmail`
    email_to_uid: dict[str, str] = {}
    if any(
        ((k.get("versionedResources") or [{}])[0].get("resource") or {}).get(
            "serviceAccountEmail"
        )
        for k in raw_keys
    ):
        try:
            raw_sas = runner.run_json([
                "asset",
                "search-all-resources",
                f"--scope={scope}",
                "--asset-types=iam.googleapis.com/ServiceAccount",
                "--page-size=500",
                "--read-mask=additionalAttributes,versionedResources",
            ])
            for sa_item in raw_sas:
                v_sa = sa_item.get("versionedResources") or []
                r_sa = v_sa[0].get("resource", {}) if v_sa else {}
                a_sa = sa_item.get("additionalAttributes") or {}
                em = str(r_sa.get("email") or a_sa.get("email") or "")
                uid = str(r_sa.get("uniqueId") or a_sa.get("uniqueId") or "")
                if em and uid:
                    email_to_uid[em] = uid
        except GcloudError:
            pass

    exposed_records: list[ApiKeyRecord] = []
    for k_item in raw_keys:
        v_res = k_item.get("versionedResources") or []
        res = v_res[0].get("resource", {}) if v_res else {}
        pnum = k_item.get("project", "").replace("projects/", "")
        parent_pid = k_item.get("parentFullResourceName", "").rsplit("/", 1)[-1]
        p_info = id_to_proj.get(parent_pid) or num_to_proj.get(pnum)
        if not p_info:
            continue

        api_scope, targets, client_type, client_detail = (
            evaluate_key_restrictions(
                res.get("restrictions"), p_info, include_vertex_express
            )
        )
        if api_scope is None:
            continue

        uid = res.get("uid") or k_item.get("name", "").rsplit("/", 1)[-1]
        sa_email = res.get("serviceAccountEmail", "")
        exposed_records.append(
            ApiKeyRecord(
                project_id=p_info.project_id,
                project_number=p_info.project_number,
                uid=uid,
                display_name=res.get("displayName")
                or k_item.get("displayName", ""),
                create_time=res.get("createTime")
                or k_item.get("createTime", ""),
                update_time=res.get("updateTime")
                or k_item.get("updateTime", ""),
                api_scope_status=api_scope,
                target_services=targets,
                client_restriction_type=client_type,
                client_restriction_detail=client_detail,
                bound_sa_email=sa_email,
                bound_sa_unique_id=email_to_uid.get(sa_email, ""),
            )
        )

    print(
        f"      -> {len(exposed_records)} de {len(raw_keys)} API Key(s) alcançam a API de IA generativa.",
        file=sys.stderr,
    )
    return id_to_proj, exposed_records


def run_direct_api_key_discovery(
    runner: GcloudRunner,
    project_ids: list[str],
    include_vertex_express: bool = False,
    workers: int = 8,
) -> tuple[dict[str, GenAIProjectInfo], list[ApiKeyRecord]]:
    print(
        f"[1/3] Inspecionando {len(project_ids)} projeto(s) em modo direto...",
        file=sys.stderr,
    )
    id_to_proj: dict[str, GenAIProjectInfo] = {}

    def inspect_proj(pid: str) -> GenAIProjectInfo | None:
        try:
            desc = runner.run_json(["projects", "describe", pid], timeout=60)
            if desc.get("lifecycleState") != "ACTIVE":
                return None
            pnum = str(desc.get("projectNumber", ""))
            f_expr = f"config.name={GENAI_SERVICE}"
            if include_vertex_express:
                f_expr = f"config.name=({GENAI_SERVICE} OR {VERTEX_SERVICE})"
            svcs = runner.run_json(
                [
                    "services",
                    "list",
                    "--enabled",
                    f"--project={pid}",
                    f"--filter={f_expr}",
                ],
                timeout=90,
            )
            enabled_names = {
                (s.get("config") or {}).get("name", "") for s in svcs
            }
            p_info = GenAIProjectInfo(
                project_id=pid,
                project_number=pnum,
                genai_enabled=GENAI_SERVICE in enabled_names,
                vertex_enabled=VERTEX_SERVICE in enabled_names,
            )
            if p_info.genai_enabled or (
                include_vertex_express and p_info.vertex_enabled
            ):
                try:
                    b_desc = runner.run_json(
                        ["billing", "projects", "describe", pid], timeout=30
                    )
                    p_info.billing_enabled = (
                        "TRUE" if b_desc.get("billingEnabled") else "FALSE"
                    )
                    p_info.billing_account = b_desc.get(
                        "billingAccountName", ""
                    )
                except GcloudError:
                    pass
            return p_info
        except GcloudError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([
            pool.submit(inspect_proj, pid) for pid in project_ids
        ]):
            res = fut.result()
            if res:
                id_to_proj[res.project_id] = res

    ai_projects = [
        p
        for p in id_to_proj.values()
        if p.genai_enabled or (include_vertex_express and p.vertex_enabled)
    ]
    print(
        f"      -> {len(ai_projects)} projeto(s) possuem a API habilitada.",
        file=sys.stderr,
    )
    if not ai_projects:
        return id_to_proj, []

    print(
        f"[2/3] Listando API Keys nos {len(ai_projects)} projeto(s)...",
        file=sys.stderr,
    )
    records: list[ApiKeyRecord] = []
    for p_info in ai_projects:
        try:
            raw_keys = runner.run_json(
                [
                    "services",
                    "api-keys",
                    "list",
                    f"--project={p_info.project_id}",
                ],
                timeout=60,
            )
        except GcloudError as exc:
            print(
                f"[AVISO] Sem permissão para listar API Keys em `{p_info.project_id}`: {exc}",
                file=sys.stderr,
            )
            continue

        for res in raw_keys:
            api_scope, targets, client_type, client_detail = (
                evaluate_key_restrictions(
                    res.get("restrictions"), p_info, include_vertex_express
                )
            )
            if api_scope is None:
                continue
            uid = res.get("uid") or res.get("name", "").rsplit("/", 1)[-1]
            sa_email = res.get("serviceAccountEmail", "")
            sa_uid = ""
            if sa_email:
                try:
                    sa_desc = runner.run_json(
                        ["iam", "service-accounts", "describe", sa_email],
                        timeout=30,
                    )
                    sa_uid = str(sa_desc.get("uniqueId") or "")
                except GcloudError:
                    pass
            records.append(
                ApiKeyRecord(
                    project_id=p_info.project_id,
                    project_number=p_info.project_number,
                    uid=uid,
                    display_name=res.get("displayName", ""),
                    create_time=res.get("createTime", ""),
                    update_time=res.get("updateTime", ""),
                    api_scope_status=api_scope,
                    target_services=targets,
                    client_restriction_type=client_type,
                    client_restriction_detail=client_detail,
                    bound_sa_email=sa_email,
                    bound_sa_unique_id=sa_uid,
                )
            )
    return id_to_proj, records


def _sum_points(points: list[dict[str, Any]]) -> int:
    total = 0
    for pt in points:
        val = pt.get("value") or {}
        if "int64Value" in val:
            total += int(val["int64Value"])
        elif "doubleValue" in val:
            total += int(round(float(val["doubleValue"])))
    return total


def enrich_api_keys_with_monitoring(
    runner: GcloudRunner,
    records: list[ApiKeyRecord],
    include_vertex_express: bool = False,
    lookback_days: int = 14,
    now: datetime | None = None,
    workers: int = 6,
) -> dict[str, KeyCallTelemetry]:
    """Consulta `serviceruntime.googleapis.com/api/request_count` para identificar
    chamadas reais de inferência por `apikey:<uid>` (e `serviceaccount:<bound_sa_uid>`).
    """
    if not records:
        return {}

    ref_now = now or datetime.now(timezone.utc)
    start_iso = (ref_now - timedelta(days=lookback_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    end_iso = ref_now.strftime("%Y-%m-%dT%H:%M:%SZ")

    telemetry_by_uid: dict[str, KeyCallTelemetry] = {
        r.uid: KeyCallTelemetry() for r in records
    }
    sa_uid_to_key_uids: dict[str, set[str]] = {}
    for r in records:
        if r.bound_sa_unique_id:
            sa_uid_to_key_uids.setdefault(r.bound_sa_unique_id, set()).add(
                r.uid
            )

    projects = sorted({r.project_id for r in records})
    print(
        f"[+] Verificando chamadas REAIS de inferência por API Key (Cloud Monitoring `serviceruntime`, "
        f"últimos {lookback_days}d) em {len(projects)} projeto(s)...",
        file=sys.stderr,
    )

    if include_vertex_express:
        svc_clause = f'(resource.labels.service="{GENAI_SERVICE}" OR resource.labels.service="{VERTEX_SERVICE}")'
    else:
        svc_clause = f'resource.labels.service="{GENAI_SERVICE}"'

    metric_filter = (
        'metric.type="serviceruntime.googleapis.com/api/request_count" '
        f'AND resource.type="consumed_api" AND {svc_clause}'
    )

    def query_proj(pid: str) -> list[dict[str, Any]]:
        try:
            return runner.list_monitoring_timeseries(
                project_id=pid,
                metric_filter=metric_filter,
                start_time_iso=start_iso,
                end_time_iso=end_iso,
                group_by_fields=[
                    "resource.labels.credential_id",
                    "resource.labels.service",
                    "resource.labels.method",
                    "metric.labels.response_code_class",
                ],
            )
        except GcloudError:
            return []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(query_proj, p) for p in projects]):
            for ts in fut.result():
                r_labels = (ts.get("resource") or {}).get("labels") or {}
                m_labels = (ts.get("metric") or {}).get("labels") or {}
                cred_id = r_labels.get("credential_id", "")
                method = r_labels.get("method", "")
                svc = r_labels.get("service", "")
                resp_class = m_labels.get("response_code_class", "")

                is_inf = is_genai_inference_method(method)
                is_rec = False if is_inf else is_genai_recon_method(method)
                if not is_inf and not is_rec:
                    continue

                matched_uids: set[str] = set()
                if cred_id.startswith("apikey:"):
                    k_uid = cred_id.split(":", 1)[1]
                    if k_uid in telemetry_by_uid:
                        matched_uids.add(k_uid)
                elif cred_id.startswith("serviceaccount:"):
                    s_uid = cred_id.split(":", 1)[1]
                    matched_uids.update(sa_uid_to_key_uids.get(s_uid, set()))

                if not matched_uids:
                    continue

                cnt = _sum_points(ts.get("points") or [])
                if cnt <= 0:
                    continue

                for k_uid in matched_uids:
                    tel = telemetry_by_uid[k_uid]
                    if is_inf:
                        tel.total_calls += cnt
                        if resp_class == "2xx" or not resp_class:
                            tel.ok_2xx_calls += cnt
                        else:
                            tel.error_calls += cnt
                        tel.methods.add(short_method_name(method))
                    else:
                        tel.recon_calls += cnt
                        tel.recon_methods.add(short_method_name(method))
                    if svc:
                        tel.services_used.add(svc)

    return telemetry_by_uid


def build_api_key_findings(
    id_to_proj: dict[str, GenAIProjectInfo],
    records: list[ApiKeyRecord],
    telemetry_by_uid: dict[str, KeyCallTelemetry],
    check_usage: bool = True,
    lookback_days: int = 14,
    now: datetime | None = None,
) -> list[ApiKeyFinding]:
    ref_now = now or datetime.now(timezone.utc)
    window_start = ref_now - timedelta(days=lookback_days)
    findings: list[ApiKeyFinding] = []
    for r in records:
        p_info = id_to_proj[r.project_id]
        tel = telemetry_by_uid.get(r.uid, KeyCallTelemetry())

        enabled_apis: list[str] = []
        if p_info.genai_enabled:
            enabled_apis.append(GENAI_SERVICE)
        if p_info.vertex_enabled:
            enabled_apis.append(VERTEX_SERVICE)

        if not check_usage:
            act_status = "NOT_CHECKED"
        elif tel.total_calls > 0:
            act_status = "CONFIRMED_KEY_INFERENCE"
        elif tel.recon_calls > 0:
            act_status = "RECON_SCOPING_DETECTED"
        else:
            act_status = "EXPOSED_NO_RECENT_CALLS"

        is_open_net = r.client_restriction_type.startswith("OPEN_")
        if act_status == "CONFIRMED_KEY_INFERENCE":
            risk = "P0_ACTIVE_API_KEY_DOING_INFERENCE"
        elif p_info.billing_enabled == "TRUE" and is_open_net:
            risk = "CRITICAL_PAYG_OPEN_KEY"
        elif p_info.billing_enabled == "FALSE":
            risk = "MEDIUM_FREE_TIER_KEY"
        elif is_open_net:
            risk = "HIGH_OPEN_KEY_UNKNOWN_BILLING"
        else:
            risk = "MODERATE_CLIENT_RESTRICTED_KEY"

        gtig_signals: list[str] = []
        if check_usage and 1 <= tel.total_calls <= VALIDATION_SWEEP_MAX_CALLS:
            gtig_signals.append("POSSIBLE_VALIDATION_SWEEP_1_TO_10_CALLS")
        if check_usage and tel.recon_calls > 0:
            gtig_signals.append(
                f"TARGET_SCOPING_RECON({','.join(sorted(tel.recon_methods))})"
            )
        created_dt = parse_iso_timestamp(r.create_time)
        if created_dt is not None and created_dt >= window_start:
            gtig_signals.append("RECENT_API_KEY_CREATED_IN_WINDOW")

        # Contenção reversível: bloqueia tráfego externo restringindo a chave p/ loopback 127.0.0.1
        # (ou `api-keys delete`, que possui janela de 30 dias para `undelete`).
        contain_cmd = (
            f"gcloud services api-keys update projects/{r.project_id}/locations/global/keys/{r.uid} "
            "--allowed-ips=127.0.0.1"
        )

        findings.append(
            ApiKeyFinding(
                risk_status=risk,
                inference_activity_status=act_status,
                project_id=r.project_id,
                billing_enabled=p_info.billing_enabled,
                key_uid=r.uid,
                display_name=r.display_name,
                api_scope_status=r.api_scope_status,
                client_restriction_type=r.client_restriction_type,
                client_restriction_detail=r.client_restriction_detail,
                bound_sa_email=r.bound_sa_email,
                created_at=r.create_time,
                inference_calls_window=tel.total_calls,
                ok_2xx_calls_window=tel.ok_2xx_calls,
                error_calls_window=tel.error_calls,
                methods_called=sorted(tel.methods),
                enabled_ai_apis=enabled_apis,
                containment_command=contain_cmd,
                recon_calls_window=tel.recon_calls,
                recon_methods_called=sorted(tel.recon_methods),
                gtig_threat_signals=gtig_signals,
            )
        )

    rank = {
        "P0_ACTIVE_API_KEY_DOING_INFERENCE": 0,
        "CRITICAL_PAYG_OPEN_KEY": 1,
        "HIGH_OPEN_KEY_UNKNOWN_BILLING": 2,
        "MODERATE_CLIENT_RESTRICTED_KEY": 3,
        "MEDIUM_FREE_TIER_KEY": 4,
    }
    findings.sort(
        key=lambda f: (
            rank.get(f.risk_status, 9),
            -f.inference_calls_window,
            -f.recon_calls_window,
            f.project_id,
            f.key_uid,
        )
    )
    return findings


def print_summary(findings: list[ApiKeyFinding], lookback_days: int) -> None:
    if not findings:
        print(
            "\n✅ Nenhuma API Key exposta ao `generativelanguage.googleapis.com` foi encontrada no escopo analisado."
        )
        return

    p0 = sum(
        1
        for f in findings
        if f.risk_status == "P0_ACTIVE_API_KEY_DOING_INFERENCE"
    )
    crit = sum(
        1 for f in findings if f.risk_status == "CRITICAL_PAYG_OPEN_KEY"
    )
    print("\n" + "=" * 138)
    print(
        f"🚨 AUDITORIA GEMINI API KEYS (`{GENAI_SERVICE}` | Janela: {lookback_days}d): "
        f"{p0} chave(s) FAZENDO INFERÊNCIA | "
        f"{crit} chave(s) ABERTA(S) c/ Billing Ativo | "
        f"{len(findings)} total"
    )
    print("=" * 138)
    header = (
        f"{'RISCO / STATUS':<33} {'PROJETO (BILLING)':<28} {'KEY UID (12c)':<14} "
        f"{'ESCOPO API':<23} {'RESTRIÇÃO REDE/APP':<22} {'CHAMADAS':>10}"
    )
    print(header)
    print("-" * 138)
    for f in findings:
        proj_col = f"{f.project_id[:19]} ({f.billing_enabled})"
        short_uid = f.key_uid[:12]
        print(
            f"{f.risk_status:<33} {proj_col:<28} {short_uid:<14} "
            f"{f.api_scope_status:<23} {f.client_restriction_type:<22} "
            f"{f.inference_calls_window:>10,}"
        )
    print("=" * 138)

    flagged = [f for f in findings if f.gtig_threat_signals]
    if flagged:
        print(
            f"⚠️  SINAIS TÁTICOS GTIG / MANDIANT DETECTADOS EM {len(flagged)} API KEY(S):"
        )
        for f in flagged[:10]:
            print(
                f"   - {f.project_id} / `{f.key_uid[:12]}`: {', '.join(f.gtig_threat_signals)}"
            )
        if any(
            "POSSIBLE_VALIDATION_SWEEP_1_TO_10_CALLS" in f.gtig_threat_signals
            for f in flagged
        ):
            print(
                "   [!] ATENÇÃO: Baixo volume (1–10 chamadas) pode indicar 'Validation Sweep' (teste de 1 token) "
                "para enfileirar a credencial como reserva em proxies LLM Mixer (`new-api` / `gcli2api`). Não ignore como ruído!"
            )
        print("=" * 138)


def write_reports(
    findings: list[ApiKeyFinding], csv_path: str, json_path: str
) -> None:
    if csv_path:
        fields = [
            "risk_status",
            "inference_activity_status",
            "project_id",
            "billing_enabled",
            "key_uid",
            "display_name",
            "api_scope_status",
            "client_restriction_type",
            "client_restriction_detail",
            "bound_sa_email",
            "created_at",
            "inference_calls_window",
            "ok_2xx_calls_window",
            "error_calls_window",
            "methods_called",
            "recon_calls_window",
            "recon_methods_called",
            "gtig_threat_signals",
            "enabled_ai_apis",
            "containment_command",
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=fields)
            writer.writeheader()
            for f in findings:
                row = asdict(f)
                row["methods_called"] = "; ".join(row["methods_called"])
                row["recon_methods_called"] = "; ".join(
                    row["recon_methods_called"]
                )
                row["gtig_threat_signals"] = "; ".join(
                    row["gtig_threat_signals"]
                )
                row["enabled_ai_apis"] = "; ".join(row["enabled_ai_apis"])
                writer.writerow(row)
        print(f"[+] Relatório CSV salvo em: {csv_path}", file=sys.stderr)

    if json_path:
        payload = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "p0_active_api_keys_doing_inference": sum(
                1
                for f in findings
                if f.risk_status == "P0_ACTIVE_API_KEY_DOING_INFERENCE"
            ),
            "critical_payg_open_keys": sum(
                1 for f in findings if f.risk_status == "CRITICAL_PAYG_OPEN_KEY"
            ),
            "keys_with_gtig_threat_signals": sum(
                1 for f in findings if f.gtig_threat_signals
            ),
            "findings": [asdict(f) for f in findings],
        }
        with open(json_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, ensure_ascii=False)
        print(f"[+] Relatório JSON salvo em: {json_path}", file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Identifica API Keys (`apikeys.googleapis.com/Key`) expostas e em uso "
            "no `generativelanguage.googleapis.com` (Resposta rápida a LLMJacking)."
        )
    )
    scope_group = parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument(
        "--org", metavar="ORG_ID", help="ID numérico da Organização GCP."
    )
    scope_group.add_argument(
        "--folder", metavar="FOLDER_ID", help="ID numérico da Pasta GCP."
    )
    scope_group.add_argument(
        "--projects",
        metavar="PROJ1,PROJ2",
        help="Lista de Project IDs separados por vírgula.",
    )
    scope_group.add_argument(
        "--all-accessible-projects",
        action="store_true",
        help="Varre todos os projetos ativos visíveis (`gcloud projects list`).",
    )

    parser.add_argument(
        "--mode",
        choices=("auto", "cai", "direct"),
        default="auto",
        help="Modo de coleta (`cai` padrão p/ --org/--folder; `direct` padrão p/ projetos).",
    )
    parser.add_argument(
        "--lookback-days",
        type=int,
        default=14,
        help="Janela em dias no Cloud Monitoring para medir chamadas reais (padrão: 14, máx: 42).",
    )
    parser.add_argument(
        "--only-confirmed-inference",
        action="store_true",
        help="Filtra apenas API Keys com chamadas de inferência confirmadas na janela.",
    )
    parser.add_argument(
        "--include-vertex-express",
        action="store_true",
        help="Inclui também API Keys liberadas para `aiplatform.googleapis.com` (Gemini Enterprise Agent Platform / Vertex AI Express Mode).",
    )
    parser.add_argument(
        "--skip-inference-usage",
        action="store_true",
        help="Pula consulta de chamadas reais no Cloud Monitoring.",
    )
    parser.add_argument(
        "--billing-project",
        metavar="PROJECT_ID",
        help="Projeto para cota das APIs (`--billing-project` / `X-Goog-User-Project`).",
    )
    parser.add_argument(
        "--csv",
        default="genai_api_keys_audit.csv",
        help="Caminho do relatório CSV (padrão: genai_api_keys_audit.csv).",
    )
    parser.add_argument(
        "--json",
        default="genai_api_keys_audit.json",
        help="Caminho do relatório JSON (padrão: genai_api_keys_audit.json).",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Logs detalhados no stderr."
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    lookback = max(1, min(args.lookback_days, 42))
    runner = GcloudRunner(
        billing_project=args.billing_project, verbose=args.verbose
    )
    mode = (
        ("cai" if (args.org or args.folder) else "direct")
        if args.mode == "auto"
        else args.mode
    )

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
                raw = runner.run_json([
                    "projects",
                    "list",
                    "--filter=lifecycleState:ACTIVE",
                ])
                scopes = [f"projects/{p['projectId']}" for p in raw]

            merged_projs: dict[str, GenAIProjectInfo] = {}
            merged_records: list[ApiKeyRecord] = []
            seen_uids: set[str] = set()
            for sc in scopes:
                pmap, recs = run_cai_api_key_discovery(
                    runner, sc, args.include_vertex_express
                )
                merged_projs.update(pmap)
                for r in recs:
                    if r.uid not in seen_uids:
                        seen_uids.add(r.uid)
                        merged_records.append(r)
        else:
            if args.org or args.folder:
                pid = (args.org or args.folder).split("/")[-1]
                raw = runner.run_json([
                    "projects",
                    "list",
                    f"--filter=parent.id={pid} AND lifecycleState=ACTIVE",
                ])
                project_ids = [p["projectId"] for p in raw]
            elif args.projects:
                project_ids = [
                    p.strip() for p in args.projects.split(",") if p.strip()
                ]
            else:
                raw = runner.run_json([
                    "projects",
                    "list",
                    "--filter=lifecycleState:ACTIVE",
                ])
                project_ids = [p["projectId"] for p in raw]

            merged_projs, merged_records = run_direct_api_key_discovery(
                runner, project_ids, args.include_vertex_express
            )

        tel_map: dict[str, KeyCallTelemetry] = {}
        if not args.skip_inference_usage and merged_records:
            tel_map = enrich_api_keys_with_monitoring(
                runner=runner,
                records=merged_records,
                include_vertex_express=args.include_vertex_express,
                lookback_days=lookback,
            )

        findings = build_api_key_findings(
            merged_projs,
            merged_records,
            tel_map,
            check_usage=not args.skip_inference_usage,
            lookback_days=lookback,
        )
        if args.only_confirmed_inference:
            findings = [
                f
                for f in findings
                if f.inference_activity_status
                in ("CONFIRMED_KEY_INFERENCE", "RECON_SCOPING_DETECTED")
            ]

        print_summary(findings, lookback_days=lookback)
        write_reports(findings, args.csv, args.json)
        return 0
    except GcloudError as exc:
        print(f"\n[ERRO] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
