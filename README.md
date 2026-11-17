# GCP LLMJacking Credential Audit Toolkit

> [!WARNING]
> **Aviso Importante — Ferramenta Não Oficial ("As-Is"):** Este repositório contém utilitários de referência independentes, fornecidos "no estado em que se encontram" (*as-is*), **sem vínculo com produtos oficiais e sem garantia ou suporte técnico do Google Cloud**. Seu objetivo exclusivo é apoiar equipes de Resposta a Incidentes (CSIRT/SecOps) e Cloud Engineering na **auditoria rápida e somente leitura (*read-only*)** durante uma suspeita de vazamento de credenciais estáticas. Nenhuma alteração, bloqueio ou exclusão de recursos é executada automaticamente pelos scripts.

---

## 1. Contexto e Objetivo

Em incidentes de **LLMJacking** (uso não autorizado de cotas de modelos generativos por meio de credenciais estáticas vazadas), o tempo de triagem é decisivo para estancar custos inesperados (*Denial of Wallet*) e exposição de modelos proprietários. Conforme documentado pelo **Google Threat Intelligence Group (GTIG) / Mandiant** em [*The Rise of LLMJacking: How Threat Actors Monetize Compromised Cloud and Model Resources*](https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models) (Nov/2026), atores de ameaça operam *Validation Sweeps* automatizados (requisições mínimas de 1 token) e proxies agregadores conhecidos como ***LLM Mixers*** (ex.: `new-api`, `gcli2api`) que mantêm dezenas de credenciais em *pool* com *failover* imediato assim que uma chave em uso é bloqueada.

Em ambientes Google Cloud, as equipes de resposta costumam enfrentar quatro dificuldades imediatas:

1. **Pontos cegos na hierarquia IAM e auto-habilitação de APIs:** Uma *Service Account Key* vazada pode residir em um projeto auxiliar (ex.: CI/CD sem APIs de IA habilitadas), mas alcançar projetos produtivos por herança de Organização/Pasta, *Google Groups*, *Custom Roles*, *Impersonation* (`TokenCreator` / `actAs`) — ou até mesmo **habilitar sozinha** a API `aiplatform.googleapis.com` (`ServiceUsage.EnableService`) em projetos dormentes caso acumule permissões amplas (`Editor`/`Owner`).
2. **API Keys antigas ou irrestritas:** Projetos com `generativelanguage.googleapis.com` (Google AI Studio / Gemini Developer API) vinculada a uma conta de faturamento ativa (*Pay-As-You-Go*) podem conter *API Keys* sem restrição de serviço ou de endereço IP.
3. **Ausência de logs `DATA_READ`:** Métodos de inferência (`:generateContent`, `:streamGenerateContent`, `:predict`, `:rawPredict`) são classificados como `DATA_READ` no Cloud Audit Logs e permanecem desabilitados por padrão. Ativá-los após a detecção do incidente não recupera o histórico retroativo do ataque.
4. **Chaves pré-validadas silenciosamente (*Validation Sweeps* e *Target Scoping*):** Credenciais com apenas 1 a 10 chamadas de teste ou apenas chamadas de enumeração (`ListModels`, `ListEndpoints`, `ListPublisherModels`) frequentemente passam despercebidas como "ruído", mas já estão catalogadas em *LLM Mixers* prontas para assumir a carga minutos ou horas após a contenção da primeira chave.

Este repositório reúne dois scripts em **Python 3 padrão + `gcloud` CLI** (sem dependências externas `pip`, prontos para execução imediata no **Google Cloud Shell**):

| Script | Plataforma Alvo | API Auditada | Credencial Analisada |
| :--- | :--- | :--- | :--- |
| **`audit_agent_platform_sa_keys.py`** | **Gemini Enterprise Agent Platform** *(antigo Vertex AI)* | `aiplatform.googleapis.com` | Chaves estáticas `USER_MANAGED` de *Service Accounts* |
| **`audit_genai_api_keys.py`** | **Gemini Developer API / Google AI Studio** *(e Agent Platform Express)* | `generativelanguage.googleapis.com` *(+ opcional `aiplatform.googleapis.com`)* | *API Keys* (`apikeys.googleapis.com/Key`), incluindo chaves irrestritas e chaves vinculadas a SA |

---

## 2. Arquitetura de Coleta (100% Somente Leitura e Sem `DATA_READ`)

Os utilitários correlacionam inventário, permissões efetivas e métricas nativas gratuitas habilitadas por padrão no Google Cloud (com retenção retroativa de até **6 semanas / 42 dias** no Cloud Monitoring e **90 dias** no Policy Analyzer / IAM Insights):

```mermaid
flowchart LR
    subgraph Descoberta["1. Inventário e Exposição (Read-Only)"]
        CAI["Cloud Asset Inventory\n(ou Fallback Direto por Projeto)"]
        IAM["IAM Policy Analyzer\n(Grupos, Pastas, Custom Roles, Impersonation)"]
        BILL["Project Billing Info\n(PAYG vs. Free Tier)"]
    end

    subgraph Telemetria["2. Comprovação de Inferência e Sinais GTIG (Sem DATA_READ)"]
        SR["Cloud Monitoring: serviceruntime\n(Inferência + Target Scoping ListModels/Endpoints)"]
        KEYM["Cloud Monitoring: IAM Key Authn\n(authn_events_count por key_id)"]
        PA["Policy Analyzer & IAM Insights\n(Último uso da chave e exercisedPermissions 90d)"]
        ADM["Cloud Audit Logs: Admin Activity\n(EnableService, CreateServiceAccountKey, SSH Metadata)"]
    end

    subgraph Saida["3. Priorização para Contenção"]
        P0["Relatório Terminal + CSV + JSON\nPriorizado por Uso Confirmado (P0) + Sinais GTIG"]
    end

    CAI --> P0
    IAM --> P0
    BILL --> P0
    SR --> P0
    KEYM --> P0
    PA --> P0
    ADM --> P0
```

### Como o uso real de inferência e os sinais táticos do GTIG são comprovados sem `DATA_READ`?

* **Contagem exata de chamadas de inferência e *Target Scoping* (`serviceruntime.googleapis.com/api/request_count`):** Registra no recurso `consumed_api` o método RPC exato de inferência (`GenerateContent`, `StreamGenerateContent`, `RawPredict`, `Predict`, `CreateBatchPredictionJob`) e de reconhecimento/enumeração (`ListModels`, `GetModel`, `ListEndpoints`, `ListPublisherModels`, `ListTunedModels`), a classe HTTP (`2xx` vs. `4xx`/`429`) e o identificador não sensível da credencial:
  * Service Accounts: `credential_id = "serviceaccount:<SA_UNIQUE_ID>"`
  * API Keys: `credential_id = "apikey:<KEY_UID>"`
* **Detecção de *Validation Sweeps* (`1 <= chamadas <= 10`):** Sinaliza automaticamente `POSSIBLE_VALIDATION_SWEEP_1_TO_10_CALLS` para impedir que testes silenciosos de 1 token (usados para validar e enfileirar chaves em *LLM Mixers*) sejam descartados como ruído operacional.
* **Isolamento de `key_id` específica (`iam.googleapis.com/service_account/key/authn_events_count` + Policy Analyzer):** Quando uma mesma Service Account possui mais de uma chave `.json` (ou também executa workloads legítimos via GCE/GKE Workload Identity), contabiliza quantas autenticações cada `key_id` realizou na janela analisada.
* **Rastreio de Persistência e Auto-Habilitação (`cloudaudit.googleapis.com%2Factivity`):** Consulta os *Admin Activity Logs* (sempre ativos e gratuitos por padrão no GCP, com *fail-open* caso o operador não possua `roles/logging.viewer`) em busca de habilitação recente de APIs de IA (`EnableService` / `BatchEnableServices`), criação lateral de novas chaves/contas (`CreateServiceAccountKey`, `CreateServiceAccount`, `ApiKeys.CreateKey`) e injeção de chaves SSH em metadados de VMs (`setCommonInstanceMetadata` / `setMetadata`).

> [!NOTE]
> **Por que existem os status `SA_ACTIVE_VERIFY_KEY` e `RECON_SCOPING_VERIFY_KEY`?** A métrica que conta chamadas ao Gemini Enterprise Agent Platform (Vertex AI) atualiza em **~2 minutos**, mas informa apenas **qual Service Account** fez as chamadas (sem dizer qual arquivo `.json` foi usado). Já a métrica do IAM que informa **qual chave `.json` específica (`key_id`)** fez login leva de **1 a 3 horas** para consolidar eventos recentes. Por isso, quando a Service Account já aparece fazendo chamadas reais de IA (ou chamadas de enumeração `ListModels`), mas a chave `.json` ainda marca zero autenticações, o script alerta imediatamente no topo — indicando **(a) um ataque muito recente (< 3h)** em que o relatório da chave ainda não fechou, ou **(b) que essa SA roda legitimamente dentro do GCP sem chave `.json`** (ex.: GKE, Cloud Run ou VM) e possui uma chave `.json` antiga esquecida na conta.

---

## 3. Escopo de Testes Validados e Limitações

### 3.1 Cenários Cobertos e Validados

| Vetor / Cenário | `audit_agent_platform_sa_keys.py` | `audit_genai_api_keys.py` | Comportamento Validado |
| :--- | :---: | :---: | :--- |
| **Permissão direta em projeto com IA habilitada** | Sim | Sim | Identifica chaves `USER_MANAGED` (`aiplatform.endpoints.predict` / `batchPredictionJobs.create`) e API Keys explícitas para `generativelanguage.googleapis.com`. |
| **Múltiplas chaves na mesma Service Account** | Sim | N/A | Separa a chave efetivamente utilizada (`CONFIRMED_KEY_INFERENCE`) de chaves irmãs ociosas (`SA_INFERENCE_KEY_IDLE`). |
| **Service Account Cross-Project (origem sem IA ativa)** | Sim | N/A | Detecta chaves criadas em projetos sem `aiplatform.googleapis.com` habilitado que possuem permissão sobre projetos onde a plataforma está ativa. |
| **Herança de Organização/Pasta, Google Groups e Custom Roles** | Sim | N/A | Avalia políticas herdadas, expande membros de grupos (`--expand-groups`) e inspeciona permissões internas de *Custom Roles*. |
| **Cadeias de Impersonation (`TokenCreator` / `actAs`)** | Sim (`--include-impersonation`) | N/A | Detecta chaves em SAs intermediárias sem acesso direto à IA que podem gerar token para outra SA com acesso, isolando papéis amplos (`roles/editor`) para não inflar contagens. |
| **Auto-habilitação latente de IA em projetos inativos** | Sim (`--include-can-enable-ai`) | N/A | Identifica SAs com chave ativa que acumulam `serviceusage.services.enable` + `aiplatform.endpoints.predict` em projetos onde `aiplatform.googleapis.com` ainda está desabilitada (`LATENT_CAN_ENABLE_AI`). |
| **Detecção de *Target Scoping* (`ListModels` / `ListEndpoints`)** | Sim | Sim | Captura enumeração pré-ataque de modelos e cotas (`RECON_SCOPING_ACTIVE_KEY` / `RECON_SCOPING_DETECTED`). |
| **Alerta de *Validation Sweep* (*LLM Mixers*) e Persistência** | Sim | Sim | Sinaliza chaves com 1 a 10 chamadas (`POSSIBLE_VALIDATION_SWEEP_1_TO_10_CALLS`), chaves recém-criadas na janela e ações administrativas (`EnableService`, `CreateServiceAccountKey`). |
| **IAM Conditions (CEL) e Chaves Desabilitadas/Expiradas** | Sim | N/A | Extrai expressões CEL do binding e classifica chaves inativas como `LOW_DISABLED_KEY` / `LOW_EXPIRED_KEY`. |
| **API Keys Irrestritas (`apiTargets` vazio)** | N/A | Sim | Alerta chaves antigas sem restrição de API (`UNRESTRICTED_ALL_APIS`) hospedadas em projetos onde `generativelanguage.googleapis.com` foi habilitado. |
| **Correlação com Faturamento (`PAYG` vs. *Free Tier*)** | N/A | Sim | Cruza `ProjectBillingInfo` para priorizar chaves abertas (`OPEN_ANY_IP_OR_APP`) em projetos com *Billing* ativo (`CRITICAL_PAYG_OPEN_KEY`). |
| **Exclusão de Papéis / Chaves Sem Acesso de Inferência** | Sim | Sim | Ignora papéis apenas de leitura (ex.: `roles/aiplatform.viewer`), chaves `SYSTEM_MANAGED`, Service Agents do Google e API Keys restritas exclusivamente a outras APIs. |

### 3.2 Limitações Conhecidas (Fora do Escopo)

* **Credenciais humanas ou federação externa sem chaves estáticas:** Tokens OAuth de usuários (`user:...`) comprometidos ou provedores de *Workload Identity Federation* mal configurados não utilizam `ServiceAccountKey` nem `API Key`.
* **Endereço IP de origem (`callerIp`) e `User-Agent`:** As métricas nativas confirmam **qual chave**, **qual projeto**, **quais métodos** e **quantas chamadas** ocorreram, o que é suficiente para contenção imediata. A atribuição de IP público por requisição exige logs `DATA_READ` habilitados previamente (ou habilitados temporariamente por alguns minutos antes da desativação da chave comprometida).

---

## 4. Pré-requisitos, Permissões IAM e Cotas (Com e Sem SCC Premium)

Requisitos: **Python 3.8+** e **Google Cloud CLI (`gcloud`)** autenticado (ambos nativos no Google Cloud Shell).

### Permissões IAM recomendadas (Somente Leitura)

* **Modo `cai` (Recomendado — varredura rápida em nível de Organização ou Pasta):**
  * APIs habilitadas no projeto informado em `--billing-project`: `cloudasset.googleapis.com`, `monitoring.googleapis.com` e (opcionalmente) `policyanalyzer.googleapis.com`, `recommender.googleapis.com` e `logging.googleapis.com`.
  * Papéis na Organização/Pasta: `roles/cloudasset.viewer` e `roles/monitoring.viewer` *(opcionais para enriquecimento: `roles/logging.viewer` p/ Admin Activity Logs, `roles/policyanalyzer.activityAnalysisViewer`, `roles/recommender.iamViewer` e `roles/billing.viewer`)*.
* **Modo `direct` (Fallback direto por projeto):**
  * `roles/iam.securityReviewer`, `roles/serviceusage.serviceUsageViewer`, `roles/serviceusage.apiKeysViewer` e `roles/monitoring.viewer` *(opcional: `roles/logging.viewer`)*.

### Impacto de Cotas sem Security Command Center (SCC) Premium/Enterprise

| API Utilizada | Cota sem SCC Premium/Enterprise | Impacto nos Scripts |
| :--- | :--- | :--- |
| **`AnalyzeIamPolicy`** (`analyze-iam-policy`) | **20 queries / dia / Organização** | Ao rodar com `--org SEU_ORG_ID`, `audit_agent_platform_sa_keys.py` consome **apenas 1 query** para varrer a organização inteira. Caso as 20 queries diárias já tenham sido esgotadas (`RESOURCE_EXHAUSTED`), o script faz **fallback automático** para `search-all-iam-policies` (400 req/min gratuitos). |
| **`SearchAllResources` / `SearchAllIamPolicies`** | **400 req/min** (gratuito) | Zero restrição de SCC (`audit_genai_api_keys.py` inteiro usa apenas chamadas livres dessa cota). |
| **`serviceAccountKeyLastAuthentication`** | **Isento do limite de 20/dia** | Consulta de último uso de chaves não consome a cota diária do Policy Analyzer. |
| **Cloud Monitoring & Admin Activity Logs** | **Gratuito / Padrão** | A comprovação real de inferência/scoping (6 semanas) e os eventos de auditoria administrativa (400 dias) funcionam integralmente sem SCC. |

---

## 5. Como Executar

### 5.1 Service Account Keys no Gemini Enterprise Agent Platform / Vertex AI (`audit_agent_platform_sa_keys.py`)

```bash
# 1. Varredura completa na Organização incluindo Impersonation e auto-habilitação latente de IA (Recomendado):
python3 audit_agent_platform_sa_keys.py \
  --org SEU_ORG_ID \
  --lookback-days 14 \
  --include-impersonation \
  --include-can-enable-ai \
  --active-keys-only \
  --billing-project PROJETO_QUOTA_SECOPS

# 2. Filtrar APENAS chaves com chamadas reais de inferência ou scoping detectados na janela (Foco P0):
python3 audit_agent_platform_sa_keys.py \
  --org SEU_ORG_ID \
  --lookback-days 30 \
  --include-impersonation \
  --only-confirmed-inference \
  --billing-project PROJETO_QUOTA_SECOPS

# 3. Modo Fallback Direto (sem Cloud Asset Inventory, varrendo projetos visíveis):
python3 audit_agent_platform_sa_keys.py \
  --all-accessible-projects \
  --mode direct \
  --lookback-days 14 \
  --active-keys-only
```

### 5.2 API Keys no Gemini Developer API / AI Studio (`audit_genai_api_keys.py`)

```bash
# 1. Varredura na Organização (incluindo Agent Platform / Vertex Express Mode):
python3 audit_genai_api_keys.py \
  --org SEU_ORG_ID \
  --lookback-days 14 \
  --include-vertex-express \
  --billing-project PROJETO_QUOTA_SECOPS

# 2. Modo Fallback Direto em lista de projetos específicos:
python3 audit_genai_api_keys.py \
  --projects projeto-app-1,projeto-ia-2 \
  --mode direct \
  --lookback-days 14
```

---

## 6. Interpretando os Resultados e Contenção Reversível

### 6.1 Classificações do `audit_agent_platform_sa_keys.py`

| `inference_activity_status` | Prioridade | Significado Operacional | Ação Recomendada |
| :--- | :---: | :--- | :--- |
| **`CONFIRMED_KEY_INFERENCE`** | **P0** | A SA realizou chamadas reais de inferência **e** esta `key_id` específica autenticou no período. | Validar legitimidade; se desconhecida, **desabilitar na hora** (`keys disable`). |
| **`SA_ACTIVE_VERIFY_KEY`** | **P0** | A SA registra chamadas reais de inferência, mas a chave `.json` ainda marca zero logins — indica **(a) ataque iniciado há < 3h** ou **(b) SA usada por GKE/Cloud Run/VM** com uma chave `.json` antiga esquecida. | Se o consumo for desconhecido, desabilitar na hora (`keys disable`). Se houver GKE/Cloud Run/VM legítimo usando a SA, desabilitar a chave `.json` órfã também é seguro (não derruba identidade anexada). |
| **`RECON_SCOPING_ACTIVE_KEY`** | **P1 (Scoping)** | Zero inferência, mas a SA executou enumeração de modelos/endpoints (`ListModels`, `ListPublisherModels`, `ListEndpoints`) **e** esta `key_id` autenticou no período. | Investigar e desabilitar imediatamente: provável fase de reconhecimento pré-exploração. |
| **`RECON_SCOPING_VERIFY_KEY`** | **P1 (Scoping)** | Enumeração de modelos detectada na SA com zero logins consolidados na `key_id` (< 3h de delay IAM ou identidade anexada). | Confirmar origem das chamadas de listagem e desabilitar chaves `.json` órfãs. |
| **`SA_INFERENCE_KEY_IDLE`** | **P1** | A SA faz inferência por meio de **outra** chave ativa na mesma conta, enquanto esta `key_id` teve zero autenticações. | Concentrar contenção na chave irmã ativa e agendar remoção desta chave ociosa. |
| **`KEY_AUTH_NO_INFERENCE`** | **P2** | A chave autentica em outras APIs (ex.: Storage/BigQuery em SA `Editor`), mas fez **zero** chamadas de inferência. | Remover permissão `aiplatform` (menor privilégio) sem interromper o pipeline. |
| **`DORMANT_NO_ACTIVITY`** | **P3** | Chave ativa com permissão de inferência, sem autenticações nem chamadas recentes. | Desabilitar preventivamente para reduzir superfície de exposição. |

### 6.2 Classificações do `audit_genai_api_keys.py`

| `risk_status` / Status | Significado Operacional | Ação Recomendada |
| :--- | :--- | :--- |
| **`P0_ACTIVE_API_KEY_DOING_INFERENCE`** | API Key com chamadas reais de geração/inferência registradas no período (`apikey:<UID>`). | Confirmar origem do consumo; se anômalo, aplicar restrição de contenção imediata. |
| **`RECON_SCOPING_DETECTED`** *(atividade)* | API Key sem chamadas de geração, mas com chamadas de enumeração (`ListModels`, `ListTunedModels`) registradas. | Tratar como credencial sob teste/reconhecimento; restringir ou revogar imediatamente. |
| **`CRITICAL_PAYG_OPEN_KEY`** | Projeto com **Billing ativo (`TRUE`)** e API Key **sem restrição de IP/App** (explícita ou irrestrita). | Restringir imediatamente por IP/Referrer/App e `apiTargets`, ou revogar. |
| **`MODERATE_CLIENT_RESTRICTED_KEY`** | API Key possui restrição configurada de IP, HTTP Referrer ou App Android/iOS. | Revisar se os endereços/domínios seguem privilégio mínimo. |
| **`MEDIUM_FREE_TIER_KEY`** | Projeto sem conta de faturamento ativa vinculada (*Free Tier*). | Menor risco financeiro direto; aplicar restrições ou excluir chaves sem uso. |

### 6.3 Sinais Táticos na Coluna `gtig_threat_signals`

| Sinal (`gtig_threat_signals`) | Significado Segundo o Relatório GTIG / Mandiant (Nov/2026) |
| :--- | :--- |
| **`POSSIBLE_VALIDATION_SWEEP_1_TO_10_CALLS`** | Credencial realizou apenas **1 a 10 chamadas** na janela — padrão típico de *Validation Sweep* (`max_tokens=1`) usado para cadastrar chaves válidas como reserva (*failover*) em *LLM Mixers* (`new-api`, `gcli2api`). |
| **`TARGET_SCOPING_RECON(...)`** | Credencial invocou métodos de descoberta de modelos e cotas (`ListModels`, `ListEndpoints`, `ListPublisherModels`). |
| **`RECENT_KEY_CREATED_IN_WINDOW`** / **`RECENT_API_KEY_CREATED_IN_WINDOW`** | Chave estática ou API Key criada dentro da janela analisada — verificar se foi gerada pelo atacante para persistência (*burn-and-rotate*). |
| **`SA_ADMIN_ACTION:<Metodo>@<Projeto>`** | A própria Service Account exposta executou ação administrativa crítica na janela (`EnableService`, `CreateServiceAccountKey`, `CreateServiceAccount`, `CreateKey` ou alteração de metadados SSH de VMs). |
| **`RECENT_AI_API_ENABLED:<Projeto>`** | A API `aiplatform.googleapis.com` ou `generativelanguage.googleapis.com` foi habilitada recentemente no projeto durante a janela analisada. |
| **`LATENT_CAN_ENABLE_AI_API`** | *(Com `--include-can-enable-ai`)* Projeto está com IA desabilitada, mas a SA detém `serviceusage.services.enable` + permissão de inferência, permitindo ao invasor ligar a API por conta própria. |

### 6.4 Comandos de Contenção Rápida e Reversível

> [!TIP]
> Prefira ações de **bloqueio reversível** antes da exclusão definitiva: elas estancam o consumo imediatamente e permitem restauração rápida caso alguma aplicação legítima seja impactada.

```bash
# 1. Service Account Keys — Desabilitar antes de excluir:
gcloud iam service-accounts keys disable <KEY_ID> \
  --iam-account=<SA_EMAIL> \
  --project=<SA_PROJECT_ID>

# 2. API Keys — Restringir a loopback (127.0.0.1) ou excluir (reversível por 30d via `undelete`):
gcloud services api-keys update projects/<PROJECT_ID>/locations/global/keys/<KEY_UID> \
  --allowed-ips=127.0.0.1
```

---

## 7. Executando os Testes Unitários

```bash
python3 -m unittest discover -s tests -v
```

## Licença

Distribuído sob a licença [Apache 2.0](LICENSE).
