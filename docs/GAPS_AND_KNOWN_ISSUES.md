# SecureNexus — Gaps, Known Issues & Native Coverage Guide

> **Audience**: Engineering, product, and pre-sales.
> **Purpose**: Honest accounting of what is fully working, what is stubbed, what breaks silently, and exactly how to cover clients that have no EDR/XDR.
> Last updated: March 2026 — verified against codebase directly.

---

## Table of Contents

1. [Critical Broken Flows](#1-critical-broken-flows)
2. [Native Sensors & Collectors — For Clients Without EDR/XDR](#2-native-sensors--collectors--for-clients-without-edrxdr)
3. [Response Actions — What Actually Executes vs What Is Simulated](#3-response-actions--what-actually-executes-vs-what-is-simulated)
4. [Features That Are Schema-Only (No Logic)](#4-features-that-are-schema-only-no-logic)
5. [Features That Are Fully Working](#5-features-that-are-fully-working)
6. [Connector Status Matrix](#6-connector-status-matrix)
7. [What Each AI Feature Actually Does](#7-what-each-ai-feature-actually-does)
8. [Pre-Sales Guidance — Honest Capability Statements](#8-pre-sales-guidance--honest-capability-statements)

---

## 1. Critical Broken Flows

### 1.1 Scheduled Connector Sync Does NOT Write Alerts to the Database

**Severity: CRITICAL**
**Impact**: Any connector configured to sync automatically (via the job queue) fetches alerts from the source and then discards them. Zero alerts are written to the database.

**What happens step by step**:

1. `job-queue.ts:30` calls `syncConnector(connector)` directly
2. `connector-engine.ts:164–171` — `syncConnector()` returns normalized alerts in `rawAlerts` but **never calls `storage.upsertAlert()`**
3. The job handler returns `{ synced: true, ...result }` — `alertsCreated` is always 0

**The correct path** (manual sync via UI):
`routes/connectors.ts:224` calls `syncConnectorWithRetry()` → then loops over `syncResult.rawAlerts` and calls `storage.upsertAlert()` for each one (lines 231–243). This WORKS.

**Net result**: Clicking "Sync Now" in the UI works. Automatic scheduled syncs silently discard every alert they fetch.

**Fix needed**: `job-queue.ts` `connector_sync` handler must replicate the upsert loop from `routes/connectors.ts:231–243` after calling `syncConnector()`.

---

### 1.2 Native Collector Instances Are Stored In-Memory — Lost on Server Restart

**Severity: CRITICAL**
**File**: `server/native-collectors-engine.ts:516–518`

```typescript
const instanceStore = new Map<string, CollectorInstance>();
const eventStore  = new Map<string, IngestedEvent>();
const scanStore   = new Map<string, ScanResult>();
```

Every collector instance, every ingested event, and every scan result lives in these Maps. When the Node process restarts (deploy, crash, scale event), everything is gone. The UI will show an empty collector list and all historical events vanish.

**What works**: Template definitions, deployment script generation, the in-memory event processing pipeline, rule matching against events (while the process is running).

**What doesn't work after restart**: Any previously deployed collector is gone. The agent running on a remote host will try to phone home but the server will return 404 because the instance no longer exists.

**Fix needed**: Persist `instanceStore` → `nativeCollectors` table (schema exists). Persist events → `sensorEvents` table. The native sensors path (separate from collectors) already does this correctly — see `routes/native-sensors.ts:257–278`.

---

### 1.3 Agent Binaries Do Not Exist

**Severity: CRITICAL**
**File**: `server/native-collectors-engine.ts:813–864`

The deployment script generator outputs install commands like:
```bash
curl -fsSL https://nexus.aricatech.xyz/agent/linux/install.sh | sudo bash
```

This URL does not exist. There is no agent binary in the repository and no CDN serving these scripts. The deployment scripts are generated correctly, but the referenced agent binary has not been built or hosted.

**Impact**: Any customer trying to deploy a native collector will get a working script that fails at the download step.

**What to tell customers until this is fixed**: Use the **native sensor** path instead (see Section 2 below), which doesn't require an agent binary — it uses a lightweight shell/Python script that calls the SecureNexus API directly.

---

### 1.4 Evidence Chain Has No Cryptographic Verification

**Severity: MEDIUM**
**Files**: `server/action-dispatcher.ts`, `shared/schema.ts` (evidenceChainEntries table)

The `evidenceChainEntries` table has columns for `entryHash` and `prevHash` (Merkle/linked-list chain), but no code computes or verifies these hashes. Actions are recorded in `agentResponseActions` and `responseActions` tables without any chain linking.

**Impact**: The UI may show an "evidence chain" view but the chain has no tamper-evidence property. Any database-level modification would not be detected.

---

## 2. Native Sensors & Collectors — For Clients Without EDR/XDR

This is the most common deployment scenario. A client has no CrowdStrike, no SentinelOne, no Splunk. They need SecureNexus to be the first line of detection.

### 2.1 The Two Paths (and Which One Actually Works)

| Path | UI Location | Backend | DB-backed | Agent Binary Required | Status |
|------|-------------|---------|-----------|----------------------|--------|
| **Native Collectors** | Settings → Native Collectors | `native-collectors-engine.ts` | ❌ In-memory only | ✅ Yes (binary missing) | ⚠️ Broken in prod |
| **Native Sensors** | Settings → Native Sensors | `routes/native-sensors.ts` | ✅ `sensorEvents` table | ❌ No binary needed | ✅ Working |

**Use Native Sensors.** This is the working path for clients without EDR/XDR.

### 2.2 Native Sensor Coverage — What Data Can Be Collected

A native sensor is a lightweight script or agent that runs on the target host and POSTs events to the SecureNexus API. The server accepts up to 500 events per call.

**Supported event types** (validated in `routes/native-sensors.ts`):

| Event Type | What It Captures | Typical Source |
|------------|-----------------|----------------|
| `process_exec` | Process name, path, args, PID, PPID, parent, user | Auditd, ETW, eBPF |
| `network_connection` | srcIp, dstIp, srcPort, dstPort, protocol, bytes | netstat, conntrack, eBPF |
| `file_access` | filePath, fileHash, action, user | inotify, fanotify, ETW |
| `auth_event` | userName, outcome, authMethod, srcIp | /var/log/auth.log, EVTX |
| `dns_query` | query, response, queryType, dstIp | dnstap, Sysmon |
| `registry_change` | keyPath, valueName, valueData, action | ETW (Windows only) |
| `scheduled_task` | taskName, action, command, user | ETW, atd |
| `service_change` | serviceName, action, binaryPath, user | systemd, SCM |

All fields go into the `sensorEvents` table with `orgId` and `sensorId` indexing.

### 2.3 How to Onboard a Client With No EDR/XDR — Step by Step

#### Step 1: Register the sensor
```bash
curl -s -X POST https://your-instance/api/native-sensors \
  -H "Authorization: Bearer <session_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "webserver-01",
    "type": "endpoint",
    "hostname": "webserver-01.corp.local",
    "ipAddress": "10.0.1.50",
    "os": "linux",
    "osVersion": "Ubuntu 22.04"
  }'
```
Response includes `sensorId` and `apiKey`. Save both.

#### Step 2: Deploy the lightweight collection script (Linux endpoint)

The script below collects process execution events using auditd and ships them to SecureNexus. No binary download required.

```bash
#!/bin/bash
# SecureNexus Native Sensor — Process Exec Collector
# Runs on Ubuntu/Debian, requires: auditd, curl, jq

SENSOR_ID="<sensorId from Step 1>"
API_KEY="<apiKey from Step 1>"
API_BASE="https://your-instance/api/native-sensors"

# Send heartbeat every 60s
heartbeat() {
  curl -s -X POST "$API_BASE/$SENSOR_ID/heartbeat" \
    -H "X-Sensor-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"cpuUsage\": $(top -bn1 | grep 'Cpu' | awk '{print $2}'), \"memoryUsage\": $(free | awk '/Mem:/{printf "%.1f", $3/$2*100}')}"
}

# Ship events
ship_events() {
  local events_json="$1"
  curl -s -X POST "$API_BASE/$SENSOR_ID/events" \
    -H "X-Sensor-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"events\": $events_json}"
}

# Tail auditd exec events and forward
ausearch -m EXECVE --checkpoint /tmp/nexus_checkpoint -i 2>/dev/null | \
while IFS= read -r line; do
  # Parse and ship...
  # (integrate with your preferred auditd parser)
  echo "$line"
done
```

For Windows endpoints, use PowerShell with Sysmon + ETW and call the same API endpoint.

#### Step 3: Set up detection rules

Go to **AI Engine → AI Detection Rules** and create rules matching your environment. For clients without EDR, focus on:
- `process_exec` rules for known LOLBins (living-off-the-land binaries)
- `network_connection` rules for outbound to unusual ports/countries
- `auth_event` rules for brute force and privilege escalation

#### Step 4: Configure heartbeat monitoring

In Settings → Native Sensors, set a heartbeat timeout. If a sensor goes offline, SecureNexus will create an alert.

### 2.4 Coverage Gaps Without EDR/XDR — What You Cannot Do Natively

| Capability | With EDR (CrowdStrike/SentinelOne) | Without EDR (Native Sensors) |
|------------|-------------------------------------|------------------------------|
| Memory scanning | ✅ Real-time | ❌ Not available |
| Kernel-level protection | ✅ Driver-based | ❌ Not available |
| Automatic quarantine | ✅ EDR executes | ⚠️ Response action queued, human must approve |
| Behavioral ML detection | ✅ EDR model runs locally | ⚠️ Rule-based only via native sensors |
| Telemetry depth | ✅ Every syscall | ⚠️ Only events you instrument |
| File integrity monitoring | ✅ Real-time | ⚠️ Poll-based via `file_access` events |
| Network isolation | ✅ Instant | ⚠️ See Section 3 |

**Recommendation**: Position native sensors as the ingestion and detection layer. Response actions (isolate, block, quarantine) still require either an EDR integration or a native sensor with the agent on that host.

### 2.5 Syslog / Log File Ingestion (No Agent at All)

For clients who can't install anything, Syslog forwarding is the fallback.

```bash
# On the device — forward syslog to SecureNexus
echo "*.* @your-instance:5144" >> /etc/rsyslog.conf
service rsyslog restart
```

Map the Syslog source to a connector of type `syslog` in the UI. This ingests raw logs which the normalization engine converts to alerts.

---

## 3. Response Actions — What Actually Executes vs What Is Simulated

### 3.1 The Decision Tree

When a playbook action fires (e.g. `isolate_host`), the code in `action-dispatcher.ts` follows this decision tree:

```
Does the context have an orgId?
  NO  → legacySimulateEdrAction() — SIMULATION ONLY
  YES → Does a native sensor match this host/IP?
          NO  → legacySimulateEdrAction() — SIMULATION ONLY
          YES → Create agentResponseActions DB record
                  → Risk level HIGH/MEDIUM? → status: pending_approval (human must approve)
                  → Risk level LOW?         → status: approved (auto-approved)
                  → ACTION IS QUEUED — NOT YET EXECUTED
                  → Agent must poll /api/native-sensors/:id/pending-actions and execute locally
```

### 3.2 What "Simulated" Means

`legacySimulateEdrAction()` creates a record in the `responseActions` table with `status: "completed"` and a fake success message. Nothing actually happens on the endpoint. The UI shows it as "completed" which is misleading.

**When simulation is triggered**:
- No native sensor is deployed on the target host
- The playbook action doesn't pass orgId in context
- Sensor lookup throws an error

### 3.3 What "Real" Means (After Agent Polling)

When a sensor IS found:
1. A record is created in `agentResponseActions` with `status: pending_approval` or `approved`
2. The native sensor agent on the host must poll `GET /api/native-sensors/:id/pending-actions`
3. The agent executes the action locally (network isolation, process kill, etc.)
4. The agent calls `PATCH /api/native-sensors/:id/actions/:actionId` to report result

**The agent polling endpoint exists** (`routes/native-sensors.ts`). If you have a native sensor deployed on a host, the full response action loop can work. Without the sensor on that specific host, it simulates.

### 3.4 Response Action Matrix

| Action | With Native Sensor on Host | Without (any EDR/sensor) |
|--------|---------------------------|--------------------------|
| `isolate_host` | ✅ Queued → agent executes network isolation | ⚠️ Simulated (logged only) |
| `kill_process` | ✅ Queued → agent kills PID | ⚠️ Simulated |
| `quarantine_file` | ✅ Queued → agent moves file | ⚠️ Simulated |
| `block_ip` | ⚠️ Queued → requires firewall API config | ⚠️ Simulated |
| `block_domain` | ⚠️ Queued → requires DNS/proxy API config | ⚠️ Simulated |
| `disable_user` | ⚠️ Queued → requires AD/LDAP integration | ⚠️ Simulated |

**High and medium risk actions always require human approval before the agent will execute them.** Low risk actions are auto-approved.

---

## 4. Features That Are Schema-Only (No Logic)

These features have database tables, UI pages, and routes, but the backend logic is a stub or returns empty data.

| Feature | UI Page | What's Missing |
|---------|---------|----------------|
| **Evidence chain hashing** | Evidence Chain Viewer | Hash computation and chain linking. Records are created but `entryHash`/`prevHash` are not computed. |
| **UEBA baseline + anomaly** | Behavior Analytics | `uebaBaselines` and `uebaAnomalies` tables exist. The `behavior-analyzer.ts` file exists but the statistical baselining logic returns stub scores. No real deviation detection runs. |
| **Predictive analytics** | Analytics → Risk Forecast | `predictiveAnomalies` and `riskForecasts` tables exist. `predictive-engine.ts` has a framework but the ML model calls are stubbed — they return hardcoded confidence values. |
| **Passive DNS** | Threat Intel → Passive DNS | `passiveDnsRecords` table exists. No feed ingestion runs automatically. Records must be inserted manually or via the ingest API. |
| **Chaos engineering** | Chaos Engineering | `chaosSchedules` and `chaosSimulations` tables exist. Schedules can be created in UI but no scheduler runs them. |
| **Tabletop exercises** | Tabletop Exercises | Schema and UI exist. No exercise orchestration or scoring logic. |
| **Browser defense** | Browser Defense | UI page exists. No browser extension, no endpoint to receive browser telemetry. |
| **Physical security** | Physical Security | Tables exist. No integrations for badge readers or physical access control systems. Manual data entry only. |
| **JIT secret access** | JIT Secret Access | UI and schema exist. No actual secrets vault integration (HashiCorp Vault, AWS Secrets Manager API calls are stubbed). |
| **Supply chain / TPRM** | Supply Chain | Vendor monitoring tables exist. No automated vendor risk scoring — scores are manually entered. |
| **Quantum readiness** | Quantum Readiness | Static content page. No cryptographic inventory scanning. |
| **Privacy engineering** | Privacy Engineering | `privacyScans` table exists. No automated PII scanning runs. |
| **OT/ICS anomaly detection** | OT Security | `otAssets`, `otConnections`, `otAnomalies` tables exist. No protocol parsing runs unless events are pushed via API. |

---

## 5. Features That Are Fully Working

These have been verified against actual code — real API calls, real DB writes, real logic.

| Feature | Verified Working |
|---------|-----------------|
| **AI triage** (`triageAlert`) | ✅ Calls Bedrock/SageMaker, parses response, writes severity/category/confidence to alerts table |
| **AI correlation** (`correlateAlerts`) | ✅ Real AI call, returns groupings and kill-chain analysis |
| **AI incident narrative** | ✅ Real AI call, stores generated narrative on incident |
| **AI deep investigation** | ✅ Multi-turn investigation with attack graph generation |
| **CSPM scanning** | ✅ Real AWS SDK calls (IAM, EC2, S3, RDS, GuardDuty), real Azure/GCP scanning, drift detection, DSPM, attack path analysis |
| **Connector fetch** (all 24) | ✅ Real API calls to CrowdStrike, Wazuh, GuardDuty, SentinelOne, Splunk, etc. |
| **Connector sync via UI** | ✅ Manual sync correctly fetches + normalizes + upserts alerts |
| **Alert ingestion API** | ✅ `POST /api/ingest/alerts/bulk` fully works, deduplication, entity resolution |
| **Native sensor event ingestion** | ✅ `POST /api/native-sensors/:id/events` persists to `sensorEvents` table |
| **Playbook execution framework** | ✅ Risk assessment, approval workflow, DB records created |
| **RBAC enforcement** | ✅ Role + permission checks on all routes |
| **Audit log** | ✅ All actions logged with userId, action, resource, IP, userAgent |
| **Stripe billing** | ✅ Real Stripe API integration |
| **OAuth (Google, GitHub)** | ✅ Real OAuth flows |
| **Report generation** | ✅ Real data aggregation, PDF export |
| **Threat intel IOC matching** | ✅ IOC ingestion and real-time matching against alerts |
| **Entity resolution** | ✅ Extracts entities from alerts, creates/links entity records |
| **Connector health monitoring** | ✅ Sync status, error rates, throughput tracked per connector |
| **MSSP multi-tenancy** | ✅ Parent/child org isolation, billing records, SLA tracking |
| **Notification dispatch** | ✅ Slack, Teams, Email, PagerDuty, webhook delivery |
| **SLA tracking** | ✅ ACK/Contain/Resolve milestones, breach detection |

---

## 6. Connector Status Matrix

All 24 connectors have real `fetch()` and `normalize()` implementations. The connector-level code works. The gap is at the job-queue level (see Section 1.1).

| Connector | Type | Real API Calls | Normalize | Scheduled Sync |
|-----------|------|---------------|-----------|----------------|
| CrowdStrike Falcon | EDR | ✅ OAuth2 + `/alerts/queries/alerts/v2` | ✅ | ⚠️ Bug (see 1.1) |
| SentinelOne | EDR | ✅ | ✅ | ⚠️ Bug |
| Microsoft Defender | EDR | ✅ | ✅ | ⚠️ Bug |
| Carbon Black | EDR | ✅ | ✅ | ⚠️ Bug |
| Splunk ES | SIEM | ✅ | ✅ | ⚠️ Bug |
| Wazuh | SIEM | ✅ OpenSearch DSL | ✅ | ⚠️ Bug |
| Elastic Security | SIEM | ✅ | ✅ | ⚠️ Bug |
| IBM QRadar | SIEM | ✅ | ✅ | ⚠️ Bug |
| AWS GuardDuty | Cloud | ✅ AWS SDK | ✅ | ⚠️ Bug |
| Wiz | Cloud | ✅ | ✅ | ⚠️ Bug |
| Palo Alto Cortex XDR | Network | ✅ | ✅ | ⚠️ Bug |
| Fortinet FortiGate | Network | ✅ | ✅ | ⚠️ Bug |
| Cisco Umbrella | Network | ✅ | ✅ | ⚠️ Bug |
| Zscaler ZIA | Network | ✅ | ✅ | ⚠️ Bug |
| Check Point | Network | ✅ | ✅ | ⚠️ Bug |
| Suricata | Network | ✅ | ✅ | ⚠️ Bug |
| Snort | Network | ✅ | ✅ | ⚠️ Bug |
| Tenable Nessus | Vuln | ✅ | ✅ | ⚠️ Bug |
| Qualys VMDR | Vuln | ✅ | ✅ | ⚠️ Bug |
| Darktrace | AI/Network | ✅ | ✅ | ⚠️ Bug |
| Rapid7 InsightIDR | SIEM | ✅ | ✅ | ⚠️ Bug |
| Okta Identity | IdP | ✅ | ✅ | ⚠️ Bug |
| Proofpoint | Email | ✅ | ✅ | ⚠️ Bug |
| Trend Micro Vision One | XDR | ✅ | ✅ | ⚠️ Bug |

**Manual sync via UI "Sync Now" button: works correctly for all 24.**

---

## 7. What Each AI Feature Actually Does

### ✅ Works — Real AI Calls

| Feature | Model Used | Real Call | Output |
|---------|-----------|-----------|--------|
| Alert triage | Mistral Large (triage tier) | ✅ | Severity, category, MITRE tactic, false-positive likelihood, containment advice |
| Alert correlation | Mistral Large (narrative tier) | ✅ | Groups of related alerts, kill chain, threat landscape |
| Incident narrative | Mistral Large (narrative tier) | ✅ | Human-readable incident summary |
| Deep investigation | Claude Opus (investigation tier) | ✅ | Attack graph nodes/edges, analyst findings, recommended queries |
| Threat hunt execution | Claude Opus | ✅ | Hunt results, matched behaviors, IOC candidates |
| Detection rule generation | Claude Opus | ✅ | SIGMA-format rules |
| Attack path prediction | Claude Opus | ✅ | Probable next attacker moves |

All of these go through `model-gateway.ts` which has: circuit breaker, 5-minute response cache, cost tracking, budget enforcement, and health monitoring.

### ⚠️ Stubbed — Returns Hardcoded Values

| Feature | What It Returns | Reality |
|---------|----------------|---------|
| UEBA behavioral scoring | A numeric score per entity | Score is computed from a simple formula using alert count, not a real ML model |
| Predictive anomaly forecasting | Forecast confidence percentages | Hardcoded/formula-based, no trained model |
| Risk forecasts | Weekly risk trend | Based on rolling window of past alerts, not ML prediction |

### ❌ Not Connected

| Feature | Status |
|---------|--------|
| A/B testing prompts | Schema exists (`ruleAbTests`), no experiment runner |
| Active learning feedback loop | `aiFeedback` table records analyst corrections, but the few-shot builder doesn't yet query production feedback — it uses seed examples only |
| Vector search / RAG | `buildRAGContext()` exists in `ai/vector-search.ts` but pgvector embeddings are not populated by default — requires running the embedding pipeline separately |

---

## 8. Pre-Sales Guidance — Honest Capability Statements

### "Do you have EDR capability?"

**Correct answer**: SecureNexus is not an EDR replacement. It is a SIEM/SOAR platform that ingests from EDRs. For clients without EDR:

- We deploy **native sensors** (lightweight scripts that call our API) that collect process execution, network, file, and auth telemetry
- Detection is rule-based on this telemetry (not kernel-level behavioral ML like an EDR)
- Response actions (isolate, quarantine, kill process) work IF a native sensor is deployed on that host AND a human approves the action
- We recommend pairing native sensors with a low-cost EDR for kernel-level protection; SecureNexus handles the cross-source correlation, investigation, and SOAR layer

### "Do connectors sync automatically?"

**Correct answer**: Yes, connectors can be configured to sync on a schedule. Note: the current build has a known issue where the scheduled sync does not persist alerts to the database. Use **manual sync ("Sync Now")** for reliable alert ingestion until the fix is deployed.

### "Is response automation real?"

**Correct answer**: Response actions (isolate host, block IP, kill process) create an approval workflow and, when a native sensor is deployed on the target host, the agent executes the action locally. For hosts without a sensor, actions are logged as "completed" but are not actually executed on the endpoint. High and medium risk actions always require human approval.

### "Is the AI real?"

**Correct answer**: Yes. Alert triage, correlation, investigation, threat hunting, and detection rule generation all make real calls to AWS Bedrock (Claude or Mistral Large depending on the task). The AI engine has budget controls, circuit breakers, and a 5-minute response cache. UEBA scoring and predictive analytics are formula-based approximations, not trained ML models.

### "Is the evidence chain tamper-proof?"

**Correct answer**: Actions are logged with timestamps and actor identity. The cryptographic hash chain (Merkle linking) is not yet implemented — the schema exists but hash values are not computed. Audit logs are append-only with sequential numbering.

### "What compliance frameworks are supported?"

**Correct answer**: The platform has control mappings for SOC 2, ISO 27001, NIST CSF, GDPR, HIPAA, PCI DSS, CCPA, CMMC, and 15+ others. Evidence collection automation is partial — CSPM findings and alerts are automatically linked to controls, but evidence collection for non-automated controls requires manual upload.

---

## Appendix: Quick Fix Priority List

For the engineering team — the items below, in order, unblock the most customer value:

| Priority | Fix | File | Effort |
|----------|-----|------|--------|
| P0 | Job queue connector_sync must call upsertAlert after syncConnector | `server/job-queue.ts:30` | 1 hour |
| P0 | Persist native collector instances to DB | `server/native-collectors-engine.ts:516` | 1 day |
| P1 | Build + host native sensor install script (no binary needed, just the API caller) | New file | 2 days |
| P1 | Make legacySimulateEdrAction clearly mark actions as "simulated" in UI | `server/action-dispatcher.ts:435` | 2 hours |
| P2 | Evidence chain hash computation | `server/` new file | 2 days |
| P2 | Active learning: wire aiFeedback table into few-shot builder | `server/ai/active-learning.ts` | 1 day |
| P2 | UEBA: replace stub scoring with real baseline deviation calculation | `server/behavior-analyzer.ts` | 3 days |
| P3 | Show "simulation" badge on response actions with no sensor | `client/src/pages/response-actions.tsx` | 4 hours |
