import {
  type Alert, type InsertAlert, alerts,
  type Incident, type InsertIncident, incidents,
  type Organization, type InsertOrganization, organizations,
  type AuditLog, auditLogs,
  type IncidentComment, type InsertComment, incidentComments,
  type Tag, type InsertTag, tags,
  type ApiKey, type InsertApiKey, apiKeys,
  type IngestionLog, type InsertIngestionLog, ingestionLogs,
  type Connector, type InsertConnector, connectors,
  type AiFeedback, type InsertAiFeedback, aiFeedback,
  type Playbook, type InsertPlaybook, playbooks,
  type PlaybookExecution, type InsertPlaybookExecution, playbookExecutions,
  type PlaybookApproval, type InsertPlaybookApproval, playbookApprovals,
  type ThreatIntelConfig, type InsertThreatIntelConfig, threatIntelConfigs,
  type CompliancePolicy, type InsertCompliancePolicy, compliancePolicies,
  type DsarRequest, type InsertDsarRequest, dsarRequests,
  type IntegrationConfig, type InsertIntegrationConfig, integrationConfigs,
  type NotificationChannel, type InsertNotificationChannel, notificationChannels,
  type ResponseAction, type InsertResponseAction, responseActions,
  type PredictiveAnomaly, type InsertPredictiveAnomaly, predictiveAnomalies,
  type AttackSurfaceAsset, type InsertAttackSurfaceAsset, attackSurfaceAssets,
  type RiskForecast, type InsertRiskForecast, riskForecasts,
  type AnomalySubscription, type InsertAnomalySubscription, anomalySubscriptions,
  type ForecastQualitySnapshot, type InsertForecastQualitySnapshot, forecastQualitySnapshots,
  type HardeningRecommendation, type InsertHardeningRecommendation, hardeningRecommendations,
  type AutoResponsePolicy, type InsertAutoResponsePolicy, autoResponsePolicies,
  type InvestigationRun, type InsertInvestigationRun, investigationRuns,
  type InvestigationStep, type InsertInvestigationStep, investigationSteps,
  type ResponseActionRollback, type InsertResponseActionRollback, responseActionRollbacks,
  type CspmAccount, type InsertCspmAccount, cspmAccounts,
  type CspmScan, type InsertCspmScan, cspmScans,
  type CspmFinding, type InsertCspmFinding, cspmFindings,
  type EndpointAsset, type InsertEndpointAsset, endpointAssets,
  type EndpointTelemetry, type InsertEndpointTelemetry, endpointTelemetry,
  type PostureScore, type InsertPostureScore, postureScores,
  type AiDeploymentConfig, type InsertAiDeploymentConfig, aiDeploymentConfigs,
  alertTags, incidentTags,
  organizationMemberships, orgInvitations,
  type OrganizationMembership, type InsertOrganizationMembership,
  type OrgInvitation, type InsertOrgInvitation,
  type IocFeed, type InsertIocFeed, iocFeeds,
  type IocEntry, type InsertIocEntry, iocEntries,
  type IocWatchlist, type InsertIocWatchlist, iocWatchlists,
  type IocWatchlistEntry, type InsertIocWatchlistEntry, iocWatchlistEntries,
  type IocMatchRule, type InsertIocMatchRule, iocMatchRules,
  type IocMatch, type InsertIocMatch, iocMatches,
  type EvidenceItem, type InsertEvidenceItem, evidenceItems,
  type InvestigationHypothesis, type InsertInvestigationHypothesis, investigationHypotheses,
  type InvestigationTask, type InsertInvestigationTask, investigationTasks,
  type RunbookTemplate, type InsertRunbookTemplate, runbookTemplates,
  type RunbookStep, type InsertRunbookStep, runbookSteps,
  type ReportTemplate, type InsertReportTemplate, reportTemplates,
  type ReportSchedule, type InsertReportSchedule, reportSchedules,
  type ReportRun, type InsertReportRun, reportRuns,
  type SuppressionRule, type InsertSuppressionRule, suppressionRules,
  type AlertDedupCluster, type InsertAlertDedupCluster, alertDedupClusters,
  type IncidentSlaPolicy, type InsertIncidentSlaPolicy, incidentSlaPolicies,
  type PostIncidentReview, type InsertPostIncidentReview, postIncidentReviews,
  type ConnectorJobRun, type InsertConnectorJobRun, connectorJobRuns,
  type ConnectorHealthCheck, type InsertConnectorHealthCheck, connectorHealthChecks,
  type PolicyCheck, type InsertPolicyCheck, policyChecks,
  type PolicyResult, type InsertPolicyResult, policyResults,
  type ComplianceControl, type InsertComplianceControl, complianceControls,
  type ComplianceControlMapping, type InsertComplianceControlMapping, complianceControlMappings,
  type EvidenceLockerItem, type InsertEvidenceLockerItem, evidenceLockerItems,
  type OutboundWebhook, type InsertOutboundWebhook, outboundWebhooks,
  type OutboundWebhookLog, type InsertOutboundWebhookLog, outboundWebhookLogs,
  type IdempotencyKey, type InsertIdempotencyKey, idempotencyKeys,
  type AlertArchive, type InsertAlertArchive, alertsArchive,
  type JobQueue as Job, type InsertJobQueue as InsertJob, jobQueue,
  type DashboardMetricsCache, type InsertDashboardMetricsCache, dashboardMetricsCache,
  type AlertDailyStats as AlertDailyStat, type InsertAlertDailyStats as InsertAlertDailyStat, alertDailyStats,
  type SliMetric, type InsertSliMetric, sliMetrics,
  type SloTarget, type InsertSloTarget, sloTargets,
  type DrRunbook, type InsertDrRunbook, drRunbooks,
  type TicketSyncJob, type InsertTicketSyncJob, ticketSyncJobs,
  type ResponseActionApproval, type InsertResponseActionApproval, responseActionApprovals,
  type LegalHold, type InsertLegalHold, legalHolds,
  type ConnectorSecretRotation, type InsertConnectorSecretRotation, connectorSecretRotations,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, count, ilike, or, asc, inArray, isNull, gte, lte } from "drizzle-orm";
import { createHash } from "crypto";

export interface IStorage {
  getAlerts(orgId?: string): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined>;
  updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined>;
  searchAlerts(query: string, orgId?: string): Promise<Alert[]>;
  getAlertsByIncident(incidentId: string): Promise<Alert[]>;
  findAlertByDedup(orgId: string | null, source: string, sourceEventId: string): Promise<Alert | undefined>;
  upsertAlert(alert: InsertAlert): Promise<{ alert: Alert; isNew: boolean }>;

  getAlertsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
    search?: string;
  }): Promise<{ items: Alert[]; total: number }>;

  getIncidents(orgId?: string): Promise<Incident[]>;
  getIncident(id: string): Promise<Incident | undefined>;
  createIncident(incident: InsertIncident): Promise<Incident>;
  updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined>;

  getIncidentsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
    queue?: string;
  }): Promise<{ items: Incident[]; total: number }>;

  getOrganizations(): Promise<Organization[]>;
  getOrganization(id: string): Promise<Organization | undefined>;
  createOrganization(org: InsertOrganization): Promise<Organization>;

  createAuditLog(log: Partial<AuditLog>): Promise<AuditLog>;
  getAuditLogs(orgId?: string): Promise<AuditLog[]>;
  getAuditLogsByResource(resourceType: string, resourceId: string): Promise<AuditLog[]>;

  getComments(incidentId: string): Promise<IncidentComment[]>;
  createComment(comment: InsertComment): Promise<IncidentComment>;
  deleteComment(id: string): Promise<boolean>;

  getTags(): Promise<Tag[]>;
  createTag(tag: InsertTag): Promise<Tag>;
  deleteTag(id: string): Promise<boolean>;
  getAlertTags(alertId: string): Promise<Tag[]>;
  getIncidentTags(incidentId: string): Promise<Tag[]>;
  addAlertTag(alertId: string, tagId: string): Promise<void>;
  removeAlertTag(alertId: string, tagId: string): Promise<void>;
  addIncidentTag(incidentId: string, tagId: string): Promise<void>;
  removeIncidentTag(incidentId: string, tagId: string): Promise<void>;

  createApiKey(key: InsertApiKey): Promise<ApiKey>;
  getApiKeys(orgId?: string): Promise<ApiKey[]>;
  getApiKeyByHash(hash: string): Promise<ApiKey | undefined>;
  revokeApiKey(id: string): Promise<ApiKey | undefined>;
  updateApiKeyLastUsed(id: string): Promise<void>;

  createIngestionLog(log: InsertIngestionLog): Promise<IngestionLog>;
  getIngestionLogs(orgId?: string, limit?: number): Promise<IngestionLog[]>;
  getIngestionLogsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
  }): Promise<{ items: IngestionLog[]; total: number }>;
  getIngestionStats(orgId?: string): Promise<{
    totalIngested: number;
    totalCreated: number;
    totalDeduped: number;
    totalFailed: number;
    sourceBreakdown: { source: string; count: number; lastReceived: Date | null }[];
  }>;

  getConnectors(orgId?: string): Promise<Connector[]>;
  getConnector(id: string): Promise<Connector | undefined>;
  createConnector(connector: InsertConnector): Promise<Connector>;
  updateConnector(id: string, data: Partial<Connector>): Promise<Connector | undefined>;
  deleteConnector(id: string): Promise<boolean>;
  updateConnectorSyncStatus(id: string, data: { lastSyncAt: Date; lastSyncStatus: string; lastSyncAlerts: number; lastSyncError?: string; totalAlertsSynced?: number }): Promise<void>;

  getConnectorsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
  }): Promise<{ items: Connector[]; total: number }>;

  createAiFeedback(feedback: InsertAiFeedback): Promise<AiFeedback>;
  getAiFeedback(resourceType?: string, resourceId?: string): Promise<AiFeedback[]>;

  getPlaybooks(): Promise<Playbook[]>;
  getPlaybook(id: string): Promise<Playbook | undefined>;
  createPlaybook(playbook: InsertPlaybook): Promise<Playbook>;
  updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook | undefined>;
  deletePlaybook(id: string): Promise<boolean>;

  getPlaybookExecutions(playbookId?: string, limit?: number): Promise<PlaybookExecution[]>;
  getPlaybookExecution(id: string): Promise<PlaybookExecution | undefined>;
  createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution>;
  updatePlaybookExecution(id: string, data: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined>;

  getPlaybookApprovals(status?: string): Promise<PlaybookApproval[]>;
  getPlaybookApproval(id: string): Promise<PlaybookApproval | undefined>;
  getPlaybookApprovalsByExecution(executionId: string): Promise<PlaybookApproval[]>;
  createPlaybookApproval(approval: InsertPlaybookApproval): Promise<PlaybookApproval>;
  updatePlaybookApproval(id: string, data: Partial<PlaybookApproval>): Promise<PlaybookApproval | undefined>;

  getThreatIntelConfigs(orgId: string): Promise<ThreatIntelConfig[]>;
  getThreatIntelConfig(orgId: string, provider: string): Promise<ThreatIntelConfig | undefined>;
  upsertThreatIntelConfig(config: InsertThreatIntelConfig): Promise<ThreatIntelConfig>;
  deleteThreatIntelConfig(orgId: string, provider: string): Promise<void>;

  getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }>;

  getDashboardAnalytics(orgId?: string): Promise<{
    severityDistribution: { name: string; value: number }[];
    sourceDistribution: { name: string; value: number }[];
    categoryDistribution: { name: string; value: number }[];
    statusDistribution: { name: string; value: number }[];
    alertTrend: { date: string; count: number }[];
    mttrHours: number | null;
    topMitreTactics: { name: string; value: number }[];
    connectorHealth: { name: string; type: string; status: string; lastSyncAt: string | null; lastSyncAlerts: number; lastSyncError: string | null }[];
    ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
  }>;

  getCompliancePolicy(orgId: string): Promise<CompliancePolicy | undefined>;
  upsertCompliancePolicy(policy: InsertCompliancePolicy): Promise<CompliancePolicy>;

  getDsarRequests(orgId: string): Promise<DsarRequest[]>;
  getDsarRequest(id: string): Promise<DsarRequest | undefined>;
  createDsarRequest(request: InsertDsarRequest): Promise<DsarRequest>;
  updateDsarRequest(id: string, data: Partial<DsarRequest>): Promise<DsarRequest | undefined>;

  getAuditLogCount(orgId?: string): Promise<number>;
  getOldestAuditLog(orgId?: string): Promise<AuditLog | undefined>;
  getLatestAuditLogSequence(orgId: string): Promise<{ sequenceNum: number; entryHash: string } | null>;

  getIntegrationConfigs(orgId?: string): Promise<IntegrationConfig[]>;
  getIntegrationConfig(id: string): Promise<IntegrationConfig | undefined>;
  createIntegrationConfig(config: InsertIntegrationConfig): Promise<IntegrationConfig>;
  updateIntegrationConfig(id: string, data: Partial<IntegrationConfig>): Promise<IntegrationConfig | undefined>;
  deleteIntegrationConfig(id: string): Promise<boolean>;

  getNotificationChannels(orgId?: string): Promise<NotificationChannel[]>;
  getNotificationChannel(id: string): Promise<NotificationChannel | undefined>;
  createNotificationChannel(channel: InsertNotificationChannel): Promise<NotificationChannel>;
  updateNotificationChannel(id: string, data: Partial<NotificationChannel>): Promise<NotificationChannel | undefined>;
  deleteNotificationChannel(id: string): Promise<boolean>;

  getResponseActions(orgId?: string, incidentId?: string): Promise<ResponseAction[]>;
  getResponseAction(id: string): Promise<ResponseAction | undefined>;
  createResponseAction(action: InsertResponseAction): Promise<ResponseAction>;
  updateResponseAction(id: string, data: Partial<ResponseAction>): Promise<ResponseAction | undefined>;

  // Predictive Defense
  getPredictiveAnomalies(orgId?: string): Promise<PredictiveAnomaly[]>;
  createPredictiveAnomaly(anomaly: InsertPredictiveAnomaly): Promise<PredictiveAnomaly>;
  clearPredictiveAnomalies(orgId: string): Promise<void>;
  getAttackSurfaceAssets(orgId?: string): Promise<AttackSurfaceAsset[]>;
  upsertAttackSurfaceAsset(asset: InsertAttackSurfaceAsset): Promise<AttackSurfaceAsset>;
  clearAttackSurfaceAssets(orgId: string): Promise<void>;
  getRiskForecasts(orgId?: string): Promise<RiskForecast[]>;
  createRiskForecast(forecast: InsertRiskForecast): Promise<RiskForecast>;
  clearRiskForecasts(orgId: string): Promise<void>;
  getAnomalySubscriptions(orgId?: string): Promise<AnomalySubscription[]>;
  createAnomalySubscription(subscription: InsertAnomalySubscription): Promise<AnomalySubscription>;
  updateAnomalySubscription(id: string, updates: Partial<AnomalySubscription>): Promise<AnomalySubscription | undefined>;
  deleteAnomalySubscription(id: string): Promise<boolean>;
  getForecastQualitySnapshots(orgId?: string): Promise<ForecastQualitySnapshot[]>;
  createForecastQualitySnapshot(snapshot: InsertForecastQualitySnapshot): Promise<ForecastQualitySnapshot>;
  getHardeningRecommendations(orgId?: string): Promise<HardeningRecommendation[]>;
  createHardeningRecommendation(rec: InsertHardeningRecommendation): Promise<HardeningRecommendation>;
  updateHardeningRecommendation(id: string, updates: Partial<InsertHardeningRecommendation>): Promise<HardeningRecommendation | undefined>;
  clearHardeningRecommendations(orgId: string): Promise<void>;

  getAutoResponsePolicies(orgId?: string): Promise<AutoResponsePolicy[]>;
  createAutoResponsePolicy(policy: InsertAutoResponsePolicy): Promise<AutoResponsePolicy>;
  updateAutoResponsePolicy(id: string, updates: Partial<AutoResponsePolicy>): Promise<AutoResponsePolicy | null>;
  deleteAutoResponsePolicy(id: string): Promise<boolean>;

  getInvestigationRuns(orgId?: string): Promise<InvestigationRun[]>;
  getInvestigationRun(id: string): Promise<InvestigationRun | null>;
  createInvestigationRun(run: InsertInvestigationRun): Promise<InvestigationRun>;
  updateInvestigationRun(id: string, updates: Partial<InvestigationRun>): Promise<InvestigationRun | null>;

  getInvestigationSteps(runId: string): Promise<InvestigationStep[]>;
  createInvestigationStep(step: InsertInvestigationStep): Promise<InvestigationStep>;
  updateInvestigationStep(id: string, updates: Partial<InvestigationStep>): Promise<InvestigationStep | null>;

  getResponseActionRollbacks(orgId?: string): Promise<ResponseActionRollback[]>;
  createResponseActionRollback(rollback: InsertResponseActionRollback): Promise<ResponseActionRollback>;
  updateResponseActionRollback(id: string, updates: Partial<ResponseActionRollback>): Promise<ResponseActionRollback | null>;

  getCspmAccounts(orgId: string): Promise<CspmAccount[]>;
  getCspmAccount(id: string): Promise<CspmAccount | undefined>;
  createCspmAccount(account: InsertCspmAccount): Promise<CspmAccount>;
  updateCspmAccount(id: string, updates: Partial<CspmAccount>): Promise<CspmAccount | null>;
  deleteCspmAccount(id: string): Promise<boolean>;
  getCspmScans(orgId: string, accountId?: string): Promise<CspmScan[]>;
  createCspmScan(scan: InsertCspmScan): Promise<CspmScan>;
  updateCspmScan(id: string, updates: Partial<CspmScan>): Promise<CspmScan | null>;
  getCspmFindings(orgId: string, scanId?: string, severity?: string): Promise<CspmFinding[]>;
  createCspmFinding(finding: InsertCspmFinding): Promise<CspmFinding>;
  updateCspmFinding(id: string, updates: Partial<CspmFinding>): Promise<CspmFinding | null>;

  getEndpointAssets(orgId: string): Promise<EndpointAsset[]>;
  getEndpointAsset(id: string): Promise<EndpointAsset | undefined>;
  createEndpointAsset(asset: InsertEndpointAsset): Promise<EndpointAsset>;
  updateEndpointAsset(id: string, updates: Partial<EndpointAsset>): Promise<EndpointAsset | null>;
  deleteEndpointAsset(id: string): Promise<boolean>;
  getEndpointTelemetry(assetId: string): Promise<EndpointTelemetry[]>;
  createEndpointTelemetry(telemetry: InsertEndpointTelemetry): Promise<EndpointTelemetry>;

  getPostureScores(orgId: string): Promise<PostureScore[]>;
  createPostureScore(score: InsertPostureScore): Promise<PostureScore>;
  getLatestPostureScore(orgId: string): Promise<PostureScore | undefined>;

  getAiDeploymentConfig(orgId: string): Promise<AiDeploymentConfig | undefined>;
  upsertAiDeploymentConfig(config: InsertAiDeploymentConfig): Promise<AiDeploymentConfig>;

  getOrgMemberships(orgId: string): Promise<OrganizationMembership[]>;
  getOrgMembership(orgId: string, userId: string): Promise<OrganizationMembership | undefined>;
  getMembershipById(id: string): Promise<OrganizationMembership | undefined>;
  getUserMemberships(userId: string): Promise<OrganizationMembership[]>;
  createOrgMembership(membership: InsertOrganizationMembership): Promise<OrganizationMembership>;
  updateOrgMembership(id: string, data: Partial<OrganizationMembership>): Promise<OrganizationMembership | undefined>;
  deleteOrgMembership(id: string): Promise<boolean>;

  getOrgInvitations(orgId: string): Promise<OrgInvitation[]>;
  getOrgInvitationByToken(token: string): Promise<OrgInvitation | undefined>;
  createOrgInvitation(invitation: InsertOrgInvitation): Promise<OrgInvitation>;
  updateOrgInvitation(id: string, data: Partial<OrgInvitation>): Promise<OrgInvitation | undefined>;
  deleteOrgInvitation(id: string): Promise<boolean>;

  // IOC Feeds
  getIocFeeds(orgId?: string): Promise<IocFeed[]>;
  getIocFeed(id: string): Promise<IocFeed | undefined>;
  createIocFeed(feed: InsertIocFeed): Promise<IocFeed>;
  updateIocFeed(id: string, data: Partial<IocFeed>): Promise<IocFeed | undefined>;
  deleteIocFeed(id: string): Promise<boolean>;

  // IOC Entries
  getIocEntries(orgId?: string, feedId?: string, iocType?: string, status?: string, limit?: number): Promise<IocEntry[]>;
  getIocEntry(id: string): Promise<IocEntry | undefined>;
  getIocEntriesByValue(iocType: string, iocValue: string, orgId?: string): Promise<IocEntry[]>;
  createIocEntry(entry: InsertIocEntry): Promise<IocEntry>;
  createIocEntries(entries: InsertIocEntry[]): Promise<IocEntry[]>;
  updateIocEntry(id: string, data: Partial<IocEntry>): Promise<IocEntry | undefined>;
  deleteIocEntry(id: string): Promise<boolean>;

  // IOC Watchlists
  getIocWatchlists(orgId?: string): Promise<IocWatchlist[]>;
  getIocWatchlist(id: string): Promise<IocWatchlist | undefined>;
  createIocWatchlist(watchlist: InsertIocWatchlist): Promise<IocWatchlist>;
  updateIocWatchlist(id: string, data: Partial<IocWatchlist>): Promise<IocWatchlist | undefined>;
  deleteIocWatchlist(id: string): Promise<boolean>;
  addIocToWatchlist(entry: InsertIocWatchlistEntry): Promise<IocWatchlistEntry>;
  removeIocFromWatchlist(watchlistId: string, iocEntryId: string): Promise<boolean>;
  getWatchlistEntries(watchlistId: string): Promise<IocWatchlistEntry[]>;

  // IOC Match Rules
  getIocMatchRules(orgId?: string): Promise<IocMatchRule[]>;
  getIocMatchRule(id: string): Promise<IocMatchRule | undefined>;
  createIocMatchRule(rule: InsertIocMatchRule): Promise<IocMatchRule>;
  updateIocMatchRule(id: string, data: Partial<IocMatchRule>): Promise<IocMatchRule | undefined>;
  deleteIocMatchRule(id: string): Promise<boolean>;

  // IOC Matches
  getIocMatches(orgId?: string, alertId?: string, iocEntryId?: string, limit?: number): Promise<IocMatch[]>;
  createIocMatch(match: InsertIocMatch): Promise<IocMatch>;

  // Evidence Items
  getEvidenceItems(incidentId: string, orgId?: string): Promise<EvidenceItem[]>;
  getEvidenceItem(id: string): Promise<EvidenceItem | undefined>;
  createEvidenceItem(item: InsertEvidenceItem): Promise<EvidenceItem>;
  deleteEvidenceItem(id: string): Promise<boolean>;

  // Investigation Hypotheses
  getHypotheses(incidentId: string, orgId?: string): Promise<InvestigationHypothesis[]>;
  getHypothesis(id: string): Promise<InvestigationHypothesis | undefined>;
  createHypothesis(hypothesis: InsertInvestigationHypothesis): Promise<InvestigationHypothesis>;
  updateHypothesis(id: string, data: Partial<InvestigationHypothesis>): Promise<InvestigationHypothesis | undefined>;
  deleteHypothesis(id: string): Promise<boolean>;

  // Investigation Tasks
  getInvestigationTasks(incidentId: string, orgId?: string): Promise<InvestigationTask[]>;
  getInvestigationTask(id: string): Promise<InvestigationTask | undefined>;
  createInvestigationTask(task: InsertInvestigationTask): Promise<InvestigationTask>;
  updateInvestigationTask(id: string, data: Partial<InvestigationTask>): Promise<InvestigationTask | undefined>;
  deleteInvestigationTask(id: string): Promise<boolean>;

  // Runbook Templates
  getRunbookTemplates(orgId?: string, incidentType?: string): Promise<RunbookTemplate[]>;
  getRunbookTemplate(id: string): Promise<RunbookTemplate | undefined>;
  createRunbookTemplate(template: InsertRunbookTemplate): Promise<RunbookTemplate>;
  updateRunbookTemplate(id: string, data: Partial<RunbookTemplate>): Promise<RunbookTemplate | undefined>;
  deleteRunbookTemplate(id: string): Promise<boolean>;

  // Runbook Steps
  getRunbookSteps(templateId: string): Promise<RunbookStep[]>;
  createRunbookStep(step: InsertRunbookStep): Promise<RunbookStep>;
  updateRunbookStep(id: string, data: Partial<RunbookStep>): Promise<RunbookStep | undefined>;
  deleteRunbookStep(id: string): Promise<boolean>;

  // Reports
  getReportTemplates(orgId?: string): Promise<ReportTemplate[]>;
  getReportTemplate(id: string): Promise<ReportTemplate | undefined>;
  createReportTemplate(template: InsertReportTemplate): Promise<ReportTemplate>;
  updateReportTemplate(id: string, data: Partial<ReportTemplate>): Promise<ReportTemplate | undefined>;
  deleteReportTemplate(id: string): Promise<boolean>;

  getReportSchedules(orgId?: string): Promise<ReportSchedule[]>;
  getReportSchedule(id: string): Promise<ReportSchedule | undefined>;
  createReportSchedule(schedule: InsertReportSchedule): Promise<ReportSchedule>;
  updateReportSchedule(id: string, data: Partial<ReportSchedule>): Promise<ReportSchedule | undefined>;
  deleteReportSchedule(id: string): Promise<boolean>;

  getReportRuns(orgId?: string, templateId?: string, limit?: number): Promise<ReportRun[]>;
  getReportRun(id: string): Promise<ReportRun | undefined>;
  createReportRun(run: InsertReportRun): Promise<ReportRun>;
  updateReportRun(id: string, data: Partial<ReportRun>): Promise<ReportRun | undefined>;
  getDueSchedules(): Promise<ReportSchedule[]>;

  // Suppression Rules
  getSuppressionRules(orgId?: string): Promise<SuppressionRule[]>;
  getSuppressionRule(id: string): Promise<SuppressionRule | undefined>;
  createSuppressionRule(rule: InsertSuppressionRule): Promise<SuppressionRule>;
  updateSuppressionRule(id: string, data: Partial<SuppressionRule>): Promise<SuppressionRule | undefined>;
  deleteSuppressionRule(id: string): Promise<boolean>;

  // Alert Dedup Clusters
  getAlertDedupClusters(orgId?: string): Promise<AlertDedupCluster[]>;
  getAlertDedupCluster(id: string): Promise<AlertDedupCluster | undefined>;
  createAlertDedupCluster(cluster: InsertAlertDedupCluster): Promise<AlertDedupCluster>;
  updateAlertDedupCluster(id: string, data: Partial<AlertDedupCluster>): Promise<AlertDedupCluster | undefined>;

  // SLA Policies
  getIncidentSlaPolicies(orgId?: string): Promise<IncidentSlaPolicy[]>;
  getIncidentSlaPolicy(id: string): Promise<IncidentSlaPolicy | undefined>;
  createIncidentSlaPolicy(policy: InsertIncidentSlaPolicy): Promise<IncidentSlaPolicy>;
  updateIncidentSlaPolicy(id: string, data: Partial<IncidentSlaPolicy>): Promise<IncidentSlaPolicy | undefined>;
  deleteIncidentSlaPolicy(id: string): Promise<boolean>;

  // Post-Incident Reviews
  getPostIncidentReviews(orgId?: string, incidentId?: string): Promise<PostIncidentReview[]>;
  getPostIncidentReview(id: string): Promise<PostIncidentReview | undefined>;
  createPostIncidentReview(review: InsertPostIncidentReview): Promise<PostIncidentReview>;
  updatePostIncidentReview(id: string, data: Partial<PostIncidentReview>): Promise<PostIncidentReview | undefined>;
  deletePostIncidentReview(id: string): Promise<boolean>;

  createConnectorJobRun(run: InsertConnectorJobRun): Promise<ConnectorJobRun>;
  updateConnectorJobRun(id: string, updates: Partial<ConnectorJobRun>): Promise<ConnectorJobRun>;
  getConnectorJobRuns(connectorId: string, limit?: number): Promise<ConnectorJobRun[]>;
  getDeadLetterJobRuns(orgId?: string): Promise<ConnectorJobRun[]>;
  getConnectorMetrics(connectorId: string): Promise<{ avgLatencyMs: number; errorRate: number; throttleCount: number; totalRuns: number; successRate: number }>;

  createConnectorHealthCheck(check: InsertConnectorHealthCheck): Promise<ConnectorHealthCheck>;
  getConnectorHealthChecks(connectorId: string, limit?: number): Promise<ConnectorHealthCheck[]>;
  getLatestHealthCheck(connectorId: string): Promise<ConnectorHealthCheck | undefined>;

  getAiFeedbackMetrics(orgId?: string, days?: number): Promise<{ date: string; avgRating: number; totalFeedback: number; negativeFeedback: number; positiveFeedback: number }[]>;
  getAiFeedbackByResource(resourceType: string, resourceId: string): Promise<AiFeedback[]>;

  getPolicyChecks(orgId: string): Promise<PolicyCheck[]>;
  getPolicyCheck(id: string): Promise<PolicyCheck | undefined>;
  createPolicyCheck(check: InsertPolicyCheck): Promise<PolicyCheck>;
  updatePolicyCheck(id: string, data: Partial<PolicyCheck>): Promise<PolicyCheck | undefined>;
  deletePolicyCheck(id: string): Promise<boolean>;

  getPolicyResults(orgId: string, policyCheckId?: string): Promise<PolicyResult[]>;
  createPolicyResult(result: InsertPolicyResult): Promise<PolicyResult>;

  getComplianceControls(framework?: string): Promise<ComplianceControl[]>;
  getComplianceControl(id: string): Promise<ComplianceControl | undefined>;
  createComplianceControl(control: InsertComplianceControl): Promise<ComplianceControl>;
  createComplianceControls(controls: InsertComplianceControl[]): Promise<ComplianceControl[]>;
  updateComplianceControl(id: string, data: Partial<ComplianceControl>): Promise<ComplianceControl | undefined>;
  deleteComplianceControl(id: string): Promise<boolean>;
  deletePolicyResult(id: string): Promise<boolean>;

  getComplianceControlMappings(orgId: string, controlId?: string): Promise<ComplianceControlMapping[]>;
  createComplianceControlMapping(mapping: InsertComplianceControlMapping): Promise<ComplianceControlMapping>;
  updateComplianceControlMapping(id: string, data: Partial<ComplianceControlMapping>): Promise<ComplianceControlMapping | undefined>;
  deleteComplianceControlMapping(id: string): Promise<boolean>;

  getEvidenceLockerItems(orgId: string, framework?: string, artifactType?: string): Promise<EvidenceLockerItem[]>;
  getEvidenceLockerItem(id: string): Promise<EvidenceLockerItem | undefined>;
  createEvidenceLockerItem(item: InsertEvidenceLockerItem): Promise<EvidenceLockerItem>;
  updateEvidenceLockerItem(id: string, data: Partial<EvidenceLockerItem>): Promise<EvidenceLockerItem | undefined>;
  deleteEvidenceLockerItem(id: string): Promise<boolean>;

  getOutboundWebhooks(orgId: string): Promise<OutboundWebhook[]>;
  getOutboundWebhook(id: string): Promise<OutboundWebhook | undefined>;
  createOutboundWebhook(webhook: InsertOutboundWebhook): Promise<OutboundWebhook>;
  updateOutboundWebhook(id: string, data: Partial<OutboundWebhook>): Promise<OutboundWebhook | undefined>;
  deleteOutboundWebhook(id: string): Promise<boolean>;
  getActiveWebhooksByEvent(orgId: string, event: string): Promise<OutboundWebhook[]>;

  getOutboundWebhookLogs(webhookId: string, limit?: number): Promise<OutboundWebhookLog[]>;
  createOutboundWebhookLog(log: InsertOutboundWebhookLog): Promise<OutboundWebhookLog>;

  getIdempotencyKey(orgId: string, key: string, endpoint: string): Promise<IdempotencyKey | undefined>;
  createIdempotencyKey(key: InsertIdempotencyKey): Promise<IdempotencyKey>;
  cleanupExpiredIdempotencyKeys(): Promise<number>;

  // Alert Archive
  getArchivedAlerts(orgId: string, limit?: number, offset?: number): Promise<AlertArchive[]>;
  getArchivedAlertCount(orgId: string): Promise<number>;
  archiveAlerts(orgId: string, alertIds: string[], reason: string): Promise<number>;
  restoreArchivedAlerts(ids: string[]): Promise<number>;
  deleteArchivedAlerts(orgId: string, beforeDate: Date): Promise<number>;

  // Job Queue
  getJobs(orgId?: string, status?: string, type?: string, limit?: number): Promise<Job[]>;
  getJob(id: string): Promise<Job | undefined>;
  createJob(job: InsertJob): Promise<Job>;
  claimNextJob(types?: string[]): Promise<Job | undefined>;
  updateJob(id: string, data: Partial<Job>): Promise<Job | undefined>;
  cancelJob(id: string): Promise<boolean>;
  getJobStats(): Promise<{ pending: number; running: number; completed: number; failed: number }>;
  cleanupCompletedJobs(olderThanDays: number): Promise<number>;

  // Dashboard Metrics Cache
  getCachedMetrics(orgId: string, metricType: string): Promise<DashboardMetricsCache | undefined>;
  upsertCachedMetrics(data: InsertDashboardMetricsCache): Promise<DashboardMetricsCache>;
  clearExpiredCache(): Promise<number>;

  // Alert Daily Stats
  getAlertDailyStats(orgId: string, startDate: string, endDate: string): Promise<AlertDailyStat[]>;
  upsertAlertDailyStat(data: InsertAlertDailyStat): Promise<AlertDailyStat>;

  // SLI Metrics
  getSliMetrics(service: string, metric: string, startTime: Date, endTime: Date): Promise<SliMetric[]>;
  createSliMetric(data: InsertSliMetric): Promise<SliMetric>;
  createSliMetricsBatch(data: InsertSliMetric[]): Promise<SliMetric[]>;
  cleanupOldSliMetrics(olderThanDays: number): Promise<number>;

  // SLO Targets
  getSloTargets(): Promise<SloTarget[]>;
  getSloTarget(id: string): Promise<SloTarget | undefined>;
  createSloTarget(target: InsertSloTarget): Promise<SloTarget>;
  updateSloTarget(id: string, data: Partial<SloTarget>): Promise<SloTarget | undefined>;
  deleteSloTarget(id: string): Promise<boolean>;

  // DR Runbooks
  getDrRunbooks(orgId: string): Promise<DrRunbook[]>;
  getDrRunbook(id: string): Promise<DrRunbook | undefined>;
  createDrRunbook(runbook: InsertDrRunbook): Promise<DrRunbook>;
  updateDrRunbook(id: string, data: Partial<DrRunbook>): Promise<DrRunbook | undefined>;
  deleteDrRunbook(id: string): Promise<boolean>;
}

export class DatabaseStorage implements IStorage {
  async getAlerts(orgId?: string): Promise<Alert[]> {
    if (orgId) {
      return db.select().from(alerts).where(eq(alerts.orgId, orgId)).orderBy(desc(alerts.createdAt));
    }
    return db.select().from(alerts).orderBy(desc(alerts.createdAt));
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
    return alert;
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const [created] = await db.insert(alerts).values(alert).returning();
    return created;
  }

  async updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined> {
    const updateData: any = { status };
    if (incidentId) updateData.incidentId = incidentId;
    const [updated] = await db.update(alerts).set(updateData).where(eq(alerts.id, id)).returning();
    return updated;
  }

  async updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined> {
    const [updated] = await db.update(alerts).set(data).where(eq(alerts.id, id)).returning();
    return updated;
  }

  async searchAlerts(query: string, orgId?: string): Promise<Alert[]> {
    const searchPattern = `%${query}%`;
    const searchCondition = or(
      ilike(alerts.title, searchPattern),
      ilike(alerts.description, searchPattern),
      ilike(alerts.hostname, searchPattern),
      ilike(alerts.sourceIp, searchPattern),
    );
    if (orgId) {
      return db.select().from(alerts).where(and(eq(alerts.orgId, orgId), searchCondition)).orderBy(desc(alerts.createdAt));
    }
    return db.select().from(alerts).where(searchCondition).orderBy(desc(alerts.createdAt));
  }

  async getAlertsByIncident(incidentId: string): Promise<Alert[]> {
    return db.select().from(alerts).where(eq(alerts.incidentId, incidentId)).orderBy(desc(alerts.detectedAt));
  }

  async findAlertByDedup(orgId: string | null, source: string, sourceEventId: string): Promise<Alert | undefined> {
    if (!sourceEventId) return undefined;
    const conditions = [eq(alerts.source, source), eq(alerts.sourceEventId, sourceEventId)];
    if (orgId) conditions.push(eq(alerts.orgId, orgId));
    const [existing] = await db.select().from(alerts).where(and(...conditions));
    return existing;
  }

  async upsertAlert(alert: InsertAlert): Promise<{ alert: Alert; isNew: boolean }> {
    if (alert.sourceEventId) {
      const existing = await this.findAlertByDedup(alert.orgId || null, alert.source, alert.sourceEventId);
      if (existing) {
        return { alert: existing, isNew: false };
      }
    }
    const created = await this.createAlert(alert);
    return { alert: created, isNew: true };
  }

  async getAlertsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
    search?: string;
  }): Promise<{ items: Alert[]; total: number }> {
    const { orgId, offset, limit, search } = params;
    const searchPattern = search ? `%${search}%` : undefined;
    const textCondition = searchPattern
      ? or(
          ilike(alerts.title, searchPattern),
          ilike(alerts.description, searchPattern),
          ilike(alerts.hostname, searchPattern),
          ilike(alerts.sourceIp, searchPattern),
        )
      : undefined;

    let whereCondition: any = undefined;
    if (orgId && textCondition) {
      whereCondition = and(eq(alerts.orgId, orgId), textCondition);
    } else if (orgId) {
      whereCondition = eq(alerts.orgId, orgId);
    } else if (textCondition) {
      whereCondition = textCondition;
    }

    const totalQuery = db.select({ total: count() }).from(alerts);
    const itemsQuery = db.select().from(alerts).orderBy(desc(alerts.createdAt)).limit(limit).offset(offset);

    const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
    const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

    return { items, total: Number(totalRow?.total ?? 0) };
  }

  async getIncidents(orgId?: string): Promise<Incident[]> {
    if (orgId) {
      return db.select().from(incidents).where(eq(incidents.orgId, orgId)).orderBy(desc(incidents.createdAt));
    }
    return db.select().from(incidents).orderBy(desc(incidents.createdAt));
  }

  async getIncident(id: string): Promise<Incident | undefined> {
    const [incident] = await db.select().from(incidents).where(eq(incidents.id, id));
    return incident;
  }

  async createIncident(incident: InsertIncident): Promise<Incident> {
    const [created] = await db.insert(incidents).values(incident).returning();
    return created;
  }

  async updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined> {
    const [updated] = await db.update(incidents).set({ ...data, updatedAt: new Date() }).where(eq(incidents.id, id)).returning();
    return updated;
  }

  async getIncidentsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
    queue?: string;
  }): Promise<{ items: Incident[]; total: number }> {
    const { orgId, offset, limit, queue } = params;

    const conditions: any[] = [];
    if (orgId) {
      conditions.push(eq(incidents.orgId, orgId));
    }
    if (queue) {
      conditions.push(eq(incidents.queueState, queue as any));
    }

    const whereCondition = conditions.length ? and(...conditions) : undefined;

    const totalQuery = db.select({ total: count() }).from(incidents);
    const itemsQuery = db
      .select()
      .from(incidents)
      .orderBy(desc(incidents.createdAt))
      .limit(limit)
      .offset(offset);

    const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
    const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

    return { items, total: Number(totalRow?.total ?? 0) };
  }

  async getOrganizations(): Promise<Organization[]> {
    return db.select().from(organizations).orderBy(desc(organizations.createdAt));
  }

  async getOrganization(id: string): Promise<Organization | undefined> {
    const [org] = await db.select().from(organizations).where(eq(organizations.id, id));
    return org;
  }

  async createOrganization(org: InsertOrganization): Promise<Organization> {
    const [created] = await db.insert(organizations).values(org).returning();
    return created;
  }

  async createAuditLog(log: Partial<AuditLog>): Promise<AuditLog> {
    const orgId = log.orgId || "system";
    const lastSeq = await this.getLatestAuditLogSequence(orgId);
    const sequenceNum = lastSeq ? lastSeq.sequenceNum + 1 : 1;
    const prevHash = lastSeq ? lastSeq.entryHash : "genesis";
    const entryHash = createHash("sha256").update(JSON.stringify({
      prevHash,
      action: log.action,
      userId: log.userId,
      resourceType: log.resourceType,
      resourceId: log.resourceId,
      details: log.details,
      sequenceNum,
    })).digest("hex");
    const [created] = await db.insert(auditLogs).values({
      ...log,
      sequenceNum,
      prevHash,
      entryHash,
    } as any).returning();
    return created;
  }

  async getAuditLogs(orgId?: string): Promise<AuditLog[]> {
    if (orgId) {
      return db.select().from(auditLogs).where(eq(auditLogs.orgId, orgId)).orderBy(desc(auditLogs.createdAt));
    }
    return db.select().from(auditLogs).orderBy(desc(auditLogs.createdAt));
  }

  async getAuditLogsByResource(resourceType: string, resourceId: string): Promise<AuditLog[]> {
    return db.select().from(auditLogs)
      .where(and(eq(auditLogs.resourceType, resourceType), eq(auditLogs.resourceId, resourceId)))
      .orderBy(desc(auditLogs.createdAt));
  }

  async getComments(incidentId: string): Promise<IncidentComment[]> {
    return db.select().from(incidentComments).where(eq(incidentComments.incidentId, incidentId)).orderBy(desc(incidentComments.createdAt));
  }

  async createComment(comment: InsertComment): Promise<IncidentComment> {
    const [created] = await db.insert(incidentComments).values(comment).returning();
    return created;
  }

  async deleteComment(id: string): Promise<boolean> {
    const result = await db.delete(incidentComments).where(eq(incidentComments.id, id)).returning();
    return result.length > 0;
  }

  async getTags(): Promise<Tag[]> {
    return db.select().from(tags).orderBy(tags.name);
  }

  async createTag(tag: InsertTag): Promise<Tag> {
    const [created] = await db.insert(tags).values(tag).returning();
    return created;
  }

  async deleteTag(id: string): Promise<boolean> {
    const result = await db.delete(tags).where(eq(tags.id, id)).returning();
    return result.length > 0;
  }

  async getAlertTags(alertId: string): Promise<Tag[]> {
    const rows = await db.select({ tag: tags }).from(alertTags).innerJoin(tags, eq(alertTags.tagId, tags.id)).where(eq(alertTags.alertId, alertId));
    return rows.map(r => r.tag);
  }

  async getIncidentTags(incidentId: string): Promise<Tag[]> {
    const rows = await db.select({ tag: tags }).from(incidentTags).innerJoin(tags, eq(incidentTags.tagId, tags.id)).where(eq(incidentTags.incidentId, incidentId));
    return rows.map(r => r.tag);
  }

  async addAlertTag(alertId: string, tagId: string): Promise<void> {
    await db.insert(alertTags).values({ alertId, tagId }).onConflictDoNothing();
  }

  async removeAlertTag(alertId: string, tagId: string): Promise<void> {
    await db.delete(alertTags).where(and(eq(alertTags.alertId, alertId), eq(alertTags.tagId, tagId)));
  }

  async addIncidentTag(incidentId: string, tagId: string): Promise<void> {
    await db.insert(incidentTags).values({ incidentId, tagId }).onConflictDoNothing();
  }

  async removeIncidentTag(incidentId: string, tagId: string): Promise<void> {
    await db.delete(incidentTags).where(and(eq(incidentTags.incidentId, incidentId), eq(incidentTags.tagId, tagId)));
  }

  async createApiKey(key: InsertApiKey): Promise<ApiKey> {
    const [created] = await db.insert(apiKeys).values(key).returning();
    return created;
  }

  async getApiKeys(orgId?: string): Promise<ApiKey[]> {
    if (orgId) {
      return db.select().from(apiKeys).where(eq(apiKeys.orgId, orgId)).orderBy(desc(apiKeys.createdAt));
    }
    return db.select().from(apiKeys).orderBy(desc(apiKeys.createdAt));
  }

  async getApiKeyByHash(hash: string): Promise<ApiKey | undefined> {
    const [key] = await db.select().from(apiKeys).where(and(eq(apiKeys.keyHash, hash), eq(apiKeys.isActive, true)));
    return key;
  }

  async revokeApiKey(id: string): Promise<ApiKey | undefined> {
    const [updated] = await db.update(apiKeys).set({ isActive: false, revokedAt: new Date() }).where(eq(apiKeys.id, id)).returning();
    return updated;
  }

  async updateApiKeyLastUsed(id: string): Promise<void> {
    await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, id));
  }

  async createIngestionLog(log: InsertIngestionLog): Promise<IngestionLog> {
    const [created] = await db.insert(ingestionLogs).values(log).returning();
    return created;
  }

  async getIngestionLogs(orgId?: string, limit = 50): Promise<IngestionLog[]> {
    if (orgId) {
      return db.select().from(ingestionLogs).where(eq(ingestionLogs.orgId, orgId)).orderBy(desc(ingestionLogs.receivedAt)).limit(limit);
    }
    return db.select().from(ingestionLogs).orderBy(desc(ingestionLogs.receivedAt)).limit(limit);
  }

  async getIngestionLogsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
  }): Promise<{ items: IngestionLog[]; total: number }> {
    const { orgId, offset, limit } = params;

    const whereCondition = orgId ? eq(ingestionLogs.orgId, orgId) : undefined;

    const totalQuery = db.select({ total: count() }).from(ingestionLogs);
    const itemsQuery = db
      .select()
      .from(ingestionLogs)
      .orderBy(desc(ingestionLogs.receivedAt))
      .limit(limit)
      .offset(offset);

    const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
    const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

    return { items, total: Number(totalRow?.total ?? 0) };
  }

  async getIngestionStats(orgId?: string): Promise<{
    totalIngested: number;
    totalCreated: number;
    totalDeduped: number;
    totalFailed: number;
    sourceBreakdown: { source: string; count: number; lastReceived: Date | null }[];
  }> {
    const conditions = orgId ? [eq(ingestionLogs.orgId, orgId)] : [];
    const condition = conditions.length ? conditions[0] : undefined;

    const [totals] = await db.select({
      totalIngested: sql<number>`COALESCE(SUM(${ingestionLogs.alertsReceived}), 0)::int`,
      totalCreated: sql<number>`COALESCE(SUM(${ingestionLogs.alertsCreated}), 0)::int`,
      totalDeduped: sql<number>`COALESCE(SUM(${ingestionLogs.alertsDeduped}), 0)::int`,
      totalFailed: sql<number>`COALESCE(SUM(${ingestionLogs.alertsFailed}), 0)::int`,
    }).from(ingestionLogs).where(condition);

    const breakdown = await db.select({
      source: ingestionLogs.source,
      count: sql<number>`COUNT(*)::int`,
      lastReceived: sql<Date | null>`MAX(${ingestionLogs.receivedAt})`,
    }).from(ingestionLogs).where(condition).groupBy(ingestionLogs.source);

    return {
      totalIngested: totals?.totalIngested ?? 0,
      totalCreated: totals?.totalCreated ?? 0,
      totalDeduped: totals?.totalDeduped ?? 0,
      totalFailed: totals?.totalFailed ?? 0,
      sourceBreakdown: breakdown,
    };
  }

  async getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }> {
    const conditions = orgId ? [eq(alerts.orgId, orgId)] : [];
    const incidentConditions = orgId ? [eq(incidents.orgId, orgId)] : [];

    const [totalAlertsResult] = await db.select({ count: count() }).from(alerts).where(conditions.length ? conditions[0] : undefined);
    const [criticalResult] = await db.select({ count: count() }).from(alerts).where(
      conditions.length ? and(conditions[0], eq(alerts.severity, "critical")) : eq(alerts.severity, "critical")
    );
    const [openResult] = await db.select({ count: count() }).from(incidents).where(
      incidentConditions.length ? and(incidentConditions[0], eq(incidents.status, "open")) : eq(incidents.status, "open")
    );
    const [resolvedResult] = await db.select({ count: count() }).from(incidents).where(
      incidentConditions.length ? and(incidentConditions[0], eq(incidents.status, "resolved")) : eq(incidents.status, "resolved")
    );

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const [newTodayResult] = await db.select({ count: count() }).from(alerts).where(
      conditions.length
        ? and(conditions[0], sql`${alerts.createdAt} >= ${today}`)
        : sql`${alerts.createdAt} >= ${today}`
    );
    const [escalatedResult] = await db.select({ count: count() }).from(incidents).where(
      incidentConditions.length
        ? and(incidentConditions[0], eq(incidents.escalated, true))
        : eq(incidents.escalated, true)
    );

    return {
      totalAlerts: totalAlertsResult?.count ?? 0,
      openIncidents: openResult?.count ?? 0,
      criticalAlerts: criticalResult?.count ?? 0,
      resolvedIncidents: resolvedResult?.count ?? 0,
      newAlertsToday: newTodayResult?.count ?? 0,
      escalatedIncidents: escalatedResult?.count ?? 0,
    };
  }

  async getConnectors(orgId?: string): Promise<Connector[]> {
    if (orgId) {
      return db.select().from(connectors).where(eq(connectors.orgId, orgId)).orderBy(desc(connectors.createdAt));
    }
    return db.select().from(connectors).orderBy(desc(connectors.createdAt));
  }

  async getConnectorsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
  }): Promise<{ items: Connector[]; total: number }> {
    const { orgId, offset, limit } = params;
    const whereCondition = orgId ? eq(connectors.orgId, orgId) : undefined;

    const totalQuery = db.select({ total: count() }).from(connectors);
    const itemsQuery = db
      .select()
      .from(connectors)
      .orderBy(desc(connectors.createdAt))
      .limit(limit)
      .offset(offset);

    const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
    const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

    return { items, total: Number(totalRow?.total ?? 0) };
  }

  async getConnector(id: string): Promise<Connector | undefined> {
    const [result] = await db.select().from(connectors).where(eq(connectors.id, id));
    return result;
  }

  async createConnector(connector: InsertConnector): Promise<Connector> {
    const [result] = await db.insert(connectors).values(connector).returning();
    return result;
  }

  async updateConnector(id: string, data: Partial<Connector>): Promise<Connector | undefined> {
    const [result] = await db.update(connectors).set({ ...data, updatedAt: new Date() }).where(eq(connectors.id, id)).returning();
    return result;
  }

  async deleteConnector(id: string): Promise<boolean> {
    const result = await db.delete(connectors).where(eq(connectors.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async updateConnectorSyncStatus(id: string, data: { lastSyncAt: Date; lastSyncStatus: string; lastSyncAlerts: number; lastSyncError?: string; totalAlertsSynced?: number }): Promise<void> {
    const updateData: any = {
      lastSyncAt: data.lastSyncAt,
      lastSyncStatus: data.lastSyncStatus,
      lastSyncAlerts: data.lastSyncAlerts,
      lastSyncError: data.lastSyncError || null,
      updatedAt: new Date(),
    };
    if (data.totalAlertsSynced !== undefined) {
      updateData.totalAlertsSynced = data.totalAlertsSynced;
    }
    await db.update(connectors).set(updateData).where(eq(connectors.id, id));
  }

  async createAiFeedback(feedback: InsertAiFeedback): Promise<AiFeedback> {
    const [created] = await db.insert(aiFeedback).values(feedback).returning();
    return created;
  }

  async getAiFeedback(resourceType?: string, resourceId?: string): Promise<AiFeedback[]> {
    const conditions = [];
    if (resourceType) conditions.push(eq(aiFeedback.resourceType, resourceType));
    if (resourceId) conditions.push(eq(aiFeedback.resourceId, resourceId));
    const condition = conditions.length > 0 ? and(...conditions) : undefined;
    return db.select().from(aiFeedback).where(condition).orderBy(desc(aiFeedback.createdAt));
  }

  async getPlaybooks(): Promise<Playbook[]> {
    return db.select().from(playbooks).orderBy(desc(playbooks.updatedAt));
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const [playbook] = await db.select().from(playbooks).where(eq(playbooks.id, id));
    return playbook;
  }

  async createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
    const [created] = await db.insert(playbooks).values(playbook).returning();
    return created;
  }

  async updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook | undefined> {
    const [updated] = await db.update(playbooks).set({ ...data, updatedAt: new Date() }).where(eq(playbooks.id, id)).returning();
    return updated;
  }

  async deletePlaybook(id: string): Promise<boolean> {
    const result = await db.delete(playbooks).where(eq(playbooks.id, id)).returning();
    return result.length > 0;
  }

  async getPlaybookExecutions(playbookId?: string, limit = 50): Promise<PlaybookExecution[]> {
    if (playbookId) {
      return db.select().from(playbookExecutions).where(eq(playbookExecutions.playbookId, playbookId)).orderBy(desc(playbookExecutions.createdAt)).limit(limit);
    }
    return db.select().from(playbookExecutions).orderBy(desc(playbookExecutions.createdAt)).limit(limit);
  }

  async getPlaybookExecution(id: string): Promise<PlaybookExecution | undefined> {
    const [execution] = await db.select().from(playbookExecutions).where(eq(playbookExecutions.id, id));
    return execution;
  }

  async createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
    const [created] = await db.insert(playbookExecutions).values(execution).returning();
    return created;
  }

  async updatePlaybookExecution(id: string, data: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
    const [updated] = await db.update(playbookExecutions).set(data).where(eq(playbookExecutions.id, id)).returning();
    return updated;
  }

  async getPlaybookApprovals(status?: string): Promise<PlaybookApproval[]> {
    if (status) {
      return db.select().from(playbookApprovals).where(eq(playbookApprovals.status, status)).orderBy(desc(playbookApprovals.requestedAt));
    }
    return db.select().from(playbookApprovals).orderBy(desc(playbookApprovals.requestedAt));
  }

  async getPlaybookApproval(id: string): Promise<PlaybookApproval | undefined> {
    const [approval] = await db.select().from(playbookApprovals).where(eq(playbookApprovals.id, id));
    return approval;
  }

  async getPlaybookApprovalsByExecution(executionId: string): Promise<PlaybookApproval[]> {
    return db.select().from(playbookApprovals).where(eq(playbookApprovals.executionId, executionId)).orderBy(desc(playbookApprovals.requestedAt));
  }

  async createPlaybookApproval(approval: InsertPlaybookApproval): Promise<PlaybookApproval> {
    const [created] = await db.insert(playbookApprovals).values(approval).returning();
    return created;
  }

  async updatePlaybookApproval(id: string, data: Partial<PlaybookApproval>): Promise<PlaybookApproval | undefined> {
    const [updated] = await db.update(playbookApprovals).set(data).where(eq(playbookApprovals.id, id)).returning();
    return updated;
  }

  async getThreatIntelConfigs(orgId: string): Promise<ThreatIntelConfig[]> {
    return db.select().from(threatIntelConfigs).where(eq(threatIntelConfigs.orgId, orgId)).orderBy(desc(threatIntelConfigs.createdAt));
  }

  async getThreatIntelConfig(orgId: string, provider: string): Promise<ThreatIntelConfig | undefined> {
    const [config] = await db.select().from(threatIntelConfigs).where(and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider)));
    return config;
  }

  async upsertThreatIntelConfig(config: InsertThreatIntelConfig): Promise<ThreatIntelConfig> {
    const [result] = await db.insert(threatIntelConfigs).values(config).onConflictDoUpdate({
      target: [threatIntelConfigs.orgId, threatIntelConfigs.provider],
      set: {
        apiKey: config.apiKey,
        enabled: config.enabled,
        updatedAt: new Date(),
      },
    }).returning();
    return result;
  }

  async deleteThreatIntelConfig(orgId: string, provider: string): Promise<void> {
    await db.delete(threatIntelConfigs).where(and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider)));
  }

  async getDashboardAnalytics(orgId?: string): Promise<{
    severityDistribution: { name: string; value: number }[];
    sourceDistribution: { name: string; value: number }[];
    categoryDistribution: { name: string; value: number }[];
    statusDistribution: { name: string; value: number }[];
    alertTrend: { date: string; count: number }[];
    mttrHours: number | null;
    topMitreTactics: { name: string; value: number }[];
    connectorHealth: { name: string; type: string; status: string; lastSyncAt: string | null; lastSyncAlerts: number; lastSyncError: string | null }[];
    ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
  }> {
    const alertCond = orgId ? eq(alerts.orgId, orgId) : undefined;
    const incidentCond = orgId ? eq(incidents.orgId, orgId) : undefined;
    const connectorCond = orgId ? eq(connectors.orgId, orgId) : undefined;
    const ingestionCond = orgId ? eq(ingestionLogs.orgId, orgId) : undefined;

    const severityDistribution = await db
      .select({ name: alerts.severity, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.severity);

    const sourceDistribution = await db
      .select({ name: alerts.source, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.source).orderBy(sql`COUNT(*) DESC`).limit(10);

    const categoryDistribution = await db
      .select({ name: alerts.category, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.category).orderBy(sql`COUNT(*) DESC`).limit(10);

    const statusDistribution = await db
      .select({ name: alerts.status, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.status);

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const trendCond = alertCond
      ? and(alertCond, sql`${alerts.createdAt} >= ${sevenDaysAgo}`)
      : sql`${alerts.createdAt} >= ${sevenDaysAgo}`;
    const alertTrend = await db
      .select({
        date: sql<string>`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`,
        count: sql<number>`COUNT(*)::int`,
      })
      .from(alerts).where(trendCond)
      .groupBy(sql`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`)
      .orderBy(sql`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`);

    const mttrResult = await db
      .select({
        avgHours: sql<number | null>`AVG(EXTRACT(EPOCH FROM (${incidents.resolvedAt} - ${incidents.createdAt})) / 3600)`,
      })
      .from(incidents)
      .where(incidentCond ? and(incidentCond, sql`${incidents.resolvedAt} IS NOT NULL`) : sql`${incidents.resolvedAt} IS NOT NULL`);
    const mttrHours = mttrResult[0]?.avgHours ? Math.round(mttrResult[0].avgHours * 10) / 10 : null;

    const tacticRows = await db
      .select({ tactic: alerts.mitreTactic, value: sql<number>`COUNT(*)::int` })
      .from(alerts)
      .where(alertCond ? and(alertCond, sql`${alerts.mitreTactic} IS NOT NULL AND ${alerts.mitreTactic} != ''`) : sql`${alerts.mitreTactic} IS NOT NULL AND ${alerts.mitreTactic} != ''`)
      .groupBy(alerts.mitreTactic)
      .orderBy(sql`COUNT(*) DESC`)
      .limit(8);
    const topMitreTactics = tacticRows.map(r => ({ name: r.tactic || "Unknown", value: r.value }));

    const connectorRows = await db
      .select({
        name: connectors.name,
        type: connectors.type,
        status: connectors.status,
        lastSyncAt: connectors.lastSyncAt,
        lastSyncAlerts: connectors.lastSyncAlerts,
        lastSyncError: connectors.lastSyncError,
      })
      .from(connectors).where(connectorCond).orderBy(desc(connectors.updatedAt));
    const connectorHealth = connectorRows.map(r => ({
      name: r.name,
      type: r.type,
      status: r.status,
      lastSyncAt: r.lastSyncAt?.toISOString() || null,
      lastSyncAlerts: r.lastSyncAlerts || 0,
      lastSyncError: r.lastSyncError,
    }));

    const ingestionTrendCond = ingestionCond
      ? and(ingestionCond, sql`${ingestionLogs.receivedAt} >= ${sevenDaysAgo}`)
      : sql`${ingestionLogs.receivedAt} >= ${sevenDaysAgo}`;
    const ingestionRate = await db
      .select({
        date: sql<string>`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`,
        created: sql<number>`COALESCE(SUM(${ingestionLogs.alertsCreated}), 0)::int`,
        deduped: sql<number>`COALESCE(SUM(${ingestionLogs.alertsDeduped}), 0)::int`,
        failed: sql<number>`COALESCE(SUM(${ingestionLogs.alertsFailed}), 0)::int`,
      })
      .from(ingestionLogs).where(ingestionTrendCond)
      .groupBy(sql`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`)
      .orderBy(sql`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`);

    return {
      severityDistribution: severityDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      sourceDistribution: sourceDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      categoryDistribution: categoryDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      statusDistribution: statusDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      alertTrend,
      mttrHours,
      topMitreTactics,
      connectorHealth,
      ingestionRate,
    };
  }
  async getCompliancePolicy(orgId: string): Promise<CompliancePolicy | undefined> {
    const [policy] = await db.select().from(compliancePolicies).where(eq(compliancePolicies.orgId, orgId));
    return policy;
  }

  async upsertCompliancePolicy(policy: InsertCompliancePolicy): Promise<CompliancePolicy> {
    const [result] = await db.insert(compliancePolicies).values(policy).onConflictDoUpdate({
      target: [compliancePolicies.orgId],
      set: {
        alertRetentionDays: policy.alertRetentionDays,
        incidentRetentionDays: policy.incidentRetentionDays,
        auditLogRetentionDays: policy.auditLogRetentionDays,
        piiMaskingEnabled: policy.piiMaskingEnabled,
        pseudonymizeExports: policy.pseudonymizeExports,
        enabledFrameworks: policy.enabledFrameworks,
        dataProcessingBasis: policy.dataProcessingBasis,
        dpoEmail: policy.dpoEmail,
        dsarSlaDays: policy.dsarSlaDays,
        updatedAt: new Date(),
      },
    }).returning();
    return result;
  }

  async getDsarRequests(orgId: string): Promise<DsarRequest[]> {
    return db.select().from(dsarRequests).where(eq(dsarRequests.orgId, orgId)).orderBy(desc(dsarRequests.createdAt));
  }

  async getDsarRequest(id: string): Promise<DsarRequest | undefined> {
    const [request] = await db.select().from(dsarRequests).where(eq(dsarRequests.id, id));
    return request;
  }

  async createDsarRequest(request: InsertDsarRequest): Promise<DsarRequest> {
    const [created] = await db.insert(dsarRequests).values(request).returning();
    return created;
  }

  async updateDsarRequest(id: string, data: Partial<DsarRequest>): Promise<DsarRequest | undefined> {
    const [updated] = await db.update(dsarRequests).set({ ...data, updatedAt: new Date() }).where(eq(dsarRequests.id, id)).returning();
    return updated;
  }

  async getAuditLogCount(orgId?: string): Promise<number> {
    const condition = orgId ? eq(auditLogs.orgId, orgId) : undefined;
    const [result] = await db.select({ count: count() }).from(auditLogs).where(condition);
    return result?.count ?? 0;
  }

  async getOldestAuditLog(orgId?: string): Promise<AuditLog | undefined> {
    const condition = orgId ? eq(auditLogs.orgId, orgId) : undefined;
    const [oldest] = await db.select().from(auditLogs).where(condition).orderBy(asc(auditLogs.createdAt)).limit(1);
    return oldest;
  }

  async getLatestAuditLogSequence(orgId: string): Promise<{ sequenceNum: number; entryHash: string } | null> {
    const [result] = await db.select({
      sequenceNum: auditLogs.sequenceNum,
      entryHash: auditLogs.entryHash,
    }).from(auditLogs).where(eq(auditLogs.orgId, orgId)).orderBy(desc(auditLogs.sequenceNum)).limit(1);
    if (!result || result.sequenceNum === null || result.entryHash === null) return null;
    return { sequenceNum: result.sequenceNum, entryHash: result.entryHash };
  }

  async getIntegrationConfigs(orgId?: string): Promise<IntegrationConfig[]> {
    if (orgId) {
      return db.select().from(integrationConfigs).where(eq(integrationConfigs.orgId, orgId)).orderBy(desc(integrationConfigs.createdAt));
    }
    return db.select().from(integrationConfigs).orderBy(desc(integrationConfigs.createdAt));
  }

  async getIntegrationConfig(id: string): Promise<IntegrationConfig | undefined> {
    const [config] = await db.select().from(integrationConfigs).where(eq(integrationConfigs.id, id));
    return config;
  }

  async createIntegrationConfig(config: InsertIntegrationConfig): Promise<IntegrationConfig> {
    const [created] = await db.insert(integrationConfigs).values(config).returning();
    return created;
  }

  async updateIntegrationConfig(id: string, data: Partial<IntegrationConfig>): Promise<IntegrationConfig | undefined> {
    const [updated] = await db.update(integrationConfigs).set({ ...data, updatedAt: new Date() }).where(eq(integrationConfigs.id, id)).returning();
    return updated;
  }

  async deleteIntegrationConfig(id: string): Promise<boolean> {
    const result = await db.delete(integrationConfigs).where(eq(integrationConfigs.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getNotificationChannels(orgId?: string): Promise<NotificationChannel[]> {
    if (orgId) {
      return db.select().from(notificationChannels).where(eq(notificationChannels.orgId, orgId)).orderBy(desc(notificationChannels.createdAt));
    }
    return db.select().from(notificationChannels).orderBy(desc(notificationChannels.createdAt));
  }

  async getNotificationChannel(id: string): Promise<NotificationChannel | undefined> {
    const [channel] = await db.select().from(notificationChannels).where(eq(notificationChannels.id, id));
    return channel;
  }

  async createNotificationChannel(channel: InsertNotificationChannel): Promise<NotificationChannel> {
    const [created] = await db.insert(notificationChannels).values(channel).returning();
    return created;
  }

  async updateNotificationChannel(id: string, data: Partial<NotificationChannel>): Promise<NotificationChannel | undefined> {
    const [updated] = await db.update(notificationChannels).set({ ...data, updatedAt: new Date() }).where(eq(notificationChannels.id, id)).returning();
    return updated;
  }

  async deleteNotificationChannel(id: string): Promise<boolean> {
    const result = await db.delete(notificationChannels).where(eq(notificationChannels.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getResponseActions(orgId?: string, incidentId?: string): Promise<ResponseAction[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(responseActions.orgId, orgId));
    if (incidentId) conditions.push(eq(responseActions.incidentId, incidentId));
    const condition = conditions.length > 0 ? and(...conditions) : undefined;
    return db.select().from(responseActions).where(condition).orderBy(desc(responseActions.createdAt)).limit(100);
  }

  async getResponseAction(id: string): Promise<ResponseAction | undefined> {
    const [action] = await db.select().from(responseActions).where(eq(responseActions.id, id));
    return action;
  }

  async createResponseAction(action: InsertResponseAction): Promise<ResponseAction> {
    const [created] = await db.insert(responseActions).values(action).returning();
    return created;
  }

  async updateResponseAction(id: string, data: Partial<ResponseAction>): Promise<ResponseAction | undefined> {
    const [updated] = await db.update(responseActions).set(data).where(eq(responseActions.id, id)).returning();
    return updated;
  }

  async getPredictiveAnomalies(orgId?: string): Promise<PredictiveAnomaly[]> {
    if (orgId) {
      return db.select().from(predictiveAnomalies).where(eq(predictiveAnomalies.orgId, orgId)).orderBy(desc(predictiveAnomalies.createdAt));
    }
    return db.select().from(predictiveAnomalies).orderBy(desc(predictiveAnomalies.createdAt));
  }

  async createPredictiveAnomaly(anomaly: InsertPredictiveAnomaly): Promise<PredictiveAnomaly> {
    const [created] = await db.insert(predictiveAnomalies).values(anomaly).returning();
    return created;
  }

  async clearPredictiveAnomalies(orgId: string): Promise<void> {
    await db.delete(predictiveAnomalies).where(eq(predictiveAnomalies.orgId, orgId));
  }

  async getAttackSurfaceAssets(orgId?: string): Promise<AttackSurfaceAsset[]> {
    if (orgId) {
      return db.select().from(attackSurfaceAssets).where(eq(attackSurfaceAssets.orgId, orgId)).orderBy(desc(attackSurfaceAssets.riskScore));
    }
    return db.select().from(attackSurfaceAssets).orderBy(desc(attackSurfaceAssets.riskScore));
  }

  async upsertAttackSurfaceAsset(asset: InsertAttackSurfaceAsset): Promise<AttackSurfaceAsset> {
    const conditions = [
      eq(attackSurfaceAssets.entityType, asset.entityType),
      eq(attackSurfaceAssets.entityValue, asset.entityValue),
    ];
    if (asset.orgId) conditions.push(eq(attackSurfaceAssets.orgId, asset.orgId));
    const [existing] = await db.select().from(attackSurfaceAssets).where(and(...conditions));
    if (existing) {
      const [updated] = await db.update(attackSurfaceAssets).set({
        ...asset,
        updatedAt: new Date(),
      }).where(eq(attackSurfaceAssets.id, existing.id)).returning();
      return updated;
    }
    const [created] = await db.insert(attackSurfaceAssets).values(asset).returning();
    return created;
  }

  async clearAttackSurfaceAssets(orgId: string): Promise<void> {
    await db.delete(attackSurfaceAssets).where(eq(attackSurfaceAssets.orgId, orgId));
  }

  async getRiskForecasts(orgId?: string): Promise<RiskForecast[]> {
    if (orgId) {
      return db.select().from(riskForecasts).where(eq(riskForecasts.orgId, orgId)).orderBy(desc(riskForecasts.probability));
    }
    return db.select().from(riskForecasts).orderBy(desc(riskForecasts.probability));
  }

  async createRiskForecast(forecast: InsertRiskForecast): Promise<RiskForecast> {
    const [created] = await db.insert(riskForecasts).values(forecast).returning();
    return created;
  }

  async clearRiskForecasts(orgId: string): Promise<void> {
    await db.delete(riskForecasts).where(eq(riskForecasts.orgId, orgId));
  }

  async getAnomalySubscriptions(orgId?: string): Promise<AnomalySubscription[]> {
    if (orgId) {
      return db.select().from(anomalySubscriptions).where(eq(anomalySubscriptions.orgId, orgId)).orderBy(desc(anomalySubscriptions.createdAt));
    }
    return db.select().from(anomalySubscriptions).orderBy(desc(anomalySubscriptions.createdAt));
  }

  async createAnomalySubscription(subscription: InsertAnomalySubscription): Promise<AnomalySubscription> {
    const [created] = await db.insert(anomalySubscriptions).values(subscription).returning();
    return created;
  }

  async updateAnomalySubscription(id: string, updates: Partial<AnomalySubscription>): Promise<AnomalySubscription | undefined> {
    const [updated] = await db.update(anomalySubscriptions).set({ ...updates, updatedAt: new Date() }).where(eq(anomalySubscriptions.id, id)).returning();
    return updated;
  }

  async deleteAnomalySubscription(id: string): Promise<boolean> {
    const result = await db.delete(anomalySubscriptions).where(eq(anomalySubscriptions.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getForecastQualitySnapshots(orgId?: string): Promise<ForecastQualitySnapshot[]> {
    if (orgId) {
      return db.select().from(forecastQualitySnapshots).where(eq(forecastQualitySnapshots.orgId, orgId)).orderBy(desc(forecastQualitySnapshots.measuredAt));
    }
    return db.select().from(forecastQualitySnapshots).orderBy(desc(forecastQualitySnapshots.measuredAt));
  }

  async createForecastQualitySnapshot(snapshot: InsertForecastQualitySnapshot): Promise<ForecastQualitySnapshot> {
    const [created] = await db.insert(forecastQualitySnapshots).values(snapshot).returning();
    return created;
  }

  async getHardeningRecommendations(orgId?: string): Promise<HardeningRecommendation[]> {
    if (orgId) {
      return db.select().from(hardeningRecommendations).where(eq(hardeningRecommendations.orgId, orgId)).orderBy(desc(hardeningRecommendations.createdAt));
    }
    return db.select().from(hardeningRecommendations).orderBy(desc(hardeningRecommendations.createdAt));
  }

  async createHardeningRecommendation(rec: InsertHardeningRecommendation): Promise<HardeningRecommendation> {
    const [created] = await db.insert(hardeningRecommendations).values(rec).returning();
    return created;
  }

  async updateHardeningRecommendation(id: string, updates: Partial<InsertHardeningRecommendation>): Promise<HardeningRecommendation | undefined> {
    const [updated] = await db.update(hardeningRecommendations).set({ ...updates, updatedAt: new Date() }).where(eq(hardeningRecommendations.id, id)).returning();
    return updated;
  }

  async clearHardeningRecommendations(orgId: string): Promise<void> {
    await db.delete(hardeningRecommendations).where(eq(hardeningRecommendations.orgId, orgId));
  }

  async getAutoResponsePolicies(orgId?: string): Promise<AutoResponsePolicy[]> {
    if (orgId) {
      return db.select().from(autoResponsePolicies).where(eq(autoResponsePolicies.orgId, orgId)).orderBy(desc(autoResponsePolicies.createdAt));
    }
    return db.select().from(autoResponsePolicies).orderBy(desc(autoResponsePolicies.createdAt));
  }

  async createAutoResponsePolicy(policy: InsertAutoResponsePolicy): Promise<AutoResponsePolicy> {
    const [created] = await db.insert(autoResponsePolicies).values(policy).returning();
    return created;
  }

  async updateAutoResponsePolicy(id: string, updates: Partial<AutoResponsePolicy>): Promise<AutoResponsePolicy | null> {
    const [updated] = await db.update(autoResponsePolicies).set({ ...updates, updatedAt: new Date() }).where(eq(autoResponsePolicies.id, id)).returning();
    return updated || null;
  }

  async deleteAutoResponsePolicy(id: string): Promise<boolean> {
    const result = await db.delete(autoResponsePolicies).where(eq(autoResponsePolicies.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getInvestigationRuns(orgId?: string): Promise<InvestigationRun[]> {
    if (orgId) {
      return db.select().from(investigationRuns).where(eq(investigationRuns.orgId, orgId)).orderBy(desc(investigationRuns.createdAt));
    }
    return db.select().from(investigationRuns).orderBy(desc(investigationRuns.createdAt));
  }

  async getInvestigationRun(id: string): Promise<InvestigationRun | null> {
    const [run] = await db.select().from(investigationRuns).where(eq(investigationRuns.id, id));
    return run || null;
  }

  async createInvestigationRun(run: InsertInvestigationRun): Promise<InvestigationRun> {
    const [created] = await db.insert(investigationRuns).values(run).returning();
    return created;
  }

  async updateInvestigationRun(id: string, updates: Partial<InvestigationRun>): Promise<InvestigationRun | null> {
    const [updated] = await db.update(investigationRuns).set(updates).where(eq(investigationRuns.id, id)).returning();
    return updated || null;
  }

  async getInvestigationSteps(runId: string): Promise<InvestigationStep[]> {
    return db.select().from(investigationSteps).where(eq(investigationSteps.runId, runId)).orderBy(asc(investigationSteps.stepOrder));
  }

  async createInvestigationStep(step: InsertInvestigationStep): Promise<InvestigationStep> {
    const [created] = await db.insert(investigationSteps).values(step).returning();
    return created;
  }

  async updateInvestigationStep(id: string, updates: Partial<InvestigationStep>): Promise<InvestigationStep | null> {
    const [updated] = await db.update(investigationSteps).set(updates).where(eq(investigationSteps.id, id)).returning();
    return updated || null;
  }

  async getResponseActionRollbacks(orgId?: string): Promise<ResponseActionRollback[]> {
    if (orgId) {
      return db.select().from(responseActionRollbacks).where(eq(responseActionRollbacks.orgId, orgId)).orderBy(desc(responseActionRollbacks.createdAt));
    }
    return db.select().from(responseActionRollbacks).orderBy(desc(responseActionRollbacks.createdAt));
  }

  async createResponseActionRollback(rollback: InsertResponseActionRollback): Promise<ResponseActionRollback> {
    const [created] = await db.insert(responseActionRollbacks).values(rollback).returning();
    return created;
  }

  async updateResponseActionRollback(id: string, updates: Partial<ResponseActionRollback>): Promise<ResponseActionRollback | null> {
    const [updated] = await db.update(responseActionRollbacks).set(updates).where(eq(responseActionRollbacks.id, id)).returning();
    return updated || null;
  }

  async getCspmAccounts(orgId: string): Promise<CspmAccount[]> {
    return db.select().from(cspmAccounts).where(eq(cspmAccounts.orgId, orgId)).orderBy(desc(cspmAccounts.createdAt));
  }

  async getCspmAccount(id: string): Promise<CspmAccount | undefined> {
    const [account] = await db.select().from(cspmAccounts).where(eq(cspmAccounts.id, id));
    return account;
  }

  async createCspmAccount(account: InsertCspmAccount): Promise<CspmAccount> {
    const [created] = await db.insert(cspmAccounts).values(account).returning();
    return created;
  }

  async updateCspmAccount(id: string, updates: Partial<CspmAccount>): Promise<CspmAccount | null> {
    const [updated] = await db.update(cspmAccounts).set(updates).where(eq(cspmAccounts.id, id)).returning();
    return updated || null;
  }

  async deleteCspmAccount(id: string): Promise<boolean> {
    const result = await db.delete(cspmAccounts).where(eq(cspmAccounts.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getCspmScans(orgId: string, accountId?: string): Promise<CspmScan[]> {
    const conditions = [eq(cspmScans.orgId, orgId)];
    if (accountId) conditions.push(eq(cspmScans.accountId, accountId));
    return db.select().from(cspmScans).where(and(...conditions)).orderBy(desc(cspmScans.startedAt));
  }

  async createCspmScan(scan: InsertCspmScan): Promise<CspmScan> {
    const [created] = await db.insert(cspmScans).values(scan).returning();
    return created;
  }

  async updateCspmScan(id: string, updates: Partial<CspmScan>): Promise<CspmScan | null> {
    const [updated] = await db.update(cspmScans).set(updates).where(eq(cspmScans.id, id)).returning();
    return updated || null;
  }

  async getCspmFindings(orgId: string, scanId?: string, severity?: string): Promise<CspmFinding[]> {
    const conditions: any[] = [eq(cspmFindings.orgId, orgId)];
    if (scanId) conditions.push(eq(cspmFindings.scanId, scanId));
    if (severity) conditions.push(eq(cspmFindings.severity, severity));
    return db.select().from(cspmFindings).where(and(...conditions)).orderBy(desc(cspmFindings.detectedAt));
  }

  async createCspmFinding(finding: InsertCspmFinding): Promise<CspmFinding> {
    const [created] = await db.insert(cspmFindings).values(finding).returning();
    return created;
  }

  async updateCspmFinding(id: string, updates: Partial<CspmFinding>): Promise<CspmFinding | null> {
    const [updated] = await db.update(cspmFindings).set(updates).where(eq(cspmFindings.id, id)).returning();
    return updated || null;
  }

  async getEndpointAssets(orgId: string): Promise<EndpointAsset[]> {
    return db.select().from(endpointAssets).where(eq(endpointAssets.orgId, orgId)).orderBy(desc(endpointAssets.createdAt));
  }

  async getEndpointAsset(id: string): Promise<EndpointAsset | undefined> {
    const [asset] = await db.select().from(endpointAssets).where(eq(endpointAssets.id, id));
    return asset;
  }

  async createEndpointAsset(asset: InsertEndpointAsset): Promise<EndpointAsset> {
    const [created] = await db.insert(endpointAssets).values(asset).returning();
    return created;
  }

  async updateEndpointAsset(id: string, updates: Partial<EndpointAsset>): Promise<EndpointAsset | null> {
    const [updated] = await db.update(endpointAssets).set(updates).where(eq(endpointAssets.id, id)).returning();
    return updated || null;
  }

  async deleteEndpointAsset(id: string): Promise<boolean> {
    const result = await db.delete(endpointAssets).where(eq(endpointAssets.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getEndpointTelemetry(assetId: string): Promise<EndpointTelemetry[]> {
    return db.select().from(endpointTelemetry).where(eq(endpointTelemetry.assetId, assetId)).orderBy(desc(endpointTelemetry.collectedAt));
  }

  async createEndpointTelemetry(telemetry: InsertEndpointTelemetry): Promise<EndpointTelemetry> {
    const [created] = await db.insert(endpointTelemetry).values(telemetry).returning();
    return created;
  }

  async getPostureScores(orgId: string): Promise<PostureScore[]> {
    return db.select().from(postureScores).where(eq(postureScores.orgId, orgId)).orderBy(desc(postureScores.generatedAt));
  }

  async createPostureScore(score: InsertPostureScore): Promise<PostureScore> {
    const [created] = await db.insert(postureScores).values(score).returning();
    return created;
  }

  async getLatestPostureScore(orgId: string): Promise<PostureScore | undefined> {
    const [score] = await db.select().from(postureScores).where(eq(postureScores.orgId, orgId)).orderBy(desc(postureScores.generatedAt)).limit(1);
    return score;
  }

  async getAiDeploymentConfig(orgId: string): Promise<AiDeploymentConfig | undefined> {
    const [config] = await db.select().from(aiDeploymentConfigs).where(eq(aiDeploymentConfigs.orgId, orgId));
    return config;
  }

  async upsertAiDeploymentConfig(config: InsertAiDeploymentConfig): Promise<AiDeploymentConfig> {
    const existing = await this.getAiDeploymentConfig(config.orgId);
    if (existing) {
      const [updated] = await db.update(aiDeploymentConfigs).set({ ...config, updatedAt: new Date() }).where(eq(aiDeploymentConfigs.orgId, config.orgId)).returning();
      return updated;
    }
    const [created] = await db.insert(aiDeploymentConfigs).values(config).returning();
    return created;
  }

  async getOrgMemberships(orgId: string): Promise<OrganizationMembership[]> {
    return db.select().from(organizationMemberships).where(eq(organizationMemberships.orgId, orgId)).orderBy(desc(organizationMemberships.createdAt));
  }

  async getOrgMembership(orgId: string, userId: string): Promise<OrganizationMembership | undefined> {
    const [membership] = await db.select().from(organizationMemberships).where(and(eq(organizationMemberships.orgId, orgId), eq(organizationMemberships.userId, userId)));
    return membership;
  }

  async getMembershipById(id: string): Promise<OrganizationMembership | undefined> {
    const [membership] = await db.select().from(organizationMemberships).where(eq(organizationMemberships.id, id));
    return membership;
  }

  async getUserMemberships(userId: string): Promise<OrganizationMembership[]> {
    return db.select().from(organizationMemberships).where(eq(organizationMemberships.userId, userId)).orderBy(desc(organizationMemberships.createdAt));
  }

  async createOrgMembership(membership: InsertOrganizationMembership): Promise<OrganizationMembership> {
    const [created] = await db.insert(organizationMemberships).values(membership).returning();
    return created;
  }

  async updateOrgMembership(id: string, data: Partial<OrganizationMembership>): Promise<OrganizationMembership | undefined> {
    const [updated] = await db.update(organizationMemberships).set(data).where(eq(organizationMemberships.id, id)).returning();
    return updated;
  }

  async deleteOrgMembership(id: string): Promise<boolean> {
    const result = await db.delete(organizationMemberships).where(eq(organizationMemberships.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getOrgInvitations(orgId: string): Promise<OrgInvitation[]> {
    return db.select().from(orgInvitations).where(eq(orgInvitations.orgId, orgId)).orderBy(desc(orgInvitations.createdAt));
  }

  async getOrgInvitationByToken(token: string): Promise<OrgInvitation | undefined> {
    const [invitation] = await db.select().from(orgInvitations).where(eq(orgInvitations.token, token));
    return invitation;
  }

  async createOrgInvitation(invitation: InsertOrgInvitation): Promise<OrgInvitation> {
    const [created] = await db.insert(orgInvitations).values(invitation).returning();
    return created;
  }

  async updateOrgInvitation(id: string, data: Partial<OrgInvitation>): Promise<OrgInvitation | undefined> {
    const [updated] = await db.update(orgInvitations).set(data).where(eq(orgInvitations.id, id)).returning();
    return updated;
  }

  async deleteOrgInvitation(id: string): Promise<boolean> {
    const result = await db.delete(orgInvitations).where(eq(orgInvitations.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getIocFeeds(orgId?: string): Promise<IocFeed[]> {
    if (orgId) {
      return db.select().from(iocFeeds).where(eq(iocFeeds.orgId, orgId)).orderBy(desc(iocFeeds.createdAt));
    }
    return db.select().from(iocFeeds).orderBy(desc(iocFeeds.createdAt));
  }

  async getIocFeed(id: string): Promise<IocFeed | undefined> {
    const [feed] = await db.select().from(iocFeeds).where(eq(iocFeeds.id, id)).limit(1);
    return feed;
  }

  async createIocFeed(feed: InsertIocFeed): Promise<IocFeed> {
    const [created] = await db.insert(iocFeeds).values(feed).returning();
    return created;
  }

  async updateIocFeed(id: string, data: Partial<IocFeed>): Promise<IocFeed | undefined> {
    const [updated] = await db.update(iocFeeds).set({ ...data, updatedAt: new Date() }).where(eq(iocFeeds.id, id)).returning();
    return updated;
  }

  async deleteIocFeed(id: string): Promise<boolean> {
    const result = await db.delete(iocFeeds).where(eq(iocFeeds.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getIocEntries(orgId?: string, feedId?: string, iocType?: string, status?: string, limit?: number): Promise<IocEntry[]> {
    const conditions: any[] = [];
    if (orgId) conditions.push(eq(iocEntries.orgId, orgId));
    if (feedId) conditions.push(eq(iocEntries.feedId, feedId));
    if (iocType) conditions.push(eq(iocEntries.iocType, iocType));
    if (status) conditions.push(eq(iocEntries.status, status));
    const query = db.select().from(iocEntries);
    if (conditions.length > 0) {
      return query.where(and(...conditions)).limit(limit || 500).orderBy(desc(iocEntries.createdAt));
    }
    return query.limit(limit || 500).orderBy(desc(iocEntries.createdAt));
  }

  async getIocEntry(id: string): Promise<IocEntry | undefined> {
    const [entry] = await db.select().from(iocEntries).where(eq(iocEntries.id, id)).limit(1);
    return entry;
  }

  async getIocEntriesByValue(iocType: string, iocValue: string, orgId?: string): Promise<IocEntry[]> {
    const conditions: any[] = [eq(iocEntries.iocType, iocType), eq(iocEntries.iocValue, iocValue.toLowerCase())];
    if (orgId) conditions.push(eq(iocEntries.orgId, orgId));
    return db.select().from(iocEntries).where(and(...conditions));
  }

  async createIocEntry(entry: InsertIocEntry): Promise<IocEntry> {
    const [created] = await db.insert(iocEntries).values(entry).returning();
    return created;
  }

  async createIocEntries(entries: InsertIocEntry[]): Promise<IocEntry[]> {
    if (entries.length === 0) return [];
    return db.insert(iocEntries).values(entries).returning();
  }

  async updateIocEntry(id: string, data: Partial<IocEntry>): Promise<IocEntry | undefined> {
    const [updated] = await db.update(iocEntries).set(data).where(eq(iocEntries.id, id)).returning();
    return updated;
  }

  async deleteIocEntry(id: string): Promise<boolean> {
    const result = await db.delete(iocEntries).where(eq(iocEntries.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getIocWatchlists(orgId?: string): Promise<IocWatchlist[]> {
    if (orgId) {
      return db.select().from(iocWatchlists).where(eq(iocWatchlists.orgId, orgId)).orderBy(desc(iocWatchlists.createdAt));
    }
    return db.select().from(iocWatchlists).orderBy(desc(iocWatchlists.createdAt));
  }

  async getIocWatchlist(id: string): Promise<IocWatchlist | undefined> {
    const [watchlist] = await db.select().from(iocWatchlists).where(eq(iocWatchlists.id, id)).limit(1);
    return watchlist;
  }

  async createIocWatchlist(watchlist: InsertIocWatchlist): Promise<IocWatchlist> {
    const [created] = await db.insert(iocWatchlists).values(watchlist).returning();
    return created;
  }

  async updateIocWatchlist(id: string, data: Partial<IocWatchlist>): Promise<IocWatchlist | undefined> {
    const [updated] = await db.update(iocWatchlists).set({ ...data, updatedAt: new Date() }).where(eq(iocWatchlists.id, id)).returning();
    return updated;
  }

  async deleteIocWatchlist(id: string): Promise<boolean> {
    const result = await db.delete(iocWatchlists).where(eq(iocWatchlists.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async addIocToWatchlist(entry: InsertIocWatchlistEntry): Promise<IocWatchlistEntry> {
    const [created] = await db.insert(iocWatchlistEntries).values(entry).returning();
    return created;
  }

  async removeIocFromWatchlist(watchlistId: string, iocEntryId: string): Promise<boolean> {
    const result = await db.delete(iocWatchlistEntries).where(and(eq(iocWatchlistEntries.watchlistId, watchlistId), eq(iocWatchlistEntries.iocEntryId, iocEntryId)));
    return (result.rowCount ?? 0) > 0;
  }

  async getWatchlistEntries(watchlistId: string): Promise<IocWatchlistEntry[]> {
    return db.select().from(iocWatchlistEntries).where(eq(iocWatchlistEntries.watchlistId, watchlistId));
  }

  async getIocMatchRules(orgId?: string): Promise<IocMatchRule[]> {
    if (orgId) {
      return db.select().from(iocMatchRules).where(eq(iocMatchRules.orgId, orgId)).orderBy(desc(iocMatchRules.createdAt));
    }
    return db.select().from(iocMatchRules).orderBy(desc(iocMatchRules.createdAt));
  }

  async getIocMatchRule(id: string): Promise<IocMatchRule | undefined> {
    const [rule] = await db.select().from(iocMatchRules).where(eq(iocMatchRules.id, id)).limit(1);
    return rule;
  }

  async createIocMatchRule(rule: InsertIocMatchRule): Promise<IocMatchRule> {
    const [created] = await db.insert(iocMatchRules).values(rule).returning();
    return created;
  }

  async updateIocMatchRule(id: string, data: Partial<IocMatchRule>): Promise<IocMatchRule | undefined> {
    const [updated] = await db.update(iocMatchRules).set({ ...data, updatedAt: new Date() }).where(eq(iocMatchRules.id, id)).returning();
    return updated;
  }

  async deleteIocMatchRule(id: string): Promise<boolean> {
    const result = await db.delete(iocMatchRules).where(eq(iocMatchRules.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getIocMatches(orgId?: string, alertId?: string, iocEntryId?: string, limit?: number): Promise<IocMatch[]> {
    const conditions: any[] = [];
    if (orgId) conditions.push(eq(iocMatches.orgId, orgId));
    if (alertId) conditions.push(eq(iocMatches.alertId, alertId));
    if (iocEntryId) conditions.push(eq(iocMatches.iocEntryId, iocEntryId));
    const query = db.select().from(iocMatches);
    if (conditions.length > 0) {
      return query.where(and(...conditions)).limit(limit || 200).orderBy(desc(iocMatches.createdAt));
    }
    return query.limit(limit || 200).orderBy(desc(iocMatches.createdAt));
  }

  async createIocMatch(match: InsertIocMatch): Promise<IocMatch> {
    const [created] = await db.insert(iocMatches).values(match).returning();
    return created;
  }

  async getEvidenceItems(incidentId: string, orgId?: string): Promise<EvidenceItem[]> {
    const conditions: any[] = [eq(evidenceItems.incidentId, incidentId)];
    if (orgId) conditions.push(eq(evidenceItems.orgId, orgId));
    return db.select().from(evidenceItems).where(and(...conditions)).orderBy(desc(evidenceItems.createdAt));
  }

  async getEvidenceItem(id: string): Promise<EvidenceItem | undefined> {
    const [item] = await db.select().from(evidenceItems).where(eq(evidenceItems.id, id));
    return item;
  }

  async createEvidenceItem(item: InsertEvidenceItem): Promise<EvidenceItem> {
    const [created] = await db.insert(evidenceItems).values(item).returning();
    return created;
  }

  async deleteEvidenceItem(id: string): Promise<boolean> {
    const result = await db.delete(evidenceItems).where(eq(evidenceItems.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getHypotheses(incidentId: string, orgId?: string): Promise<InvestigationHypothesis[]> {
    const conditions: any[] = [eq(investigationHypotheses.incidentId, incidentId)];
    if (orgId) conditions.push(eq(investigationHypotheses.orgId, orgId));
    return db.select().from(investigationHypotheses).where(and(...conditions)).orderBy(desc(investigationHypotheses.createdAt));
  }

  async getHypothesis(id: string): Promise<InvestigationHypothesis | undefined> {
    const [hypothesis] = await db.select().from(investigationHypotheses).where(eq(investigationHypotheses.id, id));
    return hypothesis;
  }

  async createHypothesis(hypothesis: InsertInvestigationHypothesis): Promise<InvestigationHypothesis> {
    const [created] = await db.insert(investigationHypotheses).values(hypothesis).returning();
    return created;
  }

  async updateHypothesis(id: string, data: Partial<InvestigationHypothesis>): Promise<InvestigationHypothesis | undefined> {
    const [updated] = await db.update(investigationHypotheses).set({ ...data, updatedAt: new Date() }).where(eq(investigationHypotheses.id, id)).returning();
    return updated;
  }

  async deleteHypothesis(id: string): Promise<boolean> {
    const result = await db.delete(investigationHypotheses).where(eq(investigationHypotheses.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getInvestigationTasks(incidentId: string, orgId?: string): Promise<InvestigationTask[]> {
    const conditions: any[] = [eq(investigationTasks.incidentId, incidentId)];
    if (orgId) conditions.push(eq(investigationTasks.orgId, orgId));
    return db.select().from(investigationTasks).where(and(...conditions)).orderBy(desc(investigationTasks.createdAt));
  }

  async getInvestigationTask(id: string): Promise<InvestigationTask | undefined> {
    const [task] = await db.select().from(investigationTasks).where(eq(investigationTasks.id, id));
    return task;
  }

  async createInvestigationTask(task: InsertInvestigationTask): Promise<InvestigationTask> {
    const [created] = await db.insert(investigationTasks).values(task).returning();
    return created;
  }

  async updateInvestigationTask(id: string, data: Partial<InvestigationTask>): Promise<InvestigationTask | undefined> {
    const [updated] = await db.update(investigationTasks).set({ ...data, updatedAt: new Date() }).where(eq(investigationTasks.id, id)).returning();
    return updated;
  }

  async deleteInvestigationTask(id: string): Promise<boolean> {
    const result = await db.delete(investigationTasks).where(eq(investigationTasks.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getRunbookTemplates(orgId?: string, incidentType?: string): Promise<RunbookTemplate[]> {
    const conditions: any[] = [];
    if (orgId) {
      conditions.push(or(eq(runbookTemplates.orgId, orgId), isNull(runbookTemplates.orgId)));
    }
    if (incidentType) {
      conditions.push(eq(runbookTemplates.incidentType, incidentType));
    }
    if (conditions.length > 0) {
      return db.select().from(runbookTemplates).where(and(...conditions)).orderBy(desc(runbookTemplates.createdAt));
    }
    return db.select().from(runbookTemplates).orderBy(desc(runbookTemplates.createdAt));
  }

  async getRunbookTemplate(id: string): Promise<RunbookTemplate | undefined> {
    const [template] = await db.select().from(runbookTemplates).where(eq(runbookTemplates.id, id));
    return template;
  }

  async createRunbookTemplate(template: InsertRunbookTemplate): Promise<RunbookTemplate> {
    const [created] = await db.insert(runbookTemplates).values(template).returning();
    return created;
  }

  async updateRunbookTemplate(id: string, data: Partial<RunbookTemplate>): Promise<RunbookTemplate | undefined> {
    const [updated] = await db.update(runbookTemplates).set({ ...data, updatedAt: new Date() }).where(eq(runbookTemplates.id, id)).returning();
    return updated;
  }

  async deleteRunbookTemplate(id: string): Promise<boolean> {
    const result = await db.delete(runbookTemplates).where(eq(runbookTemplates.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getRunbookSteps(templateId: string): Promise<RunbookStep[]> {
    return db.select().from(runbookSteps).where(eq(runbookSteps.templateId, templateId)).orderBy(asc(runbookSteps.stepOrder));
  }

  async createRunbookStep(step: InsertRunbookStep): Promise<RunbookStep> {
    const [created] = await db.insert(runbookSteps).values(step).returning();
    return created;
  }

  async updateRunbookStep(id: string, data: Partial<RunbookStep>): Promise<RunbookStep | undefined> {
    const [updated] = await db.update(runbookSteps).set(data).where(eq(runbookSteps.id, id)).returning();
    return updated;
  }

  async deleteRunbookStep(id: string): Promise<boolean> {
    const result = await db.delete(runbookSteps).where(eq(runbookSteps.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getReportTemplates(orgId?: string): Promise<ReportTemplate[]> {
    if (orgId) {
      return db.select().from(reportTemplates)
        .where(or(eq(reportTemplates.orgId, orgId), isNull(reportTemplates.orgId)))
        .orderBy(desc(reportTemplates.createdAt));
    }
    return db.select().from(reportTemplates).orderBy(desc(reportTemplates.createdAt));
  }

  async getReportTemplate(id: string): Promise<ReportTemplate | undefined> {
    const [t] = await db.select().from(reportTemplates).where(eq(reportTemplates.id, id));
    return t;
  }

  async createReportTemplate(template: InsertReportTemplate): Promise<ReportTemplate> {
    const [t] = await db.insert(reportTemplates).values(template).returning();
    return t;
  }

  async updateReportTemplate(id: string, data: Partial<ReportTemplate>): Promise<ReportTemplate | undefined> {
    const [t] = await db.update(reportTemplates).set({ ...data, updatedAt: new Date() }).where(eq(reportTemplates.id, id)).returning();
    return t;
  }

  async deleteReportTemplate(id: string): Promise<boolean> {
    const result = await db.delete(reportTemplates).where(eq(reportTemplates.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getReportSchedules(orgId?: string): Promise<ReportSchedule[]> {
    if (orgId) {
      return db.select().from(reportSchedules).where(eq(reportSchedules.orgId, orgId)).orderBy(desc(reportSchedules.createdAt));
    }
    return db.select().from(reportSchedules).orderBy(desc(reportSchedules.createdAt));
  }

  async getReportSchedule(id: string): Promise<ReportSchedule | undefined> {
    const [s] = await db.select().from(reportSchedules).where(eq(reportSchedules.id, id));
    return s;
  }

  async createReportSchedule(schedule: InsertReportSchedule): Promise<ReportSchedule> {
    const [s] = await db.insert(reportSchedules).values(schedule).returning();
    return s;
  }

  async updateReportSchedule(id: string, data: Partial<ReportSchedule>): Promise<ReportSchedule | undefined> {
    const [s] = await db.update(reportSchedules).set({ ...data, updatedAt: new Date() }).where(eq(reportSchedules.id, id)).returning();
    return s;
  }

  async deleteReportSchedule(id: string): Promise<boolean> {
    const result = await db.delete(reportSchedules).where(eq(reportSchedules.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getReportRuns(orgId?: string, templateId?: string, limit = 50): Promise<ReportRun[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(reportRuns.orgId, orgId));
    if (templateId) conditions.push(eq(reportRuns.templateId, templateId));
    if (conditions.length > 0) {
      return db.select().from(reportRuns).where(and(...conditions)).orderBy(desc(reportRuns.createdAt)).limit(limit);
    }
    return db.select().from(reportRuns).orderBy(desc(reportRuns.createdAt)).limit(limit);
  }

  async getReportRun(id: string): Promise<ReportRun | undefined> {
    const [r] = await db.select().from(reportRuns).where(eq(reportRuns.id, id));
    return r;
  }

  async createReportRun(run: InsertReportRun): Promise<ReportRun> {
    const [r] = await db.insert(reportRuns).values(run).returning();
    return r;
  }

  async updateReportRun(id: string, data: Partial<ReportRun>): Promise<ReportRun | undefined> {
    const [r] = await db.update(reportRuns).set(data).where(eq(reportRuns.id, id)).returning();
    return r;
  }

  async getDueSchedules(): Promise<ReportSchedule[]> {
    return db.select().from(reportSchedules)
      .where(and(
        eq(reportSchedules.enabled, true),
        sql`${reportSchedules.nextRunAt} IS NOT NULL AND ${reportSchedules.nextRunAt} <= NOW()`
      ))
      .orderBy(asc(reportSchedules.nextRunAt));
  }

  // Suppression Rules
  async getSuppressionRules(orgId?: string): Promise<SuppressionRule[]> {
    if (orgId) {
      return db.select().from(suppressionRules).where(eq(suppressionRules.orgId, orgId)).orderBy(desc(suppressionRules.createdAt));
    }
    return db.select().from(suppressionRules).orderBy(desc(suppressionRules.createdAt));
  }

  async getSuppressionRule(id: string): Promise<SuppressionRule | undefined> {
    const [rule] = await db.select().from(suppressionRules).where(eq(suppressionRules.id, id));
    return rule;
  }

  async createSuppressionRule(rule: InsertSuppressionRule): Promise<SuppressionRule> {
    const [created] = await db.insert(suppressionRules).values(rule).returning();
    return created;
  }

  async updateSuppressionRule(id: string, data: Partial<SuppressionRule>): Promise<SuppressionRule | undefined> {
    const [updated] = await db.update(suppressionRules).set({ ...data, updatedAt: new Date() }).where(eq(suppressionRules.id, id)).returning();
    return updated;
  }

  async deleteSuppressionRule(id: string): Promise<boolean> {
    const [deleted] = await db.delete(suppressionRules).where(eq(suppressionRules.id, id)).returning();
    return !!deleted;
  }

  // Alert Dedup Clusters
  async getAlertDedupClusters(orgId?: string): Promise<AlertDedupCluster[]> {
    if (orgId) {
      return db.select().from(alertDedupClusters).where(eq(alertDedupClusters.orgId, orgId)).orderBy(desc(alertDedupClusters.createdAt));
    }
    return db.select().from(alertDedupClusters).orderBy(desc(alertDedupClusters.createdAt));
  }

  async getAlertDedupCluster(id: string): Promise<AlertDedupCluster | undefined> {
    const [cluster] = await db.select().from(alertDedupClusters).where(eq(alertDedupClusters.id, id));
    return cluster;
  }

  async createAlertDedupCluster(cluster: InsertAlertDedupCluster): Promise<AlertDedupCluster> {
    const [created] = await db.insert(alertDedupClusters).values(cluster).returning();
    return created;
  }

  async updateAlertDedupCluster(id: string, data: Partial<AlertDedupCluster>): Promise<AlertDedupCluster | undefined> {
    const [updated] = await db.update(alertDedupClusters).set(data).where(eq(alertDedupClusters.id, id)).returning();
    return updated;
  }

  // SLA Policies
  async getIncidentSlaPolicies(orgId?: string): Promise<IncidentSlaPolicy[]> {
    if (orgId) {
      return db.select().from(incidentSlaPolicies).where(eq(incidentSlaPolicies.orgId, orgId)).orderBy(desc(incidentSlaPolicies.createdAt));
    }
    return db.select().from(incidentSlaPolicies).orderBy(desc(incidentSlaPolicies.createdAt));
  }

  async getIncidentSlaPolicy(id: string): Promise<IncidentSlaPolicy | undefined> {
    const [policy] = await db.select().from(incidentSlaPolicies).where(eq(incidentSlaPolicies.id, id));
    return policy;
  }

  async createIncidentSlaPolicy(policy: InsertIncidentSlaPolicy): Promise<IncidentSlaPolicy> {
    const [created] = await db.insert(incidentSlaPolicies).values(policy).returning();
    return created;
  }

  async updateIncidentSlaPolicy(id: string, data: Partial<IncidentSlaPolicy>): Promise<IncidentSlaPolicy | undefined> {
    const [updated] = await db.update(incidentSlaPolicies).set({ ...data, updatedAt: new Date() }).where(eq(incidentSlaPolicies.id, id)).returning();
    return updated;
  }

  async deleteIncidentSlaPolicy(id: string): Promise<boolean> {
    const [deleted] = await db.delete(incidentSlaPolicies).where(eq(incidentSlaPolicies.id, id)).returning();
    return !!deleted;
  }

  // Post-Incident Reviews
  async getPostIncidentReviews(orgId?: string, incidentId?: string): Promise<PostIncidentReview[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(postIncidentReviews.orgId, orgId));
    if (incidentId) conditions.push(eq(postIncidentReviews.incidentId, incidentId));
    if (conditions.length > 0) {
      return db.select().from(postIncidentReviews).where(and(...conditions)).orderBy(desc(postIncidentReviews.createdAt));
    }
    return db.select().from(postIncidentReviews).orderBy(desc(postIncidentReviews.createdAt));
  }

  async getPostIncidentReview(id: string): Promise<PostIncidentReview | undefined> {
    const [review] = await db.select().from(postIncidentReviews).where(eq(postIncidentReviews.id, id));
    return review;
  }

  async createPostIncidentReview(review: InsertPostIncidentReview): Promise<PostIncidentReview> {
    const [created] = await db.insert(postIncidentReviews).values(review).returning();
    return created;
  }

  async updatePostIncidentReview(id: string, data: Partial<PostIncidentReview>): Promise<PostIncidentReview | undefined> {
    const [updated] = await db.update(postIncidentReviews).set({ ...data, updatedAt: new Date() }).where(eq(postIncidentReviews.id, id)).returning();
    return updated;
  }

  async deletePostIncidentReview(id: string): Promise<boolean> {
    const [deleted] = await db.delete(postIncidentReviews).where(eq(postIncidentReviews.id, id)).returning();
    return !!deleted;
  }

  async createConnectorJobRun(run: InsertConnectorJobRun): Promise<ConnectorJobRun> {
    const [created] = await db.insert(connectorJobRuns).values(run).returning();
    return created;
  }

  async updateConnectorJobRun(id: string, updates: Partial<ConnectorJobRun>): Promise<ConnectorJobRun> {
    const [updated] = await db.update(connectorJobRuns).set(updates).where(eq(connectorJobRuns.id, id)).returning();
    return updated;
  }

  async getConnectorJobRuns(connectorId: string, limit?: number): Promise<ConnectorJobRun[]> {
    return db.select().from(connectorJobRuns)
      .where(eq(connectorJobRuns.connectorId, connectorId))
      .orderBy(desc(connectorJobRuns.startedAt))
      .limit(limit || 50);
  }

  async getDeadLetterJobRuns(orgId?: string): Promise<ConnectorJobRun[]> {
    const conditions = [eq(connectorJobRuns.isDeadLetter, true)];
    if (orgId) conditions.push(eq(connectorJobRuns.orgId, orgId));
    return db.select().from(connectorJobRuns)
      .where(and(...conditions))
      .orderBy(desc(connectorJobRuns.startedAt));
  }

  async getConnectorMetrics(connectorId: string): Promise<{ avgLatencyMs: number; errorRate: number; throttleCount: number; totalRuns: number; successRate: number }> {
    const result = await db.execute(sql`
      SELECT
        COUNT(*) as total_runs,
        COALESCE(AVG(latency_ms), 0) as avg_latency,
        CASE WHEN COUNT(*) > 0 THEN SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)::float / COUNT(*) ELSE 0 END as error_rate,
        SUM(CASE WHEN throttled = true THEN 1 ELSE 0 END) as throttle_count,
        CASE WHEN COUNT(*) > 0 THEN SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END)::float / COUNT(*) ELSE 0 END as success_rate
      FROM (
        SELECT status, latency_ms, throttled
        FROM connector_job_runs
        WHERE connector_id = ${connectorId}
        ORDER BY started_at DESC
        LIMIT 100
      ) sub
    `);
    const row = (result as any).rows?.[0] || result[0] || {};
    return {
      totalRuns: Number(row.total_runs) || 0,
      avgLatencyMs: Number(row.avg_latency) || 0,
      errorRate: Number(row.error_rate) || 0,
      throttleCount: Number(row.throttle_count) || 0,
      successRate: Number(row.success_rate) || 0,
    };
  }

  async createConnectorHealthCheck(check: InsertConnectorHealthCheck): Promise<ConnectorHealthCheck> {
    const [created] = await db.insert(connectorHealthChecks).values(check).returning();
    return created;
  }

  async getConnectorHealthChecks(connectorId: string, limit?: number): Promise<ConnectorHealthCheck[]> {
    return db.select().from(connectorHealthChecks)
      .where(eq(connectorHealthChecks.connectorId, connectorId))
      .orderBy(desc(connectorHealthChecks.checkedAt))
      .limit(limit || 50);
  }

  async getLatestHealthCheck(connectorId: string): Promise<ConnectorHealthCheck | undefined> {
    const [check] = await db.select().from(connectorHealthChecks)
      .where(eq(connectorHealthChecks.connectorId, connectorId))
      .orderBy(desc(connectorHealthChecks.checkedAt))
      .limit(1);
    return check;
  }

  async getAiFeedbackMetrics(orgId?: string, days?: number): Promise<{ date: string; avgRating: number; totalFeedback: number; negativeFeedback: number; positiveFeedback: number }[]> {
    const d = days || 30;
    const orgCondition = orgId ? sql` AND org_id = ${orgId}` : sql``;
    const result = await db.execute(sql`
      SELECT
        date_trunc('day', created_at) as date,
        AVG(rating) as avg_rating,
        COUNT(*) as total,
        SUM(CASE WHEN rating <= 2 THEN 1 ELSE 0 END) as negative,
        SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive
      FROM ai_feedback
      WHERE created_at >= NOW() - make_interval(days => ${d})${orgCondition}
      GROUP BY 1
      ORDER BY 1
    `);
    const rows = (result as any).rows || result || [];
    return rows.map((row: any) => ({
      date: row.date ? new Date(row.date).toISOString().split('T')[0] : '',
      avgRating: Number(row.avg_rating) || 0,
      totalFeedback: Number(row.total) || 0,
      negativeFeedback: Number(row.negative) || 0,
      positiveFeedback: Number(row.positive) || 0,
    }));
  }

  async getAiFeedbackByResource(resourceType: string, resourceId: string): Promise<AiFeedback[]> {
    return db.select().from(aiFeedback)
      .where(and(eq(aiFeedback.resourceType, resourceType), eq(aiFeedback.resourceId, resourceId)))
      .orderBy(desc(aiFeedback.createdAt));
  }
  async getPolicyChecks(orgId: string): Promise<PolicyCheck[]> {
    return db.select().from(policyChecks).where(eq(policyChecks.orgId, orgId)).orderBy(desc(policyChecks.createdAt));
  }

  async getPolicyCheck(id: string): Promise<PolicyCheck | undefined> {
    const [check] = await db.select().from(policyChecks).where(eq(policyChecks.id, id));
    return check;
  }

  async createPolicyCheck(check: InsertPolicyCheck): Promise<PolicyCheck> {
    const [created] = await db.insert(policyChecks).values(check).returning();
    return created;
  }

  async updatePolicyCheck(id: string, data: Partial<PolicyCheck>): Promise<PolicyCheck | undefined> {
    const [updated] = await db.update(policyChecks).set(data).where(eq(policyChecks.id, id)).returning();
    return updated;
  }

  async deletePolicyCheck(id: string): Promise<boolean> {
    const result = await db.delete(policyChecks).where(eq(policyChecks.id, id)).returning();
    return result.length > 0;
  }

  async getPolicyResults(orgId: string, policyCheckId?: string): Promise<PolicyResult[]> {
    const conditions = [eq(policyResults.orgId, orgId)];
    if (policyCheckId) {
      conditions.push(eq(policyResults.policyCheckId, policyCheckId));
    }
    return db.select().from(policyResults).where(and(...conditions)).orderBy(desc(policyResults.evaluatedAt));
  }

  async createPolicyResult(result: InsertPolicyResult): Promise<PolicyResult> {
    const [created] = await db.insert(policyResults).values(result).returning();
    return created;
  }

  async getComplianceControls(framework?: string): Promise<ComplianceControl[]> {
    if (framework) {
      return db.select().from(complianceControls).where(eq(complianceControls.framework, framework));
    }
    return db.select().from(complianceControls);
  }

  async getComplianceControl(id: string): Promise<ComplianceControl | undefined> {
    const [control] = await db.select().from(complianceControls).where(eq(complianceControls.id, id));
    return control;
  }

  async createComplianceControl(control: InsertComplianceControl): Promise<ComplianceControl> {
    const [created] = await db.insert(complianceControls).values(control).returning();
    return created;
  }

  async createComplianceControls(controls: InsertComplianceControl[]): Promise<ComplianceControl[]> {
    return db.insert(complianceControls).values(controls).returning();
  }

  async updateComplianceControl(id: string, data: Partial<ComplianceControl>): Promise<ComplianceControl | undefined> {
    const [updated] = await db.update(complianceControls).set(data).where(eq(complianceControls.id, id)).returning();
    return updated;
  }

  async deleteComplianceControl(id: string): Promise<boolean> {
    const [deleted] = await db.delete(complianceControls).where(eq(complianceControls.id, id)).returning();
    return !!deleted;
  }

  async deletePolicyResult(id: string): Promise<boolean> {
    const [deleted] = await db.delete(policyResults).where(eq(policyResults.id, id)).returning();
    return !!deleted;
  }

  async getComplianceControlMappings(orgId: string, controlId?: string): Promise<ComplianceControlMapping[]> {
    const conditions = [eq(complianceControlMappings.orgId, orgId)];
    if (controlId) {
      conditions.push(eq(complianceControlMappings.controlId, controlId));
    }
    return db.select().from(complianceControlMappings).where(and(...conditions));
  }

  async createComplianceControlMapping(mapping: InsertComplianceControlMapping): Promise<ComplianceControlMapping> {
    const [created] = await db.insert(complianceControlMappings).values(mapping).returning();
    return created;
  }

  async updateComplianceControlMapping(id: string, data: Partial<ComplianceControlMapping>): Promise<ComplianceControlMapping | undefined> {
    const [updated] = await db.update(complianceControlMappings).set(data).where(eq(complianceControlMappings.id, id)).returning();
    return updated;
  }

  async deleteComplianceControlMapping(id: string): Promise<boolean> {
    const result = await db.delete(complianceControlMappings).where(eq(complianceControlMappings.id, id)).returning();
    return result.length > 0;
  }

  async getEvidenceLockerItems(orgId: string, framework?: string, artifactType?: string): Promise<EvidenceLockerItem[]> {
    const conditions = [eq(evidenceLockerItems.orgId, orgId)];
    if (framework) {
      conditions.push(eq(evidenceLockerItems.framework, framework));
    }
    if (artifactType) {
      conditions.push(eq(evidenceLockerItems.artifactType, artifactType));
    }
    return db.select().from(evidenceLockerItems).where(and(...conditions)).orderBy(desc(evidenceLockerItems.createdAt));
  }

  async getEvidenceLockerItem(id: string): Promise<EvidenceLockerItem | undefined> {
    const [item] = await db.select().from(evidenceLockerItems).where(eq(evidenceLockerItems.id, id));
    return item;
  }

  async createEvidenceLockerItem(item: InsertEvidenceLockerItem): Promise<EvidenceLockerItem> {
    const [created] = await db.insert(evidenceLockerItems).values(item).returning();
    return created;
  }

  async updateEvidenceLockerItem(id: string, data: Partial<EvidenceLockerItem>): Promise<EvidenceLockerItem | undefined> {
    const [updated] = await db.update(evidenceLockerItems).set(data).where(eq(evidenceLockerItems.id, id)).returning();
    return updated;
  }

  async deleteEvidenceLockerItem(id: string): Promise<boolean> {
    const result = await db.delete(evidenceLockerItems).where(eq(evidenceLockerItems.id, id)).returning();
    return result.length > 0;
  }

  async getOutboundWebhooks(orgId: string): Promise<OutboundWebhook[]> {
    return db.select().from(outboundWebhooks).where(eq(outboundWebhooks.orgId, orgId)).orderBy(desc(outboundWebhooks.createdAt));
  }

  async getOutboundWebhook(id: string): Promise<OutboundWebhook | undefined> {
    const [webhook] = await db.select().from(outboundWebhooks).where(eq(outboundWebhooks.id, id));
    return webhook;
  }

  async createOutboundWebhook(webhook: InsertOutboundWebhook): Promise<OutboundWebhook> {
    const [created] = await db.insert(outboundWebhooks).values(webhook).returning();
    return created;
  }

  async updateOutboundWebhook(id: string, data: Partial<OutboundWebhook>): Promise<OutboundWebhook | undefined> {
    const [updated] = await db.update(outboundWebhooks).set(data).where(eq(outboundWebhooks.id, id)).returning();
    return updated;
  }

  async deleteOutboundWebhook(id: string): Promise<boolean> {
    const result = await db.delete(outboundWebhooks).where(eq(outboundWebhooks.id, id)).returning();
    return result.length > 0;
  }

  async getActiveWebhooksByEvent(orgId: string, event: string): Promise<OutboundWebhook[]> {
    return db.select().from(outboundWebhooks)
      .where(and(eq(outboundWebhooks.orgId, orgId), eq(outboundWebhooks.isActive, true), sql`${event} = ANY(${outboundWebhooks.events})`));
  }

  async getOutboundWebhookLogs(webhookId: string, limit?: number): Promise<OutboundWebhookLog[]> {
    return db.select().from(outboundWebhookLogs)
      .where(eq(outboundWebhookLogs.webhookId, webhookId))
      .orderBy(desc(outboundWebhookLogs.deliveredAt))
      .limit(limit || 100);
  }

  async createOutboundWebhookLog(log: InsertOutboundWebhookLog): Promise<OutboundWebhookLog> {
    const [created] = await db.insert(outboundWebhookLogs).values(log).returning();
    return created;
  }

  async getIdempotencyKey(orgId: string, key: string, endpoint: string): Promise<IdempotencyKey | undefined> {
    const [found] = await db.select().from(idempotencyKeys)
      .where(and(eq(idempotencyKeys.orgId, orgId), eq(idempotencyKeys.idempotencyKey, key), eq(idempotencyKeys.endpoint, endpoint)));
    return found;
  }

  async createIdempotencyKey(key: InsertIdempotencyKey): Promise<IdempotencyKey> {
    const [created] = await db.insert(idempotencyKeys).values(key).returning();
    return created;
  }

  async cleanupExpiredIdempotencyKeys(): Promise<number> {
    const result = await db.delete(idempotencyKeys).where(sql`${idempotencyKeys.expiresAt} < NOW()`).returning();
    return result.length;
  }

  async getArchivedAlerts(orgId: string, limit?: number, offset?: number): Promise<AlertArchive[]> {
    return db.select().from(alertsArchive)
      .where(eq(alertsArchive.orgId, orgId))
      .orderBy(desc(alertsArchive.archivedAt))
      .limit(limit || 100)
      .offset(offset || 0);
  }

  async getArchivedAlertCount(orgId: string): Promise<number> {
    const [result] = await db.select({ count: count() }).from(alertsArchive).where(eq(alertsArchive.orgId, orgId));
    return result?.count || 0;
  }

  async archiveAlerts(orgId: string, alertIds: string[], reason: string): Promise<number> {
    const alertsToArchive = await db.select().from(alerts).where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds)));
    if (alertsToArchive.length === 0) return 0;
    const archiveData = alertsToArchive.map(a => ({
      orgId: a.orgId,
      source: a.source,
      sourceEventId: a.sourceEventId,
      category: a.category,
      severity: a.severity,
      title: a.title,
      description: a.description,
      rawData: a.rawData,
      normalizedData: a.normalizedData,
      ocsfData: a.ocsfData,
      sourceIp: a.sourceIp,
      destIp: a.destIp,
      sourcePort: a.sourcePort,
      destPort: a.destPort,
      protocol: a.protocol,
      userId: a.userId,
      hostname: a.hostname,
      fileHash: a.fileHash,
      url: a.url,
      domain: a.domain,
      mitreTactic: a.mitreTactic,
      mitreTechnique: a.mitreTechnique,
      status: a.status,
      incidentId: a.incidentId,
      correlationScore: a.correlationScore,
      correlationReason: a.correlationReason,
      correlationClusterId: a.correlationClusterId,
      suppressed: a.suppressed,
      suppressedBy: a.suppressedBy,
      suppressionRuleId: a.suppressionRuleId,
      confidenceScore: a.confidenceScore,
      confidenceSource: a.confidenceSource,
      confidenceNotes: a.confidenceNotes,
      dedupClusterId: a.dedupClusterId,
      analystNotes: a.analystNotes,
      assignedTo: a.assignedTo,
      detectedAt: a.detectedAt,
      archiveReason: reason,
    }));
    await db.insert(alertsArchive).values(archiveData);
    await db.delete(alerts).where(inArray(alerts.id, alertIds));
    return alertsToArchive.length;
  }

  async restoreArchivedAlerts(ids: string[]): Promise<number> {
    const archived = await db.select().from(alertsArchive).where(inArray(alertsArchive.id, ids));
    if (archived.length === 0) return 0;
    const restoreData = archived.map(a => ({
      orgId: a.orgId,
      source: a.source,
      sourceEventId: a.sourceEventId,
      category: a.category,
      severity: a.severity,
      title: a.title,
      description: a.description,
      rawData: a.rawData,
      normalizedData: a.normalizedData,
      ocsfData: a.ocsfData,
      sourceIp: a.sourceIp,
      destIp: a.destIp,
      sourcePort: a.sourcePort,
      destPort: a.destPort,
      protocol: a.protocol,
      userId: a.userId,
      hostname: a.hostname,
      fileHash: a.fileHash,
      url: a.url,
      domain: a.domain,
      mitreTactic: a.mitreTactic,
      mitreTechnique: a.mitreTechnique,
      status: a.status,
      incidentId: a.incidentId,
      correlationScore: a.correlationScore,
      correlationReason: a.correlationReason,
      correlationClusterId: a.correlationClusterId,
      suppressed: a.suppressed,
      suppressedBy: a.suppressedBy,
      suppressionRuleId: a.suppressionRuleId,
      confidenceScore: a.confidenceScore,
      confidenceSource: a.confidenceSource,
      confidenceNotes: a.confidenceNotes,
      dedupClusterId: a.dedupClusterId,
      analystNotes: a.analystNotes,
      assignedTo: a.assignedTo,
      detectedAt: a.detectedAt,
    }));
    await db.insert(alerts).values(restoreData as any);
    await db.delete(alertsArchive).where(inArray(alertsArchive.id, ids));
    return archived.length;
  }

  async deleteArchivedAlerts(orgId: string, beforeDate: Date): Promise<number> {
    const result = await db.delete(alertsArchive)
      .where(and(eq(alertsArchive.orgId, orgId), lte(alertsArchive.archivedAt, beforeDate)))
      .returning();
    return result.length;
  }

  async getJobs(orgId?: string, status?: string, type?: string, limit?: number): Promise<Job[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(jobQueue.orgId, orgId));
    if (status) conditions.push(eq(jobQueue.status, status));
    if (type) conditions.push(eq(jobQueue.type, type));
    const query = db.select().from(jobQueue);
    if (conditions.length > 0) {
      return query.where(and(...conditions)).orderBy(desc(jobQueue.createdAt)).limit(limit || 100);
    }
    return query.orderBy(desc(jobQueue.createdAt)).limit(limit || 100);
  }

  async getJob(id: string): Promise<Job | undefined> {
    const [job] = await db.select().from(jobQueue).where(eq(jobQueue.id, id));
    return job;
  }

  async createJob(job: InsertJob): Promise<Job> {
    const [created] = await db.insert(jobQueue).values(job).returning();
    return created;
  }

  async claimNextJob(types?: string[]): Promise<Job | undefined> {
    const typesFilter = types && types.length > 0
      ? sql`AND type IN (${sql.join(types.map(t => sql`${t}`), sql`, `)})`
      : sql``;
    const result = await db.execute(sql`
      UPDATE job_queue
      SET status = 'running', started_at = NOW(), attempts = attempts + 1
      WHERE id = (
        SELECT id FROM job_queue
        WHERE status = 'pending' AND run_at <= NOW() ${typesFilter}
        ORDER BY priority DESC, run_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
      )
      RETURNING *
    `);
    const rows = result.rows as any[];
    if (!rows || rows.length === 0) return undefined;
    const row = rows[0];
    return {
      id: row.id,
      orgId: row.org_id,
      type: row.type,
      status: row.status,
      payload: row.payload,
      result: row.result,
      priority: row.priority,
      runAt: row.run_at,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      attempts: row.attempts,
      maxAttempts: row.max_attempts,
      lastError: row.last_error,
      createdAt: row.created_at,
    } as Job;
  }

  async updateJob(id: string, data: Partial<Job>): Promise<Job | undefined> {
    const [updated] = await db.update(jobQueue).set(data).where(eq(jobQueue.id, id)).returning();
    return updated;
  }

  async cancelJob(id: string): Promise<boolean> {
    const [updated] = await db.update(jobQueue).set({ status: "cancelled" } as any).where(eq(jobQueue.id, id)).returning();
    return !!updated;
  }

  async getJobStats(): Promise<{ pending: number; running: number; completed: number; failed: number }> {
    const result = await db.select({
      status: jobQueue.status,
      count: count(),
    }).from(jobQueue).groupBy(jobQueue.status);
    const stats = { pending: 0, running: 0, completed: 0, failed: 0 };
    for (const row of result) {
      if (row.status in stats) {
        (stats as any)[row.status] = row.count;
      }
    }
    return stats;
  }

  async cleanupCompletedJobs(olderThanDays: number): Promise<number> {
    const result = await db.delete(jobQueue)
      .where(and(
        or(eq(jobQueue.status, "completed"), eq(jobQueue.status, "failed")),
        sql`${jobQueue.completedAt} < NOW() - INTERVAL '${sql.raw(String(olderThanDays))} days'`
      ))
      .returning();
    return result.length;
  }

  async getCachedMetrics(orgId: string, metricType: string): Promise<DashboardMetricsCache | undefined> {
    const [cached] = await db.select().from(dashboardMetricsCache)
      .where(and(
        eq(dashboardMetricsCache.orgId, orgId),
        eq(dashboardMetricsCache.metricType, metricType),
        sql`${dashboardMetricsCache.expiresAt} > NOW()`
      ));
    return cached;
  }

  async upsertCachedMetrics(data: InsertDashboardMetricsCache): Promise<DashboardMetricsCache> {
    const [result] = await db.insert(dashboardMetricsCache).values(data)
      .onConflictDoUpdate({
        target: [dashboardMetricsCache.orgId, dashboardMetricsCache.metricType],
        set: {
          payload: data.payload,
          expiresAt: data.expiresAt,
          generatedAt: sql`NOW()`,
        },
      })
      .returning();
    return result;
  }

  async clearExpiredCache(): Promise<number> {
    const result = await db.delete(dashboardMetricsCache)
      .where(sql`${dashboardMetricsCache.expiresAt} <= NOW()`)
      .returning();
    return result.length;
  }

  async getAlertDailyStats(orgId: string, startDate: string, endDate: string): Promise<AlertDailyStat[]> {
    return db.select().from(alertDailyStats)
      .where(and(
        eq(alertDailyStats.orgId, orgId),
        gte(alertDailyStats.date, startDate),
        lte(alertDailyStats.date, endDate)
      ))
      .orderBy(asc(alertDailyStats.date));
  }

  async upsertAlertDailyStat(data: InsertAlertDailyStat): Promise<AlertDailyStat> {
    const [result] = await db.insert(alertDailyStats).values(data)
      .onConflictDoUpdate({
        target: [alertDailyStats.orgId, alertDailyStats.date],
        set: {
          totalAlerts: data.totalAlerts,
          criticalCount: data.criticalCount,
          highCount: data.highCount,
          mediumCount: data.mediumCount,
          lowCount: data.lowCount,
          infoCount: data.infoCount,
          sourceCounts: data.sourceCounts,
          categoryCounts: data.categoryCounts,
        },
      })
      .returning();
    return result;
  }

  async getSliMetrics(service: string, metric: string, startTime: Date, endTime: Date): Promise<SliMetric[]> {
    return db.select().from(sliMetrics)
      .where(and(
        eq(sliMetrics.service, service),
        eq(sliMetrics.metric, metric),
        gte(sliMetrics.recordedAt, startTime),
        lte(sliMetrics.recordedAt, endTime)
      ))
      .orderBy(asc(sliMetrics.recordedAt));
  }

  async createSliMetric(data: InsertSliMetric): Promise<SliMetric> {
    const [created] = await db.insert(sliMetrics).values(data).returning();
    return created;
  }

  async createSliMetricsBatch(data: InsertSliMetric[]): Promise<SliMetric[]> {
    if (data.length === 0) return [];
    return db.insert(sliMetrics).values(data).returning();
  }

  async cleanupOldSliMetrics(olderThanDays: number): Promise<number> {
    const result = await db.delete(sliMetrics)
      .where(sql`${sliMetrics.recordedAt} < NOW() - INTERVAL '${sql.raw(String(olderThanDays))} days'`)
      .returning();
    return result.length;
  }

  async getSloTargets(): Promise<SloTarget[]> {
    return db.select().from(sloTargets).orderBy(asc(sloTargets.service));
  }

  async getSloTarget(id: string): Promise<SloTarget | undefined> {
    const [target] = await db.select().from(sloTargets).where(eq(sloTargets.id, id));
    return target;
  }

  async createSloTarget(target: InsertSloTarget): Promise<SloTarget> {
    const [created] = await db.insert(sloTargets).values(target).returning();
    return created;
  }

  async updateSloTarget(id: string, data: Partial<SloTarget>): Promise<SloTarget | undefined> {
    const [updated] = await db.update(sloTargets).set({ ...data, updatedAt: new Date() }).where(eq(sloTargets.id, id)).returning();
    return updated;
  }

  async deleteSloTarget(id: string): Promise<boolean> {
    const result = await db.delete(sloTargets).where(eq(sloTargets.id, id)).returning();
    return result.length > 0;
  }

  async getDrRunbooks(orgId: string): Promise<DrRunbook[]> {
    return db.select().from(drRunbooks).where(eq(drRunbooks.orgId, orgId)).orderBy(desc(drRunbooks.createdAt));
  }

  async getDrRunbook(id: string): Promise<DrRunbook | undefined> {
    const [runbook] = await db.select().from(drRunbooks).where(eq(drRunbooks.id, id));
    return runbook;
  }

  async createDrRunbook(runbook: InsertDrRunbook): Promise<DrRunbook> {
    const [created] = await db.insert(drRunbooks).values(runbook).returning();
    return created;
  }

  async updateDrRunbook(id: string, data: Partial<DrRunbook>): Promise<DrRunbook | undefined> {
    const [updated] = await db.update(drRunbooks).set({ ...data, updatedAt: new Date() }).where(eq(drRunbooks.id, id)).returning();
    return updated;
  }

  async deleteDrRunbook(id: string): Promise<boolean> {
    const result = await db.delete(drRunbooks).where(eq(drRunbooks.id, id)).returning();
    return result.length > 0;
  }

  async getTicketSyncJobs(orgId?: string, integrationId?: string): Promise<TicketSyncJob[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(ticketSyncJobs.orgId, orgId));
    if (integrationId) conditions.push(eq(ticketSyncJobs.integrationId, integrationId));
    return db.select().from(ticketSyncJobs)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(ticketSyncJobs.createdAt));
  }

  async getTicketSyncJob(id: string): Promise<TicketSyncJob | undefined> {
    const [job] = await db.select().from(ticketSyncJobs).where(eq(ticketSyncJobs.id, id));
    return job;
  }

  async createTicketSyncJob(job: InsertTicketSyncJob): Promise<TicketSyncJob> {
    const [created] = await db.insert(ticketSyncJobs).values(job).returning();
    return created;
  }

  async updateTicketSyncJob(id: string, data: Partial<TicketSyncJob>): Promise<TicketSyncJob | undefined> {
    const [updated] = await db.update(ticketSyncJobs).set({ ...data, updatedAt: new Date() }).where(eq(ticketSyncJobs.id, id)).returning();
    return updated;
  }

  async deleteTicketSyncJob(id: string): Promise<boolean> {
    const result = await db.delete(ticketSyncJobs).where(eq(ticketSyncJobs.id, id)).returning();
    return result.length > 0;
  }

  async getResponseActionApprovals(orgId?: string, status?: string): Promise<ResponseActionApproval[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(responseActionApprovals.orgId, orgId));
    if (status) conditions.push(eq(responseActionApprovals.status, status));
    return db.select().from(responseActionApprovals)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(responseActionApprovals.requestedAt));
  }

  async getResponseActionApproval(id: string): Promise<ResponseActionApproval | undefined> {
    const [approval] = await db.select().from(responseActionApprovals).where(eq(responseActionApprovals.id, id));
    return approval;
  }

  async createResponseActionApproval(approval: InsertResponseActionApproval): Promise<ResponseActionApproval> {
    const [created] = await db.insert(responseActionApprovals).values(approval).returning();
    return created;
  }

  async updateResponseActionApproval(id: string, data: Partial<ResponseActionApproval>): Promise<ResponseActionApproval | undefined> {
    const [updated] = await db.update(responseActionApprovals).set(data).where(eq(responseActionApprovals.id, id)).returning();
    return updated;
  }

  async getLegalHolds(orgId?: string): Promise<LegalHold[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(legalHolds.orgId, orgId));
    return db.select().from(legalHolds)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(legalHolds.createdAt));
  }

  async getLegalHold(id: string): Promise<LegalHold | undefined> {
    const [hold] = await db.select().from(legalHolds).where(eq(legalHolds.id, id));
    return hold;
  }

  async createLegalHold(hold: InsertLegalHold): Promise<LegalHold> {
    const [created] = await db.insert(legalHolds).values(hold).returning();
    return created;
  }

  async updateLegalHold(id: string, data: Partial<LegalHold>): Promise<LegalHold | undefined> {
    const [updated] = await db.update(legalHolds).set(data).where(eq(legalHolds.id, id)).returning();
    return updated;
  }

  async getConnectorSecretRotations(connectorId?: string, orgId?: string): Promise<ConnectorSecretRotation[]> {
    const conditions = [];
    if (connectorId) conditions.push(eq(connectorSecretRotations.connectorId, connectorId));
    if (orgId) conditions.push(eq(connectorSecretRotations.orgId, orgId));
    return db.select().from(connectorSecretRotations)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(connectorSecretRotations.createdAt));
  }

  async createConnectorSecretRotation(rotation: InsertConnectorSecretRotation): Promise<ConnectorSecretRotation> {
    const [created] = await db.insert(connectorSecretRotations).values(rotation).returning();
    return created;
  }

  async updateConnectorSecretRotation(id: string, data: Partial<ConnectorSecretRotation>): Promise<ConnectorSecretRotation | undefined> {
    const [updated] = await db.update(connectorSecretRotations).set(data).where(eq(connectorSecretRotations.id, id)).returning();
    return updated;
  }

  async getExpiringSecretRotations(daysAhead: number): Promise<ConnectorSecretRotation[]> {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() + daysAhead);
    return db.select().from(connectorSecretRotations)
      .where(and(
        eq(connectorSecretRotations.status, "current"),
        lte(connectorSecretRotations.nextRotationDue, cutoff)
      ))
      .orderBy(asc(connectorSecretRotations.nextRotationDue));
  }
}

export const storage = new DatabaseStorage();
