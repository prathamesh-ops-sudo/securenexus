import {
  type Alert,
  type InsertAlert,
  type Incident,
  type InsertIncident,
  type Organization,
  type InsertOrganization,
  type AuditLog,
  type IncidentComment,
  type InsertComment,
  type Tag,
  type InsertTag,
  type ApiKey,
  type InsertApiKey,
  type IngestionLog,
  type InsertIngestionLog,
  type Connector,
  type InsertConnector,
  type AiFeedback,
  type InsertAiFeedback,
  type Playbook,
  type InsertPlaybook,
  type PlaybookExecution,
  type InsertPlaybookExecution,
  type PlaybookApproval,
  type InsertPlaybookApproval,
  type ThreatIntelConfig,
  type InsertThreatIntelConfig,
  type CompliancePolicy,
  type InsertCompliancePolicy,
  type ComplianceGapAssessment,
  type InsertComplianceGapAssessment,
  type DsarRequest,
  type InsertDsarRequest,
  type IntegrationConfig,
  type InsertIntegrationConfig,
  type NotificationChannel,
  type InsertNotificationChannel,
  type NotificationUserPreferences,
  type InsertNotificationUserPreferences,
  type NotificationDeliveryLog,
  type InsertNotificationDeliveryLog,
  type ResponseAction,
  type InsertResponseAction,
  type PredictiveAnomaly,
  type InsertPredictiveAnomaly,
  type AttackSurfaceAsset,
  type InsertAttackSurfaceAsset,
  type RiskForecast,
  type InsertRiskForecast,
  type AnomalySubscription,
  type InsertAnomalySubscription,
  type ForecastQualitySnapshot,
  type InsertForecastQualitySnapshot,
  type HardeningRecommendation,
  type InsertHardeningRecommendation,
  type AutoResponsePolicy,
  type InsertAutoResponsePolicy,
  type InvestigationRun,
  type InsertInvestigationRun,
  type InvestigationStep,
  type InsertInvestigationStep,
  type ResponseActionRollback,
  type InsertResponseActionRollback,
  type CspmAccount,
  type InsertCspmAccount,
  type CspmScan,
  type InsertCspmScan,
  type CspmFinding,
  type InsertCspmFinding,
  type CspmDriftBaseline,
  type InsertCspmDriftBaseline,
  type CspmDriftEvent,
  type InsertCspmDriftEvent,
  type CspmDspmFinding,
  type InsertCspmDspmFinding,
  type CspmAttackPath,
  type InsertCspmAttackPath,
  type CspmRemediation,
  type InsertCspmRemediation,
  type EndpointAsset,
  type InsertEndpointAsset,
  type EndpointTelemetry,
  type InsertEndpointTelemetry,
  type PostureScore,
  type InsertPostureScore,
  type AiDeploymentConfig,
  type InsertAiDeploymentConfig,
  type OrganizationMembership,
  type InsertOrganizationMembership,
  type OrgInvitation,
  type InsertOrgInvitation,
  type IocFeed,
  type InsertIocFeed,
  type IocEntry,
  type InsertIocEntry,
  type IocWatchlist,
  type InsertIocWatchlist,
  type IocWatchlistEntry,
  type InsertIocWatchlistEntry,
  type IocMatchRule,
  type InsertIocMatchRule,
  type IocMatch,
  type InsertIocMatch,
  type EvidenceItem,
  type InsertEvidenceItem,
  type InvestigationHypothesis,
  type InsertInvestigationHypothesis,
  type InvestigationTask,
  type InsertInvestigationTask,
  type RunbookTemplate,
  type InsertRunbookTemplate,
  type RunbookStep,
  type InsertRunbookStep,
  type ReportTemplate,
  type InsertReportTemplate,
  type ReportSchedule,
  type InsertReportSchedule,
  type ReportRun,
  type InsertReportRun,
  type SuppressionRule,
  type InsertSuppressionRule,
  type AlertDedupCluster,
  type InsertAlertDedupCluster,
  type IncidentSlaPolicy,
  type InsertIncidentSlaPolicy,
  type PostIncidentReview,
  type InsertPostIncidentReview,
  type ConnectorJobRun,
  type InsertConnectorJobRun,
  type ConnectorHealthCheck,
  type InsertConnectorHealthCheck,
  type PolicyCheck,
  type InsertPolicyCheck,
  type PolicyResult,
  type InsertPolicyResult,
  type ComplianceControl,
  type InsertComplianceControl,
  type ComplianceControlMapping,
  type InsertComplianceControlMapping,
  type EvidenceLockerItem,
  type InsertEvidenceLockerItem,
  type OutboundWebhook,
  type InsertOutboundWebhook,
  type OutboundWebhookLog,
  type InsertOutboundWebhookLog,
  type IdempotencyKey,
  type InsertIdempotencyKey,
  type AlertArchive,
  type InsertAlertArchive,
  type JobQueue as Job,
  type InsertJobQueue as InsertJob,
  type DashboardMetricsCache,
  type InsertDashboardMetricsCache,
  type AlertDailyStats as AlertDailyStat,
  type InsertAlertDailyStats as InsertAlertDailyStat,
  type SliMetric,
  type InsertSliMetric,
  type SloTarget,
  type InsertSloTarget,
  type DrRunbook,
  type InsertDrRunbook,
  type DrDrillResult,
  type InsertDrDrillResult,
  type TicketSyncJob,
  type InsertTicketSyncJob,
  type ResponseActionApproval,
  type InsertResponseActionApproval,
  type LegalHold,
  type InsertLegalHold,
  type ConnectorSecretRotation,
  type InsertConnectorSecretRotation,
  type OrgPlanLimit,
  type InsertOrgPlanLimit,
  type UsageMeterSnapshot,
  type InsertUsageMeterSnapshot,
  type OnboardingProgressItem,
  type InsertOnboardingProgress,
  type WorkspaceTemplate,
  type InsertWorkspaceTemplate,
  type WizardProgress,
  type InsertWizardProgress,
  type OutboxEvent,
  type InsertOutboxEvent,
  type FeatureFlag,
  type InsertFeatureFlag,
  type OrgSecurityPolicy,
  type InsertOrgSecurityPolicy,
  type OrgDomainVerification,
  type InsertOrgDomainVerification,
  type OrgSsoConfig,
  type InsertOrgSsoConfig,
  type OrgScimConfig,
  type InsertOrgScimConfig,
  type SavedView,
  type InsertSavedView,
  type EvidenceChainEntry,
  type InsertEvidenceChainEntry,
  type IncidentResponseApproval,
  type InsertIncidentResponseApproval,
  type PirActionItem,
  type InsertPirActionItem,
  type PlaybookVersion,
  type InsertPlaybookVersion,
  type BlastRadiusPreview,
  type InsertBlastRadiusPreview,
  type PlaybookSimulation,
  type InsertPlaybookSimulation,
  type PlaybookRollbackPlan,
  type InsertPlaybookRollbackPlan,
  type ReportTemplateVersion,
  type InsertReportTemplateVersion,
  type EvidenceAttachment,
  type InsertEvidenceAttachment,
  type ComplianceControlHelper,
  type InsertComplianceControlHelper,
  type Plan,
  type InsertPlan,
  type Subscription,
  type InsertSubscription,
  type Invoice,
  type InsertInvoice,
  type PasswordResetToken,
  type InsertPasswordResetToken,
  type MsspAccessGrant,
  type InsertMsspAccessGrant,
  type UsageRecord,
  type InsertUsageRecord,
  type EngineConfig,
  type InsertEngineConfig,
  type EngineDryRun,
  type InsertEngineDryRun,
  type EngineExplainabilityLog,
  type InsertEngineExplainabilityLog,
  type AttackGraph,
  type InsertAttackGraph,
  type AttackGraphNode,
  type InsertAttackGraphNode,
  type AttackGraphEdge,
  type InsertAttackGraphEdge,
  type InvestigationChatMessage,
  type InsertInvestigationChatMessage,
  type AiGeneratedRule,
  type InsertAiGeneratedRule,
  type WarRoom as WarRoomRow,
  type InsertWarRoom,
  type WarRoomParticipant,
  type InsertWarRoomParticipant,
  type WarRoomMessage,
  type InsertWarRoomMessage,
  type WarRoomActionItem,
  type InsertWarRoomActionItem,
  type WarRoomHandoff,
  type InsertWarRoomHandoff,
  type NativeSensor,
  type InsertNativeSensor,
  type DetectionRule,
  type InsertDetectionRule,
  type SensorEvent,
  type InsertSensorEvent,
  type DetectionAlert,
  type InsertDetectionAlert,
  type DarkWebExposure,
  type InsertDarkWebExposure,
  type DarkWebMonitoringConfig,
  type InsertDarkWebMonitoringConfig,
  type DarkWebScanHistoryEntry,
  type InsertDarkWebScanHistoryEntry,
  type CollectorInstance,
  type InsertCollectorInstance,
  type CollectorEvent,
  type InsertCollectorEvent,
  type CollectorScan,
  type InsertCollectorScan,
  type ChaosSimulation,
  type InsertChaosSimulation,
  type ChaosSchedule,
  type InsertChaosSchedule,
  type DnsEvent,
  type InsertDnsEvent,
  type DnsFinding,
  type InsertDnsFinding,
  type PassiveDnsRecord,
  type InsertPassiveDnsRecord,
  type SecurityGraphAsset,
  type InsertSecurityGraphAsset,
  type SecurityGraphRelationship,
  type InsertSecurityGraphRelationship,
  type TrustCenterArtifact,
  type InsertTrustCenterArtifact,
  type TrustCenterDownload,
  type InsertTrustCenterDownload,
  type PolicyPackActivation,
  type InsertPolicyPackActivation,
  type MarketplaceInstance,
  type InsertMarketplaceInstance,
  type MarketplaceWebhookEvent,
  type InsertMarketplaceWebhookEvent,
  type MarketplaceDeadLetter,
  type InsertMarketplaceDeadLetter,
  type MarketplaceSyncHistoryEntry,
  type InsertMarketplaceSyncHistoryEntry,
  type CrossCuttingEvidence,
  type InsertCrossCuttingEvidence,
  type CrossCuttingDriftRecord,
  type InsertCrossCuttingDriftRecord,
  type CrossCuttingOverride,
  type InsertCrossCuttingOverride,
  type JitAccessRequest,
  type InsertJitAccessRequest,
  type AdversarialTestExecution,
  type InsertAdversarialTestExecution,
  type AdversarialTestSchedule,
  type InsertAdversarialTestSchedule,
  type AdversarialRemediation,
  type InsertAdversarialRemediation,
  type AgentToolInvocation,
  type InsertAgentToolInvocation,
  type AgentToolAnomaly,
  type InsertAgentToolAnomaly,
  type AgentToolPolicy,
  type InsertAgentToolPolicy,
  type AgentTrustBoundaryRule,
  type InsertAgentTrustBoundaryRule,
  type BrowserDefenseSession,
  type InsertBrowserDefenseSession,
  type BrowserEgressRule,
  type InsertBrowserEgressRule,
  type BrowserTrustedPath,
  type InsertBrowserTrustedPath,
  type RuntimeGuardrailPolicy,
  type InsertRuntimeGuardrailPolicy,
  type RuntimeGuardrailDecision,
  type InsertRuntimeGuardrailDecision,
  type RuntimeGuardrailOverride,
  type InsertRuntimeGuardrailOverride,
  type RuntimeGuardrailSimulation,
  type InsertRuntimeGuardrailSimulation,
  type VulnScanTarget,
  type InsertVulnScanTarget,
  type VulnScanSchedule,
  type InsertVulnScanSchedule,
} from "@shared/schema";

export interface IStorage {
  getAlerts(orgId?: string): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined>;
  updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined>;
  searchAlerts(query: string, orgId?: string): Promise<Alert[]>;
  getAlertsByIncident(incidentId: string): Promise<Alert[]>;
  findAlertByDedup(orgId: string | null, source: string, sourceEventId: string): Promise<Alert | undefined>;
  upsertAlert(
    alert: InsertAlert,
    dedupWindowMinutes?: number,
  ): Promise<{ alert: Alert; isNew: boolean; isDuplicate: boolean }>;

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
  updateOrganization(id: string, data: Partial<Organization>): Promise<Organization | undefined>;
  softDeleteOrganization(id: string): Promise<Organization | undefined>;

  createAuditLog(log: Partial<AuditLog>): Promise<AuditLog>;
  getAuditLogs(orgId?: string): Promise<AuditLog[]>;
  getAuditLogsByResource(resourceType: string, resourceId: string, orgId?: string): Promise<AuditLog[]>;

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
  getApiKeyById(id: string): Promise<ApiKey | undefined>;
  revokeApiKey(id: string): Promise<ApiKey | undefined>;
  deprecateApiKey(keyId: string, replacedByKeyId: string): Promise<void>;
  updateApiKeyLastUsed(id: string): Promise<void>;

  createIngestionLog(log: InsertIngestionLog): Promise<IngestionLog>;
  getIngestionLogs(orgId: string, limit?: number): Promise<IngestionLog[]>;
  getIngestionLogsPaginated(params: {
    orgId: string;
    offset: number;
    limit: number;
  }): Promise<{ items: IngestionLog[]; total: number }>;
  getIngestionStats(orgId: string): Promise<{
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
  updateConnectorSyncStatus(
    id: string,
    data: {
      lastSyncAt: Date;
      lastSyncStatus: string;
      lastSyncAlerts: number;
      lastSyncError?: string;
      totalAlertsSynced?: number;
    },
  ): Promise<void>;

  getConnectorsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
  }): Promise<{ items: Connector[]; total: number }>;

  createAiFeedback(feedback: InsertAiFeedback): Promise<AiFeedback>;
  getAiFeedback(orgId: string, resourceType?: string, resourceId?: string): Promise<AiFeedback[]>;
  countAiFeedbackByOrg(orgId: string): Promise<number>;

  getPlaybooks(orgId?: string): Promise<Playbook[]>;
  getPlaybook(id: string): Promise<Playbook | undefined>;
  createPlaybook(playbook: InsertPlaybook): Promise<Playbook>;
  updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook | undefined>;
  deletePlaybook(id: string): Promise<boolean>;

  getPlaybookExecutions(orgId: string, playbookId?: string, limit?: number): Promise<PlaybookExecution[]>;
  countPlaybookExecutionsByOrg(orgId: string): Promise<number>;
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
    connectorHealth: {
      name: string;
      type: string;
      status: string;
      lastSyncAt: string | null;
      lastSyncAlerts: number;
      lastSyncError: string | null;
    }[];
    ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
  }>;

  getCompliancePolicy(orgId: string): Promise<CompliancePolicy | undefined>;
  upsertCompliancePolicy(policy: InsertCompliancePolicy): Promise<CompliancePolicy>;
  getComplianceGapAssessments(orgId: string): Promise<ComplianceGapAssessment[]>;
  getComplianceGapAssessment(id: string): Promise<ComplianceGapAssessment | undefined>;
  getComplianceGapsByFramework(orgId: string, frameworkId: string): Promise<ComplianceGapAssessment[]>;
  createComplianceGapAssessment(data: InsertComplianceGapAssessment): Promise<ComplianceGapAssessment>;

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

  getNotificationUserPreferences(
    userId: string,
    orgId?: string | null,
  ): Promise<NotificationUserPreferences | undefined>;
  upsertNotificationUserPreferences(data: InsertNotificationUserPreferences): Promise<NotificationUserPreferences>;
  createNotificationDeliveryLog(entry: InsertNotificationDeliveryLog): Promise<NotificationDeliveryLog>;
  getNotificationDeliveryLog(params: {
    orgId?: string;
    channelId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ items: NotificationDeliveryLog[]; total: number }>;

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
  updateAnomalySubscription(
    id: string,
    updates: Partial<AnomalySubscription>,
  ): Promise<AnomalySubscription | undefined>;
  deleteAnomalySubscription(id: string): Promise<boolean>;
  getForecastQualitySnapshots(orgId?: string): Promise<ForecastQualitySnapshot[]>;
  createForecastQualitySnapshot(snapshot: InsertForecastQualitySnapshot): Promise<ForecastQualitySnapshot>;
  getHardeningRecommendations(orgId?: string): Promise<HardeningRecommendation[]>;
  createHardeningRecommendation(rec: InsertHardeningRecommendation): Promise<HardeningRecommendation>;
  updateHardeningRecommendation(
    id: string,
    updates: Partial<InsertHardeningRecommendation>,
  ): Promise<HardeningRecommendation | undefined>;
  clearHardeningRecommendations(orgId: string): Promise<void>;

  getAutoResponsePolicies(orgId?: string): Promise<AutoResponsePolicy[]>;
  getAutoResponsePolicy(id: string): Promise<AutoResponsePolicy | null>;
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
  getResponseActionRollback(id: string): Promise<ResponseActionRollback | null>;
  createResponseActionRollback(rollback: InsertResponseActionRollback): Promise<ResponseActionRollback>;
  updateResponseActionRollback(
    id: string,
    updates: Partial<ResponseActionRollback>,
  ): Promise<ResponseActionRollback | null>;

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

  // CSPM Drift Detection
  getCspmDriftBaselines(orgId: string, accountId?: string): Promise<CspmDriftBaseline[]>;
  createCspmDriftBaseline(baseline: InsertCspmDriftBaseline): Promise<CspmDriftBaseline>;
  deleteCspmDriftBaselines(orgId: string, accountId: string): Promise<void>;
  getCspmDriftEvents(orgId: string, accountId?: string, status?: string): Promise<CspmDriftEvent[]>;
  createCspmDriftEvent(event: InsertCspmDriftEvent): Promise<CspmDriftEvent>;
  updateCspmDriftEvent(id: string, updates: Partial<CspmDriftEvent>): Promise<CspmDriftEvent | null>;

  // CSPM DSPM
  getCspmDspmFindings(orgId: string, accountId?: string, sensitivityLevel?: string): Promise<CspmDspmFinding[]>;
  createCspmDspmFinding(finding: InsertCspmDspmFinding): Promise<CspmDspmFinding>;
  updateCspmDspmFinding(id: string, updates: Partial<CspmDspmFinding>): Promise<CspmDspmFinding | null>;

  // CSPM Attack Paths
  getCspmAttackPaths(orgId: string, severity?: string): Promise<CspmAttackPath[]>;
  createCspmAttackPath(path: InsertCspmAttackPath): Promise<CspmAttackPath>;
  updateCspmAttackPath(id: string, updates: Partial<CspmAttackPath>): Promise<CspmAttackPath | null>;

  // CSPM Remediations
  getCspmRemediations(orgId: string, accountId?: string, status?: string): Promise<CspmRemediation[]>;
  getCspmRemediation(id: string): Promise<CspmRemediation | undefined>;
  createCspmRemediation(remediation: InsertCspmRemediation): Promise<CspmRemediation>;
  updateCspmRemediation(id: string, updates: Partial<CspmRemediation>): Promise<CspmRemediation | null>;

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
  transferOwnership(currentOwnerMembershipId: string, newOwnerMembershipId: string): Promise<void>;
  deleteOrgMembership(id: string): Promise<boolean>;

  getOrgInvitations(orgId: string): Promise<OrgInvitation[]>;
  getOrgInvitationByToken(token: string): Promise<OrgInvitation | undefined>;
  getPendingInvitationsByEmail(email: string): Promise<OrgInvitation[]>;
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
  getIocEntries(
    orgId?: string,
    feedId?: string,
    iocType?: string,
    status?: string,
    limit?: number,
  ): Promise<IocEntry[]>;
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
  getRunbookTemplates(orgId: string, incidentType?: string): Promise<RunbookTemplate[]>;
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
  getReportTemplates(orgId: string): Promise<ReportTemplate[]>;
  getReportTemplate(id: string, orgId?: string): Promise<ReportTemplate | undefined>;
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
  getDeadLetterJobRunsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
  }): Promise<{ items: ConnectorJobRun[]; total: number }>;
  getConnectorJobRunById(id: string): Promise<ConnectorJobRun | undefined>;
  getOrgAdminEmails(orgId: string): Promise<string[]>;
  getConnectorMetrics(connectorId: string): Promise<{
    avgLatencyMs: number;
    errorRate: number;
    throttleCount: number;
    totalRuns: number;
    successRate: number;
  }>;

  createConnectorHealthCheck(check: InsertConnectorHealthCheck): Promise<ConnectorHealthCheck>;
  getConnectorHealthChecks(connectorId: string, limit?: number): Promise<ConnectorHealthCheck[]>;
  getLatestHealthCheck(connectorId: string): Promise<ConnectorHealthCheck | undefined>;

  getAiFeedbackMetrics(
    orgId?: string,
    days?: number,
  ): Promise<
    { date: string; avgRating: number; totalFeedback: number; negativeFeedback: number; positiveFeedback: number }[]
  >;
  getAiFeedbackByResource(orgId: string, resourceType: string, resourceId: string): Promise<AiFeedback[]>;

  getPolicyChecks(orgId: string): Promise<PolicyCheck[]>;
  getPolicyCheck(id: string): Promise<PolicyCheck | undefined>;
  getPolicyCheckForOrg(id: string, orgId: string): Promise<PolicyCheck | undefined>;
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
  updateComplianceControlMapping(
    id: string,
    data: Partial<ComplianceControlMapping>,
  ): Promise<ComplianceControlMapping | undefined>;
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
  getSliMetrics(
    service: string,
    metric: string,
    startTime: Date,
    endTime: Date,
    labels?: Record<string, string>,
  ): Promise<SliMetric[]>;
  createSliMetric(data: InsertSliMetric): Promise<SliMetric>;
  createSliMetricsBatch(data: InsertSliMetric[]): Promise<SliMetric[]>;
  cleanupOldSliMetrics(olderThanDays: number): Promise<number>;

  // SLO Targets
  getSloTargets(orgId?: string): Promise<SloTarget[]>;
  getSloTarget(id: string, orgId?: string): Promise<SloTarget | undefined>;
  createSloTarget(target: InsertSloTarget): Promise<SloTarget>;
  updateSloTarget(id: string, data: Partial<SloTarget>, orgId?: string): Promise<SloTarget | undefined>;
  deleteSloTarget(id: string, orgId?: string): Promise<boolean>;

  // DR Runbooks
  getDrRunbooks(orgId: string): Promise<DrRunbook[]>;
  getDrRunbook(id: string): Promise<DrRunbook | undefined>;
  getDrRunbookForOrg(id: string, orgId: string): Promise<DrRunbook | undefined>;
  createDrRunbook(runbook: InsertDrRunbook): Promise<DrRunbook>;
  updateDrRunbook(id: string, data: Partial<DrRunbook>): Promise<DrRunbook | undefined>;
  deleteDrRunbook(id: string): Promise<boolean>;

  // DR Drill Results
  getDrDrillResults(orgId?: string, runbookId?: string, limit?: number): Promise<DrDrillResult[]>;
  getDrDrillResult(id: string): Promise<DrDrillResult | undefined>;
  createDrDrillResult(result: InsertDrDrillResult): Promise<DrDrillResult>;
  updateDrDrillResult(id: string, data: Partial<DrDrillResult>): Promise<DrDrillResult | undefined>;

  // Plan Limits
  getOrgPlanLimit(orgId: string): Promise<OrgPlanLimit | undefined>;
  upsertOrgPlanLimit(data: InsertOrgPlanLimit): Promise<OrgPlanLimit>;
  updateOrgPlanLimit(orgId: string, data: Partial<OrgPlanLimit>): Promise<OrgPlanLimit | undefined>;

  // Usage Metering
  getUsageMeterSnapshots(orgId: string, metricType?: string): Promise<UsageMeterSnapshot[]>;
  createUsageMeterSnapshot(data: InsertUsageMeterSnapshot): Promise<UsageMeterSnapshot>;

  // Onboarding Progress
  getOnboardingProgress(orgId: string): Promise<OnboardingProgressItem[]>;
  upsertOnboardingStep(data: InsertOnboardingProgress): Promise<OnboardingProgressItem>;
  completeOnboardingStep(
    orgId: string,
    stepKey: string,
    completedBy?: string,
  ): Promise<OnboardingProgressItem | undefined>;

  // Wizard Progress (Phase 2 Onboarding Wizard)
  getWizardProgress(userId: string): Promise<WizardProgress | undefined>;
  upsertWizardProgress(data: InsertWizardProgress): Promise<WizardProgress>;
  updateWizardProgress(userId: string, data: Partial<WizardProgress>): Promise<WizardProgress | undefined>;

  // Workspace Templates
  getWorkspaceTemplates(): Promise<WorkspaceTemplate[]>;
  getWorkspaceTemplate(id: string): Promise<WorkspaceTemplate | undefined>;
  createWorkspaceTemplate(template: InsertWorkspaceTemplate): Promise<WorkspaceTemplate>;

  // Outbox Events
  createOutboxEvent(event: InsertOutboxEvent): Promise<OutboxEvent>;
  getPendingOutboxEvents(batchSize: number): Promise<OutboxEvent[]>;
  updateOutboxEvent(id: string, data: Partial<OutboxEvent>): Promise<OutboxEvent | undefined>;
  getOutboxEvent(id: string): Promise<OutboxEvent | undefined>;
  getOutboxEvents(
    orgId?: string,
    status?: string,
    limit?: number,
    offset?: number,
  ): Promise<{ items: OutboxEvent[]; total: number }>;
  replayOutboxEvent(id: string): Promise<OutboxEvent | undefined>;
  cleanupDispatchedOutboxEvents(olderThanDays: number): Promise<number>;

  // Feature Flags
  listFeatureFlags(): Promise<FeatureFlag[]>;
  getFeatureFlag(key: string): Promise<FeatureFlag | undefined>;
  getFeatureFlagById(id: string): Promise<FeatureFlag | undefined>;
  createFeatureFlag(flag: InsertFeatureFlag): Promise<FeatureFlag>;
  updateFeatureFlag(key: string, data: Partial<FeatureFlag>): Promise<FeatureFlag | undefined>;
  deleteFeatureFlag(key: string): Promise<boolean>;

  // Enhanced Pagination
  getAlertsPaginatedWithSort(params: {
    orgId?: string;
    offset: number;
    limit: number;
    search?: string;
    severity?: string;
    status?: string;
    source?: string;
    suppressed?: boolean;
    sortBy?: string;
    sortOrder?: "asc" | "desc";
  }): Promise<{ items: Alert[]; total: number }>;
  getIncidentsPaginatedWithSort(params: {
    orgId?: string;
    offset: number;
    limit: number;
    search?: string;
    severity?: string;
    status?: string;
    queue?: string;
    sortBy?: string;
    sortOrder?: "asc" | "desc";
  }): Promise<{ items: Incident[]; total: number }>;
  getAuditLogsPaginated(params: {
    orgId?: string;
    offset: number;
    limit: number;
    action?: string;
    userId?: string;
    resourceType?: string;
    sortOrder?: "asc" | "desc";
  }): Promise<{ items: AuditLog[]; total: number }>;
  getConnectorsPaginatedWithSort(params: {
    orgId?: string;
    offset: number;
    limit: number;
    search?: string;
    type?: string;
    status?: string;
    sortBy?: string;
    sortOrder?: "asc" | "desc";
  }): Promise<{ items: Connector[]; total: number }>;

  // Saved Views
  getSavedViews(orgId: string, resourceType?: string): Promise<SavedView[]>;
  getSavedView(id: string): Promise<SavedView | undefined>;
  createSavedView(view: InsertSavedView): Promise<SavedView>;
  updateSavedView(id: string, data: Partial<SavedView>): Promise<SavedView | undefined>;
  deleteSavedView(id: string): Promise<boolean>;

  // Org Security Policies
  getOrgSecurityPolicy(orgId: string): Promise<OrgSecurityPolicy | undefined>;
  upsertOrgSecurityPolicy(policy: InsertOrgSecurityPolicy): Promise<OrgSecurityPolicy>;

  // Session management for max concurrent sessions
  countUserActiveSessions(userId: string): Promise<number>;
  evictOldestUserSessions(userId: string, count: number): Promise<number>;

  // Org Domain Verifications
  getOrgDomainVerifications(orgId: string): Promise<OrgDomainVerification[]>;
  getOrgDomainVerification(id: string): Promise<OrgDomainVerification | undefined>;
  createOrgDomainVerification(verification: InsertOrgDomainVerification): Promise<OrgDomainVerification>;
  updateOrgDomainVerification(
    id: string,
    data: Partial<OrgDomainVerification>,
  ): Promise<OrgDomainVerification | undefined>;
  deleteOrgDomainVerification(id: string): Promise<boolean>;

  // Org SSO Configs
  getOrgSsoConfig(orgId: string): Promise<OrgSsoConfig | undefined>;
  upsertOrgSsoConfig(config: InsertOrgSsoConfig): Promise<OrgSsoConfig>;
  deleteOrgSsoConfig(orgId: string): Promise<boolean>;

  // Org SCIM Configs
  getOrgScimConfig(orgId: string): Promise<OrgScimConfig | undefined>;
  upsertOrgScimConfig(config: InsertOrgScimConfig): Promise<OrgScimConfig>;
  deleteOrgScimConfig(orgId: string): Promise<boolean>;

  // Evidence Chain Entries (8.2)
  getEvidenceChainEntries(incidentId: string, orgId?: string): Promise<EvidenceChainEntry[]>;
  getEvidenceChainEntriesByOrg(orgId: string, limit?: number, offset?: number): Promise<EvidenceChainEntry[]>;
  countEvidenceChainEntriesByOrg(orgId: string): Promise<number>;
  getEvidenceChainEntry(id: string): Promise<EvidenceChainEntry | undefined>;
  createEvidenceChainEntry(entry: InsertEvidenceChainEntry): Promise<EvidenceChainEntry>;
  getNextSequenceNum(incidentId: string): Promise<number>;
  getLatestChainHash(incidentId: string): Promise<string | null>;

  // Incident Response Approvals (8.2)
  getIncidentResponseApprovals(
    orgId: string,
    incidentId?: string,
    status?: string,
  ): Promise<IncidentResponseApproval[]>;
  getIncidentResponseApproval(id: string): Promise<IncidentResponseApproval | undefined>;
  createIncidentResponseApproval(approval: InsertIncidentResponseApproval): Promise<IncidentResponseApproval>;
  updateIncidentResponseApproval(
    id: string,
    data: Partial<IncidentResponseApproval>,
  ): Promise<IncidentResponseApproval | undefined>;

  // PIR Action Items (8.2)
  getPirActionItems(reviewId: string, orgId?: string): Promise<PirActionItem[]>;
  getPirActionItem(id: string): Promise<PirActionItem | undefined>;
  createPirActionItem(item: InsertPirActionItem): Promise<PirActionItem>;
  updatePirActionItem(id: string, data: Partial<PirActionItem>): Promise<PirActionItem | undefined>;
  deletePirActionItem(id: string): Promise<boolean>;

  // Playbook Versions (8.3)
  getPlaybookVersions(playbookId: string, orgId?: string): Promise<PlaybookVersion[]>;
  getPlaybookVersion(id: string): Promise<PlaybookVersion | undefined>;
  getLatestPlaybookVersion(playbookId: string): Promise<PlaybookVersion | undefined>;
  createPlaybookVersion(version: InsertPlaybookVersion): Promise<PlaybookVersion>;
  updatePlaybookVersion(id: string, data: Partial<PlaybookVersion>): Promise<PlaybookVersion | undefined>;

  // Blast Radius Previews (8.3)
  getBlastRadiusPreviews(playbookId: string, orgId?: string): Promise<BlastRadiusPreview[]>;
  getBlastRadiusPreview(id: string): Promise<BlastRadiusPreview | undefined>;
  createBlastRadiusPreview(preview: InsertBlastRadiusPreview): Promise<BlastRadiusPreview>;

  // Playbook Simulations (8.3)
  getPlaybookSimulations(playbookId: string, orgId?: string): Promise<PlaybookSimulation[]>;
  getPlaybookSimulation(id: string): Promise<PlaybookSimulation | undefined>;
  createPlaybookSimulation(simulation: InsertPlaybookSimulation): Promise<PlaybookSimulation>;
  updatePlaybookSimulation(id: string, data: Partial<PlaybookSimulation>): Promise<PlaybookSimulation | undefined>;

  // Playbook Rollback Plans (8.3)
  getPlaybookRollbackPlans(playbookId: string, orgId?: string): Promise<PlaybookRollbackPlan[]>;
  getPlaybookRollbackPlan(id: string): Promise<PlaybookRollbackPlan | undefined>;
  createPlaybookRollbackPlan(plan: InsertPlaybookRollbackPlan): Promise<PlaybookRollbackPlan>;
  updatePlaybookRollbackPlan(
    id: string,
    data: Partial<PlaybookRollbackPlan>,
  ): Promise<PlaybookRollbackPlan | undefined>;

  // Report Template Versions (8.4)
  getReportTemplateVersions(templateId: string, orgId?: string): Promise<ReportTemplateVersion[]>;
  getReportTemplateVersion(id: string): Promise<ReportTemplateVersion | undefined>;
  getLatestTemplateVersion(templateId: string): Promise<ReportTemplateVersion | undefined>;
  createReportTemplateVersion(version: InsertReportTemplateVersion): Promise<ReportTemplateVersion>;
  updateReportTemplateVersion(
    id: string,
    data: Partial<ReportTemplateVersion>,
  ): Promise<ReportTemplateVersion | undefined>;

  // Evidence Attachments (8.4)
  getEvidenceAttachments(orgId: string, controlMappingId?: string): Promise<EvidenceAttachment[]>;
  getEvidenceAttachment(id: string): Promise<EvidenceAttachment | undefined>;
  createEvidenceAttachment(attachment: InsertEvidenceAttachment): Promise<EvidenceAttachment>;
  updateEvidenceAttachment(id: string, data: Partial<EvidenceAttachment>): Promise<EvidenceAttachment | undefined>;
  deleteEvidenceAttachment(id: string): Promise<boolean>;

  // Compliance Control Helpers (8.4)
  getComplianceControlHelpers(orgId: string, helperType?: string): Promise<ComplianceControlHelper[]>;
  getComplianceControlHelper(id: string): Promise<ComplianceControlHelper | undefined>;
  createComplianceControlHelper(helper: InsertComplianceControlHelper): Promise<ComplianceControlHelper>;
  updateComplianceControlHelper(
    id: string,
    data: Partial<ComplianceControlHelper>,
  ): Promise<ComplianceControlHelper | undefined>;

  // Plans (Phase 3)
  getPlans(activeOnly?: boolean): Promise<Plan[]>;
  getPlan(id: string): Promise<Plan | undefined>;
  getPlanByName(name: string): Promise<Plan | undefined>;
  createPlan(plan: InsertPlan): Promise<Plan>;
  updatePlan(id: string, data: Partial<Plan>): Promise<Plan | undefined>;

  // Subscriptions (Phase 3)
  getSubscription(orgId: string): Promise<Subscription | undefined>;
  getSubscriptionById(id: string): Promise<Subscription | undefined>;
  getSubscriptionByStripeCustomerId(stripeCustomerId: string): Promise<Subscription | undefined>;
  getSubscriptionByStripeSubId(stripeSubscriptionId: string): Promise<Subscription | undefined>;
  createSubscription(sub: InsertSubscription): Promise<Subscription>;
  updateSubscription(id: string, data: Partial<Subscription>): Promise<Subscription | undefined>;

  // Invoices (Phase 3)
  getInvoices(orgId: string, limit?: number): Promise<Invoice[]>;
  getInvoiceByStripeId(stripeInvoiceId: string): Promise<Invoice | undefined>;
  createInvoice(invoice: InsertInvoice): Promise<Invoice>;
  updateInvoice(id: string, data: Partial<Invoice>): Promise<Invoice | undefined>;

  // Password Reset Tokens (Phase 4)
  createPasswordResetToken(token: InsertPasswordResetToken): Promise<PasswordResetToken>;
  getPasswordResetToken(token: string): Promise<PasswordResetToken | undefined>;
  markPasswordResetTokenAsUsed(token: string): Promise<void>;
  consumePasswordResetToken(token: string): Promise<PasswordResetToken | undefined>;
  invalidateAllUserPasswordResetTokens(userId: string): Promise<void>;
  deleteExpiredPasswordResetTokens(): Promise<number>;

  // Phase 6: Domain Auto-Join & SSO helpers
  getOrganizationBySlug(slug: string): Promise<Organization | undefined>;
  getVerifiedAutoJoinDomain(domain: string): Promise<OrgDomainVerification | undefined>;

  // Phase 7: MSSP / Parent-Child Organizations
  getChildOrganizations(parentOrgId: string): Promise<Organization[]>;
  createMsspAccessGrant(grant: InsertMsspAccessGrant): Promise<MsspAccessGrant>;
  getMsspAccessGrants(parentOrgId: string): Promise<MsspAccessGrant[]>;
  getMsspAccessGrant(id: string): Promise<MsspAccessGrant | undefined>;
  revokeMsspAccessGrant(id: string, revokedBy: string): Promise<MsspAccessGrant | undefined>;
  getMsspAggregatedStats(childOrgIds: string[]): Promise<{
    totalAlerts: number;
    criticalAlerts: number;
    openIncidents: number;
    totalConnectors: number;
    perOrg: { orgId: string; orgName: string; alertCount: number; incidentCount: number; connectorCount: number }[];
  }>;

  // Phase 8: Usage Metering & Plan Enforcement
  getUsageRecord(orgId: string, metric: string, periodStart: Date): Promise<UsageRecord | undefined>;
  getUsageRecords(orgId: string, periodStart?: Date): Promise<UsageRecord[]>;
  incrementUsage(orgId: string, metric: string, amount?: number): Promise<UsageRecord>;
  resetUsagePeriod(orgId: string, oldPeriodStart: Date, newPeriodStart: Date, newPeriodEnd: Date): Promise<void>;
  countActiveConnectors(orgId: string): Promise<number>;
  countActiveApiKeys(orgId: string): Promise<number>;
  countActivePlaybooks(orgId: string): Promise<number>;

  // Engine Controls
  getEngineConfigs(orgId: string): Promise<EngineConfig[]>;
  getEngineConfig(orgId: string, engineName: string): Promise<EngineConfig | undefined>;
  upsertEngineConfig(orgId: string, engineName: string, data: Partial<InsertEngineConfig>): Promise<EngineConfig>;
  createEngineDryRun(run: InsertEngineDryRun): Promise<EngineDryRun>;
  getEngineDryRuns(orgId: string, engineName: string, limit?: number): Promise<EngineDryRun[]>;
  updateEngineDryRun(id: string, data: Partial<EngineDryRun>): Promise<EngineDryRun | undefined>;
  createEngineExplainabilityLog(log: InsertEngineExplainabilityLog): Promise<EngineExplainabilityLog>;
  getEngineExplainabilityLogs(orgId: string, engineName: string, limit?: number): Promise<EngineExplainabilityLog[]>;

  // Attack Graph Persistence
  createAttackGraph(graph: InsertAttackGraph): Promise<AttackGraph>;
  getAttackGraphsByIncident(incidentId: string, orgId: string): Promise<AttackGraph[]>;
  getAttackGraphsByOrg(orgId: string, limit?: number, days?: number): Promise<AttackGraph[]>;
  getAttackGraph(id: string): Promise<AttackGraph | undefined>;
  deleteAttackGraph(id: string): Promise<boolean>;
  createAttackGraphNodes(nodes: InsertAttackGraphNode[]): Promise<AttackGraphNode[]>;
  createAttackGraphEdges(edges: InsertAttackGraphEdge[]): Promise<AttackGraphEdge[]>;
  getAttackGraphNodes(graphId: string): Promise<AttackGraphNode[]>;
  getAttackGraphEdges(graphId: string): Promise<AttackGraphEdge[]>;

  // Investigation Chat Messages
  createChatMessage(msg: InsertInvestigationChatMessage): Promise<InvestigationChatMessage>;
  getChatThread(threadId: string, orgId: string): Promise<InvestigationChatMessage[]>;
  getChatThreadsByIncident(incidentId: string, orgId: string): Promise<InvestigationChatMessage[]>;

  // AI-Generated Detection Rules
  createAiGeneratedRule(rule: InsertAiGeneratedRule): Promise<AiGeneratedRule>;
  getAiGeneratedRulesByOrg(orgId: string, limit?: number): Promise<AiGeneratedRule[]>;
  getAiGeneratedRulesByIncident(incidentId: string, orgId: string): Promise<AiGeneratedRule[]>;
  getAiGeneratedRule(id: string): Promise<AiGeneratedRule | undefined>;
  updateAiGeneratedRule(id: string, data: Partial<AiGeneratedRule>): Promise<AiGeneratedRule | undefined>;

  // War Rooms (Persistent)
  createWarRoom(room: InsertWarRoom): Promise<WarRoomRow>;
  getWarRooms(orgId: string, status?: string): Promise<WarRoomRow[]>;
  getWarRoom(id: string): Promise<WarRoomRow | undefined>;
  updateWarRoom(id: string, data: Partial<WarRoomRow>): Promise<WarRoomRow | undefined>;
  // War Room Participants
  addWarRoomParticipant(participant: InsertWarRoomParticipant): Promise<WarRoomParticipant>;
  getWarRoomParticipants(warRoomId: string): Promise<WarRoomParticipant[]>;
  getWarRoomParticipantByUser(warRoomId: string, userId: string): Promise<WarRoomParticipant | undefined>;
  removeWarRoomParticipant(warRoomId: string, userId: string): Promise<void>;
  // War Room Messages (Timeline)
  createWarRoomMessage(msg: InsertWarRoomMessage): Promise<WarRoomMessage>;
  getWarRoomMessages(warRoomId: string, limit?: number): Promise<WarRoomMessage[]>;
  getWarRoomMessagesByType(warRoomId: string, type: string): Promise<WarRoomMessage[]>;
  // War Room Action Items
  createWarRoomActionItem(item: InsertWarRoomActionItem): Promise<WarRoomActionItem>;
  getWarRoomActionItems(warRoomId: string): Promise<WarRoomActionItem[]>;
  getWarRoomActionItem(id: string): Promise<WarRoomActionItem | undefined>;
  updateWarRoomActionItem(id: string, data: Partial<WarRoomActionItem>): Promise<WarRoomActionItem | undefined>;
  // War Room Handoffs
  createWarRoomHandoff(handoff: InsertWarRoomHandoff): Promise<WarRoomHandoff>;
  getWarRoomHandoffs(warRoomId: string): Promise<WarRoomHandoff[]>;
  getWarRoomHandoff(id: string): Promise<WarRoomHandoff | undefined>;
  updateWarRoomHandoff(id: string, data: Partial<WarRoomHandoff>): Promise<WarRoomHandoff | undefined>;

  // Native Sensors
  getNativeSensors(orgId: string): Promise<NativeSensor[]>;
  getNativeSensor(id: string): Promise<NativeSensor | undefined>;
  createNativeSensor(sensor: InsertNativeSensor): Promise<NativeSensor>;
  updateNativeSensor(id: string, updates: Partial<InsertNativeSensor>): Promise<NativeSensor | undefined>;
  deleteNativeSensor(id: string): Promise<boolean>;
  countNativeSensors(orgId: string): Promise<number>;

  // Detection Rules
  getDetectionRules(orgId: string): Promise<DetectionRule[]>;
  getDetectionRule(id: string): Promise<DetectionRule | undefined>;
  createDetectionRule(rule: InsertDetectionRule): Promise<DetectionRule>;
  updateDetectionRule(id: string, updates: Partial<InsertDetectionRule>): Promise<DetectionRule | undefined>;
  deleteDetectionRule(id: string): Promise<boolean>;
  countDetectionRules(orgId: string): Promise<number>;

  // Sensor Events
  getSensorEvents(orgId: string, limit?: number, offset?: number): Promise<SensorEvent[]>;
  getSensorEventsBySensor(sensorId: string, limit?: number): Promise<SensorEvent[]>;
  createSensorEvent(event: InsertSensorEvent): Promise<SensorEvent>;
  countSensorEvents(orgId: string): Promise<number>;

  // Detection Alerts
  getDetectionAlerts(orgId: string, limit?: number, offset?: number): Promise<DetectionAlert[]>;
  getDetectionAlertsByRule(ruleId: string): Promise<DetectionAlert[]>;
  createDetectionAlert(alert: InsertDetectionAlert): Promise<DetectionAlert>;
  countDetectionAlerts(orgId: string): Promise<number>;
  countDetectionAlertsByRule(ruleId: string): Promise<number>;

  // Dark Web Monitoring
  getDarkWebExposures(orgId: string): Promise<DarkWebExposure[]>;
  getDarkWebExposure(id: string): Promise<DarkWebExposure | undefined>;
  createDarkWebExposure(item: InsertDarkWebExposure): Promise<DarkWebExposure>;
  updateDarkWebExposure(id: string, updates: Partial<InsertDarkWebExposure>): Promise<DarkWebExposure | undefined>;
  deleteDarkWebExposure(id: string): Promise<boolean>;
  countDarkWebExposures(orgId: string): Promise<number>;
  countDarkWebExposuresByStatus(orgId: string, status: string): Promise<number>;
  getDarkWebMonitoringConfig(orgId: string): Promise<DarkWebMonitoringConfig | undefined>;
  upsertDarkWebMonitoringConfig(
    orgId: string,
    data: Partial<InsertDarkWebMonitoringConfig>,
  ): Promise<DarkWebMonitoringConfig>;
  getDarkWebScanHistory(orgId: string, limit?: number): Promise<DarkWebScanHistoryEntry[]>;
  createDarkWebScanHistoryEntry(entry: InsertDarkWebScanHistoryEntry): Promise<DarkWebScanHistoryEntry>;
  updateDarkWebScanHistoryEntry(
    id: string,
    updates: Partial<InsertDarkWebScanHistoryEntry>,
  ): Promise<DarkWebScanHistoryEntry | undefined>;

  // Collectors
  getCollectorInstances(orgId: string): Promise<CollectorInstance[]>;
  getCollectorInstance(id: string): Promise<CollectorInstance | undefined>;
  createCollectorInstance(instance: InsertCollectorInstance): Promise<CollectorInstance>;
  updateCollectorInstance(
    id: string,
    updates: Partial<InsertCollectorInstance>,
  ): Promise<CollectorInstance | undefined>;
  deleteCollectorInstance(id: string): Promise<boolean>;
  countCollectorInstances(orgId: string): Promise<number>;
  getCollectorEvents(orgId: string, limit?: number, offset?: number): Promise<CollectorEvent[]>;
  getCollectorEventsByInstance(instanceId: string, limit?: number): Promise<CollectorEvent[]>;
  createCollectorEvent(event: InsertCollectorEvent): Promise<CollectorEvent>;
  countCollectorEvents(orgId: string): Promise<number>;
  getCollectorScans(orgId: string, limit?: number): Promise<CollectorScan[]>;
  createCollectorScan(scan: InsertCollectorScan): Promise<CollectorScan>;
  updateCollectorScan(id: string, updates: Partial<InsertCollectorScan>): Promise<CollectorScan | undefined>;

  // Chaos Engineering
  getChaosSimulations(orgId: string): Promise<ChaosSimulation[]>;
  getChaosSimulation(id: string): Promise<ChaosSimulation | undefined>;
  createChaosSimulation(sim: InsertChaosSimulation): Promise<ChaosSimulation>;
  updateChaosSimulation(id: string, updates: Partial<InsertChaosSimulation>): Promise<ChaosSimulation | undefined>;
  deleteChaosSimulation(id: string): Promise<boolean>;
  countChaosSimulations(orgId: string): Promise<number>;
  getChaosSchedules(orgId: string): Promise<ChaosSchedule[]>;
  getChaosSchedule(id: string): Promise<ChaosSchedule | undefined>;
  createChaosSchedule(sched: InsertChaosSchedule): Promise<ChaosSchedule>;
  updateChaosSchedule(id: string, updates: Partial<InsertChaosSchedule>): Promise<ChaosSchedule | undefined>;
  deleteChaosSchedule(id: string): Promise<boolean>;

  // DNS Security
  getDnsEvents(orgId: string, limit?: number, offset?: number): Promise<DnsEvent[]>;
  createDnsEvent(event: InsertDnsEvent): Promise<DnsEvent>;
  countDnsEvents(orgId: string): Promise<number>;
  countSuspiciousDnsEvents(orgId: string): Promise<number>;
  getDnsFindings(orgId: string, limit?: number): Promise<DnsFinding[]>;
  getDnsFinding(id: string): Promise<DnsFinding | undefined>;
  createDnsFinding(finding: InsertDnsFinding): Promise<DnsFinding>;
  updateDnsFinding(id: string, updates: Partial<InsertDnsFinding>): Promise<DnsFinding | undefined>;
  countDnsFindings(orgId: string): Promise<number>;
  countDnsFindingsByStatus(orgId: string, status: string): Promise<number>;
  getPassiveDnsRecords(orgId: string, limit?: number): Promise<PassiveDnsRecord[]>;
  getPassiveDnsRecordsByDomain(orgId: string, domain: string): Promise<PassiveDnsRecord[]>;
  createPassiveDnsRecord(record: InsertPassiveDnsRecord): Promise<PassiveDnsRecord>;
  countPassiveDnsRecords(orgId: string): Promise<number>;

  // Security Graph
  getSecurityGraphAssets(orgId: string): Promise<SecurityGraphAsset[]>;
  getSecurityGraphAssetsByType(orgId: string, type: string): Promise<SecurityGraphAsset[]>;
  getSecurityGraphAsset(id: string, orgId: string): Promise<SecurityGraphAsset | undefined>;
  getSecurityGraphAssetByResolutionKey(orgId: string, resolutionKey: string): Promise<SecurityGraphAsset | undefined>;
  createSecurityGraphAsset(data: InsertSecurityGraphAsset): Promise<SecurityGraphAsset>;
  updateSecurityGraphAsset(
    id: string,
    orgId: string,
    updates: Partial<InsertSecurityGraphAsset>,
  ): Promise<SecurityGraphAsset | undefined>;
  deleteSecurityGraphAsset(id: string, orgId: string): Promise<boolean>;
  countSecurityGraphAssets(orgId: string): Promise<number>;
  getSecurityGraphRelationships(orgId: string): Promise<SecurityGraphRelationship[]>;
  getSecurityGraphRelationship(id: string, orgId: string): Promise<SecurityGraphRelationship | undefined>;
  getSecurityGraphRelationshipsByAsset(assetId: string): Promise<SecurityGraphRelationship[]>;
  createSecurityGraphRelationship(data: InsertSecurityGraphRelationship): Promise<SecurityGraphRelationship>;
  deleteSecurityGraphRelationship(id: string, orgId: string): Promise<boolean>;
  countSecurityGraphRelationships(orgId: string): Promise<number>;

  // Trust Center
  getTrustCenterArtifacts(orgId: string, category?: string): Promise<TrustCenterArtifact[]>;
  getTrustCenterArtifact(id: string, orgId: string): Promise<TrustCenterArtifact | undefined>;
  createTrustCenterArtifact(data: InsertTrustCenterArtifact): Promise<TrustCenterArtifact>;
  updateTrustCenterArtifact(
    id: string,
    orgId: string,
    updates: Partial<InsertTrustCenterArtifact>,
  ): Promise<TrustCenterArtifact | undefined>;
  deleteTrustCenterArtifact(id: string, orgId: string): Promise<boolean>;
  countTrustCenterArtifacts(orgId: string): Promise<number>;
  getTrustCenterDownloads(orgId: string, limit?: number): Promise<TrustCenterDownload[]>;
  createTrustCenterDownload(data: InsertTrustCenterDownload): Promise<TrustCenterDownload>;
  countTrustCenterDownloads(orgId: string): Promise<number>;

  // Policy Packs
  getPolicyPackActivations(orgId: string): Promise<PolicyPackActivation[]>;
  getPolicyPackActivation(orgId: string, packId: string): Promise<PolicyPackActivation | undefined>;
  getPolicyPackActivationById(id: string, orgId: string): Promise<PolicyPackActivation | undefined>;
  createPolicyPackActivation(data: InsertPolicyPackActivation): Promise<PolicyPackActivation>;
  updatePolicyPackActivation(
    id: string,
    orgId: string,
    updates: Partial<InsertPolicyPackActivation>,
  ): Promise<PolicyPackActivation | undefined>;
  deletePolicyPackActivation(id: string, orgId: string): Promise<boolean>;
  countPolicyPackActivations(orgId: string): Promise<number>;

  // Marketplace
  getMarketplaceInstances(orgId: string): Promise<MarketplaceInstance[]>;
  getMarketplaceInstance(id: string, orgId: string): Promise<MarketplaceInstance | undefined>;
  createMarketplaceInstance(data: InsertMarketplaceInstance): Promise<MarketplaceInstance>;
  updateMarketplaceInstance(
    id: string,
    orgId: string,
    updates: Partial<InsertMarketplaceInstance>,
  ): Promise<MarketplaceInstance | undefined>;
  deleteMarketplaceInstance(id: string, orgId: string): Promise<boolean>;
  countMarketplaceInstances(orgId: string): Promise<number>;
  getMarketplaceWebhookEvents(orgId: string, instanceId?: string, limit?: number): Promise<MarketplaceWebhookEvent[]>;
  createMarketplaceWebhookEvent(data: InsertMarketplaceWebhookEvent): Promise<MarketplaceWebhookEvent>;
  getMarketplaceDeadLetters(orgId: string, instanceId?: string, limit?: number): Promise<MarketplaceDeadLetter[]>;
  getMarketplaceDeadLetter(id: string, orgId: string): Promise<MarketplaceDeadLetter | undefined>;
  createMarketplaceDeadLetter(data: InsertMarketplaceDeadLetter): Promise<MarketplaceDeadLetter>;
  updateMarketplaceDeadLetter(
    id: string,
    orgId: string,
    updates: Partial<InsertMarketplaceDeadLetter>,
  ): Promise<MarketplaceDeadLetter | undefined>;
  getMarketplaceSyncHistory(orgId: string, instanceId: string, limit?: number): Promise<MarketplaceSyncHistoryEntry[]>;
  createMarketplaceSyncHistoryEntry(data: InsertMarketplaceSyncHistoryEntry): Promise<MarketplaceSyncHistoryEntry>;
  updateMarketplaceSyncHistoryEntry(
    id: string,
    updates: Partial<InsertMarketplaceSyncHistoryEntry>,
  ): Promise<MarketplaceSyncHistoryEntry | undefined>;

  // Cross-Cutting
  getCrossCuttingEvidenceList(orgId: string, evidenceType?: string, limit?: number): Promise<CrossCuttingEvidence[]>;
  getCrossCuttingEvidenceItem(id: string, orgId: string): Promise<CrossCuttingEvidence | undefined>;
  createCrossCuttingEvidenceItem(data: InsertCrossCuttingEvidence): Promise<CrossCuttingEvidence>;
  updateCrossCuttingEvidenceItem(
    id: string,
    orgId: string,
    updates: Partial<InsertCrossCuttingEvidence>,
  ): Promise<CrossCuttingEvidence | undefined>;
  countCrossCuttingEvidence(orgId: string): Promise<number>;
  getCrossCuttingDriftRecords(orgId: string, driftType?: string, limit?: number): Promise<CrossCuttingDriftRecord[]>;
  getCrossCuttingDriftRecord(id: string, orgId: string): Promise<CrossCuttingDriftRecord | undefined>;
  createCrossCuttingDriftRecord(data: InsertCrossCuttingDriftRecord): Promise<CrossCuttingDriftRecord>;
  updateCrossCuttingDriftRecord(
    id: string,
    orgId: string,
    updates: Partial<InsertCrossCuttingDriftRecord>,
  ): Promise<CrossCuttingDriftRecord | undefined>;
  countCrossCuttingDrift(orgId: string): Promise<number>;
  getCrossCuttingOverrides(orgId: string, overrideType?: string, limit?: number): Promise<CrossCuttingOverride[]>;
  getCrossCuttingOverride(id: string, orgId: string): Promise<CrossCuttingOverride | undefined>;
  createCrossCuttingOverride(data: InsertCrossCuttingOverride): Promise<CrossCuttingOverride>;
  updateCrossCuttingOverride(
    id: string,
    orgId: string,
    updates: Partial<InsertCrossCuttingOverride>,
  ): Promise<CrossCuttingOverride | undefined>;
  deleteCrossCuttingOverride(id: string, orgId: string): Promise<boolean>;
  countCrossCuttingOverrides(orgId: string): Promise<number>;

  // JIT Access
  getJitAccessRequests(orgId: string, limit?: number): Promise<JitAccessRequest[]>;
  getJitAccessRequest(id: string, orgId: string): Promise<JitAccessRequest | undefined>;
  getJitAccessRequestsByRequester(orgId: string, requesterId: string, limit?: number): Promise<JitAccessRequest[]>;
  createJitAccessRequest(data: InsertJitAccessRequest): Promise<JitAccessRequest>;
  updateJitAccessRequest(
    id: string,
    orgId: string,
    updates: Partial<InsertJitAccessRequest>,
  ): Promise<JitAccessRequest | undefined>;
  countJitAccessRequests(orgId: string): Promise<number>;
  countPendingJitAccessRequests(orgId: string): Promise<number>;

  // Adversarial Testing
  getAdversarialExecutions(orgId: string, limit?: number): Promise<AdversarialTestExecution[]>;
  getAdversarialExecution(id: string, orgId: string): Promise<AdversarialTestExecution | undefined>;
  createAdversarialExecution(data: InsertAdversarialTestExecution): Promise<AdversarialTestExecution>;
  updateAdversarialExecution(
    id: string,
    orgId: string,
    updates: Partial<InsertAdversarialTestExecution>,
  ): Promise<AdversarialTestExecution | undefined>;
  countAdversarialExecutions(orgId: string): Promise<number>;
  getAdversarialSchedules(orgId: string): Promise<AdversarialTestSchedule[]>;
  getAdversarialSchedule(id: string, orgId: string): Promise<AdversarialTestSchedule | undefined>;
  createAdversarialSchedule(data: InsertAdversarialTestSchedule): Promise<AdversarialTestSchedule>;
  updateAdversarialSchedule(
    id: string,
    orgId: string,
    updates: Partial<InsertAdversarialTestSchedule>,
  ): Promise<AdversarialTestSchedule | undefined>;
  deleteAdversarialSchedule(id: string, orgId: string): Promise<boolean>;
  getAdversarialRemediations(orgId: string, status?: string): Promise<AdversarialRemediation[]>;
  getAdversarialRemediation(id: string, orgId: string): Promise<AdversarialRemediation | undefined>;
  createAdversarialRemediation(data: InsertAdversarialRemediation): Promise<AdversarialRemediation>;
  updateAdversarialRemediation(
    id: string,
    orgId: string,
    updates: Partial<InsertAdversarialRemediation>,
  ): Promise<AdversarialRemediation | undefined>;

  // Agent Tool Security
  getAgentToolInvocations(orgId: string, limit?: number): Promise<AgentToolInvocation[]>;
  getAgentToolInvocation(id: string, orgId: string): Promise<AgentToolInvocation | undefined>;
  createAgentToolInvocation(data: InsertAgentToolInvocation): Promise<AgentToolInvocation>;
  countAgentToolInvocations(orgId: string): Promise<number>;
  getAgentToolAnomalies(orgId: string, unacknowledgedOnly?: boolean): Promise<AgentToolAnomaly[]>;
  acknowledgeAgentToolAnomaly(id: string, orgId: string, acknowledgedBy: string): Promise<AgentToolAnomaly | undefined>;
  createAgentToolAnomaly(data: InsertAgentToolAnomaly): Promise<AgentToolAnomaly>;
  countAgentToolAnomalies(orgId: string, unacknowledgedOnly?: boolean): Promise<number>;
  getAgentToolPoliciesList(orgId: string): Promise<AgentToolPolicy[]>;
  getAgentToolPolicyByTool(orgId: string, toolId: string): Promise<AgentToolPolicy | undefined>;
  upsertAgentToolPolicy(data: InsertAgentToolPolicy): Promise<AgentToolPolicy>;
  getAgentTrustBoundaryRulesList(orgId: string): Promise<AgentTrustBoundaryRule[]>;
  getAgentTrustBoundaryRule(id: string, orgId: string): Promise<AgentTrustBoundaryRule | undefined>;
  createAgentTrustBoundaryRule(data: InsertAgentTrustBoundaryRule): Promise<AgentTrustBoundaryRule>;
  updateAgentTrustBoundaryRule(
    id: string,
    orgId: string,
    updates: Partial<InsertAgentTrustBoundaryRule>,
  ): Promise<AgentTrustBoundaryRule | undefined>;
  deleteAgentTrustBoundaryRule(id: string, orgId: string): Promise<boolean>;

  // Browser Defense
  getBrowserSessions(orgId: string, state?: string): Promise<BrowserDefenseSession[]>;
  getBrowserSession(id: string, orgId: string): Promise<BrowserDefenseSession | undefined>;
  createBrowserSession(data: InsertBrowserDefenseSession): Promise<BrowserDefenseSession>;
  updateBrowserSession(
    id: string,
    orgId: string,
    updates: Partial<InsertBrowserDefenseSession>,
  ): Promise<BrowserDefenseSession | undefined>;
  countBrowserSessions(orgId: string, state?: string): Promise<number>;
  getBrowserEgressRules(orgId: string): Promise<BrowserEgressRule[]>;
  getBrowserEgressRule(id: string, orgId: string): Promise<BrowserEgressRule | undefined>;
  createBrowserEgressRule(data: InsertBrowserEgressRule): Promise<BrowserEgressRule>;
  updateBrowserEgressRule(
    id: string,
    orgId: string,
    updates: Partial<InsertBrowserEgressRule>,
  ): Promise<BrowserEgressRule | undefined>;
  deleteBrowserEgressRule(id: string, orgId: string): Promise<boolean>;
  getBrowserTrustedPaths(orgId: string): Promise<BrowserTrustedPath[]>;
  getBrowserTrustedPath(id: string, orgId: string): Promise<BrowserTrustedPath | undefined>;
  createBrowserTrustedPath(data: InsertBrowserTrustedPath): Promise<BrowserTrustedPath>;
  updateBrowserTrustedPath(
    id: string,
    orgId: string,
    updates: Partial<InsertBrowserTrustedPath>,
  ): Promise<BrowserTrustedPath | undefined>;
  deleteBrowserTrustedPath(id: string, orgId: string): Promise<boolean>;

  // Runtime Guardrails
  getRuntimePolicies(orgId: string): Promise<RuntimeGuardrailPolicy[]>;
  getRuntimePolicy(id: string, orgId: string): Promise<RuntimeGuardrailPolicy | undefined>;
  createRuntimePolicy(data: InsertRuntimeGuardrailPolicy): Promise<RuntimeGuardrailPolicy>;
  updateRuntimePolicy(
    id: string,
    orgId: string,
    updates: Partial<InsertRuntimeGuardrailPolicy>,
  ): Promise<RuntimeGuardrailPolicy | undefined>;
  deleteRuntimePolicy(id: string, orgId: string): Promise<boolean>;
  countRuntimePolicies(orgId: string): Promise<number>;
  getRuntimeDecisions(orgId: string, limit?: number): Promise<RuntimeGuardrailDecision[]>;
  createRuntimeDecision(data: InsertRuntimeGuardrailDecision): Promise<RuntimeGuardrailDecision>;
  countRuntimeDecisions(orgId: string): Promise<number>;
  getRuntimeOverrides(orgId: string, status?: string): Promise<RuntimeGuardrailOverride[]>;
  getRuntimeOverride(id: string, orgId: string): Promise<RuntimeGuardrailOverride | undefined>;
  createRuntimeOverride(data: InsertRuntimeGuardrailOverride): Promise<RuntimeGuardrailOverride>;
  updateRuntimeOverride(
    id: string,
    orgId: string,
    updates: Partial<InsertRuntimeGuardrailOverride>,
  ): Promise<RuntimeGuardrailOverride | undefined>;
  getRuntimeSimulations(orgId: string, limit?: number): Promise<RuntimeGuardrailSimulation[]>;
  createRuntimeSimulation(data: InsertRuntimeGuardrailSimulation): Promise<RuntimeGuardrailSimulation>;

  // Vulnerability scanner configuration
  getVulnScanTargets(orgId: string): Promise<VulnScanTarget[]>;
  getVulnScanTarget(id: string, orgId: string): Promise<VulnScanTarget | undefined>;
  createVulnScanTarget(data: InsertVulnScanTarget): Promise<VulnScanTarget>;
  getVulnScanSchedules(orgId: string): Promise<VulnScanSchedule[]>;
  getVulnScanSchedule(id: string, orgId: string): Promise<VulnScanSchedule | undefined>;
  createVulnScanSchedule(data: InsertVulnScanSchedule): Promise<VulnScanSchedule>;
}
