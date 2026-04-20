import {
  type InsertMsspAccessGrant,
  type InsertOnboardingProgress,
  type InsertOrgDomainVerification,
  type InsertOrgInvitation,
  type InsertOrgPlanLimit,
  type InsertOrgScimConfig,
  type InsertOrgSecurityPolicy,
  type InsertOrgSsoConfig,
  type InsertOrganization,
  type InsertOrganizationMembership,
  type InsertWizardProgress,
  type InsertWorkspaceTemplate,
  type MsspAccessGrant,
  type OnboardingProgressItem,
  type OrgDomainVerification,
  type OrgInvitation,
  type OrgPlanLimit,
  type OrgScimConfig,
  type OrgSecurityPolicy,
  type OrgSsoConfig,
  type Organization,
  type OrganizationMembership,
  type WizardProgress,
  type WorkspaceTemplate,
  alerts,
  connectors,
  incidents,
  msspAccessGrants,
  onboardingProgress,
  orgDomainVerifications,
  orgInvitations,
  orgPlanLimits,
  orgScimConfigs,
  orgSecurityPolicies,
  orgSsoConfigs,
  organizationMemberships,
  organizations,
  wizardProgress,
  workspaceTemplates,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, inArray, isNull, sql } from "drizzle-orm";

export async function getOrganizations(): Promise<Organization[]> {
  return db.select().from(organizations).orderBy(desc(organizations.createdAt));
}

export async function getOrganization(id: string): Promise<Organization | undefined> {
  const [org] = await db.select().from(organizations).where(eq(organizations.id, id));
  return org;
}

export async function createOrganization(org: InsertOrganization): Promise<Organization> {
  const [created] = await db.insert(organizations).values(org).returning();
  return created;
}

export async function updateOrganization(id: string, data: Partial<Organization>): Promise<Organization | undefined> {
  const [updated] = await db
    .update(organizations)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(organizations.id, id))
    .returning();
  return updated;
}

export async function softDeleteOrganization(id: string): Promise<Organization | undefined> {
  const [updated] = await db
    .update(organizations)
    .set({ deletedAt: new Date(), updatedAt: new Date() })
    .where(eq(organizations.id, id))
    .returning();
  return updated;
}

export async function getOrganizationBySlug(slug: string): Promise<Organization | undefined> {
  const [org] = await db.select().from(organizations).where(eq(organizations.slug, slug));
  return org;
}

export async function getVerifiedAutoJoinDomain(domain: string): Promise<OrgDomainVerification | undefined> {
  const [result] = await db
    .select()
    .from(orgDomainVerifications)
    .where(
      and(
        eq(orgDomainVerifications.domain, domain.toLowerCase()),
        eq(orgDomainVerifications.status, "verified"),
        eq(orgDomainVerifications.autoJoin, true),
      ),
    );
  return result;
}

// Org SCIM Configs

export async function getOrgMemberships(orgId: string): Promise<OrganizationMembership[]> {
  return db
    .select()
    .from(organizationMemberships)
    .where(eq(organizationMemberships.orgId, orgId))
    .orderBy(desc(organizationMemberships.createdAt));
}

export async function getOrgMembership(orgId: string, userId: string): Promise<OrganizationMembership | undefined> {
  const [membership] = await db
    .select()
    .from(organizationMemberships)
    .where(and(eq(organizationMemberships.orgId, orgId), eq(organizationMemberships.userId, userId)));
  return membership;
}

export async function getMembershipById(id: string): Promise<OrganizationMembership | undefined> {
  const [membership] = await db.select().from(organizationMemberships).where(eq(organizationMemberships.id, id));
  return membership;
}

export async function getUserMemberships(userId: string): Promise<OrganizationMembership[]> {
  return db
    .select()
    .from(organizationMemberships)
    .where(eq(organizationMemberships.userId, userId))
    .orderBy(desc(organizationMemberships.createdAt));
}

export async function createOrgMembership(membership: InsertOrganizationMembership): Promise<OrganizationMembership> {
  const [created] = await db.insert(organizationMemberships).values(membership).returning();
  return created;
}

export async function updateOrgMembership(
  id: string,
  data: Partial<OrganizationMembership>,
): Promise<OrganizationMembership | undefined> {
  const [updated] = await db
    .update(organizationMemberships)
    .set(data)
    .where(eq(organizationMemberships.id, id))
    .returning();
  return updated;
}

export async function transferOwnership(currentOwnerMembershipId: string, newOwnerMembershipId: string): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .update(organizationMemberships)
      .set({ role: "admin" })
      .where(eq(organizationMemberships.id, currentOwnerMembershipId));
    await tx
      .update(organizationMemberships)
      .set({ role: "owner" })
      .where(eq(organizationMemberships.id, newOwnerMembershipId));
  });
}

export async function deleteOrgMembership(id: string): Promise<boolean> {
  const result = await db.delete(organizationMemberships).where(eq(organizationMemberships.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getOrgInvitations(orgId: string): Promise<OrgInvitation[]> {
  return db
    .select()
    .from(orgInvitations)
    .where(eq(orgInvitations.orgId, orgId))
    .orderBy(desc(orgInvitations.createdAt));
}

export async function getOrgInvitationByToken(token: string): Promise<OrgInvitation | undefined> {
  const [invitation] = await db.select().from(orgInvitations).where(eq(orgInvitations.token, token));
  return invitation;
}

export async function getPendingInvitationsByEmail(email: string): Promise<OrgInvitation[]> {
  const normalizedEmail = email.toLowerCase();
  return db
    .select()
    .from(orgInvitations)
    .where(and(eq(orgInvitations.email, normalizedEmail), isNull(orgInvitations.acceptedAt)))
    .orderBy(desc(orgInvitations.createdAt));
}

export async function createOrgInvitation(invitation: InsertOrgInvitation): Promise<OrgInvitation> {
  const [created] = await db.insert(orgInvitations).values(invitation).returning();
  return created;
}

export async function updateOrgInvitation(
  id: string,
  data: Partial<OrgInvitation>,
): Promise<OrgInvitation | undefined> {
  const [updated] = await db.update(orgInvitations).set(data).where(eq(orgInvitations.id, id)).returning();
  return updated;
}

export async function deleteOrgInvitation(id: string): Promise<boolean> {
  const result = await db.delete(orgInvitations).where(eq(orgInvitations.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getOrgSecurityPolicy(orgId: string): Promise<OrgSecurityPolicy | undefined> {
  const [policy] = await db.select().from(orgSecurityPolicies).where(eq(orgSecurityPolicies.orgId, orgId));
  return policy;
}

export async function upsertOrgSecurityPolicy(policy: InsertOrgSecurityPolicy): Promise<OrgSecurityPolicy> {
  const existing = await getOrgSecurityPolicy(policy.orgId);
  if (existing) {
    const [updated] = await db
      .update(orgSecurityPolicies)
      .set({ ...policy, updatedAt: new Date() })
      .where(eq(orgSecurityPolicies.orgId, policy.orgId))
      .returning();
    return updated;
  }
  const [created] = await db.insert(orgSecurityPolicies).values(policy).returning();
  return created;
}

export async function getOrgDomainVerifications(orgId: string): Promise<OrgDomainVerification[]> {
  return db
    .select()
    .from(orgDomainVerifications)
    .where(eq(orgDomainVerifications.orgId, orgId))
    .orderBy(desc(orgDomainVerifications.createdAt));
}

export async function getOrgDomainVerification(id: string): Promise<OrgDomainVerification | undefined> {
  const [verification] = await db.select().from(orgDomainVerifications).where(eq(orgDomainVerifications.id, id));
  return verification;
}

export async function createOrgDomainVerification(
  verification: InsertOrgDomainVerification,
): Promise<OrgDomainVerification> {
  const [created] = await db.insert(orgDomainVerifications).values(verification).returning();
  return created;
}

export async function updateOrgDomainVerification(
  id: string,
  data: Partial<OrgDomainVerification>,
): Promise<OrgDomainVerification | undefined> {
  const [updated] = await db
    .update(orgDomainVerifications)
    .set(data)
    .where(eq(orgDomainVerifications.id, id))
    .returning();
  return updated;
}

export async function deleteOrgDomainVerification(id: string): Promise<boolean> {
  const result = await db.delete(orgDomainVerifications).where(eq(orgDomainVerifications.id, id)).returning();
  return result.length > 0;
}

// Org SSO Configs

export async function getOrgSsoConfig(orgId: string): Promise<OrgSsoConfig | undefined> {
  const [config] = await db.select().from(orgSsoConfigs).where(eq(orgSsoConfigs.orgId, orgId));
  return config;
}

export async function upsertOrgSsoConfig(config: InsertOrgSsoConfig): Promise<OrgSsoConfig> {
  const existing = await getOrgSsoConfig(config.orgId);
  if (existing) {
    const [updated] = await db
      .update(orgSsoConfigs)
      .set({ ...config, updatedAt: new Date() })
      .where(eq(orgSsoConfigs.orgId, config.orgId))
      .returning();
    return updated;
  }
  const [created] = await db.insert(orgSsoConfigs).values(config).returning();
  return created;
}

export async function deleteOrgSsoConfig(orgId: string): Promise<boolean> {
  const result = await db.delete(orgSsoConfigs).where(eq(orgSsoConfigs.orgId, orgId)).returning();
  return result.length > 0;
}

export async function getOrgScimConfig(orgId: string): Promise<OrgScimConfig | undefined> {
  const [config] = await db.select().from(orgScimConfigs).where(eq(orgScimConfigs.orgId, orgId));
  return config;
}

export async function upsertOrgScimConfig(config: InsertOrgScimConfig): Promise<OrgScimConfig> {
  const existing = await getOrgScimConfig(config.orgId);
  if (existing) {
    const [updated] = await db
      .update(orgScimConfigs)
      .set({ ...config, updatedAt: new Date() })
      .where(eq(orgScimConfigs.orgId, config.orgId))
      .returning();
    return updated;
  }
  const [created] = await db.insert(orgScimConfigs).values(config).returning();
  return created;
}

export async function deleteOrgScimConfig(orgId: string): Promise<boolean> {
  const result = await db.delete(orgScimConfigs).where(eq(orgScimConfigs.orgId, orgId)).returning();
  return result.length > 0;
}

// ==========================================
// Evidence Chain Entries
// ==========================================

export async function getOrgPlanLimit(orgId: string): Promise<OrgPlanLimit | undefined> {
  const [plan] = await db.select().from(orgPlanLimits).where(eq(orgPlanLimits.orgId, orgId));
  return plan;
}

export async function upsertOrgPlanLimit(data: InsertOrgPlanLimit): Promise<OrgPlanLimit> {
  const [result] = await db
    .insert(orgPlanLimits)
    .values(data)
    .onConflictDoUpdate({
      target: [orgPlanLimits.orgId],
      set: { ...data, updatedAt: new Date() },
    })
    .returning();
  return result;
}

export async function updateOrgPlanLimit(
  orgId: string,
  data: Partial<OrgPlanLimit>,
): Promise<OrgPlanLimit | undefined> {
  const [updated] = await db
    .update(orgPlanLimits)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(orgPlanLimits.orgId, orgId))
    .returning();
  return updated;
}

export async function getOnboardingProgress(orgId: string): Promise<OnboardingProgressItem[]> {
  return db
    .select()
    .from(onboardingProgress)
    .where(eq(onboardingProgress.orgId, orgId))
    .orderBy(asc(onboardingProgress.sortOrder));
}

export async function upsertOnboardingStep(data: InsertOnboardingProgress): Promise<OnboardingProgressItem> {
  const [result] = await db
    .insert(onboardingProgress)
    .values(data)
    .onConflictDoUpdate({
      target: [onboardingProgress.orgId, onboardingProgress.stepKey],
      set: {
        stepLabel: data.stepLabel,
        stepDescription: data.stepDescription,
        targetUrl: data.targetUrl,
        sortOrder: data.sortOrder,
      },
    })
    .returning();
  return result;
}

export async function completeOnboardingStep(
  orgId: string,
  stepKey: string,
  completedBy?: string,
): Promise<OnboardingProgressItem | undefined> {
  const [updated] = await db
    .update(onboardingProgress)
    .set({ isCompleted: true, completedAt: new Date(), completedBy: completedBy || null })
    .where(and(eq(onboardingProgress.orgId, orgId), eq(onboardingProgress.stepKey, stepKey)))
    .returning();
  return updated;
}

export async function getWorkspaceTemplates(): Promise<WorkspaceTemplate[]> {
  return db.select().from(workspaceTemplates).orderBy(asc(workspaceTemplates.name));
}

export async function getWorkspaceTemplate(id: string): Promise<WorkspaceTemplate | undefined> {
  const [template] = await db.select().from(workspaceTemplates).where(eq(workspaceTemplates.id, id));
  return template;
}

export async function createWorkspaceTemplate(template: InsertWorkspaceTemplate): Promise<WorkspaceTemplate> {
  const [created] = await db.insert(workspaceTemplates).values(template).returning();
  return created;
}

// ============================
// Outbox Events
// ============================

export async function getWizardProgress(userId: string): Promise<WizardProgress | undefined> {
  const [row] = await db.select().from(wizardProgress).where(eq(wizardProgress.userId, userId));
  return row;
}

export async function upsertWizardProgress(data: InsertWizardProgress): Promise<WizardProgress> {
  const [result] = await db
    .insert(wizardProgress)
    .values(data)
    .onConflictDoUpdate({
      target: [wizardProgress.userId],
      set: {
        orgId: data.orgId,
        currentStep: data.currentStep,
        completedSteps: data.completedSteps,
        skippedSteps: data.skippedSteps,
        updatedAt: new Date(),
      },
    })
    .returning();
  return result;
}

export async function updateWizardProgress(
  userId: string,
  data: Partial<WizardProgress>,
): Promise<WizardProgress | undefined> {
  const [updated] = await db
    .update(wizardProgress)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(wizardProgress.userId, userId))
    .returning();
  return updated;
}

export async function getChildOrganizations(parentOrgId: string): Promise<Organization[]> {
  return db
    .select()
    .from(organizations)
    .where(and(eq(organizations.parentOrgId, parentOrgId), isNull(organizations.deletedAt)))
    .orderBy(asc(organizations.name));
}

export async function createMsspAccessGrant(grant: InsertMsspAccessGrant): Promise<MsspAccessGrant> {
  const [created] = await db.insert(msspAccessGrants).values(grant).returning();
  return created;
}

export async function getMsspAccessGrants(parentOrgId: string): Promise<MsspAccessGrant[]> {
  return db
    .select()
    .from(msspAccessGrants)
    .where(and(eq(msspAccessGrants.parentOrgId, parentOrgId), isNull(msspAccessGrants.revokedAt)))
    .orderBy(desc(msspAccessGrants.grantedAt));
}

export async function getMsspAccessGrant(id: string): Promise<MsspAccessGrant | undefined> {
  const [grant] = await db.select().from(msspAccessGrants).where(eq(msspAccessGrants.id, id));
  return grant;
}

export async function revokeMsspAccessGrant(id: string, revokedBy: string): Promise<MsspAccessGrant | undefined> {
  const [updated] = await db
    .update(msspAccessGrants)
    .set({ revokedAt: new Date(), revokedBy, updatedAt: new Date() })
    .where(eq(msspAccessGrants.id, id))
    .returning();
  return updated;
}

export async function getMsspAggregatedStats(childOrgIds: string[]): Promise<{
  totalAlerts: number;
  criticalAlerts: number;
  openIncidents: number;
  totalConnectors: number;
  perOrg: { orgId: string; orgName: string; alertCount: number; incidentCount: number; connectorCount: number }[];
}> {
  if (childOrgIds.length === 0) {
    return { totalAlerts: 0, criticalAlerts: 0, openIncidents: 0, totalConnectors: 0, perOrg: [] };
  }

  const [alertTotals] = await db.select({ total: count() }).from(alerts).where(inArray(alerts.orgId, childOrgIds));

  const [criticalTotals] = await db
    .select({ total: count() })
    .from(alerts)
    .where(and(inArray(alerts.orgId, childOrgIds), eq(alerts.severity, "critical")));

  const [incidentTotals] = await db
    .select({ total: count() })
    .from(incidents)
    .where(and(inArray(incidents.orgId, childOrgIds), eq(incidents.status, "open")));

  const [connectorTotals] = await db
    .select({ total: count() })
    .from(connectors)
    .where(inArray(connectors.orgId, childOrgIds));

  const perOrgAlerts = await db
    .select({ orgId: alerts.orgId, total: count() })
    .from(alerts)
    .where(inArray(alerts.orgId, childOrgIds))
    .groupBy(alerts.orgId);

  const perOrgIncidents = await db
    .select({ orgId: incidents.orgId, total: count() })
    .from(incidents)
    .where(and(inArray(incidents.orgId, childOrgIds), eq(incidents.status, "open")))
    .groupBy(incidents.orgId);

  const perOrgConnectors = await db
    .select({ orgId: connectors.orgId, total: count() })
    .from(connectors)
    .where(inArray(connectors.orgId, childOrgIds))
    .groupBy(connectors.orgId);

  const childOrgs = await db
    .select({ id: organizations.id, name: organizations.name })
    .from(organizations)
    .where(inArray(organizations.id, childOrgIds));

  const alertMap = new Map(perOrgAlerts.map((r) => [r.orgId, r.total]));
  const incidentMap = new Map(perOrgIncidents.map((r) => [r.orgId, r.total]));
  const connectorMap = new Map(perOrgConnectors.map((r) => [r.orgId, r.total]));

  const perOrg = childOrgs.map((org) => ({
    orgId: org.id,
    orgName: org.name,
    alertCount: alertMap.get(org.id) ?? 0,
    incidentCount: incidentMap.get(org.id) ?? 0,
    connectorCount: connectorMap.get(org.id) ?? 0,
  }));

  return {
    totalAlerts: alertTotals.total,
    criticalAlerts: criticalTotals.total,
    openIncidents: incidentTotals.total,
    totalConnectors: connectorTotals.total,
    perOrg,
  };
}

export async function countUserActiveSessions(userId: string): Promise<number> {
  const result = await db.execute(
    sql`SELECT COUNT(*) as count FROM sessions WHERE sess#>>'{passport,user}' = ${userId} AND expire > NOW()`,
  );
  const rows = (result as any).rows ?? result;
  const row = Array.isArray(rows) ? rows[0] : undefined;
  return parseInt(String(row?.count ?? "0"), 10);
}

export async function evictOldestUserSessions(userId: string, count: number): Promise<number> {
  const result = await db.execute(
    sql`DELETE FROM sessions WHERE sid IN (
      SELECT sid FROM sessions
      WHERE sess#>>'{passport,user}' = ${userId} AND expire > NOW()
      ORDER BY expire ASC
      LIMIT ${count}
    )`,
  );
  const rowCount = (result as any).rowCount;
  if (typeof rowCount === "number") return rowCount;
  const rows = (result as any).rows;
  return Array.isArray(rows) ? rows.length : 0;
}

// Org Domain Verifications
