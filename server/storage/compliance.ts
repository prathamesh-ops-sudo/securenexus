import {
  type ComplianceControl,
  type ComplianceControlHelper,
  type ComplianceControlMapping,
  type CompliancePolicy,
  type DsarRequest,
  type EvidenceAttachment,
  type EvidenceLockerItem,
  type InsertComplianceControl,
  type InsertComplianceControlHelper,
  type InsertComplianceControlMapping,
  type InsertCompliancePolicy,
  type InsertDsarRequest,
  type InsertEvidenceAttachment,
  type InsertEvidenceLockerItem,
  type InsertLegalHold,
  type InsertPolicyCheck,
  type InsertPolicyResult,
  type LegalHold,
  type PolicyCheck,
  type PolicyResult,
  complianceControlHelpers,
  complianceControlMappings,
  complianceControls,
  compliancePolicies,
  dsarRequests,
  evidenceAttachments,
  evidenceLockerItems,
  legalHolds,
  policyChecks,
  policyResults,
} from "@shared/schema";
import { db } from "../db";
import { and, desc, eq } from "drizzle-orm";

export async function getCompliancePolicy(orgId: string): Promise<CompliancePolicy | undefined> {
  const [policy] = await db.select().from(compliancePolicies).where(eq(compliancePolicies.orgId, orgId));
  return policy;
}

export async function upsertCompliancePolicy(policy: InsertCompliancePolicy): Promise<CompliancePolicy> {
  const [result] = await db
    .insert(compliancePolicies)
    .values(policy)
    .onConflictDoUpdate({
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
    })
    .returning();
  return result;
}

export async function getDsarRequests(orgId: string): Promise<DsarRequest[]> {
  return db.select().from(dsarRequests).where(eq(dsarRequests.orgId, orgId)).orderBy(desc(dsarRequests.createdAt));
}

export async function getDsarRequest(id: string): Promise<DsarRequest | undefined> {
  const [request] = await db.select().from(dsarRequests).where(eq(dsarRequests.id, id));
  return request;
}

export async function createDsarRequest(request: InsertDsarRequest): Promise<DsarRequest> {
  const [created] = await db.insert(dsarRequests).values(request).returning();
  return created;
}

export async function updateDsarRequest(id: string, data: Partial<DsarRequest>): Promise<DsarRequest | undefined> {
  const [updated] = await db
    .update(dsarRequests)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(dsarRequests.id, id))
    .returning();
  return updated;
}

export async function getPolicyChecks(orgId: string): Promise<PolicyCheck[]> {
  return db.select().from(policyChecks).where(eq(policyChecks.orgId, orgId)).orderBy(desc(policyChecks.createdAt));
}

export async function getPolicyCheck(id: string): Promise<PolicyCheck | undefined> {
  const [check] = await db.select().from(policyChecks).where(eq(policyChecks.id, id));
  return check;
}

export async function createPolicyCheck(check: InsertPolicyCheck): Promise<PolicyCheck> {
  const [created] = await db.insert(policyChecks).values(check).returning();
  return created;
}

export async function updatePolicyCheck(id: string, data: Partial<PolicyCheck>): Promise<PolicyCheck | undefined> {
  const [updated] = await db.update(policyChecks).set(data).where(eq(policyChecks.id, id)).returning();
  return updated;
}

export async function deletePolicyCheck(id: string): Promise<boolean> {
  const result = await db.delete(policyChecks).where(eq(policyChecks.id, id)).returning();
  return result.length > 0;
}

export async function getPolicyResults(orgId: string, policyCheckId?: string): Promise<PolicyResult[]> {
  const conditions = [eq(policyResults.orgId, orgId)];
  if (policyCheckId) {
    conditions.push(eq(policyResults.policyCheckId, policyCheckId));
  }
  return db
    .select()
    .from(policyResults)
    .where(and(...conditions))
    .orderBy(desc(policyResults.evaluatedAt));
}

export async function createPolicyResult(result: InsertPolicyResult): Promise<PolicyResult> {
  const [created] = await db.insert(policyResults).values(result).returning();
  return created;
}

export async function deletePolicyResult(id: string): Promise<boolean> {
  const [deleted] = await db.delete(policyResults).where(eq(policyResults.id, id)).returning();
  return !!deleted;
}

export async function getComplianceControls(framework?: string): Promise<ComplianceControl[]> {
  if (framework) {
    return db.select().from(complianceControls).where(eq(complianceControls.framework, framework));
  }
  return db.select().from(complianceControls);
}

export async function getComplianceControl(id: string): Promise<ComplianceControl | undefined> {
  const [control] = await db.select().from(complianceControls).where(eq(complianceControls.id, id));
  return control;
}

export async function createComplianceControl(control: InsertComplianceControl): Promise<ComplianceControl> {
  const [created] = await db.insert(complianceControls).values(control).returning();
  return created;
}

export async function createComplianceControls(controls: InsertComplianceControl[]): Promise<ComplianceControl[]> {
  return db.insert(complianceControls).values(controls).returning();
}

export async function updateComplianceControl(
  id: string,
  data: Partial<ComplianceControl>,
): Promise<ComplianceControl | undefined> {
  const [updated] = await db.update(complianceControls).set(data).where(eq(complianceControls.id, id)).returning();
  return updated;
}

export async function deleteComplianceControl(id: string): Promise<boolean> {
  const [deleted] = await db.delete(complianceControls).where(eq(complianceControls.id, id)).returning();
  return !!deleted;
}

export async function getComplianceControlMappings(
  orgId: string,
  controlId?: string,
): Promise<ComplianceControlMapping[]> {
  const conditions = [eq(complianceControlMappings.orgId, orgId)];
  if (controlId) {
    conditions.push(eq(complianceControlMappings.controlId, controlId));
  }
  return db
    .select()
    .from(complianceControlMappings)
    .where(and(...conditions));
}

export async function createComplianceControlMapping(
  mapping: InsertComplianceControlMapping,
): Promise<ComplianceControlMapping> {
  const [created] = await db.insert(complianceControlMappings).values(mapping).returning();
  return created;
}

export async function updateComplianceControlMapping(
  id: string,
  data: Partial<ComplianceControlMapping>,
): Promise<ComplianceControlMapping | undefined> {
  const [updated] = await db
    .update(complianceControlMappings)
    .set(data)
    .where(eq(complianceControlMappings.id, id))
    .returning();
  return updated;
}

export async function deleteComplianceControlMapping(id: string): Promise<boolean> {
  const result = await db.delete(complianceControlMappings).where(eq(complianceControlMappings.id, id)).returning();
  return result.length > 0;
}

export async function getEvidenceLockerItems(
  orgId: string,
  framework?: string,
  artifactType?: string,
): Promise<EvidenceLockerItem[]> {
  const conditions = [eq(evidenceLockerItems.orgId, orgId)];
  if (framework) {
    conditions.push(eq(evidenceLockerItems.framework, framework));
  }
  if (artifactType) {
    conditions.push(eq(evidenceLockerItems.artifactType, artifactType));
  }
  return db
    .select()
    .from(evidenceLockerItems)
    .where(and(...conditions))
    .orderBy(desc(evidenceLockerItems.createdAt));
}

export async function getEvidenceLockerItem(id: string): Promise<EvidenceLockerItem | undefined> {
  const [item] = await db.select().from(evidenceLockerItems).where(eq(evidenceLockerItems.id, id));
  return item;
}

export async function createEvidenceLockerItem(item: InsertEvidenceLockerItem): Promise<EvidenceLockerItem> {
  const [created] = await db.insert(evidenceLockerItems).values(item).returning();
  return created;
}

export async function updateEvidenceLockerItem(
  id: string,
  data: Partial<EvidenceLockerItem>,
): Promise<EvidenceLockerItem | undefined> {
  const [updated] = await db.update(evidenceLockerItems).set(data).where(eq(evidenceLockerItems.id, id)).returning();
  return updated;
}

export async function deleteEvidenceLockerItem(id: string): Promise<boolean> {
  const result = await db.delete(evidenceLockerItems).where(eq(evidenceLockerItems.id, id)).returning();
  return result.length > 0;
}

export async function getLegalHolds(orgId?: string): Promise<LegalHold[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(legalHolds.orgId, orgId));
  return db
    .select()
    .from(legalHolds)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(legalHolds.createdAt));
}

export async function getLegalHold(id: string): Promise<LegalHold | undefined> {
  const [hold] = await db.select().from(legalHolds).where(eq(legalHolds.id, id));
  return hold;
}

export async function createLegalHold(hold: InsertLegalHold): Promise<LegalHold> {
  const [created] = await db.insert(legalHolds).values(hold).returning();
  return created;
}

export async function updateLegalHold(id: string, data: Partial<LegalHold>): Promise<LegalHold | undefined> {
  const [updated] = await db.update(legalHolds).set(data).where(eq(legalHolds.id, id)).returning();
  return updated;
}

export async function getEvidenceAttachments(orgId: string, controlMappingId?: string): Promise<EvidenceAttachment[]> {
  const conditions = [eq(evidenceAttachments.orgId, orgId)];
  if (controlMappingId) {
    conditions.push(eq(evidenceAttachments.controlMappingId, controlMappingId));
  }
  return db
    .select()
    .from(evidenceAttachments)
    .where(and(...conditions))
    .orderBy(desc(evidenceAttachments.createdAt));
}

export async function getEvidenceAttachment(id: string): Promise<EvidenceAttachment | undefined> {
  const [row] = await db.select().from(evidenceAttachments).where(eq(evidenceAttachments.id, id));
  return row;
}

export async function createEvidenceAttachment(attachment: InsertEvidenceAttachment): Promise<EvidenceAttachment> {
  const [created] = await db.insert(evidenceAttachments).values(attachment).returning();
  return created;
}

export async function updateEvidenceAttachment(
  id: string,
  data: Partial<EvidenceAttachment>,
): Promise<EvidenceAttachment | undefined> {
  const [updated] = await db.update(evidenceAttachments).set(data).where(eq(evidenceAttachments.id, id)).returning();
  return updated;
}

export async function deleteEvidenceAttachment(id: string): Promise<boolean> {
  const result = await db.delete(evidenceAttachments).where(eq(evidenceAttachments.id, id)).returning();
  return result.length > 0;
}

// ==========================================
// Compliance Control Helpers
// ==========================================

export async function getComplianceControlHelpers(
  orgId: string,
  helperType?: string,
): Promise<ComplianceControlHelper[]> {
  const conditions = [eq(complianceControlHelpers.orgId, orgId)];
  if (helperType) {
    conditions.push(eq(complianceControlHelpers.helperType, helperType));
  }
  return db
    .select()
    .from(complianceControlHelpers)
    .where(and(...conditions))
    .orderBy(desc(complianceControlHelpers.createdAt));
}

export async function getComplianceControlHelper(id: string): Promise<ComplianceControlHelper | undefined> {
  const [row] = await db.select().from(complianceControlHelpers).where(eq(complianceControlHelpers.id, id));
  return row;
}

export async function createComplianceControlHelper(
  helper: InsertComplianceControlHelper,
): Promise<ComplianceControlHelper> {
  const [created] = await db.insert(complianceControlHelpers).values(helper).returning();
  return created;
}

export async function updateComplianceControlHelper(
  id: string,
  data: Partial<ComplianceControlHelper>,
): Promise<ComplianceControlHelper | undefined> {
  const [updated] = await db
    .update(complianceControlHelpers)
    .set(data)
    .where(eq(complianceControlHelpers.id, id))
    .returning();
  return updated;
}
