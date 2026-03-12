import { createHash } from "crypto";

// ── Anonymization ─────────────────────────────────────────────────────────────

/** Hash an orgId to create an anonymous contributor identity */
export function anonymizeOrgId(orgId: string): string {
  return createHash("sha256").update(`community-intel:${orgId}`).digest("hex");
}

/** Hash an IOC value for deduplication without exposing raw indicators cross-org */
export function hashIocValue(value: string): string {
  const normalized = value.trim().toLowerCase();
  return createHash("sha256").update(normalized).digest("hex");
}

// ── TLP (Traffic Light Protocol) filtering ────────────────────────────────────

const TLP_ORDER: Record<string, number> = {
  white: 0,
  green: 1,
  amber: 2,
  red: 3,
};

export function isTlpShareable(iocTlp: string, maxTlp: string = "amber"): boolean {
  return (TLP_ORDER[iocTlp] ?? 3) <= (TLP_ORDER[maxTlp] ?? 2);
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function meetsMinSeverity(iocSeverity: string, minSeverity: string): boolean {
  return (SEVERITY_ORDER[iocSeverity] ?? 0) >= (SEVERITY_ORDER[minSeverity] ?? 0);
}

// ── Default community feeds ───────────────────────────────────────────────────

export interface DefaultFeed {
  feedName: string;
  feedType: string;
  industrySector: string | null;
  description: string;
}

export const DEFAULT_FEEDS: DefaultFeed[] = [
  {
    feedName: "Global Threat Feed",
    feedType: "global",
    industrySector: null,
    description:
      "Cross-industry IOC feed aggregated from all participating organizations. Covers IPs, domains, hashes, and URLs observed across the SecureNexus network.",
  },
  {
    feedName: "Healthcare Threat Feed",
    feedType: "industry",
    industrySector: "healthcare",
    description:
      "IOCs targeting healthcare organizations including medical device exploitation, patient data exfiltration, and HIPAA-related threats.",
  },
  {
    feedName: "Financial Services Threat Feed",
    feedType: "industry",
    industrySector: "finance",
    description:
      "Banking trojans, payment fraud indicators, SWIFT attack patterns, and financial sector-targeted APT campaigns.",
  },
  {
    feedName: "Technology Sector Feed",
    feedType: "industry",
    industrySector: "technology",
    description:
      "Supply chain attacks, CI/CD pipeline compromises, cloud credential theft, and SaaS-targeting threat indicators.",
  },
  {
    feedName: "Manufacturing & OT Feed",
    feedType: "industry",
    industrySector: "manufacturing",
    description: "ICS/SCADA-targeted malware, PLC exploitation indicators, and industrial espionage threat actors.",
  },
  {
    feedName: "Energy Sector Feed",
    feedType: "industry",
    industrySector: "energy",
    description:
      "Grid-targeting attacks, pipeline SCADA threats, and nation-state activity targeting energy infrastructure.",
  },
  {
    feedName: "Government & Defense Feed",
    feedType: "industry",
    industrySector: "government",
    description:
      "APT campaigns targeting government networks, espionage indicators, and classified network breach patterns.",
  },
  {
    feedName: "Education Sector Feed",
    feedType: "industry",
    industrySector: "education",
    description:
      "Ransomware targeting educational institutions, student data theft indicators, and research IP exfiltration.",
  },
  {
    feedName: "Retail & E-Commerce Feed",
    feedType: "industry",
    industrySector: "retail",
    description: "Magecart skimmers, POS malware, credential stuffing campaigns, and payment card fraud indicators.",
  },
  {
    feedName: "Telecom Sector Feed",
    feedType: "industry",
    industrySector: "telecom",
    description: "SIM-swapping infrastructure, SS7 exploitation, and telecom-targeted espionage campaigns.",
  },
];

// ── Campaign correlation ──────────────────────────────────────────────────────

export interface CampaignCorrelation {
  campaignName: string;
  threatActorName: string | null;
  iocCount: number;
  affectedOrgCount: number;
  severity: string;
  targetSectors: string[];
}

/**
 * Attempt to correlate IOCs into campaigns by shared tags, threat actor refs,
 * or temporal proximity. This is a simplified heuristic — production would use
 * graph-based clustering.
 */
export function correlateIocsToCampaign(
  iocs: Array<{
    tags: string[];
    threatActorRef: string | null;
    severity: string;
    industrySectors: string[];
    anonymousContributorHash: string;
  }>,
): CampaignCorrelation | null {
  if (iocs.length < 3) return null; // need minimum 3 IOCs for a campaign

  // Find most common threat actor reference
  const actorCounts = new Map<string, number>();
  for (const ioc of iocs) {
    if (ioc.threatActorRef) {
      actorCounts.set(ioc.threatActorRef, (actorCounts.get(ioc.threatActorRef) || 0) + 1);
    }
  }

  let topActor: string | null = null;
  let topActorCount = 0;
  actorCounts.forEach((count, actor) => {
    if (count > topActorCount) {
      topActor = actor;
      topActorCount = count;
    }
  });

  // Find most common tags
  const tagCounts = new Map<string, number>();
  for (const ioc of iocs) {
    const tags = Array.isArray(ioc.tags) ? ioc.tags : [];
    for (const tag of tags) {
      tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1);
    }
  }

  let topTag = "unknown";
  let topTagCount = 0;
  tagCounts.forEach((count, tag) => {
    if (count > topTagCount) {
      topTag = tag;
      topTagCount = count;
    }
  });

  // Count unique contributing orgs
  const uniqueOrgs = new Set<string>();
  for (const ioc of iocs) {
    uniqueOrgs.add(ioc.anonymousContributorHash);
  }

  // Aggregate target sectors
  const sectorSet = new Set<string>();
  for (const ioc of iocs) {
    const sectors = Array.isArray(ioc.industrySectors) ? ioc.industrySectors : [];
    for (const s of sectors) {
      sectorSet.add(s as string);
    }
  }

  // Determine max severity
  let maxSeverity = "low";
  let maxSeverityOrder = 0;
  for (const ioc of iocs) {
    const order = SEVERITY_ORDER[ioc.severity] ?? 0;
    if (order > maxSeverityOrder) {
      maxSeverityOrder = order;
      maxSeverity = ioc.severity;
    }
  }

  const campaignName = topActor
    ? `${topActor} Campaign`
    : `${topTag.charAt(0).toUpperCase() + topTag.slice(1)} Campaign`;

  return {
    campaignName,
    threatActorName: topActor,
    iocCount: iocs.length,
    affectedOrgCount: uniqueOrgs.size,
    severity: maxSeverity,
    targetSectors: Array.from(sectorSet),
  };
}

// ── Network stats computation ─────────────────────────────────────────────────

export interface NetworkStats {
  totalSharedIocs: number;
  activeIocs: number;
  participatingOrgs: number;
  campaignsTracked: number;
  iocsByType: Record<string, number>;
  iocsBySeverity: Record<string, number>;
  topIndustrySectors: Array<{ sector: string; count: number }>;
  avgConfidence: number;
  last24hContributions: number;
  last7dContributions: number;
}

export function computeNetworkStats(
  iocs: Array<{
    iocType: string;
    severity: string;
    confidence: number;
    isActive: boolean;
    industrySectors: unknown;
    createdAt: Date | null;
    anonymousContributorHash: string;
  }>,
  campaignCount: number,
): NetworkStats {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  const iocsByType: Record<string, number> = {};
  const iocsBySeverity: Record<string, number> = {};
  const sectorCounts: Record<string, number> = {};
  const uniqueOrgs = new Set<string>();
  let activeCount = 0;
  let totalConfidence = 0;
  let last24h = 0;
  let last7d = 0;

  for (const ioc of iocs) {
    iocsByType[ioc.iocType] = (iocsByType[ioc.iocType] || 0) + 1;
    iocsBySeverity[ioc.severity] = (iocsBySeverity[ioc.severity] || 0) + 1;
    if (ioc.isActive) activeCount++;
    totalConfidence += ioc.confidence;
    uniqueOrgs.add(ioc.anonymousContributorHash);

    const sectors = Array.isArray(ioc.industrySectors) ? ioc.industrySectors : [];
    for (const s of sectors) {
      sectorCounts[s as string] = (sectorCounts[s as string] || 0) + 1;
    }

    if (ioc.createdAt) {
      const age = now - new Date(ioc.createdAt).getTime();
      if (age <= day) last24h++;
      if (age <= 7 * day) last7d++;
    }
  }

  const topIndustrySectors = Object.entries(sectorCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([sector, count]) => ({ sector, count }));

  return {
    totalSharedIocs: iocs.length,
    activeIocs: activeCount,
    participatingOrgs: uniqueOrgs.size,
    campaignsTracked: campaignCount,
    iocsByType,
    iocsBySeverity,
    topIndustrySectors,
    avgConfidence: iocs.length > 0 ? Math.round(totalConfidence / iocs.length) : 0,
    last24hContributions: last24h,
    last7dContributions: last7d,
  };
}
