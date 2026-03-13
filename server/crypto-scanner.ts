/**
 * Cryptographic Scanner Engine
 * Discovers weak and quantum-vulnerable cryptographic algorithms across the environment.
 * Provides risk scoring, PQC migration recommendations, and algorithm agility assessment.
 */

import { db } from "./db";
import { cryptoInventory, quantumRiskScores, quantumScanHistory } from "../shared/schema";
import { eq, and, sql, count } from "drizzle-orm";
import { logger } from "./routes/shared";

const log = logger.child("crypto-scanner");

// ============================================================================
// Algorithm vulnerability database
// ============================================================================

interface AlgorithmProfile {
  isQuantumVulnerable: boolean;
  quantumRiskLevel: "critical" | "high" | "medium" | "low" | "safe";
  pqcReplacement: string | null;
  nistStandard: string | null;
  /** Estimated years until quantum threat is viable */
  threatHorizonYears: number;
  notes: string;
}

const ALGORITHM_PROFILES: Record<string, AlgorithmProfile> = {
  // Asymmetric — broken by Shor's algorithm
  "RSA-1024": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "critical",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 3,
    notes: "Already weak by classical standards; quantum computers will trivially break. Immediate migration required.",
  },
  "RSA-2048": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "critical",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 5,
    notes:
      "Standard RSA key size. Shor's algorithm will break with ~4000 logical qubits. Plan migration within 2-3 years.",
  },
  "RSA-3072": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 5,
    notes: "Stronger RSA but still fully vulnerable to quantum attack. No classical advantage against Shor's.",
  },
  "RSA-4096": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 7,
    notes:
      "Largest common RSA key size. Still broken by Shor's algorithm; larger key only marginally delays quantum attack.",
  },
  "ECDSA-P256": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "critical",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 5,
    notes: "Elliptic curve signatures broken by Shor's. Requires fewer qubits to break than RSA.",
  },
  "ECDSA-P384": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 5,
    notes: "Larger EC curve but equally vulnerable to quantum attack via Shor's algorithm.",
  },
  "ECDSA-P521": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 7,
    notes: "Largest standard EC curve. Still fundamentally broken by quantum computing.",
  },
  "ECDH-P256": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "critical",
    pqcReplacement: "CRYSTALS-Kyber (ML-KEM)",
    nistStandard: "FIPS-203",
    threatHorizonYears: 5,
    notes: "EC key exchange. Broken by quantum attack; harvest-now-decrypt-later threat is immediate.",
  },
  "ECDH-P384": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Kyber (ML-KEM)",
    nistStandard: "FIPS-203",
    threatHorizonYears: 5,
    notes: "EC key exchange. Same quantum vulnerability as P256.",
  },
  Ed25519: {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 5,
    notes: "Modern EdDSA signature scheme. Fast and secure classically, but broken by quantum.",
  },
  "DH-2048": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "critical",
    pqcReplacement: "CRYSTALS-Kyber (ML-KEM)",
    nistStandard: "FIPS-203",
    threatHorizonYears: 3,
    notes: "Diffie-Hellman key exchange. Broken by Shor's algorithm. Legacy protocol, replace immediately.",
  },
  "DH-4096": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Kyber (ML-KEM)",
    nistStandard: "FIPS-203",
    threatHorizonYears: 5,
    notes: "Larger DH parameters. Still fully vulnerable to quantum attack.",
  },
  "DSA-1024": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "critical",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 3,
    notes: "Legacy digital signature algorithm. Weak classically and quantum-vulnerable. Replace immediately.",
  },
  "DSA-2048": {
    isQuantumVulnerable: true,
    quantumRiskLevel: "high",
    pqcReplacement: "CRYSTALS-Dilithium (ML-DSA)",
    nistStandard: "FIPS-204",
    threatHorizonYears: 5,
    notes: "DSA with larger key. Still broken by quantum computing.",
  },
  // Symmetric — Grover's halves key strength
  "AES-128": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "medium",
    pqcReplacement: "AES-256",
    nistStandard: null,
    threatHorizonYears: 10,
    notes: "Grover's algorithm effectively halves key strength to 64-bit. Upgrade to AES-256 for quantum safety.",
  },
  "AES-256": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "Quantum-safe. Grover's reduces effective strength to 128-bit, which remains secure.",
  },
  "3DES": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "critical",
    pqcReplacement: "AES-256",
    nistStandard: null,
    threatHorizonYears: 0,
    notes: "Already deprecated. 112-bit effective strength halved to 56-bit by Grover's. Replace immediately.",
  },
  "ChaCha20-Poly1305": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "256-bit symmetric cipher. Quantum-safe with 128-bit post-quantum security level.",
  },
  // Hash functions — Grover's halves collision resistance
  "SHA-1": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "critical",
    pqcReplacement: "SHA-256 or SHA-384",
    nistStandard: null,
    threatHorizonYears: 0,
    notes: "Already broken classically. Must replace regardless of quantum threat.",
  },
  "SHA-256": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "Quantum-safe for most use cases. Grover's reduces to 128-bit preimage resistance.",
  },
  "SHA-384": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "Quantum-safe. 192-bit post-quantum preimage resistance.",
  },
  "SHA-512": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "Quantum-safe. 256-bit post-quantum preimage resistance.",
  },
  MD5: {
    isQuantumVulnerable: false,
    quantumRiskLevel: "critical",
    pqcReplacement: "SHA-256",
    nistStandard: null,
    threatHorizonYears: 0,
    notes: "Broken classically. Must replace immediately regardless of quantum threat.",
  },
  "HMAC-SHA256": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "Quantum-safe MAC. 128-bit post-quantum security.",
  },
  // Post-Quantum Algorithms — already safe
  "CRYSTALS-Kyber": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: "FIPS-203",
    threatHorizonYears: 30,
    notes: "NIST standardized post-quantum KEM (ML-KEM). Lattice-based key encapsulation.",
  },
  "CRYSTALS-Dilithium": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: "FIPS-204",
    threatHorizonYears: 30,
    notes: "NIST standardized post-quantum signature (ML-DSA). Lattice-based digital signature.",
  },
  FALCON: {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: "FIPS-206",
    threatHorizonYears: 30,
    notes: "NIST standardized post-quantum signature (FN-DSA). Compact lattice-based signatures.",
  },
  "SPHINCS+": {
    isQuantumVulnerable: false,
    quantumRiskLevel: "safe",
    pqcReplacement: null,
    nistStandard: "FIPS-205",
    threatHorizonYears: 30,
    notes: "NIST standardized post-quantum signature (SLH-DSA). Hash-based, conservative security.",
  },
  BIKE: {
    isQuantumVulnerable: false,
    quantumRiskLevel: "low",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "NIST Round 4 candidate. Code-based KEM with compact keys.",
  },
  HQC: {
    isQuantumVulnerable: false,
    quantumRiskLevel: "low",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 30,
    notes: "NIST Round 4 candidate. Code-based KEM with provable security reduction.",
  },
};

/**
 * Look up the profile for an algorithm string, with fuzzy matching.
 */
export function getAlgorithmProfile(algorithm: string): AlgorithmProfile {
  // Exact match
  if (ALGORITHM_PROFILES[algorithm]) return ALGORITHM_PROFILES[algorithm];

  // Fuzzy match
  const upper = algorithm.toUpperCase();
  for (const [key, profile] of Object.entries(ALGORITHM_PROFILES)) {
    if (upper.includes(key.toUpperCase())) return profile;
  }

  // Default: unknown algorithm assumed medium risk
  return {
    isQuantumVulnerable: false,
    quantumRiskLevel: "medium",
    pqcReplacement: null,
    nistStandard: null,
    threatHorizonYears: 10,
    notes: "Unknown algorithm. Manual assessment required.",
  };
}

/**
 * Calculate migration priority based on algorithm risk and asset context.
 */
export function calculateMigrationPriority(profile: AlgorithmProfile, source: string): number {
  let priority = 50;

  // Risk level scoring
  const riskScores: Record<string, number> = {
    critical: 30,
    high: 20,
    medium: 0,
    low: -10,
    safe: -30,
  };
  priority += riskScores[profile.quantumRiskLevel] || 0;

  // Source criticality
  const sourceScores: Record<string, number> = {
    tls_certificate: 15,
    vpn_tunnel: 15,
    key_exchange: 15,
    ipsec: 12,
    jwt_signing: 10,
    code_signing: 10,
    ssh_key: 8,
    api_key: 5,
    database_encryption: 5,
    email_signing: 3,
    disk_encryption: 3,
    file_encryption: 2,
    password_hashing: 0,
    configuration: 0,
    library: 0,
    manual_entry: 0,
  };
  priority += sourceScores[source] || 0;

  // Harvest-now-decrypt-later bump for key exchange
  if (["key_exchange", "vpn_tunnel", "ipsec", "tls_certificate"].includes(source) && profile.isQuantumVulnerable) {
    priority += 10;
  }

  return Math.max(1, Math.min(100, priority));
}

/**
 * Compute the quantum risk score for an organization based on its crypto inventory.
 */
export async function computeQuantumRiskScore(orgId: string): Promise<{
  overallScore: number;
  cryptoAgility: number;
  algorithmDiversity: number;
  pqcReadiness: number;
  complianceScore: number;
  totalAssets: number;
  vulnerableAssets: number;
  migratedAssets: number;
  criticalRiskCount: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  estimatedMigrationMonths: number;
}> {
  const assets = await db.select().from(cryptoInventory).where(eq(cryptoInventory.orgId, orgId));

  const totalAssets = assets.length;

  if (totalAssets === 0) {
    return {
      overallScore: 0,
      cryptoAgility: 0,
      algorithmDiversity: 0,
      pqcReadiness: 0,
      complianceScore: 0,
      totalAssets: 0,
      vulnerableAssets: 0,
      migratedAssets: 0,
      criticalRiskCount: 0,
      highRiskCount: 0,
      mediumRiskCount: 0,
      lowRiskCount: 0,
      estimatedMigrationMonths: 0,
    };
  }

  let vulnerableAssets = 0;
  let migratedAssets = 0;
  let criticalRiskCount = 0;
  let highRiskCount = 0;
  let mediumRiskCount = 0;
  let lowRiskCount = 0;
  let hardcodedCount = 0;
  let upgradableCount = 0;
  const uniqueAlgorithms = new Set<string>();
  const pqcAssets = new Set<string>();

  for (const asset of assets) {
    uniqueAlgorithms.add(asset.algorithm);

    if (asset.isQuantumVulnerable) vulnerableAssets++;
    if (asset.migrationStatus === "migrated" || asset.migrationStatus === "verified") migratedAssets++;
    if (asset.isHardcoded) hardcodedCount++;
    if (asset.canBeUpgraded) upgradableCount++;

    const profile = getAlgorithmProfile(asset.algorithm);
    if (profile.quantumRiskLevel === "safe" || profile.nistStandard) {
      pqcAssets.add(asset.id);
    }

    switch (asset.quantumRiskLevel) {
      case "critical":
        criticalRiskCount++;
        break;
      case "high":
        highRiskCount++;
        break;
      case "medium":
        mediumRiskCount++;
        break;
      case "low":
        lowRiskCount++;
        break;
    }
  }

  // Crypto agility: % of assets that can be upgraded (not hardcoded)
  const cryptoAgility = totalAssets > 0 ? Math.round((upgradableCount / totalAssets) * 100) : 0;

  // Algorithm diversity: having variety is good for resilience
  const algorithmDiversity = Math.min(100, Math.round((uniqueAlgorithms.size / Math.max(totalAssets, 1)) * 100 * 2));

  // PQC readiness: % of assets already using PQC or quantum-safe algorithms
  const pqcReadiness = totalAssets > 0 ? Math.round((pqcAssets.size / totalAssets) * 100) : 0;

  // Compliance score: based on NIST PQC standard coverage
  const nistCoveredAssets = assets.filter((a) => {
    const p = getAlgorithmProfile(a.algorithm);
    return p.nistStandard !== null;
  }).length;
  const complianceScore = totalAssets > 0 ? Math.round((nistCoveredAssets / totalAssets) * 100) : 0;

  // Overall score: weighted average (higher = safer)
  const safeAssetRatio = totalAssets > 0 ? (totalAssets - vulnerableAssets) / totalAssets : 0;
  const migrationRatio = vulnerableAssets > 0 ? migratedAssets / vulnerableAssets : 1;
  const overallScore = Math.round(
    safeAssetRatio * 40 +
      migrationRatio * 25 +
      (cryptoAgility / 100) * 15 +
      (pqcReadiness / 100) * 10 +
      (complianceScore / 100) * 10,
  );

  // Estimate migration time: ~2 weeks per critical, 1 week per high, 3 days per medium
  const estimatedDays = criticalRiskCount * 14 + highRiskCount * 7 + mediumRiskCount * 3;
  const estimatedMigrationMonths = Math.max(1, Math.ceil(estimatedDays / 30));

  return {
    overallScore: Math.min(100, overallScore),
    cryptoAgility,
    algorithmDiversity,
    pqcReadiness,
    complianceScore,
    totalAssets,
    vulnerableAssets,
    migratedAssets,
    criticalRiskCount,
    highRiskCount,
    mediumRiskCount,
    lowRiskCount,
    estimatedMigrationMonths,
  };
}

/**
 * Persist a quantum risk score snapshot.
 */
export async function persistRiskScore(orgId: string): Promise<void> {
  try {
    const score = await computeQuantumRiskScore(orgId);

    await db.insert(quantumRiskScores).values({
      orgId,
      ...score,
      scoredAt: new Date(),
    });

    log.info("Quantum risk score persisted", { orgId, overallScore: score.overallScore });
  } catch (err) {
    log.error("Failed to persist quantum risk score", { orgId, error: String(err) });
  }
}

/**
 * Auto-enrich a crypto inventory item with vulnerability data from the algorithm profile DB.
 */
export function enrichCryptoAsset(asset: { algorithm: string; source: string }): {
  isQuantumVulnerable: boolean;
  quantumRiskLevel: string;
  pqcReplacement: string | null;
  migrationPriority: number;
  canBeUpgraded: boolean;
} {
  const profile = getAlgorithmProfile(asset.algorithm);
  const migrationPriority = calculateMigrationPriority(profile, asset.source);

  return {
    isQuantumVulnerable: profile.isQuantumVulnerable,
    quantumRiskLevel: profile.quantumRiskLevel,
    pqcReplacement: profile.pqcReplacement,
    migrationPriority,
    canBeUpgraded: profile.quantumRiskLevel !== "safe",
  };
}

/**
 * Generate a migration roadmap for all vulnerable assets in an org.
 */
export async function generateMigrationRoadmap(orgId: string): Promise<
  Array<{
    phase: number;
    phaseName: string;
    description: string;
    assets: Array<{ id: string; assetName: string; algorithm: string; replacement: string; priority: number }>;
    estimatedWeeks: number;
  }>
> {
  const assets = await db
    .select()
    .from(cryptoInventory)
    .where(and(eq(cryptoInventory.orgId, orgId), eq(cryptoInventory.isQuantumVulnerable, true)));

  // Sort by migration priority (highest first)
  const sorted = assets.sort((a, b) => b.migrationPriority - a.migrationPriority);

  const phases: Array<{
    phase: number;
    phaseName: string;
    description: string;
    assets: Array<{ id: string; assetName: string; algorithm: string; replacement: string; priority: number }>;
    estimatedWeeks: number;
  }> = [];

  // Phase 1: Critical (priority 80-100) — harvest-now-decrypt-later targets
  const critical = sorted.filter((a) => a.migrationPriority >= 80);
  if (critical.length > 0) {
    phases.push({
      phase: 1,
      phaseName: "Immediate — Harvest-Now-Decrypt-Later Defense",
      description:
        "Migrate key exchange and TLS endpoints to hybrid PQC. These are actively at risk from adversaries recording encrypted traffic for future quantum decryption.",
      assets: critical.map((a) => ({
        id: a.id,
        assetName: a.assetName,
        algorithm: a.algorithm,
        replacement: a.pqcReplacement || "CRYSTALS-Kyber (ML-KEM)",
        priority: a.migrationPriority,
      })),
      estimatedWeeks: Math.max(2, critical.length * 2),
    });
  }

  // Phase 2: High (priority 60-79) — signatures and authentication
  const high = sorted.filter((a) => a.migrationPriority >= 60 && a.migrationPriority < 80);
  if (high.length > 0) {
    phases.push({
      phase: 2,
      phaseName: "Short-term — Signature & Authentication Migration",
      description:
        "Replace RSA/ECDSA signing keys with CRYSTALS-Dilithium. Covers code signing, API authentication, and certificate infrastructure.",
      assets: high.map((a) => ({
        id: a.id,
        assetName: a.assetName,
        algorithm: a.algorithm,
        replacement: a.pqcReplacement || "CRYSTALS-Dilithium (ML-DSA)",
        priority: a.migrationPriority,
      })),
      estimatedWeeks: Math.max(4, high.length * 1),
    });
  }

  // Phase 3: Medium (priority 40-59) — internal systems
  const medium = sorted.filter((a) => a.migrationPriority >= 40 && a.migrationPriority < 60);
  if (medium.length > 0) {
    phases.push({
      phase: 3,
      phaseName: "Medium-term — Internal Systems Upgrade",
      description:
        "Upgrade internal SSH keys, database encryption, and remaining legacy cryptographic implementations.",
      assets: medium.map((a) => ({
        id: a.id,
        assetName: a.assetName,
        algorithm: a.algorithm,
        replacement: a.pqcReplacement || "AES-256 / ML-DSA",
        priority: a.migrationPriority,
      })),
      estimatedWeeks: Math.max(4, medium.length),
    });
  }

  // Phase 4: Low (priority < 40) — cleanup
  const low = sorted.filter((a) => a.migrationPriority < 40);
  if (low.length > 0) {
    phases.push({
      phase: 4,
      phaseName: "Long-term — Legacy Cleanup & Verification",
      description:
        "Address remaining low-priority items. Verify all migrations, run PQC interop testing, and update compliance documentation.",
      assets: low.map((a) => ({
        id: a.id,
        assetName: a.assetName,
        algorithm: a.algorithm,
        replacement: a.pqcReplacement || "Review required",
        priority: a.migrationPriority,
      })),
      estimatedWeeks: Math.max(2, Math.ceil(low.length / 2)),
    });
  }

  return phases;
}

/**
 * Assess algorithm agility for all crypto assets in an org.
 * Returns a breakdown of hardcoded vs. configurable algorithms.
 */
export async function assessAlgorithmAgility(orgId: string): Promise<{
  totalAssets: number;
  hardcodedCount: number;
  configurableCount: number;
  agilityScore: number;
  hardcodedAssets: Array<{ id: string; assetName: string; algorithm: string; source: string; filePath: string | null }>;
  recommendations: string[];
}> {
  const assets = await db.select().from(cryptoInventory).where(eq(cryptoInventory.orgId, orgId));

  const hardcodedAssets = assets.filter((a) => a.isHardcoded);
  const configurableCount = assets.length - hardcodedAssets.length;
  const agilityScore = assets.length > 0 ? Math.round((configurableCount / assets.length) * 100) : 0;

  const recommendations: string[] = [];

  if (hardcodedAssets.length > 0) {
    recommendations.push(
      `${hardcodedAssets.length} cryptographic asset(s) use hardcoded algorithms that cannot be upgraded without code changes.`,
    );
  }

  const legacyAlgos = assets.filter((a) => ["3DES", "MD5", "SHA-1", "DSA-1024", "RSA-1024"].includes(a.algorithm));
  if (legacyAlgos.length > 0) {
    recommendations.push(
      `${legacyAlgos.length} asset(s) use deprecated algorithms (3DES, MD5, SHA-1, DSA-1024, RSA-1024). These should be replaced immediately regardless of quantum readiness.`,
    );
  }

  const noUpgradePath = assets.filter((a) => !a.canBeUpgraded && a.isQuantumVulnerable);
  if (noUpgradePath.length > 0) {
    recommendations.push(
      `${noUpgradePath.length} quantum-vulnerable asset(s) cannot be upgraded. Consider replacing the underlying system or service.`,
    );
  }

  if (agilityScore >= 90) {
    recommendations.push(
      "Excellent crypto agility. Most algorithms are configurable and can be swapped to PQC without code changes.",
    );
  } else if (agilityScore >= 70) {
    recommendations.push(
      "Good crypto agility. Focus on decoupling the remaining hardcoded algorithms from application code.",
    );
  } else if (agilityScore >= 50) {
    recommendations.push(
      "Moderate crypto agility. Significant refactoring needed to make cryptographic choices configurable.",
    );
  } else {
    recommendations.push(
      "Poor crypto agility. Most algorithms are hardcoded. Adopt a crypto abstraction layer to enable rapid migration.",
    );
  }

  return {
    totalAssets: assets.length,
    hardcodedCount: hardcodedAssets.length,
    configurableCount,
    agilityScore,
    hardcodedAssets: hardcodedAssets.map((a) => ({
      id: a.id,
      assetName: a.assetName,
      algorithm: a.algorithm,
      source: a.source,
      filePath: a.filePath,
    })),
    recommendations,
  };
}

/**
 * Get NIST PQC compliance status for an org.
 */
export async function getNistPqcCompliance(orgId: string): Promise<
  Record<
    string,
    {
      standard: string;
      name: string;
      description: string;
      status: "not_started" | "in_progress" | "compliant";
      progress: number;
      relevantAssets: number;
      migratedAssets: number;
    }
  >
> {
  const assets = await db.select().from(cryptoInventory).where(eq(cryptoInventory.orgId, orgId));

  const standards: Record<
    string,
    {
      standard: string;
      name: string;
      description: string;
      relevantAlgos: string[];
      pqcAlgo: string;
    }
  > = {
    "FIPS-203": {
      standard: "FIPS-203",
      name: "ML-KEM (CRYSTALS-Kyber)",
      description: "Module-Lattice-Based Key-Encapsulation Mechanism. Replaces RSA/ECDH key exchange.",
      relevantAlgos: ["RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096", "ECDH-P256", "ECDH-P384", "DH-2048", "DH-4096"],
      pqcAlgo: "CRYSTALS-Kyber",
    },
    "FIPS-204": {
      standard: "FIPS-204",
      name: "ML-DSA (CRYSTALS-Dilithium)",
      description: "Module-Lattice-Based Digital Signature Algorithm. Replaces RSA/ECDSA/Ed25519 signatures.",
      relevantAlgos: [
        "RSA-1024",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
        "ECDSA-P256",
        "ECDSA-P384",
        "ECDSA-P521",
        "Ed25519",
        "DSA-1024",
        "DSA-2048",
      ],
      pqcAlgo: "CRYSTALS-Dilithium",
    },
    "FIPS-205": {
      standard: "FIPS-205",
      name: "SLH-DSA (SPHINCS+)",
      description:
        "Stateless Hash-Based Digital Signature Algorithm. Conservative fallback for high-assurance signing.",
      relevantAlgos: ["RSA-4096", "ECDSA-P521"],
      pqcAlgo: "SPHINCS+",
    },
    "FIPS-206": {
      standard: "FIPS-206",
      name: "FN-DSA (FALCON)",
      description:
        "FFT over NTRU-Lattice-Based Digital Signature Algorithm. Compact signatures for constrained environments.",
      relevantAlgos: ["Ed25519", "ECDSA-P256"],
      pqcAlgo: "FALCON",
    },
  };

  const result: Record<
    string,
    {
      standard: string;
      name: string;
      description: string;
      status: "not_started" | "in_progress" | "compliant";
      progress: number;
      relevantAssets: number;
      migratedAssets: number;
    }
  > = {};

  for (const [key, std] of Object.entries(standards)) {
    const relevantAssets = assets.filter((a) => std.relevantAlgos.includes(a.algorithm));
    const migratedAssets = assets.filter((a) => a.algorithm === std.pqcAlgo);
    const totalRelevant = relevantAssets.length + migratedAssets.length;

    let status: "not_started" | "in_progress" | "compliant" = "not_started";
    let progress = 0;

    if (totalRelevant > 0) {
      progress = Math.round((migratedAssets.length / totalRelevant) * 100);
      if (progress >= 100) status = "compliant";
      else if (progress > 0) status = "in_progress";
    }

    result[key] = {
      standard: std.standard,
      name: std.name,
      description: std.description,
      status,
      progress,
      relevantAssets: relevantAssets.length,
      migratedAssets: migratedAssets.length,
    };
  }

  return result;
}

export { ALGORITHM_PROFILES };
