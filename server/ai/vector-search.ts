/**
 * RAG Vector Search Layer
 *
 * Provides semantic search over:
 * - Past incidents from the org's own DB
 * - MITRE ATT&CK technique descriptions
 * - CVE advisories matching observed software/versions
 *
 * Uses AWS Bedrock Titan Embeddings for vector generation
 * and pgvector for similarity search.
 */

import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";
import { getAwsClientConfig } from "../aws-credentials";
import { pool } from "../db";
import { logger } from "../logger";

const log = logger.child("vector-search");

const EMBEDDING_MODEL = process.env.AI_EMBEDDING_MODEL_ID || "amazon.titan-embed-text-v2:0";
const EMBEDDING_DIMENSION = 1024;

const bedrockClient = new BedrockRuntimeClient(getAwsClientConfig());

// ── Embedding Generation ────────────────────────────────────────────

interface EmbeddingResult {
  embedding: number[];
  inputTextTokenCount: number;
}

async function generateEmbedding(text: string): Promise<EmbeddingResult> {
  const truncated = text.slice(0, 8000);

  const command = new InvokeModelCommand({
    modelId: EMBEDDING_MODEL,
    contentType: "application/json",
    accept: "application/json",
    body: JSON.stringify({
      inputText: truncated,
      dimensions: EMBEDDING_DIMENSION,
    }),
  });

  const response = await bedrockClient.send(command);
  const result = JSON.parse(new TextDecoder().decode(response.body));

  return {
    embedding: result.embedding,
    inputTextTokenCount: result.inputTextTokenCount || 0,
  };
}

async function generateEmbeddingsBatch(texts: string[]): Promise<EmbeddingResult[]> {
  const results: EmbeddingResult[] = [];
  const batchSize = 5;

  for (let i = 0; i < texts.length; i += batchSize) {
    const batch = texts.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map((t) => generateEmbedding(t)));
    results.push(...batchResults);
  }

  return results;
}

// ── Vector Search Functions ─────────────────────────────────────────

export interface VectorSearchResult {
  id: string;
  category: string;
  sourceType: string;
  sourceId: string | null;
  title: string;
  content: string;
  metadata: Record<string, unknown>;
  similarity: number;
}

export async function vectorSearch(
  queryText: string,
  category: string,
  limit: number = 5,
  orgId?: string,
): Promise<VectorSearchResult[]> {
  try {
    const { embedding } = await generateEmbedding(queryText);
    const vecStr = `[${embedding.join(",")}]`;

    let query: string;
    let params: (string | number)[];

    if (orgId) {
      // Search both global entries (org_id IS NULL) and org-specific entries
      query = `
        SELECT id, category, source_type, source_id, title, content, metadata,
               1 - (embedding <=> $1::vector) AS similarity
        FROM rag_knowledge_base
        WHERE category = $2
          AND (org_id IS NULL OR org_id = $3)
          AND embedding IS NOT NULL
        ORDER BY embedding <=> $1::vector
        LIMIT $4
      `;
      params = [vecStr, category, orgId, limit];
    } else {
      query = `
        SELECT id, category, source_type, source_id, title, content, metadata,
               1 - (embedding <=> $1::vector) AS similarity
        FROM rag_knowledge_base
        WHERE category = $2
          AND org_id IS NULL
          AND embedding IS NOT NULL
        ORDER BY embedding <=> $1::vector
        LIMIT $3
      `;
      params = [vecStr, category, limit];
    }

    const result = await pool.query(query, params);

    return result.rows.map((row) => ({
      id: row.id,
      category: row.category,
      sourceType: row.source_type,
      sourceId: row.source_id,
      title: row.title,
      content: row.content,
      metadata: row.metadata || {},
      similarity: parseFloat(row.similarity),
    }));
  } catch (err) {
    log.warn("Vector search failed", { error: String(err), category });
    return [];
  }
}

export interface IncidentSearchResult {
  id: string;
  incidentId: string;
  title: string;
  summary: string | null;
  severity: string | null;
  mitreTactics: string[];
  mitreTechniques: string[];
  iocs: string[];
  similarity: number;
}

export async function searchSimilarIncidents(
  queryText: string,
  orgId: string,
  limit: number = 5,
): Promise<IncidentSearchResult[]> {
  try {
    const { embedding } = await generateEmbedding(queryText);
    const vecStr = `[${embedding.join(",")}]`;

    const result = await pool.query(
      `
      SELECT id, incident_id, title, summary, severity,
             mitre_tactics, mitre_techniques, iocs,
             1 - (embedding <=> $1::vector) AS similarity
      FROM rag_incident_embeddings
      WHERE org_id = $2
        AND embedding IS NOT NULL
      ORDER BY embedding <=> $1::vector
      LIMIT $3
      `,
      [vecStr, orgId, limit],
    );

    return result.rows.map((row) => ({
      id: row.id,
      incidentId: row.incident_id,
      title: row.title,
      summary: row.summary,
      severity: row.severity,
      mitreTactics: row.mitre_tactics || [],
      mitreTechniques: row.mitre_techniques || [],
      iocs: row.iocs || [],
      similarity: parseFloat(row.similarity),
    }));
  } catch (err) {
    log.warn("Incident search failed", { error: String(err) });
    return [];
  }
}

// ── Knowledge Base Management ───────────────────────────────────────

export async function upsertKnowledgeEntry(entry: {
  orgId?: string;
  category: string;
  sourceType: string;
  sourceId?: string;
  title: string;
  content: string;
  metadata?: Record<string, unknown>;
}): Promise<string> {
  const { embedding } = await generateEmbedding(`${entry.title}\n\n${entry.content}`);
  const vecStr = `[${embedding.join(",")}]`;

  const result = await pool.query(
    `
    INSERT INTO rag_knowledge_base (org_id, category, source_type, source_id, title, content, metadata, embedding)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::vector)
    ON CONFLICT (source_type, source_id) WHERE source_id IS NOT NULL
    DO UPDATE SET
      title = EXCLUDED.title,
      content = EXCLUDED.content,
      metadata = EXCLUDED.metadata,
      embedding = EXCLUDED.embedding,
      updated_at = NOW()
    RETURNING id
    `,
    [
      entry.orgId || null,
      entry.category,
      entry.sourceType,
      entry.sourceId || null,
      entry.title,
      entry.content,
      JSON.stringify(entry.metadata || {}),
      vecStr,
    ],
  );

  return result.rows[0].id;
}

export async function upsertIncidentEmbedding(incident: {
  orgId: string;
  incidentId: string;
  title: string;
  summary?: string;
  severity?: string;
  mitreTactics?: string[];
  mitreTechniques?: string[];
  iocs?: string[];
}): Promise<void> {
  const contentParts = [
    `Title: ${incident.title}`,
    incident.summary ? `Summary: ${incident.summary}` : "",
    incident.severity ? `Severity: ${incident.severity}` : "",
    incident.mitreTactics?.length ? `MITRE Tactics: ${incident.mitreTactics.join(", ")}` : "",
    incident.mitreTechniques?.length ? `MITRE Techniques: ${incident.mitreTechniques.join(", ")}` : "",
    incident.iocs?.length ? `IOCs: ${incident.iocs.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const { embedding } = await generateEmbedding(contentParts);
  const vecStr = `[${embedding.join(",")}]`;

  await pool.query(
    `
    INSERT INTO rag_incident_embeddings
      (org_id, incident_id, title, summary, severity, mitre_tactics, mitre_techniques, iocs, content, embedding)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::vector)
    ON CONFLICT (incident_id)
    DO UPDATE SET
      title = EXCLUDED.title,
      summary = EXCLUDED.summary,
      severity = EXCLUDED.severity,
      mitre_tactics = EXCLUDED.mitre_tactics,
      mitre_techniques = EXCLUDED.mitre_techniques,
      iocs = EXCLUDED.iocs,
      content = EXCLUDED.content,
      embedding = EXCLUDED.embedding,
      updated_at = NOW()
    `,
    [
      incident.orgId,
      incident.incidentId,
      incident.title,
      incident.summary || null,
      incident.severity || null,
      incident.mitreTactics || [],
      incident.mitreTechniques || [],
      incident.iocs || [],
      contentParts,
      vecStr,
    ],
  );
}

export async function deleteKnowledgeEntry(id: string, orgId?: string): Promise<boolean> {
  // Org-scoped delete: only delete entries belonging to this org (or global entries with no org)
  if (orgId) {
    const result = await pool.query(
      "DELETE FROM rag_knowledge_base WHERE id = $1 AND (org_id = $2 OR org_id IS NULL)",
      [id, orgId],
    );
    return (result.rowCount ?? 0) > 0;
  }
  const result = await pool.query("DELETE FROM rag_knowledge_base WHERE id = $1", [id]);
  return (result.rowCount ?? 0) > 0;
}

export async function getKnowledgeStats(): Promise<{
  totalEntries: number;
  byCategory: Record<string, number>;
  incidentEmbeddings: number;
  lastUpdated: string | null;
}> {
  const [kbResult, incResult, lastResult] = await Promise.all([
    pool.query("SELECT category, COUNT(*) as cnt FROM rag_knowledge_base GROUP BY category"),
    pool.query("SELECT COUNT(*) as cnt FROM rag_incident_embeddings"),
    pool.query(
      "SELECT MAX(updated_at) as last FROM (SELECT updated_at FROM rag_knowledge_base UNION ALL SELECT updated_at FROM rag_incident_embeddings) sub",
    ),
  ]);

  const byCategory: Record<string, number> = {};
  let total = 0;
  for (const row of kbResult.rows) {
    byCategory[row.category] = parseInt(row.cnt, 10);
    total += parseInt(row.cnt, 10);
  }

  return {
    totalEntries: total,
    byCategory,
    incidentEmbeddings: parseInt(incResult.rows[0].cnt, 10),
    lastUpdated: lastResult.rows[0]?.last?.toISOString() || null,
  };
}

// ── MITRE ATT&CK Knowledge Seeding ─────────────────────────────────

const MITRE_ATTACK_TECHNIQUES = [
  {
    id: "T1566.001",
    name: "Phishing: Spearphishing Attachment",
    tactic: "Initial Access",
    description:
      "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry.",
  },
  {
    id: "T1566.002",
    name: "Phishing: Spearphishing Link",
    tactic: "Initial Access",
    description:
      "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself.",
  },
  {
    id: "T1059.001",
    name: "Command and Scripting Interpreter: PowerShell",
    tactic: "Execution",
    description:
      "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer.",
  },
  {
    id: "T1059.003",
    name: "Command and Scripting Interpreter: Windows Command Shell",
    tactic: "Execution",
    description:
      "Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands.",
  },
  {
    id: "T1059.004",
    name: "Command and Scripting Interpreter: Unix Shell",
    tactic: "Execution",
    description:
      "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist. Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.",
  },
  {
    id: "T1053.005",
    name: "Scheduled Task/Job: Scheduled Task",
    tactic: "Persistence",
    description:
      "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.",
  },
  {
    id: "T1547.001",
    name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    tactic: "Persistence",
    description:
      "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the 'run keys' in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.",
  },
  {
    id: "T1548.002",
    name: "Abuse Elevation Control Mechanism: Bypass User Account Control",
    tactic: "Privilege Escalation",
    description:
      "Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation.",
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Defense Evasion",
    description:
      "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services.",
  },
  {
    id: "T1003.001",
    name: "OS Credential Dumping: LSASS Memory",
    tactic: "Credential Access",
    description:
      "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material.",
  },
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    description:
      "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data.",
  },
  {
    id: "T1087",
    name: "Account Discovery",
    tactic: "Discovery",
    description:
      "Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior. Adversaries may obtain lists of valid accounts, usernames, or email addresses by querying directory services, social media accounts, or threat intelligence databases.",
  },
  {
    id: "T1018",
    name: "Remote System Discovery",
    tactic: "Discovery",
    description:
      "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used.",
  },
  {
    id: "T1021.001",
    name: "Remote Services: Remote Desktop Protocol",
    tactic: "Lateral Movement",
    description:
      "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system.",
  },
  {
    id: "T1021.002",
    name: "Remote Services: SMB/Windows Admin Shares",
    tactic: "Lateral Movement",
    description:
      "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain.",
  },
  {
    id: "T1560.001",
    name: "Archive Collected Data: Archive via Utility",
    tactic: "Collection",
    description:
      "Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.",
  },
  {
    id: "T1071.001",
    name: "Application Layer Protocol: Web Protocols",
    tactic: "Command and Control",
    description:
      "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
  },
  {
    id: "T1573",
    name: "Encrypted Channel",
    tactic: "Command and Control",
    description:
      "Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.",
  },
  {
    id: "T1048",
    name: "Exfiltration Over Alternative Protocol",
    tactic: "Exfiltration",
    description:
      "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel.",
  },
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "Impact",
    description:
      "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This is done in order to extract payment from the victim, a behavior commonly known as ransomware.",
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    description:
      "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration. Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols, and any other system with Internet accessible open sockets.",
  },
  {
    id: "T1133",
    name: "External Remote Services",
    tactic: "Initial Access",
    description:
      "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services.",
  },
  {
    id: "T1098",
    name: "Account Manipulation",
    tactic: "Persistence",
    description:
      "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies.",
  },
  {
    id: "T1055",
    name: "Process Injection",
    tactic: "Defense Evasion",
    description:
      "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges.",
  },
  {
    id: "T1562.001",
    name: "Impair Defenses: Disable or Modify Tools",
    tactic: "Defense Evasion",
    description:
      "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information.",
  },
  {
    id: "T1027",
    name: "Obfuscated Files or Information",
    tactic: "Defense Evasion",
    description:
      "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.",
  },
  {
    id: "T1552.001",
    name: "Unsecured Credentials: Credentials In Files",
    tactic: "Credential Access",
    description:
      "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.",
  },
  {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    description:
      "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system.",
  },
  {
    id: "T1570",
    name: "Lateral Tool Transfer",
    tactic: "Lateral Movement",
    description:
      "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment, files may then be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols.",
  },
  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    description:
      "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications. Data is exfiltrated through C2 as the data is transmitted alongside normal C2 traffic.",
  },
  {
    id: "T1490",
    name: "Inhibit System Recovery",
    tactic: "Impact",
    description:
      "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options. Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features.",
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: "Command and Control",
    description:
      "Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment.",
  },
  {
    id: "T1569.002",
    name: "System Services: Service Execution",
    tactic: "Execution",
    description:
      "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (services.exe) is an interface to manage and manipulate services. The service control manager is accessible to users via GUI components as well as system utilities such as sc.exe and Net.",
  },
  {
    id: "T1543.003",
    name: "Create or Modify System Process: Windows Service",
    tactic: "Persistence",
    description:
      "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.",
  },
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
    description:
      "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.",
  },
  {
    id: "T1040",
    name: "Network Sniffing",
    tactic: "Credential Access",
    description:
      "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network.",
  },
  {
    id: "T1049",
    name: "System Network Connections Discovery",
    tactic: "Discovery",
    description:
      "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected.",
  },
  {
    id: "T1557",
    name: "Adversary-in-the-Middle",
    tactic: "Credential Access",
    description:
      "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing, Transmitted Data Manipulation, or replay attacks (Exploitation for Credential Access). By abusing features of common networking protocols that can determine the flow of network traffic, adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.",
  },
  {
    id: "T1204.001",
    name: "User Execution: Malicious Link",
    tactic: "Execution",
    description:
      "An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Link.",
  },
  {
    id: "T1204.002",
    name: "User Execution: Malicious File",
    tactic: "Execution",
    description:
      "An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Attachment.",
  },
  {
    id: "T1595",
    name: "Active Scanning",
    tactic: "Reconnaissance",
    description:
      "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction. Adversaries may perform different forms of active scanning depending on what information they seek to gather.",
  },
  {
    id: "T1592",
    name: "Gather Victim Host Information",
    tactic: "Reconnaissance",
    description:
      "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).",
  },
  {
    id: "T1195.002",
    name: "Supply Chain Compromise: Compromise Software Supply Chain",
    tactic: "Initial Access",
    description:
      "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.",
  },
  {
    id: "T1136",
    name: "Create Account",
    tactic: "Persistence",
    description:
      "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.",
  },
  {
    id: "T1556",
    name: "Modify Authentication Process",
    tactic: "Credential Access",
    description:
      "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials.",
  },
  {
    id: "T1499",
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    description:
      "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition.",
  },
  {
    id: "T1485",
    name: "Data Destruction",
    tactic: "Impact",
    description:
      "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.",
  },
];

// Famous CVE advisories for security knowledge base
const CVE_ADVISORIES = [
  {
    id: "CVE-2021-44228",
    name: "Log4Shell",
    severity: "critical",
    cvss: 10.0,
    software: "Apache Log4j",
    description:
      "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. Log4Shell allows unauthenticated remote code execution.",
  },
  {
    id: "CVE-2023-44487",
    name: "HTTP/2 Rapid Reset",
    severity: "high",
    cvss: 7.5,
    software: "HTTP/2 implementations",
    description:
      "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023. This vulnerability affects all major web servers and proxy implementations including nginx, Apache httpd, and various cloud providers.",
  },
  {
    id: "CVE-2024-3094",
    name: "XZ Utils Backdoor",
    severity: "critical",
    cvss: 10.0,
    software: "XZ Utils",
    description:
      "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library. Specifically targets OpenSSH sshd to allow unauthorized remote access.",
  },
  {
    id: "CVE-2021-34527",
    name: "PrintNightmare",
    severity: "critical",
    cvss: 8.8,
    software: "Windows Print Spooler",
    description:
      "Windows Print Spooler Remote Code Execution Vulnerability. A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.",
  },
  {
    id: "CVE-2023-23397",
    name: "Outlook Elevation of Privilege",
    severity: "critical",
    cvss: 9.8,
    software: "Microsoft Outlook",
    description:
      "Microsoft Outlook Elevation of Privilege Vulnerability. An attacker could exploit this vulnerability by sending a specially crafted email which triggers automatically when it is retrieved and processed by the Outlook client. This could lead to exploitation BEFORE the email is viewed in the Preview Pane. The attacker could use the vulnerability to leak the victim's Net-NTLMv2 hash to a remote attacker-controlled server, allowing relay attacks.",
  },
  {
    id: "CVE-2021-26855",
    name: "ProxyLogon",
    severity: "critical",
    cvss: 9.8,
    software: "Microsoft Exchange Server",
    description:
      "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon). This vulnerability is part of an attack chain. The initial attack requires the ability to make an untrusted connection to Exchange server port 443. This can be protected against by restricting untrusted connections, or by setting up a VPN to separate the Exchange server from external access. Using this mitigation will only protect against the initial portion of the attack.",
  },
  {
    id: "CVE-2020-1472",
    name: "Zerologon",
    severity: "critical",
    cvss: 10.0,
    software: "Windows Netlogon",
    description:
      "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited this vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access.",
  },
  {
    id: "CVE-2023-34362",
    name: "MOVEit Transfer SQL Injection",
    severity: "critical",
    cvss: 9.8,
    software: "Progress MOVEit Transfer",
    description:
      "In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements.",
  },
  {
    id: "CVE-2024-21762",
    name: "FortiOS Out-of-Bound Write",
    severity: "critical",
    cvss: 9.8,
    software: "Fortinet FortiOS",
    description:
      "A out-of-bounds write vulnerability in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0 all versions allows an attacker to execute unauthorized code or commands via specially crafted requests. This vulnerability is being actively exploited in the wild and allows remote code execution without authentication.",
  },
  {
    id: "CVE-2023-4966",
    name: "Citrix Bleed",
    severity: "critical",
    cvss: 9.4,
    software: "Citrix NetScaler ADC/Gateway",
    description:
      "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server. This vulnerability allows unauthenticated attackers to extract sensitive information including session tokens, enabling session hijacking. The LockBit ransomware group actively exploited this vulnerability in attacks against multiple organizations.",
  },
  {
    id: "CVE-2017-0144",
    name: "EternalBlue",
    severity: "critical",
    cvss: 9.3,
    software: "Windows SMBv1",
    description:
      "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets. This vulnerability was used by the WannaCry ransomware and NotPetya wiper malware in devastating worldwide attacks. It exploits a buffer overflow in the Windows SMB protocol implementation.",
  },
  {
    id: "CVE-2019-19781",
    name: "Citrix ADC Path Traversal",
    severity: "critical",
    cvss: 9.8,
    software: "Citrix ADC/Gateway",
    description:
      "An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway allowing directory traversal. This vulnerability allows unauthenticated remote code execution and was widely exploited by ransomware groups and nation-state actors.",
  },
  {
    id: "CVE-2021-27065",
    name: "ProxyShell/HAFNIUM Exchange",
    severity: "critical",
    cvss: 7.8,
    software: "Microsoft Exchange Server",
    description:
      "Microsoft Exchange Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858. Part of the ProxyShell chain used by HAFNIUM threat group for post-authentication arbitrary file write leading to web shell deployment.",
  },
  {
    id: "CVE-2022-26134",
    name: "Confluence Server OGNL Injection",
    severity: "critical",
    cvss: 9.8,
    software: "Atlassian Confluence Server",
    description:
      "In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. This vulnerability was exploited in the wild as a zero-day prior to disclosure.",
  },
  {
    id: "CVE-2023-0669",
    name: "GoAnywhere MFT RCE",
    severity: "critical",
    cvss: 7.2,
    software: "Fortra GoAnywhere MFT",
    description:
      "Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This was exploited by the Clop ransomware group to steal data from over 130 organizations.",
  },
  {
    id: "CVE-2024-47575",
    name: "FortiManager Missing Authentication",
    severity: "critical",
    cvss: 9.8,
    software: "Fortinet FortiManager",
    description:
      "A missing authentication for critical function vulnerability in FortiManager fgfmd daemon may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests. This vulnerability, dubbed FortiJump, was exploited in the wild by threat actors to compromise managed FortiGate firewalls through their management platform.",
  },
];

export async function seedMitreAttackKnowledge(): Promise<number> {
  let seeded = 0;

  for (const technique of MITRE_ATTACK_TECHNIQUES) {
    try {
      const content = `MITRE ATT&CK Technique ${technique.id}: ${technique.name}\nTactic: ${technique.tactic}\n\n${technique.description}`;

      await upsertKnowledgeEntry({
        category: "attack_techniques",
        sourceType: "mitre_attack",
        sourceId: technique.id,
        title: `${technique.id} - ${technique.name}`,
        content,
        metadata: {
          techniqueId: technique.id,
          tactic: technique.tactic,
          name: technique.name,
        },
      });
      seeded++;
    } catch (err) {
      log.warn("Failed to seed MITRE ATT&CK technique", { id: technique.id, error: String(err) });
    }
  }

  log.info("MITRE ATT&CK knowledge seeded", { count: seeded });
  return seeded;
}

export async function seedCveAdvisories(): Promise<number> {
  let seeded = 0;

  for (const cve of CVE_ADVISORIES) {
    try {
      const content = `${cve.id} (${cve.name}) - CVSS ${cve.cvss}\nSeverity: ${cve.severity}\nAffected Software: ${cve.software}\n\n${cve.description}`;

      await upsertKnowledgeEntry({
        category: "cve_advisories",
        sourceType: "cve",
        sourceId: cve.id,
        title: `${cve.id} - ${cve.name}`,
        content,
        metadata: {
          cveId: cve.id,
          name: cve.name,
          severity: cve.severity,
          cvss: cve.cvss,
          software: cve.software,
        },
      });
      seeded++;
    } catch (err) {
      log.warn("Failed to seed CVE advisory", { id: cve.id, error: String(err) });
    }
  }

  log.info("CVE advisories seeded", { count: seeded });
  return seeded;
}

// ── RAG Context Builder ─────────────────────────────────────────────

export interface RAGContext {
  similarPastIncidents: IncidentSearchResult[];
  relatedAttackTechniques: VectorSearchResult[];
  relevantCveAdvisories: VectorSearchResult[];
  ragSummary: string;
}

export async function buildRAGContext(
  alertData: {
    title?: string;
    description?: string;
    mitreTactic?: string;
    mitreTechnique?: string;
    sourceIp?: string;
    destIp?: string;
    hostname?: string;
    domain?: string;
    fileHash?: string;
    category?: string;
    severity?: string;
    software?: string[];
  },
  orgId?: string,
): Promise<RAGContext> {
  const result: RAGContext = {
    similarPastIncidents: [],
    relatedAttackTechniques: [],
    relevantCveAdvisories: [],
    ragSummary: "",
  };

  try {
    // Build a semantic query from alert data
    const queryParts = [
      alertData.title || "",
      alertData.description || "",
      alertData.mitreTactic ? `MITRE Tactic: ${alertData.mitreTactic}` : "",
      alertData.mitreTechnique ? `MITRE Technique: ${alertData.mitreTechnique}` : "",
      alertData.category ? `Category: ${alertData.category}` : "",
      alertData.severity ? `Severity: ${alertData.severity}` : "",
      alertData.hostname ? `Host: ${alertData.hostname}` : "",
      alertData.domain ? `Domain: ${alertData.domain}` : "",
    ]
      .filter(Boolean)
      .join("\n");

    if (!queryParts.trim()) return result;

    // Execute all three searches in parallel
    const [incidents, techniques, cves] = await Promise.all([
      orgId ? searchSimilarIncidents(queryParts, orgId, 5) : Promise.resolve([]),
      vectorSearch(queryParts, "attack_techniques", 10, orgId),
      vectorSearch(queryParts, "cve_advisories", 5, orgId),
    ]);

    // Filter by minimum similarity threshold
    result.similarPastIncidents = incidents.filter((i) => i.similarity > 0.3);
    result.relatedAttackTechniques = techniques.filter((t) => t.similarity > 0.4);
    result.relevantCveAdvisories = cves.filter((c) => c.similarity > 0.35);

    // Build summary
    const summaryParts: string[] = [];

    if (result.similarPastIncidents.length > 0) {
      summaryParts.push(
        `Found ${result.similarPastIncidents.length} similar past incident(s): ${result.similarPastIncidents.map((i) => `"${i.title}" (${(i.similarity * 100).toFixed(0)}% match)`).join(", ")}`,
      );
    }

    if (result.relatedAttackTechniques.length > 0) {
      summaryParts.push(
        `Matched ${result.relatedAttackTechniques.length} MITRE ATT&CK technique(s): ${result.relatedAttackTechniques.map((t) => t.metadata?.techniqueId || t.title).join(", ")}`,
      );
    }

    if (result.relevantCveAdvisories.length > 0) {
      summaryParts.push(
        `Relevant CVE(s): ${result.relevantCveAdvisories.map((c) => `${c.metadata?.cveId} (${c.metadata?.name})`).join(", ")}`,
      );
    }

    if (summaryParts.length > 0) {
      result.ragSummary = summaryParts.join(". ") + ".";
    }
  } catch (err) {
    log.warn("RAG context build failed (non-fatal)", { error: String(err) });
  }

  return result;
}

export function formatRAGContextForPrompt(ctx: RAGContext): string {
  if (
    ctx.similarPastIncidents.length === 0 &&
    ctx.relatedAttackTechniques.length === 0 &&
    ctx.relevantCveAdvisories.length === 0
  ) {
    return "";
  }

  const lines: string[] = [];
  lines.push("HISTORICAL & KNOWLEDGE BASE CONTEXT (RAG):");
  lines.push("The following context was retrieved via semantic search from the organization's knowledge base.");
  lines.push("");

  if (ctx.similarPastIncidents.length > 0) {
    lines.push("SIMILAR PAST INCIDENTS:");
    for (const inc of ctx.similarPastIncidents) {
      lines.push(
        `- "${inc.title}" (severity: ${inc.severity || "unknown"}, similarity: ${(inc.similarity * 100).toFixed(0)}%)`,
      );
      if (inc.summary) lines.push(`  Summary: ${inc.summary}`);
      if (inc.mitreTactics.length > 0) lines.push(`  Tactics: ${inc.mitreTactics.join(", ")}`);
      if (inc.mitreTechniques.length > 0) lines.push(`  Techniques: ${inc.mitreTechniques.join(", ")}`);
      if (inc.iocs.length > 0) lines.push(`  IOCs: ${inc.iocs.slice(0, 5).join(", ")}`);
    }
    lines.push("");
  }

  if (ctx.relatedAttackTechniques.length > 0) {
    lines.push("RELATED MITRE ATT&CK TECHNIQUES:");
    for (const tech of ctx.relatedAttackTechniques) {
      const meta = tech.metadata || {};
      lines.push(
        `- ${meta.techniqueId || "?"} ${meta.name || tech.title} [${meta.tactic || "?"}] (${(tech.similarity * 100).toFixed(0)}% match)`,
      );
      // Include a brief excerpt
      const excerpt = tech.content.slice(0, 200);
      lines.push(`  ${excerpt}${tech.content.length > 200 ? "..." : ""}`);
    }
    lines.push("");
  }

  if (ctx.relevantCveAdvisories.length > 0) {
    lines.push("RELEVANT CVE ADVISORIES:");
    for (const cve of ctx.relevantCveAdvisories) {
      const meta = cve.metadata || {};
      lines.push(
        `- ${meta.cveId || "?"} (${meta.name || cve.title}) — CVSS ${meta.cvss || "?"}, ${meta.severity || "?"} severity`,
      );
      lines.push(`  Affected: ${meta.software || "unknown"}`);
      const excerpt = cve.content.slice(0, 200);
      lines.push(`  ${excerpt}${cve.content.length > 200 ? "..." : ""}`);
    }
    lines.push("");
  }

  if (ctx.ragSummary) {
    lines.push(`RAG SUMMARY: ${ctx.ragSummary}`);
    lines.push("");
  }

  lines.push(
    "Use this historical and knowledge base context to improve your analysis. Similar past incidents suggest recurring attack patterns. Matched ATT&CK techniques indicate the likely adversary playbook. Relevant CVEs may point to the exploited vulnerability.",
  );

  return lines.join("\n");
}
