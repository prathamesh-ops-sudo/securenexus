/**
 * GitLab CI Integration — Developer Security
 *
 * Handles GitLab webhook events for merge requests and pushes,
 * triggers SAST scans, posts merge request comments with findings.
 */

import { logger } from "../logger";
import { scanCode, scanSecrets, inferLanguage } from "../sast-engine";
import type { SastFindingResult, SecretFindingResult } from "../sast-engine";

const log = logger.child("gitlab-integration");

export interface GitLabWebhookPayload {
  object_kind?: string;
  event_type?: string;
  ref?: string;
  checkout_sha?: string;
  project?: {
    id: number;
    name: string;
    path_with_namespace: string;
    default_branch: string;
    web_url: string;
  };
  object_attributes?: {
    iid: number;
    title: string;
    source_branch: string;
    target_branch: string;
    last_commit: { id: string };
    action: string;
    state: string;
  };
  commits?: Array<{
    id: string;
    message: string;
    added: string[];
    modified: string[];
    removed: string[];
  }>;
  user?: { username: string; name: string };
}

export interface GitLabScanContext {
  orgId: string;
  accessToken: string;
  projectId: number;
  projectPath: string;
  gitlabUrl: string;
  commitSha: string;
  branch: string;
  mergeRequestIid?: number;
}

/**
 * Fetch file content from GitLab
 */
export async function fetchGitLabFileContent(ctx: GitLabScanContext, filePath: string): Promise<string | null> {
  try {
    const encodedPath = encodeURIComponent(filePath);
    const url = `${ctx.gitlabUrl}/api/v4/projects/${ctx.projectId}/repository/files/${encodedPath}/raw?ref=${ctx.commitSha}`;

    const response = await fetch(url, {
      headers: { "PRIVATE-TOKEN": ctx.accessToken },
    });

    if (!response.ok) return null;
    return await response.text();
  } catch (err) {
    log.warn("Failed to fetch GitLab file", { filePath, error: String(err) });
    return null;
  }
}

/**
 * Get merge request changes (diff files)
 */
export async function getMergeRequestChanges(
  ctx: GitLabScanContext,
): Promise<Array<{ new_path: string; old_path: string; deleted_file: boolean }>> {
  if (!ctx.mergeRequestIid) return [];

  try {
    const url = `${ctx.gitlabUrl}/api/v4/projects/${ctx.projectId}/merge_requests/${ctx.mergeRequestIid}/changes`;

    const response = await fetch(url, {
      headers: { "PRIVATE-TOKEN": ctx.accessToken },
    });

    if (!response.ok) return [];
    const data = (await response.json()) as {
      changes: Array<{ new_path: string; old_path: string; deleted_file: boolean }>;
    };
    return data.changes || [];
  } catch (err) {
    log.error("Failed to get MR changes", { error: String(err) });
    return [];
  }
}

/**
 * Scan a merge request for security findings
 */
export async function scanMergeRequest(ctx: GitLabScanContext): Promise<{
  findings: SastFindingResult[];
  secrets: SecretFindingResult[];
  filesScanned: number;
}> {
  const changes = await getMergeRequestChanges(ctx);
  const allFindings: SastFindingResult[] = [];
  const allSecrets: SecretFindingResult[] = [];
  let filesScanned = 0;

  for (const change of changes) {
    if (change.deleted_file) continue;

    const language = inferLanguage(change.new_path);
    if (!language) continue;

    const content = await fetchGitLabFileContent(ctx, change.new_path);
    if (!content) continue;

    filesScanned++;
    const codeFindings = scanCode(content, change.new_path, language);
    allFindings.push(...codeFindings);

    const secretFindings = scanSecrets(content, change.new_path);
    allSecrets.push(...secretFindings);
  }

  log.info("GitLab MR scan complete", {
    project: ctx.projectPath,
    mr: ctx.mergeRequestIid,
    findings: allFindings.length,
    secrets: allSecrets.length,
    filesScanned,
  });

  return { findings: allFindings, secrets: allSecrets, filesScanned };
}

/**
 * Post a note (comment) on a merge request
 */
export async function postMergeRequestNote(ctx: GitLabScanContext, body: string): Promise<boolean> {
  if (!ctx.mergeRequestIid) return false;

  try {
    const url = `${ctx.gitlabUrl}/api/v4/projects/${ctx.projectId}/merge_requests/${ctx.mergeRequestIid}/notes`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "PRIVATE-TOKEN": ctx.accessToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body }),
    });

    return response.ok;
  } catch (err) {
    log.error("Failed to post MR note", { error: String(err) });
    return false;
  }
}

/**
 * Post scan summary on a merge request
 */
export async function postGitLabScanSummary(
  ctx: GitLabScanContext,
  findings: SastFindingResult[],
  secrets: SecretFindingResult[],
  filesScanned: number,
): Promise<void> {
  const critCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;

  const hasIssues = findings.length > 0 || secrets.length > 0;
  const statusIcon = hasIssues ? "⚠️" : "✅";

  let body =
    `## ${statusIcon} SecureNexus Security Scan\n\n` +
    `**Files scanned:** ${filesScanned} | **Commit:** \`${ctx.commitSha.substring(0, 7)}\`\n\n`;

  if (findings.length > 0) {
    body +=
      `### SAST Findings\n` +
      `| Severity | Count |\n|---|---|\n` +
      `| Critical | ${critCount} |\n` +
      `| High | ${highCount} |\n` +
      `| Medium | ${mediumCount} |\n` +
      `| Low | ${lowCount} |\n\n`;

    const topFindings = findings
      .sort((a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      })
      .slice(0, 10);

    body += `**Top findings:**\n`;
    for (const f of topFindings) {
      body += `- **${f.severity.toUpperCase()}** \`${f.filePath}:${f.startLine}\` — ${f.title}\n`;
    }
    body += `\n`;
  } else {
    body += `### SAST Findings\nNo code vulnerabilities detected.\n\n`;
  }

  if (secrets.length > 0) {
    body +=
      `### Exposed Secrets\n` + `**${secrets.length} secret(s) detected!** These must be rotated immediately.\n\n`;
    for (const s of secrets) {
      body += `- \`${s.filePath}:${s.line}\` — ${s.secretType} (${s.maskedValue})\n`;
    }
  }

  body += `\n---\n*Powered by SecureNexus Developer Security*`;

  await postMergeRequestNote(ctx, body);
}

/**
 * Set pipeline status on a commit
 */
export async function setGitLabCommitStatus(
  ctx: GitLabScanContext,
  state: "success" | "failed" | "pending" | "running",
  description: string,
  targetUrl?: string,
): Promise<void> {
  try {
    const url = `${ctx.gitlabUrl}/api/v4/projects/${ctx.projectId}/statuses/${ctx.commitSha}`;

    await fetch(url, {
      method: "POST",
      headers: {
        "PRIVATE-TOKEN": ctx.accessToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        state,
        description: description.substring(0, 140),
        name: "SecureNexus Security Scan",
        target_url: targetUrl,
      }),
    });
  } catch (err) {
    log.warn("Failed to set GitLab commit status", { error: String(err) });
  }
}

/**
 * List projects accessible by the GitLab token
 */
export async function listGitLabProjects(
  gitlabUrl: string,
  accessToken: string,
): Promise<Array<{ id: number; path: string; defaultBranch: string }>> {
  try {
    const url = `${gitlabUrl}/api/v4/projects?membership=true&per_page=100&order_by=updated_at`;

    const response = await fetch(url, {
      headers: { "PRIVATE-TOKEN": accessToken },
    });

    if (!response.ok) return [];
    const data = (await response.json()) as Array<{
      id: number;
      path_with_namespace: string;
      default_branch: string;
    }>;

    return data.map((p) => ({
      id: p.id,
      path: p.path_with_namespace,
      defaultBranch: p.default_branch,
    }));
  } catch (err) {
    log.error("Failed to list GitLab projects", { error: String(err) });
    return [];
  }
}

/**
 * Get repository tree from GitLab
 */
export async function getGitLabRepositoryTree(ctx: GitLabScanContext): Promise<Array<{ path: string; type: string }>> {
  try {
    const url = `${ctx.gitlabUrl}/api/v4/projects/${ctx.projectId}/repository/tree?ref=${ctx.commitSha}&recursive=true&per_page=100`;

    const response = await fetch(url, {
      headers: { "PRIVATE-TOKEN": ctx.accessToken },
    });

    if (!response.ok) return [];
    const data = (await response.json()) as Array<{ path: string; type: string }>;

    return data.filter((item) => item.type === "blob").map((item) => ({ path: item.path, type: item.type }));
  } catch (err) {
    log.error("Failed to get GitLab tree", { error: String(err) });
    return [];
  }
}
