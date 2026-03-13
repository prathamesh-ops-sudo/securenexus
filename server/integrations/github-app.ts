/**
 * GitHub App Integration — Developer Security
 *
 * Handles GitHub webhooks for push events and pull requests,
 * triggers SAST scans, posts PR review comments with findings.
 */

import { Octokit } from "@octokit/rest";
import { config } from "../config";
import { logger } from "../logger";
import { scanCode, scanSecrets, inferLanguage } from "../sast-engine";
import type { SastFindingResult, SecretFindingResult } from "../sast-engine";

const log = logger.child("github-app");

export interface GitHubWebhookPayload {
  action?: string;
  ref?: string;
  repository?: {
    full_name: string;
    name: string;
    owner: { login: string };
    default_branch: string;
  };
  pull_request?: {
    number: number;
    head: { sha: string; ref: string };
    base: { sha: string; ref: string };
    title: string;
    user: { login: string };
  };
  commits?: Array<{
    id: string;
    message: string;
    added: string[];
    modified: string[];
    removed: string[];
  }>;
  sender?: { login: string };
}

export interface GitHubScanContext {
  orgId: string;
  installationToken?: string;
  owner: string;
  repo: string;
  commitSha: string;
  branch: string;
  pullRequestNumber?: number;
}

/**
 * Get an authenticated Octokit client
 */
function getOctokit(token?: string): Octokit {
  const authToken = token || config.githubToken;
  if (!authToken) {
    throw new Error("GitHub token not configured");
  }
  return new Octokit({ auth: authToken });
}

/**
 * Fetch file content from GitHub
 */
export async function fetchFileContent(ctx: GitHubScanContext, filePath: string): Promise<string | null> {
  try {
    const octokit = getOctokit(ctx.installationToken);
    const response = await octokit.repos.getContent({
      owner: ctx.owner,
      repo: ctx.repo,
      path: filePath,
      ref: ctx.commitSha,
    });

    if ("content" in response.data && response.data.type === "file") {
      return Buffer.from(response.data.content, "base64").toString("utf-8");
    }
    return null;
  } catch (err) {
    log.warn("Failed to fetch file content", { filePath, error: String(err) });
    return null;
  }
}

/**
 * Get changed files in a pull request
 */
export async function getPullRequestFiles(
  ctx: GitHubScanContext,
): Promise<Array<{ filename: string; status: string; patch?: string }>> {
  if (!ctx.pullRequestNumber) return [];

  try {
    const octokit = getOctokit(ctx.installationToken);
    const response = await octokit.pulls.listFiles({
      owner: ctx.owner,
      repo: ctx.repo,
      pull_number: ctx.pullRequestNumber,
      per_page: 100,
    });

    return response.data.map((f) => ({
      filename: f.filename,
      status: f.status,
      patch: f.patch,
    }));
  } catch (err) {
    log.error("Failed to list PR files", { error: String(err) });
    return [];
  }
}

/**
 * Scan a pull request for security findings
 */
export async function scanPullRequest(ctx: GitHubScanContext): Promise<{
  findings: SastFindingResult[];
  secrets: SecretFindingResult[];
  filesScanned: number;
}> {
  const files = await getPullRequestFiles(ctx);
  const allFindings: SastFindingResult[] = [];
  const allSecrets: SecretFindingResult[] = [];
  let filesScanned = 0;

  for (const file of files) {
    if (file.status === "removed") continue;

    const language = inferLanguage(file.filename);
    if (!language) continue;

    const content = await fetchFileContent(ctx, file.filename);
    if (!content) continue;

    filesScanned++;
    const codeFindings = scanCode(content, file.filename, language);
    allFindings.push(...codeFindings);

    const secretFindings = scanSecrets(content, file.filename);
    allSecrets.push(...secretFindings);
  }

  log.info("PR scan complete", {
    repo: `${ctx.owner}/${ctx.repo}`,
    pr: ctx.pullRequestNumber,
    findings: allFindings.length,
    secrets: allSecrets.length,
    filesScanned,
  });

  return { findings: allFindings, secrets: allSecrets, filesScanned };
}

/**
 * Post a review comment on a PR for a SAST finding
 */
export async function postPrReviewComment(ctx: GitHubScanContext, finding: SastFindingResult): Promise<string | null> {
  if (!ctx.pullRequestNumber) return null;

  try {
    const octokit = getOctokit(ctx.installationToken);
    const severityEmoji: Record<string, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🔵",
      info: "⚪",
    };
    const emoji = severityEmoji[finding.severity] || "⚠️";

    const body =
      `${emoji} **SecureNexus SAST: ${finding.title}**\n\n` +
      `**Severity:** ${finding.severity.toUpperCase()} | **Category:** ${finding.category} | **CWE:** ${finding.cweId}\n\n` +
      `${finding.description}\n\n` +
      `**Remediation:** ${finding.remediation}\n\n` +
      `<details><summary>OWASP Reference</summary>\n${finding.owaspCategory}\n</details>`;

    const response = await octokit.pulls.createReviewComment({
      owner: ctx.owner,
      repo: ctx.repo,
      pull_number: ctx.pullRequestNumber,
      body,
      commit_id: ctx.commitSha,
      path: finding.filePath,
      line: finding.startLine,
    });

    return String(response.data.id);
  } catch (err) {
    log.warn("Failed to post PR review comment", {
      file: finding.filePath,
      line: finding.startLine,
      error: String(err),
    });
    return null;
  }
}

/**
 * Post a PR comment summarizing scan results
 */
export async function postScanSummaryComment(
  ctx: GitHubScanContext,
  findings: SastFindingResult[],
  secrets: SecretFindingResult[],
  filesScanned: number,
): Promise<void> {
  if (!ctx.pullRequestNumber) return;

  try {
    const octokit = getOctokit(ctx.installationToken);

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
        `| 🔴 Critical | ${critCount} |\n` +
        `| 🟠 High | ${highCount} |\n` +
        `| 🟡 Medium | ${mediumCount} |\n` +
        `| 🔵 Low | ${lowCount} |\n\n`;

      // Top findings
      const topFindings = findings
        .sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
        })
        .slice(0, 10);

      body += `<details><summary>Top findings</summary>\n\n`;
      for (const f of topFindings) {
        body += `- **${f.severity.toUpperCase()}** \`${f.filePath}:${f.startLine}\` — ${f.title}\n`;
      }
      body += `\n</details>\n\n`;
    } else {
      body += `### SAST Findings\nNo code vulnerabilities detected.\n\n`;
    }

    if (secrets.length > 0) {
      body +=
        `### 🔑 Exposed Secrets\n` + `**${secrets.length} secret(s) detected!** These must be rotated immediately.\n\n`;
      for (const s of secrets) {
        body += `- \`${s.filePath}:${s.line}\` — ${s.secretType} (${s.maskedValue})\n`;
      }
      body += `\n`;
    }

    body += `\n---\n*Powered by SecureNexus Developer Security*`;

    await octokit.issues.createComment({
      owner: ctx.owner,
      repo: ctx.repo,
      issue_number: ctx.pullRequestNumber,
      body,
    });
  } catch (err) {
    log.error("Failed to post scan summary", { error: String(err) });
  }
}

/**
 * Set commit status check
 */
export async function setCommitStatus(
  ctx: GitHubScanContext,
  state: "success" | "failure" | "pending" | "error",
  description: string,
  targetUrl?: string,
): Promise<void> {
  try {
    const octokit = getOctokit(ctx.installationToken);
    await octokit.repos.createCommitStatus({
      owner: ctx.owner,
      repo: ctx.repo,
      sha: ctx.commitSha,
      state,
      description: description.substring(0, 140),
      context: "SecureNexus Security Scan",
      target_url: targetUrl,
    });
  } catch (err) {
    log.warn("Failed to set commit status", { error: String(err) });
  }
}

/**
 * List repositories accessible by the GitHub token
 */
export async function listRepositories(
  token?: string,
): Promise<Array<{ fullName: string; defaultBranch: string; private: boolean }>> {
  try {
    const octokit = getOctokit(token);
    const response = await octokit.repos.listForAuthenticatedUser({
      per_page: 100,
      sort: "updated",
    });

    return response.data.map((r) => ({
      fullName: r.full_name,
      defaultBranch: r.default_branch,
      private: r.private,
    }));
  } catch (err) {
    log.error("Failed to list repositories", { error: String(err) });
    return [];
  }
}

/**
 * Get repository branches
 */
export async function getRepositoryBranches(owner: string, repo: string, token?: string): Promise<string[]> {
  try {
    const octokit = getOctokit(token);
    const response = await octokit.repos.listBranches({
      owner,
      repo,
      per_page: 100,
    });
    return response.data.map((b) => b.name);
  } catch (err) {
    log.error("Failed to list branches", { error: String(err) });
    return [];
  }
}

/**
 * Get tree of files in a repository at a given ref
 */
export async function getRepositoryTree(
  owner: string,
  repo: string,
  ref: string,
  token?: string,
): Promise<Array<{ path: string; type: string; size?: number }>> {
  try {
    const octokit = getOctokit(token);
    const response = await octokit.git.getTree({
      owner,
      repo,
      tree_sha: ref,
      recursive: "true",
    });

    return response.data.tree
      .filter((item) => item.type === "blob" && item.path)
      .map((item) => ({
        path: item.path!,
        type: item.type!,
        size: item.size,
      }));
  } catch (err) {
    log.error("Failed to get repository tree", { error: String(err) });
    return [];
  }
}
