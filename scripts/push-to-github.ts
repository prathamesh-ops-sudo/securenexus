import { getUncachableGitHubClient } from "../server/github";
import * as fs from "fs";
import * as path from "path";

const REPO_NAME = "ATS-AI-SEC";
const REPO_DESCRIPTION = "SecureNexus - AI-Powered Security Orchestration & Intelligence Platform";

const IGNORE_PATTERNS = [
  "node_modules", "dist", ".DS_Store", "server/public", "*.tar.gz",
  ".git", ".cache", ".local", ".config", ".upm", "generated-icon.png",
  "scripts/push-to-github.ts", ".replit", "replit.nix", "replit_agent",
  ".breakpoints", "attached_assets", "snippets",
];

function shouldIgnore(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return IGNORE_PATTERNS.some((pattern) => {
    if (pattern.startsWith("*")) return normalized.endsWith(pattern.slice(1));
    return normalized === pattern || normalized.startsWith(pattern + "/");
  });
}

function getAllFiles(dir: string, baseDir: string = dir): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(baseDir, fullPath);
    if (shouldIgnore(relativePath)) continue;
    if (entry.isDirectory()) files.push(...getAllFiles(fullPath, baseDir));
    else files.push(relativePath);
  }
  return files;
}

async function main() {
  const octokit = await getUncachableGitHubClient();
  const { data: user } = await octokit.users.getAuthenticated();
  const owner = user.login;
  console.log(`Authenticated as: ${owner}`);

  let repo;
  try {
    const { data } = await octokit.repos.get({ owner, repo: REPO_NAME });
    repo = data;
    console.log(`Repository exists: ${repo.html_url}`);
  } catch {
    const { data } = await octokit.repos.createForAuthenticatedUser({
      name: REPO_NAME,
      description: REPO_DESCRIPTION,
      private: false,
      auto_init: true,
    });
    repo = data;
    console.log(`Created repository: ${repo.html_url}`);
    await new Promise(r => setTimeout(r, 3000));
  }

  const defaultBranch = repo.default_branch || "main";
  console.log(`Default branch: ${defaultBranch}`);

  // Delete all non-default branches
  try {
    const { data: branches } = await octokit.repos.listBranches({ owner, repo: REPO_NAME, per_page: 100 });
    for (const branch of branches) {
      if (branch.name !== defaultBranch) {
        try {
          await octokit.git.deleteRef({ owner, repo: REPO_NAME, ref: `heads/${branch.name}` });
          console.log(`Deleted branch: ${branch.name}`);
        } catch (e: any) {
          console.log(`Could not delete branch ${branch.name}: ${e.message}`);
        }
      }
    }
    console.log("All non-default branches deleted");
  } catch (e: any) {
    console.log(`Branch cleanup skipped: ${e.message}`);
  }

  // Check if repo has any commits
  let isEmpty = false;
  try {
    await octokit.repos.listCommits({ owner, repo: REPO_NAME, per_page: 1 });
  } catch (e: any) {
    if (e.status === 409) isEmpty = true;
  }

  if (isEmpty) {
    console.log("Repo is empty, initializing with README...");
    await octokit.repos.createOrUpdateFileContents({
      owner,
      repo: REPO_NAME,
      path: "README.md",
      message: "Initial commit",
      content: Buffer.from("# SecureNexus\n\nAI-Powered Security Orchestration & Intelligence Platform\n").toString("base64"),
    });
    await new Promise(r => setTimeout(r, 2000));
    console.log("Initialized repo with README");
  }

  const workspaceDir = process.cwd();
  const files = getAllFiles(workspaceDir);
  console.log(`Found ${files.length} files to push`);

  const tree = [];
  for (let i = 0; i < files.length; i++) {
    const filePath = files[i];
    const fullPath = path.join(workspaceDir, filePath);
    const content = fs.readFileSync(fullPath);
    const isBinary = content.some((byte) => byte === 0);

    const { data: blob } = await octokit.git.createBlob({
      owner, repo: REPO_NAME,
      content: isBinary ? content.toString("base64") : content.toString("utf-8"),
      encoding: isBinary ? "base64" : "utf-8",
    });
    tree.push({ path: filePath, mode: "100644" as const, type: "blob" as const, sha: blob.sha });

    if ((i + 1) % 20 === 0) console.log(`  Uploaded ${i + 1}/${files.length} files...`);
  }
  console.log(`  Uploaded all ${files.length} files`);

  // Get current HEAD
  const { data: ref } = await octokit.git.getRef({ owner, repo: REPO_NAME, ref: `heads/${defaultBranch}` });
  const parentSha = ref.object.sha;

  // Create tree (without base_tree to do a full replacement)
  const { data: treeData } = await octokit.git.createTree({ owner, repo: REPO_NAME, tree });

  // Create commit
  const { data: commit } = await octokit.git.createCommit({
    owner, repo: REPO_NAME,
    message: "SecureNexus Phase 0-5: Foundation, data models, ingestion, normalization, SOC dashboard, AI correlation engine",
    tree: treeData.sha,
    parents: [parentSha],
  });

  // Force update ref to replace all content
  await octokit.git.updateRef({ owner, repo: REPO_NAME, ref: `heads/${defaultBranch}`, sha: commit.sha, force: true });

  console.log(`\nSuccessfully pushed to: ${repo!.html_url}`);
  console.log(`Commit: ${commit.sha}`);
}

main().catch(console.error);
