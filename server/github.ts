import { Octokit } from '@octokit/rest';
import { config } from './config';

export async function getUncachableGitHubClient() {
  if (!config.githubToken) {
    throw new Error('GITHUB_TOKEN environment variable is not set');
  }
  return new Octokit({ auth: config.githubToken });
}
