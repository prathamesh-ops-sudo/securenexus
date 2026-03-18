# Testing SecureNexus Staging

## Devin Secrets Needed
- `AWS_ACCESS_KEY_ID` — AWS access key for ECR and EKS
- `AWS_SECRET_ACCESS_KEY` — AWS secret key
- `GITHUB_TOKEN` — GitHub token for repo access

## Staging Environment
- URL: `https://staging.aricatech.xyz/`
- EKS Cluster: `securenexus` in `us-east-1`
- ECR: `557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus`
- Namespace: `staging`
- Deployment: `securenexus`

## Deploying to Staging

The GitHub Actions CI/CD pipeline may not auto-deploy. If staging needs manual deployment:

1. **Login to ECR:**
   ```bash
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 557845624595.dkr.ecr.us-east-1.amazonaws.com
   ```

2. **Build Docker image:**
   ```bash
   docker build -t 557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus:<tag> .
   ```
   Build takes ~90-100 seconds. The `chown` step in Dockerfile can take 30+ seconds.

3. **Push to ECR:**
   ```bash
   docker push 557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus:<tag>
   ```

4. **Update staging deployment:**
   ```bash
   kubectl set image deployment/securenexus securenexus=557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus:<tag> -n staging
   kubectl -n staging rollout status deployment/securenexus --timeout=300s
   ```

## Prerequisites

- `kubectl` must be installed. If missing: `curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo mv kubectl /usr/local/bin/ && sudo chmod +x /usr/local/bin/kubectl`
- `aws-cli` v2 is required (v1 generates `v1alpha1` API version that newer kubectl rejects). If aws-cli v1 is installed, upgrade to v2.
- EKS kubeconfig: `aws eks update-kubeconfig --name securenexus --region us-east-1`

## Local Dev Server

### Starting the Dev Server
```bash
set -a && source .env && set +a && npm run dev
```
- Runs on port 5000 (Vite + Express backend)
- PostgreSQL must be running locally
- Rate limiter: In dev mode, `express-rate-limit` v7 is configured to skip all requests (`skip: () => true`). If you see 429 errors blocking all requests, check that the rate limiter config uses `limit` (not `max`) and has `skip: () => true` for dev mode.

### Known Dev Mode Issues
- **express-rate-limit v7**: `max: 0` blocks ALL requests (v6 treated it as unlimited). The fix is to use `skip: () => true` in dev mode and `validate: { limit: false }` to suppress the WRN_ERL_MAX_ZERO warning.

## Testing UI Changes

### Test User Credentials
- A test user `testuser-devin@aricatech.com` / `TestPass123!` was created during a previous session. It may still be available.
- If the test user doesn't work, create a new one via the registration flow at the staging URL.

### Native Sensors Testing

**Supported Platforms (7 total):**
- Linux, Windows, macOS, iOS, Android, Docker, Kubernetes

**Testing Flow:**
1. Navigate to `/native-sensors` via sidebar: Standalone Security → Native Sensors
2. Click "Register Sensor" to open the registration dialog
3. Enter hostname and select platform from dropdown
4. Platform capabilities and requirements display automatically based on selection
5. After registration, click the sensor row to open details, then "Generate Install Command"
6. Verify install command format matches platform (iOS: MDM/AppConfig XML, Android: EMM/ADB commands)
7. Check Deployment Guide tab — all 7 platform buttons should be visible with correct emoji icons

**Platform-Specific Verification:**
- iOS: Capabilities include jailbreak detection, MDM compliance, NEFilterDataProvider. Requirements: iOS 15+, MDM/TestFlight.
- Android: Capabilities include UsageStatsManager, VpnService, root detection. Requirements: Android 10+ (API 29+), Device Owner/Profile Owner.

**Browser Automation Tips:**
- Platform dropdown items may timeout with `devinid` clicks. Use coordinate-based clicks as fallback for dropdown selection.
- After registering a sensor, the dialog shows credentials with install command. Click "Done" to close.

### Onboarding 5th Step Testing

**Navigation:** Sidebar → Admin & Settings → Onboarding → `/onboarding`

**Verification Points:**
- Page header shows "X of 5 core steps completed" (totalSteps must be 5, not 4)
- 5 cards visible: Integrations, Ingestion, Endpoints, CSPM, Deploy native sensors
- "Deploy native sensors" card shows sensor count and green checkmark when count > 0
- "Go to Native Sensors" button navigates back to `/native-sensors`
- Frontend fallback: `data?.totalSteps ?? 5` (was previously 4, fixed in PR #445)

### Coming Soon Pages (501 Detection)
These pages detect 501 responses from stub endpoints and show "Coming Soon" UI:
- `/cve-browser` — via sidebar: Watch & Recon → CVE Database
- `/ai-budget-controls` — via sidebar: AI Analyst → Budget & Limits
- `/job-queue-dashboard` — via sidebar: Data & Integrations → Job Queue
- `/dr-drill-scheduler` — direct URL only (not in sidebar)
- `/post-incident-review` — direct URL only (not in sidebar)
- `/role-dashboard`, `/usage-metering-analytics`, `/data-lifecycle` — additional Coming Soon pages

### 501 Detection Pattern
The frontend detects 501 via `error?.message?.startsWith("501:")`. This depends on `throwIfResNotOk` in `queryClient.ts` formatting errors as `"${status}: ${text}"`. If this contract changes, Coming Soon detection will break.

### Testing Tips
- Pages may take 5-8 seconds to load after navigation — wait before checking content
- The skeleton loading state appears first, then the actual content renders
- After a deployment rollout, the first page load may be slow due to pod startup
- Use screen recording to capture the full test flow for the user
- Annotate recordings at each major test step for clarity
- For local testing, ensure PostgreSQL is running and `.env` file is sourced before starting the dev server
