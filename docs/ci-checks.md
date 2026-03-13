# SecureNexus CI/CD Check Catalogue

> 110 checks across 11 categories. Each entry lists the check, why it matters for this codebase, and the tool/method to implement it.

---

## Category 1: Code Quality (16 checks)

| #   | Check                                                   | Why                                                                            | Tool/Method                                                              |
| --- | ------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| 1   | TypeScript strict typecheck                             | Catches type errors before runtime                                             | `tsc --noEmit`                                                           |
| 2   | ESLint — errors fatal                                   | Enforces coding standards, catches bugs statically                             | `eslint . --max-warnings=0`                                              |
| 3   | Prettier format verification                            | Consistent formatting, removes style debates in PRs                            | `prettier --check`                                                       |
| 4   | No unused exports                                       | Dead exports indicate dead code paths or forgotten refactors                   | `ts-prune`                                                               |
| 5   | No unused variables / imports                           | Keeps codebase lean; unused imports can mask real bugs                         | ESLint `no-unused-vars` (already in config — enforce `error` not `warn`) |
| 6   | Cyclomatic complexity limit                             | Complex functions in `correlation-engine.ts`, `ai.ts` are high-risk; cap at 15 | ESLint `complexity` rule                                                 |
| 7   | Max file line length                                    | `routes.ts` is already massive; prevent further unchecked growth               | ESLint `max-lines`                                                       |
| 8   | No `console.log` in production paths                    | Log noise + potential PII leakage in a security product                        | ESLint `no-console` on `server/**`                                       |
| 9   | No `debugger` statements                                | Pauses production process                                                      | ESLint `no-debugger`                                                     |
| 10  | No circular dependencies                                | Circular deps cause subtle init-order bugs in Express route registration       | `madge --circular`                                                       |
| 11  | Import order consistency                                | Predictable import order makes diffs cleaner                                   | `eslint-plugin-import` order rule                                        |
| 12  | Duplicate code detection                                | Copy-paste in route handlers leads to divergent bug fixes                      | `jscpd --threshold 5`                                                    |
| 13  | Spell check on identifiers/comments                     | Typos in API field names (`recieved` vs `received`) break client contracts     | `cspell`                                                                 |
| 14  | No `TODO`/`FIXME` in `server/auth/` or `server/rbac.ts` | Security-critical paths must not have deferred work                            | `grep -rn 'TODO\|FIXME' server/auth/ server/rbac.ts`                     |
| 15  | TypeScript type coverage >= 90%                         | Low type coverage defeats the purpose of TypeScript                            | `type-coverage --at-least 90`                                            |
| 16  | No `any` casts in shared schema                         | `shared/schema.ts` is the contract between client and server; `any` breaks it  | `grep -n ': any' shared/` as a count gate                                |

---

## Category 2: Testing (16 checks)

| #   | Check                               | Why                                                                                    | Tool/Method                                                                                         |
| --- | ----------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 17  | Unit tests pass                     | Baseline correctness                                                                   | `vitest run`                                                                                        |
| 18  | Line coverage >= 60%                | Current threshold of 10% is a no-op                                                    | `vitest run --coverage` with `lines: 60`                                                            |
| 19  | Branch coverage >= 50%              | Untested branches hide null-path bugs                                                  | `branches: 50` in vitest coverage config                                                            |
| 20  | Function coverage >= 70%            | Ensures exported functions are exercised                                               | `functions: 70`                                                                                     |
| 21  | Statement coverage >= 60%           | Broad floor                                                                            | `statements: 60`                                                                                    |
| 22  | No skipped tests (`.skip`)          | Skipped tests are forgotten tests                                                      | `grep -rn '\.skip\|xit\|xdescribe' tests/` failing if found                                         |
| 23  | No `.only` tests                    | Accidentally committed `.only` silently skips the rest of the suite                    | `grep -rn '\.only\|fit\|fdescribe' tests/`                                                          |
| 24  | E2E tests pass                      | Validates full user flows (login, alert triage, incident creation)                     | `playwright test`                                                                                   |
| 25  | Accessibility tests pass (axe-core) | WCAG compliance; already have `@axe-core/playwright` as a dep                          | `axe-core` via Playwright on key pages                                                              |
| 26  | API smoke tests on staging          | Validates actual deployed API, not mocks                                               | curl suite against `/api/health`, `/api/alerts`, `/api/incidents`                                   |
| 27  | API smoke tests on UAT              | Same validation one env further                                                        | Same curl suite, UAT URL                                                                            |
| 28  | No test file without assertions     | Test files that run but assert nothing give false confidence                           | `grep -L 'expect\|assert' tests/**/*.test.ts`                                                       |
| 29  | Snapshot tests not silently updated | Stale snapshots hide regressions in rendered components                                | `vitest run --reporter=verbose` — fail if snapshot diff present without explicit `--updateSnapshot` |
| 30  | Integration tests pass              | `storage.ts` DB query functions tested against a real PG instance (via docker-compose) | `vitest run --project=integration` with `docker-compose up -d`                                      |
| 31  | Flaky test detection                | Run unit suite 3× on PR if it failed once; fails only if it fails 2/3 times            | `vitest run` retried via a bash loop                                                                |
| 32  | Test execution time budget          | A suite taking > 5 min means someone added a real sleep                                | `timeout 300 vitest run`                                                                            |

---

## Category 3: Security (22 checks)

| #   | Check                                             | Why                                                                                            | Tool/Method                                                                                                       |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 33  | Gitleaks secret scanning (full history)           | Current regex scan only checks working tree, not git history                                   | `gitleaks/gitleaks-action@v2`                                                                                     |
| 34  | `npm audit` — critical severity blocks deploy     | Critical CVEs in prod deps are unacceptable                                                    | `npm audit --omit=dev --audit-level=critical`                                                                     |
| 35  | `npm audit` — high severity blocks PR merge       | High CVEs should require an explicit decision to accept                                        | `npm audit --omit=dev --audit-level=high`                                                                         |
| 36  | CodeQL SAST — JavaScript/TypeScript               | Finds injection, path traversal, prototype pollution                                           | `github/codeql-action` with `security-extended` queries                                                           |
| 37  | Semgrep SAST — Express-specific rules             | Catches Express antipatterns CodeQL misses (unvalidated redirects, res.send with user input)   | `semgrep --config=p/expressjs`                                                                                    |
| 38  | Semgrep SAST — React-specific rules               | `dangerouslySetInnerHTML`, missing key props, eval in components                               | `semgrep --config=p/react`                                                                                        |
| 39  | No `eval()` usage                                 | Remote code execution vector                                                                   | ESLint `no-eval` on all files                                                                                     |
| 40  | No `dangerouslySetInnerHTML` without sanitization | XSS in a security dashboard would be severe                                                    | Custom ESLint rule or `semgrep` pattern                                                                           |
| 41  | SQL injection pattern scan                        | Detect template-literal SQL queries that bypass Drizzle's parameterization                     | `grep -rn 'db.execute.*\${' server/`                                                                              |
| 42  | Path traversal pattern scan                       | File operations in `server/` using unsanitized user input                                      | Semgrep rule `path-traversal`                                                                                     |
| 43  | `Math.random()` in security context               | Non-cryptographic randomness in token generation is a security bug                             | `grep -rn 'Math\.random' server/auth/ server/routes/`                                                             |
| 44  | Insecure `http://` in production config           | All inter-service calls should be TLS                                                          | `grep -rn 'http://' server/ --include='*.ts'` excluding localhost/test                                            |
| 45  | Helmet.js headers present                         | Validates CSP, HSTS, X-Frame-Options are configured                                            | Runtime check or static scan of `server/index.ts`                                                                 |
| 46  | CORS not set to wildcard `*` in production        | A security product with `Access-Control-Allow-Origin: *` would be embarrassing                 | `grep -n "cors.*\*\|origin.*\*" server/`                                                                          |
| 47  | Every route has authentication middleware         | Unauthenticated route accidentally added to `server/routes.ts`                                 | Static analysis: every `app.get/post/put/delete` must be preceded by `requireAuth` or be in an explicit allowlist |
| 48  | RBAC enforcement on sensitive routes              | `response_actions`, `api_keys`, `settings` routes must call `requirePermission`                | Grep for route definitions + cross-reference against RBAC-required route list                                     |
| 49  | Webhook HMAC validation present                   | Replayed webhooks without signature check can trigger playbooks                                | Verify `server/routes/webhooks.ts` still imports and calls signature verification                                 |
| 50  | Rate limiting on auth endpoints                   | Brute-force protection on `/api/auth/login`                                                    | Static check that `express-rate-limit` is applied to auth routes                                                  |
| 51  | Zod validation on all ingest endpoints            | `/api/ingest/alert` and `/api/ingest/alerts/bulk` accepting unsanitized input could corrupt DB | Grep for `schema.parse` or `schema.safeParse` on ingest route handlers                                            |
| 52  | Session secret not hardcoded                      | Rotating session secret is in AWS Secrets Manager — verify code reads from env                 | `grep -n 'SESSION_SECRET.*=' server/` — fail if literal value present                                             |
| 53  | PII engine applied before logging                 | `server/pii-engine.ts` must be called before any log statement containing user data            | Semgrep rule detecting `console.log`/`logger.info` with alert/user fields not routed through PII engine           |
| 54  | No `process.env` reads outside config files       | Scattered env reads are hard to audit; they must go through a central config module            | `grep -rn 'process\.env\.' server/ --include='*.ts'` cross-referenced against allowed files                       |

---

## Category 4: Container & Supply Chain (10 checks)

| #   | Check                                    | Why                                                                    | Tool/Method                                                                            |
| --- | ---------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| 55  | Docker build succeeds                    | Catches Dockerfile syntax errors and missing files                     | `docker build .`                                                                       |
| 56  | Trivy — CRITICAL CVEs in image           | CVEs in the base image or installed packages                           | `trivy image --severity CRITICAL --exit-code 1`                                        |
| 57  | Trivy — HIGH CVEs block promotion to UAT | High CVEs require sign-off before UAT                                  | `trivy image --severity HIGH --exit-code 1` on UAT deploy gate                         |
| 58  | No root user in container                | Running as root in a container is a privilege escalation risk          | `docker inspect` checking `User` field; or Trivy misconfiguration scan                 |
| 59  | Multi-stage build verification           | Ensures dev dependencies and source maps are not in the prod image     | Verify Dockerfile has `FROM ... AS build` and final `FROM` doesn't copy `node_modules` |
| 60  | `.dockerignore` completeness             | `.env`, `*.key`, `migrations/` secrets must not be in build context    | Check `.dockerignore` contains `.env*`, `*.pem`, `*.key`, `.git`                       |
| 61  | No secrets in Docker layer history       | `docker history --no-trunc` to detect secrets passed as `--build-arg`  | `docker history` scan + `grep -i 'secret\|password\|key'`                              |
| 62  | Image size regression                    | Image growing unexpectedly signals accidental inclusion of large files | Record size in bytes; fail if > 20% larger than previous tag                           |
| 63  | SBOM generation (CycloneDX)              | Software Bill of Materials required for enterprise SOC 2 audits        | `syft image <tag> -o cyclonedx-json` as a build artifact                               |
| 64  | Image signing with cosign                | Prevents image substitution attacks between ECR and EKS pull           | `cosign sign --key ${{ secrets.COSIGN_KEY }} <image>` post-push                        |

---

## Category 5: Dependencies (10 checks)

| #   | Check                                            | Why                                                                     | Tool/Method                                                                                 |
| --- | ------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------- |
| 65  | License compliance — no GPL in prod              | GPL in a commercial SaaS product is a legal liability                   | `license-checker --onlyAllow "MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC;CC0-1.0"`        |
| 66  | No deprecated packages                           | Deprecated packages stop receiving security fixes                       | `npx npm-check --skip-unused` or `npm outdated` with a fail threshold                       |
| 67  | Lock file committed and consistent               | `package-lock.json` must match `package.json`                           | `npm ci` will fail if inconsistent — verify this is the install command in all jobs (it is) |
| 68  | No duplicate packages (semver ranges)            | Two versions of `zod` or `drizzle-orm` can cause type incompatibilities | `npm ls --all 2>&1                                                                          | grep 'UNMET\|deduped' && dedupe check`       |
| 69  | GitHub Actions pinned to SHA                     | `uses: actions/checkout@v4` can be hijacked; pin to SHA                 | `grep -rn 'uses:' .github/workflows/                                                        | grep -v '@[a-f0-9]\{40\}'` — report unpinned |
| 70  | Dependabot alerts resolved within SLA            | Open critical Dependabot alerts older than 7 days block prod deploy     | GitHub API check on open Dependabot alerts severity                                         |
| 71  | No `patch-package` patches older than 90 days    | Stale patches indicate an upstream fix was never adopted                | Check `patches/` directory timestamps if present                                            |
| 72  | Frontend bundle size budget                      | Bundle exceeding budget means users on slow connections see degraded UX | `vite-bundle-visualizer` or `bundlesize` with thresholds per chunk                          |
| 73  | No new direct deps without PR description update | Tracks supply chain additions intentionally                             | PR template check (manual/honour system enforced by CODEOWNERS review)                      |
| 74  | `npm install` never used in CI (only `npm ci`)   | `npm install` can silently update lock file; `npm ci` is deterministic  | `grep -rn 'npm install' .github/workflows/` failing if found                                |

---

## Category 6: Database & Migrations (10 checks)

| #   | Check                                            | Why                                                                                                  | Tool/Method                                                                                                      |
| --- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------- |
| 75  | Schema drift detection                           | `shared/schema.ts` changed without a corresponding migration file                                    | `drizzle-kit check` — exits non-zero if migration needed                                                         |
| 76  | No destructive DDL without explicit label        | `DROP COLUMN`, `DROP TABLE`, `TRUNCATE` in a migration must be intentional                           | `grep -n 'DROP\|TRUNCATE\|ALTER.*DROP' migrations/*.sql` — fail unless PR has label `breaking-migration`         |
| 77  | Migration files are append-only                  | Editing an existing migration file after it has been applied is dangerous                            | `git diff origin/main -- migrations/                                                                             | grep '^-'                              | grep -v '^---'` — fail if deletions in existing migration files |
| 78  | Migration naming convention                      | All files must match `NNNN_<snake_case_description>.sql`                                             | `ls migrations/                                                                                                  | grep -vE '^[0-9]{4}_[a-z0-9_]+\.sql$'` |
| 79  | Foreign keys have indexes                        | Missing indexes on FK columns cause full table scans on JOINs                                        | Static analysis of `shared/schema.ts` — every `references()` column should have a corresponding `.index()`       |
| 80  | No `db.execute` with string interpolation        | Template-literal SQL bypasses Drizzle's parameterization                                             | `grep -rn 'db\.execute.*\`' server/`                                                                             |
| 81  | Rollback script exists for each migration        | Enables recovery from a failed migration in production                                               | Check `scripts/migration-rollback.ts` handles the latest migration index                                         |
| 82  | Dry-run migration succeeds                       | Validates the migration SQL is valid without applying it                                             | `npm run db:migrate:dry-run` in CI against a test database                                                       |
| 83  | No `db:push` called in non-dev environments      | `drizzle-kit push` applies schema without a migration file — dangerous in prod                       | `grep -rn 'db:push\|drizzle-kit push' .github/workflows/ server/ scripts/` — fail if found outside `dev` context |
| 84  | Unique constraints present on deduplication keys | `alerts` table deduplicates on `(orgId, source, sourceEventId)` — verify this index exists in schema | Static check of `shared/schema.ts` for `uniqueIndex` on those columns                                            |

---

## Category 7: Infrastructure & Kubernetes (10 checks)

| #   | Check                                      | Why                                                                 | Tool/Method                                                                                       |
| --- | ------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| 85  | kubeconform validation                     | Validates all manifests in `k8s/` against the Kubernetes API schema | `kubeconform -strict -summary k8s/`                                                               |
| 86  | kube-score security scoring                | Scores manifests for security best practices; fails below threshold | `kube-score score k8s/**/*.yml --exit-one-on-warning`                                             |
| 87  | CPU/memory limits set on all containers    | Missing limits allow one noisy pod to starve others                 | `kube-score` or `grep` for `resources:` block in all rollout YAMLs                                |
| 88  | Liveness and readiness probes present      | Missing probes mean Kubernetes can't detect a stuck pod             | Check all `rollout.yml` files contain `livenessProbe` and `readinessProbe`                        |
| 89  | PodDisruptionBudget present for production | Ensures zero-downtime rolling updates                               | Verify `k8s/production/pdb.yml` exists and `minAvailable >= 1`                                    |
| 90  | Network policies defined                   | `k8s/base/network-policy.yml` must be applied before deployment     | Verify it's in the deploy step (it is) — also validate its contents with kubeconform              |
| 91  | No `privileged: true` containers           | Privileged containers can escape to the host                        | `grep -rn 'privileged: true' k8s/` — fail if found                                                |
| 92  | No `hostPath` volumes                      | Mounts from host filesystem can expose sensitive data               | `grep -rn 'hostPath' k8s/` — fail if found                                                        |
| 93  | AWS OIDC instead of static credentials     | Eliminate long-lived `AWS_ACCESS_KEY_ID` from GitHub Secrets        | Replace `aws-access-key-id` / `aws-secret-access-key` with `role-to-assume` in all workflow steps |
| 94  | Argo Rollout analysis template present     | Canary without automated analysis is just a slow deploy             | Verify `k8s/production/analysis-template.yml` exists and references Prometheus metrics            |

---

## Category 8: API & Schema Contracts (8 checks)

| #   | Check                                             | Why                                                                                         | Tool/Method                                                                                               |
| --- | ------------------------------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 95  | OpenAPI spec validates (no broken `$ref`)         | `server/openapi.ts` must be self-consistent                                                 | `swagger-cli validate` or `redocly lint`                                                                  |
| 96  | All routes documented in OpenAPI                  | Undocumented routes become shadow API surface                                               | Diff between routes registered in Express vs. paths in OpenAPI spec                                       |
| 97  | `ApiEnvelope<T>` used on all route responses      | Canonical envelope is the client contract — deviations break the SDK                        | `grep -rn 'res\.json\|res\.send' server/routes/` — fail if not delegating to `reply()` / `sendEnvelope()` |
| 98  | Deprecation headers on legacy endpoints           | `legacyEndpoint()` middleware must be applied to deprecated routes                          | `grep -rn 'legacyEndpoint' server/routes.ts` — cross-reference against known deprecated paths             |
| 99  | No breaking schema changes without version bump   | Removing a field from `ApiEnvelope` response breaks existing clients                        | `ts-json-schema-generator` diff between PR branch and main                                                |
| 100 | Zod schema and TypeScript type are in sync        | `drizzle-zod` generated types must match manual TypeScript interfaces in `shared/schema.ts` | `tsc --noEmit` catches most cases; also `drizzle-kit generate` to verify no unexpected diff               |
| 101 | Idempotency key support on all mutating endpoints | Prevents duplicate alert creation on network retry — must stay present                      | `grep -rn 'idempotency\|X-Idempotency-Key' server/routes.ts` — fail if count drops below expected         |
| 102 | Rate limit headers in API responses               | Clients need `X-RateLimit-*` headers to implement backoff                                   | Verify `express-rate-limit` `standardHeaders: true` is configured                                         |

---

## Category 9: Performance & Observability (8 checks)

| #   | Check                                             | Why                                                                                | Tool/Method                                                                                                 |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 103 | Frontend bundle size per chunk < 500KB            | Large chunks delay initial load for SOC analysts on corp networks                  | `bundlesize` or `vite-bundle-analyzer` with thresholds                                                      |
| 104 | Lighthouse CI performance score >= 70             | Dashboard is the primary UX surface — slow dashboards lose users                   | `lhci autorun` against staging after deploy                                                                 |
| 105 | Lighthouse CI accessibility score >= 90           | Compliance requirement for enterprise customers                                    | Same `lhci autorun`                                                                                         |
| 106 | Build time regression (> 20% slower)              | Slow builds are a developer experience tax                                         | Record build time each run; alert if significantly slower                                                   |
| 107 | All new API routes have structured logging        | Unlogged endpoints are invisible in Grafana                                        | `grep -n 'router\.\(get\|post\|put\|delete\|patch\)' server/routes/` — cross-reference against logger calls |
| 108 | SLO alerting rules valid YAML                     | `k8s/monitoring/alerting-rules.yml` must parse as valid Prometheus rules           | `promtool check rules k8s/monitoring/alerting-rules.yml`                                                    |
| 109 | Prometheus metrics endpoint reachable post-deploy | `/api/ops/metrics` must respond 200 in staging smoke test                          | Add to staging smoke test suite alongside health check                                                      |
| 110 | Audit log chain hash integrity                    | `server/storage.ts` tamper-evident audit log chain must not be broken by refactors | Unit test that inserts 5 audit entries and verifies hash chain                                              |

---

## Category 10: Git & Process Hygiene (6 checks)

| #   | Check                                              | Why                                                                                                | Tool/Method                                                              |
| --- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | --- | ----- | ---- | ---- | -------- | ------------------------------- |
| 111 | Commit messages follow Conventional Commits        | Enables automatic changelog generation and semantic versioning                                     | `commitlint` with `@commitlint/config-conventional`                      |
| 112 | PR title follows Conventional Commits              | PR title becomes the squash commit message                                                         | GitHub Action checking PR title via regex                                |
| 113 | PR has a linked issue                              | Traceability; prevents mystery changes                                                             | PR template + GitHub Action checking for `Closes #NNN` or `Fixes #NNN`   |
| 114 | Branch name convention (`feat/`, `fix/`, `chore/`) | Consistent branch names make git log readable                                                      | `grep -E '^(feat                                                         | fix | chore | docs | test | refactor | security)/' <<< "$BRANCH_NAME"` |
| 115 | No direct pushes to `main` (branch protection)     | All changes must go through PR review                                                              | GitHub branch protection rule (not a workflow check — a repo setting)    |
| 116 | CODEOWNERS review required for security paths      | Changes to `server/auth/`, `server/rbac.ts`, `server/pii-engine.ts` require security team approval | `.github/CODEOWNERS` entries for those paths (already partially present) |

---

## Summary by Phase

```
PR Gate (runs on every pull_request → main):
  Checks: 1–16, 17–23, 33–43, 65–74, 75–84, 95–102, 111–116
  Goal: Block merging broken or insecure code

Post-Merge / Staging Deploy (runs on push main):
  Checks: 55–64 (container), 85–94 (k8s), 103–106 (perf)
  Goal: Validate the artifact before promotion

UAT Gate (manual workflow_dispatch, after staging passes):
  Checks: 26–27 (API smoke), 56–57 (Trivy HIGH), 107–110 (observability)
  Goal: Final validation before production

Weekly Sweep (cron, catches drift):
  Checks: 33–54 (full security suite), 34–35 (audit with fresh DB), 36 (CodeQL)
  Goal: Catch slow-burn issues that don't fail fast
```

---

## Quick-win Implementation Order

1. **PR gate workflow** — adds checks 1–23 to every PR (currently zero)
2. **Gitleaks** — replaces the current 4-regex scanner (check 33)
3. **Fix `npm audit`** — remove `|| true`, enforce high severity (checks 34–35)
4. **Trivy** — add to post-push job (checks 56–57)
5. **`drizzle-kit check`** — migration drift on every PR (check 75)
6. **kubeconform + kube-score** — k8s manifest validation (checks 85–86)
7. **AWS OIDC** — remove static credentials (check 93)
8. **Raise coverage thresholds** — 10% → 60% lines (checks 18–21)
9. **License checker** — one-liner npm script (check 65)
10. **commitlint** — PR title + commit message gate (checks 111–112)
