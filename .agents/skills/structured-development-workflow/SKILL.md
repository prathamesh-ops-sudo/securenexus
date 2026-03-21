# Structured Development Workflow

Adapted from the GSD (Get Shit Done) framework's context engineering and spec-driven development patterns. Translated for Devin's toolchain.

## Core Principles

### 1. Context Engineering
Before implementing, ensure you have structured context that prevents drift:
- **Requirements doc** (`~/.devin/requirements.md`): Every acceptance criterion for the current task
- **TodoWrite**: Granular task breakdown — one in_progress at a time, mark complete immediately
- **Existing patterns**: Always read 2-3 existing files of the same type before writing new ones

### 2. Fresh Context Per Sub-Task
For large features (3+ files, multiple domains), treat each sub-task independently:
- Re-read the relevant source files before each sub-task
- Don't rely on memory of file contents from earlier in the session
- Verify imports, types, and conventions fresh each time

### 3. Existence ≠ Implementation
A file existing does not mean the feature works. Verify at 4 levels:
1. **Exists** — File is present at expected path
2. **Substantive** — Content is real implementation, not placeholder
3. **Wired** — Connected to the rest of the system (routes registered, imports resolved, UI navigable)
4. **Functional** — Actually works when invoked (typecheck passes, no runtime errors)

## Planning Phase

### Before Writing Code
1. **Understand the ask**: What exactly needs to be built? What does "done" look like?
2. **Map the codebase**: Read existing patterns in neighboring files — conventions, imports, types, API patterns
3. **Write requirements**: Update `~/.devin/requirements.md` with specific deliverables
4. **Create TodoWrite plan**: Break into atomic tasks, each independently completable and verifiable
5. **Identify dependencies**: Which tasks depend on others? Do backend routes need to exist before frontend?

### Planning Anti-Patterns
- **Skipping exploration**: Writing code without reading existing patterns first
- **Vague todos**: "Build frontend" instead of "Create InteractivePhaseCard component with expand/collapse"
- **Monolithic tasks**: One todo for 500+ lines of code
- **Assuming libraries**: Never assume a library is available — check `package.json` / imports first

## Execution Phase

### Deviation Rules (from GSD)
While executing, you WILL discover work not in the plan. Apply these rules:

**Rule 1 — Auto-fix bugs**: Code doesn't work as intended (broken behavior, type errors, null pointers). Fix inline, no permission needed.

**Rule 2 — Auto-add missing critical functionality**: Missing error handling, no input validation, no auth on protected routes, missing null checks. These aren't "features" — they're correctness requirements. Fix inline.

**Rule 3 — Auto-fix blocking issues**: Missing dependency, wrong types, broken imports, missing env var. Fix inline to unblock the current task.

**Rule 4 — Ask about architectural changes**: Fix requires new DB table, major schema changes, switching libraries, breaking API changes. STOP and ask the user.

**Priority**: Rule 4 → STOP. Rules 1-3 → Fix automatically. Unsure → Rule 4.

**Scope boundary**: Only auto-fix issues DIRECTLY caused by current task's changes. Pre-existing warnings or failures in unrelated files are out of scope.

**Fix attempt limit**: After 3 auto-fix attempts on a single issue, document it and move on.

### Commit Discipline
- One logical change per commit
- Never `git add .` — stage specific files only
- Commit message format: `type(scope): concise description`
- Types: `feat`, `fix`, `refactor`, `chore`, `docs`, `test`
- Run pre-commit hooks (prettier, eslint) — if hook modifies files, commit those changes too

### Analysis Paralysis Guard
If you've made 5+ consecutive read/search calls without any edit/write action:
1. State in one sentence why you haven't written anything yet
2. Either write code (you have enough context) or report "blocked" with the specific missing information
3. Do NOT continue reading endlessly

## Verification Phase

### Stub Detection Patterns
Before claiming any feature is complete, scan for these red flags:

**Comment-based stubs:**
- `TODO`, `FIXME`, `XXX`, `HACK`, `PLACEHOLDER`
- `implement later`, `coming soon`, `will be added`

**Empty/trivial implementations:**
- `return null`, `return undefined`, `return {}`, `return []`
- `onClick={() => {}}` — empty event handlers
- `console.log('clicked')` — log-only handlers

**Hardcoded values where dynamic expected:**
- Hardcoded IDs, counts, or display values
- Mock data instead of API calls
- Static arrays instead of query results

### Wiring Verification
For every new feature, verify the full chain:

| Chain | Check |
|-------|-------|
| Route registration | Is the route file imported and registered in `index.ts`? |
| Frontend → API | Does the component call `apiRequest()` with the correct endpoint? |
| API → Database | Does the route handler query with `orgId` filter? |
| Navigation | Is the page accessible via sidebar or direct URL? |
| Types | Do frontend interfaces match backend response shapes? |

### Quality Checklist (Run Before Every Commit)
1. `npx prettier --write <files>` — Format
2. `npx tsc --noEmit` — Typecheck (zero errors required)
3. `npx eslint <files>` — Lint (zero errors required, warnings OK unless user asks to fix)
4. Verify no `apiFetch`, `Any`, `getattr`, or other lazy patterns introduced
5. Check that imports are at top of file, not nested inside functions

## SecureNexus-Specific Patterns

### API Call Pattern
```typescript
// GET requests in useQuery:
queryFn: () => apiRequest("GET", `/api/endpoint?param=${value}`).then(r => r.json())

// POST/PUT/DELETE in useMutation:
mutationFn: (body) => apiRequest("POST", "/api/endpoint", body)
```

### Backend Route Pattern
```typescript
// Always include auth middleware chain:
app.get("/api/feature/endpoint",
  isAuthenticated, resolveOrgContext, requireOrgId,
  async (req, res) => {
    const orgId = getOrgId(req);
    // Always filter by orgId for multi-tenant isolation
  }
);
```

### Frontend Page Pattern
- One file per feature in `client/src/pages/`
- Use shadcn/ui components from `@/components/ui/`
- Use `useQuery` / `useMutation` from `@tanstack/react-query`
- Use `apiRequest` from `@/lib/queryClient`
- Use `toast` from `@/hooks/use-toast` for user feedback
- Dark mode: Use Tailwind `dark:` variants and CSS variables

## Anti-Patterns to Avoid

| Anti-Pattern | Correct Approach |
|-------------|------------------|
| Writing code before reading existing patterns | Read 2-3 neighboring files first |
| Using `apiFetch` or other non-existent functions | Check `queryClient.ts` for actual exports |
| Importing inside functions | All imports at top of file |
| Using `Any` type | Look at actual types and use them |
| Committing with `git add .` | Stage specific files only |
| Skipping typecheck before commit | Always run `npx tsc --noEmit` |
| Claiming done without verification | Run the quality checklist |
| Fixing pre-existing warnings | Only fix errors caused by your changes |
| Adding packages without checking | Verify package exists in `package.json` first |
