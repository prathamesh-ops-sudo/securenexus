# Superpowers Development Framework

Comprehensive reference for the Superpowers framework (https://github.com/obra/superpowers) — a composable skill-driven development methodology for coding agents. Created by Jesse Vincent (@obra).

## Core Philosophy

- **TDD always**: No production code without a failing test first
- **Systematic process over heroics**: Follow proven workflows, especially under pressure
- **Complexity reduction**: Break problems into small, verifiable pieces
- **Evidence-based verification**: Run commands and read output before claiming success
- **Design before implementation**: Brainstorm → Plan → Execute → Review → Finish

## The 14 Skills

### 1. using-superpowers (Meta/Entry Point)
- Loaded at session start via hooks; establishes skill discipline
- **Rule**: Invoke relevant skills BEFORE any response or action — even 1% chance = must invoke
- Priority: User instructions > Superpowers skills > Default system prompt
- Skills are mandatory, not optional. "IF A SKILL APPLIES, YOU MUST USE IT"
- Skill priority: Process skills first (brainstorming, debugging), then implementation skills

### 2. brainstorming (Design-First)
- **HARD GATE**: Do NOT write any code, scaffold, or implement until design is presented and user approves
- Process: Explore context → Ask clarifying questions → Propose approaches → Present design → Write design doc → Spec review loop → User review → Transition to writing-plans
- Offer visual companion (diagrams) for spatial/structural questions
- Spec review loop: Dispatch plan-document-reviewer subagent, max 3 iterations before escalation
- Working in existing codebases: Map current architecture first, understand conventions

### 3. test-driven-development (Core)
- **Iron Law**: NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST — no exceptions
- **RED-GREEN-REFACTOR cycle**:
  - RED: Write minimal failing test → Run it → MUST watch it fail
  - GREEN: Write minimal code to pass → Run it → MUST watch it pass
  - REFACTOR: Clean up while staying green
- Good tests: Minimal, clear names showing intent, test behavior not implementation
- Common rationalizations to reject: "Too simple to test", "I'll test after", "Tests after achieve same goals", "It's about spirit not ritual"
- Bug fixes: Write test reproducing bug FIRST → Watch fail → Fix → Watch pass
- Verification checklist: Every feature has test, every test was watched fail then pass, no test modifications to force pass

### 4. systematic-debugging (Debugging)
- **Iron Law**: NO FIXES WITHOUT ROOT CAUSE INVESTIGATION FIRST
- **Phase 1 — Root Cause Investigation** (must complete before proposing fixes):
  1. Read error messages carefully
  2. Reproduce consistently
  3. Check recent changes
  4. Gather evidence in multi-component systems (add diagnostic instrumentation)
  5. Trace data flow
- **Phase 2 — Pattern Analysis**: Find working examples, compare, identify differences
- **Phase 3 — Hypothesis Testing**: Form single hypothesis, test minimally, verify before continuing
- **Phase 4 — Implementation**: Create failing test → Implement single fix → Verify
- Exit criteria: If 3+ fixes failed, question the architecture
- Use ESPECIALLY under time pressure (not less)

### 5. writing-plans (Planning)
- Creates detailed implementation plans before touching code
- Save to: `docs/superpowers/plans/YYYY-MM-DD-<feature-name>.md`
- **Bite-sized tasks**: Each 2-5 minutes, with exact file paths, complete code snippets, exact commands with expected output
- Plan document header: Goal, architecture decisions, tech stack, subagent note
- Task structure: Checkbox syntax with step-by-step instructions
- Plan review: Dispatch plan-document-reviewer subagent, max 3 iterations
- Execution handoff: Offer subagent-driven (recommended) or inline executing-plans

### 6. using-git-worktrees (Isolation)
- Create isolated workspaces sharing same repository for parallel branch work
- Directory selection priority: Existing `.worktrees/` > `worktrees/` > CLAUDE.md preference > Ask user
- **Safety**: MUST verify directory is in .gitignore before creating project-local worktree
- Steps: Detect project → Create worktree with new branch → Run project setup (auto-detect package manager) → Verify clean test baseline → Report location
- If tests fail at baseline: Report failures, ask permission to proceed
- Called by: brainstorming, subagent-driven-development, executing-plans

### 7. subagent-driven-development (Execution — Recommended)
- Execute plan by dispatching fresh subagent per task with two-stage review
- **Core**: Fresh subagent per task + two-stage review (spec then quality) = high quality
- Process per task:
  1. Dispatch implementer subagent with full task text + context
  2. Handle questions/status (DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, BLOCKED)
  3. Dispatch spec reviewer subagent → Must pass before code quality review
  4. Dispatch code quality reviewer subagent
  5. Fix issues in review loops until both approve
  6. Mark task complete
- Model selection: Cheap model for mechanical tasks (1-2 files), standard for integration, most capable for architecture/review
- **Never**: Skip reviews, dispatch parallel implementers, make subagent read plan file (provide full text), start code quality before spec compliance passes
- After all tasks: Dispatch final code reviewer → Use finishing-a-development-branch

### 8. executing-plans (Execution — Alternative)
- Simpler alternative when subagents unavailable
- Load plan → Review critically → Execute tasks sequentially → Use finishing-a-development-branch
- Stop and ask when: Hit blocker, plan has gaps, instruction unclear, verification fails repeatedly
- Don't force through blockers — stop and ask

### 9. dispatching-parallel-agents (Parallel Work)
- Use when: 3+ independent failures across different subsystems/files
- Each agent gets: Specific scope, clear goal, constraints, expected output format
- **Don't use when**: Failures are related, need full system context, agents would share state
- After agents return: Review summaries → Check for conflicts → Run full test suite → Spot check
- Good prompts: Focused (one problem domain), self-contained (all context included), specific about output

### 10. requesting-code-review (Quality)
- Dispatch code-reviewer subagent with git SHAs and context
- **Mandatory**: After each task in subagent-driven dev, after major features, before merge
- Template placeholders: WHAT_WAS_IMPLEMENTED, PLAN_OR_REQUIREMENTS, BASE_SHA, HEAD_SHA, DESCRIPTION
- Act on feedback: Fix Critical immediately, Important before proceeding, note Minor for later
- Push back if reviewer is wrong (with reasoning)

### 11. receiving-code-review (Quality)
- **Core**: Verify before implementing. Technical correctness over social comfort.
- Response pattern: READ → UNDERSTAND → VERIFY → EVALUATE → RESPOND → IMPLEMENT
- **Forbidden**: "You're absolutely right!", "Great point!", "Thanks for catching that!" — NO performative agreement
- Correct acknowledgment: "Fixed. [description]" or just fix it silently
- Push back when: Suggestion breaks things, reviewer lacks context, violates YAGNI, technically incorrect
- From external reviewers: Check technically correct for THIS codebase, breaks existing functionality?, reason for current impl?
- Implementation order: Clarify unclear items FIRST → Blocking issues → Simple fixes → Complex fixes → Test each individually

### 12. verification-before-completion (Discipline)
- **Iron Law**: NO COMPLETION CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE
- Gate function: IDENTIFY command → RUN it fresh → READ full output → VERIFY claim → ONLY THEN claim
- Red flags: "should", "probably", "seems to", expressing satisfaction before verification
- Rationalization prevention: "Should work now" → RUN it. "I'm confident" → Confidence ≠ evidence. "Just this once" → No exceptions.
- Applies to: Tests, builds, linting, bug fixes, agent delegation, requirements completion
- "Claiming work is complete without verification is dishonesty, not efficiency"

### 13. finishing-a-development-branch (Completion)
- Process: Verify tests pass → Determine base branch → Present exactly 4 options → Execute → Cleanup
- Options: 1) Merge locally, 2) Push and create PR, 3) Keep as-is, 4) Discard (requires typed confirmation)
- Worktree cleanup: Only for Options 1 and 4
- **Never**: Proceed with failing tests, merge without verifying, delete without confirmation

### 14. writing-skills (Meta — Skill Creation)
- **Writing skills IS TDD for process documentation**
- Iron Law: NO SKILL WITHOUT A FAILING TEST FIRST
- TDD mapping: Test case = pressure scenario with subagent, Production code = SKILL.md
- RED: Run pressure scenario WITHOUT skill, document baseline behavior/rationalizations
- GREEN: Write minimal skill addressing those specific violations
- REFACTOR: Find new rationalizations → Add explicit counters → Re-test
- SKILL.md structure: Frontmatter (name + description only), Overview, When to Use, Core Pattern, Quick Reference, Common Mistakes
- Claude Search Optimization (CSO): Description = triggering conditions ONLY ("Use when..."), NEVER summarize workflow in description
- Bulletproofing: Close every loophole explicitly, build rationalization tables, create red flags lists

## Workflow Integration Map

```
brainstorming → using-git-worktrees → writing-plans → subagent-driven-development/executing-plans
                                                        ↓ (per task)
                                                    test-driven-development
                                                        ↓
                                                    requesting-code-review
                                                        ↓
                                                    receiving-code-review
                                                        ↓ (all tasks done)
                                                    finishing-a-development-branch

systematic-debugging: Triggered by bugs at any stage
verification-before-completion: Applied at every completion claim
dispatching-parallel-agents: Used for independent parallel failures
```

## Key Patterns to Apply

| Situation | Skill to Use |
|-----------|-------------|
| New feature request | brainstorming → writing-plans → subagent-driven-development |
| Bug report | systematic-debugging → test-driven-development |
| Multiple independent failures | dispatching-parallel-agents |
| About to claim "done" | verification-before-completion |
| Code review received | receiving-code-review |
| Ready to merge | finishing-a-development-branch |
| Need isolated workspace | using-git-worktrees |

## Anti-Patterns to Avoid

- Writing code before tests (TDD violation)
- Proposing fixes before root cause investigation (debugging violation)
- Implementing before design approval (brainstorming violation)
- Claiming completion without running verification commands
- Performative agreement with reviewers ("You're absolutely right!")
- Skipping spec compliance review and going straight to code quality review
- Making subagents read plan files instead of providing full text
- Dispatching parallel implementation subagents (conflicts)
- Proceeding with unfixed Important/Critical review issues
- Using "should", "probably", "seems to" when describing work status

## Code Review Agent

The `code-reviewer` agent performs:
1. Plan alignment analysis (deviations from spec)
2. Code quality assessment (error handling, type safety, conventions)
3. Architecture review (SOLID, separation of concerns)
4. Documentation check
5. Issue categorization: Critical (must fix) > Important (should fix) > Suggestions

## Platform Support

- **Claude Code**: Native plugin with hooks, Skill tool, Task tool for subagents
- **Cursor**: hooks-cursor.json for session start
- **Codex**: Symlink skills to `~/.agents/skills/superpowers`
- **OpenCode**: Plugin via `opencode.json`
- **Gemini CLI**: GEMINI.md adapter with tool mapping

## Source

GitHub: https://github.com/obra/superpowers
License: MIT
Author: Jesse Vincent (@obra)
