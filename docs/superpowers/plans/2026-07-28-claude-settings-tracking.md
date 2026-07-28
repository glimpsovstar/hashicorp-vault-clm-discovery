# Plan — Claude Code settings: ignore the tool-owned directory

- **Issue:** #76
- **Spec:** [2026-07-28-claude-settings-tracking-design.md](../specs/2026-07-28-claude-settings-tracking-design.md)
- **Branch:** `fix/76-claude-settings-tracking`
- **Date:** 2026-07-28

> Revised mid-flight. The first plan tracked a pruned `.claude/settings.json`;
> code review refuted that (verified host-root grant, file re-dirtied during the
> review, ignore rule leaked on a fresh clone). See the spec's
> [Revision](../specs/2026-07-28-claude-settings-tracking-design.md#revision-after-code-review).

## Steps

### 1. Revert the interim local exclude

`.claude/` had been added to `.git/info/exclude` as a stopgap. Remove that line —
leaving it would mask whether the committed `.gitignore` rule actually works, so
the verification in step 4 would pass locally and fail for everyone else.

### 2. Ignore `.claude/` in `.gitignore`

Directory form, with a comment explaining *why* (tool-owned, rewritten every
session) so the next contributor does not "helpfully" start tracking it:

```text
.claude/
```

### 3. Document the policy in `CONTRIBUTING.md`

The part worth sharing is the judgment, not the file. Two subsections:

- **Never allowlist these** — a table of dangerous entries with the concrete
  reason each is unsafe (`podman machine *` → passwordless host root;
  `compose *` → arbitrary host mounts and `down -v` data loss; `exec *`,
  `python3 -c`, `Bash(*)`, `sudo *`), plus the narrower forms to prefer.
- **Prefer entries that generalize** — patterns are *prefix* matches, and fixed
  entries legitimately recur (the repo's own `curl` health checks). The argument
  against one-offs is that they encode incidental history and leak local paths.

### 4. Verify

Full suite (nothing should regress) plus the config invariants, per the spec's
test-plan table. Critically, verify the fresh-clone property — `git check-ignore`
on a `.claude/` path that has never existed — since that is the failure the
review caught.

### 5. Review, PR, merge

Sub-agent code review → PR with `Fixes #76` → squash-merge → close issue →
update `progress.md`.

## Risks

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Interim `.git/info/exclude` line left in place, masking a broken `.gitignore` | Medium | Step 1 runs first; step 4 verifies via `git check-ignore`, which reports which file supplied the rule |
| A future contributor re-adds `.claude/settings.json` to git | Medium | `.gitignore` comment states the reason; CONTRIBUTING documents it |
| Someone re-adds a dangerous grant locally | Medium | Never-allowlist table names each one and why |
| Losing the shared allowlist benefit | Accepted | Deliberate trade: contributors approve their own commands once. The safety knowledge — the part that matters — is in CONTRIBUTING |

## Out of scope

- `.playwright-mcp/`, which agent sessions also create and which is likewise
  untracked. Same class of problem; filed separately rather than widened here.
- Any application source, schema, or scan behaviour.
