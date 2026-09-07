# COKS-40 ignored-state inventory completeness

- Status: Proposed for owner confirmation
- Date: 2026-09-07
- Issue: COKS-40

## Problem

The real approved Project Plan exposed a fail-open reporting defect in the read-only Project audit. The installed Git adapter intentionally rejects any individual standard-output or standard-error stream larger than one mebibyte. Several real Projects legitimately produce more than one mebibyte when Git enumerates ignored paths. `audit_ignored_candidates` currently treats any adapter failure as an empty candidate list, so the public report can say that a Project has zero ignored candidates even though enumeration failed.

This contradicts the COKS-40 requirement that every ignored secret, certificate, upload, database, local configuration file, and unexpectedly large item receive an explicit Disposition. Raising the byte limit alone is insufficient because a future larger Project would reintroduce the silent false-zero result.

The real audit also emits already approved excluded generated paths one by one. Those paths remain valid Plan evidence, but repeating every descendant obscures the smaller owner-review set and makes the human report impractical.

## Interface alternatives

### Alternative A: Fail the complete audit on any ignored enumeration error

`ProjectAuditEngine::audit` returns an error as soon as one Project cannot enumerate ignored state.

This fails closed but discards verified observations for every other Project. It gives the owner less useful evidence and makes one oversized repository prevent review of unrelated Projects.

### Alternative B: Increase the Git output limit and keep the existing report shape

The adapter accepts a larger bounded output and `ignored_candidates()` remains a plain list.

This handles today's Projects but preserves the false-zero behavior when the larger bound is exceeded or Git fails for another reason. It also continues to repeat every descendant already covered by an exact Plan exclusion.

### Alternative C: Make ignored-state coverage explicit per Project

Recommended.

Each `ProjectAudit` returns one explicit ignored-state inventory outcome:

```text
Complete {
  candidates,
  excluded_by_plan_count,
}

Unavailable {
  reason_code,
}
```

The Project audit remains a partial-results report so verified observations for other Projects survive. An Unavailable ignored-state inventory is always a Restorable blocking gap and is visible in both human and machine results. It can never be rendered as zero candidates.

The implementation uses a larger but still bounded Git stream allowance for the one legitimate ignored-path enumeration command. Exceeding that allowance, malformed output, or any Git failure produces Unavailable. Other Git commands retain their narrower bound.

Candidates already beneath an exact Excluded Plan subtree are counted as `excluded_by_plan_count` and omitted from the pending owner-review list. The Plan remains the canonical path-level evidence for those exclusions. Every remaining ignored candidate keeps its stable identifier, review classification, explanation, and path in local human output. Machine output remains path-free and content-free.

This creates a deep Project-audit module: callers receive one complete or unavailable outcome without learning adapter limits, parsing rules, exclusion matching, or Git command details.

## Proposed public seams

Behavior tests use `ProjectAuditEngine::audit(ProjectAuditRequest)` and the supported `iniza projects scan` command:

1. A complete ignored-state enumeration returns every candidate not already covered by an exact Plan exclusion and an exact count of candidates covered by approved exclusions.
2. A Git enumeration failure or bounded-output overflow returns an explicit Unavailable ignored-state outcome, never an empty successful inventory.
3. An Unavailable ignored-state outcome adds a Restorable blocking gap while preserving other Projects' verified local and remote observations.
4. Exact Plan exclusion matching applies to the selected Project path and descendants without hiding ignored candidates outside the approved exclusion subtree.
5. Human output shows pending local paths, excluded-by-Plan counts, and the Unavailable reason when applicable. Machine output exposes only stable identifiers, counts, state, and reason codes; it remains path-free and content-free.
6. The installed Git adapter remains bounded: the ignored-path command receives a documented larger bound, while ordinary commands retain the existing narrow bound and all oversized streams fail closed.
7. The command continues to perform no Git mutation. It never fetches, pulls, merges, rebases, commits, resets, pushes, edits configuration, or follows an ignored symbolic link.

## Test-driven implementation sequence

After owner confirmation:

1. Red: prove a synthetic ignored-enumeration failure is currently rendered as a false empty list.
2. Green: add the explicit Complete or Unavailable result and Restorable gap.
3. Red and green: prove exact Plan-exclusion filtering and covered count.
4. Red and green: prove the command-specific bounded stream behavior against real synthetic Git executables.
5. Red and green: prove human and machine rendering, partial-results preservation, and secret/path redaction.
6. Run the focused Project audit suites, formatting, static analysis, and the complete repository suite.
7. Re-run the real read-only audit and reconcile every remaining ignored-state decision before producing any revised Plan.

Confirming these seams authorizes only test-driven correction of ignored-state audit completeness. It does not revise or approve a Plan, publish Git state, capture a Bundle, contact Vaultwarden, delete data, or authorize machine erasure.
