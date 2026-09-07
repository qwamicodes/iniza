# COKS-40 reviewed Plan decision interface

- Status: Proposed for owner confirmation
- Date: 2026-09-07
- Issue: COKS-40

## Problem

The real Project Plan correctly begins every discovered Project as Must-Protect and allows exact subtrees to be made Optional or Excluded. It also correctly classifies symbolic links as Requires Review rather than silently following or including them.

The current public interface has no way to record the owner's positive review decision for a symbolic link. `--exclude` can remove it and `--optional` can downgrade its requirement, but neither expresses “I reviewed this exact link and want its link object retained.” Editing the Plan document by hand would bypass the supported review workflow and is not acceptable for Owner Dogfood.

The real COKS-40 Plan currently demonstrates this gap with thirty-one internal Project skill links that the owner explicitly approved for retention.

## Proposed public seam

`ScanRequest::include_reviewed(relative_path)` records one explicit positive review decision. The command-line form is repeatable:

```text
iniza scan <APPROVED_ROOT> \
  --include-reviewed <RELATIVE_PATH>... \
  --output-plan <PLAN>
```

The decision applies to the exact relative path and its descendants, matching the existing subtree behavior of `--exclude` and `--optional`. It is stored in the Plan request, changes the affected Migration Item Disposition from Requires Review to Included, changes the explanation to `included by explicit owner review`, and participates in the canonical Plan hash.

## Fail-closed rules

- The path must be a non-empty, safe relative path beneath the approved root.
- The target must exist in the new scan and currently have Requires Review disposition.
- A reviewed inclusion cannot convert Unsupported, Unavailable, Changed, or otherwise unverified state into Included.
- The same path or overlapping subtrees cannot be both excluded and reviewed for inclusion.
- Conflicting decisions reject the scan instead of depending on command-line order.
- A reviewed inclusion does not follow a symbolic link during discovery, execute it, or read its target content.
- A reviewed inclusion does not change Protection Requirement. Must-Protect remains Must-Protect and Optional remains Optional.
- Re-running the scan re-observes the source. A changed kind or missing target invalidates the earlier decision rather than silently retaining it.

## Review and partial selection workflow

The existing review loop remains:

1. Run `iniza plan show --plan <PLAN>` to see relative paths and Dispositions locally.
2. Re-run `iniza scan` with exact `--exclude`, `--optional`, and `--include-reviewed` decisions for a path or subtree.
3. Run `iniza plan diff <OLD> <NEW>` to inspect approval-relevant changes without reading protected content.
4. Repeat until every Must-Protect blocker is resolved.
5. Approve only the exact final canonical Plan hash.

There is no partial approval of one Plan hash. Partial selection means revising subpath decisions and producing a new complete Plan for review.

## Confirmed test seams after owner approval

Behavior tests will use `PlanEngine::scan(ScanRequest)` and the supported `iniza scan` command:

1. An exact reviewed symbolic link becomes Included, retains Must-Protect, and is not followed.
2. A reviewed directory applies the decision to review-required descendants without changing ordinary included descendants.
3. A reviewed inclusion of Unsupported, Unavailable, or Changed state fails closed.
4. Unsafe, missing, and conflicting include/exclude paths fail before a Plan is written.
5. The decision and explanation change the canonical Plan hash and appear in `plan diff`.
6. Human output shows the local reviewed path; machine output remains path-free and content-free.

Confirming this seam authorizes only test-driven implementation of the Plan review decision. It does not approve the real Plan, read protected content, contact remotes, publish Git state, create a Bundle, delete data, or authorize machine erasure.
