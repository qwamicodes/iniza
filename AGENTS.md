All issues must follow the Test-Driven Development procedure.

Load and apply the `tdd` skill before implementing any issue, feature, defect fix, or behavior change in this repository.

# Required preparation

Before writing a test or implementation:

1. Read the complete issue, including its user stories, acceptance criteria, dependencies, and human-review requirements.
2. Read `CONTEXT.md` and use its canonical domain language in interfaces, tests, errors, and documentation.
3. Read every architecture decision relevant to the issue under `docs/adr/` and respect its constraints.
4. Identify the public interfaces and testing seams the issue will exercise.
5. Write those proposed seams down and confirm them with the user. Do not write a test against an unconfirmed seam.
6. When the interface or seam itself is unclear, consult the `codebase-design` skill before proposing the seam.

# Test-driven implementation loop

Work in narrow vertical tracer-bullet slices. Repeat this loop for one observable behavior at a time:

1. **Red:** Write one behavior-focused test through a confirmed public interface.
2. Run that test and confirm that it fails for the expected missing behavior, not because the test is broken.
3. **Green:** Write only the minimum implementation needed to make that test pass.
4. Run the focused test and the relevant existing test suite, and confirm they pass.
5. Continue with the next smallest behavior required by the issue.

Do not write all tests first and then implement everything. Do not add speculative behavior for future tests. Refactoring belongs to the review stage after the behavior cycles, not inside the red-to-green loop.

# Test quality rules

- Test user-visible or caller-visible behavior through public interfaces, not private methods or internal collaborators.
- Name tests as behavioral specifications using the vocabulary in `CONTEXT.md`.
- Derive expected results from the specification, a worked example, a known-good fixture, or another independent source of truth.
- Do not duplicate the implementation algorithm inside the test.
- Avoid snapshots when explicit behavioral assertions can express the contract more clearly.
- Mock only genuine system boundaries such as Git remotes, Vaultwarden, time, randomness, operating-system behavior, or an external filesystem when a real isolated adapter is impractical.
- Do not mock modules owned by Iniza merely to expose their internal call order or call counts.
- Prefer real adapters with synthetic fixtures at important integration seams.
- Inject external dependencies through small interfaces rather than constructing them inside the behavior under test.
- Keep each test focused on one logical behavior while allowing multiple assertions needed to prove that behavior.

# Issue completion rules

An issue is not complete until:

- Every acceptance criterion is covered by an automated behavior test or by an explicitly identified human-review step that cannot be automated.
- The red failure and green success were both observed for each implemented behavior.
- The relevant focused, integration, and full repository test suites pass.
- Tests verify behavior through the confirmed seams and remain insensitive to internal refactoring.
- No unresolved must-protect, security, data-loss, or secret-leak regression is hidden by a warning or skipped test.
- Human-review-required issues have received the required owner decision or rehearsal evidence.
- Documentation and architecture decisions are updated when the completed slice changes a public contract or records an approved trade-off.
- The completion handoff includes a local manual quality-assurance walkthrough that lets the owner observe and understand the implemented behavior.

Never weaken, delete, ignore, or skip a failing test merely to make an issue appear complete.

# Local manual quality-assurance handoff

When an issue is completed, provide a self-contained local testing guide in the completion response. Do not assume the owner has followed the implementation process or read earlier progress messages.

The guide must include:

1. **What was implemented:** A plain-language explanation of the observable behavior delivered by the issue.
2. **Prerequisites:** Required tools, fixtures, credentials, environment state, and completed dependency issues. Never include secret values.
3. **Setup:** Exact safe commands or actions needed to prepare an isolated local test.
4. **Primary walkthrough:** Numbered commands or actions that exercise the main user story through the public interface.
5. **Expected result:** The specific output, files, state transitions, exit behavior, or visible evidence the owner should observe after each important step.
6. **Failure or safety check:** At least one relevant negative path that demonstrates rejection, containment, non-overwrite, non-publication, secret protection, or another safety guarantee from the issue.
7. **Automated verification:** The exact focused and repository-wide test commands to run, together with the expected successful result.
8. **Cleanup or recovery:** Safe steps to remove synthetic artifacts, stop test processes, or return the environment to its prior state without deleting unrelated data.
9. **Known limitations:** Anything intentionally deferred, unsupported, simulated, or still dependent on a later issue.

Manual quality assurance must use synthetic, duplicated, disposable, or isolated data until the Owner Dogfood gates explicitly permit real data. Commands that can publish, overwrite, delete, contact an external service, or expose secrets require a clear warning and separate user approval before execution.
