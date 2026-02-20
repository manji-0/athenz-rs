# Operations Handover

This document defines how maintainers hand over day-to-day operations for
`athenz-rs`.

## What to hand over

- Current `main` health (CI/check status)
- Open PRs that need review or follow-up
- High-priority issues and blockers
- Security- or reliability-related risks
- Any pending release tasks

## Minimal status capture example

```sh
jj status
jj log -r "main | @" --no-graph
```

Attach the output summary in the handover note.

## Handover template

Use this template in your handover message:

```text
Date:
Owner:
Main status:
Open PRs:
Top issues:
Risks:
Next actions:
```

## Operations checklist

1. Verify required checks pass before merge:

```sh
prek run --all-files
```

2. Confirm docs are updated when behavior or API coverage changes.
3. Confirm tests were added for new endpoints or behavior changes.
4. Flag security-sensitive changes for explicit review.

## Release-touching changes

For changes that affect users:

1. Add an entry in `CHANGELOG.md` under `Unreleased`.
2. Verify versioning impact (normal vs breaking).
3. Call out migration notes in the PR when needed.
