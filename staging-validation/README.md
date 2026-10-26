# Staging validation

Every PR must add or update a file in this directory describing how to validate
the change in staging. CI (`.github/workflows/staging-validation.yaml`) fails
the PR otherwise.

```sh
make staging-validation        # creates staging-validation/<random>.md from TEMPLATE.md
make check-staging-validation  # runs the CI check locally (BASE=origin/main by default)
```

File names are random so PRs never collide; the file's title line records the
branch. Files stay here after release, and release notes pick up the ones that
changed between two release branches.

Required sections: **Change**, **Validation steps**, **Success criteria**,
**Edge cases and risks**. Each needs real content; HTML comments don't count.
**Staging result** is optional at PR time and is filled in once the release has
soaked in staging.

PRs opened by bots, and PRs labelled `no-staging-validation` (docs-only,
CI-only, test-only changes), skip the check.

When cutting a release, `make staging-validation-notes PREV=<previous release>`
prints the "Staging validation" section for the GitHub release notes.
