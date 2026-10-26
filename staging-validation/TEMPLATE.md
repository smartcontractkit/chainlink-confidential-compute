# Staging validation: TITLE

<!--
Fill in every required section (Change, Validation steps, Success criteria,
Edge cases and risks). HTML comments are ignored by the CI check, so a section
containing only these hints counts as empty.
-->

## Change

<!-- One or two lines: what changes and which components ship it
(confidential-http enclave, confidential-workflows enclave, host,
config-tracker, capability plugin, ...). -->

## Validation steps

<!-- How to confirm this works once it is running in staging: dashboards,
Loki/Prometheus queries, workflows to trigger, commands to run. "Existing
canaries" is fine for low-risk changes; be specific for risky ones. -->

## Success criteria

<!-- What you expect to see if it works, concretely: metric values, log lines,
error rates, latencies. -->

## Edge cases and risks

<!-- What could go wrong, what to watch for, and what would make you roll
back. Write "None" if there genuinely are none. -->

## Staging result

<!-- Optional at PR time. After the release soaks in staging, record what you
observed and set "Staging Validated" in the release changelog. -->
