# Staging validation: fix/final-error-retry-wait

## Change

The shared executor used by the confidential-http and confidential-workflows capability plugins no longer waits after the last failed attempt. It also checks cancellation before starting each attempt. Attempt counts, exponential backoff between attempts, and error classification remain unchanged.

## Validation steps

- Deploy both capability plugins with this change and verify their existing canaries.
- In an isolated staging test, force a retryable failure with three configured attempts and a 10-second initial backoff. Compare attempt timestamps with the terminal `all retries exhausted` log.
- Cancel a request during backoff and submit an already-expired request; verify no further attempt starts. Check a transient failure followed by success and a non-retryable user error.

## Success criteria

- Attempts start 10 and 20 seconds after the preceding failure; the third failure returns immediately, without a final 40-second wait or a misleading `nextBackoff` log.
- Recovery succeeds, user errors return immediately, and cancellation prevents additional attempts. Retryable errors still receive the configured number of attempts.

## Edge cases and risks

This improves terminal failure latency, not the underlying quorum or transport failure. The final failed attempt is reported by `all retries exhausted`, not another `attempt failed` warning. Validate one-attempt configurations too; they must not sleep after failure.
