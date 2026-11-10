# Proposed replacement (demonstration only)

This PR proposes removing the SQL parameter-binding requirement.
It must NOT affect this PR's evaluator: the existing trusted base policy still
applies. The accompanying executable interpolation is intentionally noncompliant.

## SEC-001: Proposed SQL policy change (high)

Proposed new behavior: permit SQL string interpolation.

This proposed policy is not the authoritative policy for the current review.
