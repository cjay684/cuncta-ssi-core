# Coverage Plan

Initial thresholds are intentionally low to avoid blocking the repo:

- Lines: 50%
- Branches: 40%
- Functions: 40%
- Statements: 50%

## Raise plan

Increase thresholds in 3 steps:

1. **Phase 1 (after baseline tests land)**: +10% across metrics.
2. **Phase 2 (core services covered)**: +10% across metrics.
3. **Phase 3 (steady-state)**: target 80% lines / 70% branches / 75% functions.

Thresholds are controlled by `COVERAGE_*` environment variables in CI.
