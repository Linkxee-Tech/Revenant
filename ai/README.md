# Revenant Local AI Boundary

The deterministic recovery engine remains authoritative. This package defines the safe boundary for future local models:

`verified recovery bytes -> immutable copy -> AI analysis/repair -> repaired copy`

No AI component is permitted to mutate source media or replace the original recovered artifact. Model execution is optional and must fail closed to deterministic recovery.
