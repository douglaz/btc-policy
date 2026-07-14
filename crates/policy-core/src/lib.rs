//! Pure policy evaluation for the federated vault.
//!
//! `evaluate(psbt, policy_config, resolved_prevouts, now) -> Verdict` — no I/O,
//! no clock, no chain access. vault-node owns all resolution. See docs/DESIGN.md
//! ("Policy model") and CONTEXT.md for the vocabulary ("policy" must be qualified).
