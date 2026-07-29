# No correlation class may reach quorum

> **WAIVED for rollout stages 2–5 by [ADR-0015](0015-rollout-funding-caps-and-the-test-only-correlation-waiver.md).**
> Those stages deliberately run all five nodes at a single hosting provider — a correlation class
> holding quorum — under a test-only waiver with capped funds, expiring at stage 6. Sealing does NOT
> substitute for diversity: per ADR-0005 a VPS is never fully sealed against its provider. Any claim
> of compliance with this ADR dates from rollout stage 6, not earlier.

The deployer enforces one topology invariant: no single point of correlated compromise or failure — a provider account, a network block, a physical location, a household — may host t (default 3) of the n nodes. Three nodes behind one provider account make one hijacked console a quorum; three nodes in one house make one fire (or one raid, in the duress scenario) a forced recovery ceremony. Violations are hard warnings at deploy time **during the ADR-0015 waiver (rollout stages 2–5); from stage 6 onward they are a deployment REFUSAL**, and the test-mode bypass that permits them is compiled out of stage-6+ and alpha binaries.

The setup wizard preaches the clean default: five sealed VPSes across at least three providers, ideally two-plus jurisdictions (~$25–30/month). Mixed topologies (e.g., three VPSes plus two home devices) are legal within the rule — home devices even fail safe under seizure, since in-memory keys die on reboot (ADR-0007) — but never three co-located anythings.

Corollary: the coordinator laptop must not be a correlation class itself — provider-account sessions for the node hosts must not all live, logged-in, on the machine that drives the vault (and that sits next to the user under duress).
