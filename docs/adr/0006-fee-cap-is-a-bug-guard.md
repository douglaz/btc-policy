# The fee cap is a bug guard, not a security control

Every transaction — all classes, including escape sweeps — is subject to a single generous cap: fee ≤ 10% of total input value (`max_fee_pct = 10`). There are no per-class fee caps and no tight absolute cap.

A reviewer would expect a vault to cap fees tightly, because the fee is an implicit output the allowlist cannot see (burn-to-miners theft). We deliberately don't: that attack requires getting transactions signed instantly and invisibly, and the design closes those elsewhere — the Hold makes hot-class spends visible for ~24h before signing, the mandatory PIN means a stolen user key alone cannot submit anything, and an escape-class burn is one-shot (after a single ≤10% fee, the whole vault sits in the cold escape wallet). The cap that remains exists to catch fee-calculation bugs and fat-fingered feerates, and is sized so it can never refuse a legitimate panic-priced escape sweep.
