//! PIN substrate (V0-4a): dual-Argon2id constant-cost verification, a per-node
//! attempt budget, and the Lockdown seam.
//!
//! Three load-bearing properties live here, all from ADR-0012 / ADR-0013 §7:
//!
//!  - **Constant-cost pin-compare (silence-critical).** The two enrolled PINs are
//!    Argon2id PHC digests with DISTINCT salts. A short-circuit ("try normal; if it
//!    matches, stop") would make a *duress* pin cost one extra Argon2 (~100ms),
//!    which the coordinator-controlling attacker can measure and average over
//!    replays — reading the duress bit off latency. So [`verify_pin`] computes BOTH
//!    digests unconditionally, in a fixed order, and constant-time-selects the
//!    verdict. Normal and duress are then observably identical (both "correct":
//!    two Argon2, no budget change, no backoff); only a WRONG pin diverges (it
//!    sleeps its backoff and consumes the budget), and a wrong pin reveals nothing
//!    about the duress bit because it is neither PIN.
//!
//!  - **Per-node attempt budget** ([`AttemptBudget`]) rate-limits online guessing
//!    of the normal PIN with the NORMATIVE transition table of ADR-0013 §7 (encoded
//!    verbatim in [`AttemptBudget::charge`]). RAMDISK/node-lifetime — a reboot wipes
//!    it AND the signing key together (ADR-0007), so it needs no durable store and
//!    cannot be reset-by-reboot while retaining the ability to sign guesses.
//!
//!  - **Fail-closed.** A valid duress pin is a *matching* compare: it never consumes
//!    the budget, and it must arm even while the node is locked out on a wrong-pin
//!    flood. The budget rate-limits ONLY wrong pins; a locked-out node signs nothing
//!    (denial, never an unfrozen quorum).
//!
//! Lockout (a transient rate-limit here) is NOT Lockdown (the terminal duress state
//! in [`crate`]). This module builds the pin/budget substrate; V0-4b builds the
//! duress arming/sweep state machine on the [`PinVerdict::Duress`] arm-hook seam.

use std::time::Duration;

use argon2::password_hash::{PasswordHash, Salt};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use vault_proto::MAX_PIN_BYTES;
use zeroize::Zeroizing;

/// Startup safety ceilings for deployment-supplied Argon2 PHCs. The crate's
/// syntactic maxima (`u32::MAX`) are not executable policy: accepting them would
/// let a valid-looking config defer an enormous allocation or effectively
/// unbounded computation to the first SpendRequest. These ceilings admit the
/// expected production-grade costs while keeping validation meaningfully fatal.
const MAX_ARGON2_M_COST_KIB: u32 = 256 * 1024;
const MAX_ARGON2_T_COST: u32 = 10;
const MAX_ARGON2_P_COST: u32 = 16;

/// The internal outcome of one pin compare. Never leaves the node — only which
/// transaction eventually fires and whether the budget is charged depend on it, and
/// both of those are invisible on the wire (ADR-0012 "pin-independent ingress").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PinVerdict {
    /// The submitted pin matched the enrolled NORMAL digest.
    Normal,
    /// The submitted pin matched the enrolled DURESS digest.
    Duress,
    /// The submitted pin matched neither.
    Wrong,
}

/// Which enrolled digest an [`Argon2 evaluation`](PinEvaluator::evaluate) targets.
/// The two are always evaluated in the fixed order `Normal` then `Duress`, so the
/// structural test can assert exactly two evaluations run per SpendRequest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PinSlot {
    Normal,
    Duress,
}

/// One Argon2id evaluation, behind a trait so a test can COUNT evaluations and
/// assert the constant-cost invariant structurally (exactly two, fixed order),
/// rather than only through a flaky wall-clock latency measurement.
///
/// The contract: `evaluate` MUST run a full Argon2id computation of `pin` against
/// this slot's enrolled digest and return a constant-time [`Choice`] of match. The
/// caller ([`verify_pin`]) invokes it for BOTH slots unconditionally — an
/// implementation that skips work when a match is already known would reintroduce
/// the exact timing leak this trait exists to defend.
pub(crate) trait PinEvaluator: Send + Sync {
    fn evaluate(&self, slot: PinSlot, pin: &[u8]) -> Choice;
}

/// The production evaluator: the two enrolled Argon2id PHC strings, verified with
/// the RustCrypto `argon2` crate. The PHC embeds each digest's own params and salt;
/// each evaluation reconstructs that context and supplies caller-owned zeroizing
/// output and memory-matrix buffers (there is no pepper).
pub(crate) struct Argon2Evaluator {
    normal_phc: String,
    duress_phc: String,
    /// Node-wide memory-hard work slot, shared with [`CarrierKdf`]. The PIN slots are
    /// already sequential; sharing this guard also prevents an authenticated
    /// `/channel` carrier derivation from overlapping either one and doubling peak
    /// Argon2 memory at the reboot-death boundary.
    work_lock: std::sync::Arc<std::sync::Mutex<()>>,
}

/// Per-node, per-boot KDF for the long-lived arm-carrier map key.
///
/// A spend request's coordinator-auth digest commits to its plaintext PIN. Keeping
/// that digest (or merely hashing it with a process-resident salt) until request
/// expiry would give a full process-memory capture a cheap offline PIN oracle: the
/// capture contains the salt too. Stretching the digest with the enrolled Argon2id
/// work parameters preserves the PIN's configured offline work factor. The random
/// salt still makes the resulting identifier node-local and boot-local; it is
/// initialized fallibly during node construction, never on the request path.
pub(crate) struct CarrierKdf {
    version: Version,
    params: Params,
    salt: Zeroizing<[u8; 32]>,
    /// Serializes ALL node Argon2 work: carrier derivations share this lock with the
    /// production [`Argon2Evaluator`], so the node holds at most one memory matrix —
    /// never one carrier matrix plus one PIN matrix. The carrier id is derived on the
    /// `/channel` receipt path OUTSIDE `sign_state`, and that path admits
    /// `max_concurrent_channel_requests` (default 64) simultaneous `spawn_blocking`
    /// jobs. A compromised-but-authenticated peer may send conflicting coordinator
    /// signatures across many live nonces at its full quota. If all such jobs queued
    /// on this lock while retaining their `/channel` permits, ordinary confirmations
    /// and partials would be shed until combine windows expired. The receipt path
    /// therefore uses [`Self::try_reserve`]: at most one conflicting-signature job owns
    /// a permit while deriving, and every contender returns `RATE_LIMITED` for bounded
    /// retry. Exact-signature confirmations and partials never need this lock. Direct
    /// ingress still uses blocking [`Self::derive`], so the lock also keeps peak memory
    /// at one carrier matrix. Contention is pin-independent, so this adds no duress
    /// oracle.
    derive_lock: std::sync::Arc<std::sync::Mutex<()>>,
    /// Derivations currently INSIDE the critical section, and the high-water mark of
    /// that count. Sampled under the lock, which is the only place the observation is
    /// meaningful: a caller queued on the lock has allocated nothing, so counting
    /// around the call would report queue depth rather than concurrent matrices.
    #[cfg(test)]
    live_derivations: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    peak_derivations: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    total_derivations: std::sync::atomic::AtomicUsize,
}

impl CarrierKdf {
    /// Build from the two already-validated PIN PHCs and a fresh per-boot salt.
    ///
    /// The work factor is the elementwise MAXIMUM of both enrolled slots, not the
    /// normal slot's alone. [`validate_digests`] permits the two PHCs to carry
    /// different costs, and a carrier id is a memory-capture-testable function of the
    /// submitted PIN: deriving at the normal slot's cost while the duress slot is
    /// enrolled stronger would hand a capture an oracle for the DURESS pin at the
    /// weaker of the two work factors. Taking the max keeps the derivation at least
    /// as strong as either enrolled slot, so neither PIN is testable below its own
    /// configured cost.
    pub(crate) fn new(normal_phc: &str, duress_phc: &str, salt: [u8; 32]) -> Result<Self, String> {
        let normal = parse_digest(normal_phc, "pin_normal_hash")?;
        let duress = parse_digest(duress_phc, "pin_duress_hash")?;
        // Version is NOT merely a format revision: Argon2 v0x13 changed the indexing
        // specifically to resist the tradeoff attack v0x10 admits, and RFC 9106
        // standardizes v0x13. Deriving at the NORMAL slot's version while the duress
        // slot is enrolled at v0x13 would hand a memory capture a cheaper attack on the
        // DURESS pin than its own enrolment declares — the same asymmetry the
        // elementwise-max cost below exists to prevent. Take the stronger version for
        // the same reason.
        let version = Self::stronger_version(
            slot_version(&normal, "pin_normal_hash")?,
            slot_version(&duress, "pin_duress_hash")?,
        );
        let normal_params = Params::try_from(&normal)
            .map_err(|e| format!("pin_normal_hash has invalid argon2 params: {e}"))?;
        let duress_params = Params::try_from(&duress)
            .map_err(|e| format!("pin_duress_hash has invalid argon2 params: {e}"))?;
        // Carrier ids are fixed at 32 bytes, but retain the strongest enrolled
        // memory/time/parallelism work factor.
        let params = Params::new(
            normal_params.m_cost().max(duress_params.m_cost()),
            normal_params.t_cost().max(duress_params.t_cost()),
            normal_params.p_cost().max(duress_params.p_cost()),
            Some(32),
        )
        .map_err(|e| format!("cannot construct arm-carrier Argon2 parameters: {e}"))?;
        Ok(Self {
            version,
            params,
            salt: Zeroizing::new(salt),
            derive_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
            #[cfg(test)]
            live_derivations: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            peak_derivations: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            total_derivations: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The later of two Argon2 versions. `Version` is a plain field-less enum whose
    /// discriminants are the wire values (0x10 < 0x13), so ordering them by that value
    /// is exactly "the revision with the stronger indexing".
    fn stronger_version(a: Version, b: Version) -> Version {
        if (a as u32) >= (b as u32) {
            a
        } else {
            b
        }
    }

    /// The work factor [`Self::derive`] runs at, so a test can assert it dominates
    /// BOTH enrolled slots without timing an Argon2 evaluation.
    #[cfg(test)]
    pub(crate) fn params(&self) -> &Params {
        &self.params
    }

    /// The Argon2 revision [`Self::derive`] runs at, so a test can assert it is at
    /// least as strong as either enrolled slot's.
    #[cfg(test)]
    pub(crate) fn version(&self) -> Version {
        self.version
    }

    /// The most derivations ever simultaneously inside the critical section — 1 iff
    /// `derive_lock` actually bounds concurrent Argon2 matrices.
    #[cfg(test)]
    pub(crate) fn peak_derivations(&self) -> usize {
        self.peak_derivations
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn total_derivations(&self) -> usize {
        self.total_derivations
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stretch one coordinator-auth digest for direct ingress. Caller-owned output is
    /// wiped after the carrier id has been domain-separated from it. Direct callers
    /// wait on `derive_lock`; conflicting-signature `/channel` receipts use
    /// [`Self::try_reserve`] instead so they are shed rather than queued.
    pub(crate) fn derive(&self, auth_digest: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let _serialized = self
            .derive_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.derive_locked(auth_digest)
    }

    /// Clone the node-wide Argon2 work slot into the production PIN evaluator.
    pub(crate) fn work_lock(&self) -> std::sync::Arc<std::sync::Mutex<()>> {
        std::sync::Arc::clone(&self.derive_lock)
    }

    /// Reserve the one carrier-derivation slot without queueing. `/channel` uses this
    /// before resolving a conflicting coordinator signature: a busy slot produces a
    /// retriable `RATE_LIMITED` reply instead of holding one of the ordinary channel
    /// permits behind memory-hard work.
    pub(crate) fn try_reserve(&self) -> Option<CarrierDerivation<'_>> {
        let guard = match self.derive_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return None,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        Some(CarrierDerivation {
            kdf: self,
            _guard: guard,
        })
    }

    fn derive_locked(&self, auth_digest: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering::SeqCst;
            self.total_derivations.fetch_add(1, SeqCst);
            let live = self.live_derivations.fetch_add(1, SeqCst) + 1;
            self.peak_derivations.fetch_max(live, SeqCst);
        }
        let argon2 = Argon2::new(Algorithm::Argon2id, self.version, self.params.clone());
        let mut memory = Zeroizing::new(vec![Block::default(); self.params.block_count()]);
        let mut output = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into_with_memory(
                auth_digest,
                self.salt.as_slice(),
                output.as_mut_slice(),
                memory.as_mut_slice(),
            )
            .expect("arm-carrier KDF executable after startup validation");
        #[cfg(test)]
        self.live_derivations
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        output
    }
}

/// Exclusive ownership of the carrier KDF's one memory-hard work slot. Keeping this
/// guard alive while the channel records the sender's derivation budget makes the
/// budget claim atomic with admission: a contender is either admitted once or told to
/// retry, never marked resolved merely because somebody else held the KDF.
pub(crate) struct CarrierDerivation<'a> {
    kdf: &'a CarrierKdf,
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl CarrierDerivation<'_> {
    pub(crate) fn derive(self, auth_digest: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        self.kdf.derive_locked(auth_digest)
    }
}

impl Argon2Evaluator {
    /// Build from two PHC strings already validated by [`validate_digests`]. Stored
    /// as owned strings and re-parsed per request (a string parse is negligible
    /// beside the Argon2 evaluation it precedes).
    #[cfg(test)]
    pub(crate) fn new(normal_phc: String, duress_phc: String) -> Argon2Evaluator {
        Self::with_work_lock(
            normal_phc,
            duress_phc,
            std::sync::Arc::new(std::sync::Mutex::new(())),
        )
    }

    /// Build with the node-wide Argon2 work slot shared by [`CarrierKdf`].
    pub(crate) fn with_work_lock(
        normal_phc: String,
        duress_phc: String,
        work_lock: std::sync::Arc<std::sync::Mutex<()>>,
    ) -> Argon2Evaluator {
        Argon2Evaluator {
            normal_phc,
            duress_phc,
            work_lock,
        }
    }
}

impl PinEvaluator for Argon2Evaluator {
    fn evaluate(&self, slot: PinSlot, pin: &[u8]) -> Choice {
        let _work = self
            .work_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let phc = match slot {
            PinSlot::Normal => &self.normal_phc,
            PinSlot::Duress => &self.duress_phc,
        };
        // Validated at startup, so a parse failure here is a bug, not input.
        let parsed = PasswordHash::new(phc).expect("pin digest validated at startup");
        let algorithm =
            Algorithm::try_from(parsed.algorithm).expect("pin algorithm validated at startup");
        let version = parsed
            .version
            .map(Version::try_from)
            .transpose()
            .expect("pin version validated at startup")
            .unwrap_or_default();
        let params = Params::try_from(&parsed).expect("pin parameters validated at startup");
        let block_count = params.block_count();
        let argon2 = Argon2::new(algorithm, version, params);
        let salt = parsed.salt.expect("pin salt validated at startup");
        let expected = parsed.hash.expect("pin hash validated at startup");
        let mut salt_buf = [0u8; Salt::MAX_LENGTH];
        let salt = salt
            .decode_b64(&mut salt_buf)
            .expect("pin salt validated at startup");

        // `Argon2::hash_password_into` allocates its memory matrix internally and
        // frees it without wiping. The matrix contains PIN-derived state from which
        // low-entropy guesses are cheaper to test, so own it here and zeroize it on
        // every return/unwind. The computed output is PIN-derived too and receives
        // the same treatment. Enabling argon2's `zeroize` feature makes each Block
        // wipeable and also clears the crate's stack intermediates.
        let mut memory = Zeroizing::new(vec![Block::default(); block_count]);
        let mut output = Zeroizing::new(vec![0u8; expected.len()]);
        argon2
            .hash_password_into_with_memory(pin, salt, output.as_mut_slice(), memory.as_mut_slice())
            .expect("pin digest executable after startup validation");
        output.as_slice().ct_eq(expected.as_bytes())
    }
}

/// Verify `pin` against both enrolled digests and constant-time-select the verdict.
///
/// BOTH evaluations always run, in the fixed order Normal then Duress (they are
/// separate `let` bindings, so the compiler cannot short-circuit the second). The
/// verdict is then selected branch-free: a normal-only match yields `Normal`, any
/// duress match yields `Duress`, otherwise `Wrong`. Duress deliberately wins a
/// double match: distinct salts do not prove distinct enrolled plaintexts, and
/// silently treating that provisioning mistake as Normal would disable duress.
pub(crate) fn verify_pin(evaluator: &dyn PinEvaluator, pin: &[u8]) -> PinVerdict {
    let normal = evaluator.evaluate(PinSlot::Normal, pin);
    let duress = evaluator.evaluate(PinSlot::Duress, pin);
    // 0 = Wrong, 1 = Normal, 2 = Duress. Assign normal first, then duress, so an
    // ambiguous double match fails closed to Duress instead of disabling the arm.
    let mut code = 0u8;
    code.conditional_assign(&1, normal);
    code.conditional_assign(&2, duress);
    match code {
        1 => PinVerdict::Normal,
        2 => PinVerdict::Duress,
        _ => PinVerdict::Wrong,
    }
}

/// Validate the two enrolled pin digests at startup (fatal config error otherwise):
/// each must be an Argon2id PHC string with valid, resource-bounded params and a
/// usable salt, and the two salts must be DISTINCT. Distinct salts are what force two
/// independent Argon2 evaluations — with a shared salt a single evaluation could
/// answer both, and an enrolment that reused one salt would be a silent weakening.
pub(crate) fn validate_digests(normal_phc: &str, duress_phc: &str) -> Result<(), String> {
    let normal = parse_digest(normal_phc, "pin_normal_hash")?;
    let duress = parse_digest(duress_phc, "pin_duress_hash")?;
    let normal_salt = normal
        .salt
        .ok_or_else(|| "pin_normal_hash has no salt".to_string())?;
    let duress_salt = duress
        .salt
        .ok_or_else(|| "pin_duress_hash has no salt".to_string())?;
    // A salt that PARSES is not necessarily one Argon2 can RUN: the PHC grammar
    // admits a 4-char (3-byte) salt, but Argon2 rejects anything under
    // `MIN_SALT_LEN` at verify time. Catching that here turns a silent dead node
    // (boots, then rejects the enrolled pin forever) into a fatal config error.
    require_usable_salt(&normal_salt, "pin_normal_hash")?;
    require_usable_salt(&duress_salt, "pin_duress_hash")?;
    if normal_salt.as_str() == duress_salt.as_str() {
        return Err(
            "pin_normal_hash and pin_duress_hash must use DISTINCT salts: a shared salt lets one \
             Argon2 evaluation answer both digests, weakening the constant-cost compare"
                .to_string(),
        );
    }
    Ok(())
}

/// The Argon2 revision one enrolled slot declares, defaulting to the crate's current
/// version when the PHC omits it. Already validated by [`parse_digest`]; re-mapping
/// here keeps [`CarrierKdf::new`] free of a second error shape.
fn slot_version(parsed: &PasswordHash<'_>, field: &str) -> Result<Version, String> {
    Ok(parsed
        .version
        .map(Version::try_from)
        .transpose()
        .map_err(|e| format!("{field} has unsupported argon2 version: {e}"))?
        .unwrap_or_default())
}

/// Parse one PHC digest and require it be Argon2id with a hash and valid params.
fn parse_digest<'a>(phc: &'a str, field: &str) -> Result<PasswordHash<'a>, String> {
    let parsed = PasswordHash::new(phc)
        .map_err(|e| format!("{field} is not a valid Argon2id PHC string: {e}"))?;
    let algorithm = Algorithm::try_from(parsed.algorithm)
        .map_err(|e| format!("{field} names an unknown password-hash algorithm: {e}"))?;
    if algorithm != Algorithm::Argon2id {
        return Err(format!(
            "{field} must be argon2id (ADR-0012), not {}",
            parsed.algorithm
        ));
    }
    // Reject an explicit version the verifier cannot execute. `Params::try_from`
    // intentionally ignores the PHC version, so omitting this check would let the
    // node boot and then classify the enrolled pin as Wrong on every request.
    parsed
        .version
        .map(Version::try_from)
        .transpose()
        .map_err(|e| format!("{field} has unsupported argon2 version: {e}"))?;
    // Params must reconstruct into a valid Argon2 context and fit the node's
    // executable resource envelope. Merely accepting Argon2's u32 syntactic
    // maxima would move an OOM/effectively-unbounded-work failure to request time.
    let params =
        Params::try_from(&parsed).map_err(|e| format!("{field} has invalid argon2 params: {e}"))?;
    require_bounded_params(&params, field)?;
    if parsed.hash.is_none() {
        return Err(format!("{field} carries no hash output to compare against"));
    }
    Ok(parsed)
}

fn require_bounded_params(params: &Params, field: &str) -> Result<(), String> {
    if params.m_cost() > MAX_ARGON2_M_COST_KIB {
        return Err(format!(
            "{field} argon2 memory cost m={} KiB exceeds the node maximum of {} KiB",
            params.m_cost(),
            MAX_ARGON2_M_COST_KIB
        ));
    }
    if params.t_cost() > MAX_ARGON2_T_COST {
        return Err(format!(
            "{field} argon2 iteration cost t={} exceeds the node maximum of {}",
            params.t_cost(),
            MAX_ARGON2_T_COST
        ));
    }
    if params.p_cost() > MAX_ARGON2_P_COST {
        return Err(format!(
            "{field} argon2 parallelism p={} exceeds the node maximum of {}",
            params.p_cost(),
            MAX_ARGON2_P_COST
        ));
    }
    Ok(())
}

/// Reject a syntactically-valid PHC salt that Argon2 cannot execute. The PHC
/// grammar's minimum is [`Salt::MIN_LENGTH`] (4 base64 chars ≈ 3 bytes), but
/// Argon2 requires at least [`argon2::MIN_SALT_LEN`] bytes and returns
/// `SaltTooShort` below it. [`Argon2Evaluator::evaluate`] relies on startup
/// validation before its infallible request-time path, so accepting one here would
/// turn the first spend into a process panic. Decoding and length-checking makes it
/// a fatal config error instead.
fn require_usable_salt(salt: &Salt, field: &str) -> Result<(), String> {
    // `Salt::MAX_LENGTH` base64 chars decode to fewer bytes, so this buffer always
    // holds the decoded salt.
    let mut buf = [0u8; Salt::MAX_LENGTH];
    let decoded = salt
        .decode_b64(&mut buf)
        .map_err(|e| format!("{field} salt is not valid base64: {e}"))?;
    if decoded.len() < argon2::MIN_SALT_LEN {
        return Err(format!(
            "{field} salt decodes to {} bytes but argon2 requires at least {}: a shorter salt \
             makes request-time evaluation return SaltTooShort",
            decoded.len(),
            argon2::MIN_SALT_LEN
        ));
    }
    Ok(())
}

/// The per-node attempt-budget config (ADR-0013 §7), validated at startup.
#[derive(Clone, Debug)]
pub(crate) struct PinBudgetConfig {
    /// Wrong pins in `window_secs` that trip a lockout. `>= 1` (validated).
    pub(crate) max_attempts: u64,
    /// The sliding window over which wrong pins accumulate. `>= 1` (validated).
    pub(crate) window_secs: u64,
    /// The per-failure backoff sleep, indexed by the pre-failure count and clamped
    /// to the last entry. Non-empty (validated).
    pub(crate) backoff_schedule: Vec<u64>,
    /// How long a lockout lasts once tripped. `>= 1` (validated).
    pub(crate) lockout_secs: u64,
}

impl PinBudgetConfig {
    /// Reject values that make the transition table undefined or silently disable
    /// its sliding-window/lockout defenses — a fatal config.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.max_attempts < 1 {
            return Err("pin_attempt_budget.max_attempts must be >= 1".to_string());
        }
        if self.backoff_schedule.is_empty() {
            return Err("pin_attempt_budget.backoff_schedule must be non-empty".to_string());
        }
        if self.window_secs < 1 {
            return Err("pin_attempt_budget.window_secs must be >= 1".to_string());
        }
        if self.lockout_secs < 1 {
            return Err("pin_attempt_budget.lockout_secs must be >= 1".to_string());
        }
        Ok(())
    }
}

/// The RAMDISK/node-lifetime wrong-pin accounting (ADR-0013 §7). Holds only mutable
/// state; the immutable config is passed to [`charge`](AttemptBudget::charge). Lives
/// under the one `/sign` `SignState` lock, so its check-then-update is atomic with
/// the rest of the handler.
///
/// `fail_times` is a fixed-size ring of `max_attempts` timestamps. `fail_head` and
/// `fails` identify the live wrong pins inside the current window; keeping the ring
/// allocated lets every request touch the same candidate slot and select the
/// logical update in constant time instead of making a wrong pin take a distinct
/// container-mutation path. `locked_until` is the lockout horizon (`0` = not locked).
pub(crate) struct AttemptBudget {
    fail_times: Vec<u64>,
    fail_head: u64,
    fails: u64,
    locked_until: u64,
    /// Test-only: how many times `charge` ran, so the structural test can assert
    /// the budget is touched exactly once per SpendRequest regardless of pin class.
    #[cfg(test)]
    pub(crate) charges: u64,
}

impl Default for AttemptBudget {
    fn default() -> AttemptBudget {
        // `SignState::default` needs a value before `Node::from_toml_str` replaces
        // it with the validated configured ring. A one-slot budget is itself valid.
        AttemptBudget::new(1).expect("one attempt slot always fits")
    }
}

/// What one [`charge`](AttemptBudget::charge) tells the handler.
pub(crate) struct ChargeOutcome {
    /// Refuse to sign this request: the node is locked out (ANY pin) OR the pin was
    /// wrong. Only a correct pin on an un-locked node signs.
    pub(crate) refuse: bool,
    /// Backoff to sleep before answering — non-zero only for a wrong pin on an
    /// un-locked node (a locked node never extends its lockout, ADR-0013 §7).
    pub(crate) backoff: Duration,
    /// Whether the node is locked out after this event (drives the uniform lockout
    /// refusal that leaks nothing about which pin was submitted).
    pub(crate) locked: bool,
}

impl AttemptBudget {
    /// Protocol ceiling on `max_attempts`. The budget rate-limits *online*
    /// guessing of a human-entered PIN (ADR-0013 §7), so a real value is a
    /// handful (the default is 5) — nothing legitimate approaches this. It is a
    /// safety bound, not a policy knob: it keeps a fat-fingered config from
    /// sizing the attempt ring large enough to OOM-kill the node at allocation.
    pub(crate) const MAX_ATTEMPTS_CEILING: u64 = 1024;

    /// Allocate the fixed timestamp ring once at startup. An absurdly large value
    /// is a fatal config error, never a node-killing allocation: the ceiling
    /// check rejects it BEFORE any allocation, because `try_reserve_exact` alone
    /// does not catch a size that fits the virtual address space under memory
    /// overcommit — the later `resize` would then fault in every page and
    /// OOM-kill the node instead of returning this `Err`.
    pub(crate) fn new(max_attempts: u64) -> Result<AttemptBudget, String> {
        if max_attempts > AttemptBudget::MAX_ATTEMPTS_CEILING {
            return Err(format!(
                "pin_attempt_budget.max_attempts ({max_attempts}) exceeds the protocol ceiling \
                 ({}): an online-guessing budget never needs more, and a ring this large would \
                 OOM-kill the node at allocation",
                AttemptBudget::MAX_ATTEMPTS_CEILING
            ));
        }
        let slots = usize::try_from(max_attempts).map_err(|_| {
            "pin_attempt_budget.max_attempts does not fit this platform".to_string()
        })?;
        let mut fail_times = Vec::new();
        fail_times.try_reserve_exact(slots).map_err(|e| {
            format!("pin_attempt_budget.max_attempts cannot allocate its attempt ring: {e}")
        })?;
        fail_times.resize(slots, 0);
        Ok(AttemptBudget {
            fail_times,
            fail_head: 0,
            fails: 0,
            locked_until: 0,
            #[cfg(test)]
            charges: 0,
        })
    }

    /// Apply the ADR-0013 §7 transition table for one SpendRequest.
    ///
    /// | Current state | Event | Action | Next |
    /// |---|---|---|---|
    /// | not locked, `fails = k < max-1` | wrong | `fails += 1`; sleep `backoff[min(k,len-1)]` | not locked |
    /// | not locked, `fails = max-1` | wrong (the max-th) | sleep `backoff[min(max-1,len-1)]` THEN `fails = max`; lock | locked |
    /// | not locked | correct (normal/duress) | no change (does NOT reset `fails`) | not locked |
    /// | not locked | oldest wrong older than `window` | it drops out of `fails` | not locked |
    /// | locked (`now < locked_until`) | ANY | refuse; a wrong pin does NOT extend the lockout | locked |
    /// | locked, `now >= locked_until` | any | `fails = 0`; unlock | not locked |
    ///
    /// Normal and duress take the IDENTICAL (no-op) path here, so the budget mutation
    /// is timing-uniform between the two silent classes (codex C3); only a WRONG pin
    /// diverges, and a wrong pin is neither PIN, so it leaks no duress bit.
    pub(crate) fn charge(
        &mut self,
        verdict: PinVerdict,
        now: u64,
        cfg: &PinBudgetConfig,
    ) -> ChargeOutcome {
        #[cfg(test)]
        {
            self.charges += 1;
        }
        // The ring is sized to `max_attempts` at `new`, and every index below is
        // taken modulo `cfg.max_attempts`. Both derive from the one config in
        // `Node::from_toml_str`, so they always agree — pin that coupling here so a
        // future refactor that split them would trip in tests, not index the ring
        // out of bounds at `fail_times[tail]`.
        debug_assert_eq!(
            self.fail_times.len(),
            cfg.max_attempts as usize,
            "attempt ring must be sized to cfg.max_attempts"
        );
        // Recover from an EXPIRED lockout first: fails reset, node un-locked.
        if self.locked_until != 0 && now >= self.locked_until {
            self.fail_head = 0;
            self.fails = 0;
            self.locked_until = 0;
        }
        // Slide the window: a failure older than `window_secs` drops out of `fails`.
        while self.fails != 0 {
            let oldest = self.fail_times[self.fail_head as usize];
            if now.saturating_sub(oldest) >= cfg.window_secs {
                self.fail_head = (self.fail_head + 1) % cfg.max_attempts;
                self.fails -= 1;
            } else {
                break;
            }
        }
        let locked = Choice::from((self.locked_until != 0) as u8);
        let is_wrong = (verdict as u8).ct_eq(&(PinVerdict::Wrong as u8));
        // The budget charges ONLY wrong pins, and NEVER while already locked (a
        // wrong-pin flood cannot extend the lockout — no infinite extension).
        let apply = is_wrong & !locked;
        // `k` = fails BEFORE this event; every wrong pin sleeps its backoff first.
        let k = self.fails;
        let idx = k.min((cfg.backoff_schedule.len() - 1) as u64) as usize;
        let scheduled_backoff = cfg.backoff_schedule[idx];
        let backoff_secs = u64::conditional_select(&0, &scheduled_backoff, apply);

        // Same-shaped state touch for every pin class: always read and write the
        // candidate ring slot, then constant-time-select whether its timestamp and
        // the logical wrong-count advance. Only the selected values differ.
        let tail = (self.fail_head + self.fails) % cfg.max_attempts;
        let prior_time = self.fail_times[tail as usize];
        self.fail_times[tail as usize] = u64::conditional_select(&prior_time, &now, apply);
        let incremented = self.fails.saturating_add(1).min(cfg.max_attempts);
        self.fails = u64::conditional_select(&self.fails, &incremented, apply);

        // The max_attempts-th wrong pin sleeps first, then begins a FULL lockout.
        // Include that terminal backoff in the horizon because the handler sleeps
        // outside this lock after the atomic state update.
        let trips_lockout = apply & self.fails.ct_eq(&cfg.max_attempts);
        let lockout_horizon = now
            .saturating_add(backoff_secs)
            .saturating_add(cfg.lockout_secs);
        self.locked_until =
            u64::conditional_select(&self.locked_until, &lockout_horizon, trips_lockout);

        let refuse = locked | is_wrong;
        ChargeOutcome {
            refuse: bool::from(refuse),
            backoff: Duration::from_secs(backoff_secs),
            locked: self.locked_until != 0,
        }
    }
}

#[cfg(test)]
impl AttemptBudget {
    /// Times `charge` ran (structural test: exactly once per SpendRequest).
    pub(crate) fn charges(&self) -> u64 {
        self.charges
    }
    /// Wrong pins currently counted in the window (0 after any correct pin).
    pub(crate) fn fails(&self) -> usize {
        self.fails as usize
    }
    /// The lockout horizon (0 = not locked).
    pub(crate) fn locked_until(&self) -> u64 {
        self.locked_until
    }
}

// ---- PHC generation (setup ceremony / demo / fixtures) ----------------------

/// The v0 Argon2id parameters used to ENROLL a pin digest. A deliberate v0
/// placeholder (the real setup ceremony picks production-grade cost + a random
/// per-deployment salt); kept at Argon2's minimum here so the demo and the many
/// fixtures that enrol pins stay fast even in an unoptimized `cargo test` build,
/// where Argon2 memory-hardness is 10-50× slower than release. The node verifies
/// with whatever params the PHC embeds, so this choice is not baked into
/// verification and a production digest with real params verifies unchanged.
fn enrol_params() -> Params {
    Params::new(Params::MIN_M_COST, 1, 1, None).expect("valid v0 argon2 params")
}

/// The baked NORMAL-slot salt for demo/fixture enrolment — distinct from
/// [`argon2id_duress_phc`]'s so a generated pair passes [`validate_digests`].
const NORMAL_SALT: &[u8; 16] = b"btcpolicy-normal";
/// The baked DURESS-slot salt (distinct from `NORMAL_SALT`).
const DURESS_SALT: &[u8; 16] = b"btcpolicy-duress";

/// Enrol `pin` as an Argon2id PHC string under the NORMAL-slot salt (demo/fixture
/// helper; the node stores and later verifies against the returned string).
pub fn argon2id_normal_phc(pin: &str) -> String {
    require_enrollable_pin(pin);
    argon2id_phc(pin, NORMAL_SALT)
}

/// Enrol `pin` as an Argon2id PHC string under the DURESS-slot salt.
pub fn argon2id_duress_phc(pin: &str) -> String {
    require_enrollable_pin(pin);
    argon2id_phc(pin, DURESS_SALT)
}

fn require_enrollable_pin(pin: &str) {
    assert!(
        !pin.is_empty(),
        "an enrolled PIN must not be empty (an omitted wire PIN also decodes as empty)"
    );
    assert!(
        pin.len() <= MAX_PIN_BYTES,
        "an enrolled PIN is {} bytes but the request protocol maximum is {MAX_PIN_BYTES}",
        pin.len()
    );
}

fn argon2id_phc(pin: &str, salt: &[u8]) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(salt).expect("valid salt bytes");
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, enrol_params());
    argon2
        .hash_password(pin.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Wrap another evaluator and record every `evaluate` call, so a test can assert
    /// EXACTLY two Argon2 evaluations run in the fixed order [Normal, Duress] per
    /// SpendRequest — the structural half of the constant-cost invariant.
    pub(crate) struct CountingEvaluator {
        inner: Arc<dyn PinEvaluator>,
        pub(crate) calls: Arc<Mutex<Vec<PinSlot>>>,
    }

    impl CountingEvaluator {
        pub(crate) fn new(inner: Arc<dyn PinEvaluator>) -> CountingEvaluator {
            CountingEvaluator {
                inner,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl PinEvaluator for CountingEvaluator {
        fn evaluate(&self, slot: PinSlot, pin: &[u8]) -> Choice {
            self.calls
                .lock()
                .expect("counting-evaluator lock")
                .push(slot);
            self.inner.evaluate(slot, pin)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn evaluator() -> Argon2Evaluator {
        Argon2Evaluator::new(
            argon2id_normal_phc("normal-pin"),
            argon2id_duress_phc("duress-pin"),
        )
    }

    fn cfg(max_attempts: u64, backoff: &[u64], lockout: u64, window: u64) -> PinBudgetConfig {
        PinBudgetConfig {
            max_attempts,
            window_secs: window,
            backoff_schedule: backoff.to_vec(),
            lockout_secs: lockout,
        }
    }

    #[test]
    fn verify_pin_classifies_all_three_and_survives_double_run() {
        let evaluator = evaluator();
        assert_eq!(
            verify_pin(&evaluator, b"normal-pin"),
            PinVerdict::Normal,
            "the normal pin verifies against the normal digest"
        );
        assert_eq!(verify_pin(&evaluator, b"duress-pin"), PinVerdict::Duress);
        assert_eq!(verify_pin(&evaluator, b"neither"), PinVerdict::Wrong);
        // The empty pin is Wrong, not a panic or a match.
        assert_eq!(verify_pin(&evaluator, b""), PinVerdict::Wrong);
    }

    #[test]
    fn a_double_match_fails_closed_to_duress() {
        let evaluator = Argon2Evaluator::new(
            argon2id_normal_phc("same-pin"),
            argon2id_duress_phc("same-pin"),
        );
        assert_eq!(
            verify_pin(&evaluator, b"same-pin"),
            PinVerdict::Duress,
            "equal enrolled plaintexts must not silently disable the duress arm"
        );
    }

    #[test]
    fn both_digests_are_evaluated_in_a_fixed_order_every_time() {
        use test_util::CountingEvaluator;
        let counting = CountingEvaluator::new(Arc::new(evaluator()));
        let calls = Arc::clone(&counting.calls);
        // Whatever the verdict, exactly two evaluations run, Normal then Duress.
        for pin in [b"normal-pin".as_slice(), b"duress-pin", b"wrong"] {
            calls.lock().expect("calls").clear();
            let _ = verify_pin(&counting, pin);
            assert_eq!(
                *calls.lock().expect("calls"),
                vec![PinSlot::Normal, PinSlot::Duress],
                "every pin class must run exactly two Argon2 evaluations, Normal then Duress"
            );
        }
    }

    #[test]
    fn validate_digests_requires_argon2id_and_distinct_salts() {
        // A well-formed pair validates.
        assert!(validate_digests(&argon2id_normal_phc("a"), &argon2id_duress_phc("b")).is_ok());
        // Same salt on both slots is rejected (both via the normal-salt helper).
        let err = validate_digests(&argon2id_normal_phc("a"), &argon2id_normal_phc("b"))
            .expect_err("shared salt must be rejected");
        assert!(err.contains("DISTINCT salts"), "unexpected error: {err}");
        // A plain SHA-256 hex (the old placeholder) is not a PHC string.
        let err = validate_digests("deadbeef", &argon2id_duress_phc("b"))
            .expect_err("non-PHC digest must be rejected");
        assert!(err.contains("pin_normal_hash"), "unexpected error: {err}");
        // `Params::try_from` does not inspect the PHC version; startup must.
        let unsupported = argon2id_normal_phc("a").replacen("v=19", "v=42", 1);
        let err = validate_digests(&unsupported, &argon2id_duress_phc("b"))
            .expect_err("an unsupported version must fail at startup");
        assert!(err.contains("version"), "unexpected error: {err}");
        // A syntactically-valid PHC whose salt decodes below argon2's MIN_SALT_LEN
        // parses fine but would make every verify return SaltTooShort. Splice a
        // 4-char (3-byte) salt into an otherwise-valid digest: the PHC fields are
        // `$argon2id$v=..$m=..,t=..,p=..$<salt>$<hash>`.
        let base_phc = argon2id_normal_phc("a");
        let parts: Vec<&str> = base_phc.split('$').collect();
        let short_salt = format!("${}${}${}$abcd${}", parts[1], parts[2], parts[3], parts[5]);
        let err = validate_digests(&short_salt, &argon2id_duress_phc("b"))
            .expect_err("an under-length salt must fail at startup, not at first spend");
        assert!(err.contains("salt"), "unexpected error: {err}");
    }

    #[test]
    fn digest_validation_rejects_unexecutable_resource_costs() {
        let too_much_memory =
            Params::new(MAX_ARGON2_M_COST_KIB + 1, 1, 1, None).expect("syntactically valid");
        let err = require_bounded_params(&too_much_memory, "pin_normal_hash")
            .expect_err("an OOM-scale memory cost must fail at startup");
        assert!(err.contains("memory cost"), "unexpected error: {err}");

        let too_many_iterations = Params::new(Params::MIN_M_COST, MAX_ARGON2_T_COST + 1, 1, None)
            .expect("syntactically valid");
        let err = require_bounded_params(&too_many_iterations, "pin_normal_hash")
            .expect_err("an effectively unbounded iteration cost must fail at startup");
        assert!(err.contains("iteration cost"), "unexpected error: {err}");

        let too_much_parallelism =
            Params::new(8 * (MAX_ARGON2_P_COST + 1), 1, MAX_ARGON2_P_COST + 1, None)
                .expect("syntactically valid");
        let err = require_bounded_params(&too_much_parallelism, "pin_duress_hash")
            .expect_err("excessive parallelism must fail at startup");
        assert!(err.contains("parallelism"), "unexpected error: {err}");

        let boundary = Params::new(
            MAX_ARGON2_M_COST_KIB,
            MAX_ARGON2_T_COST,
            MAX_ARGON2_P_COST,
            None,
        )
        .expect("boundary params are syntactically valid");
        assert!(
            require_bounded_params(&boundary, "pin_normal_hash").is_ok(),
            "the documented ceilings are inclusive"
        );

        // Prove the PHC startup path calls the ceiling check, rather than only
        // exercising the helper in isolation. The digest bytes need not match the
        // substituted params for this parse/validation boundary.
        let normal = argon2id_normal_phc("normal");
        let fields: Vec<&str> = normal.split('$').collect();
        let oversized_phc = format!(
            "${}${}$m={},t=1,p=1${}${}",
            fields[1],
            fields[2],
            MAX_ARGON2_M_COST_KIB + 1,
            fields[4],
            fields[5]
        );
        let err = validate_digests(&oversized_phc, &argon2id_duress_phc("duress"))
            .expect_err("an over-ceiling PHC must be a fatal startup config");
        assert!(err.contains("memory cost"), "unexpected error: {err}");
    }

    #[test]
    fn demo_enrolment_helpers_reject_empty_and_over_length_pins() {
        let over_length = "x".repeat(MAX_PIN_BYTES + 1);
        for enrol in [
            argon2id_normal_phc as fn(&str) -> String,
            argon2id_duress_phc as fn(&str) -> String,
        ] {
            assert!(
                std::panic::catch_unwind(|| enrol("")).is_err(),
                "neither slot may enrol an empty PIN"
            );
            assert!(
                std::panic::catch_unwind(|| enrol(&over_length)).is_err(),
                "neither slot may enrol a PIN the request protocol can never accept"
            );
        }
    }

    #[test]
    fn budget_validation_rejects_zero_durations() {
        let mut budget = cfg(3, &[0], 100, 0);
        assert!(budget
            .validate()
            .expect_err("a zero window disables accumulation")
            .contains("window_secs"));
        budget.window_secs = 100;
        budget.lockout_secs = 0;
        assert!(budget
            .validate()
            .expect_err("a zero lockout disables refusal")
            .contains("lockout_secs"));
    }

    #[test]
    fn a_max_attempts_past_the_protocol_ceiling_is_a_fatal_config() {
        // A real online-guessing budget is a handful; a value this large would
        // size the attempt ring big enough to OOM the node at allocation (which
        // `try_reserve_exact` does not catch under memory overcommit), so `new`
        // must reject it up front instead of trying to allocate it.
        let err = AttemptBudget::new(AttemptBudget::MAX_ATTEMPTS_CEILING + 1)
            .err()
            .expect("an over-ceiling max_attempts must be a fatal config error");
        assert!(err.contains("max_attempts"), "unexpected error: {err}");
        // The ceiling itself is still accepted (the boundary is inclusive).
        assert!(AttemptBudget::new(AttemptBudget::MAX_ATTEMPTS_CEILING).is_ok());
    }

    #[test]
    fn a_correct_pin_never_consumes_the_budget() {
        let mut budget = AttemptBudget::new(3).expect("budget");
        let cfg = cfg(3, &[0], 100, 3600);
        for verdict in [PinVerdict::Normal, PinVerdict::Duress] {
            let out = budget.charge(verdict, 1_000, &cfg);
            assert!(!out.refuse, "a correct pin on an un-locked node signs");
            assert!(!out.locked);
        }
        // Neither correct pin left any failure behind.
        assert_eq!(budget.fails, 0);
    }

    #[test]
    fn wrong_pins_back_off_then_lock_out_then_recover() {
        // max_attempts = 3, backoff ramp [0, 5, 30], lockout 100s, window 3600s.
        let mut budget = AttemptBudget::new(3).expect("budget");
        let cfg = cfg(3, &[0, 5, 30], 100, 3600);

        // 1st wrong (k=0): backoff[0] = 0, not yet locked.
        let out = budget.charge(PinVerdict::Wrong, 1_000, &cfg);
        assert_eq!(out.backoff, Duration::from_secs(0));
        assert!(out.refuse && !out.locked);

        // 2nd wrong (k=1): backoff[1] = 5, still not locked.
        let out = budget.charge(PinVerdict::Wrong, 1_001, &cfg);
        assert_eq!(out.backoff, Duration::from_secs(5));
        assert!(out.refuse && !out.locked);

        // 3rd wrong (k=2, the max_attempts-th): backoff[2] = 30 FIRST, then lock.
        let out = budget.charge(PinVerdict::Wrong, 1_002, &cfg);
        assert_eq!(
            out.backoff,
            Duration::from_secs(30),
            "the max-th wrong pin sleeps its terminal backoff before locking"
        );
        assert!(
            out.refuse && out.locked,
            "the max-th wrong pin trips the lockout"
        );
        assert_eq!(
            budget.locked_until, 1_132,
            "the terminal 30s backoff must not consume the following 100s lockout"
        );

        // While locked, ANY pin is refused and a wrong pin does NOT extend the lock.
        let out = budget.charge(PinVerdict::Normal, 1_010, &cfg);
        assert!(
            out.refuse && out.locked,
            "a correct pin is still refused while locked"
        );
        assert_eq!(
            out.backoff,
            Duration::from_secs(0),
            "no backoff while locked"
        );
        let before = budget.locked_until;
        budget.charge(PinVerdict::Wrong, 1_050, &cfg);
        assert_eq!(
            budget.locked_until, before,
            "a wrong-pin flood cannot extend the lockout"
        );

        // Once `now >= locked_until` the lockout clears and a correct pin signs.
        let out = budget.charge(PinVerdict::Normal, 1_132, &cfg);
        assert!(
            !out.refuse && !out.locked,
            "the node recovers after lockout_secs"
        );
    }

    #[test]
    fn the_sliding_window_drops_stale_failures() {
        // max_attempts = 2 within a 100s window; two wrongs 200s apart never lock.
        let mut budget = AttemptBudget::new(2).expect("budget");
        let cfg = cfg(2, &[0], 100, 100);
        assert!(!budget.charge(PinVerdict::Wrong, 1_000, &cfg).locked);
        // 200s later the first failure has aged out of the window, so this is again
        // the "first" failure — not the second-in-window that would lock.
        let out = budget.charge(PinVerdict::Wrong, 1_200, &cfg);
        assert!(
            !out.locked,
            "a failure older than window_secs must not count toward lockout"
        );
    }

    /// Enrol a PHC at EXPLICIT Argon2 params, so a test can pin the two slots at
    /// different work factors (which [`validate_digests`] permits).
    fn phc_at(pin: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> String {
        phc_at_version(pin, salt, m_cost, t_cost, p_cost, Version::V0x13)
    }

    /// As [`phc_at`], but at an explicit Argon2 REVISION. `validate_digests` accepts
    /// any version the verifier can execute, so the two slots may legally disagree.
    fn phc_at_version(
        pin: &str,
        salt: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        version: Version,
    ) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(salt).expect("valid salt bytes");
        let params = Params::new(m_cost, t_cost, p_cost, None).expect("valid params");
        Argon2::new(Algorithm::Argon2id, version, params)
            .hash_password(pin.as_bytes(), &salt)
            .expect("argon2 hash")
            .to_string()
    }

    /// The carrier id is a memory-capture-testable function of the submitted PIN, so
    /// its derivation must not run BELOW either enrolled slot's own work factor.
    /// `validate_digests` deliberately permits the two slots to carry different costs;
    /// deriving at the normal slot's cost alone would hand a full-process-memory
    /// capture an oracle for a stronger-enrolled DURESS pin at the weaker normal cost,
    /// silently undoing that slot's configured offline resistance. The derivation
    /// therefore runs at the elementwise MAXIMUM of both slots.
    #[test]
    fn the_carrier_kdf_is_at_least_as_strong_as_both_enrolled_slots() {
        let m = Params::MIN_M_COST;
        // Duress enrolled strictly stronger in memory and time than normal.
        let normal = phc_at("normal-pin", NORMAL_SALT, m, 1, 1);
        let duress = phc_at("duress-pin", DURESS_SALT, m * 4, 3, 1);
        validate_digests(&normal, &duress).expect("asymmetric costs are a legal enrolment");
        let kdf = CarrierKdf::new(&normal, &duress, [7u8; 32]).expect("kdf");
        assert_eq!(
            kdf.params().m_cost(),
            m * 4,
            "the carrier KDF must not derive below the DURESS slot's memory cost"
        );
        assert_eq!(kdf.params().t_cost(), 3);

        // Symmetrically when the NORMAL slot is the stronger one.
        let normal = phc_at("normal-pin", NORMAL_SALT, m * 4, 5, 1);
        let duress = phc_at("duress-pin", DURESS_SALT, m, 1, 1);
        let kdf = CarrierKdf::new(&normal, &duress, [7u8; 32]).expect("kdf");
        assert_eq!(kdf.params().m_cost(), m * 4);
        assert_eq!(kdf.params().t_cost(), 5);
    }

    /// "At least as strong as both slots" covers the Argon2 REVISION too, not only the
    /// cost parameters. v0x13 changed the indexing specifically to resist the tradeoff
    /// attack v0x10 admits, and RFC 9106 standardizes v0x13 — so deriving at the normal
    /// slot's declared version while the duress slot is enrolled at v0x13 would hand a
    /// memory capture a cheaper attack on the DURESS pin than its own enrolment
    /// declares. Exactly the asymmetry the elementwise-max cost above exists to prevent.
    #[test]
    fn the_carrier_kdf_runs_at_the_stronger_enrolled_argon2_revision() {
        let m = Params::MIN_M_COST;
        // Normal enrolled at the legacy revision, duress at the current one.
        let normal = phc_at_version("normal-pin", NORMAL_SALT, m, 1, 1, Version::V0x10);
        let duress = phc_at_version("duress-pin", DURESS_SALT, m, 1, 1, Version::V0x13);
        validate_digests(&normal, &duress).expect("mixed revisions are a legal enrolment");
        let kdf = CarrierKdf::new(&normal, &duress, [7u8; 32]).expect("kdf");
        assert_eq!(
            kdf.version(),
            Version::V0x13,
            "the carrier KDF must not derive at a revision weaker than the DURESS slot's"
        );

        // Symmetrically when the NORMAL slot is the stronger one.
        let normal = phc_at_version("normal-pin", NORMAL_SALT, m, 1, 1, Version::V0x13);
        let duress = phc_at_version("duress-pin", DURESS_SALT, m, 1, 1, Version::V0x10);
        let kdf = CarrierKdf::new(&normal, &duress, [7u8; 32]).expect("kdf");
        assert_eq!(kdf.version(), Version::V0x13);
    }

    /// Carrier confirmation and PIN verification are independently reachable request
    /// paths. They must nevertheless share one memory-hard work slot: at the permitted
    /// 256 MiB per-matrix ceiling, an overlap would require 512 MiB and an OOM kill is
    /// permanent node death under reboot-death.
    #[test]
    fn pin_and_carrier_kdfs_share_one_node_wide_memory_slot() {
        let normal = argon2id_normal_phc("normal-pin");
        let duress = argon2id_duress_phc("duress-pin");
        let kdf = CarrierKdf::new(&normal, &duress, [7u8; 32]).expect("kdf");
        let evaluator = Argon2Evaluator::with_work_lock(normal, duress, kdf.work_lock());

        assert!(
            Arc::ptr_eq(&evaluator.work_lock, &kdf.derive_lock),
            "production PIN and carrier Argon2 must serialize on the same work slot"
        );
    }

    /// Conflicting-signature `/channel` work must never queue behind the one active
    /// carrier Argon2 while retaining ordinary channel permits. Admission is therefore
    /// non-blocking: one reservation succeeds, every contender is shed for bounded
    /// retry, and the slot becomes available again after the owner finishes.
    #[test]
    fn carrier_derivation_reservation_sheds_contention_without_queueing() {
        let kdf = CarrierKdf::new(
            &argon2id_normal_phc("normal-pin"),
            &argon2id_duress_phc("duress-pin"),
            [8u8; 32],
        )
        .expect("kdf");
        let reservation = kdf.try_reserve().expect("first work slot");
        assert!(
            kdf.try_reserve().is_none(),
            "a contender must be shed, not queued behind memory-hard work"
        );
        let derived = reservation.derive(&[4u8; 32]);
        assert_eq!(kdf.total_derivations(), 1);
        drop(derived);
        assert!(
            kdf.try_reserve().is_some(),
            "the bounded-retry path can acquire the slot after the owner finishes"
        );
    }

    /// `derive` is reached from the `/channel` receipt path OUTSIDE `sign_state`, where
    /// `max_concurrent_channel_requests` jobs run at once and an authenticated peer can
    /// replay one captured coordinator-signed body at its quota. Unserialized, that is
    /// `max_concurrent_channel_requests × m_cost` of simultaneous Argon2 memory — an
    /// abort, which under reboot-death (ADR-0007) is a permanently dead node. Assert
    /// the derivations actually serialize, and that concurrency does not corrupt the
    /// result (every caller must still get the deterministic id for its digest).
    #[test]
    fn concurrent_carrier_derivations_serialize() {
        let kdf = Arc::new(
            CarrierKdf::new(
                &argon2id_normal_phc("normal-pin"),
                &argon2id_duress_phc("duress-pin"),
                [3u8; 32],
            )
            .expect("kdf"),
        );
        let expected = *kdf.derive(&[9u8; 32]);

        // Eight threads all deriving at once — well past what an unserialized
        // implementation needs to overlap two matrices.
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let kdf = Arc::clone(&kdf);
                std::thread::spawn(move || {
                    for _ in 0..4 {
                        assert_eq!(
                            *kdf.derive(&[9u8; 32]),
                            expected,
                            "the carrier id must stay deterministic under contention"
                        );
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("derive thread");
        }
        assert_eq!(
            kdf.peak_derivations(),
            1,
            "carrier-KDF derivations must serialize so peak memory-hard allocation is \
             one matrix regardless of /channel concurrency"
        );
    }
}
