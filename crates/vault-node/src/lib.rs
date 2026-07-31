//! vault-node: one federation key, one policy engine, `POST /sign`.
//!
//! Scope so far (see docs/DESIGN.md "Milestones"): PIN verification, the
//! descriptor-derived policy-core checks (input ownership, destination
//! allowlist, verified change, PSBT consistency, fee cap), user
//! partial-signature verification, the anti-replay log, and the Hold
//! (ADR-0004). Under Model B (ADR-0012) a node signs its partial(s) at INGRESS,
//! pin-independently, and the Hold delays a hot-class spend's **combine +
//! broadcast** — never its signing; a partial reaches a peer only at its
//! candidate's authorized fire event (invariant 7), while escape sweeps and
//! refresh self-spends fire at ingress. The NODES then combine and broadcast:
//! `/sign` answers accepted|refusal and structurally cannot carry a signature,
//! so the coordinator stays a pure relay that never holds a finalizable
//! transaction. Watchtower duty (ADR-0001) — a callable scan pass
//! ([`Node::watchtower_tick`]) classifies recovery-path spends and spends this
//! node never validated AND policy-ACCEPTED, of the node's own chain view, and
//! queues alerts a puller reads via `GET /events` (ADR-0002). Recognition is
//! NOT "co-signed" (in t-of-n, n−t nodes legitimately sign nothing) and NOT
//! merely "evaluated" (a spend this node REFUSED must still alert, or a theft
//! fanned to honest nodes would suppress its own alert). The classification
//! stays a deterministic callable
//! pass for tests, and in the running daemon a thin background task drives it
//! on a fixed interval ([`spawn_drivers`], V0-6b) — each node is its own
//! watchtower. Duress actions and lockdown remain v0 work (V0-4).

pub mod chain;
pub mod channel;
pub mod nodekey;
mod pin;
mod replay;
pub mod server;
pub mod watchtower;

/// V0-7: arbitrary-byte robustness for every untrusted-input parser.
#[cfg(test)]
mod prop_decoder;
/// V0-7 (DESIGN.md T3): the PSBT-mutation property over the real ingress.
#[cfg(test)]
mod prop_mutation;

pub use pin::{
    argon2id_duress_phc, argon2id_duress_phc_at, argon2id_normal_phc, argon2id_normal_phc_at,
};

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Txid};
use miniscript::{Descriptor, DescriptorPublicKey};
use replay::{NonceDecision, NonceLog, ReplayLog, SignState, MAX_COORD_NONCE_BYTES};
use serde::Deserialize;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use vault_proto::{
    Commitment, CommitmentInput, CommitmentOutput, CoordRequest, RefreshRequest, Refusal,
    RefusalCode, SignRequest, SignResponse, MAX_PIN_BYTES,
};
use zeroize::Zeroizing;

use crate::chain::{BitcoindBackend, ChainBackend, Prevout};
use crate::channel::ChannelReply;
use crate::watchtower::{AlertQueue, Event};

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The `GET /healthz` projection (bead btc-policy-9y5.6): this node's NON-SECRET
/// liveness state, and deliberately nothing else.
///
/// A poison-bricked node or an engaged Lockdown was otherwise externally invisible —
/// an operator could not tell a dead node from a healthy one without probing it with
/// a spend. But `/healthz` is reachable over the same coordinator relay path as
/// `/sign`, and the coordinator is hostile-at-wrench (ADR-0010/0012), so every field
/// here must be answerable without reading the PIN, the arm bit, or anything else a
/// **pre-`T` duress carrier changes**. Each field earns its place on that test:
///
/// - `serving` — constant `true`: the daemon parsed its config, built this node, and
///   is answering HTTP. It carries exactly what the `200` carries and no more — it is
///   the deliverable's named field, not an authenticated identity claim, and any
///   process on the port could emit the same byte.
/// - `locked_down` — the terminal Lockdown latch (ADR-0008). Public by construction:
///   a locked-down node already answers `FRAUD_SUSPECTED` to every spend, so this
///   reveals nothing one `/sign` would not. It is reached at `T` by
///   [`lockdown_tick`], adopted from the terminal persisted latch at startup, or
///   forced by a critical-lock poison net — never by a PIN- or arm-dependent
///   pre-`T` path — so it cannot separate an armed pre-`T` node from an idle one.
/// - `last_deadline_tick` — the coarse SAFETY deadline-driver heartbeat
///   ([`Node::last_deadline_tick`]), `None` before that driver's first pass. A plain "the
///   loop ran at time X", not "something armed or fired". Read its field doc for the
///   exact coverage: it is the deadline driver's heartbeat ALONE, so it goes stale on
///   a dead process, a starved runtime, a wedged or poison-bricked store — and NOT on
///   a release/combine/broadcast or watchtower pass stuck in a chain-backend RPC.
/// - `generation_claimed` — the one-shot process-generation marker (ADR-0007
///   reboot-death), claimed at the serving boundary before any request exists.
///
/// What is ABSENT is the point of the type, and the rule for extending it is the one
/// that kept those out: **if a pre-`T` duress carrier can change a field, the field
/// does not belong here.** No arm state, no pending/candidate counts, no `T` or any
/// hold/fire deadline, no pin class, no per-commitment anything. Each of those is the
/// duress oracle ADR-0012's SILENCE forbids — a coordinator could poll it to learn
/// "a duress carrier armed this node" before `T`, which is precisely the knowledge
/// the hostage window exists to deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Health {
    pub serving: bool,
    pub locked_down: bool,
    pub last_deadline_tick: Option<u64>,
    pub generation_claimed: bool,
}

/// The `GET /pending` projection (bead btc-policy-k0t): the commitment ids of the
/// spends this node has ACCEPTED and has not yet seen settle — the Hold-window view a
/// user can read straight off a node, without the coordinator relay.
///
/// **Why it exists.** `demo theft-refused`'s "the user notices the pending spend" step
/// was faithful only because the MODELLED attacker (stolen user key + PIN, but NOT the
/// coordinator auth key) has to relay through the user's OWN coordinator, which
/// surfaces the `/sign` acknowledgements. A strictly stronger thief who ALSO holds the
/// coordinator auth key can feed ONE node directly — §3 request propagation then
/// reaches the rest of the federation — and nothing the user watches would have shown
/// it: `GET /events` carries only on-chain watchtower alerts, and no node answered
/// "what have you accepted?". This is that answer.
///
/// **Why it is not a duress oracle.** It is a function of [`replay::PendingLog`]
/// ALONE — `commitment_id -> expiry`, and nothing else — so the read NEVER touches the
/// channel store, which is where every piece of duress state lives (arm intents, `T`,
/// Armed-vs-Scheduled, the sweep and its ladder). That is structural rather than a
/// promise about which fields got picked. The log has exactly three writers, and the
/// pin class reaches none of them:
///
/// - **record**, at ingress ([`handle_sign_after_lock`]) — gated on
///   `class == TxClass::Hot` and on nothing else. A duress-pin spend and a normal-pin
///   spend of the same transaction record the SAME id under the SAME expiry.
/// - **remove** — only once a candidate has been observed ON THE NETWORK: a normal
///   spend in the mempool or the chain ([`settle_candidate`]), or a CONFIRMED armed
///   escape. Both are public events, and both drop the same two sets — the settled
///   spend's own paired sibling, and every hot spend that transaction defeated by
///   spending their inputs. The second set comes from one shared scan
///   (`channel::PartialStore::invalidate_hot_conflicts`), which the settle path reaches
///   through [`channel::ChannelState::mark_broadcast`] and the confirmation branch
///   through [`channel::ChannelState::invalidate_hot_conflicts_in_store`]. A defeated
///   candidate is terminalized in the same settlement, so an id this stops reporting
///   is one no later fire tick can broadcast.
/// - **prune**, at commitment expiry — the coordinator's own `expiry` field, which is
///   the same byte under either pin.
///
/// So at any instant, a duress-carrying node's projection can differ from the
/// equivalent normal-pin node's only AFTER a transaction the whole world can see has
/// settled. The dynamic-`T` rule corroborates that from the other side: `T <= earliest
/// pending hot Hold-expiry - epsilon_secs` (ADR-0012), so an armed node has already
/// latched the PUBLIC Lockdown — `/healthz`'s `locked_down`, plus `FRAUD_SUSPECTED` on
/// every spend — strictly before the spend it froze could have settled on the normal
/// path.
///
/// **What is deliberately absent.** [`Health`]'s rule applies unchanged ("if a pre-`T`
/// duress carrier can change a field, the field does not belong here"), and a second
/// one applies on top of it: every byte exposed here is also visible to the thief, so
/// expose only what closes the gap. Hence no fire time, `T`, Hold remainder or
/// deadline FIELD — the fire schedule is precisely what arming rewrites; no arm or
/// Armed/Scheduled state; no txid, PSBT, sighash, partial signature, amount,
/// destination or fee — the crown jewels and everything derivable from them; no escape,
/// ladder rung or bump; no count of refusals, since a refused request is never pending
/// and a refusal count would be a policy oracle; no timestamp, which would make two
/// honest nodes' bodies differ for no reason at all. Not even `expiry`, which is
/// pin-uniform and would have been safe: the id alone is what lets a user say "I did
/// not authorize that", so the expiry would be a byte handed to the attacker for
/// nothing.
///
/// **What this gives the modelled attacker.** They hold the user key, the PIN and the
/// coordinator auth key. For candidates THEY submitted this is strictly less than
/// `/sign` already handed them — `Accepted` carries this same `commitment_id` plus
/// `first_seen` and `remaining_secs`. What is genuinely new is that a coordinator-auth
/// key thief who is not also the running coordinator can now see that the USER has a
/// spend in flight: an opaque SHA-256 id with no explicit amount, destination or
/// deadline in the body, for a transaction that broadcasts publicly at the end of its
/// Hold regardless. Repeated polling can still bound when an id appeared and when it
/// disappeared through settlement or expiry; that timing is pin-uniform, but it is
/// observable and is part of the price of the surface.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PendingProjection {
    /// Live accepted-but-unsettled spend commitment ids, sorted.
    ///
    /// The order is imposed here because `HashMap` iteration order is unspecified and
    /// varies per process. Without it, one node polled twice — never mind two nodes in
    /// the same state — would emit different bytes, and the byte-for-byte
    /// pin-uniformity this whole type rests on could not be asserted at all.
    pub pending: Vec<String>,
}

// Lifecycle markers are extended attributes on the already-open config inode,
// rather than sibling files derived from the caller's pathname. Symlinks and
// hardlinks therefore resolve to the SAME one-shot generation gate and Lockdown
// latch. Both attributes have exactly the config/key's tmpfs durability and vanish
// with that inode on reboot-death.
//
// DEPLOYMENT REQUIREMENT: the RAMDISK backing the config/key inode must support
// `user.*` extended attributes. tmpfs — the documented substrate — gained that
// support only in Linux 6.6; on an older kernel the first xattr call returns
// EOPNOTSUPP and the node fails closed at startup with an actionable error (see
// `read_xattr`) rather than running unable to persist the Lockdown latch.
const GENERATION_XATTR: &[u8] = b"user.btc-policy.process-generation.v0\0";
const LOCKDOWN_XATTR: &[u8] = b"user.btc-policy.lockdown.v0\0";
const XATTR_CREATE: i32 = 1;
// Raw errno values for the generic Linux syscall ABI (x86_64 / aarch64 — the vault's
// deployment target). ENODATA/ERANGE/EOPNOTSUPP carry these numbers on every common
// arch but differ on mips/sparc/alpha/parisc; the xattr mechanism is scoped to the
// generic ABI. Kept as literals rather than pulling in `libc` — they are stable
// kernel ABI and a dependency would earn nothing here.
const ENODATA: i32 = 61;
const ERANGE: i32 = 34;
const EOPNOTSUPP: i32 = 95;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn fgetxattr(
        fd: std::os::raw::c_int,
        name: *const std::os::raw::c_char,
        value: *mut std::ffi::c_void,
        size: usize,
    ) -> isize;
    fn fsetxattr(
        fd: std::os::raw::c_int,
        name: *const std::os::raw::c_char,
        value: *const std::ffi::c_void,
        size: usize,
        flags: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    fn fstatfs(fd: std::os::raw::c_int, buf: *mut Statfs) -> std::os::raw::c_int;
}

// --- P3a: fail-closed volatile-storage assertion (holistic v0 audit) -----------
//
// The whole "reboot = node death" model (ADR-0007) assumes the config/key inode
// lives on tmpfs/ramfs, wiped on reboot: on a durable FS (ext4) the key, the
// Lockdown xattr, and the generation xattr all survive a reboot, and operator
// recovery (clearing the generation xattr) then resurrects an unlocked, unarmed
// signer. Nothing else checks this, so `Node::load` asserts it at startup.

/// Filesystem magic for the RAM-backed filesystems the reboot-death model relies
/// on. `f_type` is the FIRST field of `struct statfs` (a signed `__fsword_t`, i.e.
/// `long` on LP64).
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: i64 = 0x0102_1994;
#[cfg(target_os = "linux")]
const RAMFS_MAGIC: i64 = 0x8584_58f6;

/// Setting this env var (to any value) disables the startup volatile-storage
/// assertion. INSECURE: it defeats the reboot-death model (ADR-0007). It exists for
/// the regtest harness (`vault-cli`'s `fed.rs`), which deploys nodes on ordinary
/// temp dirs, and is documented as such in the fatal message below.
#[cfg(target_os = "linux")]
const ALLOW_DURABLE_STORAGE_ENV: &str = "BTC_VAULT_ALLOW_DURABLE_STORAGE";

/// A deliberately oversized `#[repr(C)]` view of `struct statfs`: only `f_type`
/// (offset 0) is read, and `fstatfs` writes exactly `sizeof(struct statfs)` (120 on
/// x86-64), so the trailing slack makes the exact layout of everything after
/// `f_type` irrelevant.
#[cfg(target_os = "linux")]
#[repr(C)]
struct Statfs {
    f_type: i64,
    _rest: [u8; 128],
}

/// The startup gate's verdict, factored out of the syscall so it is unit-testable
/// on synthetic `f_type` values. `override_on` is true when enforcement is disabled
/// (`cfg!(test)` or [`ALLOW_DURABLE_STORAGE_ENV`]).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// A confirmed RAM-backed filesystem (tmpfs/ramfs): the reboot-death model
    /// holds — proceed silently.
    Volatile,
    /// Not confirmed volatile, but enforcement is disabled — proceed after ONE loud
    /// warning.
    OverrideDurable,
    /// Not confirmed volatile and enforcement is active — fatal startup.
    RejectDurable,
}

/// Pure gate decision: tmpfs/ramfs pass unconditionally; anything else is fatal
/// unless `override_on`. The `fstatfs`-failed (indeterminate) case is handled by
/// the caller and treated identically to a non-volatile `f_type` — an unidentified
/// filesystem is never silently trusted.
#[cfg(target_os = "linux")]
fn classify_fs(f_type: i64, override_on: bool) -> Decision {
    if f_type == TMPFS_MAGIC || f_type == RAMFS_MAGIC {
        Decision::Volatile
    } else if override_on {
        Decision::OverrideDurable
    } else {
        Decision::RejectDurable
    }
}

/// Fail closed at startup unless the config/key inode lives on tmpfs/ramfs. Called
/// from [`Node::load`] on the real config inode. Enforcement is SKIPPED under
/// `cfg!(test)` — vault-node unit tests path-load configs from ordinary, non-tmpfs
/// temp dirs — or when [`ALLOW_DURABLE_STORAGE_ENV`] is set (the regtest harness).
/// When skipped but the FS is not confirmed volatile, warn once and proceed; a
/// durable or indeterminate FS is otherwise a fatal startup error naming the fix.
#[cfg(target_os = "linux")]
fn assert_volatile_storage(file: &File) -> Result<(), Error> {
    use std::os::fd::AsRawFd;

    let override_on = std::env::var_os(ALLOW_DURABLE_STORAGE_ENV).is_some();
    let enforcement_off = cfg!(test) || override_on;

    let mut buf = Statfs {
        f_type: 0,
        _rest: [0u8; 128],
    };
    // SAFETY: `file` owns a valid fd; `buf` is a #[repr(C)] region at least as large
    // as `struct statfs`, which `fstatfs` initializes (it writes only sizeof(statfs);
    // the remaining bytes are slack we never read).
    let rc = unsafe { fstatfs(file.as_raw_fd(), &mut buf) };
    if rc == -1 {
        // INDETERMINATE: no `f_type` to classify. Treat exactly as not-confirmed-
        // volatile — an unidentified filesystem must not be silently trusted.
        let error = std::io::Error::last_os_error();
        if enforcement_off {
            eprintln!(
                "WARNING: vault-node could not determine the config/key filesystem type \
                 (fstatfs failed: {error}); the reboot-death model (ADR-0007) assumes tmpfs/ramfs. \
                 Proceeding only because storage enforcement is disabled."
            );
            return Ok(());
        }
        return Err(format!(
            "cannot determine the config/key filesystem type (fstatfs failed: {error}); \
             vault-node's reboot-death model (ADR-0007) requires the config/key inode to live on \
             tmpfs or ramfs. Deploy on tmpfs, or set {ALLOW_DURABLE_STORAGE_ENV}=1 (INSECURE — \
             defeats reboot-death) to override."
        )
        .into());
    }

    match classify_fs(buf.f_type, enforcement_off) {
        Decision::Volatile => Ok(()),
        Decision::OverrideDurable => {
            eprintln!(
                "WARNING: vault-node's config/key inode is on a non-volatile filesystem \
                 (statfs f_type {:#x}); the reboot-death model (ADR-0007) assumes tmpfs/ramfs so the \
                 signing key, Lockdown latch, and process-generation xattr are wiped on reboot. \
                 Proceeding only because storage enforcement is disabled (INSECURE).",
                buf.f_type
            );
            Ok(())
        }
        Decision::RejectDurable => Err(format!(
            "the config/key inode is on a non-volatile filesystem (statfs f_type {:#x}); \
             vault-node's reboot-death model (ADR-0007) requires tmpfs or ramfs so the signing key, \
             Lockdown latch, and process-generation xattr do NOT survive a reboot — otherwise \
             operator recovery could resurrect an unlocked signer. Deploy on tmpfs, or set \
             {ALLOW_DURABLE_STORAGE_ENV}=1 (INSECURE — defeats reboot-death) to override.",
            buf.f_type
        )
        .into()),
    }
}

/// Non-Linux targets have no `fstatfs`/tmpfs notion here, so the check is a no-op —
/// `Node::load` compiles everywhere (the vault's deployment target is Linux).
#[cfg(not(target_os = "linux"))]
fn assert_volatile_storage(_file: &File) -> Result<(), Error> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod storage_gate_tests {
    use super::{classify_fs, Decision, RAMFS_MAGIC, TMPFS_MAGIC};

    /// EXT4_SUPER_MAGIC — a stand-in for any durable, non-RAM filesystem.
    const EXT4_MAGIC: i64 = 0xEF53;

    #[test]
    fn classify_fs_passes_only_confirmed_volatile_filesystems() {
        // tmpfs/ramfs are volatile regardless of the override — the reboot-death
        // model holds, so no warning and no fatal.
        assert_eq!(classify_fs(TMPFS_MAGIC, false), Decision::Volatile);
        assert_eq!(classify_fs(RAMFS_MAGIC, false), Decision::Volatile);
        assert_eq!(classify_fs(TMPFS_MAGIC, true), Decision::Volatile);
        assert_eq!(classify_fs(RAMFS_MAGIC, true), Decision::Volatile);

        // A durable filesystem is FATAL when enforcement is on, and only downgraded
        // to a proceed-with-warning when explicitly overridden.
        assert_eq!(classify_fs(EXT4_MAGIC, false), Decision::RejectDurable);
        assert_eq!(classify_fs(EXT4_MAGIC, true), Decision::OverrideDurable);
        // An arbitrary/unknown magic (and the indeterminate f_type == 0 sentinel)
        // is treated the same as durable: never silently trusted.
        assert_eq!(classify_fs(0, false), Decision::RejectDurable);
        assert_eq!(classify_fs(0, true), Decision::OverrideDurable);
    }

    #[test]
    fn the_volatile_magics_are_the_documented_kernel_constants() {
        assert_eq!(TMPFS_MAGIC, 0x0102_1994);
        assert_eq!(RAMFS_MAGIC, 0x8584_58f6);
    }
}

#[cfg(target_os = "linux")]
fn read_xattr(file: &File, name: &'static [u8]) -> Result<Option<Vec<u8>>, Error> {
    use std::os::fd::AsRawFd;

    debug_assert_eq!(name.last(), Some(&0));
    // The Lockdown value can grow from empty to `locked` between the size query and
    // read. Retry once on that race so lower-level state adoption cannot mistake a
    // concurrently latched inode for a fresh one.
    for attempt in 0..2 {
        // SAFETY: `file` owns a valid fd; `name` is a static NUL-terminated byte
        // string; a null value with size 0 is the documented size query.
        let size = unsafe {
            fgetxattr(
                file.as_raw_fd(),
                name.as_ptr().cast(),
                std::ptr::null_mut(),
                0,
            )
        };
        if size < 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                // ENODATA: this inode has no attribute by that name (a fresh boot).
                Some(ENODATA) => return Ok(None),
                // EOPNOTSUPP: the backing filesystem cannot store `user.*` xattrs
                // (tmpfs before Linux 6.6). The generation gate + Lockdown latch have
                // nowhere durable to live, so fail closed with a message that names the
                // fix instead of an opaque "Operation not supported".
                Some(EOPNOTSUPP) => {
                    return Err(format!(
                        "the config/key filesystem does not support user.* extended attributes \
                         ({error}); vault-node's process-generation gate and Lockdown latch require \
                         them — run the RAMDISK on tmpfs with Linux >= 6.6 (or another filesystem \
                         with user.* xattr support)"
                    )
                    .into())
                }
                _ => return Err(format!("cannot read lifecycle attribute: {error}").into()),
            }
        }
        let size = usize::try_from(size).map_err(|_| "lifecycle attribute size exceeds usize")?;
        let mut value = vec![0u8; size];
        let value_ptr = if size == 0 {
            std::ptr::null_mut()
        } else {
            value.as_mut_ptr().cast()
        };
        // SAFETY: for non-empty values the buffer is valid for `size` writable bytes;
        // for an empty value the documented null/zero size query is repeated. Other
        // arguments satisfy the same invariants as the first query.
        let read = unsafe { fgetxattr(file.as_raw_fd(), name.as_ptr().cast(), value_ptr, size) };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            // ERANGE: the value grew between the two calls.
            if error.raw_os_error() == Some(ERANGE) && attempt == 0 {
                continue;
            }
            return Err(format!("cannot read lifecycle attribute value: {error}").into());
        }
        let read = usize::try_from(read).map_err(|_| "lifecycle attribute size exceeds usize")?;
        if read > size {
            if attempt == 0 {
                continue;
            }
            return Err("lifecycle attribute changed repeatedly while being read".into());
        }
        value.truncate(read);
        return Ok(Some(value));
    }
    unreachable!("the bounded lifecycle-attribute read always returns or errors")
}

#[cfg(target_os = "linux")]
fn write_xattr(
    file: &File,
    name: &'static [u8],
    value: &[u8],
    create_only: bool,
) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;

    debug_assert_eq!(name.last(), Some(&0));
    // SAFETY: `file` owns a valid fd; `name` is static and NUL-terminated; `value`
    // remains alive and readable for the duration of the call (including len 0).
    let result = unsafe {
        fsetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            value.as_ptr().cast(),
            value.len(),
            if create_only { XATTR_CREATE } else { 0 },
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn read_xattr(_file: &File, _name: &'static [u8]) -> Result<Option<Vec<u8>>, Error> {
    Err("vault-node lifecycle attributes require Linux".into())
}

#[cfg(not(target_os = "linux"))]
fn write_xattr(
    _file: &File,
    _name: &'static [u8],
    _value: &[u8],
    _create_only: bool,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "vault-node lifecycle attributes require Linux",
    ))
}

/// Write one diagnostic line without letting a broken stderr sink panic through a
/// safety boundary. Diagnostics are subordinate to the fail-closed transition: callers
/// must latch any required state before calling this helper.
fn best_effort_stderr(args: std::fmt::Arguments<'_>) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_fmt(args);
    let _ = stderr.write_all(b"\n");
}

/// Input the node cannot decode: answered with HTTP 400, never a refusal.
#[derive(Debug)]
pub struct BadRequest(pub String);

/// The node's policy config file (TOML, written once at deploy time).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub listen_port: u16,
    /// The PUBLIC half of this node's key derivation (DESIGN.md D4/T1, ADR-0007;
    /// bead btc-policy-9y5.5): the wskdf salt, as `2 * SALT_BYTES` hex characters.
    ///
    /// **There is no key at rest.** The config names the derivation, never the
    /// secret: the node's federation signing key is derived in RAM at startup from
    /// this salt plus the operator-held preimage read from stdin
    /// ([`nodekey`]). A host-level attacker reading this file learns the
    /// parameters of a 63-bit-preimage Argon2id derivation, which is not the key —
    /// where before it learned the key itself.
    pub node_key_salt: String,
    /// Argon2id pass count for the node-key derivation (public; see
    /// [`nodekey::DEFAULT_KDF_OPS`]).
    pub node_key_ops: u32,
    /// Argon2id memory, in KiB, for the node-key derivation (public; see
    /// [`nodekey::DEFAULT_KDF_MEM_KIB`]).
    pub node_key_mem_kib: u32,
    /// The node's own copy of the vault descriptor.
    pub descriptor: String,
    /// Allowlisted destination WALLETS as descriptors (hot + escape), never
    /// fixed addresses: an output is allowed when its script re-derives from one
    /// of these within `max_derivation_index` (DESIGN.md, "Destination
    /// allowlist"; CONTEXT.md, "Allowlist").
    pub allowlist: Vec<String>,
    /// The escape wallet's descriptor (ADR-0013 §5). Named apart from the
    /// allowlist so the node can tell an escape sweep (instant, under either PIN)
    /// from a hot-wallet spend (the Hold applies); its descriptor must ALSO appear
    /// in `allowlist` so the sweep passes the destination check.
    ///
    /// Mandatory since V0-8b: every `SpendRequest` carries a mandatory escape
    /// validated against it, so a node without one serves nothing.
    pub escape_descriptor: String,
    /// Bound on own-descriptor / allowlist derivation scans (DESIGN.md config
    /// schema, `max_derivation_index`).
    pub max_derivation_index: u32,
    pub hold_secs: u64,
    /// The **Hot budget** (ADR-0014), in satoshis and seconds. All three are
    /// MANDATORY and federation-uniform: they are hashed into the Manifest
    /// preimage, so a node configured with caps the federation did not agree
    /// computes a different `manifest_hash` and fails startup. A non-uniform cap
    /// would only be as strong as the laxest node, and a `#[serde(default)]` here
    /// would silently restore the unbounded pre-ADR-0014 behaviour for any config
    /// that forgot the field — the one failure mode this bound exists to remove.
    ///
    /// `hot_max_per_tx` caps a single hot spend's outflow (enforced in
    /// `policy-core`); `hot_max_per_window` caps the SUM of hot outflow this node
    /// has accepted within the last `hot_window_secs` (enforced by the
    /// [`channel::HotBudgetLedger`] at ingress). Both are needed: a per-tx cap
    /// alone is unbounded in the number of spends, and a window cap alone lets one
    /// spend take the whole window's budget.
    pub hot_max_per_tx: u64,
    pub hot_max_per_window: u64,
    /// The velocity window. Required to be `>= max_commitment_age_secs` (checked
    /// at load, sibling to `hold_secs < max_commitment_age_secs`) so the window
    /// covers every candidate throughout its node-authorized completion lifetime —
    /// see [`Node::from_toml_str`].
    pub hot_window_secs: u64,
    /// How long after a candidate's fire event the nodes may keep exchanging
    /// partials and combining (ADR-0013 §6; §1's combine window is
    /// `[fire_time, min(commitment_expiry, fire_time + combine_slack_secs)]`).
    /// Also the slack `EXPIRY_TOO_SHORT` demands a hot-class commitment outlive,
    /// so a spend is never accepted that could not possibly finish combining.
    #[serde(default = "default_combine_slack_secs")]
    pub combine_slack_secs: u64,
    /// Node-enforced cap on the coordinator-proposed commitment expiry: the
    /// node refuses any expiry beyond `now + max_commitment_age_secs` by its
    /// OWN clock, so a hostile coordinator cannot inflate the replay log's
    /// retention (DESIGN.md config schema; "Transaction commitment").
    pub max_commitment_age_secs: u64,
    /// Minimum time between refreshes of one coin (ADR-0013 §6, default ~30d).
    /// Well under the ~90-day refresh cadence, so legitimate refreshes never see
    /// it — but a wrench-time coordinator cannot drive repeated refreshes to burn
    /// the vault. The refresh path is pin-less and instant, so it has neither of
    /// the two things ADR-0006 leans on; this is half of what replaces them.
    #[serde(default = "default_refresh_min_interval_secs")]
    pub refresh_min_interval_secs: u64,
    /// Tight refresh-specific fee cap in sats/vB (ADR-0013 §6) — the other half.
    /// A real self-spend pays a normal feerate, never the 10% `max_fee_pct` a
    /// hot-class spend may use.
    #[serde(default = "default_refresh_max_feerate")]
    pub refresh_max_feerate: u64,
    /// The hostage-safety window (ADR-0012 / ADR-0013 §6): a valid duress pin
    /// schedules the escape sweep + unconditional Lockdown at `T = min(first_seen +
    /// duress_delay_secs, earliest pending hot Hold-expiry − ε)`. Purely the delay
    /// the person buys before the vault visibly reacts; **`0` is allowed** (fire
    /// immediately). It is a CEILING, not a guarantee — a matured pending hot spend
    /// collapses it to "fire now" (ADR-0012 matured-pending). Bounded above by
    /// `max_commitment_age_secs` ([`Node::from_toml_str`] rejects a larger value): a
    /// delay past the commitment lifetime would hold the constant-observable escape
    /// slot's expiry exemption open beyond the candidates' own expiry and let ordinary
    /// traffic exhaust the bounded candidate store.
    #[serde(default)]
    pub duress_delay_secs: u64,
    /// The bounded margin `ε` subtracted so the escape fires strictly BEFORE any
    /// frozen hot spend would have settled at its public Hold-expiry — otherwise the
    /// visible non-settlement during the hostage window would leak duress (ADR-0012
    /// dynamic-T). A small value (ADR-0013 §6 default 60); an absurd ε is a fatal
    /// config error ([`Node::from_toml_str`] rejects `ε > max_commitment_age_secs`).
    #[serde(default = "default_epsilon_secs")]
    pub epsilon_secs: u64,
    /// The §0 delivery horizon: the minimum margin a coordinator-signed carrier's
    /// `expiry` must leave beyond `now` for the asynchronous peer fan-out AND those
    /// peers' processing to complete. A request with less is refused at ingress,
    /// BEFORE the pin, identically for every pin class ([`ensure_delivery_horizon`]).
    ///
    /// It exists because confirmation-gated arming needs a carrier that can actually
    /// reach `t` nodes: a near-`now` expiry lapses mid-fan-out, so peers reject it as
    /// stale and no node ever confirms. Bounded above by `max_commitment_age_secs`
    /// (a horizon past the node's own expiry cap would refuse EVERY request) and
    /// required to be non-zero (a zero margin is no guarantee at all).
    #[serde(default = "default_delivery_horizon_secs")]
    pub delivery_horizon_secs: u64,
    /// The fire-time escape-sweep coverage threshold, a percentage (ADR-0013 §6,
    /// default 95). The sweep fires only if `Σ escape-output-to-escape-descriptor ≥
    /// escape_coverage_pct%` of the node's own vault balance — measuring on OUTPUTS
    /// implicitly caps the escape fee at `(100 − pct)%`. **NEVER an arm gate**
    /// (ADR-0012 invariant ii): coverage failure leaves the node frozen + locked
    /// down → recovery, never unarms.
    #[serde(default = "default_escape_coverage_pct")]
    pub escape_coverage_pct: u8,
    /// The static panic feerate floor in sats/vB (ADR-0013 §6): a fire-time sweep
    /// check, static (not a live estimate) so the sweep-admissibility verdict is
    /// deterministic across nodes and the armed set does not split. Below it the
    /// sweep does not fire → recovery. Never an arm gate (ADR-0012).
    #[serde(default = "default_escape_feerate_floor")]
    pub escape_feerate_floor: u64,
    /// The baked-at-setup policy identifier, bound into every commitment
    /// (policy is immutable, so this never changes).
    pub policy_version: u32,
    /// The two enrolled PINs as **Argon2id PHC strings**, each with its OWN salt
    /// (ADR-0012). Both are validated at startup as argon2id with valid params and
    /// DISTINCT salts (fatal config error otherwise), and the node compares a
    /// submitted pin against BOTH unconditionally in constant time
    /// ([`pin::verify_pin`]). Not SHA-256: a plain hash makes online guessing cheap,
    /// and distinct-salt argon2id is what the constant-cost duress compare rests on.
    pub pin_normal_hash: String,
    pub pin_duress_hash: String,
    /// The per-node pin-attempt budget (ADR-0013 §7): online-guessing rate limit.
    /// RAMDISK/node-lifetime, defaulted so a config that omits it still loads; the
    /// defaults are validated exactly as an explicit block is (`max_attempts`,
    /// `window_secs`, and `lockout_secs` >= 1; non-empty `backoff_schedule`).
    #[serde(default)]
    pub pin_attempt_budget: PinAttemptBudgetConfig,
    /// The coordinator's 33-byte compressed authentication pubkey: the mandatory
    /// per-vault trust root every request authenticates against (ADR-0013 §2/§4).
    /// Channel mode includes this same value in its base-manifest hash; when an
    /// `expected_manifest_hash` is provisioned, a changed key fails startup.
    /// Operationally, **rotation is a new vault** — this code has no in-place
    /// rotation mechanism (ADR-0013 §7).
    ///
    /// **Mandatory, deliberately un-defaulted**: every node is configured with
    /// exactly one coordinator, so `/sign` always enforces the coordinator-auth +
    /// freshness gate at ingress. ADR-0013 §2 states the rule unconditionally
    /// ("nodes reject any request not validly coord-signed and fresh"), and unlike
    /// `[channel]` — which §5 marks OPTIONAL — this field has no absent mode; it is
    /// required exactly as `pin_normal_hash` is. A `#[serde(default)]` would not be
    /// fail-open (the length check in [`Node::from_toml_str`] rejects the empty
    /// string an omitted field would produce), but it would move the "there is no
    /// coordinator-less node" rule out of the type and onto a guard several lines
    /// away, and it would answer a config that never mentions the field with a
    /// complaint about a malformed key instead of naming what is missing.
    pub coordinator_auth_pubkey: String,
    /// Optional chain-backend endpoint for the watchtower driver (ADR-0001,
    /// V0-6b). Absent ⇒ the daemon runs no scan task (unit tests and nodes
    /// without a reachable bitcoind still load). Present ⇒ the daemon spawns one
    /// background task scanning this bitcoind on a fixed interval.
    #[serde(default)]
    pub chain_backend: Option<ChainBackendConfig>,
    /// Optional at the parsing seam so policy-only tests can still construct the
    /// pre-channel shape. The runnable Model-B daemon requires this block: without
    /// a channel it cannot collect a quorum or broadcast, and `/sign` no longer
    /// returns a partial to let the coordinator finish instead. [`Node::load`] and
    /// [`server::serve`](crate::server::serve) therefore reject an absent channel
    /// before accepting traffic. Present ⇒ every invariant applies and `/channel`
    /// mounts.
    #[serde(default)]
    pub channel: Option<channel::ChannelConfig>,
}

/// The federation-uniform **Hot budget** (ADR-0014), as the node runtime carries
/// it: the two caps in satoshis plus the velocity window in seconds.
///
/// This is one struct rather than three loose arguments because all three are a
/// single sealed decision: they are hashed into the Manifest preimage together
/// (see [`channel::base_manifest_bytes`]), so they agree federation-wide or the
/// node does not boot. Splitting them across call sites is how one would silently
/// drift out of the preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotBudget {
    /// Per-transaction cap on hot outflow, in sats.
    pub max_per_tx_sat: u64,
    /// Rolling-window cap on the sum of accepted hot outflow, in sats.
    pub max_per_window_sat: u64,
    /// The rolling window's width, in seconds.
    pub window_secs: u64,
}

/// ADR-0013 §6's default combine slack: 60 seconds is ample for a loopback (v0)
/// or Tor (v1) partial exchange among `n ≤ 15` nodes, and short enough that a
/// commitment need only outlive its Hold by a minute.
fn default_combine_slack_secs() -> u64 {
    60
}

/// ADR-0013 §6's ~30-day default refresh interval.
fn default_refresh_min_interval_secs() -> u64 {
    2_592_000
}

/// A deliberately generous sats/vB default: the refresh cap is a burn BOUND, not
/// a fee optimizer, and it only has to sit far below `max_fee_pct` (10% of a
/// vault-sized input is orders of magnitude more than this).
fn default_refresh_max_feerate() -> u64 {
    100
}

/// ADR-0013 §6's default ε: 60 seconds is enough to cover per-node clock skew so
/// the escape fires strictly before a frozen spend would settle.
fn default_epsilon_secs() -> u64 {
    60
}

/// The default §0 delivery horizon. 60 seconds comfortably covers one fan-out round
/// (`per_send_deadline_secs` is 5 by default) plus each peer's own ingress
/// processing, while staying far below any realistic commitment lifetime.
fn default_delivery_horizon_secs() -> u64 {
    60
}

/// ADR-0013 §6's default escape coverage threshold (95%). A `pub const` because it
/// is a federation-uniform selector input sealed into the manifest preimage (see
/// [`channel::base_manifest_bytes`]): the ceremony that seals it and the
/// configs it is sealed alongside must share ONE source or the manifest a node
/// computes would not match the sealed one.
pub const DEFAULT_ESCAPE_COVERAGE_PCT: u8 = 95;

/// A minimal default panic feerate floor (sats/vB). A real per-vault deployment
/// sets this to a value that reliably confirms under stress; the floor only has to
/// be a static, cross-node-deterministic sweep-admissibility check. `pub const` for
/// the same manifest-preimage reason as [`DEFAULT_ESCAPE_COVERAGE_PCT`].
pub const DEFAULT_ESCAPE_FEERATE_FLOOR: u64 = 1;

/// ADR-0013 §6's default escape coverage threshold (95%).
fn default_escape_coverage_pct() -> u8 {
    DEFAULT_ESCAPE_COVERAGE_PCT
}

/// A minimal default panic feerate floor (sats/vB). A real per-vault deployment
/// sets this to a value that reliably confirms under stress; the floor only has to
/// be a static, cross-node-deterministic sweep-admissibility check.
fn default_escape_feerate_floor() -> u64 {
    DEFAULT_ESCAPE_FEERATE_FLOOR
}

/// The per-node pin-attempt budget config (ADR-0013 §7). Every field defaults so a
/// config may omit the whole block, but the defaults are validated like any other
/// value at load ([`pin::PinBudgetConfig::validate`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinAttemptBudgetConfig {
    /// Wrong pins within `window_secs` that trip a lockout (default 5).
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u64,
    /// Sliding window over which wrong pins accumulate (default 1h).
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Per-failure backoff sleep in seconds, indexed by the pre-failure count and
    /// clamped to the last entry (default `[0]` — no per-attempt delay; the lockout
    /// after `max_attempts` is the primary online-guessing defense). A deployment
    /// that wants a rising delay sets an explicit ramp, e.g. `[0, 1, 5, 30]` (keep a
    /// leading `0` so an honest single mistype is not penalized).
    #[serde(default = "default_backoff_schedule")]
    pub backoff_schedule: Vec<u64>,
    /// How long a lockout lasts once tripped, in seconds (default 15m).
    #[serde(default = "default_lockout_secs")]
    pub lockout_secs: u64,
}

impl Default for PinAttemptBudgetConfig {
    fn default() -> PinAttemptBudgetConfig {
        PinAttemptBudgetConfig {
            max_attempts: default_max_attempts(),
            window_secs: default_window_secs(),
            backoff_schedule: default_backoff_schedule(),
            lockout_secs: default_lockout_secs(),
        }
    }
}

fn default_max_attempts() -> u64 {
    5
}

fn default_window_secs() -> u64 {
    3_600
}

fn default_backoff_schedule() -> Vec<u64> {
    vec![0]
}

fn default_lockout_secs() -> u64 {
    900
}

/// The bitcoind JSON-RPC endpoint the watchtower driver scans, exactly what
/// [`BitcoindBackend`] needs (DESIGN.md, "Per-node chain backend").
#[derive(Debug, Deserialize)]
pub struct ChainBackendConfig {
    /// bitcoind JSON-RPC socket address, e.g. `"127.0.0.1:18443"` (loopback
    /// regtest). The daemon requires a fully-synced `-txindex=1` backend so
    /// escape-class union coverage can verify the completed leg's confirmation.
    pub rpc_addr: String,
    /// base64 of `<user>:<password>` for HTTP Basic auth — the regtest cookie,
    /// base64-encoded, as the `Authorization: Basic` header carries it.
    pub auth: String,
}

/// A running node's validated state.
pub struct Node {
    pub listen_port: u16,
    seckey: SecretKey,
    pubkey: PublicKey,
    user_pubkey: PublicKey,
    witness_script: ScriptBuf,
    check_params: policy_core::CheckParams,
    /// The dual-Argon2id pin verifier (ADR-0012 constant-cost compare). Behind an
    /// `Arc<dyn ...>` so a test can inject a counting evaluator and assert exactly
    /// two evaluations run per SpendRequest; production always holds the real
    /// [`pin::Argon2Evaluator`].
    pin_evaluator: Arc<dyn pin::PinEvaluator>,
    /// Memory-hard, node-local identity derivation for confirmation intents. A plain
    /// auth digest commits to the PIN and would be an offline oracle while retained;
    /// this KDF preserves the stronger work factor of both enrolled PIN slots.
    carrier_kdf: pin::CarrierKdf,
    /// The per-node attempt-budget config (ADR-0013 §7). Immutable; the mutable
    /// wrong-pin accounting lives in [`replay::SignState`] under the one `/sign`
    /// lock, so the budget check-then-update is atomic with the rest of the handler.
    pin_budget_config: pin::PinBudgetConfig,
    /// Terminal **Lockdown** (ADR-0008): once set, every spend AND refresh answers
    /// `FRAUD_SUSPECTED` for the node's lifetime. A monotonic latch (false→true,
    /// never back) with **durability EQUAL to the signing key's** (see
    /// `lifecycle_file`). Production additionally claims a one-shot process
    /// generation, so a crash cannot reload the surviving tmpfs key with empty
    /// Armed/candidate state; the latch still ensures any in-process/lower-level
    /// adoption of surviving tmpfs state observes terminal Lockdown. No reset on
    /// sealed nodes; a machine reboot is node death (tmpfs wiped → key, generation
    /// marker, and flag all gone), strictly stronger. V0-4a builds the state, the
    /// refusal, and the [`Node::enter_lockdown`] entry point; V0-4b drives WHEN it
    /// is entered (at T under duress).
    lockdown: AtomicBool,
    /// A PRE-OPENED handle to the RAMDISK config inode — the artifact that names
    /// this node's key derivation, the key itself now living only in RAM
    /// ([`nodekey`]). Lockdown and the one-shot process generation are extended
    /// attributes on THIS inode, so they have the config's durability — which under
    /// the tmpfs deployment is the same zero as the key's — and cannot be bypassed
    /// by loading the same config through a symlink or hardlink. Opened once by
    /// [`Node::load`] before the server accepts connections and held for life, so
    /// [`Node::enter_lockdown`] needs no fresh fd (EMFILE-safe). The Lockdown
    /// attribute is created empty on a fresh boot to prove the future write is
    /// possible; non-empty means terminally locked. `None` exists only for path-less
    /// [`Node::from_toml_str`] unit-test construction. This remains RAMDISK-only, not
    /// a durable at-rest duress record: reboot wipes the config/key inode and both
    /// attributes together.
    lifecycle_file: Option<File>,
    /// The duress arm-hook seam (ADR-0012 "internal fire bit"): incremented whenever
    /// a valid DURESS pin is seen — even when the node is locked out (fail-closed).
    /// V0-4a exposes only this counter (invisible on the wire, so it does not break
    /// pin-independent ingress); V0-4b builds the arm/freeze/sweep state machine on
    /// this same seam.
    duress_arm: AtomicU64,
    /// How many `/sign` requests are currently inside the OUT-OF-LOCK chain preflight
    /// — the in-flight half of refresh subordination (bead btc-policy-f91).
    ///
    /// Refresh subordination (ADR-0012: "while any normal-path spend is pending, a
    /// refresh is queued behind it") reads [`replay::PendingLog`], and a spend only
    /// lands there in phase 2, AFTER its preflight. Across the preflight window the
    /// spend is therefore invisible to that rule, so a concurrent `RefreshRequest`
    /// could complete its own (shorter) preflight, re-acquire `sign_state`, see no
    /// pending spend, and register an immediately-fireable refresh. If that refresh
    /// consumed an input the spend's MANDATORY ESCAPE needs, the escape could no
    /// longer cover and the T-time sweep would fail → funds frozen → recovery. This
    /// counter closes that window: the spend claims it under the lock in phase 1 and
    /// releases it only after phase 2 has finished, so `has_any`-plus-this is true
    /// continuously from ingress to registration.
    ///
    /// It is an ATOMIC on `Node` rather than a field of [`replay::SignState`] for one
    /// reason: it is released by an RAII guard ([`SpendPreflightGuard`]) so no early
    /// return, `?`, or panic can leak it, and a guard whose `Drop` had to take
    /// `sign_state` would either deadlock against the phase-2 hold or panic during
    /// unwind on a poisoned lock. A counter (not a flag) is what makes it idempotent
    /// under concurrent replays: each in-flight request owns exactly one unit.
    ///
    /// PIN-UNIFORM by construction: it is claimed after the pin verdict exists but
    /// before that verdict can branch any observable, on the one code path both
    /// matching pin classes take, and released identically. A refresh refusal caused
    /// by it is the byte-identical `REFRESH_SUBORDINATED` a pending spend produces.
    spend_preflight: AtomicUsize,
    /// The SAFETY deadline driver's liveness heartbeat (bead btc-policy-9y5.6): the
    /// coarse wall-clock bucket of the last absolute-schedule deadline pass this
    /// process began, or `0` before the first pass. `0` reads as "no pass yet"
    /// (`unix_now` only returns 0 for a before-epoch clock, which is already the
    /// fail-safe reading everywhere else).
    ///
    /// WHAT IT COVERS, exactly — the wire name `last_deadline_tick` is the one the bead
    /// fixed, but the publisher is [`lockdown_driver_with_clock`]'s deadline pass,
    /// NOT [`fire_tick`]. So the heartbeat goes stale on: a dead process, a runtime
    /// that has stopped scheduling, a channel store lock wedged or held forever (the
    /// pass blocks in `lockdown_due` on the very next tick), and the POISON-BRICKED
    /// node — [`lockdown_tick_with_lockdown_net`] deliberately stops running passes
    /// once a critical lock is poisoned and the fail-closed latch has fired, so a
    /// stale heartbeat alongside `locked_down: true` is precisely that state, made
    /// visible from outside for the first time.
    ///
    /// It does NOT go stale when the best-effort release/combine/broadcast pass, the
    /// watchtower scan, or the vault-scan cache refresher is stuck in a chain-backend
    /// RPC: those three are separately scheduled and none of them publishes here.
    /// That gap is deliberate, not an oversight. All three reset their ticker from
    /// pass COMPLETION, so each one's phase is a function of how long its last pass
    /// took — and for the fire pass that duration depends on what the candidate
    /// registry holds, i.e. on whether this node is ARMED. Publishing that phase
    /// would hand a polling coordinator the pre-`T` arm signal ADR-0012's SILENCE
    /// denies it; bucketing a timestamp coarsens a secret-dependent cadence, it does
    /// not remove it. The deadline driver's own schedule is never reset and performs
    /// no backend work, which is what makes this one field publishable at all, and
    /// pin-uniformity beats coverage wherever the two collide (bead 9y5.6's
    /// load-bearing constraint).
    ///
    /// Be precise about what an operator is left with, because no surface closes it:
    /// a backend call that FAILS prints on the node's own log (`fire: cannot
    /// broadcast …`, `fire: cannot check settlement …`, `vault scan cache refresh
    /// failed …`), while a call that BLOCKS forever prints nothing and queues
    /// nothing. `/events` is not the fallback either — [`Node::events`] drains the
    /// alert queue, whose only writers are the watchtower scan and the channel
    /// freshness reject path, so no sweep progress has ever reached it. A
    /// backend-wedged sweep is therefore invisible from outside, deliberately: the
    /// field that would show it is the arm-dependent one SILENCE forbids.
    ///
    /// An atomic, deliberately, and not anything reachable through `sign_state` or
    /// the channel store: a `/healthz` that waited on those locks would queue behind
    /// exactly the contention an operator is probing for, and would expose a
    /// lock-contention timing channel on a surface a hostile coordinator can poll.
    ///
    /// PIN-UNIFORM on the wire, which is load-bearing (`/healthz` must not become a
    /// duress oracle): it is stamped by the never-reset [`FIRE_INTERVAL`] deadline
    /// ticker in [`lockdown_tick_with_lockdown_net`], before the Armed deadline is
    /// read. The best-effort release/combine pass never WRITES it, so that pass's
    /// completion-scheduled cadence is not published directly.
    ///
    /// Do not overread that separation as a scheduler-isolation guarantee. A
    /// deadline iteration synchronously waits in [`channel::ChannelState::lockdown_due`]
    /// on the channel store, and the fire pass also uses that mutex. Contention can
    /// therefore postpone the NEXT deadline iteration and its bucket publication — a
    /// co-residency latency residual documented in DESIGN.md (equally present on
    /// `/events` and the TCP accept), not a tested `/healthz` property.
    last_deadline_tick: AtomicU64,
    /// Whether THIS process claimed the one-shot generation marker
    /// ([`Node::claim_process_generation`]). Reported by `/healthz` as the "this is
    /// the sealed node that was provisioned, not a reload of its surviving tmpfs key"
    /// signal (ADR-0007 reboot-death). Pin-independent by construction: the claim
    /// happens once at the serving boundary, before any request can exist. Production
    /// [`server::serve`] therefore exposes only `true`; `false` remains meaningful to
    /// embedders that construct the router directly and to tests.
    generation_claimed: AtomicBool,
    /// The coordinator authentication pubkey this node is sealed to (ADR-0013
    /// §2): every `/sign` request must be validly coord-signed, carry a fresh
    /// nonce, and fall inside the expiry window before the PIN is even consulted.
    /// Not optional — a node is always configured with exactly one coordinator.
    /// Channel mode includes this value in its manifest hash, and a provisioned
    /// `expected_manifest_hash` seals that hash at startup. The specified key
    /// lifecycle treats a change as a new vault rather than in-place rotation
    /// (§4/§7).
    coordinator_auth: PublicKey,
    /// Hash of this node's descriptor: the `wallet_id` bound into every
    /// commitment.
    wallet_id: [u8; 32],
    policy_version: u32,
    max_commitment_age_secs: u64,
    /// The Hold for hot-class spends (ADR-0004, as reworked by ADR-0012's Model-B
    /// Hold lifecycle): the node signs its partial at INGRESS and the Hold delays
    /// **combine + broadcast**, not signing. `0` fires on first submission (first
    /// light; keeps the demo one-shot).
    hold_secs: u64,
    /// The combine window's slack past a fire event (ADR-0013 §6).
    combine_slack_secs: u64,
    /// The federation-uniform Hot budget (ADR-0014). The per-tx cap is ALSO in
    /// `check_params` (policy-core enforces it); this copy is what the velocity
    /// ledger was built with and what the `HOT_VELOCITY_EXCEEDED` detail reports.
    hot_budget: HotBudget,
    /// `t` — the federation threshold from the descriptor's `multi(t, …)`. A
    /// candidate combines once EVERY input carries `t` distinct valid partials.
    threshold: usize,
    /// Conservative upper bound on the witness weight needed to satisfy one vault
    /// input. The fire-time escape preflight uses this before releasing this node's
    /// share: the exact finalized vsize does not exist until peers exchange shares,
    /// but an upper bound lets the panic-feerate floor fail closed without giving a
    /// compromised `t-1` set a finalizable signature first.
    max_vault_satisfaction_weight: u64,
    /// ADR-0013 §6 refresh bounds. The refresh path is pin-less and instant, so
    /// these are its only burn defense.
    refresh_min_interval_secs: u64,
    refresh_max_feerate: u64,
    /// The duress hostage-safety window (ADR-0012 / ADR-0013 §6). `T = min(now +
    /// duress_delay_secs, earliest pending hot Hold-expiry − epsilon_secs)`; `0`
    /// allowed (fire immediately).
    duress_delay_secs: u64,
    /// The bounded ε margin (ADR-0012 dynamic-T): the escape fires ε seconds before
    /// any frozen hot spend would have settled, so the visible non-settlement never
    /// leaks duress. Validated bounded at load.
    epsilon_secs: u64,
    /// The §0 delivery horizon: the minimum `expiry − now` margin a carrier must
    /// leave so the async peer fan-out can complete before it lapses. Enforced at
    /// ingress BEFORE the pin, so it is never a duress oracle.
    delivery_horizon_secs: u64,
    /// Fire-time escape-sweep coverage threshold (percent) and static panic feerate
    /// floor (sats/vB) — ADR-0013 §6. **Fire-time sweep-admissibility checks only,
    /// NEVER arm gates** (ADR-0012 invariant ii): a failure freezes → recovery.
    escape_coverage_pct: u8,
    escape_feerate_floor: u64,
    /// The `/sign` handler's replay log AND Hold-timer pending log under ONE
    /// lock (see [`replay::SignState`]). `/sign` uses two guarded phases around
    /// the slow chain preflight: phase 1 atomically consumes coordinator freshness
    /// and records the safety intent, then phase 2 holds this same lock continuously
    /// across every replay/pending check-and-update. Exact replays cannot enter the
    /// gap because phase 1 already consumed their nonce. Splitting the state across
    /// separate locks is FORBIDDEN — interleaved check/update over replay and pending
    /// state would corrupt their shared semantics.
    sign_state: Mutex<SignState>,
    /// **The validated-AND-policy-ACCEPTED transaction set** (ADR-0012's
    /// watchtower recognition rule, and V0-8b's vault-authorized set). Holds the
    /// txid of every transaction this node validated and would authorize — the
    /// spend AND the escape of each accepted request — recorded at ingress when
    /// the node accepts, NEVER when it refuses.
    ///
    /// It replaces V0-6's co-signed set, which was the wrong criterion twice over:
    ///
    /// - **too narrow** for recognition: in a `t`-of-`n`, `n−t` nodes legitimately
    ///   never sign a given spend, so "I didn't sign it" false-alarms on honest
    ///   traffic;
    /// - **too broad** if relaxed to "I evaluated it": a spend a node policy-
    ///   REFUSED was evaluated, so a theft deliberately fanned out to honest nodes
    ///   would count as recognized and suppress its own alert. Acceptance is the
    ///   line — a refused theft is not in this set, so it alerts.
    ///
    /// Segwit txids exclude the witness and SIGHASH_ALL binds the witness to the
    /// exact transaction, so the unsigned tx's txid IS the txid it will confirm
    /// under; recording it at ingress is sound.
    ///
    /// The same set answers "may this spend chain off that unconfirmed parent?"
    /// (ADR-0012 build-over-mempool): a parent in here is vault-authorized and
    /// cannot be replaced without `t`-of-`n`; anything else is an external
    /// unconfirmed deposit and is excluded. Shared behind its own `Mutex` (not the
    /// per-`/sign` `SignState` lock): `/sign` writes it while the watchtower and
    /// fire drivers read it.
    authorized: Arc<Mutex<HashSet<Txid>>>,
    /// Queued watchtower alerts, pulled by the coordinator via `GET /events`
    /// (ADR-0002). Bounded, in-memory (DESIGN.md). Shared behind a `Mutex`: the
    /// background watchtower task writes it and `/events` reads it (V0-6b).
    alerts: Arc<Mutex<AlertQueue>>,
    /// Parsed chain-backend endpoint (rpc socket + base64 auth) for the
    /// watchtower driver, if configured. `None` ⇒ no scan task. Held so the
    /// daemon can build the backend and spawn the driver after load
    /// ([`spawn_drivers`]).
    chain_backend: Option<(SocketAddr, String)>,
    /// Unit tests build channel-valid nodes from configs that carry the required
    /// production backend stanza but intentionally launch no bitcoind. Keep their
    /// deterministic policy/state-machine tests off sockets; integration tests
    /// compile the production path and exercise the real backend.
    #[cfg(test)]
    chain_backend_override: Option<Arc<dyn ChainBackend + Send + Sync>>,
    /// The node-to-node channel runtime (V0-8a), built from the sealed manifest
    /// when `[channel]` is present. `None` ⇒ absent-channel mode: `/channel` is
    /// not mounted and no channel invariant runs. Read by the `/channel` route and
    /// the `/sign`-path candidate-registry funnel.
    pub(crate) channel: Option<channel::ChannelState>,
    /// Coordinator-authenticated requests this node owes every peer (§3
    /// propagation). Fully validated requests are staged before candidate admission.
    /// On the early PIN-refusal path, every propagatable request is staged regardless
    /// of verdict: once lockout makes the direct response uniform, propagating only a
    /// matching PIN would let a coordinator replay the nonce at a peer and distinguish
    /// `NONCE_REPLAYED` from `BAD_PIN`. A duress request must still reach the rest of
    /// the federation even when this node cannot sign it or its store is full. A
    /// malformed/bad-signature/policy-refused request is not propagated and therefore
    /// never becomes a local holder; config drift cannot turn that intent into an
    /// asymmetric arm from peer claims.
    ///
    /// A staging area, not a queue with semantics: `/sign` runs under the one
    /// `SignState` lock and must never do network I/O there, so it drops the
    /// request here and the async pump ([`propagate_outbox`]) drains it
    /// once the lock is released.
    outbox: Mutex<Vec<vault_proto::TaggedRequest>>,
}

impl Node {
    pub fn load(path: &str) -> Result<Node, Error> {
        // Open ONCE and parse from this exact inode. Re-opening by pathname after
        // parsing would let a swapped symlink bind lifecycle state to a different
        // file than the signing key that was loaded.
        let mut lifecycle_file =
            File::open(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        // P3a (holistic v0 audit): the reboot-death model (ADR-0007) assumes this
        // inode is on tmpfs/ramfs (wiped on reboot). Fail closed here if it is not,
        // unless explicitly overridden. `load` is the production entry with a real
        // inode; the unit-test `from_toml_str` path has none and never reaches here.
        assert_volatile_storage(&lifecycle_file)?;
        let mut raw = String::new();
        lifecycle_file
            .read_to_string(&mut raw)
            .map_err(|e| format!("cannot read config {path}: {e}"))?;
        // The one secret this node holds arrives HERE, on stdin, from the operator —
        // never from the config inode above (bead btc-policy-9y5.5; DESIGN.md T1).
        // Read after the config so a destroyed deployment still fails on the config,
        // which is what the reboot-death drill reads as its evidence, and so an
        // operator is not asked for a secret by a process that was going to die
        // anyway.
        //
        // Nothing re-prompts and nothing retries: under ADR-0007 a node starts once
        // in its life, at provisioning, before the host is sealed (ADR-0005). A
        // reboot does not come back here — it comes back to a bare machine with no
        // config, no key, and no way to ask for one. That is the resolution ADR-0005
        // recorded as open: sealing and an in-memory key do not conflict, because
        // there is no second startup to hand a preimage to.
        let preimage = nodekey::Preimage::read_from_stdin().map_err(|e| {
            format!(
                "cannot read the operator node-key preimage from stdin ({e}); a vault-node \
                 derives its signing key at startup and holds none at rest"
            )
        })?;
        let mut node = Node::from_toml_str(&raw, &preimage)?;
        node.require_channel_mode()?;
        node.apply_persisted_lockdown(lifecycle_file, Path::new(path))?;
        // The one-shot process generation is NOT claimed here. The public serving
        // boundary claims it only AFTER every fallible startup resource — above all
        // the listener bind — has succeeded. Claiming it during `load` would
        // let a transient bind failure, on a node that never served and therefore never
        // armed, permanently consume the generation and brick the tmpfs-held key. The
        // reboot-death gate is for a process that actually ran, not one that failed to
        // start. `apply_persisted_lockdown` above is idempotent, so it is safe to run
        // before the bind.
        Ok(node)
    }

    /// Claim the one process generation allowed to use this tmpfs-held signing
    /// key. The Armed overlay and candidate registry are deliberately RAM-only; a
    /// process crash cannot reconstruct them, while the sibling config (and its
    /// signing key) survives until the MACHINE reboots. Allowing a supervisor to
    /// reload that key would therefore resurrect an unarmed signer before `T`.
    ///
    /// The pin-independent marker is created on EVERY production start, with
    /// XATTR_CREATE as the cross-process atomic gate. It records only "this key
    /// generation has run", never whether duress occurred. Attaching it to the
    /// config/key inode gives it exactly the key's durability and one identity through
    /// every symlink/hardlink: a process exit leaves it and makes the node dead; a
    /// machine reboot wipes marker + key + config together.
    ///
    /// [`server::serve`](crate::server::serve) calls this AFTER the listener has bound
    /// but BEFORE it accepts connections — the last production startup boundary.
    /// Claiming it earlier (in `load`) would let a transient bind failure on a
    /// never-served node consume the generation and permanently brick the key;
    /// claiming it at the serving boundary cannot, while still preceding any request
    /// that could arm the node.
    pub fn claim_process_generation(&self) -> Result<(), Error> {
        let file = self
            .lifecycle_file
            .as_ref()
            .ok_or("cannot claim a process generation without a loaded config inode")?;
        write_xattr(file, GENERATION_XATTR, b"claimed\n", true).map_err(|e| {
            format!(
                "cannot claim one-shot process generation on the config/key inode ({e}); refusing \
                 to reload a signing key whose RAM-only Armed/candidate state may have died"
            )
        })?;
        file.sync_all().map_err(|e| {
            format!(
                "cannot sync the process-generation marker on the config/key inode ({e}); \
                 refusing to start"
            )
        })?;
        // Only AFTER the marker is on the inode AND synced: `/healthz` reports this
        // as "the one-shot generation is claimed", and a flag set ahead of the write
        // would claim a generation the inode does not actually record.
        self.generation_claimed.store(true, Ordering::Release);
        Ok(())
    }

    /// Bind this node to its RAMDISK config/key inode and adopt any Lockdown latch
    /// that survived into this process. Production then refuses any second process
    /// generation entirely because Armed/candidate RAM cannot be reconstructed;
    /// this latch separately preserves fail-closed lower-level state adoption.
    fn apply_persisted_lockdown(&mut self, file: File, config_path: &Path) -> Result<(), Error> {
        // Create an EMPTY value on a fresh boot, before serving, to prove the
        // filesystem and caller can perform the later Lockdown write. XATTR_CREATE
        // makes concurrent first starts harmless: the loser re-reads the winner.
        let mut marker = read_xattr(&file, LOCKDOWN_XATTR)?;
        if marker.is_none() {
            match write_xattr(&file, LOCKDOWN_XATTR, b"", true) {
                Ok(()) => {
                    file.sync_all().map_err(|e| {
                        format!(
                            "cannot sync the RAMDISK Lockdown latch on {} ({e}); refusing to start",
                            config_path.display()
                        )
                    })?;
                    marker = Some(Vec::new());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    marker = read_xattr(&file, LOCKDOWN_XATTR)?;
                }
                Err(e) => {
                    return Err(format!(
                        "cannot create the RAMDISK Lockdown latch on {} ({e}); refusing to start \
                         rather than run unable to lock down",
                        config_path.display()
                    )
                    .into())
                }
            }
        }
        let marker = marker.ok_or("Lockdown latch disappeared during startup")?;
        if !marker.is_empty() {
            self.lockdown.store(true, Ordering::Release);
        }
        self.lifecycle_file = Some(file);
        Ok(())
    }

    /// Build a node from its config TOML plus the operator-held preimage.
    ///
    /// The preimage is a PARAMETER, not a config field, and that is the whole point
    /// of this signature: the config is an artifact at rest on the node's tmpfs, the
    /// preimage is not, and the type system is where that distinction is cheapest to
    /// keep true. Production reaches this through [`Node::load`], which reads the
    /// preimage from stdin.
    pub fn from_toml_str(raw: &str, preimage: &nodekey::Preimage) -> Result<Node, Error> {
        let config: ConfigFile = toml::from_str(raw).map_err(|e| format!("bad config: {e}"))?;
        let secp = Secp256k1::new();
        // Derive the federation signing key in RAM. Nothing this reads from the
        // config is secret; the secret arrived on stdin and dies with the process.
        let kdf = nodekey::KdfParams::from_hex_salt(
            &config.node_key_salt,
            config.node_key_ops,
            config.node_key_mem_kib,
        )?;
        let seckey = nodekey::derive(preimage, &kdf)?;
        let pubkey = PublicKey::new(seckey.public_key(&secp));
        // The coordinator authentication pubkey this vault is configured with
        // (ADR-0013 §2). Parsed once here; it arms the `/sign` coord-auth gate and
        // is folded into the channel manifest hash below. Mandatory: a node with no pinned
        // coordinator could authenticate nothing, so an unparseable — or, via
        // serde, an absent — key is a fatal config error, never a silent no-gate.
        if config.coordinator_auth_pubkey.len() != 66 {
            return Err(
                "bad coordinator_auth_pubkey: expected a 33-byte compressed secp256k1 public key"
                    .into(),
            );
        }
        let coordinator_auth = PublicKey::from_str(&config.coordinator_auth_pubkey)
            .map_err(|e| format!("bad coordinator_auth_pubkey: {e}"))?;
        // The vault descriptor is parsed twice, on purpose: as concrete
        // `PublicKey` for the witness script + user-key extraction + sighash
        // (the first-light vault is definite), and as `DescriptorPublicKey` for
        // the bounded re-derivation primitive (input ownership + verified
        // change). Both parses are of the same string, so they cannot disagree.
        let descriptor = Descriptor::<PublicKey>::from_str(&config.descriptor)
            .map_err(|e| format!("bad descriptor: {e}"))?;
        let vault = Descriptor::<DescriptorPublicKey>::from_str(&config.descriptor)
            .map_err(|e| format!("bad descriptor: {e}"))?;
        // Parse + VALIDATE the vault descriptor against the fixed two-branch
        // template (ADR-0013 §1): the normal branch (user key + `t`-of-`n`
        // federation) AND the timelocked recovery branch (`older(4224679)` +
        // 2-of-3). policy-core owns the template shape, so setup and every node
        // enforce the same rule; a descriptor off-template — including one with NO
        // recovery branch (a vault with no exit) or an `older(30375)` BLOCK lock —
        // is a fatal config error here, never a runtime refusal. `t` and the node
        // keys come from the descriptor, never config: both are consensus facts
        // about the script the coins are locked to. A config copy of `t` could
        // disagree with it — too low and this node broadcasts transactions the
        // network rejects, too high and every legitimate spend stalls forever. The
        // node keys are the descriptor-canonical set the channel manifest's
        // `node_id` bijection is defined over (§1); they come back in descriptor
        // order, and the channel derives the canonical (lexicographic) order itself.
        // The recovery keys are validated (2-of-3, off-branch) but not otherwise
        // used by the node — recovery is a user-side exit (vault-cli), never
        // node-signed.
        let template = policy_core::parse_vault_template(&descriptor)
            .map_err(|e| format!("bad descriptor: {e}"))?;
        let user_pubkey = template.user_key;
        let threshold = template.threshold;
        let node_keys = template.node_keys;
        // The derived key must be a key this vault actually names. This is the
        // fail-closed end of the wskdf path: a mistyped preimage, a salt from
        // another node's bundle, or a config paired with the wrong operator secret
        // all land here, and all of them must be a FATAL startup error rather than a
        // daemon that serves with a key no descriptor contains. Such a node would
        // authenticate, validate, and "sign" every request while producing partials
        // that can never combine — the whole federation would look healthy and no
        // spend would ever complete, with nothing on the wire to say why.
        //
        // `[channel]` mode re-derives a stronger form of this (the manifest's self
        // entry must equal this key, and every manifest entry must equal a canonical
        // descriptor key — `ChannelState::build`). This check is what covers the
        // channel-LESS fixtures, and it runs first so the error names the cause.
        if !node_keys.iter().any(|key| key.inner == pubkey.inner) {
            return Err(format!(
                "the wskdf-derived node key {pubkey} is not one of the vault descriptor's \
                 federation node keys: the operator preimage does not match this node's \
                 node_key_salt/node_key_ops/node_key_mem_kib, or the config belongs to a \
                 different node"
            )
            .into());
        }
        // Confirmation-gated arming commits only on a peer `/channel` receipt. A
        // 1-of-n channel federation has no peer receipt to wait for when n = 1, and
        // treating self-holding as an ingress commit would violate V0-4b §0's
        // load-bearing "the handler never arms" rule. ADR-0013 §1 already requires
        // t >= 2; enforce that production/channel invariant here while retaining the
        // deliberately channel-less one-key fixtures used by pre-channel tests.
        if config.channel.is_some() && threshold < 2 {
            return Err(
                "[channel] confirmation-gated arming requires a federation threshold of at \
                 least 2 (ADR-0013 §1); a t=1 carrier can never receive the peer confirmation \
                 that is the only authorized arm trigger"
                    .into(),
            );
        }
        // Confirmation must tolerate every minority smaller than `t` withholding
        // propagation while also leaving no disjoint unfrozen signing quorum. The
        // first requirement is `n - (t - 1) >= t`; the second is `2t > n`. Together
        // they force `n = 2t - 1`. Merely checking quorum intersection admits e.g.
        // 4-of-5, where three compromised nodes can withhold and leave the two honest
        // nodes below the arm threshold even though those same three nodes plus one
        // honest partial can finalize the coerced spend. Channel-less legacy fixtures
        // do not run this protocol.
        if config.channel.is_some()
            && node_keys.len() != threshold.saturating_mul(2).saturating_sub(1)
        {
            return Err(format!(
                "[channel] confirmation-gated arming requires n = 2t - 1, \
                 but descriptor threshold is {threshold}-of-{}: the federation must both \
                 tolerate t-1 withholding nodes and leave no unfrozen signing quorum",
                node_keys.len()
            )
            .into());
        }
        // The coordinator is a DISTINCT role from the two the descriptor names:
        // its key authorizes *requests*, the user key authorizes *spends*, and the
        // federation keys *sign* them. Reusing one key across two roles silently
        // voids that separation — whoever holds that role's secret could then mint
        // coordinator-authenticated requests, which is precisely what this trust
        // root exists to prevent (a compromised node must not be able to
        // manufacture coordinator requests, ADR-0013 §2/§4). The collapse is
        // invisible at runtime: every gate still passes, so nothing else would
        // ever report it. No deployment needs the reuse — one human may hold two
        // roles, but a second keypair is free — so a collision is a fatal
        // provisioning error, caught here with the config's other cross-field
        // invariants rather than trusted to the setup ceremony.
        //
        // All three checks below compare the curve point (`.inner`), never
        // `bitcoin::PublicKey`, which also compares its compressed-encoding flag:
        // roles are identities on the curve, and an encoding must not disguise
        // reuse. No key reaching these checks can currently be uncompressed — the
        // length check above pins the coordinator key to 33 bytes, and `wsh()`
        // rejects uncompressed keys when the descriptor parses — so this is one
        // rule stated once for all three, not a live gap in any of them.
        if coordinator_auth.inner == user_pubkey.inner {
            return Err(
                "coordinator_auth_pubkey must not be the descriptor's user key: the coordinator \
                 authorizes requests and the user authorizes spends, so one key for both lets the \
                 user key mint its own coordinator requests"
                    .into(),
            );
        }
        if node_keys
            .iter()
            .any(|key| key.inner == coordinator_auth.inner)
        {
            return Err(
                "coordinator_auth_pubkey must not be one of the descriptor's federation node \
                 keys: one key for both roles lets a single compromised node mint coordinator \
                 requests to its peers"
                    .into(),
            );
        }
        // The channel identity is not a fourth independent key: `derive_channel_seckey`
        // is a deterministic, publicly-known function of the federation seckey, so
        // holding a node's signing key IS holding its channel key. A coordinator key
        // equal to a channel pubkey therefore collapses the same two roles the check
        // above rejects — it just spells the node's key differently. `ChannelState::build`
        // catches this for every node in the manifest, but only `[channel]` mode has a
        // manifest, so without this an absent-channel node accepts the collapse.
        // A node holds only its OWN seckey, so its own derived key is the only one it
        // can check here — which makes this a tripwire, not the complete check. The
        // reused node always refuses to boot (every node is provisioned with the same
        // vault-wide coordinator key), but the other n−1 cannot detect the collapse and
        // a quorum survives one dead node, so an operator who ignores the dead node
        // keeps a federation that honors requests minted by its key holder. The residual
        // is bounded — coordinator auth is one gate, and the user signature and PIN
        // still gate signing — and `[channel]` mode's `ChannelState::build` is the
        // complete check, because only it has the manifest to check peers against.
        if channel::channel_pubkey_of(&channel::derive_channel_seckey(&seckey)).inner
            == coordinator_auth.inner
        {
            return Err(
                "coordinator_auth_pubkey must not be this node's derived channel key: the \
                 channel key is derived from the node's federation seckey, so one key for both \
                 roles lets this node mint coordinator requests for the whole vault"
                    .into(),
            );
        }
        let witness_script = descriptor
            .explicit_script()
            .map_err(|e| format!("descriptor has no witness script: {e}"))?;
        let max_vault_satisfaction_weight = descriptor
            .max_weight_to_satisfy()
            .map_err(|e| format!("cannot bound vault satisfaction weight: {e}"))?
            .to_wu();
        // wallet_id binds a commitment to this vault. Hash the descriptor's
        // canonical string (checksum included) so coordinator and node — which
        // parse the same descriptor — derive the same id.
        let wallet_id = sha256::Hash::hash(descriptor.to_string().as_bytes()).to_byte_array();
        let mut allowed = Vec::new();
        for entry in &config.allowlist {
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(entry)
                .map_err(|e| format!("bad allowlist descriptor {entry}: {e}"))?;
            allowed.push(descriptor);
        }
        let escape_descriptor =
            Descriptor::<DescriptorPublicKey>::from_str(&config.escape_descriptor)
                .map_err(|e| format!("bad escape_descriptor: {e}"))?;
        if config.hold_secs >= config.max_commitment_age_secs {
            return Err(format!(
                "max_commitment_age_secs ({}) must exceed hold_secs ({})",
                config.max_commitment_age_secs, config.hold_secs
            )
            .into());
        }
        // The Hot budget's velocity window must cover every candidate throughout
        // its node-authorized completion lifetime (ADR-0014 §3). A node caps a
        // commitment's expiry at `now +
        // max_commitment_age_secs`, so a spend accepted at `now` can still combine
        // and broadcast at any point up to that horizon. With a SHORTER window its
        // reservation ages out while the spend itself is still live, and the
        // attacker gets the budget back for free: accept V at `t`, wait
        // `hot_window_secs`, accept another V at `t + window`, and both broadcast —
        // the aggregate bound this whole mechanism exists to enforce is simply
        // gone. One window that dominates the commitment lifetime is what lets ONE
        // cap bound both newly admitted in-flight outflow and the rate.
        if config.hot_window_secs < config.max_commitment_age_secs {
            return Err(format!(
                "hot_window_secs ({}) must be at least max_commitment_age_secs ({}): a velocity \
                 window shorter than the commitment lifetime lets a reservation age out while \
                 its spend can still broadcast, so the aggregate Hot budget would not bind",
                config.hot_window_secs, config.max_commitment_age_secs
            )
            .into());
        }
        // Either Hot cap at zero is a silent refuse-everything, the same class of
        // provisioning error as `combine_slack_secs = 0` and `escape_coverage_pct =
        // 0` below. `check_hot_budget` refuses on `outflow > max_per_tx` and the
        // ledger on `sum + outflow > max_per_window`, so a zero either way makes
        // every hot spend of even one satoshi inadmissible and quietly reduces the
        // vault to escape-and-refresh-only — a vault that looks configured and can
        // never pay its hot wallet. "Disable the hot wallet" is not a Hot-budget
        // setting; it is an empty allowlist.
        if config.hot_max_per_tx == 0 || config.hot_max_per_window == 0 {
            return Err(format!(
                "hot_max_per_tx ({}) and hot_max_per_window ({}) must both be greater than 0: \
                 a zero cap refuses every hot spend, silently reducing the vault to \
                 escape-and-refresh-only (ADR-0014)",
                config.hot_max_per_tx, config.hot_max_per_window
            )
            .into());
        }
        // A per-tx cap above the window cap is a dead knob, and a misleading one.
        // The ledger reserves the FULL outflow at ingress, so any spend in
        // `(max_per_window, max_per_tx]` clears `policy-core` and is then refused
        // `HOT_VELOCITY_EXCEEDED` regardless — the effective per-transaction bound
        // is silently `min(per_tx, per_window)`. That contradicts the "both are
        // needed" split this pair documents (a per-tx cap alone is unbounded in
        // count; a window cap alone lets one spend take the whole window), and an
        // operator sizing the two off ADR-0014's guidance would be reading a bound
        // the node does not actually apply. Equality is fine and is the intended
        // "one maximal spend may consume the whole window" setting.
        if config.hot_max_per_tx > config.hot_max_per_window {
            return Err(format!(
                "hot_max_per_tx ({}) must not exceed hot_max_per_window ({}): the ledger \
                 reserves the whole outflow at ingress, so a larger per-tx cap can never be \
                 reached and the effective bound would silently be the window cap (ADR-0014)",
                config.hot_max_per_tx, config.hot_max_per_window
            )
            .into());
        }
        // The combine window `[fire, fire + combine_slack_secs]` must be at least one
        // confirmed-vault cache refresh interval (V0-6b's `SCAN_INTERVAL`) wide. Two
        // silent-failure traps live below that floor:
        //  - A zero-width window `[fire, fire]`: the fan-out never *initiates* a send once
        //    `now >= deadline` (see `try_endpoints`), so no partial ever leaves any node
        //    after its fire event, no candidate reaches quorum, and every accepted spend
        //    signs at ingress then silently never broadcasts.
        //  - A window shorter than the refresh cadence: the fire-time escape-coverage check
        //    reads the background-maintained cache (never a synchronous `scantxoutset` on
        //    the combine path, bead 9y5.3), and that cache refreshes only every
        //    `SCAN_INTERVAL`. A block arriving just before the fire event leaves the cache
        //    stale for the WHOLE window, so `confirmed_candidates` refuses coverage every
        //    tick and `prune` deletes the armed escape before the next refresh — silently
        //    reducing duress to recovery-only (v0-exit 9y5.3 review, codex P2).
        // Floor at TWICE the refresh interval. The refresher (`spawn_drivers`) ticks
        // `SCAN_INTERVAL` from each pass's COMPLETION (`ticker.reset()` after an awaited
        // pass), so the worst-case gap between refreshes is `SCAN_INTERVAL + pass_duration`,
        // not `SCAN_INTERVAL`; a floor of exactly one interval would leave the equality case
        // marginal (codex/Fable pass 4). Two intervals gives a full interval of margin for a
        // pass to complete inside the window. This is NOT a hard guarantee: a single refresh
        // pass slower than the window (a post-reorg full `scantxoutset` on a large chain) can
        // still leave the cache stale for the whole window, which — like a backend stall —
        // degrades duress to frozen-funds → recovery, never theft (ADR-0012). The default
        // (60s) is 6× the interval; only pathologically short windows are rejected. Reject at
        // load, not at "money never moved" (same class as the `escape_coverage_pct = 100`
        // fatal).
        let min_combine_slack = 2 * watchtower::SCAN_INTERVAL.as_secs();
        if config.combine_slack_secs < min_combine_slack {
            return Err(format!(
                "combine_slack_secs ({}) must be at least twice the vault cache refresh \
                 interval ({min_combine_slack}s): a shorter combine window can go stale for its \
                 whole duration when a block arrives near the fire event (the refresher ticks \
                 from pass completion, so the worst-case gap exceeds one interval), so the \
                 escape sweep's coverage check fails every tick and the armed escape is pruned \
                 before the next refresh — silently reducing duress to recovery-only (a \
                 zero-width window additionally lets no node transmit a partial after the fire \
                 event)",
                config.combine_slack_secs
            )
            .into());
        }
        // A zero refresh interval disables ADR-0013 §6's per-coin burn-rate
        // bound: every mark is pruned immediately and `elapsed < interval` can
        // never refuse. Unlike `duress_delay_secs`, zero has no useful meaning
        // here, so fail at provisioning rather than silently accepting an
        // unbounded refresh chain.
        if config.refresh_min_interval_secs == 0 {
            return Err(
                "refresh_min_interval_secs must be greater than 0: zero disables the per-coin \
                 refresh burn-rate bound"
                    .into(),
            );
        }
        // Bounded ε (ADR-0012 duress-T; codex D4 "reject absurd ε"). ε is a small
        // margin subtracted from a pending hot spend's public Hold-expiry so the
        // escape fires strictly before it would settle. An ε larger than the whole
        // commitment lifetime is nonsensical — it could drive `T` arbitrarily far
        // into the past for any pending spend and collapse the hostage window with
        // no relation to real clock skew — so it is a fatal provisioning error, not
        // a runtime surprise. (`0` is permitted: no margin, e.g. a single-node
        // regtest with no skew.)
        if config.epsilon_secs > config.max_commitment_age_secs {
            return Err(format!(
                "epsilon_secs ({}) must not exceed max_commitment_age_secs ({}): an ε larger \
                 than the commitment lifetime is absurd (ADR-0012 bounded ε)",
                config.epsilon_secs, config.max_commitment_age_secs
            )
            .into());
        }
        // Bounded duress delay (Reviewer round-12 P1; same class as bounded ε). The
        // hostage window sets the escape's fire time `T = first_seen +
        // duress_delay_secs` (absent an earlier pending hot Hold-expiry). Under a
        // NORMAL pin the identical no-op delayed slot still installs a `[T, T +
        // combine_slack_secs]` fire window on its escape candidate, and `prune`
        // exempts that escape candidate AND its paired spend from commitment-expiry
        // eviction while `now <= deadline` (constant-observable capacity, ADR-0012
        // silence). A `duress_delay_secs` past the commitment-age cap makes that
        // exemption outlive the candidates' OWN expiry, so sustained ordinary traffic
        // accumulates un-prunable escape+spend pairs and can exhaust the bounded
        // candidate store — defeating requirement 7's finite-lifecycle guarantee that
        // an armed candidate "cannot pin the capacity cap". At or below the cap the
        // exemption closes within the same `combine_slack` overrun the armed-escape
        // reconciliation already grants. A delay longer than the maximum commitment
        // lifetime is also nonsensical for the design — the escape would be scheduled
        // past the point any pending hot spend could still be live. Reject it at
        // provisioning, exactly as ε above (`0` remains valid: fire immediately).
        if config.duress_delay_secs > config.max_commitment_age_secs {
            return Err(format!(
                "duress_delay_secs ({}) must not exceed max_commitment_age_secs ({}): a delay \
                 past the commitment lifetime keeps the constant-observable escape slot's \
                 expiry exemption open beyond the candidates' own expiry, so ordinary traffic \
                 could exhaust the bounded candidate store (ADR-0012 duress-T; requirement 7)",
                config.duress_delay_secs, config.max_commitment_age_secs
            )
            .into());
        }
        // The §0 delivery horizon must be non-zero (a zero margin guarantees the
        // fan-out nothing, which is the near-`now`-expiry split vector this check
        // exists to close) and must be strictly below the node's own expiry cap. At
        // equality, coord-auth's `expiry <= now + max_age` and this check's `expiry >=
        // now + horizon` collapse to ONE timestamp; a one-second queue/clock advance
        // then refuses every request. Keep a non-empty acceptance window.
        //
        // Gated on channel mode, like the two §0 invariants above and like the runtime
        // gate itself: `ensure_delivery_horizon` returns early for a channel-less node
        // (no peers, no fan-out, no confirmation path, so it can never arm), and
        // `the_delivery_horizon_does_not_apply_without_a_channel` pins that. Enforcing
        // a cross-field bound on a field the node provably never reads would reject
        // working legacy fixtures — e.g. the default 60s horizon against a 60s
        // `max_commitment_age_secs` — for a window that does not exist there.
        if config.channel.is_some()
            && (config.delivery_horizon_secs == 0
                || config.delivery_horizon_secs >= config.max_commitment_age_secs)
        {
            return Err(format!(
                "delivery_horizon_secs ({}) must be in 1..{}: it is the margin that lets an \
                 authenticated carrier reach every peer before it expires (V0-4b §0 \
                 confirmation-gated arming), and a horizon at or above \
                 max_commitment_age_secs leaves no usable authenticated-expiry window",
                config.delivery_horizon_secs, config.max_commitment_age_secs
            )
            .into());
        }
        // The escape coverage threshold is a percentage (ADR-0013 §6). `0` would
        // accept any escape (no coverage floor); `> 100` is unsatisfiable (no escape
        // can pay more than the swept value to the escape wallet), silently turning
        // every sweep into lockdown-only. Both are provisioning errors.
        if config.escape_coverage_pct == 0 || config.escape_coverage_pct > 100 {
            return Err(format!(
                "escape_coverage_pct ({}) must be in 1..=100 (ADR-0013 §6)",
                config.escape_coverage_pct
            )
            .into());
        }
        // With vault-only inputs, 100% output coverage leaves zero satoshis for the
        // escape's fee. A positive panic feerate floor simultaneously requires a
        // positive fee, so accepting that pair of settings would make every sweep
        // deterministically inadmissible and silently reduce duress to recovery-only.
        if config.escape_coverage_pct == 100 && config.escape_feerate_floor > 0 {
            return Err("escape_coverage_pct = 100 is incompatible with a positive \
                 escape_feerate_floor: the escape cannot both deliver every protected \
                 satoshi and pay a positive fee"
                .into());
        }
        // The EXPIRY_TOO_SHORT floor a hot spend must clear is `now + hold_secs +
        // combine_slack_secs`, while the node caps every accepted expiry at `now +
        // max_commitment_age_secs`. If the floor exceeds the cap, NO hot-class spend
        // can ever be accepted — a silent refuse-everything. Reject at load. (`==`
        // is allowed: the sole acceptable expiry is then exactly the cap, and
        // EXPIRY_TOO_SHORT accepts equality.)
        if config.hold_secs.saturating_add(config.combine_slack_secs)
            > config.max_commitment_age_secs
        {
            return Err(format!(
                "hold_secs ({}) + combine_slack_secs ({}) must not exceed \
                 max_commitment_age_secs ({}): the EXPIRY_TOO_SHORT floor would sit past the \
                 node's own expiry cap, so every hot-class spend would be refused",
                config.hold_secs, config.combine_slack_secs, config.max_commitment_age_secs
            )
            .into());
        }
        // Descriptor membership: the escape wallet must be an allowlist entry
        // so its sweep passes the destination check (canonical-string equality
        // covers checksum/format normalization).
        let escape_canonical = escape_descriptor.to_string();
        if !allowed.iter().any(|d| d.to_string() == escape_canonical) {
            return Err("escape_descriptor must also be present in allowlist".into());
        }
        // These are the descriptors that make a non-vault, non-escape output Hot.
        // Seal their canonical strings beside the numeric budget caps; otherwise
        // two nodes could share a manifest hash while classifying and metering the
        // same output differently. The manifest encoder sorts/deduplicates because
        // TOML order has no policy meaning.
        let hot_allowlist: Vec<String> = allowed
            .iter()
            .map(ToString::to_string)
            .filter(|descriptor| descriptor != &escape_canonical)
            .collect();
        // Both enrolled PINs must be Argon2id PHC strings with valid params and
        // DISTINCT salts (ADR-0012). Validated here so a placeholder SHA-256, a
        // non-argon2id KDF, or a copy-pasted shared salt is a fatal provisioning
        // error, never a silently-weakened compare at the wrench.
        pin::validate_digests(&config.pin_normal_hash, &config.pin_duress_hash)?;
        // Initialize the carrier KDF (including its per-boot salt) at load, before
        // serving. `/dev/urandom` failure is therefore a clean startup error, not a
        // first-request panic while `sign_state` is held.
        let carrier_kdf = pin::CarrierKdf::new(
            &config.pin_normal_hash,
            &config.pin_duress_hash,
            channel::random_bytes::<32>()?,
        )?;
        // The pin-attempt budget config (ADR-0013 §7): reject undefined table
        // indices and zero durations that silently disable accumulation/lockout.
        let pin_budget_config = pin::PinBudgetConfig {
            max_attempts: config.pin_attempt_budget.max_attempts,
            window_secs: config.pin_attempt_budget.window_secs,
            backoff_schedule: config.pin_attempt_budget.backoff_schedule.clone(),
            lockout_secs: config.pin_attempt_budget.lockout_secs,
        };
        pin_budget_config.validate()?;
        let pin_budget = pin::AttemptBudget::new(pin_budget_config.max_attempts)?;
        // The pin digests are stored (owned) inside the evaluator, re-parsed per
        // request. NOT lowercased: a PHC string's base64 salt/hash is case-sensitive,
        // so the old `.to_lowercase()` would corrupt it.
        let pin_evaluator: Arc<dyn pin::PinEvaluator> =
            Arc::new(pin::Argon2Evaluator::with_work_lock(
                config.pin_normal_hash.clone(),
                config.pin_duress_hash.clone(),
                carrier_kdf.work_lock(),
            ));
        // Parse the optional watchtower endpoint now so a bad address fails at
        // load, not silently at the first scan.
        let chain_backend = config
            .chain_backend
            .as_ref()
            .map(|cb| {
                SocketAddr::from_str(&cb.rpc_addr)
                    .map(|addr| (addr, cb.auth.clone()))
                    .map_err(|e| format!("bad chain_backend.rpc_addr {:?}: {e}", cb.rpc_addr))
            })
            .transpose()?;
        // Channel mode is what makes this node responsible for BROADCASTING (§5):
        // it collects peers' partials, combines at fire, package-validates, and
        // pushes the transaction itself. With no chain backend it can do none of
        // that — it would authenticate requests, sign at ingress, exchange
        // partials, reach quorum, and then silently never broadcast, while every
        // `/sign` answer told the coordinator the spend was accepted. That failure
        // is invisible until the user notices the money never moved, so it is a
        // fatal provisioning error here rather than a runtime surprise.
        if config.channel.is_some() && chain_backend.is_none() {
            return Err(
                "[channel] mode requires a [chain_backend]: the nodes combine and broadcast \
                 (ADR-0012 Model B), so a node with no chain view of its own could accept and \
                 sign a spend it can never broadcast"
                    .into(),
            );
        }
        // The alert queue is shared with the channel so freshness-reject events
        // surface through the same `GET /events` path (codex I2).
        let alerts = Arc::new(Mutex::new(AlertQueue::new(watchtower::DEFAULT_ALERT_CAP)));
        let hot_budget = HotBudget {
            max_per_tx_sat: config.hot_max_per_tx,
            max_per_window_sat: config.hot_max_per_window,
            window_secs: config.hot_window_secs,
        };
        // Build the channel runtime iff `[channel]` is present. Every §2 startup
        // invariant runs inside `build`; a failure is a fatal config error here,
        // never a runtime refusal.
        let channel = config
            .channel
            .as_ref()
            .map(|cfg| {
                channel::ChannelState::build(
                    cfg,
                    &seckey,
                    pubkey,
                    wallet_id,
                    &node_keys,
                    config.listen_port,
                    // The coordinator key is part of the hashed manifest (ADR-0013
                    // §4), so the node's manifest_hash binds the vault's one
                    // coordinator: a different key is a different vault (§7).
                    coordinator_auth,
                    // The Hot budget is a Manifest preimage field (ADR-0014 §6),
                    // so `build` both hashes it and hands it to the velocity
                    // ledger: the caps a node enforces are provably the caps the
                    // federation sealed.
                    hot_budget,
                    &hot_allowlist,
                    &escape_canonical,
                    config.max_derivation_index,
                    // The two federation-uniform fire-time selector inputs (bead
                    // btc-policy-9y5.7): sealed into the manifest so a node whose
                    // floor/coverage differs from the federation's fails startup.
                    config.escape_feerate_floor,
                    config.escape_coverage_pct,
                    Arc::clone(&alerts),
                )
            })
            .transpose()?;
        let sign_state = SignState {
            pin_budget,
            ..SignState::default()
        };
        Ok(Node {
            listen_port: config.listen_port,
            seckey,
            pubkey,
            user_pubkey,
            witness_script,
            check_params: policy_core::CheckParams {
                vault,
                allowed,
                // policy-core keeps this optional (a library contract: with no
                // escape configured nothing is escape-class). A node always has
                // one — the config above made it mandatory.
                escape: Some(escape_descriptor),
                max_derivation_index: config.max_derivation_index,
                // The per-tx half of the Hot budget (ADR-0014 §1). It rides in
                // CheckParams because it is a pure, chain-view-free property of
                // the spend, decided beside the allowlist and fee checks.
                hot_max_per_tx: Amount::from_sat(config.hot_max_per_tx),
            },
            pin_evaluator,
            carrier_kdf,
            pin_budget_config,
            lockdown: AtomicBool::new(false),
            // Path-less construction (unit tests): no persistence. `Node::load`
            // attaches the config/key inode and reads its latch so a real
            // deployment's Lockdown survives a process restart.
            lifecycle_file: None,
            duress_arm: AtomicU64::new(0),
            spend_preflight: AtomicUsize::new(0),
            last_deadline_tick: AtomicU64::new(0),
            // Path-less construction claims no generation (there is no config inode
            // to claim it on), so `/healthz` on a unit-test node honestly reports
            // `generation_claimed: false`. `server::serve` is what flips it.
            generation_claimed: AtomicBool::new(false),
            coordinator_auth,
            wallet_id,
            policy_version: config.policy_version,
            max_commitment_age_secs: config.max_commitment_age_secs,
            hold_secs: config.hold_secs,
            combine_slack_secs: config.combine_slack_secs,
            hot_budget,
            threshold,
            max_vault_satisfaction_weight,
            refresh_min_interval_secs: config.refresh_min_interval_secs,
            refresh_max_feerate: config.refresh_max_feerate,
            duress_delay_secs: config.duress_delay_secs,
            epsilon_secs: config.epsilon_secs,
            delivery_horizon_secs: config.delivery_horizon_secs,
            escape_coverage_pct: config.escape_coverage_pct,
            escape_feerate_floor: config.escape_feerate_floor,
            sign_state: Mutex::new(sign_state),
            authorized: Arc::new(Mutex::new(HashSet::new())),
            alerts,
            chain_backend,
            #[cfg(test)]
            chain_backend_override: Some(Arc::new(crate::chain::mock::MockBackend::default())),
            channel,
            outbox: Mutex::new(Vec::new()),
        })
    }

    /// The vault's own watched scriptPubKey(s) for the watchtower scan
    /// (ADR-0001). The vault is a single definite P2WSH, so this is one script —
    /// the P2WSH of the node's witness script. Both descriptor branches (normal
    /// AND recovery) share this one scriptPubKey (ADR-0013 §1), so it covers a
    /// recovery spend too; the branch is told apart from the spend's witness.
    pub fn vault_scripts(&self) -> Vec<ScriptBuf> {
        vec![ScriptBuf::new_p2wsh(&self.witness_script.wscript_hash())]
    }

    /// Run one watchtower scan pass (ADR-0001) against `backend`, classifying
    /// every spend of the vault's watched scripts at or after `from_height` and
    /// queueing new alerts. Returns how many NEW alerts were queued (a re-scan of
    /// an already-alerted spend queues nothing).
    ///
    /// This is the SAME pass the daemon's background driver runs — both go
    /// through [`watchtower::scan_pass`] over this node's shared authorized set
    /// and alert queue — so tests and production exercise one code path. A spend
    /// that took the recovery branch is classified `RecoveryPathSpend` from its
    /// witness (the two branches share one scriptPubKey); every other vault spend
    /// this node did not validate-and-accept is `UnrecognizedSpend`
    /// ([`watchtower::scan`]).
    pub fn watchtower_tick(
        &self,
        backend: &dyn ChainBackend,
        from_height: u32,
    ) -> Result<usize, Error> {
        // A callable single pass builds a throwaway cursor at `from_height`; the
        // reorg-rewind history lives in the daemon driver's persistent cursor
        // ([`watchtower::spawn_driver`]). Both run the SAME `scan_pass`.
        let mut cursor = watchtower::ScanCursor::starting_at(from_height);
        watchtower::scan_pass(
            backend,
            &self.vault_scripts(),
            &self.authorized,
            &self.alerts,
            &mut cursor,
        )
        .map(|outcome| outcome.new_alerts)
    }

    /// The queued events after cursor `since`, plus the new cursor (the `GET
    /// /events` pull API; ADR-0002). No loss, no duplication across successive
    /// pulls. Carries watchtower alerts and — under `[channel]` — channel
    /// freshness-reject events, both through the one queue (codex I2).
    pub fn events(&self, since: u64) -> (Vec<Event>, u64) {
        self.alerts
            .lock()
            .expect("alerts lock poisoned")
            .since(since)
    }

    /// This node's own chain backend, when one is configured.
    fn backend(&self) -> Option<Arc<dyn ChainBackend + Send + Sync>> {
        #[cfg(test)]
        if let Some(backend) = &self.chain_backend_override {
            return Some(Arc::clone(backend));
        }
        let (addr, auth) = self.chain_backend.clone()?;
        Some(Arc::new(BitcoindBackend::new_for_node(
            addr,
            auth,
            &self.pubkey.to_bytes(),
        )))
    }

    /// Validate production-only backend capabilities before the process-generation
    /// marker is claimed and before any request can be served.
    pub fn validate_chain_backend(&self) -> Result<(), Error> {
        let Some((addr, auth)) = self.chain_backend.clone() else {
            return Ok(());
        };
        BitcoindBackend::new(addr, auth).verify_required_indexes()
    }

    /// Model B has no channel-less completion path: `/sign` structurally withholds
    /// the node partial, so only the node channel can collect `t` partials and let a
    /// node broadcast. Keep the parser usable by deterministic policy tests, but
    /// fail every runnable daemon before it can acknowledge an unfinishable spend.
    pub(crate) fn require_channel_mode(&self) -> Result<(), Error> {
        if self.channel.is_none() {
            return Err(
                "[channel] is required for the Model-B node daemon: /sign withholds partials, so \
                 a channel-less node cannot collect a quorum or broadcast"
                    .into(),
            );
        }
        Ok(())
    }

    /// Enter the terminal **Lockdown** state (ADR-0008). The entry point V0-4b calls
    /// at `T` under duress; V0-4a exposes it so the state + `FRAUD_SUSPECTED` refusal
    /// can be built and tested in isolation. Monotonic: once entered there is no
    /// programmatic exit (RAMDISK, no reset on sealed nodes — the only exit is the
    /// recovery path, and a reboot is node death, strictly stronger).
    ///
    /// The flag is set while holding `sign_state` so the transition LINEARIZES with
    /// in-flight `/sign` and `/refresh` handlers, which re-check `is_locked_down`
    /// under that same lock: a request either commits fully BEFORE this store (it
    /// began pre-Lockdown) or observes the flag and refuses — none registers a new
    /// candidate AFTER Lockdown. Because it acquires `sign_state`, it MUST NOT be
    /// called while that lock is already held.
    ///
    /// This linearization is the NORMAL path only. The poison-FORCED sibling
    /// [`Node::force_lockdown_fail_closed`] latches the SAME flag WITHOUT any lock, so it
    /// does NOT linearize — a handler inside its `sign_state` critical section can still
    /// read `is_locked_down() == false` after that latch. That is safe because the forced
    /// path fires ONLY when a critical lock is already poisoned: the racing handler then
    /// either cannot exist (a poisoned `sign_state` has no live holder) or panics
    /// fail-closed at its own store op (e.g. `register_pair`) before anything egresses
    /// (see that fn's doc). Reason about post-Lockdown registration as "impossible OR
    /// fail-closed-panics on the poisoned store", never just "impossible".
    pub fn enter_lockdown(&self) {
        let _guard = self.sign_state.lock().expect("sign_state lock poisoned");
        // The dedicated deadline driver and the fire pass can observe T together.
        // Re-check (in `latch_lockdown`) after taking their shared signing-state lock
        // so only the winner performs the tmpfs latch write; terminal state remains
        // monotonic.
        self.latch_lockdown();
    }

    /// Persist the RAMDISK lockdown latch and flip the in-RAM flag. Takes NO lock: it
    /// is the shared body of [`Self::enter_lockdown`] (which holds `sign_state` around
    /// it, to linearize the transition with in-flight `/sign`) and of
    /// [`Self::force_lockdown_fail_closed`] (the panic-boundary path, which must NOT
    /// touch `sign_state` because the panic it is recovering from may have poisoned it).
    fn latch_lockdown(&self) {
        if self.is_locked_down() {
            return;
        }
        // Persist the latch to tmpfs BEFORE flipping the in-RAM flag, so a crash or
        // OOM-kill after this point restarts LOCKED (fail-closed): once the marker is
        // on the config inode the next process reads it, and the only remaining
        // window — a crash between the write and the store below — still leaves the
        // marker there, i.e. still locked. The xattr write uses the descriptor
        // pre-opened at startup (see `lifecycle_file`), so it allocates NO new fd and
        // cannot be blocked by fd-table exhaustion (EMFILE). Durability = key
        // durability, and pathname aliases cannot select another latch.
        let persistence_error = self.lifecycle_file.as_ref().and_then(|file| {
            write_xattr(file, LOCKDOWN_XATTR, b"locked\n", false)
                .and_then(|()| file.sync_all())
                .err()
        });
        self.lockdown.store(true, Ordering::Release);
        if let Some(e) = persistence_error {
            // Only ENOSPC-class failure remains (the RAM is full); irreducible
            // (you cannot write to full storage) and self-limiting — such a node
            // is failing and a reboot is node death = safe. The in-RAM latch is
            // already set above, BEFORE this best-effort diagnostic, so even a
            // broken stderr sink cannot prevent this process from locking down.
            best_effort_stderr(format_args!(
                "enter_lockdown: WARNING could not persist RAMDISK lockdown latch: {e} \
                 (this process stays locked; the one-shot generation gate forbids restart)"
            ));
        }
    }

    /// Force terminal **Lockdown** from a panic-recovery boundary WITHOUT taking any
    /// lock the panicking critical section could have poisoned (bead btc-policy-9y5.2).
    ///
    /// The uniform `.expect("… lock poisoned")` convention means a panic while holding
    /// `sign_state` or the channel `store` lock poisons it, and every later `.lock()`
    /// on it re-panics. [`Self::enter_lockdown`] itself acquires `sign_state`, so on
    /// that path it would re-panic instead of locking down — leaving a poisoned node
    /// that can neither Lockdown-at-T nor serve, an ambiguous zombie. This path instead
    /// reaches the SAME terminal latch through poison-independent state only: the
    /// pre-opened `lifecycle_file` descriptor (no lock, no fresh fd) and the atomic
    /// `lockdown` flag. It is the deterministic fail-closed destination the tick/handler
    /// safety nets ([`fire_tick_with_lockdown_net`], [`lockdown_tick_with_lockdown_net`],
    /// and the `/sign` + `/channel` handler panic arms) steer a panicked node into.
    ///
    /// Safe to run without `sign_state`'s linearization: this is only ever called after
    /// a caught panic in a critical section, and that panic poisoned the very lock a
    /// concurrent handler would need to register a candidate — so poison propagation,
    /// not this lock, is what blocks any post-Lockdown signing. Monotonic and
    /// idempotent, exactly like [`Self::enter_lockdown`].
    pub(crate) fn force_lockdown_fail_closed(&self) {
        self.latch_lockdown();
    }

    /// Whether a production critical-section lock is poisoned — i.e. some thread
    /// panicked while holding `sign_state` or the channel `store` lock, unwinding
    /// through its guard. The tick/handler safety nets read this after catching a panic
    /// to decide whether to force fail-closed Lockdown: a poisoned lock means a critical
    /// section tore mid-mutation, so the node must not keep serving as if intact. A
    /// benign panic that held neither lock leaves both un-poisoned and does not lock the
    /// node down.
    pub(crate) fn critical_lock_poisoned(&self) -> bool {
        self.sign_state.is_poisoned()
            || self
                .channel
                .as_ref()
                .is_some_and(channel::ChannelState::store_poisoned)
    }

    /// Whether this node is in Lockdown. Read at the top of every spend/refresh (a
    /// lock-free fast path) AND re-checked under `sign_state` inside the handler, so
    /// a locked-down node answers `FRAUD_SUSPECTED` and does nothing else.
    pub fn is_locked_down(&self) -> bool {
        self.lockdown.load(Ordering::Acquire)
    }

    /// Stamp the SAFETY deadline driver's liveness heartbeat (bead
    /// btc-policy-9y5.6). Called from its absolute schedule before any Armed deadline
    /// is read — see [`Node::last_deadline_tick`] and
    /// [`DEADLINE_HEARTBEAT_RESOLUTION_SECS`] for why the publisher is separate from the
    /// completion-scheduled release/combine pass.
    fn record_deadline_tick(&self, now: u64) {
        let bucket = now - now % DEADLINE_HEARTBEAT_RESOLUTION_SECS;
        // Wall time can step backwards. A liveness heartbeat must not regress and
        // falsely look stalled merely because NTP corrected the clock. The cost of
        // that choice, stated plainly: a forward clock EXCURSION followed by a
        // correction leaves the heartbeat ahead of wall time until real time catches
        // up, masking a genuinely stalled driver for the length of the excursion.
        // Monotonicity is still the right trade: a regressing heartbeat would cry
        // stall on every NTP step-back.
        self.last_deadline_tick.fetch_max(bucket, Ordering::Release);
    }

    /// The `/healthz` projection ([`Health`]). Reads three atomics and takes NO lock,
    /// so it cannot queue behind a held `sign_state` or channel store — the
    /// contention an operator probing a stuck node is trying to see through — and
    /// cannot mutate anything.
    pub fn health(&self) -> Health {
        let last_deadline_tick = self.last_deadline_tick.load(Ordering::Acquire);
        Health {
            // Constant: reaching this function at all means the daemon parsed its
            // config, built this node, and is answering HTTP.
            serving: true,
            locked_down: self.is_locked_down(),
            last_deadline_tick: (last_deadline_tick != 0).then_some(last_deadline_tick),
            generation_claimed: self.generation_claimed.load(Ordering::Acquire),
        }
    }

    /// The `GET /pending` projection ([`PendingProjection`]) as of `now`.
    ///
    /// Read-only in the strongest sense: it takes `sign_state` for ONE `HashMap` scan
    /// and copy, releases it before sorting or serializing anything, mutates nothing —
    /// not even a prune — and performs no I/O of any kind under the guard. The last
    /// part is load-bearing, not tidiness: the fire driver and Lockdown-at-`T` contend
    /// for this exact lock, and bead btc-policy-9y5.3 had to hoist chain I/O out of it
    /// for that reason. A poll of this surface must never be the thing that postpones
    /// `T`. (`/sign` holds the same lock across Argon2, so the marginal contention a
    /// scan adds is not a new class of delay either.)
    ///
    /// `now` is filtered through the nonce log's rollback-guarded lower bound — the
    /// same clock [`replay::PendingLog::prune`] and [`replay::PendingLog::has_any`] run
    /// on — so this reports precisely what the log itself considers live, rather than
    /// becoming a second opinion about which spends are outstanding.
    pub fn pending_projection(&self, now: u64) -> PendingProjection {
        self.pending_projection_with(move || now)
    }

    /// [`Node::pending_projection`] on this node's own clock — the production entry.
    pub fn pending_projection_now(&self) -> PendingProjection {
        self.pending_projection_with(unix_now)
    }

    /// The shared body. `clock` is read INSIDE the guard, so the production entry
    /// filters on the time the snapshot is actually taken rather than on the time the
    /// request arrived: a poll that waited behind a long `/sign` across a commitment
    /// expiry would otherwise answer with a stale horizon and report an id the log no
    /// longer considers live. A clock read is not I/O and adds no lock-held work of
    /// the kind bead btc-policy-9y5.3 hoisted out. The explicit-time entry above keeps
    /// tests deterministic.
    fn pending_projection_with(&self, clock: impl FnOnce() -> u64) -> PendingProjection {
        let mut pending = {
            let state = self.sign_state.lock().expect("sign_state lock poisoned");
            let effective_now = state.coord_nonces.effective_now(clock());
            state.pending.ids(effective_now)
        };
        pending.sort_unstable();
        PendingProjection { pending }
    }

    /// Fire the duress arm-hook (the ADR-0012 "internal fire bit"). V0-4a only
    /// counts firings — the observable seam V0-4b's arm/freeze/sweep machine hangs
    /// off. Invisible on the wire, so it does not break pin-independent ingress.
    ///
    /// Runs on EVERY SpendRequest with a constant-time-selected delta (1 for a
    /// duress verdict, 0 for normal/wrong) rather than behind an `if verdict ==
    /// Duress` branch: that keeps the arm-hook the SAME observable work for normal
    /// and duress — the last verdict-dependent step on the ingress hot path — so the
    /// constant-shape story (both Argon2 always run, budget touch is uniform) has no
    /// remaining seam. The COUNT is still +1 only for duress, so the fail-closed test
    /// reads exactly the duress arms.
    ///
    /// V0-4b hangs the **SAFETY track** off this same seam (ADR-0012): every request
    /// runs the identical store-lock + `T` computation
    /// ([`channel::ChannelState::record_arm_intent`]) and records the same-shaped
    /// per-carrier arm INTENT; only the internal, constant-time-selected duress bit
    /// differs. It runs BEFORE the locked-out / wrong-pin refusal (its call site is
    /// above `charge.refuse`), so a valid duress pin records its intent — and can
    /// therefore still arm on confirmation — even when the node is locked out
    /// (fail-closed, invariant v). Constant-observable: an outside attacker measuring
    /// latency or storage contention sees the identical lock and work under both pins.
    ///
    /// **It does NOT arm (V0-4b §0).** Ingress records intent and propagates; the
    /// freeze + Lockdown-at-`T` + Firing schedule commit asynchronously on the
    /// `/channel` receipt path once `t` distinct federation members are known to hold
    /// the carrier ([`channel::ChannelState::confirm_carrier`]). Arming a node the
    /// moment it sees a duress pin is what made a hostile coordinator able to freeze
    /// ONE node and leave `t−1` free to finalize the coerced hot spend.
    fn fire_arm_hook(
        &self,
        verdict: pin::PinVerdict,
        carrier: &str,
        nonce: &str,
        signature_tag: [u8; 32],
        expiry: u64,
        now: u64,
    ) {
        let is_duress = (verdict as u8).ct_eq(&(pin::PinVerdict::Duress as u8));
        let delta = u64::conditional_select(&0, &1, is_duress);
        self.duress_arm.fetch_add(delta, Ordering::Relaxed);
        if let Some(channel) = &self.channel {
            channel.record_arm_intent(
                is_duress.into(),
                carrier,
                nonce,
                signature_tag,
                expiry,
                now,
                self.duress_timing(),
            );
        }
    }

    /// Claim one in-flight-spend slot for the duration of the out-of-lock chain
    /// preflight (bead btc-policy-f91). MUST be called while `sign_state` is still
    /// held in phase 1: the claim has to become visible to every refresh that later
    /// acquires that lock, and only the lock orders it against a refresh already
    /// inside its own phase 2. The returned guard releases the slot on EVERY exit —
    /// early return, `?`, or panic — so the marker cannot leak.
    ///
    /// The claim itself is a single lock-free atomic increment, so it adds nothing to
    /// the time the lock is held and nothing to the preflight window (LOAD-BEARING:
    /// the preflight stays OUT of `sign_state`, or a hung backend delays the deadline
    /// driver's unconditional Lockdown-at-T — the round-2 P0).
    fn enter_spend_preflight(&self) -> SpendPreflightGuard<'_> {
        self.spend_preflight.fetch_add(1, Ordering::SeqCst);
        SpendPreflightGuard { node: self }
    }

    /// Whether any `/sign` request is currently between its phase-1 claim and its
    /// phase-2 completion — the in-flight half of the refresh-subordination predicate
    /// (the other half is [`replay::PendingLog::has_any`]).
    ///
    /// Read under `sign_state`, which is what makes it sound: the claim is published
    /// under that lock, so a refresh holding it sees every spend that entered its
    /// preflight first. The RELEASE is deliberately outside the lock (it happens when
    /// the guard drops, after phase 2 has already released it), so this can read
    /// `true` for a moment after a spend finished. That direction is safe — it
    /// subordinates a refresh very slightly longer than strictly necessary, which the
    /// coordinator resolves by retrying — while the opposite direction would be the
    /// escape-invalidation race this exists to close.
    fn spend_preflight_in_flight(&self) -> bool {
        self.spend_preflight.load(Ordering::SeqCst) > 0
    }

    /// The §0 confirmation receipt: a peer's propagation of `carrier` proves that peer
    /// holds it. Counts the sender and commits the holder decision when the holder set
    /// reaches `t`, arming the SAFETY track if this node's own verdict for the carrier
    /// was duress.
    ///
    /// Returns both facts separately ([`channel::CarrierConfirmation`]): the commit is
    /// pin-uniform, the arm is not, and a caller that treats "committed" as "armed"
    /// builds a duress oracle out of the difference.
    ///
    /// Driven only from the `/channel` receipt path, deliberately: keeping the commit
    /// off `/sign` is what makes the coordinator's view pin-independent.
    pub(crate) fn confirm_carrier(
        &self,
        sender: u16,
        carrier: &str,
        now: u64,
    ) -> channel::CarrierConfirmation {
        let Some(channel) = &self.channel else {
            return channel::CarrierConfirmation::NONE;
        };
        // Serialize the rollback-guarded freshness lower bound with confirmation.
        // `verify_coord_auth` may have logically expired and forgotten this carrier's
        // nonce while the raw wall clock later steps backwards. Holding `sign_state`
        // until the store commit gives the two lifetimes one linearization order.
        let state = self.sign_state.lock().expect("sign_state lock poisoned");
        let effective_now = state.coord_nonces.effective_now(now);
        channel.confirm_carrier(
            sender,
            carrier,
            self.threshold,
            effective_now,
            self.duress_timing(),
        )
    }

    /// This node's ADR-0013 §6 duress timing parameters, as one value.
    fn duress_timing(&self) -> channel::DuressTiming {
        channel::DuressTiming {
            duress_delay_secs: self.duress_delay_secs,
            epsilon_secs: self.epsilon_secs,
            combine_slack_secs: self.combine_slack_secs,
        }
    }

    /// How many times the duress arm-hook has fired — i.e. how many valid duress pins
    /// recorded an [`channel::ArmIntent`], NOT how many arms committed (§0: the arm
    /// commits later, on the `/channel` receipt path). Test-only observable for the
    /// fail-closed property: a valid duress pin still records its intent — and can
    /// therefore still arm on confirmation — while the node is locked out.
    #[cfg(test)]
    pub(crate) fn duress_arm_count(&self) -> u64 {
        self.duress_arm.load(Ordering::Relaxed)
    }

    /// Swap in a test evaluator (e.g. a counting one) to assert the constant-cost
    /// invariant structurally.
    #[cfg(test)]
    pub(crate) fn set_pin_evaluator(&mut self, evaluator: Arc<dyn pin::PinEvaluator>) {
        self.pin_evaluator = evaluator;
    }

    /// Inject a deterministic chain view into handler-level tests. Production never
    /// compiles this field or setter; it exists so tests can prove the `/sign` wiring,
    /// including the safety-hook ordering around a confirmed prevout mismatch.
    #[cfg(test)]
    pub(crate) fn set_chain_backend(&mut self, backend: Arc<dyn ChainBackend + Send + Sync>) {
        self.chain_backend_override = Some(backend);
    }

    /// The current pin evaluator, so a test can wrap it in a counting evaluator.
    #[cfg(test)]
    pub(crate) fn pin_evaluator(&self) -> Arc<dyn pin::PinEvaluator> {
        Arc::clone(&self.pin_evaluator)
    }

    #[cfg(test)]
    pub(crate) fn carrier_derivation_count(&self) -> usize {
        self.carrier_kdf.total_derivations()
    }
}

/// The RAII half of [`Node::enter_spend_preflight`] (bead btc-policy-f91): holds one
/// in-flight-spend slot for the out-of-lock chain preflight and gives it back when it
/// drops.
///
/// A guard rather than a paired `-= 1` because `handle_sign_after_lock`'s phase 2 has
/// a dozen early returns and every one of them must release the slot; a leaked slot
/// would subordinate every refresh on this node until it died, which is denial. `Drop`
/// runs on unwind too, so a panic between the two phases cannot strand it either.
///
/// `Drop` takes NO lock. That is deliberate and load-bearing: phase 2 holds
/// `sign_state` across its returns, and locals drop in reverse declaration order, so a
/// guard that re-took that lock would deadlock (std mutexes are not reentrant) or —
/// worse — panic while unwinding past a poisoned one. Releasing after the lock is
/// already gone is also the SAFE order: the slot outlives the phase-2 registration it
/// protects rather than being handed back a moment early.
struct SpendPreflightGuard<'a> {
    node: &'a Node,
}

impl Drop for SpendPreflightGuard<'_> {
    fn drop(&mut self) {
        self.node.spend_preflight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Domain separation for [`arm_carrier_id`], which is a node-local key and not a
/// federation-reproducible one.
const ARM_CARRIER_TAG: &str = "btc-policy/vault-node/arm-carrier/v0";
const ARM_SIGNATURE_TAG: &str = "btc-policy/vault-node/arm-signature/v0";

fn arm_signature_tag(coord_sig: &str) -> [u8; 32] {
    // Every call site has already passed `verify_coord_signature`. Reparse and
    // serialize the verified DER value so text aliases such as upper/lowercase hex
    // share one replay memo key.
    let der = Vec::<u8>::from_hex(coord_sig).expect("verified coordinator signature is hex");
    let signature =
        Signature::from_der(&der).expect("verified coordinator signature is strict DER");
    vault_proto::tagged_hash(ARM_SIGNATURE_TAG, &signature.serialize_der())
}

/// Stable identity for one exact coordinator-authenticated carrier.
///
/// A freshness nonce is signed, but it is not itself a commitment to the rest of
/// the request: a hostile coordinator owns the signing key and can validly reuse a
/// nonce across different bodies delivered to different nodes. Confirmation sets
/// must therefore bind the digest the coordinator signature authenticates, which
/// covers the variant, both PSBTs, PIN, nonce, expiry, and policy version.
///
/// **Memory-hard for SpendRequest, because that digest commits to the plaintext
/// PIN.** Its preimage is `Zeroizing` in `vault-proto` precisely because it contains
/// the PIN, and this id is the key of the `intents` map — so it OUTLIVES the request
/// bytes it came from, up to the carrier's expiry. Merely mixing a random salt into a
/// fast hash does not help against the relevant full-process-memory capture: that
/// capture contains the salt too and restores one cheap hash per PIN guess. The
/// per-node [`pin::CarrierKdf`] instead stretches the auth digest at the strongest
/// Argon2id work factor either enrolled slot declares, so even a capture containing
/// its salt retains the configured offline work factor — for BOTH pins, including
/// when the two slots are enrolled at different costs. RefreshRequest carries no PIN
/// and therefore needs only the domain-separated digest.
fn arm_carrier_id(node: &Node, request: CoordRequest<'_>) -> String {
    let digest = Zeroizing::new(request.auth_digest(&node.wallet_id));
    match request {
        CoordRequest::Spend { .. } => {
            let stretched = node.carrier_kdf.derive(&digest);
            vault_proto::tagged_hash(ARM_CARRIER_TAG, stretched.as_slice()).to_lower_hex_string()
        }
        CoordRequest::Refresh { .. } => {
            vault_proto::tagged_hash(ARM_CARRIER_TAG, digest.as_slice()).to_lower_hex_string()
        }
    }
}

/// Spawn the node's background drivers, from within the tokio runtime, once after
/// [`Node::load`]:
///
///  - the **watchtower** (ADR-0001, V0-6b): scans this node's own chain view on an
///    interval, alerting on any vault spend it never validated-and-accepted;
///  - the **Lockdown deadline driver** (ADR-0012 SAFETY): observes only the local
///    Armed deadline and enters terminal Lockdown at T, independent of backend work;
///  - the **vault-scan cache refresher**: reads the node-owned watch-only descriptor
///    wallet — or, as a fallback, warms the cold full UTXO scan and advances it by
///    bounded block deltas — outside the fire path;
///  - the **fire driver** (§1): releases partials at each candidate's authorized
///    fire event, then combines + broadcasts once quorum arrives.
///
/// The watchtower and fire driver need a chain backend; channel mode makes its
/// absence a fatal config error, precisely so a node that must broadcast cannot
/// boot unable to (see [`Node::from_toml_str`]). Only `main.rs` calls this: unit
/// tests carry a `#[cfg(test)]` mock backend but never spawn these background tasks,
/// driving the passes directly instead (e.g. [`Node::watchtower_tick`]).
pub fn spawn_drivers(node: &Arc<Node>) {
    let Some(backend) = node.backend() else {
        return;
    };
    watchtower::spawn_driver(
        Arc::clone(&backend),
        node.vault_scripts(),
        Arc::clone(&node.authorized),
        Arc::clone(&node.alerts),
    );
    // Absent-channel mode has no candidate registry, so nothing can ever fire.
    if node.channel.is_none() {
        return;
    }
    // Warm the cache before the daemon begins serving. `main` calls `spawn_drivers`
    // before `server::serve`, and a fresh process cannot carry an armed schedule
    // (reboot-death), so even a slow cold read here is startup work rather than work
    // inside a live fire/combine window. Starting service with an avoidably cold cache
    // would make an early, otherwise-admissible sweep depend on a race with the
    // refresher's first task tick.
    //
    // Once this backend holds the node-owned watch-only descriptor wallet (bead
    // btc-policy-hn8) this pass is one `listunspent`, not a whole-UTXO-set scan — the
    // measured 10.4 s/scan, serialized process-wide across all five nodes, that
    // docs/SIGNET-SPEND-RECORD.md recorded. Only the first bring-up against a fresh
    // backend still pays a `scantxoutset`, and it is that scan which supplies the
    // wallet's birthday.
    //
    // ORDERING DEPENDENCY, named because this bead made it load-bearing (Fable hn8
    // review). This warmup is SYNCHRONOUS and runs BEFORE the Lockdown deadline driver
    // spawns. That ordering is unchanged from before this bead, but the window it
    // tolerates grew roughly a hundredfold: the previous worst case was one ~10 s scan,
    // whereas a first bring-up here can pay a `loadwallet` catch-up plus two
    // `importdescriptors` calls, each under a 600 s budget. It is safe ONLY because
    // reboot-death (ADR-0007) guarantees a fresh process carries no armed schedule, so
    // there is no `T` this startup could be late for. Anyone weakening reboot-death must
    // revisit THIS line first — it is where that assumption quietly pays for itself.
    if let Err(e) = backend.refresh_vault_unspent_cache(&node.vault_scripts()) {
        eprintln!("initial vault scan cache warmup failed (will retry): {e}");
    }
    // Keep subsequent whole-UTXO scanning and delta catch-up completely outside the
    // finite fire/combine window. The first task tick is immediate and cache passes are
    // awaited before scheduling the next, so scans/deltas never overlap themselves. A
    // deep-reorg descriptor repair may outlive its pass; exactly one runs in the
    // background while later passes advance the complete scan-derived cache, so its
    // ten-minute RPC budget cannot make that cache stale at the first new block.
    // Fire-time coverage consumes only a cache already at the active tip and otherwise
    // fails fast (Lockdown remains unconditional).
    let cache_backend = Arc::clone(&backend);
    let cache_scripts = node.vault_scripts();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(watchtower::SCAN_INTERVAL);
        loop {
            ticker.tick().await;
            let backend = Arc::clone(&cache_backend);
            let scripts = cache_scripts.clone();
            match tokio::task::spawn_blocking(move || {
                backend.refresh_vault_unspent_cache_live(&scripts)
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    eprintln!("vault scan cache refresh failed (will retry): {e}");
                }
                Err(join_error) => {
                    eprintln!("vault scan cache refresh task panicked: {join_error}");
                }
            }
            ticker.reset();
        }
    });
    // SAFETY has its own always-running deadline driver. It never calls the chain
    // backend and reads only the local Armed deadline under the store lock, so no
    // Firing pass — however slow its `scantxoutset`, package check, or
    // `sendrawtransaction` — can delay first arm or Lockdown at T. Arm and final-send
    // authorization linearize on that same short-held store lock: an arm that wins
    // suppresses the hot send; an overlapping send that already passed its final
    // check is committed first, then releases every lock before backend I/O. The task
    // performs the same poll+lock work whether or not any request has armed the node;
    // the pin does not install a distinguishable timer.
    // One-second resolution matches the node's existing fire-clock resolution and
    // ADR-0012's allowed small skew.
    let lockdown_node = Arc::clone(node);
    tokio::spawn(lockdown_driver_with_clock(lockdown_node, unix_now));
    let node = Arc::clone(node);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(FIRE_INTERVAL);
        loop {
            ticker.tick().await;
            fire_tick_with_lockdown_net(
                Arc::clone(&node),
                Arc::clone(&backend),
                unix_now(),
                unix_now,
            )
            .await;
            // Schedule from pass completion, like the watchtower driver.
            ticker.reset();
        }
    });
}

/// Unix seconds by this node's own clock; before-epoch reads 0, which fails safe
/// (every real commitment then reads as expired).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Interval between fire passes in the daemon driver. A `const`, not a config
/// knob: it is scheduling resolution, not policy. One second keeps the demo
/// snappy and costs nothing — a pass over an empty registry is a lock and a scan.
pub const FIRE_INTERVAL: Duration = Duration::from_secs(1);

/// Resolution, in seconds, of the `/healthz` SAFETY deadline-driver heartbeat
/// ([`Node::last_deadline_tick`]).
///
/// Ten times [`FIRE_INTERVAL`], and that RATIO is the safety property rather than a
/// tuning preference. Publication comes only from the never-reset deadline ticker,
/// not from a ticker reset after release/combine pass completion. Actual publication
/// can still be delayed when the preceding deadline check waits on the channel-store
/// mutex that the fire pass also uses; bucketing removes ordinary sub-bucket
/// scheduler jitter without pretending to provide scheduler isolation.
///
/// Liveness is not weakened: the loop ticks at 1 Hz, so a heartbeat more than a
/// bucket or two behind the wall clock is a deadline driver that has stopped
/// looping — exactly what the field exists to show, and see [`Node::last_deadline_tick`]
/// for the failure modes that deliberately fall outside it.
pub const DEADLINE_HEARTBEAT_RESOLUTION_SECS: u64 = 10;

/// Run the unconditional SAFETY deadline driver on an absolute Tokio interval.
///
/// The heartbeat publication lives here, not in the completion-scheduled
/// release/combine loop: an ARMED candidate can change that loop's pass duration
/// before `T`, so exposing its phase would be a duress oracle even after timestamp
/// bucketing. This driver never resets its ticker and performs no backend work.
async fn lockdown_driver_with_clock(node: Arc<Node>, clock: impl Fn() -> u64 + Send + 'static) {
    let mut ticker = tokio::time::interval(FIRE_INTERVAL);
    loop {
        ticker.tick().await;
        lockdown_tick_with_lockdown_net(&node, clock());
    }
}

/// Drive only the unconditional SAFETY transition. Kept separate from every
/// backend-dependent sweep/combine operation so Lockdown at `T` cannot wait for
/// the best-effort SWEEP track.
fn lockdown_tick(node: &Node, now: u64) -> bool {
    let Some(channel) = node.channel.as_ref() else {
        return false;
    };
    let due = channel.lockdown_due(now);
    if due && !node.is_locked_down() {
        node.enter_lockdown();
        return true;
    }
    false
}

/// One SAFETY Lockdown-deadline tick under the §2b panic safety net (bead
/// btc-policy-9y5.2), the always-running-driver analogue of
/// [`fire_tick_with_lockdown_net`].
///
/// [`lockdown_tick`] calls [`Node::enter_lockdown`], which acquires `sign_state`; if a
/// prior panic poisoned that lock, `enter_lockdown` re-panics on the `.expect`. Without
/// this net that panic would kill the deadline driver loop permanently — the node could
/// then never Lockdown-at-T, the worst failure. Catch the panic so the loop survives,
/// then force the poison-independent terminal Lockdown when a critical lock is poisoned
/// (so a torn critical section still reaches the known-safe fail-closed state rather
/// than an ambiguous zombie). The tick is synchronous, so a plain `catch_unwind`
/// suffices; `AssertUnwindSafe` is sound because a caught panic never resumes use of the
/// possibly-torn state — it forces Lockdown and returns.
fn lockdown_tick_with_lockdown_net(node: &Node, now: u64) {
    // A critical-lock panic has already reached the only safe terminal state. Do not
    // re-enter the poisoned store/sign-state path: `catch_unwind` would contain it, but
    // the default panic hook would still print at 1 Hz and grow RAMDISK logs forever.
    if node.is_locked_down() && node.critical_lock_poisoned() {
        return;
    }
    // Publish before reading the Armed overlay. This prevents the result or duration
    // of THIS deadline check from changing the stamp, and the completion-scheduled
    // release/combine pass never writes it. The next scheduled iteration can still
    // be postponed if this check waits on the store mutex shared with that pass; see
    // [`Node::last_deadline_tick`] for the precise observable contract.
    // Its position BELOW the terminal-poison return is equally load-bearing: a
    // poison-bricked node runs no further pass, and its frozen heartbeat next to
    // `locked_down: true` is the whole external signal for that state (see
    // [`Node::last_deadline_tick`]). Hoisting this call above the guard — a plausible
    // "publish first, unconditionally" refactor — would keep the heartbeat advancing
    // on a node that is doing nothing, and is pinned by
    // `server::tests::healthz_heartbeat_freezes_on_a_poison_bricked_node`.
    node.record_deadline_tick(now);
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lockdown_tick(node, now)));
    // Log on the poison→terminal transition, gated on ACTUAL poison rather than
    // `!is_locked_down()`: a node that locked down normally at T and is THEN poisoned
    // (e.g. a panic during post-Lockdown escape combining) still deserves the one
    // diagnostic. Flooding is prevented by the poison early-return above — once
    // locked-down AND poisoned, the tick returns before reaching here — so this fires
    // exactly once, on the transition.
    let should_log = outcome.is_err() && node.critical_lock_poisoned();
    // Lockdown is the safety action; diagnostics are best-effort and happen only after
    // the poison-independent latch. This ordering must survive a broken stderr sink.
    if node.critical_lock_poisoned() {
        node.force_lockdown_fail_closed();
    }
    // Log once, on the transition into Lockdown, not every 1 Hz tick a poisoned lock
    // keeps re-panicking on.
    if should_log {
        best_effort_stderr(format_args!(
            "lockdown: deadline tick panicked; forcing fail-closed Lockdown if a critical \
             section was torn (bead btc-policy-9y5.2)"
        ));
    }
}

/// Compile-checked marker at the partial-release gate (bead btc-policy-9y5.2).
///
/// Requiring a live `MutexGuard<SignState>` at the loop makes the exclusion structural:
/// the release call cannot be moved outside the guard's scope without a compile error.
/// The debug assertion documents the corresponding runtime invariant — while this
/// guard is held, no concurrent handler can poison `sign_state` or enter the
/// `sign_state -> store` confirmation path between the health check and release.
fn require_sign_state_guard_before_release(
    node: &Node,
    _guard: &std::sync::MutexGuard<'_, SignState>,
) {
    debug_assert!(
        !node.sign_state.is_poisoned(),
        "partial release requires a live, unpoisoned sign_state guard"
    );
}

/// One fire pass (§1) — the Model-B spend path's engine.
///
/// For every candidate whose authorized fire event has arrived and whose combine
/// window is still open:
///
///  1. **release** this node's own partials to every peer, once, through the
///     partial-release gate (ADR-0012 invariant 7) — the fan-out is spawned, not
///     awaited, so a dead peer's bounded retry never stalls the pass;
///  2. **combine + broadcast** as soon as ≥ `t` distinct valid signatures are
///     present on EVERY input, gated on package mempool-acceptance.
///
/// Release and combine are separate steps across ticks by nature: this node
/// releases on the first due tick and a later tick finds the peers' partials that
/// crossed in the meantime. Returns how many transactions this pass broadcast.
pub async fn fire_tick(
    node: Arc<Node>,
    backend: Arc<dyn ChainBackend + Send + Sync>,
    now: u64,
) -> usize {
    // Deterministic seam for direct tests. The daemon calls
    // `fire_tick_with_clock(..., unix_now)` above so blocking backend work never
    // reuses this pass-start timestamp for its final authorization check.
    fire_tick_with_clock(node, backend, now, move || now).await
}

async fn fire_tick_with_clock(
    node: Arc<Node>,
    backend: Arc<dyn ChainBackend + Send + Sync>,
    due_now: u64,
    clock: impl Fn() -> u64 + Send + Sync + 'static,
) -> usize {
    let Some(channel) = node.channel.as_ref() else {
        return 0;
    };
    channel.prune_store(due_now);
    // DURESS — unconditional Lockdown at T (ADR-0012 invariant i). Independent of the
    // sweep: EVERY fire-failure branch still Locks Down at T, so this fires on its own
    // timer, never waiting on escape quorum, coverage, or confirmation. Monotonic and
    // idempotent (`enter_lockdown` latches false→true), so re-running each tick is
    // harmless. Lockdown blocks NEW signing, not the in-flight escape combine below.
    lockdown_tick(&node, due_now);
    let mut due = channel.due_for_fire(due_now);
    // A peer can settle near the end of the combine window while this node lacks
    // quorum or is delayed in backend work. Once the window closes it is too late
    // to release or broadcast, but not too late to observe settlement and clear a
    // hot spend's refresh-subordination entry. Add only live pending hot spends
    // still inside the bounded settlement-observation window (`fire_settlement_pollable`);
    // the channel gates below still keep their partials and finalization closed
    // outside the authorized window. The bound matters: without it a candidate
    // that missed its window would be re-polled at 1 Hz — two settlement RPCs each
    // pass — until commitment expiry (up to `max_commitment_age_secs`), needlessly
    // loading the backend and, under a post-outage backlog, risking a fresh
    // quorum-ready candidate's window on the same serial pass. Past the grace no
    // peer's combine window is still open, so the pending Hold instead lifts on its
    // commitment-expiry prune backstop.
    // A lock poisoned before this pass still aborts at the pending poll, before any
    // backend work or partial release. The release loop takes a second guard below:
    // that guard closes the concurrent-poison window after this short poll.
    let pending = {
        let state = node.sign_state.lock().expect("sign_state lock poisoned");
        state.pending.ids(due_now)
    };
    due.extend(
        pending
            .into_iter()
            .filter(|commitment_id| channel.fire_settlement_pollable(commitment_id, due_now)),
    );
    due.sort();
    due.dedup();
    if due.is_empty() {
        return 0;
    }

    // An escape partial is itself finalizable authority once a compromised `t-1`
    // set receives it. Therefore the checks whose inputs exist before combine MUST
    // run before release, not merely before this node's later broadcast. Otherwise
    // those peers can combine our honest share and broadcast a user-signed but
    // under-covered / under-fee escape after this node correctly rejects it.
    //
    // Full `testmempoolaccept` still runs on the exact finalized transaction below:
    // Bitcoin Core cannot script-validate an incomplete witness. The preflight does
    // cover every security-bearing predicate available on the immutable transaction
    // plus local chain view, including authorized ancestry; see its contract.
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(clock);
    let preflight_node = Arc::clone(&node);
    let preflight_backend = Arc::clone(&backend);
    let preflight_due = due.clone();
    let sweep_contexts = match tokio::task::spawn_blocking(move || {
        let channel = preflight_node
            .channel
            .as_ref()
            .expect("fire preflight only runs in channel mode");
        preflight_due
            .into_iter()
            .filter_map(|commitment_id| {
                if !channel.is_armed_escape(&commitment_id) {
                    return None;
                }
                match escape_sweep_pre_release_admissible(
                    &preflight_node,
                    preflight_backend.as_ref(),
                    channel,
                    &commitment_id,
                ) {
                    Ok(context) => Some((commitment_id, context)),
                    Err(reason) => {
                        eprintln!(
                            "fire: escape sweep {commitment_id} is INADMISSIBLE before share \
                             release (funds frozen → recovery; Lockdown already entered at T): \
                             {reason}"
                        );
                        None
                    }
                }
            })
            .collect::<HashMap<_, _>>()
    })
    .await
    {
        Ok(contexts) => contexts,
        Err(join_error) => {
            // Fail closed for armed escapes. Normal candidates keep the unchanged
            // V0-8b release path below; only the duress preflight task failed.
            eprintln!("fire: escape pre-release admissibility task panicked: {join_error}");
            HashMap::new()
        }
    };
    // TEST-ONLY poison-injection rendezvous, at the pending-poll -> guard seam where
    // `sign_state` is momentarily free (the pending poll dropped it; the release guard has
    // not yet taken it). The after-poll poison test's clock poisons `sign_state` on its
    // first call and must fire it HERE, while the lock is still free, so its poisoning
    // thread can acquire the lock (no deadlock) and the guard acquisition below then aborts
    // fail-closed on the poisoned lock. Gated to test builds so production never carries a
    // discarded read; the AUTHORITATIVE release timestamp is always sampled AFTER the guard
    // (below), so the timing invariant is identical either way.
    #[cfg(test)]
    let _ = clock();
    // Re-acquire AFTER the potentially-blocking preflight and hold the guard through
    // every release + fan-out. A critical-section panic that races this pass therefore
    // linearizes on one side of the release gate: poison before this acquisition aborts
    // here; poison after it cannot occur until every selected partial has been handed to
    // the fan-out tasks. This preserves the existing `sign_state -> store` lock order
    // used by `confirm_carrier`.
    {
        let release_guard = node.sign_state.lock().expect("sign_state lock poisoned");
        // Sample the release clock AFTER acquiring the guard. The acquisition can BLOCK (a
        // `/sign` or relayed request holds `sign_state` through the ~100ms Argon2), so a
        // `release_now` sampled BEFORE it would be STALE: `release_partials` would then
        // authorize a share against an in-window timestamp the real send time has already
        // passed, emitting a finalizable share AFTER the true `FireWindow::deadline`
        // (v0-exit multi-reviewer-loop pass 4, codex P1). Sampling here — under the guard,
        // just before the gate — makes release authorization reflect the actual send time.
        let release_now = clock();
        for commitment_id in &due {
            require_sign_state_guard_before_release(&node, &release_guard);
            if channel.is_armed_escape(commitment_id) && !sweep_contexts.contains_key(commitment_id)
            {
                continue;
            }
            // THE GATE. `release_partials` returns `None` unless this candidate's
            // fire event has arrived — so a Hold-bound spend, and every unscheduled
            // escape, silently produce nothing here.
            //
            // SAFETY-CRITICAL ORDERING (v0-exit audit 2026-07-22, bead btc-policy-9y5.2):
            // this release loop is fail-CLOSED under a poisoned `sign_state` because the
            // fire pass holds `release_guard` across the gate and fan-out. A panic that
            // poisoned the lock before this scope aborts at acquisition; a concurrent
            // handler cannot acquire and poison it until this scope ends. Do NOT move the
            // release loop outside this guard, remove it, or make it conditional: doing so
            // leaves `release_partials` reachable while the freeze/arm path is dead — a
            // FAIL-OPEN release of an unfrozen, coerced hot partial. The guarantee also
            // rests on `confirm_carrier` setting `holder_quorum_reached` (opens the gate)
            // and `armed.active` (freezes) atomically under one store lock, so a duress
            // candidate is never due-here-but-unfrozen. Both legs are load-bearing and
            // must stay asserted by test (btc-policy-9y5.2 adds the poisoned-sign_state
            // test).
            if let Some(release) = channel.release_partials(commitment_id, release_now) {
                spawn_fan_out(&node, release.outbound());
            }
        }
    }
    // Combining calls the chain backend (blocking JSON-RPC), so it runs off the
    // runtime exactly as the watchtower pass does.
    let combine_node = Arc::clone(&node);
    let combine_clock = Arc::clone(&clock);
    match tokio::task::spawn_blocking(move || {
        combine_and_broadcast_with_contexts(
            &combine_node,
            backend.as_ref(),
            &due,
            &sweep_contexts,
            move || combine_clock(),
        )
    })
    .await
    {
        Ok(count) => count,
        Err(join_error) => {
            eprintln!("fire: combine task panicked: {join_error}");
            0
        }
    }
}

/// One fire pass under the §2b panic safety net (bead btc-policy-9y5.2).
///
/// A panic inside the pass — in particular the deliberate `.expect("… lock poisoned")`
/// fail-closed abort taken when a prior panic poisoned `sign_state` or the channel
/// store lock — must neither kill the daemon's fire-driver loop (a permanent zombie
/// that can no longer Lockdown-at-T) nor leave the node observable as still-releasing.
/// Run the pass on a child task so tokio captures any panic as a `JoinError` (the
/// default runtime does not abort the process on a task panic), keeping the driver loop
/// alive; then, if a production critical lock is poisoned, steer the node into
/// deterministic terminal Lockdown through the poison-independent path
/// ([`Node::force_lockdown_fail_closed`]). This preserves fail-closed-for-THEFT — the
/// pass still panics BEFORE the release loop under a poisoned `sign_state`, releasing
/// nothing — while removing "one reachable panic permanently kills a member into an
/// ambiguous state". Returns the pass's broadcast count (0 if it panicked).
async fn fire_tick_with_lockdown_net(
    node: Arc<Node>,
    backend: Arc<dyn ChainBackend + Send + Sync>,
    due_now: u64,
    clock: impl Fn() -> u64 + Send + Sync + 'static,
) -> usize {
    // Preserve post-Lockdown escape combining on healthy nodes, but a node whose
    // critical state is poisoned can do no safe store/sign-state work. It already
    // reached the fail-closed terminal latch, so do not spawn another task whose
    // inevitable panic would invoke the default hook and flood RAMDISK logs at 1 Hz.
    if node.is_locked_down() && node.critical_lock_poisoned() {
        return 0;
    }
    let pass_node = Arc::clone(&node);
    let (broadcast, panic_error) =
        match tokio::spawn(fire_tick_with_clock(pass_node, backend, due_now, clock)).await {
            Ok(broadcast) => (broadcast, None),
            Err(join_error) => (0, Some(join_error)),
        };
    // Poison→terminal transition, gated on ACTUAL poison (not `!is_locked_down()`), so a
    // node poisoned AFTER a normal Lockdown at T still logs once; the poison early-return
    // above prevents any repeat.
    let should_log = panic_error.is_some() && node.critical_lock_poisoned();
    // Force the terminal state before attempting diagnostics: stderr failure must not
    // punch through the panic net and leave a poisoned node unlocked.
    if node.critical_lock_poisoned() {
        node.force_lockdown_fail_closed();
    }
    // Log once — on the transition into fail-closed Lockdown — not every 1 Hz tick a
    // persistently poisoned lock keeps re-panicking on (a terminal node must not flood
    // its RAMDISK logs).
    if should_log {
        if let Some(join_error) = panic_error {
            best_effort_stderr(format_args!(
                "fire: pass panicked ({join_error}); forcing fail-closed Lockdown if a \
                 critical section was torn (bead btc-policy-9y5.2)"
            ));
        }
    }
    broadcast
}

/// Combine + broadcast every due candidate that has reached quorum. Synchronous
/// (the chain backend is blocking) and driven by `now`, so tests call it directly
/// with a mock backend and no runtime. Returns the number this node broadcast.
///
/// `try_finalize` reads the `broadcast` flag under the store lock, releases it,
/// broadcasts lock-free, then `mark_broadcast` re-takes the lock. That is safe
/// only because the daemon runs exactly one fire task ([`spawn_drivers`]) that
/// `await`s each pass to completion, so no two combine passes for one candidate
/// ever overlap; a second concurrent driver would need those three steps made
/// atomic (on-chain a double push is harmless — identical txid, deduped).
#[cfg(test)]
pub(crate) fn combine_and_broadcast(
    node: &Node,
    backend: &dyn ChainBackend,
    due: &[String],
    now: u64,
) -> usize {
    combine_and_broadcast_with_clock(node, backend, due, move || now)
}

#[cfg(test)]
fn combine_and_broadcast_with_clock(
    node: &Node,
    backend: &dyn ChainBackend,
    due: &[String],
    clock: impl Fn() -> u64,
) -> usize {
    combine_and_broadcast_with_contexts(node, backend, due, &HashMap::new(), clock)
}

/// The combine half of one fire tick. Production supplies the armed escape's
/// already-computed pre-release context so the same tick never repeats its mempool
/// ladder scan or chain-derived coverage environment. Direct unit tests that call
/// [`combine_and_broadcast`] bypass the release half, so they compute that one
/// context lazily here.
fn combine_and_broadcast_with_contexts(
    node: &Node,
    backend: &dyn ChainBackend,
    due: &[String],
    sweep_contexts: &HashMap<String, EscapeSweepTickContext>,
    clock: impl Fn() -> u64,
) -> usize {
    let Some(channel) = node.channel.as_ref() else {
        return 0;
    };
    let mut broadcast = 0;
    for commitment_id in due {
        // Settlement does not require this node to have collected a local quorum.
        // A peer may already have broadcast while some partials to this node were
        // delayed or lost. Check by exact candidate txid first so the local pending
        // Hold cannot subordinate refreshes until expiry for a spend already in the
        // mempool or chain.
        let Some(candidate_txid) = channel.candidate_txid(commitment_id) else {
            continue;
        };
        // The ARMED ESCAPE follows ADR-0012's Firing row — "combine + re-broadcast
        // until CONFIRMED", with 9y5.7 replacing "fixed panic-fee" by the bounded
        // deterministic fee ladder. A panic-fee escape can be evicted from the mempool,
        // so — unlike a normal spend — mere mempool presence is NOT terminal for it:
        // only a CONFIRMATION clears it, and while it is confirmed-absent it stays
        // resident (unlatched) so an evicted copy is re-broadcast on the next tick. The
        // re-broadcast loop is requirement-7-bounded by the escape's
        // `[T, T + combine_slack_secs]` window (`prune` clears the escape once the
        // window closes), so the Firing job stays finite and never spins for the node's
        // lifetime.
        let armed_escape = channel.is_armed_escape(commitment_id);
        let sweep_context = sweep_contexts.get(commitment_id);
        if armed_escape {
            // A laddered escape can settle as ANY rung — the rungs conflict by
            // construction, so at most one of them can ever be on the network, but
            // which one depends on how far the federation bumped. Reading only rung 0
            // would leave a confirmed BUMP looking permanently unsettled.
            let rung_txids = channel
                .candidate_rung_txids(commitment_id)
                .unwrap_or_else(|| vec![candidate_txid]);
            match armed_escape_network_state(
                backend,
                &rung_txids,
                channel.escape_rung(commitment_id).unwrap_or(0),
                sweep_context.and_then(|context| context.resident_rung.as_ref()),
            ) {
                // Confirmed. The confirmation clears the paired hot spend's pending
                // Hold, but the already-authorized escape candidate itself remains
                // resident until the finite fire window closes. If a reorg removes that
                // confirmation inside the window, the next tick therefore reaches the
                // `Absent` arm and re-broadcasts at the SAME latched rung.
                Ok(ArmedEscapeState::Confirmed(txid)) => {
                    let paired = channel.pairing(commitment_id).map(|(_, sibling)| sibling);
                    // A confirmed sweep defeats every OTHER resident hot candidate that
                    // spends one of its inputs, not just its own paired sibling: those
                    // coins are now provably gone, so those candidates must stop being
                    // projected as pending, and hand their Hot reservations back rather
                    // than metering until an unrelated expiry. Without this the node
                    // would report as outstanding a spend it has already watched the
                    // network defeat (bead btc-policy-6nq).
                    //
                    // LOCK ORDER: same shape as `settle_candidate` and as the `pairing`
                    // call above — the store lock is taken and released INSIDE this
                    // call, before `sign_state` is acquired below, so this branch never
                    // holds the two together. The armed escape itself is untouched:
                    // `invalidate_hot_conflicts` never writes the spender, which is what
                    // keeps the sweep resident and unlatched for in-window reorg
                    // recovery.
                    //
                    // SCOPE (the window bound is stated on the branch above): what this
                    // settles is the projection and the reservation, never the
                    // authorization — `armed` is monotonic and `T` has already Locked
                    // Down, so nothing it touches could have fired either way.
                    let invalidated_hot = channel.invalidate_hot_conflicts_in_store(commitment_id);
                    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
                    let mut first_confirmation = state.pending.remove(commitment_id);
                    if let Some(paired) = paired {
                        first_confirmation |= state.pending.remove(&paired);
                    }
                    // Folded into the one-shot marker rather than discarded: these are
                    // settlements this tick performed, so a confirmation whose paired
                    // spend had already been pruned at its own expiry still logs once
                    // when it clears an OTHER defeated candidate. Still one-shot — they
                    // are gone from the log after this pass, and Lockdown at `T` means
                    // no later `record` can put a spend back.
                    for invalidated in invalidated_hot {
                        first_confirmation |= state.pending.remove(&invalidated);
                    }
                    drop(state);
                    if first_confirmation {
                        println!(
                            "fire: armed escape {commitment_id} confirmed on-chain ({txid}); \
                             retaining it through the fire window for in-window reorg recovery"
                        );
                    }
                    continue;
                }
                // A copy at or above the latched rung is already resting in the
                // mempool: nothing to do, and re-running admissibility now would read
                // the escape's own inputs as spent-by-mempool.
                Ok(ArmedEscapeState::InMempoolAtOrAboveLatch) => continue,
                // Either nothing is on the network, or only a rung BELOW the latch is —
                // which is precisely the fee-bump case. Fall through to combine and
                // broadcast the latched rung; being RBF-signalling, it replaces the
                // lower copy instead of being rejected as a conflict.
                Ok(ArmedEscapeState::Absent) => {}
                Err(e) => {
                    eprintln!(
                        "fire: cannot check settlement for armed escape {commitment_id}: {e}"
                    );
                    continue;
                }
            }
        } else {
            // Normal spend / refresh — unchanged V0-8b: mempool presence IS settlement.
            match transaction_is_settled(backend, &candidate_txid) {
                Ok(true) => {
                    settle_candidate(node, channel, commitment_id);
                    println!(
                        "fire: candidate {commitment_id} already settled on-chain ({candidate_txid})"
                    );
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    eprintln!("fire: cannot check settlement for candidate {commitment_id}: {e}");
                    continue;
                }
            }
        }

        // Production normally supplies the pre-release context. A direct unit test can
        // enter at combine, and a production preflight can fail because a just-confirmed
        // escape's prevouts are now spent. Settlement MUST be checked first: confirmation
        // is terminal for this pass and retains the candidate for reorg recovery without
        // requiring those spent prevouts to remain admissible. Only a still-unsettled
        // escape needs the fallback context before it can combine or broadcast.
        let owned_sweep_context;
        let sweep_context = if let Some(context) = sweep_context {
            Some(context)
        } else if armed_escape {
            owned_sweep_context =
                match escape_sweep_pre_release_admissible(node, backend, channel, commitment_id) {
                    Ok(context) => context,
                    Err(reason) => {
                        eprintln!(
                            "fire: escape sweep {commitment_id} is INADMISSIBLE before combine \
                             (funds frozen → recovery; Lockdown already entered at T): {reason}"
                        );
                        continue;
                    }
                };
            Some(&owned_sweep_context)
        } else {
            None
        };

        // `None` is the ordinary "still collecting" case, not an error. For the armed
        // escape this is where the `t distinct escape signers per input` requirement is
        // enforced — quorum on the ESCAPE's own commitment_id IS cross-node agreement on
        // one escape (its partials are keyed by that id), so an armed set that does not
        // converge on one escape simply never reaches quorum here → no sweep → Lockdown
        // + recovery (already scheduled).
        let Some(finalized) = channel.try_finalize(commitment_id, node.threshold, clock()) else {
            continue;
        };
        // Fire-time escape-sweep admissibility (ADR-0012 / ADR-0013 §6) — the FULL
        // predicate, for the ARMED escape ONLY, gating its broadcast. Every other due
        // candidate (a normal spend, a refresh) rides the unchanged V0-8b path. A
        // failure means the sweep does not fire — Lockdown at T already happened
        // unconditionally (above), so funds stay frozen → recovery, never theft.
        if armed_escape {
            let Some(context) = sweep_context else {
                eprintln!(
                    "fire: escape sweep {commitment_id} has no preflight context, not firing \
                     (funds frozen → recovery; Lockdown already entered at T)"
                );
                continue;
            };
            if let Err(reason) = sweep_rung_admissible(
                node,
                &context.env,
                &finalized.tx,
                finalized.tx.vsize() as u64,
            ) {
                eprintln!(
                    "fire: escape sweep {commitment_id} is INADMISSIBLE, not firing (funds frozen \
                     → recovery; Lockdown already entered at T): {reason}"
                );
                continue;
            }
        }
        match broadcast_package(
            node,
            backend,
            channel,
            commitment_id,
            &finalized,
            sweep_context.and_then(|context| context.resident_rung.as_ref()),
            &clock,
        ) {
            Ok(outcome) => {
                // A NORMAL spend is done once it is on the network (mempool or chain):
                // clear the candidate and lift its pending-Hold refresh subordination
                // before publishing the terminal log marker. Acceptance harnesses use
                // that marker as a settlement barrier, so it must describe state that
                // is already settled rather than state this thread will settle next.
                //
                // The ARMED ESCAPE is deliberately NOT latched here: it must re-broadcast
                // until it CONFIRMS (checked at the top of the next tick), so a later
                // mempool eviction of the non-RBF escape is still resendable within its
                // bounded window.
                if !armed_escape {
                    settle_candidate(node, channel, commitment_id);
                }
                match outcome {
                    BroadcastOutcome::Sent(txid) => {
                        broadcast += 1;
                        // Name the rung. For a laddered escape this is the only place
                        // an operator can see that the sweep went out at a BUMPED fee
                        // rather than its base one, and which replacement is now the
                        // live transaction.
                        match finalized.rung {
                            0 => println!("fire: broadcast {txid} for candidate {commitment_id}"),
                            rung => println!(
                                "fire: broadcast {txid} for candidate {commitment_id} at \
                                 fee-bump rung {rung}"
                            ),
                        }
                    }
                    // A peer beat this node to it (redundant-broadcast race).
                    BroadcastOutcome::AlreadySettled(txid) => println!(
                        "fire: candidate {commitment_id} already settled on-chain ({txid})"
                    ),
                }
            }
            Err(e) => eprintln!("fire: cannot broadcast candidate {commitment_id}: {e}"),
        }
    }
    broadcast
}

/// Mark an exact non-armed candidate settled locally and release refresh
/// subordination for it, its paired sibling, and every hot candidate whose inputs
/// the settled transaction conflicts with. The last set is what makes an independent
/// escape-class clawback the implicit cancel ADR-0004 promises: its public spend must
/// not leave the defeated hot spend projected until expiry. [`ChannelState::mark_broadcast`]
/// terminalizes those same candidates under the store lock before returning them, so
/// the pending removal here never outruns the fire path: an id this drops is an id
/// [`ChannelState::due_for_fire`] will not schedule.
///
/// Armed escapes use the confirmation branch above instead: it clears the same two
/// sets — the paired sibling AND every hot candidate the settling transaction defeated
/// — but reaches the second through
/// [`ChannelState::invalidate_hot_conflicts_in_store`] rather than `mark_broadcast`,
/// which is what lets it deliberately retain the escape itself, resident and unlatched,
/// through the fire window so an in-window reorg can re-broadcast it. Read the pairing
/// BEFORE `mark_broadcast`, which may remove candidate context. Every pending removal
/// is idempotent.
fn settle_candidate(node: &Node, channel: &channel::ChannelState, commitment_id: &str) {
    let paired = channel.pairing(commitment_id).map(|(_, sibling)| sibling);
    let invalidated_hot = channel.mark_broadcast(commitment_id);
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    state.pending.remove(commitment_id);
    if let Some(paired) = paired {
        state.pending.remove(&paired);
    }
    for invalidated in invalidated_hot {
        state.pending.remove(&invalidated);
    }
}

/// The outcome of trying to put a finalized candidate on the network.
enum BroadcastOutcome {
    /// This node package-validated and pushed the transaction; the backend
    /// returned this txid.
    Sent(Txid),
    /// The exact transaction is ALREADY in this node's chain view — a peer won the
    /// redundant-broadcast race, the designed steady state (ADR-0012: every node
    /// fires on its own clock). Settlement is settlement no matter who broadcast,
    /// so this node treats it as done, never as a failure to retry.
    AlreadySettled(Txid),
}

/// Package-validate `tx` against this node's own chain view, then broadcast it
/// (§5). Every failure is an `Err` — the transaction is simply not broadcast, and
/// nothing panics.
///
/// Package assembly validates every unconfirmed vault-authorized ancestor, then
/// tests `tx` against this node's full mempool view. The RPC package is a
/// singleton because its ancestors are, by construction, transactions already
/// present in this node's OWN mempool; re-listing them makes Core reject
/// multi-generation/already-present packages. "Relay-standard" alone would not
/// tell us the candidate and its ancestry are acceptable.
fn broadcast_package(
    node: &Node,
    backend: &dyn ChainBackend,
    channel: &channel::ChannelState,
    commitment_id: &str,
    finalized: &channel::FinalizedCandidate,
    resident_escape_rung: Option<&bitcoin::Transaction>,
    clock: &impl Fn() -> u64,
) -> Result<BroadcastOutcome, Error> {
    let tx = &finalized.tx;
    let deadline = finalized.deadline;
    let txid = tx.compute_txid();
    // A peer may already have broadcast this exact transaction — redundant
    // broadcast is the designed steady state, since each node fires on its own
    // clock (ADR-0012). Once it is in this node's mempool its inputs read as
    // spent, so `assemble_package` below would `Err` on the "spent" prevout and
    // this node would mistake an already-SETTLED spend for a failure — never
    // clearing its pending Hold and wrongly subordinating refreshes until
    // commitment expiry. The peer copy may already be in a block rather than the
    // mempool, so recognize either location as settled.
    if transaction_is_settled(backend, &txid)? {
        return Ok(BroadcastOutcome::AlreadySettled(txid));
    }
    let authorized = node
        .authorized
        .lock()
        .expect("authorized lock poisoned")
        .clone();
    let package = if channel.is_armed_escape(commitment_id) {
        assemble_escape_package(backend, tx, resident_escape_rung, &authorized)?
    } else {
        chain::assemble_package(backend, tx, &authorized)?
    };
    match backend.test_package_accept(&package)? {
        chain::PackageVerdict::Accepted => {}
        chain::PackageVerdict::Rejected(reason) => {
            return Err(format!("package mempool-acceptance failed: {reason}").into())
        }
    }
    // Package/ancestor RPCs above are blocking and may begin just before either
    // the combine deadline OR a concurrent duress arm. Authorization is about the
    // instant the transaction leaves this node, not the pass-start/finalize time.
    // Re-check both the live clock and the Armed hot-freeze under the candidate-store
    // lock. That short check is the arm-vs-send linearization point; every lock is
    // released before `sendrawtransaction`, so backend latency cannot delay arming or
    // the independent Lockdown timer.
    let raw_tx = bitcoin::consensus::serialize(tx);
    let send_result = channel
        .with_broadcast_authorization(commitment_id, clock, || backend.broadcast(&raw_tx))
        .map_err(|reason| -> Error {
            format!(
                "broadcast authorization closed for candidate {commitment_id} \
                 (deadline {deadline}): {reason}"
            )
            .into()
        })?;
    match send_result {
        Ok(sent) => Ok(BroadcastOutcome::Sent(sent)),
        // A peer's copy can land in the narrow window between the check above and
        // this push; the backend then rejects the duplicate. If the exact
        // transaction is now in our mempool or active chain it settled after all
        // — the same AlreadySettled case, not a failure to retry.
        Err(e) => {
            if matches!(transaction_is_settled(backend, &txid), Ok(true)) {
                Ok(BroadcastOutcome::AlreadySettled(txid))
            } else {
                Err(e)
            }
        }
    }
}

/// Whether the exact candidate is already in this node's mempool OR active
/// chain. Redundant node broadcasts race both mempool admission and mining; both
/// outcomes settle the local candidate and its pending Hold.
fn transaction_is_settled(backend: &dyn ChainBackend, txid: &Txid) -> Result<bool, Error> {
    Ok(backend.mempool_transaction(txid)?.is_some() || backend.transaction_confirmed(txid)?)
}

/// Where the armed escape stands on this node's chain view, across its whole fee
/// ladder.
enum ArmedEscapeState {
    /// Some rung is confirmed. Only one ever can be — the rungs conflict.
    Confirmed(Txid),
    /// No rung is confirmed, but a rung at or above the latch is in the mempool, so
    /// the sweep is already riding at (or past) the fee this node would pay.
    InMempoolAtOrAboveLatch,
    /// Nothing is on the network, or only a rung strictly BELOW the latch is — the
    /// eviction case and the fee-bump case respectively. Both want a broadcast of the
    /// latched rung.
    Absent,
}

/// Classify the armed escape's ladder against this node's mempool and chain.
///
/// The "only a lower rung is in the mempool" case is what makes a bump actually
/// happen: the pre-9y5.7 rule ("anything of ours on the network ⇒ nothing to do")
/// would see the stale low-fee copy and never send the replacement.
fn armed_escape_network_state(
    backend: &dyn ChainBackend,
    rung_txids: &[Txid],
    latched: usize,
    resident_rung: Option<&bitcoin::Transaction>,
) -> Result<ArmedEscapeState, Error> {
    for txid in rung_txids {
        if backend.transaction_confirmed(txid)? {
            return Ok(ArmedEscapeState::Confirmed(*txid));
        }
    }
    if let Some(resident) = resident_rung {
        let resident_txid = resident.compute_txid();
        if rung_txids
            .iter()
            .position(|txid| *txid == resident_txid)
            .is_some_and(|rung| rung >= latched)
        {
            return Ok(ArmedEscapeState::InMempoolAtOrAboveLatch);
        }
    }
    Ok(ArmedEscapeState::Absent)
}

/// The exact authorized escape-ladder rung, if any, currently resident in this
/// node's mempool.
///
/// A resident rung is more than a settlement hint: Core hides the outpoints it
/// spends from `gettxout(..., include_mempool=true)`. Recognizing the exact txid and
/// parsing the backend's returned bytes lets the replacement path distinguish that
/// authorized conflict from an unrelated spender without trusting arrival order or
/// any local fee estimate.
fn mempool_escape_rung(
    backend: &dyn ChainBackend,
    channel: &channel::ChannelState,
    commitment_id: &str,
) -> Result<Option<bitcoin::Transaction>, Error> {
    let Some(rungs) = channel.candidate_rung_txs(commitment_id) else {
        return Ok(None);
    };
    // ONE batched membership read for the whole ladder, cheapest rung first. Asking per
    // rung would make the Core backend pull the entire mempool once per rung — up to
    // four full `getrawmempool` snapshots per 1 Hz fire tick, worst exactly under the
    // congestion that makes the combine window tightest (bead btc-policy-nvr).
    let txids: Vec<Txid> = rungs
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    let Some((expected, raw)) = backend.mempool_resident(&txids)? else {
        return Ok(None);
    };
    // The answer must be one of the txids WE asked for. The per-rung loop got this by
    // construction — it compared the backend's bytes against a locally computed
    // `rung.compute_txid()` — and the batched call must not downgrade it to trust in the
    // backend's own claim. Distinguishing an authorized rung from an unrelated spender of
    // the same vault inputs is exactly what this function exists to do (see above): a
    // backend returning a foreign conflicting spend would otherwise pass the byte check
    // below and have its ancestry walked as if it were a rung.
    if !txids.contains(&expected) {
        return Err(format!(
            "mempool lookup returned {expected}, which is not a rung of this escape's ladder"
        )
        .into());
    }
    let resident: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw)
        .map_err(|e| format!("mempool escape rung {expected} is malformed: {e}"))?;
    if resident.compute_txid() != expected {
        return Err(format!(
            "mempool lookup for escape rung {expected} returned transaction {}",
            resident.compute_txid()
        )
        .into());
    }
    Ok(Some(resident))
}

/// Validate the candidate's ancestry either from ordinary unspent prevouts or,
/// during a bump, from the exact lower ladder rung already spending them in this
/// node's mempool.
fn assemble_escape_package(
    backend: &dyn ChainBackend,
    tx: &bitcoin::Transaction,
    resident_rung: Option<&bitcoin::Transaction>,
    authorized: &HashSet<Txid>,
) -> Result<Vec<Vec<u8>>, Error> {
    match resident_rung {
        // Also covers "the exact candidate is already resident" (a peer broadcast it
        // first): the two input sets are then trivially equal and the ancestry walk
        // runs over the resident bytes, so the authorized-ancestry guard keeps
        // running instead of being waved through as already-validated.
        Some(resident) => chain::assemble_replacement_package(backend, tx, resident, authorized),
        None => chain::assemble_package(backend, tx, authorized),
    }
}

/// Pre-release portion of fire-time escape admissibility.
///
/// This runs at `T`, never at arm/ingress. It deliberately precedes partial release:
/// once a compromised `t-1` set receives this node's share, it can assemble the escape
/// without this node and bypass any later local refusal. The immutable transaction and
/// local chain view are sufficient to check finality, class-aware coverage, authorized
/// ancestry, and the panic feerate. Feerate uses the descriptor's MAXIMUM satisfaction
/// weight, so passing here guarantees the exact finalized transaction cannot fall below
/// the floor when the missing signatures are added.
///
/// Core's full package `testmempoolaccept` cannot run until the witness is complete. It
/// remains an exact post-combine/pre-broadcast gate in [`broadcast_package`]. By then
/// the pre-release policy has already bounded value/fee loss and excluded toxic external
/// ancestry; a package-policy reject cannot turn the user-signed escape into theft.
fn escape_sweep_pre_release_admissible(
    node: &Node,
    backend: &dyn ChainBackend,
    channel: &channel::ChannelState,
    commitment_id: &str,
) -> Result<EscapeSweepTickContext, String> {
    let rungs = channel
        .candidate_rung_txs(commitment_id)
        .filter(|rungs| !rungs.is_empty())
        .ok_or_else(|| "armed escape candidate context is unavailable".to_string())?;
    let resident_rung = mempool_escape_rung(backend, channel, commitment_id)
        .map_err(|e| format!("cannot inspect the escape ladder in the mempool: {e}"))?;
    let env = sweep_env(
        node,
        backend,
        channel,
        commitment_id,
        rungs.len() > 1,
        resident_rung.as_ref(),
    )?;
    // Per rung, the vsize the transaction can reach once the missing federation
    // signatures are added. Using the MAXIMUM means a rung that clears the floor (or
    // the bump target) here still clears it as the exact finalized transaction.
    let maximum_vsizes = rungs
        .iter()
        .map(|tx| maximum_finalized_vsize(node, tx))
        .collect::<Result<Vec<u64>, String>>()?;
    let admissible: Vec<Result<(), String>> = rungs
        .iter()
        .zip(&maximum_vsizes)
        .map(|(tx, vsize)| sweep_rung_admissible(node, &env, tx, *vsize))
        .collect();
    let ladder = ScoredLadder {
        rungs: &rungs,
        maximum_vsizes: &maximum_vsizes,
        admissible: &admissible,
        total_in: env.total_in,
    };
    let old_latch = channel.escape_rung(commitment_id).unwrap_or(0);
    let (selected, target, required) =
        select_escape_rung(node, backend, channel, commitment_id, &ladder)?;
    // Validate every unconfirmed ancestor before releasing the share. This proves
    // each input is confirmed or descends only from vault-authorized mempool parents;
    // an external unconfirmed deposit (toxic/replaceable parent) fails closed here.
    // The returned singleton bytes are intentionally not submitted yet: an unsigned
    // witness cannot pass Core's script checks. Every rung spends the same inputs, so
    // one check over the selected rung covers the whole ladder's ancestry.
    let authorized = node
        .authorized
        .lock()
        .expect("authorized lock poisoned")
        .clone();
    assemble_escape_package(
        backend,
        &rungs[selected],
        resident_rung.as_ref(),
        &authorized,
    )
    .map_err(|e| format!("escape package ancestry is inadmissible before release: {e}"))?;

    // Commit the monotone rung only AFTER every fallible pre-release check above.
    // A transient ancestry/backend failure therefore releases no share and leaves the
    // old latch intact; the next pass can retry at the same fee rather than burning a
    // higher rung that was never actually authorized for release.
    //
    // The same commit carries the LOWEST rung this pass found admissible. Release is a
    // prefix, and a rung refused here — in practice a base rung under the panic
    // feerate floor — must not travel to peers who could combine it into the very
    // under-fee escape this node declined to fire.
    let lowest_admissible = admissible
        .iter()
        .position(Result::is_ok)
        .unwrap_or(selected)
        .min(selected);
    let latched = channel
        .latch_escape_rung(commitment_id, selected, lowest_admissible)
        .ok_or_else(|| "armed escape disappeared while latching its fee rung".to_string())?;
    if latched > old_latch {
        println!(
            "fire: armed escape {commitment_id} is at fee-bump rung {latched} of {} (required \
             {required} sat/vB: target {target}, floor {})",
            rungs.len().saturating_sub(1),
            node.escape_feerate_floor
        );
    }
    Ok(EscapeSweepTickContext { resident_rung, env })
}

/// The vsize `tx` can reach once every missing federation signature is added.
///
/// `max_weight_to_satisfy` is the per-input delta from an EMPTY witness, whose
/// stack-count varint itself weighs 1 WU. The unsigned transaction serializes no
/// witnesses at all, so restore that 1 WU per input as well as the segwit
/// marker+flag (2 WU). Round weight up to vbytes, as `Transaction::vsize` does.
fn maximum_finalized_vsize(node: &Node, tx: &bitcoin::Transaction) -> Result<u64, String> {
    maximum_finalized_vsize_for(node.max_vault_satisfaction_weight, tx)
}

/// The maximum finalized (witness-complete) vsize of an escape or bump `tx`, in vB,
/// as a PURE function of the vault's per-input satisfaction-weight bound and the
/// unsigned transaction — the node-independent core of [`maximum_finalized_vsize`].
///
/// Exposed so the coordinator that composes the fee-bump ladder (vault-cli's
/// `fed::escape_fee_ladder`) measures each rung's replacement size with the EXACT
/// bound the node enforces at ingress ([`ensure_escape_ladder`]): the two
/// must not drift, or the coordinator could offer a rung whose fee delta the node
/// then rejects — taking the whole spend, including a duress carrier, with it (bead
/// btc-policy-9y5.7). `max_vault_satisfaction_weight` is
/// `descriptor.max_weight_to_satisfy().to_wu()`, which the coordinator derives from
/// the same vault descriptor the node parses.
pub fn maximum_finalized_vsize_for(
    max_vault_satisfaction_weight: u64,
    tx: &bitcoin::Transaction,
) -> Result<u64, String> {
    let input_count = u64::try_from(tx.input.len())
        .map_err(|_| "escape input count does not fit u64".to_string())?;
    let maximum_witness_weight = max_vault_satisfaction_weight
        .checked_add(1)
        .ok_or_else(|| "escape maximum witness weight overflow".to_string())?
        .checked_mul(input_count)
        .ok_or_else(|| "escape maximum satisfaction weight overflow".to_string())?;
    let maximum_weight = tx
        .weight()
        .to_wu()
        .checked_add(2)
        .and_then(|weight| weight.checked_add(maximum_witness_weight))
        .ok_or_else(|| "escape maximum finalized weight overflow".to_string())?;
    Ok(maximum_weight
        .checked_add(3)
        .ok_or_else(|| "escape maximum finalized vsize overflow".to_string())?
        / 4)
}

/// The minimum absolute fee increase (sat) a replacement of `tx` must pay over the
/// transaction it replaces to clear this build's incremental-relay bound — the exact
/// per-rung quantity [`ensure_escape_ladder`] enforces
/// (`maximum_finalized_vsize · ESCAPE_RBF_INCREMENTAL_RELAY_SAT_VB`).
///
/// The coordinator composing a ladder calls this so it never offers a rung whose
/// delta falls below the node's minimum: such a rung is refused at ingress and takes
/// the entire spend with it (bead btc-policy-9y5.7). Because every rung shares the
/// escape's inputs and output scripts, this size — and hence this minimum — is
/// identical for the base and every bump, so one call bounds the whole ladder.
pub fn escape_replacement_min_fee_delta(
    max_vault_satisfaction_weight: u64,
    tx: &bitcoin::Transaction,
) -> Result<u64, String> {
    Ok(
        maximum_finalized_vsize_for(max_vault_satisfaction_weight, tx)?
            .saturating_mul(ESCAPE_RBF_INCREMENTAL_RELAY_SAT_VB),
    )
}

/// How many blocks the bump target's anchor height is quantized to.
///
/// Two honest nodes can hold tips one block apart at the instant they fire, and a
/// target read straight off each node's own tip would then differ between them.
/// Anchoring on `tip − (tip mod 6)` collapses that: within a six-block span every
/// node reads the SAME block, so a disagreement is possible only in the moment the
/// tip crosses a multiple of six — and even then the prefix release
/// ([`channel::ChannelState::release_partials`]) keeps the sweep combinable.
const FEE_ANCHOR_QUANTUM: u32 = 6;

/// The sat/vB step the observed feerate is quantized to.
///
/// The second half of the same determinism argument: two nodes that do read
/// different anchor blocks still land on the same target unless those blocks differ
/// by a whole step. It also stops a one-sat wobble in the chain's median from
/// walking the latch up a rung for nothing.
///
/// Quantized DOWN, not up. Rounding up would make ANY block with a median of at
/// least 1 sat/vB demand a whole step, so an escape already composed at (or just
/// under) the chain's own median would be bumped a full 4× rung for fee pressure
/// that does not exist — money the user did not have to spend. Giving up the
/// sub-step remainder cannot cost a rung the pressure genuinely needed: the ladder's
/// rungs are 4× apart, an order of magnitude coarser than this step, and the sealed
/// panic floor still sets the minimum the sweep must pay.
const FEE_TARGET_STEP_SAT_VB: u64 = 5;

/// **The deterministic bump target**, in sat/vB: the median feerate of the block at
/// the quantized anchor height, quantized down to [`FEE_TARGET_STEP_SAT_VB`].
///
/// Every input is consensus-observable — a height and a confirmed block's contents —
/// so every honest node on the same chain computes the SAME number. That is not a
/// nicety: nodes that disagreed here would release partials over different
/// transactions, no rung would reach `t` signatures, and the sweep would fail at the
/// exact moment it is needed. Nothing from this node's own mempool, wall clock, or
/// arrival order may enter this function.
///
/// `Ok(None)` means the node has no reading (no such block, or a backend that does
/// not report fee statistics) and is treated as no observed pressure — the escape
/// stays on its base rung, which is the pre-ladder behaviour.
fn escape_bump_target_feerate(backend: &dyn ChainBackend) -> Result<Option<u64>, String> {
    let tip = backend
        .tip_height()
        .map_err(|e| format!("cannot read the tip height for the escape bump target: {e}"))?;
    let anchor = tip - (tip % FEE_ANCHOR_QUANTUM);
    let Some(median) = backend
        .block_median_feerate(anchor)
        .map_err(|e| format!("cannot read the anchor block's feerate: {e}"))?
    else {
        return Ok(None);
    };
    // Quantize DOWN to the step: the target never exceeds the observed median, so
    // the ladder cannot charge for pressure the chain is not showing.
    Ok(Some(
        median / FEE_TARGET_STEP_SAT_VB * FEE_TARGET_STEP_SAT_VB,
    ))
}

/// **Pick the fee-ladder rung this sweep should fire at.**
///
/// The rule, in order:
///
///  1. The required feerate is `max(deterministic bump target, the static panic
///     floor)`. Both are federation-uniform: the floor is config sealed into the
///     manifest, the target is a pure function of the confirmed chain.
///  2. `needed` is the CHEAPEST rung whose guaranteed feerate reaches it — cheapest,
///     because a bump that overshoots burns the user's own money. If no rung reaches
///     it, the ladder simply tops out.
///  3. The choice is clamped to the rungs that are ADMISSIBLE, which is where the
///     coverage guard bites: a rung whose fee would push delivered value below
///     `escape_coverage_pct` of the protected balance is not selectable at any
///     target. This is the "never bump past the cap" rule, and it is why an
///     above-cap spike ends at the recovery path instead of at an overpaying sweep.
///  4. The result is raised to the monotone latch, so a bump is never walked back.
///     The caller commits that result only after ancestry validation succeeds.
///
/// `Err` means no rung may fire at all this pass: the sweep does not broadcast,
/// Lockdown at `T` has already happened unconditionally, and the funds exit through
/// the Recovery path. That is the designed fail-safe, not a new failure mode.
fn select_escape_rung(
    node: &Node,
    backend: &dyn ChainBackend,
    channel: &channel::ChannelState,
    commitment_id: &str,
    ladder: &ScoredLadder,
) -> Result<(usize, u64, u64), String> {
    let count = ladder.rungs.len();
    // No ladder, no choice — and no reason to read the chain for a target. An escape
    // submitted without bumps takes exactly the pre-9y5.7 path, including its failure
    // modes: it must not newly depend on a `getblockcount`/`getblockstats` pair that
    // could fail and suppress a sweep the old code would have fired.
    if count <= 1 {
        return match ladder.admissible.first() {
            Some(Ok(())) => Ok((0, 0, node.escape_feerate_floor)),
            Some(Err(reason)) => Err(reason.clone()),
            None => Err("the armed escape has no candidate transaction".to_string()),
        };
    }
    let target = match escape_bump_target_feerate(backend) {
        Ok(reading) => reading.unwrap_or(0),
        Err(error) => {
            // Fee pressure is an optional deterministic signal, not new liveness
            // authority. A backend that cannot provide it falls back to the sealed
            // panic floor, preserving the pre-ladder sweep instead of suppressing it.
            eprintln!("fire: {error}; using the static escape feerate floor");
            0
        }
    };
    let required = target.max(node.escape_feerate_floor);
    let needed = (0..count)
        .find(|rung| ladder.reaches(*rung, required))
        .unwrap_or(count.saturating_sub(1));
    let ok = |rung: &usize| ladder.admissible.get(*rung).is_some_and(Result::is_ok);
    // The cheapest admissible rung that meets the target; failing that, the most
    // expensive admissible rung — the cap — and never anything above it.
    let choice = (0..count)
        .filter(ok)
        .find(|rung| *rung >= needed)
        .or_else(|| (0..count).rfind(ok));
    let Some(choice) = choice else {
        // Rung 0's own reason is the honest one to report: with no admissible rung
        // there is nothing to fire, and the base escape's failure is what an operator
        // needs to see.
        return Err(match ladder.admissible.first() {
            Some(Err(reason)) => reason.clone(),
            _ => "no escape ladder rung is admissible".to_string(),
        });
    };
    let selected = choice.max(channel.escape_rung(commitment_id).unwrap_or(0));
    if let Some(Err(reason)) = ladder.admissible.get(selected) {
        return Err(format!(
            "escape ladder rung {selected} is already latched but no longer admissible, and a \
             lower rung cannot replace a higher one that may already be in the mempool: {reason}"
        ));
    }
    Ok((selected, target, required))
}

/// A fee ladder with every rung already scored against the shared [`SweepEnv`]:
/// the transactions, the vsize each rung's feerate is measured over, whether each
/// rung is admissible, and the swept value they all share.
struct ScoredLadder<'a> {
    rungs: &'a [bitcoin::Transaction],
    maximum_vsizes: &'a [u64],
    admissible: &'a [Result<(), String>],
    total_in: u64,
}

impl ScoredLadder<'_> {
    /// Whether rung `rung` pays at least `required` sat/vB even at its maximum
    /// finalized vsize. Compared in `u128` against `required · vsize` rather than as
    /// a truncated integer feerate, exactly as the panic-floor check does.
    fn reaches(&self, rung: usize, required: u64) -> bool {
        let (Some(tx), Some(vsize)) = (self.rungs.get(rung), self.maximum_vsizes.get(rung)) else {
            return false;
        };
        // Every rung spends the same inputs, so one swept total serves them all.
        let fee = self.total_in.saturating_sub(
            tx.output
                .iter()
                .fold(0u64, |total, out| total.saturating_add(out.value.to_sat())),
        );
        u128::from(fee) >= u128::from(required).saturating_mul(u128::from(*vsize))
    }
}

/// One armed escape's shared fire-time state for a single driver tick.
///
/// The mempool rung and rung-independent [`SweepEnv`] are read once before release,
/// then reused by settlement classification, exact finalized admissibility, and
/// replacement-package assembly. A ladder therefore costs one mempool scan, one
/// `prevouts` batch, and one `vault_unspent` scan per tick rather than repeating
/// those blocking reads inside the tight `[T, T + combine_slack]` window.
struct EscapeSweepTickContext {
    /// The one authorized rung in this node's mempool when the tick began, if any.
    /// Reused by settlement classification and replacement-package assembly.
    resident_rung: Option<bitcoin::Transaction>,
    /// The chain-derived, rung-independent coverage and fee environment.
    env: SweepEnv,
}

/// The rung-INDEPENDENT half of fire-time escape admissibility: everything that
/// comes from the chain and from the paired spend, and is therefore identical for
/// every rung of a fee ladder.
///
/// The rungs share one input set by construction ([`ensure_escape_ladder`]), so
/// they share one swept total, one protected balance, and one class-aware union
/// with the paired spend; only the outputs — and hence the fee and delivered value
/// — differ.
struct SweepEnv {
    /// Σ prevout value over the escape's inputs: the swept value.
    total_in: u64,
    /// The coverage DENOMINATOR: this node's complete confirmed +
    /// vault-authorized-unconfirmed vault balance, plus (for a completed escape-class
    /// spend) the value that already departed the vault in it.
    protected_value: u64,
    /// The part of the coverage NUMERATOR that does not come from the rung: the
    /// escape-wallet outputs of an already-confirmed, disjoint escape-class spend.
    /// Zero in the ordinary hot-class case.
    paired_delivered: u64,
    /// Whether this escape carries a fee-bump ladder, which decides the `nSequence`
    /// its rungs must show.
    laddered: bool,
}

fn sweep_env(
    node: &Node,
    backend: &dyn ChainBackend,
    channel: &channel::ChannelState,
    commitment_id: &str,
    laddered: bool,
    resident_rung: Option<&bitcoin::Transaction>,
) -> Result<SweepEnv, String> {
    let candidate = channel
        .candidate_coverage_context(commitment_id)
        .ok_or_else(|| "armed escape candidate context is unavailable".to_string())?;
    let tx = &candidate.tx;
    // The swept value: Σ prevout value over the escape's inputs. Ordinarily a prevout
    // this node cannot see means the escape is not spendable now. The one exception is
    // an exact authorized ladder rung already in this node's mempool: Core deliberately
    // hides the outpoints that rung spends, while its mempool admission proves the
    // ingress-validated witness amounts were the real amounts used by script
    // verification. Those stored amounts remain the shared ground truth for its
    // replacement.
    let mut total_in: u64 = 0;
    let escape_outpoints: Vec<OutPoint> =
        tx.input.iter().map(|input| input.previous_output).collect();
    let escape_prevouts = backend
        .prevouts(&escape_outpoints)
        .map_err(|e| format!("cannot read escape prevouts: {e}"))?;
    if escape_prevouts.len() != escape_outpoints.len() {
        return Err(format!(
            "chain backend returned {} escape prevouts for {} inputs",
            escape_prevouts.len(),
            escape_outpoints.len()
        ));
    }
    for ((outpoint, prevout), (stored_outpoint, stored_value)) in escape_outpoints
        .iter()
        .zip(escape_prevouts)
        .zip(&candidate.inputs)
    {
        if outpoint != stored_outpoint {
            return Err("armed escape input context does not match its transaction".into());
        }
        let value = match prevout {
            Some(prevout) => prevout.txout.value.to_sat(),
            None if resident_rung.is_some() => *stored_value,
            None => {
                return Err(format!(
                    "escape prevout {} is unknown to this node (spent or missing)",
                    outpoint
                ))
            }
        };
        total_in = total_in.saturating_add(value);
    }
    let escape_desc = node
        .check_params
        .escape
        .as_ref()
        .ok_or("no escape descriptor configured")?;
    let authorized = node
        .authorized
        .lock()
        .expect("authorized lock poisoned")
        .clone();
    let vault_unspent = backend
        .vault_unspent(&node.vault_scripts(), &authorized)
        .map_err(|e| format!("cannot enumerate the protected vault balance: {e}"))?;
    // A resident rung is authorized, so `vault_unspent` counts any vault-change
    // output it created. That change is a DERIVATIVE of the escape inputs restored
    // just below — counting both would inflate the denominator by the change and
    // make a near-threshold escape spuriously inadmissible on the very tick it
    // wants to bump or re-broadcast. The escape's own inputs are the canonical,
    // rung-independent view of that value, so drop the rung's outputs and restore
    // the inputs.
    let resident_txid = resident_rung.map(bitcoin::Transaction::compute_txid);
    let mut protected_value = vault_unspent
        .iter()
        .filter(|(outpoint, _)| Some(outpoint.txid) != resident_txid)
        .fold(0u64, |total, (_, prevout)| {
            total.saturating_add(prevout.txout.value.to_sat())
        });
    if resident_rung.is_some() {
        // `vault_unspent` uses the same include-mempool view as `prevout`, so the
        // resident rung also hides the vault coins from the coverage denominator.
        // Restore exactly those canonical escape inputs, without double-counting a
        // backend that still returned one.
        let visible: HashSet<OutPoint> = vault_unspent
            .iter()
            .map(|(outpoint, _)| *outpoint)
            .collect();
        for (outpoint, value) in &candidate.inputs {
            if !visible.contains(outpoint) {
                protected_value = protected_value.saturating_add(*value);
            }
        }
    }
    if protected_value == 0 {
        return Err("protected confirmed + authorized-unconfirmed vault balance is empty".into());
    }
    let mut paired_delivered = 0u64;

    // Class-aware: hot-class is frozen and superseded by E. Escape-class must have
    // completed first; its inputs must be disjoint from the residual, and coverage is
    // computed over completed spend ∪ residual. Missing pair context is itself an
    // admissibility failure — silently defaulting to hot would weaken the predicate.
    let (_, spend_commitment_id) = channel
        .pairing(commitment_id)
        .ok_or_else(|| "armed escape has no registered paired spend".to_string())?;
    let paired = channel
        .candidate_coverage_context(&spend_commitment_id)
        .ok_or_else(|| "armed escape's paired spend context is unavailable".to_string())?;
    if !paired.hot {
        let escape_inputs: HashSet<bitcoin::OutPoint> =
            tx.input.iter().map(|input| input.previous_output).collect();
        if let Some((shared, _)) = paired
            .inputs
            .iter()
            .find(|(outpoint, _)| escape_inputs.contains(outpoint))
        {
            return Err(format!(
                "residual escape shares input {shared} with its completed escape-class spend — \
                 not disjoint (ADR-0012 class-aware coverage)"
            ));
        }
        let paired_txid = paired.tx.compute_txid();
        let paired_confirmed = backend
            .transaction_confirmed(&paired_txid)
            .map_err(|e| format!("cannot confirm paired escape-class spend {paired_txid}: {e}"))?;
        if !paired_confirmed {
            return Err(format!(
                "paired escape-class spend {paired_txid} is not confirmed, so its outputs cannot \
                 count as delivered in union coverage"
            ));
        }
        // `vault_unspent` already contains the completed spend's vault change (or a
        // vault-authorized descendant of it). Add only the value that LEFT the vault
        // in the completed spend — escape outputs + fee — rather than its full input
        // value, or the change is counted once as current balance and again as part of
        // the completed side of the union.
        let paired_input_value = paired
            .inputs
            .iter()
            .fold(0u64, |total, (_, value)| total.saturating_add(*value));
        let vault_scripts = node.vault_scripts();
        let paired_vault_change = paired
            .tx
            .output
            .iter()
            .filter(|output| vault_scripts.contains(&output.script_pubkey))
            .fold(0u64, |total, output| {
                total.saturating_add(output.value.to_sat())
            });
        let departed_value = paired_input_value
            .checked_sub(paired_vault_change)
            .ok_or_else(|| {
                "paired escape-class spend returns more value to the vault than its inputs"
                    .to_string()
            })?;
        protected_value = protected_value.saturating_add(departed_value);
        paired_delivered = paired
            .tx
            .output
            .iter()
            .filter(|output| {
                policy_core::derives_within(
                    escape_desc,
                    output.script_pubkey.as_script(),
                    node.check_params.max_derivation_index,
                )
            })
            .fold(0u64, |total, output| {
                total.saturating_add(output.value.to_sat())
            });
    }
    Ok(SweepEnv {
        total_in,
        protected_value,
        paired_delivered,
        laddered,
    })
}

/// Fire-time escape-sweep admissibility (ADR-0012 / ADR-0013 §6) on one rung,
/// evaluated against the shared [`SweepEnv`]. It runs ONLY in the armed escape's
/// Firing job, NEVER as an arm gate. Every failure returns `Err` so the sweep does
/// not fire; Lockdown at `T` has already happened UNCONDITIONALLY, so failure leaves
/// funds frozen → recovery, never theft.
///
/// The `t` distinct escape signers per input are enforced by `try_finalize` before
/// this. Authorized ancestry and full-package `testmempoolaccept` are enforced by
/// [`assemble_escape_package`] before release and [`broadcast_package`] after
/// combine. This function enforces the remaining rung-dependent checks:
///
/// - final `nLockTime` + the exact non-relative `nSequence` for the ladder shape;
/// - feerate at or above the static panic floor;
/// - output coverage at or above `escape_coverage_pct`, which caps the fee;
/// - class-aware union coverage for a completed, disjoint escape-class spend.
///
/// The backend-derived denominator contains confirmed plus
/// vault-authorized-unconfirmed value only; external toxic deposits never enter it.
///
/// Pure apart from the node's config, so the whole ladder can be scored in one pass
/// and the selector can ask "which rungs may fire?" without repeating chain I/O.
/// `feerate_vsize` is the vsize the feerate is measured over — the MAXIMUM finalized
/// vsize before release (so a rung that clears the floor here still clears it when
/// the missing signatures land) and the exact vsize once finalized.
fn sweep_rung_admissible(
    node: &Node,
    env: &SweepEnv,
    tx: &bitcoin::Transaction,
    feerate_vsize: u64,
) -> Result<(), String> {
    // Final nLockTime + non-relative nSequence on EVERY input (broadcastable-at-T).
    // See [`ESCAPE_RBF_SEQUENCE`] for why a LADDERED escape carries `0xfffffffd`
    // instead, and where its finality then comes from.
    let expected_sequence = expected_escape_sequence(env.laddered);
    for (i, input) in tx.input.iter().enumerate() {
        if input.sequence != expected_sequence {
            return Err(format!(
                "escape input {i} nSequence {:#010x} is not {:#010x} — a non-final / \
                 relative-locking escape, or one whose replaceability does not match its \
                 fee-bump ladder, is not broadcastable-at-T",
                input.sequence.to_consensus_u32(),
                expected_sequence.to_consensus_u32()
            ));
        }
    }
    let total_out: u64 = tx
        .output
        .iter()
        .fold(0u64, |acc, o| acc.saturating_add(o.value.to_sat()));
    let fee = env.total_in.saturating_sub(total_out);

    // Feerate ≥ the static panic floor. Compare fee against floor·vsize in u128 (no
    // truncated integer feerate, mirroring the refresh-fee-cap comparison).
    let vsize = feerate_vsize;
    if vsize == 0 {
        return Err("escape has zero vsize".into());
    }
    let floor_sats = u128::from(node.escape_feerate_floor).saturating_mul(u128::from(vsize));
    if u128::from(fee) < floor_sats {
        return Err(format!(
            "escape feerate below the panic floor: {fee} sat over {vsize} vB is under {} sat/vB \
             ({floor_sats} sat)",
            node.escape_feerate_floor
        ));
    }

    // Coverage numerator: Σ output value paying the escape descriptor, plus whatever a
    // completed disjoint escape-class spend already delivered. Measuring on OUTPUTS is
    // what caps the escape's fee at `(100 − pct)%` of the protected value — and it is
    // therefore also the cap a fee BUMP runs into: raising the fee lowers this
    // numerator, so a rung that would overpay simply fails here and is never selected.
    let escape_desc = node
        .check_params
        .escape
        .as_ref()
        .ok_or("no escape descriptor configured")?;
    let delivered_value = tx
        .output
        .iter()
        .filter(|o| {
            policy_core::derives_within(
                escape_desc,
                o.script_pubkey.as_script(),
                node.check_params.max_derivation_index,
            )
        })
        .fold(env.paired_delivered, |acc, o| {
            acc.saturating_add(o.value.to_sat())
        });
    if u128::from(delivered_value).saturating_mul(100)
        < u128::from(env.protected_value).saturating_mul(u128::from(node.escape_coverage_pct))
    {
        return Err(format!(
            "escape coverage below {}%: {delivered_value} sat to the escape wallet over \
             {} sat of protected confirmed + authorized-unconfirmed vault value",
            node.escape_coverage_pct, env.protected_value
        ));
    }
    Ok(())
}

/// Spawn one detached send task PER PEER, each sending that peer's messages in
/// order. Detached on purpose: each send retries with backoff until its own
/// deadline, so awaiting the tasks would let one dead peer hold up the fire pass —
/// and every other candidate with it. Peers are independent tasks (a dead peer
/// costs only its own redundancy); within a peer the messages are serialized so the
/// cheapest-rung-first order the payloads already carry becomes the delivery order
/// (see the base-first rationale in the body).
fn spawn_fan_out(node: &Arc<Node>, messages: Vec<channel::Outbound>) {
    let Some(channel) = node.channel.as_ref() else {
        return;
    };
    // One task PER PEER, sending that peer's messages IN ORDER, rather than one task
    // per (peer, message) racing them concurrently. The release payloads are already
    // ordered cheapest-rung-first (`release_partials` emits `[release_floor ..=
    // authorized]`), so per-peer ordering makes each recipient charge the common base
    // rung to this node's quota BEFORE any higher rung OF THE SAME RELEASE. That is
    // what keeps the sweep convergent under a tight `per_peer_quota_per_min`: if higher
    // rungs could win the quota race first, the base rung — the one rung every honest
    // node's prefix shares — could be rate-limited at some peers, and the honest shares
    // would scatter across rungs with none reaching quorum before the combine window
    // closes (codex 9y5.7 review). Base-first delivery makes that the guarantee, so the
    // quota rung-cap in `release_partials` is now only a best-effort "don't send rungs
    // that won't fit" bound, not the thing convergence depends on. (The ordering is
    // within ONE release: a later tick that raises the latch fans out again, and those
    // higher-rung messages can race a still-rate-limited base retry from the earlier
    // release — a contrived schedule that, like everything here, degrades to Recovery,
    // never theft.) Peers are still fanned out concurrently; only messages to the SAME
    // peer are serialized. The request propagation path sends a single-message vec, so
    // its behaviour is unchanged.
    //
    // Share the message list across the per-peer tasks through an `Arc` rather than
    // deep-cloning it (and its `Zeroizing` payload bytes) once per peer.
    let messages = Arc::new(messages);
    for peer in channel.peer_ids() {
        let node = Arc::clone(node);
        let messages = Arc::clone(&messages);
        tokio::spawn(async move {
            let channel = node
                .channel
                .as_ref()
                .expect("fan-out only spawns in channel mode");
            for message in messages.iter() {
                if let Err(e) = channel::retry_message_until(
                    channel,
                    message.msg_type,
                    peer,
                    &message.payload,
                    message.deadline,
                )
                .await
                {
                    // A peer that never accepts costs redundancy, never safety: the
                    // combine simply proceeds with whoever answered. Keep sending this
                    // peer's remaining rungs — a rate-limit on one need not abandon the
                    // rest once the window frees up.
                    eprintln!(
                        "channel: cannot deliver {} to node {peer}: {e}",
                        message.msg_type
                    );
                }
            }
        });
    }
}

/// Drain the outbox and propagate every staged coordinator-authenticated request to
/// every peer (§3). Matching PINs use this for safety/quorum propagation; the early
/// refusal path also stages wrong PINs so lockout cannot expose match-vs-wrong through
/// peer nonce state.
///
/// Called once the sign lock is released — by `/sign` and by the `/channel`
/// `request` path alike, so a request that arrives either way fans out the same.
/// Bounded and loop-free with no new mechanism: coordinator authentication consumed
/// the request nonce before staging, so the copy that comes back from a peer is
/// refused as a replay and propagates no further. The fan-out therefore dies after
/// one round, at `n·(n−1)` messages. Staging does not mean the local policy accepted
/// or signed the request; it carries the authenticated safety signal independently.
pub fn propagate_outbox(node: &Arc<Node>) {
    if node.channel.is_none() {
        return;
    }
    let requests: Vec<vault_proto::TaggedRequest> =
        std::mem::take(&mut *node.outbox.lock().expect("outbox lock poisoned"));
    for request in requests {
        let expiry = match &request {
            vault_proto::TaggedRequest::Spend(spend) => spend.expiry,
            vault_proto::TaggedRequest::Refresh(refresh) => refresh.expiry,
        };
        // ONE outbound message, built by a pure function of the request: identical
        // path, identical count (every peer), identical size under either PIN.
        spawn_fan_out(
            node,
            vec![channel::Outbound {
                msg_type: channel::MSG_TYPE_REQUEST,
                payload: channel::request_payload(&request),
                deadline: expiry,
            }],
        );
    }
}

/// Stage a coordinator-signed carrier for federation fan-out and claim this node's
/// holder slot, so it will contribute a matching receipt to every peer.
///
/// ONE function for both call sites, deliberately. The pre-validation early exits
/// (lockout / wrong PIN, which reach the outbox before either PSBT is decoded) and the
/// fully-validated path (both PSBTs decoded, user signatures verified, policy passed)
/// must stage IDENTICALLY: §0 counts receipt + processing of the authenticated safety
/// carrier, never signing eligibility, so holder evidence is intentionally independent
/// of whether this node may sign. That is what preserves ADR-0012's fail-closed lockout
/// invariant (v) — lockout refuses signing but cannot make a valid duress arm require
/// `t` OTHER peers instead of self + `t−1`. Two identically-bodied helpers would let one
/// path silently drift from the other and break that invariant.
fn stage_spend_carrier(node: &Node, request: vault_proto::TaggedRequest, carrier: &str) {
    node.outbox
        .lock()
        .expect("outbox lock poisoned")
        .push(request);
    if let Some(channel) = &node.channel {
        channel.mark_carrier_propagated(carrier);
    }
}

/// Ingest one raw `/channel` body (§3). The channel authenticates the envelope;
/// a `request` comes back here so THIS node applies its own coordinator-auth,
/// freshness, user-signature, and policy gates before anything is registered or
/// signed — a peer is transport, never an authority (signing-oracle prohibition).
///
/// A coordinator-authenticated request lands in the outbox before an early PIN
/// refusal regardless of verdict, keeping peer nonce effects uniform under lockout;
/// a matching-PIN request also lands there before cached acceptance, and a newly
/// validated request is staged before candidate capacity admission. The caller pumps
/// it onward, so one valid delivered safety signal reaches the whole federation.
///
/// This is ALSO the confirmation path of V0-4b §0, and the ONLY site that commits an
/// arm. A peer propagates a request only after receiving AND processing one, so each
/// arrival here is evidence that its authenticated sender holds the carrier; once
/// `t` distinct members are known to hold one this node judged DURESS, the freeze +
/// Lockdown-at-`T` + Firing sweep commit. Ingress never arms, so a coordinator that
/// keeps a carrier from reaching `t` nodes achieves censorship, never a split.
#[cfg(test)]
pub(crate) fn handle_channel_body(node: &Node, body: &[u8], now: u64) -> ChannelReply {
    handle_channel_body_with_clocks(node, body, now, || now, || now)
}

/// Production `/channel` entry: envelope freshness is sampled on receipt, while the
/// arm-confirmation boundary is sampled again after signature verification, KDF (when
/// genuinely new), and local processing. Tests use [`handle_channel_body`] with one
/// fixed clock so boundary cases stay deterministic.
///
/// `confirmation_clock` is read TWICE — once to resolve the carrier memo and again
/// immediately before the commit — because everything between them (signature
/// verification, and on the conflicting-signature path a memory-hard derivation) is
/// unbounded local work. See [`handle_channel_body_with_clocks`].
pub(crate) fn handle_channel_body_now(node: &Node, body: &[u8]) -> ChannelReply {
    let received_at = channel::unix_now();
    handle_channel_body_with_clocks(
        node,
        body,
        received_at,
        channel::unix_now,
        channel::unix_now,
    )
}

/// Whether the harness-only `/channel` holder-commit marker should be emitted.
///
/// `/channel` deliberately maps every decodable policy outcome to ACCEPTED, so the
/// adversarial harness has no other way to observe that a holder decision committed.
/// Emitting that marker unconditionally in production would be a standing local side
/// channel, so it is gated on the `BTC_VAULT_CHANNEL_MARKER` environment variable,
/// which the harness sets when it launches daemons (`vault-cli/src/fed.rs`);
/// production is silent by default. Read once and cached — the value cannot change
/// over a process's life — so the hot `/channel` path carries no per-request
/// environment read. The gate is a single process-wide bool, independent of pin, so
/// it stays PIN-UNIFORM: it never turns the marker into a duress oracle, and the
/// `committed` crossing it guards still fires for NORMAL and DURESS alike.
fn channel_marker_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("BTC_VAULT_CHANNEL_MARKER").is_some())
}

#[cfg(test)]
fn handle_channel_body_with_clock(
    node: &Node,
    body: &[u8],
    received_at: u64,
    confirmation_clock: impl Fn() -> u64,
) -> ChannelReply {
    handle_channel_body_with_clocks(node, body, received_at, || received_at, confirmation_clock)
}

fn handle_channel_body_with_clocks(
    node: &Node,
    body: &[u8],
    received_at: u64,
    processing_clock: impl Fn() -> u64,
    confirmation_clock: impl Fn() -> u64,
) -> ChannelReply {
    let Some(channel) = node.channel.as_ref() else {
        // Unreachable: `/channel` is mounted only in channel mode.
        return ChannelReply::Rejected(channel::RejectReason::UnknownMsgType);
    };
    match channel.ingest(body, received_at) {
        channel::Ingested::Reply(reply) => reply,
        channel::Ingested::Request { sender, request } => {
            // The node's own gates decide. The peer learns only that we processed
            // it — never our policy verdict, which is ours alone and which a peer
            // has no authority to act on anyway.
            let outcome = match request.as_ref() {
                // Envelope freshness used the caller's `now` above, but policy
                // freshness, Hold scheduling, and refresh timestamps must read the
                // clock only after acquiring `sign_state`. A relayed request may
                // wait behind another signer just like a direct `/sign` request.
                vault_proto::TaggedRequest::Spend(spend) => {
                    handle_sign_after_lock(node, spend, processing_clock)
                }
                vault_proto::TaggedRequest::Refresh(refresh) => {
                    handle_refresh_after_lock(node, refresh, processing_clock)
                }
            };
            // §0 CONFIRMATION-GATED ARMING. `sender` propagated this carrier, and a
            // node propagates only what it received AND processed — so this receipt is
            // evidence that `sender` holds it. Counted AFTER local processing, which
            // is what guarantees this node's own verdict is already recorded: the very
            // first copy to arrive (from the coordinator or from a peer) runs the full
            // ingress above and registers the intent, so by the t-th receipt there is
            // always an intent to count into.
            //
            // Resolve the carrier only AFTER the authoritative handler has sampled
            // its processing clock and made the freshness/capacity decision. A
            // separately-clocked prefilter can disagree at the future-expiry boundary:
            // the handler accepts and memoizes a carrier while the prefilter drops its
            // receipt. Post-processing lookup returns the exact carrier the handler
            // actually used. It also makes a capacity refusal cheap: a request that
            // could not record an intent leaves the memo vacant and performs no
            // otherwise-unmemoizable carrier derivation.
            //
            // The coordinator signature and outbound-size checks still precede the
            // lookup. They bind an `Exact` signature memo to this body (the signature
            // cannot be copied onto different canonical bytes) and keep an invalid
            // channel body from spending a conflicting-signature derivation budget.
            //
            // Counted regardless of the local policy outcome. The common case here is the
            // loop-suppression refusal — coordinator auth consumed the nonce when this
            // node first processed the carrier, so a peer's copy returns
            // NONCE_REPLAYED — and that refusal says nothing about whether the PEER
            // holds it. Dropping the count there would make the fan-out unable to ever
            // reach t, i.e. nothing would ever arm.
            //
            // This is the ONLY site that commits an arm. Keeping it here, off the
            // `/sign` response path, is what makes the coordinator's view of a duress
            // request byte-identical to a normal one.
            if let vault_proto::TaggedRequest::Spend(spend) = request.as_ref() {
                let lookup_now = confirmation_clock();
                let carrier = if !node.is_locked_down()
                    && !spend.nonce.is_empty()
                    && spend.nonce.len() <= MAX_COORD_NONCE_BYTES
                    && ensure_request_propagatable(node, request.as_ref()).is_ok()
                    && verify_coord_signature(node, spend.coord_request(), &spend.coord_sig).is_ok()
                {
                    match channel.carrier_memo_lookup(
                        &spend.nonce,
                        arm_signature_tag(&spend.coord_sig),
                        sender,
                        lookup_now,
                    ) {
                        channel::CarrierMemoLookup::Exact(carrier) => Some(carrier),
                        // Post-processing vacancy means the authoritative handler did
                        // not record an intent (invalid/expired/capacity-refused), so
                        // there is nothing this receipt can confirm and no reason to
                        // pay the carrier KDF.
                        channel::CarrierMemoLookup::Vacant | channel::CarrierMemoLookup::Skip => {
                            None
                        }
                        // A DIFFERENT valid signature over the SAME body is not a
                        // different carrier: canonical request bytes exclude
                        // `coord_sig`. Derive the body identity once for this sender;
                        // a genuinely different body under a reused nonce resolves to
                        // a carrier for which this node has no intent.
                        channel::CarrierMemoLookup::DeriveForConfirmation { memoized_carrier } => {
                            // A hostile coordinator plus one compromised peer can
                            // manufacture conflicting signatures across thousands of
                            // live nonces. Never let those memory-hard resolutions all
                            // queue while retaining the ordinary `/channel` permits:
                            // reserve the one global KDF slot non-blockingly and ask the
                            // sender to retry with a fresh channel envelope when busy.
                            // Exact confirmations and partials take neither this slot nor
                            // this return, so they retain channel capacity during the
                            // attack. Claim the per-(nonce, sender) budget only AFTER the
                            // reservation exists; a rate-limited attempt must stay
                            // retryable.
                            let Some(reservation) = node.carrier_kdf.try_reserve() else {
                                return ChannelReply::RateLimited {
                                    retry_after_secs: 1,
                                };
                            };
                            if !channel.claim_carrier_derivation(
                                &spend.nonce,
                                sender,
                                &memoized_carrier,
                            ) {
                                None
                            } else {
                                let digest = Zeroizing::new(
                                    spend.coord_request().auth_digest(&node.wallet_id),
                                );
                                let stretched = reservation.derive(&digest);
                                Some(
                                    vault_proto::tagged_hash(ARM_CARRIER_TAG, stretched.as_slice())
                                        .to_lower_hex_string(),
                                )
                            }
                        }
                    }
                } else {
                    None
                };
                if let Some(carrier) = carrier {
                    // Resample. `lookup_now` predates `verify_coord_signature` and — on
                    // the conflicting-signature branch — a full memory-hard carrier
                    // derivation, which is deliberately expensive and can be queued
                    // behind the one global KDF slot. Reusing it would let a receipt
                    // whose processing CROSSED the carrier's expiry commit an arm that a
                    // node whose processing happened to be faster refuses, making "who
                    // armed" a function of local scheduling — the exact split
                    // `confirm_carrier`'s own expiry guard exists to rule out. The clock
                    // is read identically for every verdict, so this costs no pin
                    // observability; erring late only ever refuses (censorship), never
                    // arms.
                    let confirmation = node.confirm_carrier(sender, &carrier, confirmation_clock());
                    // Pin-uniform live-harness evidence. `/channel` intentionally maps
                    // every decodable policy outcome to ACCEPTED, so that reply cannot
                    // establish that the carrier memo resolved or its holder decision
                    // committed. Emit the same local marker for NORMAL and DURESS only
                    // after observing the production decision — and ONLY when the harness
                    // has set `BTC_VAULT_CHANNEL_MARKER` (`channel_marker_enabled`), so a
                    // production node is silent by default. It is not an API/event surface
                    // and changes no state-machine behavior.
                    //
                    // Gated on `committed`, NEVER on `armed`. Those differ exactly on a
                    // normal carrier's commit, so gating on the arm would print this line
                    // for duress and withhold it for normal — turning the marker itself
                    // into the local duress oracle it is written to avoid being.
                    //
                    // The nonce is hex-encoded, never interpolated raw. It is
                    // coordinator-chosen and validated only for length
                    // (`NonceDecision::InvalidLength`), so interpolating it verbatim would
                    // let an authenticated hostile coordinator — which ADR-0010 puts
                    // squarely in the threat model — embed newlines and forge whole log
                    // records on an honest node, including this very marker for a nonce
                    // whose holder decision never committed.
                    if confirmation.committed && channel_marker_enabled() {
                        eprintln!(
                            "channel: holder decision committed for request nonce {}",
                            spend.nonce.as_bytes().to_lower_hex_string()
                        );
                    }
                }
            }
            match outcome {
                Ok(_) => ChannelReply::Accepted,
                // A peer relayed something this node cannot even decode. That is a
                // malformed payload, not a policy outcome.
                Err(_) => ChannelReply::Rejected(channel::RejectReason::MalformedPayload),
            }
        }
    }
}

/// Handle one `/sign` submission. `now` is unix seconds by the node's own
/// clock (a parameter, never a system-clock read, so the anti-replay, expiry,
/// and fire logic is deterministically testable). `Err(BadRequest)` means
/// undecodable input (HTTP 400); every policy outcome — accepted or refused — is
/// `Ok`. Under Model B (ADR-0012) an accepted response carries NO node signature:
/// the node signs at ingress but withholds every partial until its candidate's
/// authorized fire event, and the NODES combine + broadcast, so a hostile
/// coordinator collecting `/sign` responses can never finalize (§2).
///
/// Ordering (ADR-0012 Model-B Hold lifecycle; ADR-0013 §§2-3, §6-7; ADR-0008):
///  -. Lockdown (ADR-0008) — a terminal-Lockdown node answers `FRAUD_SUSPECTED`
///     and does nothing else. Checked before the lock, so it short-circuits auth,
///     PIN, and the budget entirely.
///  0. coordinator-auth + freshness + fresh nonce + node-capped expiry — before
///     the PIN; an authentic request consumes its nonce even when a later check
///     refuses it ([`verify_coord_auth`]).
/// 0b. PIN-INDEPENDENT delivery preconditions (V0-4b §0), refused BEFORE the PIN so
///     the refusal is provably identical for every PIN class: the carrier must fit
///     the federation-uniform `max_msg_bytes` ([`ensure_request_propagatable`]) and
///     must outlive `now + delivery_horizon_secs` ([`ensure_delivery_horizon`]).
///     Together these mean "deliverable to me" implies "deliverable to every peer,
///     in time" — which is what confirmation-gated arming rests on.
///  1. PIN + per-node attempt budget (ADR-0012 constant-cost compare; ADR-0013 §7)
///     — before anything is signed. BOTH Argon2id digests are computed and the
///     verdict is constant-time-selected ([`pin::verify_pin`]); the budget charges
///     ONLY wrong pins, a valid duress pin records its arm INTENT even when locked
///     out (fail-closed) — it does NOT arm here; arming commits only at t-of-n
///     confirmation on the `/channel` path — and every PIN verdict stages the identical coordinator request
///     before an early PIN-refusal exit so peer nonce effects cannot pierce lockout
///     cover. Both matching pins stage before cached acceptance; a freshly validated
///     request stages before candidate capacity admission. A locked-out node still refuses to sign.
///     A bad/locked PIN
///     verdict is never logged: the PIN is not part of the commitment, so recording
///     it would wrongly replay a `BAD_PIN` refusal for the same transaction
///     resubmitted with a good PIN.
///  2. decode BOTH PSBTs — the spend and its MANDATORY escape (§4); undecodable
///     input is a 400, not a refusal.
///  3. compute BOTH `commitment_id`s — the exact-byte pair of §4 (V0-2b).
///  4. idempotency — prune the replay/pending/refresh/candidate logs, then return
///     the recorded verdict for an identical resubmission. Accepted state is keyed
///     by the COMPLETE pair; a transaction-determined refusal stays keyed by the
///     spend commitment.
///  5. validate the spend: user-signature verification, then policy-core. A
///     refusal here is final and (when the commitment fully determines it,
///     [`is_recordable_verdict`]) recorded; an INVALID spend is never signed,
///     registered, or authorized (the earlier safety carrier gives peers no signing
///     authority; each independently reaches the same refusal).
///  6. derive the transaction CLASS from the outputs (ADR-0013 §3): reject a
///     mixed hot+escape spend, and reject a refresh-shaped (pays-only-the-vault)
///     SpendRequest, as `PSBT_INCONSISTENT`.
///  7. validate the mandatory escape (§4): node-VALIDATED, never node-built.
///  8. `EXPIRY_TOO_SHORT` for hot-class: the commitment must outlive its Hold and
///     the combine window (`now + hold_secs + combine_slack_secs`); equality passes.
///  9. sign BOTH transactions at ingress, pin-independently — NOTHING is
///     transmitted here (invariant 7: partials wait for the fire gate).
/// 10. register the PAIR — two distinct exact-byte candidates with roles; the
///     spend gets the fire window its class earned; the escape gets the same-shaped
///     delayed window under both pins (normal no-op, duress sweep). In channel mode
///     BOTH are born release-CLOSED: a fire window alone is not release authority
///     under §0. Every pair — normal as well as duress — additionally waits for its
///     own carrier's t-holder decision, so `t−1` peers withholding receipts cannot
///     collect this node's matured share ahead of a duress carrier's confirmation
///     (ADR-0012 "Partial-release authorization"; opened by
///     [`channel::ChannelState::confirm_carrier`]).
/// 11. record both txids in the vault-authorized set (watchtower recognition +
///     unconfirmed-parent eligibility, ADR-0012); a REFUSED request never reaches
///     here, which is exactly what the recognition fix needs.
/// 12. the Hold timer, hot-class only — what refresh subordination reads.
/// 13. answer `Accepted` with no signature; the already-staged peer carrier is sent
///     asynchronously after the lock releases and cannot affect this response. The
///     holder decision that opens step 10's release gate — and, under duress, commits
///     the arm — also happens there, entirely off this path.
pub fn handle_sign(
    node: &Node,
    request: &SignRequest,
    now: u64,
) -> Result<SignResponse, BadRequest> {
    handle_sign_after_lock(node, request, || now)
}

/// Handle an HTTP sign submission using the node's clock. The first read happens
/// under the ingress sign-state guard; after the out-of-lock chain preflight a
/// second guarded read prevents slow RPC from staling expiry or Hold checks.
pub(crate) fn handle_sign_now(
    node: &Node,
    request: &SignRequest,
) -> Result<SignResponse, BadRequest> {
    handle_sign_after_lock(node, request, || {
        // Before the epoch is impossible in practice; treating it as 0 fails
        // safe because every real commitment then reads as expired.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Handle one first-class, pin-less refresh request (ADR-0013 §2): a self-spend
/// that resets a coin's recovery timelock. It passes the identical
/// coordinator-auth + freshness gate as a spend, then — because a refresh fires
/// at ingress — signs, registers, and becomes collectable immediately.
///
/// ADR-0012 makes a pin-less refresh conditional on burn bounds of its own because
/// "pin-less + instant means the refresh path has neither the Hold nor the pin that
/// ADR-0006 relies on for its burn defense". All three bounds are enforced here:
/// a minimum refresh interval and a tight refresh fee cap
/// ([`ConfigFile::refresh_min_interval_secs`], [`ConfigFile::refresh_max_feerate`],
/// ADR-0013 §6), plus refresh **subordination** — any pending spend blocks every
/// refresh, so a refresh can never race a spend that is waiting out its Hold, nor
/// one still inside its out-of-lock chain preflight
/// ([`Node::spend_preflight_in_flight`]).
///
/// A refresh arrives ONLY through this handler. The tagged union (ADR-0013 §2)
/// is what makes that true: a pure self-spend submitted as a PIN-carrying
/// `SpendRequest` is refused `PSBT_INCONSISTENT` in [`handle_sign`] rather than
/// served, which is what keeps refresh off the duress surface — admitting it there
/// would pose the question the union exists to delete (honor the pin, or ignore it?).
pub fn handle_refresh(
    node: &Node,
    request: &RefreshRequest,
    now: u64,
) -> Result<SignResponse, BadRequest> {
    handle_refresh_after_lock(node, request, || now)
}

/// Handle an HTTP Refresh submission using the node's clock, read only after the
/// sign-state lock so queueing cannot stale the freshness window.
pub(crate) fn handle_refresh_now(
    node: &Node,
    request: &RefreshRequest,
) -> Result<SignResponse, BadRequest> {
    handle_refresh_after_lock(node, request, || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

fn handle_sign_after_lock(
    node: &Node,
    request: &SignRequest,
    clock: impl Fn() -> u64,
) -> Result<SignResponse, BadRequest> {
    // Terminal Lockdown (ADR-0008) short-circuits everything: a locked-down node
    // answers FRAUD_SUSPECTED to every spend for its lifetime and does no further
    // work — no auth, no pin, no signing. Checked before the lock so a locked-down
    // node does not even contend it.
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    // The handler has two short sign-state phases around one out-of-lock chain
    // preflight. Phase 1 atomically consumes coordinator freshness, evaluates the PIN,
    // and records the safety intent. Phase 2 holds the SAME lock continuously across
    // every replay/pending check-and-update. Consuming the nonce before releasing phase
    // 1 prevents an exact replay from entering the RPC gap, while keeping the slow
    // backend call out of the lock lets Lockdown-at-T take it independently.
    //
    // Deliberate throughput tradeoff (V0-4a/V0-4b): the PIN compare's TWO Argon2id
    // evaluations and, in channel mode, one carrier derivation run under this lock,
    // so an authenticated request holds it for roughly three memory-hard evaluations
    // instead of the old SHA-256 microseconds. The confirmed-prevout preflight's
    // chain I/O is deliberately NOT part of that tradeoff: it runs between the two
    // sign-state phases, after the safety intent exists, so no 60-second RPC timeout
    // can delay the deadline driver's unconditional Lockdown-at-T. Hoisting the PIN
    // work out would either
    // run Argon2 BEFORE coord-auth (an unauthenticated-Argon2 DoS vector) or
    // duplicate the atomic nonce consumption the lock exists to give. New carrier
    // work is coordinator-signature-gated; exact peer replays use the nonce/signature
    // memo and do not re-enter the KDF, preventing a captured-request replay convoy.
    // The wrong-pin rate-limit backoff sleep is taken OUTSIDE this lock (below),
    // so a wrong-pin flood never pins `/sign` against honest spends.
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    // Authoritative Lockdown check, UNDER the lock. The pre-lock check above is only
    // a fast path; `enter_lockdown` sets the flag while holding this same lock, so a
    // terminal transition that races an in-flight request linearizes here — this
    // request either saw `false` and now holds the lock (and commits before Lockdown
    // could store) or sees `true` and refuses. Either way nothing is signed or
    // registered after Lockdown is entered — via the NORMAL `enter_lockdown`. The
    // poison-FORCED latch sets the flag without this lock and does not linearize, but it
    // fires only on a poisoned critical lock, so a request that raced past this check
    // then panics fail-closed at its store op before any egress (see `enter_lockdown`).
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    let raw_now = clock();

    // 0. Coordinator-auth + freshness gate (ADR-0013 §2/§3): every request must be
    //    validly coord-signed over its canonical bytes by the vault's one pinned
    //    coordinator, carry a fresh (unseen) nonce, and fall inside the expiry
    //    window — BEFORE the PIN, so an unauthenticated caller never reaches the
    //    PIN compare (the trust root V0-8b builds on). Runs under the one sign
    //    lock, so the nonce check-then-record is atomic. The same expiry bounds are
    //    re-checked after the out-of-lock chain preflight so slow RPC cannot stale
    //    the candidate-registration timestamp. Its stale lower bound uses the nonce log's
    //    rollback-guarded clock (`max(high_water, now)`, [`NonceLog`]), so a clock
    //    rollback cannot revive a pruned nonce. Its future upper bound still uses
    //    raw `now`, preserving V0-2's exact `now + max_commitment_age_secs` cap.
    let effective_now = match verify_coord_auth(
        node,
        request.coord_request(),
        &request.coord_sig,
        raw_now,
        &mut state.coord_nonces,
    ) {
        Ok(effective_now) => effective_now,
        Err(rejected) => return Ok(rejected),
    };
    // 0b. PIN-INDEPENDENT DELIVERY PRECONDITIONS (V0-4b §0), refused BEFORE the pin
    //     is evaluated. Confirmation-gated arming rests on "a carrier this node can
    //     process is a carrier every peer can also receive and process in time". A
    //     carrier that fails either half can never reach t-of-n, so admitting it would
    //     let a hostile coordinator drive nodes into divergent states. Both checks are
    //     decisions the coordinator can already make itself — a size and a clock
    //     comparison over bytes it authored — so refusing here leaks nothing, and
    //     refusing BEFORE the pin makes the refusal provably identical for every pin
    //     class (no oversized/near-expiry pin oracle).
    let propagated_request = vault_proto::TaggedRequest::Spend(request.clone());
    // The SIZE bound applies to peer relays too. `max_msg_bytes` is manifest-uniform
    // and the check is a pure function of the bytes, so a relay failing it would have
    // failed at its origin as well; there is nothing latency-dependent to forgive.
    // Exempting relays reopened a split vector: the `/channel` pre-KDF guard is a
    // short-circuiting `&&`, so a body failing ONLY this bound yields `carrier = None`
    // and was then processed with the gate skipped — derived its carrier, reached the
    // outbox, and became a local holder of a carrier this node can never actually fan
    // out. A compromised peer could hand that to one node and leave it armed alone.
    ensure_request_propagatable(node, &propagated_request)?;
    // Every node enforces a fresh horizon the FIRST time it processes the carrier,
    // whether that first ingress is `/sign` or a peer relay. Otherwise `t−1`
    // compromised peers can hold a valid carrier until just before expiry, deliver it
    // concurrently to one honest node, and let that node self-count + count their
    // receipts before its own async fan-out can land — a persistent one-node arm.
    // Replayed peer receipts return from coordinator freshness above, so an existing
    // holder does not restart the horizon merely to count another existing holder.
    if let Some(refused) = ensure_delivery_horizon(node, request.expiry, effective_now) {
        // PROPAGATE ANYWAY — this is a NODE-LOCAL CLOCK refusal, and every such refusal
        // must still fan the carrier out. Its sibling `EXPIRY_TOO_SHORT` (step 8) has
        // always done so; this one did not, and that asymmetry was a THEFT vector, not
        // merely the accepted censorship residual:
        //
        //   The gate is `expiry >= now + delivery_horizon_secs`, evaluated against each
        //   node's OWN clock. A coordinator that tunes `expiry` to exactly
        //   `now_A + delivery_horizon_secs` is admitted by the node it reaches first and
        //   refused by every peer, whose clock has advanced by the relay latency. If
        //   that refusal also skipped propagation, the refusing peers contributed no
        //   receipt, so node A — which validated and signed — could sit below `t`
        //   holders while the tolerated `t−1` compromised minority simply withheld
        //   theirs. A, unarmed, still releases its partial at fire, and A + the `t−1`
        //   compromised partials finalize the coerced hot spend with NO node armed.
        //   That is the outcome [`CarrierMemoLookup`] names theft rather than
        //   censorship. Fanning out here restores the invariant that decides it: a node
        //   that refuses on its own clock still forwards the carrier, so its receipt
        //   reaches every signer, and any honest node that signs sees every other
        //   honest node that saw the carrier — hence reaches `t` and freezes.
        //
        // This node still records NO intent (the pin hook is below) and claims NO
        // holder slot, so it cannot itself arm off this carrier. That is what keeps the
        // gate's original purpose intact: a carrier held by compromised peers until
        // just before expiry is refused HERE, so the node it was aimed at has no intent
        // to commit and cannot be armed alone by their forged receipts.
        //
        // Pin-uniform by construction: the whole branch runs before the pin is
        // evaluated, so both pin classes fan out identically. It is also the same
        // distinction the policy refusals draw — a FEDERATION-UNIFORM refusal
        // (`verify_spend`/`verify_escape`) deliberately does not propagate, because
        // every honest node reaches it independently and propagating would break theft
        // recognition; a NODE-LOCAL clock refusal must, because peers do not.
        //
        // Coordinator auth already consumed this nonce, but the refusal returns
        // before any carrier exists. Peer receipt resolution runs after this
        // authoritative handler and treats a vacant memo as "nothing to confirm",
        // so replays stay KDF-free without creating refusal-only carrier state.
        node.outbox
            .lock()
            .expect("outbox lock poisoned")
            .push(propagated_request);
        return Ok(refused);
    }
    // Every RAMDISK lifetime coupled to coordinator freshness uses the same
    // rollback-guarded lower bound — including the delivery horizon above, whose
    // refusal decides whether an intent is ever recorded and is therefore confirmation
    // state in the sense [`replay::NonceLog::effective_now`] governs. Only the
    // future-expiry cap deliberately stays on the raw clock, so rollback protection
    // cannot widen V0-2's exact `now + max_commitment_age_secs` acceptance horizon.
    let now = effective_now;
    // 1. PIN + per-node attempt budget, before anything is signed (ADR-0012 /
    //    ADR-0013 §7). BOTH Argon2id digests are computed unconditionally for every
    //    authenticated, deliverable SpendRequest and the verdict is constant-time-
    //    selected ([`pin::verify_pin`]). A short-circuit would make a duress pin one
    //    Argon2 slower and leak the duress bit to the coordinator-attacker. Normal
    //    and duress are then observably identical: same two PIN evaluations, same
    //    memory-hard carrier-id derivation, same (no-op) budget touch, same lack of
    //    backoff. Only a WRONG pin diverges (it charges the budget and sleeps its
    //    backoff), and a wrong pin is neither PIN, so its divergence leaks nothing
    //    about duress.
    //
    //    A bad-pin verdict is never recorded in the replay log: the pin is not part
    //    of the commitment, so recording it would wrongly replay a BAD_PIN refusal
    //    for the same transaction later resubmitted with a good pin.
    // Even an empty or over-length value runs both PIN Argon2 evaluations: there is
    // no PIN-shape fast path. It is forced Wrong afterward: empty is also how an
    // omitted wire field decodes, and values beyond MAX_PIN_BYTES are outside the
    // enrolment protocol. The pin-independent 0b refusal above intentionally occurs
    // before these evaluations, as §0 requires.
    let compared = pin::verify_pin(node.pin_evaluator.as_ref(), request.pin.as_bytes());
    let verdict = if request.pin.is_empty() || request.pin.len() > MAX_PIN_BYTES {
        pin::PinVerdict::Wrong
    } else {
        compared
    };
    let charge = state
        .pin_budget
        .charge(verdict, now, &node.pin_budget_config);
    // Fail-closed (ADR-0012): a valid DURESS pin ALWAYS fires the arm-hook — even
    // when the node is locked out on a wrong-pin flood, and even though V0-4a still
    // signs a not-locked duress request identically to a normal one. The budget
    // never charges a valid pin, so this can never be rate-limited away. The hook
    // runs UNCONDITIONALLY here and selects its +1/+0 delta in constant time, so
    // normal and duress do identical observable work on this line too.
    //
    // **The hook RECORDS INTENT; it does not arm (V0-4b §0).** Nothing on this path
    // freezes hot-class finalization or schedules Lockdown/Firing: it writes the
    // same-shaped per-carrier `ArmIntent` and the pre-arm cover overlay
    // (`record_arm_intent` passes `arm = false` unconditionally). The freeze commits
    // asynchronously in `confirm_carrier`, off the `/sign` response path, once `t`
    // distinct members are known to hold the carrier — so a hostile coordinator
    // cannot freeze THIS node while leaving `t−1` free to finalize the coerced hot
    // spend. Do not "restore" an arm here; that is the theft class §0 closes.
    //
    // Placed above `charge.refuse` so a locked-out node still records the intent and
    // can therefore still arm on confirmation (fail-closed, invariant v).
    let carrier = if node.channel.is_some() {
        arm_carrier_id(node, request.coord_request())
    } else {
        String::new()
    };
    node.fire_arm_hook(
        verdict,
        &carrier,
        &request.nonce,
        arm_signature_tag(&request.coord_sig),
        request.expiry,
        now,
    );
    if charge.refuse {
        // Propagation belongs to the coordinator-authenticated request, not to this
        // node's ability to sign. Stage EVERY PIN verdict before this early exit: a
        // selectively-delivered duress request must reach peers even if this node is
        // already locked out — otherwise a lockout could hold the federation below the
        // t-confirmations arming needs — while a wrong request must consume the same
        // peer nonce state. Otherwise the coordinator can replay the envelope directly
        // at a peer and distinguish a propagated match (`NONCE_REPLAYED`) from an
        // unpropagated wrong guess (`BAD_PIN`), piercing the uniform lockout response.
        // The async pump runs after `sign_state` is released, and the direct response
        // never waits on or varies with peer outcomes.
        //
        // Unconditional now: an un-propagatable carrier was already refused above, at
        // 0b, BEFORE the pin — so no pin class can reach this line with one, and the
        // old best-effort skip (which existed only to keep the LOCKED response from
        // becoming pin-dependent) has nothing left to guard against.
        //
        // STAGE + SELF-HOLD — §0's holder criterion is receipt and processing of the
        // authenticated safety carrier, not eligibility to sign its PSBT pair. The
        // attempt budget therefore cannot turn a valid duress arm into a requirement
        // for `t` OTHER receipts: once the carrier is staged, this node contributes self
        // and arms with `t−1` distinct peer receipts even while locked out. The tolerated
        // compromised minority can falsely over-arm a node whose peers reject the body,
        // but the task explicitly accepts that direction as nuisance denial → recovery;
        // allowing minority WITHHOLDING to defeat fail-closed arming is the real break.
        stage_spend_carrier(node, propagated_request, &carrier);
        // Locked out (any pin) or a wrong pin: refuse to sign. Nothing below runs and
        // no verdict is recorded, so it is safe to drop the sign lock now and sleep
        // the backoff OUTSIDE it — a wrong-pin flood must not pin the one `/sign`
        // lock for the whole backoff and stall honest spends.
        drop(state);
        if !charge.backoff.is_zero() {
            std::thread::sleep(charge.backoff);
        }
        return Ok(pin_refusal(charge.locked));
    }
    // Prevout ground-truth FETCH, after the chain-INDEPENDENT safety intent exists
    // and after coordinator freshness has been consumed, but OUTSIDE `sign_state`.
    // This ordering closes both sides of the boundary:
    //
    //  - a slow/hung backend cannot delay the intent or Lockdown-at-T; and
    //  - a captured nonce replay cannot repeatedly launch the two RPC batches.
    //
    // Re-acquire before any replay/pending mutation and re-sample time: an RPC that
    // outlasts the request's expiry or delivery horizon must not register a stale
    // candidate using the phase-1 timestamp.
    //
    // Claim the in-flight-spend slot FIRST, while the lock is still held (bead
    // btc-policy-f91). This spend does not enter `state.pending` until phase 2, so
    // without the claim it is invisible to refresh subordination for the whole
    // preflight, and a `RefreshRequest` racing it could finish its own shorter
    // preflight, see no pending spend, and register an immediately-fireable refresh
    // over an input this request's MANDATORY ESCAPE needs — the escape then fails
    // coverage at `T` and the sweep dies. Degrades to frozen funds → recovery, never
    // theft, but it is honest-reachable, so it is closed rather than accepted. The
    // guard releases the slot on every exit path including a panic; see
    // [`SpendPreflightGuard`].
    // The class is not derived until phase 2, so this conservatively covers an
    // escape-class SpendRequest during preflight too; once accepted it releases the
    // claim without entering `pending`, preserving ADR-0012's steady-state exception.
    //
    // WHAT THIS WINDOW STILL COSTS, and why that is the accepted answer (f91 (B)).
    // `stage_spend_carrier` — the peer fan-out that lets a selectively-delivered
    // carrier reach `t` holders and arm the federation — first becomes possible only
    // AFTER the preflight. A node whose backend is slow therefore contributes that
    // stall to its fan-out delay. The OUT-OF-LOCK PREFLIGHT component is a bounded
    // DELAY, not a MISS, and each clause below is load-bearing:
    //
    //  - the safety INTENT is already chain-independent and already recorded — the
    //    arm hook ran above, before any of this;
    //  - the fan-out is not conditional on this node being able to SIGN: every
    //    NODE-LOCAL refusal below stages the carrier too (expiry, horizon, backward
    //    clock, EXPIRY_TOO_SHORT, the Hot budget, and the fetch failure at 4b). The
    //    federation-uniform refusals deliberately do not stage — but a peer reaches
    //    those independently, which is exactly why they need no forward;
    //  - the preflight is exactly TWO batch RPCs regardless of the request — one for
    //    the spend, one for the escape, the ladder reusing the escape's — each a
    //    single loopback HTTP request under [`chain::RPC_TIMEOUT`]. That INVARIANCE is
    //    the part a hostile coordinator could otherwise exploit: it cannot multiply
    //    this preflight component by declaring more inputs. (A wall-clock ceiling rests on this
    //    node's OWN bitcoind, which is inside its trust boundary already — a backend
    //    that lies or trickles bytes is a dead node, i.e. the accepted censorship
    //    residual, not a new vector.); and
    //  - the fully-hung case degrades into the node-local `CommitmentExpired` forward
    //    just below, which stages as well.
    //
    // Fanning the request out BEFORE validation is INVARIANT-BLOCKED, not merely
    // unimplemented: the staged item is the full `TaggedRequest`, and staging it
    // pre-validation would propagate federation-uniform policy and prevout-MISMATCH
    // refusals that every honest node reaches independently — breaking theft
    // recognition and silence. A reduced "safety-only" signal is no better: peers
    // authenticate a carrier by the coordinator signature over the request's exact
    // canonical bytes, so anything they can verify IS the full request, and anything
    // smaller would be forgeable by a single compromised peer into a holder receipt.
    // Hence the preflight bound is made explicit and tested here rather than
    // engineered away. It is deliberately NOT a bound on total ingress-to-fan-out
    // latency: after the I/O returns, this request must wait to re-acquire
    // `sign_state`, then performs phase-2 validation and signing before the accepted
    // path stages at step 9. That additional lock-wait/work term can grow under
    // concurrent authenticated coordinator traffic; it is separate from the
    // request-shape-controlled preflight term this bead closes.
    let _preflight = node.enter_spend_preflight();
    drop(state);
    let (spend_prevouts, escape_prevouts) = prefetch_spend_escape_prevouts(node, request);
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    let raw_now = clock();
    let now = state.coord_nonces.effective_now(raw_now);
    if request.expiry <= now {
        // NODE-LOCAL expiry: this node's own chain preflight (up to two RPC_TIMEOUT
        // batches) outlived the commitment, so its `now` advanced past `expiry` while a
        // faster peer's did not. Forward the carrier exactly like the two delivery-
        // horizon refusals (phase-1 above, phase-2 just below) — the safety intent is
        // already recorded, and a node that refuses to sign on its OWN clock must still
        // fan the carrier out so every honest signer sees its receipt and can reach `t`
        // (the theft vector the phase-1 horizon comment details). It still registers NO
        // candidate against the stale window. `expiry <= now` also implies
        // `expiry < now + delivery_horizon`, so this is exactly the expired subset of
        // the horizon refusal below, split out only to keep the CommitmentExpired code
        // (v0-exit 9y5.3 review, [P2] Fable: a slow/hung backend must not let this node
        // silently swallow the duress signal). STAGE (not a bare outbox push): the pin
        // hook already recorded this node's duress intent, so it must claim its holder
        // slot too — otherwise the intent is hollow, `confirm_carrier` returns NONE
        // forever, and this node can never arm/Lockdown off its OWN carrier even with all
        // peer receipts. Matches the lockout and EXPIRY_TOO_SHORT node-local paths.
        stage_spend_carrier(node, propagated_request, &carrier);
        return Ok(refusal(
            RefusalCode::CommitmentExpired,
            "commitment_expiry",
            format!(
                "expiry {} is at or before this node's post-preflight clock (now {now}); \
                 forwarded but not signed",
                request.expiry
            ),
        ));
    }
    if request.expiry > raw_now.saturating_add(node.max_commitment_age_secs) {
        // The future-expiry cap on the RAW clock (rollback protection deliberately does
        // not widen it). For a monotonic clock this is defensively unreachable — the
        // request already cleared `expiry <= now + max_age` at coordinator auth and
        // `raw_now` only advanced. It can newly fire ONLY if system time stepped BACKWARD
        // during the preflight, dropping `raw_now` below the phase-1 sample — a NODE-LOCAL
        // clock fault this node's peers do not share. So STAGE it, like the expiry/horizon
        // node-local refusals, rather than letting one node's backward clock step swallow
        // a selectively-delivered duress carrier (v0-exit 9y5.3 review, codex P2).
        stage_spend_carrier(node, propagated_request, &carrier);
        return Ok(refusal(
            RefusalCode::CommitmentExpired,
            "commitment_expiry",
            format!(
                "expiry {} exceeds now + max age {}s (raw clock; a backward step forwarded \
                 but did not sign)",
                request.expiry, node.max_commitment_age_secs
            ),
        ));
    }
    if let Some(refused) = ensure_delivery_horizon(node, request.expiry, now) {
        // The carrier was fresh enough when received and its safety intent is already
        // recorded, but slow chain I/O consumed the remaining relay margin. STAGE (not a
        // bare push): unlike the PHASE-1 horizon — which runs before the pin hook and
        // deliberately claims no holder slot — the intent already exists here, so this
        // node must also self-hold or its recorded intent is hollow and non-confirmable
        // (Fable pass 3). It still refuses to sign/register a candidate against a stale
        // delivery window.
        stage_spend_carrier(node, propagated_request, &carrier);
        return Ok(refused);
    }
    // 2. Decode BOTH PSBTs; undecodable input is a 400, not a refusal. The escape
    //    is mandatory (ADR-0012: "a request missing the escape is invalid and
    //    rejected outright, so a hostile coordinator cannot strip the escape to
    //    force lockdown-only").
    let mut spend = decode_psbt(&request.psbt, "spend")?;
    let mut escape = decode_psbt(&request.escape_psbt, "escape")?;
    // The escape's fee-bump ladder (bead btc-policy-9y5.7). Bounded BEFORE decoding so
    // an oversized ladder costs one length comparison rather than N base64+PSBT
    // decodes, and decoded here — beside the escape — because every rung is validated,
    // signed, and registered on exactly the same pin-independent path the escape is.
    if request.escape_bumps.len() > MAX_ESCAPE_BUMPS {
        return Ok(refusal(
            RefusalCode::PsbtInconsistent,
            "escape:bump_ladder",
            format!(
                "the escape fee-bump ladder has {} rungs, more than the {MAX_ESCAPE_BUMPS} a \
                 request may authorize",
                request.escape_bumps.len()
            ),
        ));
    }
    let mut escape_bumps = request
        .escape_bumps
        .iter()
        .map(|bump| decode_psbt(bump, "escape_bump"))
        .collect::<Result<Vec<Psbt>, _>>()?;

    // 3. Bind this decision to the exact transactions. The commitments carry
    //    this node's OWN baked `policy_version` (from config, not the request):
    //    the node always evaluates and signs against its own static policy, so
    //    the request's `policy_version` is coordinator metadata that cannot
    //    change what gets signed and needs no separate match check here. The two
    //    are DISTINCT commitments — the pair of §4.
    let commitment_id = commitment_of(node, &spend, request.expiry).commitment_id();
    let escape_commitment_id = commitment_of(node, &escape, request.expiry).commitment_id();
    // Accepted idempotency must bind the COMPLETE candidate pair, not just the
    // spend commitment. A commitment deliberately excludes signature bytes, and
    // the spend id says nothing about which mandatory escape accompanied it. If an
    // Accepted entry lived under `commitment_id`, a coordinator could send peers
    // different valid user-signature instances or escapes and have the cache hide
    // the conflict before validation/registration. The request-pair key includes
    // both exact ingress PSBTs; PIN/auth transmission fields stay outside because
    // coordinator auth and the PIN are processed before this lookup by design.
    // The ladder is part of the accepted pair's identity: two requests that agree on
    // the spend and the escape but authorize different bumps authorize different
    // replacements, and an acceptance cached across that difference would let a
    // coordinator hand peers different ladders behind one cache hit.
    let accepted_replay_key = {
        // Scoped so the borrows of the PSBTs end here — they are taken mutably
        // further down, for this node's own ingress signatures.
        let mut labels: Vec<(String, &Psbt)> = vec![
            (commitment_id.clone(), &spend),
            (escape_commitment_id.clone(), &escape),
        ];
        for (index, bump) in escape_bumps.iter().enumerate() {
            labels.push((format!("escape_bump:{index}"), bump));
        }
        let entries: Vec<(&str, &Psbt)> = labels
            .iter()
            .map(|(id, psbt)| (id.as_str(), *psbt))
            .collect();
        acceptance_replay_key(&entries)
    };
    // The two ids must remain distinct for an escape-class request: its spend completes
    // immediately, while the mandatory escape is the disjoint residual swept at T.
    // The structural equality check sits after both node validations below, and it is
    // never a PIN-dependent arm gate: arming is decided solely by the §0 confirmation
    // count. This policy-shaped refusal is identical under both PINs and returns without
    // staging the carrier; contributing no self receipt is what prevents a provisionally
    // drifted node from arming alone.

    // 4. Anti-replay log: prune expired entries (retention is bounded by each
    //    entry's expiry), then return idempotently for an identical, unexpired
    //    resubmission. Accepted state is keyed by the complete pair above;
    //    transaction-determined refusals remain keyed by the spend commitment. An
    //    RBF replacement has a different commitment and is never blocked here.
    //    Prune the pending log on the same schedule so its Hold timers stay bounded.
    state.replay.prune(now);
    if let Some(recorded) = state.replay.get(&accepted_replay_key, now) {
        // Maintain the cover overlay on the cached path exactly as fresh ingress
        // does, and record the already-registered paired escape as THIS carrier's
        // delayed slot. Neither call arms: under §0 a duress resubmission of a
        // normal-pending pair is still un-armed here, so `apply_cached_schedule`'s
        // sweep selection is a no-op unless this node is ALREADY armed, and it is
        // `record_intent_pair` that carries the pair forward so the Scheduled +
        // duress row lands on it when the resubmission reaches t-confirmation —
        // rather than on whatever later cover traffic left in the overlay. Without
        // that, the row would silently degrade to Lockdown-only.
        if let Some(channel) = &node.channel {
            channel.apply_cached_schedule(
                &escape_commitment_id,
                verdict == pin::PinVerdict::Duress,
                now,
                node.epsilon_secs,
            );
            channel.record_intent_pair(&carrier, &commitment_id, &escape_commitment_id);
        }
        // Idempotent accepted requests re-propagate under BOTH matching pins, so a
        // selectively-delivered duress retry can still gather the t confirmations
        // arming needs instead of stopping at this node's cache.
        stage_spend_carrier(node, propagated_request, &carrier);
        return Ok(recorded);
    }
    if let Some(recorded) = state.replay.get(&commitment_id, now) {
        // A commitment-keyed hit is a recorded REFUSAL (never an acceptance — those are
        // keyed by the pair above), so the direct request is refused. The carrier is
        // not staged and this node therefore never becomes a holder; peer claims
        // cannot turn a locally refused intent into a one-node arm.
        // Escape-derived refusals are deliberately NOT cached under the spend id
        // (see `verify_escape` below), so a corrupt escape cannot poison this entry.
        return Ok(recorded);
    }
    // 4b. A NODE-LOCAL prevout FETCH failure: this node's own backend errored, so it
    //     has no chain ground truth and cannot evaluate ANY of this request. Refuse
    //     fail-closed (as before — policy-core must never see attacker-supplied
    //     `witness_utxo` values once the chain view is gone) but FORWARD the carrier,
    //     exactly like the node-local expiry and delivery-horizon refusals above.
    //     Otherwise one node with a down bitcoind silently swallows a selectively
    //     delivered duress carrier: it recorded the intent at the arm hook, so without
    //     a holder claim that intent is hollow, `confirm_carrier` never reaches `t`,
    //     and the node can never arm or Lockdown off its OWN carrier (bead f91 (C)).
    //
    //     Two orderings decide whether this is a fix or a regression, and BOTH were
    //     violated by earlier attempts:
    //
    //      - it runs AFTER the accepted-replay lookup, so a retry of an ALREADY
    //        ACCEPTED request returns its cached ACCEPTED verdict rather than being
    //        overridden by a transient backend failure (codex 9y5.3 pass-5 P1). It
    //        runs after the commitment-keyed refusal lookup for the same reason.
    //      - it fires ONLY on a FETCH failure, never on a value MISMATCH. A fetch
    //        failure is NODE-LOCAL — it is this node's backend that is down, and a
    //        healthy peer reaches a different verdict — so peers must hear the
    //        carrier. A `witness_utxo`-vs-chain mismatch is FEDERATION-UNIFORM: every
    //        honest node computes it alike from the same consensus data, so
    //        propagating it would leak a theft-recognition signal. The split is
    //        STRUCTURAL, not a string match on the refusal: `Err` on the pre-fetch is
    //        the fetch failure, and the mismatch lives inside
    //        `compare_prevouts_against_chain`, which only runs on `Ok`.
    //
    //     Pin-uniform: the fetch outcome is a pure function of the backend and the
    //     PSBTs, never of the pin, so both matching pin classes take this branch
    //     identically. This costs a hostile coordinator nothing it did not already
    //     have — staging still requires a valid coordinator signature and a fresh
    //     nonce, and arming still requires a valid duress pin plus `t`-of-`n`
    //     confirmation — and it only ever adds the fail-safe direction.
    if let Some(refused) = node_local_prevout_fetch_failure(&spend_prevouts, &escape_prevouts) {
        stage_spend_carrier(node, propagated_request, &carrier);
        return Ok(refused);
    }
    state.pending.prune(now);
    state.refreshes.prune(now, node.refresh_min_interval_secs);
    // Prune expired channel candidates on the SAME sweep the replay/pending logs
    // run on (§5): a candidate and its stored partials evict when its commitment
    // expires. (`/channel` lookup also evicts expired candidates, so an idle node
    // that never runs this sweep still rejects them.)
    if let Some(channel) = &node.channel {
        channel.prune_store(now);
    }

    // 5. Validate the spend (user-signature verification, then policy-core)
    //    WITHOUT signing yet. A refusal here is final and is recorded exactly as
    //    in V0-2: only verdicts the commitment fully determines are logged, so a
    //    signature- or PSBT-structure-dependent refusal stays unrecorded and an
    //    identical commitment resubmitted with a corrected signature is
    //    re-evaluated, not answered from a stale refusal (the log does not
    //    defend the signature; DESIGN.md, "What the anti-replay log is — and is
    //    not"). An invalid submission is never signed, registered, authorized, or
    //    propagated; peers retain their own policy verdict and coordinator-nonce
    //    semantics. A valid duress PIN still recorded THIS node's intent above,
    //    independent of chain view and policy outcome; the safety arm commits only
    //    if the carrier later reaches t-confirmation.
    if let Err(refused) = verify_spend(node, &spend, spend_prevouts.as_ref()) {
        // ONE exception to "an invalid submission is never propagated": the
        // per-transaction Hot budget (ADR-0014 §1).
        //
        // Every other refusal here rejects a spend the vault would never have
        // authorized anyway. The Hot budget is different — it moved a whole class of
        // spends that WERE valid before ADR-0014 (large hot-wallet payments) into the
        // refused set, and that class is precisely what a coercer asks for. Leaving it
        // on the silent path would mean the greedier the demand, the quieter the vault:
        // every honest node refuses identically (the caps are manifest-uniform), so no
        // node would stage the carrier, the carrier would never reach t-confirmation,
        // and the duress freeze would never fire ANYWHERE. Capping the loss must not
        // buy that with the safety signal.
        //
        // So this refusal stages exactly as EXPIRY_TOO_SHORT does, and for the same
        // reason: it is pin-independent (amount-based — `hot_outflow` reads outputs,
        // never the pin), so both PIN classes take this branch identically and the
        // observable is unchanged, while a duress carrier still records intent,
        // propagates, and arms. The coerced spend is refused AND the vault freezes,
        // which is strictly better than the pre-ADR-0014 behaviour of completing it.
        //
        // Staging adds no attacker capability: propagation still requires a valid
        // coordinator signature and a fresh nonce, and arming still requires a valid
        // duress PIN plus t-of-n confirmation. It only adds a safety signal, and
        // arming is the fail-safe direction (freeze + Lockdown → recovery).
        if matches!(
            &refused,
            SignResponse::Refusal(r) if r.code == RefusalCode::HotBudgetExceeded
        ) {
            stage_spend_carrier(node, propagated_request, &carrier);
        }
        // This call is a NO-OP for the Hot budget: `is_recordable_verdict` excludes
        // `HOT_BUDGET_EXCEEDED` (and its velocity sibling), so neither reaches the
        // log. That exclusion is what keeps the staging branch above reachable on
        // EVERY fresh authenticated carrier under BOTH pins — a commitment-keyed
        // replay hit returns before it, so a cached per-tx verdict would suppress a
        // later duress carrier for the same commitment. See `is_recordable_verdict`,
        // where the exclusion and its cost (re-derivation, deterministic and cheap)
        // are stated at the site a maintainer would edit. Every other refusal
        // `verify_spend` can produce reaches this call exactly as in V0-2 and is
        // filtered by that one predicate — which records only the commitment-bound
        // policy verdicts and drops the witness- and clock-dependent ones. The Hot
        // budget adds no new caller-side filtering here; it only widens the
        // predicate's exclusion list.
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // 6. Derive the spend's class from its OUTPUTS (ADR-0013 §3) — never from a
    //    coordinator label. This rejects a mixed hot+escape spend, which the
    //    per-output allowlist check above happily admits.
    // The classification carries the hot outflow its own output scan measured, so
    // the velocity ledger below meters the very quantity the class decision turned
    // on rather than re-deriving every output against the descriptors a second time.
    let policy_core::Classification {
        class,
        hot_outflow: outflow,
    } = match policy_core::classify(&spend, &node.check_params) {
        Ok(classification) => classification,
        Err(v) => {
            let refused = refusal(map_policy_code(v.code), v.check, v.detail);
            record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
            return Ok(refused);
        }
    };
    if class == policy_core::TxClass::Refresh {
        // A pure self-spend arriving as a PINNED SpendRequest (ADR-0013 §3). It
        // belongs in a pin-less RefreshRequest, and admitting it here would pose
        // the question the tagged union exists to delete: honor the pin, or ignore
        // it? Refusing is what keeps refresh off the duress surface.
        let refused = refusal(
            RefusalCode::PsbtInconsistent,
            "transaction_class",
            "every output pays the vault: a refresh must be submitted as a pin-less \
             RefreshRequest, not a SpendRequest"
                .into(),
        );
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // 6b. The velocity half of the Hot budget (ADR-0014 §4). The pure per-tx
    //     check ran before the fee guard inside policy-core; this stateful check
    //     runs before validating the paired escape. That precedence is deliberate:
    //     an otherwise over-velocity duress carrier must still take the budget's
    //     propagation path even if the coordinator also supplied an invalid escape.
    //     Both decisions are pin-independent, and the spend is still refused before
    //     signing, so this closes a safety-signal suppression path without admitting
    //     any transaction.
    let mut hot_reservation: Option<&str> = None;
    if class == policy_core::TxClass::Hot {
        // Absent `[channel]` there is no store to meter against; `Node::load` and
        // `server::serve` both reject that shape before any traffic, so this is
        // only the path-less unit-test construction, which still gets the per-tx
        // cap from policy-core.
        if let Some(channel) = &node.channel {
            // The window AGES against the channel's MONOTONIC clock, never against
            // this request's wall time: `now` here is `effective_now`, whose
            // high-water mark guards clock ROLLBACK only — a forward excursion (NTP
            // step, VM restore) passes straight through it, and letting that drive
            // the ledger's destructive prune would free a live window's budget. The
            // RAW wall pair is handed over for the other half of the rule: candidate
            // pruning and firing compare `request.expiry` against raw Unix time, so
            // the reservation must use that same clock. Feeding the nonce high-water
            // here could call a reservation dead after a rollback while its paired
            // spend remained resident through the delayed-slot exemption. See
            // `channel::HotClock` and `channel::HotBudgetLedger::is_live`.
            match channel.reserve_hot_budget(
                &commitment_id,
                outflow.to_sat(),
                raw_now,
                request.expiry,
            ) {
                Ok(true) => hot_reservation = Some(&commitment_id),
                Ok(false) => {}
                Err(refused) => {
                    stage_spend_carrier(node, propagated_request, &carrier);
                    return Ok(hot_velocity_refusal(node, outflow.to_sat(), refused));
                }
            }
        }
    }
    // Every refusal from here to candidate admission must hand back a reservation
    // this call created. An idempotent hit belongs to the earlier accepted
    // candidate and leaves `hot_reservation` empty, so it is never unwound here.
    let unwind_hot_reservation = || {
        if let (Some(id), Some(channel)) = (hot_reservation, &node.channel) {
            channel.release_hot_budget(id);
        }
    };

    // 7. Validate the mandatory escape the same way (§4): node-VALIDATED, never
    //    node-built — every input a vault UTXO, every destination output paying
    //    the escape descriptor, and the user's signature verifying over the exact
    //    bytes.
    if let Err(refused) = verify_escape(node, &escape, escape_prevouts.as_ref()) {
        // The replay key binds only the spend. An escape-derived refusal is not a
        // property of that commitment: the same exact spend may be paired with a
        // corrected escape on a fresh request. Caching it under the spend id would
        // strand that correction until expiry.
        unwind_hot_reservation();
        return Ok(refused);
    }
    // 7b. Validate the escape's fee-bump ladder (bead btc-policy-9y5.7): every rung is
    //     an escape in its own right (user-signed, vault inputs, escape-class), and the
    //     ladder as a whole changes ONLY the fee. Pin-independent, exactly like the
    //     escape validation above, and never an arm gate — a bad ladder refuses the
    //     request under both PINs identically.
    //
    //     The ladder's SHAPE is checked FIRST, before the per-rung escape validation.
    //     `compare_prevouts_against_chain` matches a PSBT's inputs against a
    //     pre-fetched prevout batch POSITIONALLY, and the batch below is the escape's;
    //     reusing it for a rung is only ground truth once "same inputs, same order" is
    //     established. Establishing it first means the reuse is sound on its own terms
    //     rather than by appeal to a check further down. (The shape check reads
    //     coordinator-supplied `witness_utxo` values, but only to order the rungs by
    //     fee, and all rungs share one input set — so the ordering turns on the
    //     outputs, which are consensus data. The values themselves are then verified
    //     against the chain for every rung by the loop that follows.)
    if let Err(refused) = ensure_escape_ladder(
        node,
        &escape,
        &escape_bumps,
        escape_commitment_id == commitment_id,
    ) {
        unwind_hot_reservation();
        return Ok(refused);
    }
    for bump in &escape_bumps {
        // The rungs spend the same inputs in the same order as the escape, so the
        // escape's already-fetched prevouts are the exact ground truth for each rung
        // and no extra RPC is needed.
        if let Err(refused) = verify_escape(node, bump, escape_prevouts.as_ref()) {
            unwind_hot_reservation();
            return Ok(refused);
        }
    }
    if class == policy_core::TxClass::Escape && escape_commitment_id == commitment_id {
        // VACUOUS, and deliberately so: this branch requires `class == Escape` while
        // `hot_reservation` is only ever set inside the `class == Hot` block above, so
        // there is provably nothing to free. Kept for uniformity along the stretch —
        // every return between the reserve and admission unwinds — rather than as a
        // hint that an escape-class request could hold budget. It cannot (§7).
        unwind_hot_reservation();
        return Ok(refusal(
            RefusalCode::PsbtInconsistent,
            "escape_class_residual",
            "an escape-class spend completes immediately, so its mandatory escape must be a \
             distinct disjoint residual candidate for the T-time sweep"
                .into(),
        ));
    }

    // 8. EXPIRY_TOO_SHORT (ADR-0013 §6): a hot-class commitment must outlive its
    //    Hold AND the combine window that follows, or this node would sign at
    //    ingress, hold the partial, and watch the candidate expire before it could
    //    ever combine. Equality passes. Not recorded in the replay log: it is a
    //    verdict about the node's clock, not about the commitment, so the same
    //    commitment resubmitted earlier in its life must be re-evaluated.
    let fire_at = match class {
        // Hot-class: the Hold delays combine + broadcast, never signing.
        policy_core::TxClass::Hot => now.saturating_add(node.hold_secs),
        // Escape-class completes immediately under EITHER pin — the destination is
        // the user's own escape wallet either way, so there is nothing to defer and
        // therefore no timing oracle (ADR-0012).
        policy_core::TxClass::Escape => now,
        policy_core::TxClass::Refresh => {
            // Vacuous here — the reserve lives in the `class == Hot` block below, so no
            // reservation exists yet — but kept for the "every return between reserve and
            // admission unwinds" uniformity this function maintains (cf. the Escape-branch
            // vacuous unwind above).
            unwind_hot_reservation();
            return Ok(refusal(
                RefusalCode::PsbtInconsistent,
                "transaction_class",
                "a RefreshRequest must use the pin-less refresh request variant".into(),
            ));
        }
    };
    if class == policy_core::TxClass::Hot {
        let floor = fire_at.saturating_add(node.combine_slack_secs);
        if request.expiry < floor {
            // This refusal depends on THIS NODE'S CLOCK, so keep the existing all-peer
            // propagation and avoid needless carrier censorship at a per-node Hold
            // boundary. Crucially, the §0 holder claim is now ordered AFTER this
            // outbox write by `stage_spend_carrier`: if any earlier refusal skips
            // staging, its same-shaped intent remains non-armable regardless of peer
            // claims. `class` and `expiry` are pin-independent, so both PINs still take
            // this branch identically.
            unwind_hot_reservation();
            stage_spend_carrier(node, propagated_request, &carrier);
            return Ok(refusal(
                RefusalCode::ExpiryTooShort,
                "commitment_expiry",
                format!(
                    "expiry {} is before {floor} (now {now} + hold_secs {} + combine_slack_secs \
                     {}), so the spend could not finish combining before it expired",
                    request.expiry, node.hold_secs, node.combine_slack_secs
                ),
            ));
        }
    }

    // 9. Sign BOTH transactions, at ingress, pin-independently (ADR-0012's
    //    Model-B Hold lifecycle: "signing must not depend on the pin, or signing
    //    itself is a duress oracle"). NOTHING is transmitted here — the partials
    //    stay in this node's candidate registry until each candidate's authorized
    //    fire event opens the release gate (invariant 7).
    if let Err(detail) = add_node_signatures(node, &mut spend) {
        unwind_hot_reservation();
        return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
    }
    if let Err(detail) = add_node_signatures(node, &mut escape) {
        unwind_hot_reservation();
        return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
    }
    // Every rung too, at ingress and under both PINs. A rung signed later — say, only
    // once a bump is selected at `T` — would put a signing operation on the duress
    // side of the fire path and make the node's work pin-dependent; it would also be
    // too late, since Lockdown blocks new signing from `T` onward.
    for bump in &mut escape_bumps {
        if let Err(detail) = add_node_signatures(node, bump) {
            unwind_hot_reservation();
            return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
        }
    }

    // The pair is now fully validated. Stage the same coordinator-signed carrier
    // under BOTH matching pins before candidate admission, so a full store cannot
    // drop a valid duress safety signal. Self-holding linearizes after the outbox write:
    // a same-shaped intent that never reaches propagation remains non-confirmable, while
    // every processed/staged carrier counts this node regardless of signing eligibility.
    stage_spend_carrier(node, propagated_request, &carrier);

    // 10. Register the PAIR (§4): two distinct exact-byte candidates with
    //     unambiguous roles, both signed, paired by this request. The spend gets
    //     the fire window its class earned; the escape gets the same delayed slot
    //     under both pins (normal no-op, duress sweep at T).
    if let Err(refused) = register_pair(
        node,
        RegisterPair {
            spend: &spend,
            spend_commitment_id: &commitment_id,
            // Hot-class spends are the ones a duress arm freezes; an escape-class
            // spend completes under either pin.
            spend_hot: class == policy_core::TxClass::Hot,
            // Only a valid duress pin adopts this request's escape as the sweep. The
            // verdict is Normal or Duress here (a wrong/locked pin returned above).
            duress: verdict == pin::PinVerdict::Duress,
            // SpendRequest candidates cannot release/finalize until this carrier (or
            // another carrier for the same exact pair) reaches the t-holder decision.
            confirmation_required: true,
            escape: &escape,
            escape_bumps: &escape_bumps,
            escape_commitment_id: &escape_commitment_id,
            fire: channel::FireWindow {
                fire_at,
                deadline: request
                    .expiry
                    .min(fire_at.saturating_add(node.combine_slack_secs)),
            },
            expiry: request.expiry,
            now,
            // The first reserve ran before signing above. Candidate admission
            // revalidates it under the store lock so an expiry sweep cannot release
            // an idempotently-hit reservation between that check and insertion.
            hot_reserve: (class == policy_core::TxClass::Hot).then_some(channel::HotReserveSpec {
                commitment_id: &commitment_id,
                outflow_sat: outflow.to_sat(),
                wall_now: raw_now,
                expiry: request.expiry,
            }),
            carrier: &carrier,
        },
    ) {
        unwind_hot_reservation();
        return Ok(refused);
    }

    // 11. Recognition + the vault-authorized set (ADR-0012): this node validated
    //     and policy-ACCEPTED both transactions, so both are recognized by its
    //     watchtower and both may serve as unconfirmed parents. A REFUSED request
    //     never reaches here, which is exactly the property the recognition fix
    //     needs — a theft fanned to honest nodes must still alert.
    //
    //     Every fee-bump rung counts too, and for both halves of that. A bumped
    //     rung is the sweep: it was validated and accepted at this same ingress, so
    //     the node's watchtower must not alarm on the federation's own successful
    //     escape — precisely during the incident where an alert has to mean
    //     something. And a rung sitting unconfirmed in the mempool is as
    //     authorized a parent as the base escape is.
    {
        let mut authorized = node.authorized.lock().expect("authorized lock poisoned");
        authorized.insert(spend.unsigned_tx.compute_txid());
        authorized.insert(escape.unsigned_tx.compute_txid());
        for bump in &escape_bumps {
            authorized.insert(bump.unsigned_tx.compute_txid());
        }
    }

    // 12. The Hold timer, for hot-class only. It is what "a refresh is subordinate
    //     to any pending spend" reads (ADR-0012). An escape-class spend fires now,
    //     so it is never pending — the ADR names that as the explicit exception.
    if class == policy_core::TxClass::Hot {
        state.pending.record(commitment_id.clone(), request.expiry);
    }

    let verdict = SignResponse::Accepted(vault_proto::Accepted {
        commitment_id: commitment_id.clone(),
        first_seen: now,
        remaining_secs: fire_at.saturating_sub(now),
    });
    record_verdict(
        &mut state.replay,
        &accepted_replay_key,
        request.expiry,
        &verdict,
    );
    Ok(verdict)
}

fn handle_refresh_after_lock(
    node: &Node,
    request: &RefreshRequest,
    clock: impl Fn() -> u64,
) -> Result<SignResponse, BadRequest> {
    // Lockdown (ADR-0008) refuses refreshes too: every spend AND refresh answers
    // FRAUD_SUSPECTED for the node's lifetime. (The refresh path is pin-less, so it
    // has no budget to touch — only Lockdown gates it here.) This pre-lock check is
    // a fast path.
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    // Refreshes share the same serialized SignState as spends, so consuming the
    // nonce remains atomic with every other request at ingress.
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    // Authoritative Lockdown re-check under the lock: `enter_lockdown` sets the flag
    // while holding `sign_state`, so a transition racing this refresh linearizes here
    // and no refresh registers after Lockdown is entered (mirrors `/sign`). The
    // poison-FORCED latch does not linearize (it holds no lock) but fires only on a
    // poisoned critical lock, where a raced-past refresh panics fail-closed at its store
    // op before egress (see `enter_lockdown`).
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    let raw_now = clock();

    let _ingress_now = match verify_coord_auth(
        node,
        request.coord_request(),
        &request.coord_sig,
        raw_now,
        &mut state.coord_nonces,
    ) {
        Ok(effective_now) => effective_now,
        Err(rejected) => return Ok(rejected),
    };
    ensure_request_propagatable(node, &vault_proto::TaggedRequest::Refresh(request.clone()))?;
    // Consume freshness before external work so a captured signed request cannot
    // repeatedly launch backend RPC. As on `/sign`, the slow fetch runs without
    // `sign_state`; phase 2 re-checks Lockdown and expiry before any policy/state
    // mutation.
    drop(state);
    let refresh_prevouts = prefetch_refresh_prevouts(node, request);
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    let raw_now = clock();
    let now = state.coord_nonces.effective_now(raw_now);
    if request.expiry <= now
        || request.expiry > raw_now.saturating_add(node.max_commitment_age_secs)
    {
        return Ok(refusal(
            RefusalCode::CommitmentExpired,
            "commitment_expiry",
            format!(
                "expiry {} is outside the acceptance window after chain preflight \
                 (now {now}, max age {}s)",
                request.expiry, node.max_commitment_age_secs
            ),
        ));
    }

    // Preserve the transport boundary: a signed but undecodable PSBT is still a
    // bad request (HTTP 400), not a policy outcome.
    let mut refresh = decode_psbt(&request.refresh_psbt, "refresh")?;

    let commitment_id = commitment_of(node, &refresh, request.expiry).commitment_id();
    let accepted_replay_key = acceptance_replay_key(&[(&commitment_id, &refresh)]);
    state.replay.prune(now);
    if let Some(recorded) = state.replay.get(&accepted_replay_key, now) {
        return Ok(recorded);
    }
    if let Some(recorded) = state.replay.get(&commitment_id, now) {
        return Ok(recorded);
    }
    state.pending.prune(now);
    state.refreshes.prune(now, node.refresh_min_interval_secs);
    if let Some(channel) = &node.channel {
        channel.prune_store(now);
    }

    // The same validation a spend gets: the user's signature over the exact bytes,
    // then input ownership + allowlist + fee cap.
    if let Err(refused) = verify_spend(node, &refresh, refresh_prevouts.as_ref()) {
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // A refresh must BE a refresh: every output pays the vault (ADR-0013 §3). This
    // is what makes it safe to be pin-less — a transaction that can move nothing
    // to anyone needs no duress decision, so there is no signal for an attacker to
    // read on this path.
    match policy_core::classify(&refresh, &node.check_params).map(|c| c.class) {
        Ok(policy_core::TxClass::Refresh) => {}
        Ok(other) => {
            let refused = refusal(
                RefusalCode::PsbtInconsistent,
                "transaction_class",
                format!(
                    "a RefreshRequest must be a pure self-spend, but this is {other:?}-class: \
                     every output must pay the vault descriptor"
                ),
            );
            record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
            return Ok(refused);
        }
        Err(v) => {
            let refused = refusal(map_policy_code(v.code), v.check, v.detail);
            record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
            return Ok(refused);
        }
    }

    // Subordination (ADR-0012): any pending spend blocks EVERY refresh. The rule
    // is deliberately COARSE — not "refreshes whose inputs overlap the pending
    // spend". A duress escape sweeps most of the vault while the triggering hot
    // spend touches a small subset, so an input-overlap rule would let a refresh
    // over a non-overlapping escape input finalize instantly and invalidate the
    // armed escape. Only the coarse rule closes that.
    //
    // It is silent, which is why it can be unconditional: the refresh is deferred
    // for a reason the attacker can already see — their own visible pending spend
    // — and it behaves identically under both PINs and in ordinary operation.
    //
    // The predicate has TWO halves, and the second one is what makes the first
    // airtight (bead btc-policy-f91). `pending` holds spends this node has already
    // REGISTERED, which happens in `/sign`'s phase 2; a spend inside its out-of-lock
    // chain preflight has not reached that point yet and is invisible here. Since a
    // refresh's own preflight is shorter (one PSBT, one batch, versus the spend's
    // two), a refresh submitted while a spend is mid-preflight would otherwise
    // overtake it, find `pending` empty, and register as immediately fireable — and
    // if it spent an input the racing spend's mandatory escape needs, the escape
    // would no longer cover at `T`, the sweep would fail, and the vault would exit
    // through recovery. `spend_preflight_in_flight` covers exactly that gap; the two
    // halves overlap (the claim is released only after phase 2 has registered), so
    // there is no instant at which an in-flight spend is invisible to this rule.
    //
    // Both halves produce the SAME refusal bytes, deliberately: an attacker must not
    // be able to tell which one deferred them, and neither half depends on the racing
    // spend's PIN class (the claim is taken on the one path both matching pins take).
    if state.pending.has_any(now) || node.spend_preflight_in_flight() {
        return Ok(refusal(
            RefusalCode::RefreshSubordinated,
            "refresh_subordination",
            "a spend is pending on this node; refreshes are subordinate to pending spends \
             (retry once it settles)"
                .into(),
        ));
    }

    // ADR-0013 §6's two burn bounds. ADR-0006 leans on the Hold and the pin for
    // its burn defense; a refresh is pin-less AND instant, so it has neither and
    // needs its own.
    if let Some(refused) = check_refresh_interval(node, &state, &refresh, now) {
        return Ok(refused);
    }
    if let Some(refused) = check_refresh_feerate(node, &refresh) {
        return Ok(refused);
    }

    // Sign at ingress, like every other class.
    if let Err(detail) = add_node_signatures(node, &mut refresh) {
        return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
    }

    // A refresh is its own candidate with no escape to pair — it moves nothing to
    // anyone, so ADR-0013 §2 gives it no escape and no pin. It fires immediately.
    let fire = channel::FireWindow {
        fire_at: now,
        deadline: request
            .expiry
            .min(now.saturating_add(node.combine_slack_secs)),
    };
    // A refresh carries no PIN and so owns no §0 arm intent, but it must still key
    // its (no-op) delayed-slot write by the SAME carrier identity a spend uses.
    // Keying it by the raw `nonce` would let a post-wrench coordinator — which
    // computed a live duress carrier's digest itself, in order to sign that request
    // — set a refresh's nonce to that 64-char hex id (`MAX_COORD_NONCE_BYTES` is
    // exactly 64) and overwrite the duress intent's escape slot with the refresh's
    // own commitment. That commitment is registered with role `Spend`, which both
    // `refresh_escape_window` and `slot_active` reject, so the later t-confirmation
    // would pin the sweep to a slot that can never fire — Lockdown-only, forever.
    // The authenticated request digest tags the variants independently, and the
    // carrier construction's preimage/collision resistance prevents the refresh's
    // fast-hash output from naming a spend's independently stretched carrier.
    let carrier = arm_carrier_id(node, request.coord_request());
    if let Err(refused) = register_pair(
        node,
        RegisterPair {
            spend: &refresh,
            spend_commitment_id: &commitment_id,
            // A refresh is vault→vault and never frozen by a duress arm (it can move
            // nothing to anyone); it is subordinate to pending spends instead.
            spend_hot: false,
            // A refresh carries no pin, so it never adopts a sweep escape.
            duress: false,
            // Pin-less refreshes have no arm carrier and therefore no holder decision.
            confirmation_required: false,
            // Self-paired: a refresh has no escape (ADR-0013 §2), and the pairing
            // field is not optional, so it names itself rather than inventing an
            // absent-sibling case for one variant.
            escape: &refresh,
            // A refresh has no escape at all, so nothing to fee-bump.
            escape_bumps: &[],
            escape_commitment_id: &commitment_id,
            fire,
            expiry: request.expiry,
            now,
            hot_reserve: None,
            // Pin-less, so no §0 arm intent exists under this refresh-tagged
            // carrier id and the delayed-slot write is a no-op. See the derivation
            // above for why it must be the digest and not the raw nonce.
            carrier: &carrier,
        },
    ) {
        return Ok(refused);
    }

    // Start every touched coin's interval clock: the inputs (this coin has now
    // been refreshed) AND the outputs (the coins this refresh creates). Recording
    // the OUTPUTS is what actually bounds the burn RATE — an attacker chains
    // refreshes, each spending the last one's fresh output, so an inputs-only rule
    // would never fire on the chain it is meant to stop.
    state.refreshes.record(&refresh, now);

    node.authorized
        .lock()
        .expect("authorized lock poisoned")
        .insert(refresh.unsigned_tx.compute_txid());
    node.outbox
        .lock()
        .expect("outbox lock poisoned")
        .push(vault_proto::TaggedRequest::Refresh(request.clone()));

    let verdict = SignResponse::Accepted(vault_proto::Accepted {
        commitment_id: commitment_id.clone(),
        first_seen: now,
        remaining_secs: 0,
    });
    record_verdict(
        &mut state.replay,
        &accepted_replay_key,
        request.expiry,
        &verdict,
    );
    Ok(verdict)
}

/// ADR-0013 §6's minimum refresh interval, per coin. `None` ⇒ within bounds.
fn check_refresh_interval(
    node: &Node,
    state: &SignState,
    refresh: &Psbt,
    now: u64,
) -> Option<SignResponse> {
    for input in &refresh.unsigned_tx.input {
        let outpoint = input.previous_output;
        let Some(last) = state.refreshes.last_refresh(&outpoint) else {
            continue;
        };
        let elapsed = now.saturating_sub(last);
        if elapsed < node.refresh_min_interval_secs {
            return Some(refusal(
                RefusalCode::RefreshTooSoon,
                "refresh_min_interval",
                format!(
                    "coin {outpoint} was refreshed {elapsed}s ago, inside the \
                     {}s minimum refresh interval",
                    node.refresh_min_interval_secs
                ),
            ));
        }
    }
    None
}

/// ADR-0013 §6's tight refresh fee cap. `None` ⇒ within bounds.
///
/// The feerate is measured over the UNSIGNED transaction's vsize, which every node
/// computes identically from the exact committed bytes — the same determinism the
/// combine needs. It is a deliberate over-estimate (the final witness makes the
/// real transaction larger, hence its real feerate lower), so the error is always
/// toward refusing, never toward admitting a burn. That suits what this cap is: a
/// bound on the burn RATE, not a fee optimizer. It only has to sit far below
/// `max_fee_pct`, and it does.
fn check_refresh_feerate(node: &Node, refresh: &Psbt) -> Option<SignResponse> {
    let total_in: u64 = refresh
        .inputs
        .iter()
        .filter_map(|input| input.witness_utxo.as_ref())
        .fold(0, |acc, utxo| acc.saturating_add(utxo.value.to_sat()));
    let total_out: u64 = refresh
        .unsigned_tx
        .output
        .iter()
        .fold(0, |acc, txout| acc.saturating_add(txout.value.to_sat()));
    let fee = total_in.saturating_sub(total_out);
    let vsize = refresh.unsigned_tx.vsize() as u64;
    if vsize == 0 {
        return None;
    }
    // Compare `fee` against `cap * vsize` directly (widened to u128 so the product
    // cannot overflow) rather than the truncated integer feerate `fee / vsize`:
    // integer division rounds DOWN, so a refresh paying `cap * vsize + (vsize - 1)`
    // sats computes a feerate exactly equal to the cap and would slip through above
    // the bound. `fee == cap * vsize` (exactly the cap) still passes.
    let cap_sats = u128::from(node.refresh_max_feerate).saturating_mul(u128::from(vsize));
    if u128::from(fee) > cap_sats {
        return Some(refusal(
            RefusalCode::RefreshFeeExceedsCap,
            "refresh_fee_cap",
            format!(
                "refresh pays {fee} sat over {vsize} vB, above the {} sat/vB refresh cap \
                 ({cap_sats} sat)",
                node.refresh_max_feerate
            ),
        ));
    }
    None
}

/// The pair of exact-byte-bound transactions one accepted `SpendRequest` produces
/// (§4), ready to register.
struct RegisterPair<'a> {
    spend: &'a Psbt,
    spend_commitment_id: &'a str,
    /// Whether the spend is **hot-class** — the class a duress arm freezes
    /// (ADR-0012 invariant vii). Escape-class spends and refreshes pass `false`; the
    /// node derives this from the spend's own outputs, never a coordinator label.
    spend_hot: bool,
    /// Whether THIS request carried the duress pin. Gates only the SWEEP-escape
    /// adoption (a normal spend accepted while armed is still frozen + shrinks `T`,
    /// but never becomes the duress sweep escape).
    duress: bool,
    /// Whether the pair is governed by the SpendRequest holder-decision gate. False
    /// only for the pin-less refresh variant, which has no arm carrier.
    confirmation_required: bool,
    escape: &'a Psbt,
    /// The escape's validated fee-bump ladder (bead btc-policy-9y5.7), ascending by
    /// fee; empty when the request authorized no bump. A self-paired request (its
    /// escape IS its spend) always passes an empty slice — [`ensure_escape_ladder`]
    /// refuses a ladder there, so the collapsed single candidate never carries one.
    escape_bumps: &'a [Psbt],
    escape_commitment_id: &'a str,
    /// The SPEND's fire window. The escape's delayed slot is installed atomically
    /// by [`channel::ChannelState::register_candidates`].
    fire: channel::FireWindow,
    expiry: u64,
    /// Node-local ingress time for past-means-fire-now schedule semantics.
    now: u64,
    /// Hot-budget claim to revalidate atomically with candidate insertion. The
    /// pre-sign reserve already ran; this closes the idempotent-resubmit race with
    /// terminal candidate pruning. Escape-class spends and refreshes pass `None`.
    hot_reserve: Option<channel::HotReserveSpec<'a>>,
    /// The carrier identity (the coordinator-auth digest of the exact request) whose
    /// §0 arm intent this registration names its delayed escape slot into. A refresh
    /// carries no pin and so has no intent; the write is a no-op there.
    carrier: &'a str,
}

/// The §4 candidate-registry funnel: register the accepted request's **pair** —
/// the spend and its mandatory escape — as two distinct candidates, each bound to
/// its own exact-byte commitment, each already carrying this node's ingress
/// signature, each naming the other.
///
/// The spend carries `pair.fire`; the escape candidate receives the fixed delayed
/// slot under the same atomic store write. Under a normal pin that slot is a no-op;
/// under duress it is authorized at `T`. The escape is therefore signed,
/// registered, and assembled-and-waiting identically in both cases, while the three
/// release/finalize gates read one internal selector bit — no second release path.
///
/// Absent-channel mode ⇒ a no-op (no registry, so no assembly). In channel mode,
/// capacity is preflighted for the whole pair and refuses the request atomically:
/// an acknowledgement without retained partials cannot complete now that the
/// coordinator is structurally unable to assemble. A live same-id candidate bound
/// to a different user signature, sighash, or sibling is likewise a refusal.
fn register_pair(node: &Node, pair: RegisterPair) -> Result<(), SignResponse> {
    let Some(channel) = &node.channel else {
        return Ok(());
    };
    let keys = channel::CandidateKeys {
        witness_script: &node.witness_script,
        user_pubkey: &node.user_pubkey,
        self_signing_pubkey: &node.pubkey,
    };
    let specs = [
        Some(channel::CandidateSpec {
            psbt: pair.spend,
            // The ladder belongs to the ESCAPE, never to the spend. The spend is what
            // a duress arm freezes; bumping it is neither wanted nor authorized.
            escape_bumps: &[],
            commitment_id: pair.spend_commitment_id,
            paired_commitment_id: pair.escape_commitment_id,
            holder_quorum_reached: !pair.confirmation_required,
            role: channel::CandidateRole::Spend,
            // Only a hot-class spend is frozen by a duress arm. An escape-class
            // spend and a refresh (both `spend_hot = false`) complete under either
            // pin.
            hot: pair.spend_hot,
            fire: Some(pair.fire),
            expiry: pair.expiry,
        }),
        // A SELF-PAIRED request collapses to ONE candidate: an escape-class spend
        // byte-identical to its mandatory escape, OR a refresh (escape == spend,
        // ADR-0013 §2 gives a refresh no escape). The spend candidate already carries
        // the immediate fire window; registering a SECOND Escape-role candidate under
        // the SAME exact commitment id collides in the store — `register` keys on
        // `commitment_id`, so the two rows (differing only in `role`) surface
        // [Inserted, Conflict], refusing the whole request with PSBT_INCONSISTENT
        // while leaking the already-inserted fire-now spend. That refused every
        // channel-mode refresh and broke ADR-0013 §2's burn defense. Only build the
        // escape spec when its commitment id actually differs from the spend's.
        (pair.escape_commitment_id != pair.spend_commitment_id).then_some(channel::CandidateSpec {
            psbt: pair.escape,
            escape_bumps: pair.escape_bumps,
            commitment_id: pair.escape_commitment_id,
            paired_commitment_id: pair.spend_commitment_id,
            holder_quorum_reached: !pair.confirmation_required,
            role: channel::CandidateRole::Escape,
            // An escape is never a frozen hot spend — it is the sweep the arm
            // schedules at `T`.
            hot: false,
            fire: None,
            expiry: pair.expiry,
        }),
    ];
    let mut candidates = Vec::new();
    let mut commitment_ids = Vec::new();
    for spec in specs.into_iter().flatten() {
        let commitment_id = spec.commitment_id.to_string();
        match channel::Candidate::build(spec, &keys) {
            Ok(candidate) => {
                commitment_ids.push(commitment_id);
                candidates.push(candidate);
            }
            Err(e) => {
                return Err(refusal(
                    RefusalCode::PsbtInconsistent,
                    "candidate_registration",
                    format!("cannot build candidate {commitment_id}: {e}"),
                ))
            }
        }
    }
    // The duress SWEEP arm rides this same registration (constant-observable: the
    // directive is built on EVERY accepted request). `sweep_escape` names the
    // fixed delayed slot at `T`: normal makes it a no-op and duress makes it live.
    // Both pins write this same delayed-slot id. Escape-class validation above
    // guarantees it is a distinct residual rather than the already-completed spend.
    let outcomes = channel
        .register_candidates(
            candidates,
            channel::ArmDirective {
                sweep_escape: pair.escape_commitment_id,
                spend_commitment_id: pair.spend_commitment_id,
                carrier: pair.carrier,
                duress: pair.duress,
                epsilon_secs: node.epsilon_secs,
                now: pair.now,
            },
            pair.hot_reserve,
        )
        .map_err(|refused| {
            pair.hot_reserve.map_or_else(
                || {
                    refusal(
                        RefusalCode::PsbtInconsistent,
                        "candidate_registration",
                        "a non-hot candidate unexpectedly reached the hot-budget refusal path"
                            .into(),
                    )
                },
                |reserve| hot_velocity_refusal(node, reserve.outflow_sat, refused),
            )
        })?;
    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, channel::RegisterOutcome::Conflict))
    {
        return Err(refusal(
            RefusalCode::PsbtInconsistent,
            "candidate_identity",
            "this commitment is already registered under a different user-signature instance, \
             sighash, or paired candidate"
                .into(),
        ));
    }
    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, channel::RegisterOutcome::AtCapacity))
    {
        return Err(refusal(
            RefusalCode::CandidateCapacity,
            "candidate_registry_capacity",
            format!(
                "the bounded candidate registry cannot atomically retain request candidates: {}",
                commitment_ids.join(", ")
            ),
        ));
    }
    // `register_candidates` attached this resident pair to the carrier intent in the
    // same atomic store write. Conflict/AtCapacity returned before that attachment, so
    // an arm can never select or holder-confirm a pair that was not retained.
    Ok(())
}

/// Reject a request before policy acceptance when its coordinator JSON fits the
/// `/sign` cap but its base64 channel envelope would not fit `max_msg_bytes`.
/// This is a transport-shape error (HTTP 400 / malformed peer payload), not a
/// policy refusal, and it occurs before signing, registration, authorization, or
/// propagation acceptance state is written (coordinator freshness was already
/// consumed by the trust-root gate).
fn ensure_request_propagatable(
    node: &Node,
    request: &vault_proto::TaggedRequest,
) -> Result<(), BadRequest> {
    let Some(channel) = node.channel.as_ref() else {
        return Ok(());
    };
    if channel::request_fits_channel_body(request, channel.max_msg_bytes()) {
        return Ok(());
    }
    Err(BadRequest(format!(
        "request expands beyond the federation-uniform channel max_msg_bytes ({})",
        channel.max_msg_bytes()
    )))
}

/// The second §0 delivery precondition, checked BEFORE the pin: the carrier must
/// still be valid long enough for the asynchronous fan-out to reach every peer AND
/// for those peers to process it. `expiry ≥ now + delivery_horizon_secs`.
///
/// Without it, a hostile coordinator sets an expiry a second or two out: this node
/// accepts and stages the carrier, but every peer's freshness gate rejects it as
/// expired before the async pump lands — so no node reaches t-confirmation. Under
/// confirmation-gated arming that is already only censorship rather than a split,
/// but refusing here converts a silent, timing-dependent federation-wide failure
/// into an explicit, deterministic refusal the coordinator sees immediately.
///
/// Unlike its sibling precondition `max_msg_bytes`, `delivery_horizon_secs` is a
/// per-node config value and NOT a manifest preimage field. A heterogeneous SIZE cap
/// would break the §0 premise directly — "it fits me" would stop implying "it fits
/// every peer" — so that cap is manifest-bound. A heterogeneous horizon (or the same
/// horizon evaluated at slightly different clocks) can instead remove nodes before
/// they record an intent, so the admitting set can be a PROPER SUBSET of the honest
/// nodes that saw the carrier. Theft safety at that boundary does NOT come from
/// counting admitters — a receipt is authenticated as coming from a federation member,
/// never as evidence that the member admitted anything, so the tolerated `t−1`
/// compromised nodes can emit receipts without processing the carrier at all, and
/// "fewer than `t` admit ⟹ nobody arms" is FALSE. It comes from two facts about
/// SIGNERS:
///
/// * A node that signs has staged the carrier and fanned it out to every peer
///   ([`stage_spend_carrier`]), and so has every node that refused on its own clock —
///   this gate included, which is why its caller propagates before returning. So every
///   honest signer's receipt reaches every other honest node that saw the carrier.
/// * Therefore each honest signer counts at least the whole honest set that saw the
///   carrier. If that set has `t` members, every honest SIGNER in it reaches `t` and
///   freezes. An honest node that refused on its OWN clock does not freeze — it returns
///   above without recording an intent — but it never signed this request either, so the
///   only nodes able to release a partial for it are the `≤ t−1` compromised ones, below
///   quorum. If the set has fewer than `t` members, then `≥ t` honest nodes never saw the
///   carrier and never signed, so no `t` partials exist to combine in the first place.
///   Both branches bound partials for THIS request only. A commitment already pending
///   from an earlier normally-pinned submission keeps its partials at every unarmed node;
///   that is the accepted censorship residual (see [`ChannelState::confirm_carrier`]),
///   which no arrival-time precondition can close, not a hole this gate leaves open.
///
/// [`Node::from_toml_str`] requires `n = 2t - 1` so that removing every tolerated
/// `t-1` withholder still leaves `t` honest nodes for the first branch. What the
/// boundary CAN still produce is a proper subset of honest nodes arming — a node that
/// admitted, plus forged receipts, reaching `t` while its peers hold no intent. That
/// is fund-identical to nobody arming (the coordinator's already-accepted censorship),
/// costs the sweep its escape quorum, and lands on the two-track residual the design
/// accepts: Lockdown at `T` → funds frozen → recovery, never theft. Closing it outright
/// would need receipts to carry non-forgeable evidence of local admission — a second
/// agreement round that buys no fund safety over the argument above.
///
/// The margin must be provisioned to cover LOCAL ingress processing too, not just the
/// wire. This gate is evaluated before the pin, so everything between it and the outbox
/// write — both pin Argon2 evaluations, the serialized carrier derivation, PSBT decode,
/// user-signature verification, and signing — is spent inside the margin, and each peer
/// then spends its own share before its freshness check. A boundary-valid carrier can
/// therefore still reach peers expired. That is deliberately NOT re-checked before
/// staging: the check would sit AFTER the pin hook has already recorded this node's
/// intent, so its only possible action is to skip the fan-out — deterministically
/// dropping a duress signal that best-effort propagation might still have delivered in
/// time. It buys nothing in exchange, because a carrier that lands expired gathers no
/// genuine receipts, and the signer argument above holds regardless of how many nodes
/// admit it. The margin is a provisioning parameter; consuming it is an availability
/// question, and only refusing early can answer it.
///
/// Pin-independent by construction (it reads only `expiry` and the clock), and
/// evaluated before the pin, so it cannot become a duress oracle. Treated exactly like
/// its sibling `EXPIRY_TOO_SHORT` in the two ways a node-local clock verdict differs
/// from a verdict about the commitment: it is NOT recorded in the replay log (the same
/// request submitted earlier in its life must be re-evaluated), and its refusal still
/// fans the carrier out to every peer (see the caller — a clock refuser that withheld
/// its receipt would let a boundary-tuned expiry strand an honest signer below `t`).
///
/// Skipped in absent-channel mode, exactly like its sibling
/// [`ensure_request_propagatable`]: a node with no `[channel]` block has no peers to
/// fan out to and no confirmation path, so it can never arm and there is no
/// propagation window to protect. Refusing a short-expiry spend there would be a
/// pure availability loss with nothing on the other side of the trade.
fn ensure_delivery_horizon(node: &Node, expiry: u64, now: u64) -> Option<SignResponse> {
    // `None` from this function means "no refusal", so absent-channel mode short-
    // circuits to exactly that.
    node.channel.as_ref()?;
    let floor = now.saturating_add(node.delivery_horizon_secs);
    if expiry >= floor {
        return None;
    }
    Some(refusal(
        RefusalCode::ExpiryTooShort,
        "delivery_horizon",
        format!(
            "expiry {expiry} is before {floor} (now {now} + delivery_horizon_secs {}), so the \
             coordinator-signed carrier could expire before peer propagation completes",
            node.delivery_horizon_secs
        ),
    ))
}

/// Replay identity for an ACCEPTED candidate set. Each entry binds both the
/// exact unsigned commitment id and the complete ingress PSBT serialization,
/// including the user-signature instance and mandatory pair bytes. Length
/// prefixes keep the encoding unambiguous.
fn acceptance_replay_key(candidates: &[(&str, &Psbt)]) -> String {
    let mut bytes = b"vault-policy/accepted-request/v0".to_vec();
    for (commitment_id, psbt) in candidates {
        let commitment_id = commitment_id.as_bytes();
        bytes.extend_from_slice(&(commitment_id.len() as u64).to_le_bytes());
        bytes.extend_from_slice(commitment_id);
        let psbt = psbt.serialize();
        bytes.extend_from_slice(&(psbt.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&psbt);
    }
    format!("accepted:{}", sha256::Hash::hash(&bytes))
}

/// The `commitment_id` this node binds `psbt` to at `expiry` — the registry key
/// its candidate lives under. Test-only: production code derives it inside the
/// handler, from the same [`commitment_of`].
#[cfg(test)]
pub(crate) fn commitment_id_for(node: &Node, psbt: &Psbt, expiry: u64) -> String {
    commitment_of(node, psbt, expiry).commitment_id()
}

/// Build the [`Commitment`] for `psbt` under this node's wallet, at the
/// coordinator-proposed `expiry`. Every transaction-identifying field —
/// `version`, `lock_time`, each input's outpoint and `sequence`, and the
/// outputs — is read from the node's OWN unsigned tx, so the commitment binds
/// the exact transaction (ADR-0012): two txs differing in any of them get
/// distinct ids. The fee is `Σ input value − Σ output value`,
/// taking input values from each `witness_utxo` (v0 trusts the PSBT's prevout
/// data — regtest, honest coordinator; DESIGN.md, per-node chain backend).
/// It is computed saturating and never fails: an inconsistent PSBT (missing
/// `witness_utxo`, outputs exceeding inputs) still gets a stable commitment id
/// here and its refusal downstream — and any change to a prevout amount yields
/// a different fee, hence a different id.
fn commitment_of(node: &Node, psbt: &Psbt, expiry: u64) -> Commitment {
    let inputs = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| CommitmentInput {
            txid: txin.previous_output.txid.to_byte_array(),
            vout: txin.previous_output.vout,
            // Read this input's nSequence from the node's OWN copy of the
            // unsigned tx (ADR-0012) — never a coordinator-supplied summary.
            sequence: txin.sequence.to_consensus_u32(),
        })
        .collect();
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|txout| CommitmentOutput {
            script_pubkey: txout.script_pubkey.as_bytes().to_vec(),
            amount: txout.value.to_sat(),
        })
        .collect();
    let total_in = psbt
        .inputs
        .iter()
        .filter_map(|input| input.witness_utxo.as_ref())
        .fold(0u64, |acc, utxo| acc.saturating_add(utxo.value.to_sat()));
    let total_out = psbt
        .unsigned_tx
        .output
        .iter()
        .fold(0u64, |acc, txout| acc.saturating_add(txout.value.to_sat()));
    Commitment {
        wallet_id: node.wallet_id,
        // nVersion and nLockTime, read from the node's own unsigned tx so the
        // commitment binds the exact transaction (ADR-0012).
        version: psbt.unsigned_tx.version.0,
        lock_time: psbt.unsigned_tx.lock_time.to_consensus_u32(),
        inputs,
        outputs,
        fee: total_in.saturating_sub(total_out),
        expiry,
        policy_version: node.policy_version,
    }
}

/// The coordinator-auth + freshness gate (ADR-0013 §2/§3): the ingress check
/// EVERY request passes BEFORE the PIN. A request is rejected unless it is validly
/// coord-signed over its canonical bytes against the node's configured
/// `coordinator_auth_pubkey`, carries a nonce this node has not seen, and has an
/// expiry that is neither past nor beyond `now + max_commitment_age_secs`. `Err`
/// carries the wire refusal. There is no un-gated mode: the key is mandatory
/// config, so an unauthenticated caller never reaches the PIN, let alone a signer.
///
/// The `coord_sig` binds every field of the canonical [`vault_proto::CoordRequest`]
/// variant (spend/escape/pin or refresh, plus nonce, expiry, policy_version), so
/// tampering with any of them fails verification here; the nonce is single-use,
/// so a captured request cannot be replayed once recorded. `nonces` is taken under
/// the one `/sign` lock, making the seen-check and record atomic with the rest of
/// the handler.
///
/// Order matters: freshness state changes ONLY after the signature verifies, so a
/// caller without the coordinator key cannot advance its monotonic clock or grow
/// the bounded nonce log.
///
/// The nonce and expiry come from `request` itself ([`CoordRequest::nonce`] /
/// [`CoordRequest::expiry`]), never as parameters beside it: taking them
/// separately would let this gate check freshness on values other than the ones
/// `coord_sig` authenticated. `coord_sig` is a parameter because it is the one
/// field that is NOT part of its own preimage.
fn verify_coord_auth(
    node: &Node,
    request: CoordRequest<'_>,
    coord_sig: &str,
    now: u64,
    nonces: &mut NonceLog,
) -> Result<u64, SignResponse> {
    verify_coord_signature(node, request, coord_sig)?;
    // Sender authenticated. Validate the expiry window, reject replay, enforce
    // capacity, and consume the nonce in one operation under the sign-state lock.
    // Pruning and the matching high-water advance through the expiries actually
    // removed happen ONLY when the complete freshness gate accepts the request.
    // Window, replay, and capacity refusals leave both untouched, while the mark
    // prevents a backwards clock step from reopening a pruned nonce ([`NonceLog`]).
    match nonces.check_and_record(
        request.nonce(),
        request.expiry(),
        now,
        node.max_commitment_age_secs,
    ) {
        NonceDecision::Accepted => Ok(nonces.effective_now(now)),
        NonceDecision::InvalidLength => Err(refusal(
            RefusalCode::CoordAuthInvalid,
            "coord_nonce",
            format!("request nonce must be 1..={MAX_COORD_NONCE_BYTES} bytes"),
        )),
        NonceDecision::OutsideWindow { now } => Err(refusal(
            RefusalCode::CommitmentExpired,
            "commitment_expiry",
            format!(
                "expiry {} is outside the acceptance window (now {now}, max age {}s)",
                request.expiry(),
                node.max_commitment_age_secs
            ),
        )),
        NonceDecision::Replayed => Err(refusal(
            RefusalCode::NonceReplayed,
            "coord_nonce",
            "request nonce has already been seen by this node".into(),
        )),
        NonceDecision::AtCapacity => Err(refusal(
            RefusalCode::CoordNonceCapacity,
            "coord_nonce_capacity",
            "coordinator nonce cache is at capacity".into(),
        )),
    }
}

/// Verify only the coordinator signature, without consulting or mutating freshness
/// state. The `/channel` path uses this before deriving a spend's memory-hard carrier
/// id; the complete ingress gate remains [`verify_coord_auth`].
fn verify_coord_signature(
    node: &Node,
    request: CoordRequest<'_>,
    coord_sig: &str,
) -> Result<(), SignResponse> {
    // Authentication: coord_sig must ECDSA-verify over the canonical request bytes
    // against the configured coordinator_auth_pubkey. An absent, non-hex, or
    // non-DER signature is an authentication failure like any other.
    let digest = request.auth_digest(&node.wallet_id);
    let der = Vec::<u8>::from_hex(coord_sig).map_err(|_| {
        refusal(
            RefusalCode::CoordAuthInvalid,
            "coord_sig",
            "coord_sig is not hex".into(),
        )
    })?;
    let sig = Signature::from_der(&der).map_err(|_| {
        refusal(
            RefusalCode::CoordAuthInvalid,
            "coord_sig",
            "coord_sig is not a DER ECDSA signature".into(),
        )
    })?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(digest),
            &sig,
            &node.coordinator_auth.inner,
        )
        .map_err(|_| {
            refusal(
                RefusalCode::CoordAuthInvalid,
                "coord_sig",
                "coord_sig does not verify against the pinned coordinator_auth_pubkey".into(),
            )
        })
}

/// The V0-6 prevout ground-truth PREFLIGHT (deliverable 9y5.3-d), run in the
/// `/sign` path BEFORE policy-core. `policy-core` reads each input's PSBT
/// `witness_utxo` for ownership (scriptPubKey) and fee (value) and trusts it as-is —
/// its "No I/O, no clock, no chain access — same verdict every run" purity is
/// load-bearing and stays untouched. So a lying coordinator can inflate a
/// `witness_utxo` value to slip a fee-cap bypass, or forge its scriptPubKey, past
/// those pure checks. This is the vault-node side finally doing the prevout check
/// policy-core defers to V0-6.
///
/// For each input it fetches the real prevout from THIS node's own chain view and,
/// for a CONFIRMED prevout, requires the `witness_utxo` scriptPubKey AND value to
/// match the chain's ground truth; a mismatch is a fail-closed refusal — nothing is
/// signed, so no partial is released. It deliberately does NOT refuse when:
///
///  - the prevout is absent (`gettxout` null): the input may legitimately spend a
///    vault-AUTHORIZED-but-unconfirmed parent this node has not yet seen in its own
///    mempool — the exact case [`chain::assemble_package`] allows for spend-change
///    and refresh chaining. Absence is left to the fire-time package check, the
///    authoritative double-spend gate; refusing here would break that rule.
///  - the prevout is present but UNCONFIRMED: only a confirmed output is immutable
///    ground truth. An unconfirmed one is the authorized-parent case above.
///
/// A backend RPC error refuses fail-closed on the first failed batch: policy-core
/// must never evaluate attacker-supplied prevout data after chain ground truth became
/// unavailable. The batch RPC — the only slow step — is hoisted OUT of the sign lock
/// ([`prefetch_spend_escape_prevouts`], round-2 review) so a slow/hung bitcoind cannot
/// delay the deadline driver's unconditional Lockdown-at-T; only the pure comparison
/// ([`compare_prevouts_against_chain`]) runs under the lock. PIN-UNIFORM and
/// duress-safe: the check is a pure function of the PSBT + chain (never the pin), runs
/// identically for both pin classes, and its refusal sits AFTER the arm hook, so it
/// opens no duress observable and does not suppress a duress arm the coordinator's own
/// lie earned. The caller guards it behind `node.backend()`, so a backend-less
/// deterministic policy test simply never runs it.
///
/// A prevout preflight FETCH result: `Ok` holds one entry per PSBT input (in order),
/// `Err` a fail-closed refusal (backend RPC failure or a length mismatch). Produced
/// OUTSIDE the sign lock and consumed by the pure comparison under it, so the
/// under-lock check re-raises the `Err` verbatim rather than re-running the slow RPC.
type PrevoutFetch = Result<Vec<Option<Prevout>>, SignResponse>;

/// Fetch the chain's view of `psbt`'s input prevouts in ONE batch — the only
/// chain-I/O step of the prevout preflight (deliverable 9y5.3-d). The request-body
/// limit is already the protocol's input bound; adding a lower arbitrary input-count
/// refusal would reject valid consolidations and large refreshes. The pure comparison
/// is [`compare_prevouts_against_chain`].
fn fetch_prevouts(psbt: &Psbt, backend: &dyn ChainBackend) -> PrevoutFetch {
    let outpoints: Vec<OutPoint> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    let prevouts = backend.prevouts(&outpoints).map_err(|e| {
        refusal(
            RefusalCode::PsbtInconsistent,
            "prevout_ground_truth",
            format!(
                "cannot verify PSBT prevouts against this node's chain view; refusing \
                 fail-closed before policy evaluation: {e}"
            ),
        )
    })?;
    if prevouts.len() != outpoints.len() {
        return Err(refusal(
            RefusalCode::PsbtInconsistent,
            "prevout_ground_truth",
            format!(
                "chain backend returned {} prevout results for {} PSBT inputs",
                prevouts.len(),
                outpoints.len()
            ),
        ));
    }
    Ok(prevouts)
}

/// The pure scriptPubKey/value comparison of `psbt`'s inputs against pre-fetched
/// chain `prevouts`. No chain I/O — safe under the sign lock, AFTER the arm hook.
/// Refuses fail-closed on any input whose declared `witness_utxo` disagrees with the
/// prevout `gettxout` RETURNED (confirmed OR unconfirmed-in-mempool — both fix the
/// output at that outpoint); only an ABSENT (`None`) prevout stays the authorized-parent
/// case the fire-time package check backstops.
fn compare_prevouts_against_chain(
    psbt: &Psbt,
    prevouts: &[Option<Prevout>],
) -> Result<(), SignResponse> {
    if prevouts.len() != psbt.unsigned_tx.input.len() {
        // Defensive: the fetch was over these exact inputs, so this cannot happen
        // unless the PSBT changed between fetch and compare. Refuse fail-closed.
        return Err(refusal(
            RefusalCode::PsbtInconsistent,
            "prevout_ground_truth",
            format!(
                "pre-fetched {} prevouts for {} PSBT inputs",
                prevouts.len(),
                psbt.unsigned_tx.input.len()
            ),
        ));
    }
    for (index, (input, prevout)) in psbt.unsigned_tx.input.iter().zip(prevouts).enumerate() {
        let Some(prevout) = prevout else {
            // Null prevout: a legitimately-unconfirmed authorized parent not yet visible,
            // an unknown/already-spent output, or an RBF-replaced parent whose original
            // txid is gone. Allowed exactly as today — the fire-time package check is the
            // double-spend backstop.
            continue;
        };
        // NO `!prevout.confirmed` skip: if `gettxout(include_mempool)` RETURNED a prevout,
        // the output at this exact outpoint is fixed (an RBF replacement carries a different
        // txid and would have returned `None` above), so an unconfirmed mempool output is
        // just as verifiable as a confirmed one. A coerced user signs whatever `witness_utxo`
        // the coordinator supplies, so skipping the compare for unconfirmed-present prevouts
        // let a forged one reach policy + registration as an unusable candidate (codex P2).
        let Some(witness_utxo) = psbt.inputs.get(index).and_then(|i| i.witness_utxo.as_ref())
        else {
            // A missing witness_utxo is policy-core's own PSBT_INCONSISTENT refusal.
            continue;
        };
        if witness_utxo.script_pubkey != prevout.txout.script_pubkey
            || witness_utxo.value != prevout.txout.value
        {
            let outpoint = input.previous_output;
            return Err(refusal(
                RefusalCode::PsbtInconsistent,
                "prevout_ground_truth",
                format!(
                    "input {index} witness_utxo disagrees with the on-chain/mempool prevout \
                     {outpoint} that gettxout returned: declared scriptPubKey/value do not \
                     match the chain's ground truth (an attacker-supplied prevout the \
                     fee/ownership checks would trust)"
                ),
            ));
        }
    }
    Ok(())
}

/// The NODE-LOCAL half of the prevout preflight's two failure modes (bead f91 (C)):
/// the pre-fetched refusal iff the out-of-lock batch RPC itself failed, for the spend
/// or for its mandatory escape.
///
/// This is the whole node-local-vs-federation-uniform split, and it is deliberately
/// structural rather than a match on the refusal's code or `check` string — both
/// failure modes share `PSBT_INCONSISTENT`/`prevout_ground_truth`, so a text test would
/// silently reclassify one as the other the first time a message is edited:
///
///  - **`Err` here — NODE-LOCAL.** [`fetch_prevouts`] failed: this node's backend
///    errored, or returned the wrong number of results. A healthy peer asking the same
///    question gets an answer, so peers must still receive the carrier; the caller
///    forwards it.
///  - **A value MISMATCH — FEDERATION-UNIFORM.** That verdict is produced by
///    [`compare_prevouts_against_chain`], which runs only on `Ok`, comparing the PSBT's
///    declared `witness_utxo` against consensus data every honest node reads alike.
///    It must NOT propagate, and it cannot reach this function.
///
/// `None` for a PSBT that was never fetched (no backend, or it did not decode) is not a
/// failure: a backend-less deterministic test simply runs no preflight.
fn node_local_prevout_fetch_failure(
    spend_prevouts: &Option<PrevoutFetch>,
    escape_prevouts: &Option<PrevoutFetch>,
) -> Option<SignResponse> {
    if let Some(Err(refused)) = spend_prevouts {
        return Some(refused.clone());
    }
    if let Some(Err(escape_failure)) = escape_prevouts {
        // This early path runs before `verify_escape`, so add the same attribution that
        // function would have supplied around `run_prevout_check`.
        //
        // EXHAUSTIVE on purpose. The spend arm above forwards ANY `Err`, and this arm must
        // not be narrower: `fetch_prevouts` only ever constructs refusals today, so the
        // fallback is unreachable — but an `if let` matching only `Refusal` would SILENTLY
        // DROP the escape forward if a future variant appeared, which is precisely the
        // swallow this fetch-failure forwarding exists to prevent (Fable f91 review).
        // Forwarding it unattributed beats not forwarding it at all.
        return Some(match escape_failure {
            SignResponse::Refusal(refused) => refusal(
                refused.code,
                &format!("escape:{}", refused.check),
                refused.detail.clone(),
            ),
            other => other.clone(),
        });
    }
    None
}

/// Fetch + compare in one call — the standalone form kept for the unit tests that
/// exercise the whole preflight against a mock backend. The `/sign` and `/refresh`
/// handlers instead pre-fetch out of the lock and call [`compare_prevouts_against_chain`]
/// via [`run_prevout_check`], so production never takes this fused path.
#[cfg(test)]
fn verify_prevouts_against_chain(
    psbt: &Psbt,
    backend: &dyn ChainBackend,
) -> Result<(), SignResponse> {
    let prevouts = fetch_prevouts(psbt, backend)?;
    compare_prevouts_against_chain(psbt, &prevouts)
}

/// Run the prevout preflight for `psbt`: use the pre-fetched result when the handler
/// hoisted the batch RPC out of the lock (the normal path), else fetch it here as a
/// fallback for callers that did not pre-fetch. Either way the comparison is pure and
/// identical.
fn run_prevout_check(
    psbt: &Psbt,
    backend: &dyn ChainBackend,
    prefetched: Option<&PrevoutFetch>,
) -> Result<(), SignResponse> {
    let _ = backend; // retained for signature symmetry; the fallback no longer fetches.
    match prefetched {
        Some(Ok(prevouts)) => compare_prevouts_against_chain(psbt, prevouts),
        Some(Err(refused)) => Err(refused.clone()),
        None => {
            // The handlers ALWAYS pre-fetch the prevout batch OUT of the sign lock
            // (round-2 P0: never chain RPC under `sign_state`, or a hung bitcoind pins the
            // lock Lockdown-at-T needs). Reaching here means a caller with a live backend
            // forgot to pre-fetch. Rather than silently reinstate that under-lock fetch,
            // fail CLOSED — so the invariant is enforced structurally, not by convention
            // (Fable pass-4 P3). Loud in debug so a test catches the mis-wiring at once.
            debug_assert!(
                false,
                "run_prevout_check reached its no-prefetch fallback with a live backend; the \
                 handler must pre-fetch prevouts out of the lock (round-2 P0)"
            );
            Err(refusal(
                RefusalCode::PsbtInconsistent,
                "prevout_ground_truth",
                "internal: prevout preflight was not pre-fetched out of the sign lock; refusing \
                 rather than running chain I/O under the lock"
                    .into(),
            ))
        }
    }
}

/// Fetch the prevout ground truth for a `SpendRequest`'s spend + mandatory escape
/// OUTSIDE the sign lock (round-2 review, deliverable 9y5.3-d). The batch `gettxout`
/// RPC is the ONLY slow step of the preflight. The handler calls this only after
/// coordinator signature/freshness, PIN evaluation, and the safety-intent hook, then
/// with `sign_state` released. A slow or hung bitcoind therefore cannot delay either
/// the intent or the deadline driver's unconditional Lockdown-at-T (which acquires
/// that lock). The pure comparison runs after the lock is re-acquired.
///
/// Returns `(spend, escape)` fetch results, each `None` when there is no backend or
/// that PSBT does not decode. A decode failure becomes HTTP 400 before validation;
/// the `None` fallback is otherwise only for backend-less deterministic tests.
fn prefetch_spend_escape_prevouts(
    node: &Node,
    request: &SignRequest,
) -> (Option<PrevoutFetch>, Option<PrevoutFetch>) {
    let Some(backend) = node.backend() else {
        return (None, None);
    };
    let spend = decode_psbt(&request.psbt, "spend")
        .ok()
        .map(|psbt| fetch_prevouts(&psbt, backend.as_ref()));
    let escape = decode_psbt(&request.escape_psbt, "escape")
        .ok()
        .map(|psbt| fetch_prevouts(&psbt, backend.as_ref()));
    (spend, escape)
}

/// The refresh analogue of [`prefetch_spend_escape_prevouts`]: pre-fetch the single
/// refresh PSBT's prevouts out of the sign lock. The caller has already consumed
/// coordinator freshness before entering this helper.
fn prefetch_refresh_prevouts(node: &Node, request: &RefreshRequest) -> Option<PrevoutFetch> {
    let backend = node.backend()?;
    decode_psbt(&request.refresh_psbt, "refresh")
        .ok()
        .map(|psbt| fetch_prevouts(&psbt, backend.as_ref()))
}

/// The V0-1 validation: verify the user's signatures, verify each input's prevout
/// against the chain (V0-6), then run policy-core. Does NOT sign — signing is
/// deferred (handler step 8) so a hot-class spend can be held first (ADR-0004).
/// `Err` carries the wire refusal to return.
fn verify_spend(
    node: &Node,
    psbt: &Psbt,
    prefetched: Option<&PrevoutFetch>,
) -> Result<(), SignResponse> {
    // The user's partial signature must cryptographically verify on every
    // input against the node's own recomputed sighash — presence of a
    // partial_sig is never enough (DESIGN.md, "Sighash enforcement"). This
    // subsumes the "no output mutation after authorization" check: any
    // mutation after signing changes the sighash and invalidates the very
    // signature the node verifies.
    verify_user_signatures(node, psbt)?;
    // V0-6 prevout ground truth, BEFORE policy-core — so the pure ownership/fee
    // checks below never trust an attacker-supplied `witness_utxo` for a confirmed
    // input. The batch RPC was hoisted out of the sign lock (`prefetched`); the pure
    // comparison runs here. Guarded by `node.backend()`: a backend-less deterministic
    // policy test skips it. Not recorded in the replay log: `PSBT_INCONSISTENT` is
    // excluded by [`is_recordable_verdict`], so a coordinator that corrects the
    // prevout on a resubmission is re-evaluated, not answered from a stale refusal
    // keyed by the unchanged commitment.
    if let Some(backend) = node.backend() {
        run_prevout_check(psbt, backend.as_ref(), prefetched)?;
    }
    // The policy-core checks: input ownership, destination allowlist +
    // verified change, and the fee cap — all descriptor-derived. `evaluate`
    // also keeps its own consistency precondition for direct policy-core
    // callers.
    if let Err(v) = policy_core::evaluate(psbt, &node.check_params) {
        return Err(refusal(map_policy_code(v.code), v.check, v.detail));
    }
    Ok(())
}

/// Record `verdict` under its already-derived replay `key`, but only when that
/// identity fully determines it (see [`is_recordable_verdict`]). Takes the
/// already-locked replay log (the handler holds the one `SignState` lock across
/// its whole run), so recording stays inside the same critical section as the
/// idempotency check above it.
fn record_verdict(replay: &mut ReplayLog, key: &str, expiry: u64, verdict: &SignResponse) {
    if is_recordable_verdict(verdict) {
        replay.record(key.to_string(), expiry, verdict.clone());
    }
}

/// Validate the request's mandatory escape (§4). The node **validates** it; it
/// never **builds** it — that is what dissolves the cross-node byte-identical
/// construction problem, since all `n` nodes must add partials over the *identical*
/// bytes for them to combine at all.
///
/// Three checks, all against the bytes as provided:
///
///  - the user's signature verifies over the exact bytes (so the coordinator
///    cannot alter a coin, fee, or output afterward — [`verify_user_signatures`]);
///  - every input is a vault UTXO and the fee is capped (policy-core);
///  - every destination output pays the escape descriptor — i.e. it is genuinely
///    escape-class, not a hot spend wearing the escape's name.
///
/// The fire-time sweep-admissibility checks (value coverage, the feerate floor,
/// package acceptance) are deliberately NOT here: ADR-0012 makes them fire-time
/// checks on the sweep track, never gates at ingress, and the sweep itself is
/// V0-4b.
fn verify_escape(
    node: &Node,
    psbt: &Psbt,
    prefetched: Option<&PrevoutFetch>,
) -> Result<(), SignResponse> {
    let escape_refusal = |code, check: &str, detail| {
        // Name the escape explicitly: a refusal an operator cannot attribute to
        // one of the request's two transactions is a refusal they cannot act on.
        refusal(code, &format!("escape:{check}"), detail)
    };
    if let Err(SignResponse::Refusal(r)) = verify_user_signatures(node, psbt) {
        return Err(escape_refusal(r.code, &r.check, r.detail));
    }
    // V0-6 prevout ground truth for the escape's inputs too, before policy-core. The
    // batch RPC was hoisted out of the sign lock; only the pure comparison runs here.
    if let Some(backend) = node.backend() {
        if let Err(SignResponse::Refusal(r)) = run_prevout_check(psbt, backend.as_ref(), prefetched)
        {
            return Err(escape_refusal(r.code, &r.check, r.detail));
        }
    }
    if let Err(v) = policy_core::evaluate(psbt, &node.check_params) {
        return Err(escape_refusal(map_policy_code(v.code), v.check, v.detail));
    }
    match policy_core::classify(psbt, &node.check_params).map(|c| c.class) {
        Ok(policy_core::TxClass::Escape) => Ok(()),
        Ok(other) => Err(escape_refusal(
            RefusalCode::PsbtInconsistent,
            "transaction_class",
            format!(
                "the request's escape is {other:?}-class: every destination output must pay \
                 the escape descriptor"
            ),
        )),
        Err(v) => Err(escape_refusal(map_policy_code(v.code), v.check, v.detail)),
    }
}

/// The maximum number of pre-signed fee-bump rungs one request may authorize
/// (bead btc-policy-9y5.7). Three bumps span roughly two orders of magnitude of
/// feerate at 4× steps, which is more than a real spike moves inside one
/// commitment's life. It is also what makes "bounded number of bumps" structural
/// rather than a policy: the latch is monotone, so the sweep can be bumped at most
/// this many times, ever.
///
/// Taken from `vault-proto`, not restated: the coordinator composes the ladder this
/// bound refuses, so a second copy of the number would be a comment-enforced
/// contract between two crates that already share a wire-types crate.
const MAX_ESCAPE_BUMPS: usize = vault_proto::MAX_ESCAPE_BUMPS;

/// The `nSequence` every input of a LADDERED escape must carry
/// ([`vault_proto::ESCAPE_RBF_SEQUENCE`], the same shared definition).
///
/// `0xfffffffd` is below `0xfffffffe`, so the transaction opts in to BIP125
/// replacement — which is the whole point: a bump is a mempool replacement of a
/// lower rung, and a replacement of a non-signalling parent is simply not relayed
/// by the network, so the escalation would die at the first peer that still held
/// the earlier rung. Bit 31 (`0x80000000`) is still SET, so BIP68 relative
/// timelocks stay disabled exactly as they are under `0xffffffff`, and the ladder
/// keeps the "no relative lock can delay the sweep" half of broadcastable-at-T.
/// The other half — finality — no longer comes free from `nSequence`, so
/// [`ensure_escape_ladder`] requires `nLockTime == 0` alongside it.
const ESCAPE_RBF_SEQUENCE: u32 = vault_proto::ESCAPE_RBF_SEQUENCE;

/// The maximum Bitcoin Core incremental relay fee this build permits, in sat/vB.
///
/// BIP125 replacement requires the absolute fee increase to pay for relaying the
/// replacement at this rate. Production startup verifies Core's live
/// `incrementalfee` does not exceed the shared bound, so a ladder accepted here is
/// relayable by the configured backend rather than only by a default Core node.
const ESCAPE_RBF_INCREMENTAL_RELAY_SAT_VB: u64 =
    chain::MAX_SUPPORTED_INCREMENTAL_RELAY_SAT_KVB / 1_000;

/// The `nSequence` an escape's inputs must carry, given whether it has a ladder.
/// One function so the ingress rule and the fire-time re-check cannot drift.
fn expected_escape_sequence(laddered: bool) -> bitcoin::Sequence {
    if laddered {
        bitcoin::Sequence::from_consensus(ESCAPE_RBF_SEQUENCE)
    } else {
        bitcoin::Sequence::MAX
    }
}

/// Σ `witness_utxo` value − Σ output value, saturating. `None` when an input has
/// no `witness_utxo` — which `verify_escape` has already refused before any caller
/// here reaches it.
fn psbt_fee(psbt: &Psbt) -> Option<u64> {
    let total_in = psbt.inputs.iter().try_fold(0u64, |total, input| {
        Some(total.saturating_add(input.witness_utxo.as_ref()?.value.to_sat()))
    })?;
    let total_out = psbt.unsigned_tx.output.iter().fold(0u64, |total, output| {
        total.saturating_add(output.value.to_sat())
    });
    Some(total_in.saturating_sub(total_out))
}

/// **The escape fee-bump ladder's structural contract** (bead btc-policy-9y5.7),
/// checked at ingress against the bytes as provided, identically under both PINs.
///
/// Each rung has already passed [`verify_escape`] — user-signed over its exact
/// bytes, vault inputs, escape-class outputs, fee under the policy cap. What is
/// left is the ladder's own shape, and every clause of it is load-bearing:
///
///  - **Same inputs, same order.** A rung is a REPLACEMENT of the escape, and two
///    transactions only conflict — hence only replace — when they spend the same
///    coins. It also means the rungs share one prevout ground truth and one swept
///    value, so `Σ in` drops out of the comparison below and the ladder cannot
///    smuggle in a coin the escape never swept.
///  - **Same outputs, same scripts, same order.** The bump changes the FEE and
///    nothing else. This is what makes "a bump must not change WHAT is swept" a
///    checked property rather than a convention, and it also pins the serialized
///    size, so a strictly higher fee is necessarily a strictly higher FEERATE
///    (BIP125 rule 4, not just rule 3).
///  - **A relay-sized fee increase.** Ascending order is what lets the fire-time
///    selector treat the ladder as monotone in both feerate and coverage. Each step
///    also pays at least the replacement's maximum finalized vsize times Core's
///    default incremental relay rate, so a one-satoshi increase cannot pass ingress
///    only to fail BIP125 replacement policy.
///  - **RBF-signalling with `nLockTime == 0`,** for the whole ladder including the
///    base — see [`ESCAPE_RBF_SEQUENCE`]. A ladder whose base cannot be replaced
///    could never escalate past its first broadcast.
///  - **Not on a self-paired request.** An escape-class spend IS its own escape and
///    completes immediately at ingress; there is no delayed sweep to bump, and the
///    collapsed single candidate has no escape role to hang a ladder on.
///
/// A ladder-less request is untouched: the escape keeps `Sequence::MAX`, which is
/// non-signalling and final, exactly as before this bead.
fn ensure_escape_ladder(
    node: &Node,
    escape: &Psbt,
    bumps: &[Psbt],
    self_paired: bool,
) -> Result<(), SignResponse> {
    let bad = |detail: String| {
        Err(refusal(
            RefusalCode::PsbtInconsistent,
            "escape:bump_ladder",
            detail,
        ))
    };
    if bumps.is_empty() {
        return Ok(());
    }
    if self_paired {
        return bad(
            "an escape-class spend is its own escape and completes at ingress, so it has no \
             delayed sweep to fee-bump"
                .into(),
        );
    }
    let base_version = escape.unsigned_tx.version;
    let expected_sequence = expected_escape_sequence(true);
    for (rung, psbt) in std::iter::once(escape).chain(bumps).enumerate() {
        if psbt.unsigned_tx.version != base_version {
            return bad(format!(
                "escape ladder rung {rung} has transaction version {}, but every rung must keep \
                 the base escape's version {}: a fee bump may change only output values",
                psbt.unsigned_tx.version.0, base_version.0
            ));
        }
        if psbt.unsigned_tx.lock_time != bitcoin::absolute::LockTime::ZERO {
            return bad(format!(
                "escape ladder rung {rung} has nLockTime {}, but a replaceable escape must be \
                 final at T (nLockTime 0): with RBF-signalling nSequence, nSequence no longer \
                 makes it final",
                psbt.unsigned_tx.lock_time
            ));
        }
        for (index, input) in psbt.unsigned_tx.input.iter().enumerate() {
            if input.sequence != expected_sequence {
                return bad(format!(
                    "escape ladder rung {rung} input {index} nSequence {:#010x} is not \
                     {ESCAPE_RBF_SEQUENCE:#010x}: every rung of a ladder must signal BIP125 \
                     replacement, or a bump cannot replace the rung below it",
                    input.sequence.to_consensus_u32()
                ));
            }
        }
    }
    let base_inputs: Vec<bitcoin::OutPoint> = escape
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    let base_scripts: Vec<&bitcoin::ScriptBuf> = escape
        .unsigned_tx
        .output
        .iter()
        .map(|output| &output.script_pubkey)
        .collect();
    let mut previous_fee = psbt_fee(escape).ok_or_else(|| {
        refusal(
            RefusalCode::PsbtInconsistent,
            "escape:bump_ladder",
            "the escape has an input without a witness_utxo, so its fee is unknown".into(),
        )
    })?;
    // Per-output values of the rung below (the base to start): a bump may only LOWER
    // an output to pay its higher fee, never RAISE one. Without this, a rung could move
    // value from vault-change into the escape output (same scripts, higher fee) so its
    // escape coverage RISES above a lower rung's — breaking the assumption that the
    // coverage-admissible set is downward-closed. The prefix release
    // (`release_partials` sends `[floor ..= latch]`) would then hand a t-1 compromised
    // set this node's honest share for an INTERMEDIATE rung that fails the ≥95% coverage
    // guard, which they could combine and broadcast (codex 9y5.7 pass-2). Monotone
    // non-increasing per-output values keep every rung's escape value ≤ the one below
    // it, so coverage is monotone and the admissible prefix carries no failing rung.
    let mut previous_values: Vec<u64> = escape
        .unsigned_tx
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .collect();
    for (index, bump) in bumps.iter().enumerate() {
        let rung = index + 1;
        let inputs: Vec<bitcoin::OutPoint> = bump
            .unsigned_tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect();
        if inputs != base_inputs {
            return bad(format!(
                "escape ladder rung {rung} spends a different input set than the escape, so it \
                 could never replace it"
            ));
        }
        let scripts: Vec<&bitcoin::ScriptBuf> = bump
            .unsigned_tx
            .output
            .iter()
            .map(|output| &output.script_pubkey)
            .collect();
        if scripts != base_scripts {
            return bad(format!(
                "escape ladder rung {rung} pays a different set of output scripts than the \
                 escape: a fee bump may change the fee, never what is swept"
            ));
        }
        let values: Vec<u64> = bump
            .unsigned_tx
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .collect();
        if values
            .iter()
            .zip(&previous_values)
            .any(|(value, previous)| value > previous)
        {
            return bad(format!(
                "escape ladder rung {rung} raises an output value above the rung below it: a bump \
                 may only lower an output to pay a higher fee, never move value between outputs — \
                 otherwise an intermediate rung's escape coverage could dip below the lower rungs' \
                 and the prefix release would hand a t-1 set a share for an under-coverage escape"
            ));
        }
        previous_values = values;
        let fee = psbt_fee(bump).ok_or_else(|| {
            refusal(
                RefusalCode::PsbtInconsistent,
                "escape:bump_ladder",
                format!("escape ladder rung {rung} has an input without a witness_utxo"),
            )
        })?;
        let replacement_vsize =
            maximum_finalized_vsize(node, &bump.unsigned_tx).map_err(|detail| {
                refusal(
                    RefusalCode::PsbtInconsistent,
                    "escape:bump_ladder",
                    format!("cannot bound escape ladder rung {rung}'s finalized size: {detail}"),
                )
            })?;
        let minimum_delta = replacement_vsize.saturating_mul(ESCAPE_RBF_INCREMENTAL_RELAY_SAT_VB);
        let Some(delta) = fee.checked_sub(previous_fee) else {
            return bad(format!(
                "escape ladder rung {rung} pays {fee} sat, not more than the {previous_fee} sat \
                 of the rung below it: a replacement must pay a strictly higher fee (BIP125 \
                 rule 3) and the ladder must ascend"
            ));
        };
        if delta < minimum_delta {
            return bad(format!(
                "escape ladder rung {rung} raises the fee by only {delta} sat, below the \
                 {minimum_delta} sat needed to relay its at-most-{replacement_vsize}-vB \
                 replacement at {ESCAPE_RBF_INCREMENTAL_RELAY_SAT_VB} sat/vB"
            ));
        }
        previous_fee = fee;
    }
    Ok(())
}

/// Whether `verdict` may be recorded in the anti-replay log for idempotent
/// replay. Refusals are keyed by `commitment_id`, which binds only the logical
/// spend (wallet, version, lock time, outpoints + sequences, outputs, fee,
/// expiry, policy_version) — never witness data. Accepted decisions are keyed by
/// [`acceptance_replay_key`], which additionally binds every candidate's complete
/// ingress PSBT. Only verdicts their chosen key fully determines are safe:
///
/// - `Accepted` — this node validated, signed, and registered this exact candidate
///   set, including its user-signature instance and mandatory escape. Replaying
///   the acknowledgement is the idempotency job, and it makes a coordinator retry
///   safe without letting a conflicting pair borrow the earlier acceptance.
/// - `DEST_NOT_ALLOWED` / `CHANGE_NOT_DERIVABLE` / `FEE_EXCEEDS_CAP` /
///   `PSBT_INCONSISTENT` from the class predicate — the policy refusals that turn
///   solely on the outputs and fee the commitment binds. Because the outputs are
///   commitment-bound, the same commitment can NEVER become an acceptance, so
///   caching the refusal cannot block an honest spend. (An untrusted bip32 change
///   label only decides `DEST_NOT_ALLOWED` vs `CHANGE_NOT_DERIVABLE`; both are
///   refusals, so replaying either stays safe.)
///
/// Refusals that depend on data the commitment does NOT bind — the signature
/// (`USER_SIG_INVALID`, `BAD_SIGHASH`), the PSBT structure, or the untrusted
/// `witness_utxo` prevout script (`UNKNOWN_INPUT`) — are NOT recorded: an
/// identical commitment resubmitted with corrected witness data could legitimately
/// be accepted, so caching would otherwise replay a stale refusal and block an
/// honest spend. The log does not defend the signature — V0-1's sighash binding
/// does (DESIGN.md, "What the anti-replay log is — and is not").
///
/// `EXPIRY_TOO_SHORT` and `REFRESH_*` are likewise unrecorded: each turns on the
/// node's CLOCK or on state outside the commitment (a pending spend, a coin's last
/// refresh), so the same commitment can legitimately earn a different verdict
/// later. Caching them would make a transient "not yet" permanent.
///
/// `PSBT_INCONSISTENT` is not recordable in general (it can come from witness
/// data), so the class refusals ride the general rule and are simply re-derived on
/// resubmission — cheap, and always right.
///
/// **`HOT_BUDGET_EXCEEDED` is a deliberate EXCLUSION, and the reason is not the one
/// the rule above would give.** Read literally it qualifies: the per-transaction Hot
/// budget (ADR-0014 §1) turns solely on the outputs the commitment binds, exactly
/// like `DEST_NOT_ALLOWED`, and caching it could never block a spend that might
/// later be accepted. It is excluded anyway because it is the ONE refusal reaching
/// here that also stages the duress carrier (see the `verify_spend` refusal branch
/// in [`handle_sign_after_lock`]; the same code raised on the request's paired
/// escape carries an `escape:` check prefix, stages nothing, and never reaches this
/// predicate at all). A commitment-keyed replay hit returns BEFORE that
/// staging branch, so a recorded per-tx verdict would let one submission poison this
/// node's cache and then silently suppress a later duress carrier for the same
/// commitment — the coercer's second, duress-pinned submission would be answered from
/// cache, never staged, never counted toward t-of-n confirmation, and the freeze
/// would not fire. Capping the loss must not buy that. Re-deriving the verdict is
/// deterministic and cheap, so the exclusion costs nothing.
///
/// Adding `RefusalCode::HotBudgetExceeded` to the match below therefore breaks an
/// ADR-0014 composition guarantee, not merely an optimisation.
/// `resubmitting_an_over_cap_commitment_still_stages_the_duress_carrier` is the
/// regression. `HOT_VELOCITY_EXCEEDED` is excluded for the ordinary reason instead —
/// it turns on this node's rolling window, which the commitment does not bind.
fn is_recordable_verdict(verdict: &SignResponse) -> bool {
    match verdict {
        SignResponse::Accepted(_) => true,
        SignResponse::Refusal(refusal) => matches!(
            refusal.code,
            RefusalCode::DestNotAllowed
                | RefusalCode::ChangeNotDerivable
                | RefusalCode::FeeExceedsCap
        ),
    }
}

fn decode_psbt(base64: &str, field: &str) -> Result<Psbt, BadRequest> {
    Psbt::from_str(base64.trim()).map_err(|e| BadRequest(format!("cannot decode {field}: {e}")))
}

fn refusal(code: RefusalCode, check: &str, detail: String) -> SignResponse {
    SignResponse::Refusal(Refusal {
        code,
        check: check.into(),
        detail,
    })
}

fn hot_velocity_refusal(
    node: &Node,
    outflow_sat: u64,
    refused: channel::HotReserveRefusal,
) -> SignResponse {
    let detail = match refused {
        channel::HotReserveRefusal::Window(window_sum) => format!(
            "hot outflow {outflow_sat} sat would put this node's {}-second rolling hot outflow \
             at {} sat, past the Hot budget of {} sat",
            node.hot_budget.window_secs,
            window_sum.saturating_add(outflow_sat),
            node.hot_budget.max_per_window_sat,
        ),
        channel::HotReserveRefusal::Capacity => format!(
            "this node's hot-budget ledger is at capacity for the current {}-second window; \
             no further hot spend is metered until reservations age out",
            node.hot_budget.window_secs,
        ),
    };
    refusal(
        RefusalCode::HotVelocityExceeded,
        "hot_budget_velocity",
        detail,
    )
}

/// The terminal-Lockdown refusal (ADR-0008): every post-lockdown spend/refresh
/// presents as automated fraud prevention, never as "duress PIN used" — the story
/// is "the system locked itself; nobody can override it."
fn fraud_suspected() -> SignResponse {
    refusal(
        RefusalCode::FraudSuspected,
        "lockdown",
        "funds quarantined by policy".into(),
    )
}

/// The pin/lockout refusal. Uniform within each state so it leaks nothing about
/// which pin was submitted: while locked out, a correct pin (normal OR duress) gets
/// the IDENTICAL refusal a wrong pin would, so an attacker who floods a node into
/// lockout cannot then read the victim's pin off the response. Lockout is a
/// transient rate-limit, NOT Lockdown, so it stays a `BAD_PIN` denial that clears
/// after `lockout_secs`.
fn pin_refusal(locked: bool) -> SignResponse {
    if locked {
        refusal(
            RefusalCode::BadPin,
            "pin_attempt_budget",
            "pin attempts are rate-limited; this node is temporarily locked out".into(),
        )
    } else {
        refusal(
            RefusalCode::BadPin,
            "pin",
            "submitted PIN does not match an enrolled PIN".into(),
        )
    }
}

fn map_policy_code(code: policy_core::ViolationCode) -> RefusalCode {
    match code {
        policy_core::ViolationCode::UnknownInput => RefusalCode::UnknownInput,
        policy_core::ViolationCode::DestNotAllowed => RefusalCode::DestNotAllowed,
        policy_core::ViolationCode::ChangeNotDerivable => RefusalCode::ChangeNotDerivable,
        policy_core::ViolationCode::FeeExceedsCap => RefusalCode::FeeExceedsCap,
        policy_core::ViolationCode::PsbtInconsistent => RefusalCode::PsbtInconsistent,
        policy_core::ViolationCode::HotBudgetExceeded => RefusalCode::HotBudgetExceeded,
    }
}

/// Cryptographically verify the user's partial signature on every input
/// before the node contributes its own (DESIGN.md, Policy model →
/// "Sighash enforcement"). For each input the node recomputes the P2WSH
/// sighash from its own full `and_v(v:pk(USER),multi(...))` witness script,
/// the `witness_utxo` amount, and sighash type ALL, then:
///
/// - requires a `partial_sig` under the configured user key
///   (absent → `USER_SIG_INVALID`);
/// - requires that signature to commit to SIGHASH_ALL — P2WSH has no
///   SIGHASH_DEFAULT (anything else → `BAD_SIGHASH`);
/// - ECDSA-verifies it against the recomputed sighash and the user pubkey
///   (invalid → `USER_SIG_INVALID`).
///
/// A stale, garbage, or wrong-key signature — and any output mutated after
/// the user signed — all fail here. `Err` carries the wire refusal to return.
fn verify_user_signatures(node: &Node, psbt: &Psbt) -> Result<(), SignResponse> {
    let secp = Secp256k1::verification_only();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, input) in psbt.inputs.iter().enumerate() {
        // Amount comes from witness_utxo; without it no sighash exists to
        // verify against — a decodable-but-inconsistent PSBT.
        let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
            refusal(
                RefusalCode::PsbtInconsistent,
                "user_signature",
                format!("input {index} has no witness_utxo; sighash cannot be computed"),
            )
        })?;
        let sighash = cache
            .p2wsh_signature_hash(
                index,
                &node.witness_script,
                utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| {
                refusal(
                    RefusalCode::PsbtInconsistent,
                    "user_signature",
                    format!("cannot compute sighash for input {index}: {e}"),
                )
            })?;
        let Some(sig) = input.partial_sigs.get(&node.user_pubkey) else {
            return Err(refusal(
                RefusalCode::UserSigInvalid,
                "user_signature",
                format!("input {index} carries no partial signature for the user key"),
            ));
        };
        if sig.sighash_type != EcdsaSighashType::All {
            return Err(refusal(
                RefusalCode::BadSighash,
                "user_signature",
                format!(
                    "input {index} user signature commits to {:?}, not SIGHASH_ALL",
                    sig.sighash_type
                ),
            ));
        }
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &sig.signature,
            &node.user_pubkey.inner,
        )
        .map_err(|_| {
            refusal(
                RefusalCode::UserSigInvalid,
                "user_signature",
                format!(
                    "input {index} user signature does not verify against the recomputed sighash"
                ),
            )
        })?;
    }
    Ok(())
}

/// Add this node's partial signature to every input, signing the node's own
/// recomputed p2wsh sighash (SIGHASH_ALL) with its own witness script.
fn add_node_signatures(node: &Node, psbt: &mut Psbt) -> Result<(), String> {
    let secp = Secp256k1::signing_only();
    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {index} has no witness_utxo"))?;
        let sighash = cache
            .p2wsh_signature_hash(
                index,
                &node.witness_script,
                utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| format!("sighash for input {index}: {e}"))?;
        let signature =
            secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &node.seckey);
        input.partial_sigs.insert(
            node.pubkey,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod watchtower_wiring {
    //! Node-level wiring for ADR-0012's watchtower recognition rule: the node
    //! recognizes a vault spend iff it VALIDATED AND POLICY-ACCEPTED it, and
    //! alerts otherwise. Classification and cursor edge cases live in
    //! `watchtower`'s own tests; this proves the `Node` glue.

    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Psbt, Txid};
    use std::str::FromStr;

    use crate::chain::{mock::MockBackend, SpendSeen};
    use crate::watchtower::AlertKind;
    use crate::Node;
    use vault_proto::{SignResponse, TaggedRequest};

    /// The shared fixture vault, having ACCEPTED one honest hot spend, plus that
    /// spend's txid. Acceptance — not signing — is what puts the txid in the
    /// node's authorized set, which is what the watchtower recognizes against.
    fn accepted_node() -> (Node, Txid) {
        let (node, request) = crate::test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture psbt");
        // The fixture's expiry is set against the real clock, so this reads the
        // real clock too (`handle_sign_now`) rather than a fixed `NOW`.
        let SignResponse::Accepted(_) = crate::handle_sign_now(&node, &request).expect("decodable")
        else {
            panic!("the honest hot spend must be accepted");
        };
        (node, psbt.unsigned_tx.compute_txid())
    }

    fn vault_spend(node: &Node, spend_txid: Txid) -> SpendSeen {
        vault_spend_witness(node, spend_txid, normal_branch_witness())
    }

    /// A spend of the vault script carrying `witness` — the watchtower reads it to
    /// tell the recovery branch from the normal branch.
    fn vault_spend_witness(node: &Node, spend_txid: Txid, witness: bitcoin::Witness) -> SpendSeen {
        SpendSeen {
            spend_txid,
            outpoint: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            script: node.vault_scripts()[0].clone(),
            witness,
        }
    }

    /// A normal-branch (`or_i` IF) witness: a non-empty `01` selector before the
    /// witness script.
    fn normal_branch_witness() -> bitcoin::Witness {
        bitcoin::Witness::from_slice(&[vec![0x30u8; 71], vec![0x01u8], vec![0xABu8; 32]])
    }

    /// A recovery-branch (`or_i` ELSE) witness: an EMPTY selector before the
    /// witness script — the on-chain signal the watchtower alerts on.
    fn recovery_branch_witness() -> bitcoin::Witness {
        bitcoin::Witness::from_slice(&[vec![0x30u8; 71], Vec::new(), vec![0xABu8; 32]])
    }

    #[test]
    fn an_accepted_spend_is_recognized_and_an_unknown_one_alerts_through_events() {
        let (node, accepted) = accepted_node();

        // The accepted spend on chain is recognized: nothing queued.
        let known = MockBackend {
            spends: vec![vault_spend(&node, accepted)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&known, 0).expect("scan"), 0);
        assert!(node.events(0).0.is_empty());

        // A vault spend the node never accepted is an UnrecognizedSpend.
        let foreign = Txid::from_byte_array([0xAB; 32]);
        let unknown = MockBackend {
            spends: vec![vault_spend(&node, foreign)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&unknown, 0).expect("scan"), 1);
        let (alerts, cursor) = node.events(0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].watchtower().kind, AlertKind::UnrecognizedSpend);
        assert_eq!(alerts[0].watchtower().spend_txid, foreign.to_string());
        assert_eq!(cursor, 1);
    }

    #[test]
    fn a_recovery_branch_spend_surfaces_a_recovery_path_alert_through_events() {
        // The V0-10 exit, end to end through the node's own watchtower pass: a
        // spend of the vault script that took the recovery (or_i ELSE) branch is a
        // RecoveryPathSpend — even though the node never validated-and-accepted it
        // (recovery uses recovery keys, not node keys), and even though it pays
        // from the SAME scriptPubKey a normal spend does. The witness is the signal.
        let (node, _accepted) = accepted_node();
        let recovery_txid = Txid::from_byte_array([0xEC; 32]);
        let backend = MockBackend {
            spends: vec![vault_spend_witness(
                &node,
                recovery_txid,
                recovery_branch_witness(),
            )],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&backend, 0).expect("scan"), 1);
        let (alerts, _) = node.events(0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].watchtower().kind,
            AlertKind::RecoveryPathSpend,
            "a recovery-branch spend must alert RECOVERY_PATH_SPEND, never UNRECOGNIZED_SPEND"
        );
        assert_eq!(alerts[0].watchtower().spend_txid, recovery_txid.to_string());
    }

    /// **The B5 recognition fix.** A spend this node policy-REFUSED must NOT count
    /// as recognized.
    ///
    /// This is the attack it closes: a thief fans their theft out to the honest
    /// nodes on purpose. Under a "recognized because I evaluated it" rule, every
    /// honest node would mark it recognized and stay silent — the theft would
    /// suppress its own alert, using the watchtower's own fan-out to do it. Under
    /// "recognized because I ACCEPTED it", the refusal keeps it out of the
    /// authorized set and every honest node alerts.
    #[test]
    fn a_spend_this_node_policy_refused_is_not_recognized_and_still_alerts() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let theft = crate::test_support::theft_request(&node, &request);
        let theft_txid = Psbt::from_str(&theft.psbt)
            .expect("theft psbt")
            .unsigned_tx
            .compute_txid();

        // The node evaluates it in full and REFUSES it on the allowlist.
        let refusal = match crate::handle_sign_now(&node, &theft).expect("decodable") {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("the theft must be refused, got {other:?}"),
        };
        assert_eq!(refusal.code, vault_proto::RefusalCode::DestNotAllowed);
        assert!(
            !node
                .authorized
                .lock()
                .expect("authorized")
                .contains(&theft_txid),
            "a REFUSED spend must never enter the authorized set: it was evaluated, not accepted"
        );

        // The thief broadcasts it anyway. The node must alert.
        let backend = MockBackend {
            spends: vec![vault_spend(&node, theft_txid)],
            ..Default::default()
        };
        assert_eq!(
            node.watchtower_tick(&backend, 0).expect("scan"),
            1,
            "a theft fanned to an honest node must still alert — it cannot suppress its own alarm"
        );
        let (alerts, _) = node.events(0);
        assert_eq!(alerts[0].watchtower().kind, AlertKind::UnrecognizedSpend);
        assert_eq!(alerts[0].watchtower().spend_txid, theft_txid.to_string());
    }

    /// The other half of the same fix: recognition is NOT co-signing. In a
    /// `t`-of-`n` only `t` nodes sign any spend, so keying the alert off the
    /// co-signed set false-alarms on the `n−t` honest non-signers. Here the node
    /// accepted the spend and never released a partial to anyone (no fire event has
    /// arrived) — and it must still recognize it.
    #[test]
    fn recognition_does_not_require_this_node_to_have_signed_into_the_quorum() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture psbt");
        assert!(matches!(
            crate::handle_sign_now(&node, &request).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        // This node is channel-less: it has no peers, released nothing, and is in
        // no combine set. Recognition rests on ACCEPTANCE alone.
        assert!(node.channel.is_none());
        let backend = MockBackend {
            spends: vec![vault_spend(&node, psbt.unsigned_tx.compute_txid())],
            ..Default::default()
        };
        assert_eq!(
            node.watchtower_tick(&backend, 0).expect("scan"),
            0,
            "a spend this node accepted raises nothing, whether or not it signed into the quorum"
        );
    }

    /// The escape of every accepted request is authorized too: it was validated and
    /// accepted at the same ingress, so if V0-4b ever fires it, the node's own
    /// watchtower must not alarm on its own sweep.
    #[test]
    fn the_accepted_requests_escape_is_recognized_as_well() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let escape_txid = Psbt::from_str(&request.escape_psbt)
            .expect("escape psbt")
            .unsigned_tx
            .compute_txid();
        assert!(matches!(
            crate::handle_sign_now(&node, &request).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let backend = MockBackend {
            spends: vec![vault_spend(&node, escape_txid)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&backend, 0).expect("scan"), 0);
    }

    /// A propagated request reaches recognition too: the node ran its own gates on
    /// it, so a spend it learned from a PEER is recognized exactly as one the
    /// coordinator delivered. Without this, `n−1` nodes would alert on every spend
    /// the coordinator happened to deliver to only one of them.
    #[test]
    fn a_request_learned_from_a_peer_is_recognized_after_this_node_validates_it() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture psbt");
        // Exactly what `handle_channel_body` does with a propagated request: run
        // this node's own gates over it.
        let tagged = TaggedRequest::Spend(request);
        let TaggedRequest::Spend(spend) = &tagged else {
            unreachable!("built as a spend")
        };
        assert!(matches!(
            crate::handle_sign_now(&node, spend).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let backend = MockBackend {
            spends: vec![vault_spend(&node, psbt.unsigned_tx.compute_txid())],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&backend, 0).expect("scan"), 0);
    }
}

#[cfg(test)]
mod prevout_preflight {
    //! Deliverable 9y5.3-d: the `/sign`-path preflight that verifies each CONFIRMED
    //! input's `witness_utxo` against the chain's ground truth (keeping policy-core
    //! pure). It refuses a confirmed mismatch fail-closed, yet leaves the
    //! unconfirmed-authorized-parent rule (null / unconfirmed prevout) untouched.

    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::{Arc, Barrier};

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    use super::{
        compare_prevouts_against_chain, fetch_prevouts, run_prevout_check,
        verify_prevouts_against_chain,
    };
    use crate::chain::mock::MockBackend;
    use crate::chain::Prevout;
    use crate::test_support::{coord_sign, node_and_valid_request};
    use vault_proto::{RefusalCode, SignResponse};

    fn outpoint(byte: u8) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([byte; 32]), 0)
    }

    /// A one-input PSBT declaring `witness_utxo` for `op`.
    fn psbt_spending(op: OutPoint, witness_utxo: TxOut) -> Psbt {
        psbt_spending_many(vec![(op, witness_utxo)])
    }

    fn psbt_spending_many(inputs: Vec<(OutPoint, TxOut)>) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(op, _)| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                value: Amount::from_sat(500),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        for (input, (_, witness_utxo)) in psbt.inputs.iter_mut().zip(inputs) {
            input.witness_utxo = Some(witness_utxo);
        }
        psbt
    }

    fn backend_with(op: OutPoint, prevout: Prevout) -> MockBackend {
        let mut prevouts = HashMap::new();
        prevouts.insert(op, prevout);
        MockBackend {
            prevouts,
            ..Default::default()
        }
    }

    fn refusal_code(result: Result<(), SignResponse>) -> RefusalCode {
        match result {
            Err(SignResponse::Refusal(r)) => {
                assert_eq!(r.check, "prevout_ground_truth", "unexpected check: {r:?}");
                r.code
            }
            other => panic!("expected a fail-closed refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_confirmed_value_mismatch_is_refused_fail_closed() {
        // The coordinator inflates the declared value — the fee-cap bypass policy-core
        // would otherwise trust.
        let op = outpoint(1);
        let script = ScriptBuf::from_bytes(vec![0x51, 0x52]);
        let real = TxOut {
            script_pubkey: script.clone(),
            value: Amount::from_sat(100_000),
        };
        let lied = TxOut {
            script_pubkey: script,
            value: Amount::from_sat(50_000_000),
        };
        let psbt = psbt_spending(op, lied);
        let backend = backend_with(
            op,
            Prevout {
                txout: real,
                confirmed: true,
            },
        );
        assert_eq!(
            refusal_code(verify_prevouts_against_chain(&psbt, &backend)),
            RefusalCode::PsbtInconsistent
        );
    }

    #[test]
    fn a_confirmed_script_mismatch_is_refused_fail_closed() {
        // The coordinator forges the prevout scriptPubKey (a forged-ownership attempt).
        let op = outpoint(2);
        let real = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            value: Amount::from_sat(100_000),
        };
        let lied = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x99]),
            value: Amount::from_sat(100_000),
        };
        let psbt = psbt_spending(op, lied);
        let backend = backend_with(
            op,
            Prevout {
                txout: real,
                confirmed: true,
            },
        );
        assert_eq!(
            refusal_code(verify_prevouts_against_chain(&psbt, &backend)),
            RefusalCode::PsbtInconsistent
        );
    }

    #[test]
    fn a_confirmed_truthful_prevout_passes() {
        let op = outpoint(3);
        let txout = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            value: Amount::from_sat(100_000),
        };
        let psbt = psbt_spending(op, txout.clone());
        let backend = backend_with(
            op,
            Prevout {
                txout,
                confirmed: true,
            },
        );
        verify_prevouts_against_chain(&psbt, &backend).expect("a truthful witness_utxo passes");
    }

    #[test]
    fn an_unconfirmed_present_authorized_parent_with_matching_values_is_allowed() {
        // `gettxout(include_mempool)` returns the output, UNCONFIRMED — the vault-
        // authorized-but-unconfirmed parent, in this node's mempool. Its `witness_utxo`
        // MATCHES the actual output, so it is the legitimate authorized-parent case and
        // must pass.
        let op = outpoint(4);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let txout = TxOut {
            script_pubkey: script,
            value: Amount::from_sat(100_000),
        };
        let psbt = psbt_spending(op, txout.clone());
        let backend = backend_with(
            op,
            Prevout {
                txout,
                confirmed: false,
            },
        );
        verify_prevouts_against_chain(&psbt, &backend)
            .expect("an unconfirmed authorized parent whose witness_utxo matches is allowed");
    }

    /// A txid commits to the whole tx, so the output at a fixed `(txid, vout)` is immutable
    /// whether confirmed or in-mempool; an RBF replacement carries a DIFFERENT txid and
    /// would make `gettxout` return null. So an unconfirmed prevout that `gettxout`
    /// RETURNS is ground truth, and a `witness_utxo` disagreeing with it is a forgery a
    /// coerced user would sign — refuse it, don't wave it through as "unconfirmed" (codex P2).
    #[test]
    fn an_unconfirmed_present_prevout_with_a_forged_witness_utxo_is_refused() {
        let op = outpoint(4);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let real = TxOut {
            script_pubkey: script.clone(),
            value: Amount::from_sat(100_000),
        };
        let declared = TxOut {
            script_pubkey: script,
            value: Amount::from_sat(90_000),
        };
        let psbt = psbt_spending(op, declared);
        let backend = backend_with(
            op,
            Prevout {
                txout: real,
                confirmed: false,
            },
        );
        assert_eq!(
            refusal_code(verify_prevouts_against_chain(&psbt, &backend)),
            RefusalCode::PsbtInconsistent,
            "a forged witness_utxo on an unconfirmed-present prevout must be refused",
        );
    }

    #[test]
    fn a_null_prevout_is_allowed_the_authorized_parent_not_yet_in_mempool() {
        // `gettxout` null: the authorized parent this node has not yet seen, or an
        // unknown/spent output. Allowed as today — the fire-time package check is the
        // double-spend backstop; refusing here would break spend-change chaining.
        let op = outpoint(5);
        let declared = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            value: Amount::from_sat(100_000),
        };
        let psbt = psbt_spending(op, declared);
        let backend = MockBackend::default(); // no prevout for `op` ⇒ null
        verify_prevouts_against_chain(&psbt, &backend).expect("a null prevout is allowed");
    }

    #[test]
    fn a_backend_failure_refuses_and_aborts_after_the_first_lookup() {
        let declared = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            value: Amount::from_sat(100_000),
        };
        let first = outpoint(6);
        let second = outpoint(7);
        let psbt = psbt_spending_many(vec![(first, declared.clone()), (second, declared)]);
        let backend = MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        };

        assert_eq!(
            refusal_code(verify_prevouts_against_chain(&psbt, &backend)),
            RefusalCode::PsbtInconsistent
        );
        assert_eq!(
            *backend.prevout_lookups.lock().expect("prevout lookups"),
            vec![first],
            "the default backend batch aborts on its first error instead of multiplying timeouts"
        );
    }

    #[test]
    fn a_large_valid_consolidation_is_not_rejected_by_an_arbitrary_input_cap() {
        let declared = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            value: Amount::from_sat(100_000),
        };
        let inputs = (0..=128)
            .map(|index| {
                (
                    OutPoint::new(Txid::from_byte_array([index as u8; 32]), index as u32),
                    declared.clone(),
                )
            })
            .collect();
        let psbt = psbt_spending_many(inputs);
        let backend = MockBackend::default();

        let fetched = fetch_prevouts(&psbt, &backend)
            .expect("the request-body bound, not an arbitrary input cap, governs the batch");
        compare_prevouts_against_chain(&psbt, &fetched)
            .expect("null prevouts are allowed, so the large consolidation passes");
        assert_eq!(
            backend
                .prevout_lookups
                .lock()
                .expect("prevout lookups")
                .len(),
            129,
            "every input reaches the backend preflight"
        );
    }

    #[test]
    fn a_prefetched_backend_error_is_re_raised_by_the_comparison_path() {
        // The batch RPC is hoisted out of the sign lock; if it failed (bitcoind down),
        // the fail-closed refusal it produced must be re-raised verbatim when the
        // under-lock check consumes the pre-fetched result — never quietly treated as
        // "no prevouts to compare" (which would let policy-core trust witness_utxo).
        let declared = TxOut {
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            value: Amount::from_sat(100_000),
        };
        let psbt = psbt_spending(outpoint(9), declared);
        let backend = MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        };
        let prefetched = fetch_prevouts(&psbt, &backend);
        assert!(prefetched.is_err(), "the hoisted fetch must fail closed");
        assert_eq!(
            refusal_code(run_prevout_check(&psbt, &backend, Some(&prefetched))),
            RefusalCode::PsbtInconsistent
        );
    }

    #[test]
    fn sign_handler_refuses_a_confirmed_mismatch_after_recording_duress_intent() {
        let (mut node, mut request) = node_and_valid_request();
        request.pin = "9999".into();
        coord_sign(&mut request, &node.wallet_id, "handler-prevout-mismatch");
        let psbt = Psbt::from_str(&request.psbt).expect("fixture spend");
        let outpoint = psbt.unsigned_tx.input[0].previous_output;
        let declared = psbt.inputs[0]
            .witness_utxo
            .clone()
            .expect("fixture witness_utxo");
        let mut mismatch = declared.clone();
        mismatch.value = Amount::from_sat(declared.value.to_sat() - 1);
        node.set_chain_backend(Arc::new(backend_with(
            outpoint,
            Prevout {
                txout: mismatch,
                confirmed: true,
            },
        )));
        let now = request.expiry - 100;

        let refused = super::handle_sign(&node, &request, now).expect("decodable request");
        assert!(matches!(
            refused,
            SignResponse::Refusal(ref refusal)
                if refusal.code == RefusalCode::PsbtInconsistent
                    && refusal.check == "prevout_ground_truth"
        ));
        assert_eq!(
            node.duress_arm_count(),
            1,
            "chain-dependent refusal must land after the chain-independent safety hook"
        );
        assert_eq!(
            node.sign_state.lock().expect("sign state").replay.len(),
            0,
            "a corrected witness_utxo must be re-evaluated rather than replaying the mismatch"
        );

        node.set_chain_backend(Arc::new(backend_with(
            outpoint,
            Prevout {
                txout: declared,
                confirmed: true,
            },
        )));
        coord_sign(&mut request, &node.wallet_id, "handler-prevout-corrected");
        assert!(matches!(
            super::handle_sign(&node, &request, now).expect("corrected request"),
            SignResponse::Accepted(_)
        ));
    }

    #[test]
    fn duress_intent_precedes_blocked_chain_io_and_lockdown_lock_stays_free() {
        let (mut node, mut request) = node_and_valid_request();
        request.pin = "9999".into();
        coord_sign(&mut request, &node.wallet_id, "blocked-prevout-preflight");
        let psbt = Psbt::from_str(&request.psbt).expect("fixture spend");
        let outpoint = psbt.unsigned_tx.input[0].previous_output;
        let declared = psbt.inputs[0]
            .witness_utxo
            .clone()
            .expect("fixture witness_utxo");
        let entered = Arc::new(Barrier::new(2));
        let proceed = Arc::new(Barrier::new(2));
        node.set_chain_backend(Arc::new(MockBackend {
            prevouts: [(
                outpoint,
                Prevout {
                    txout: declared,
                    confirmed: true,
                },
            )]
            .into_iter()
            .collect(),
            prevout_fetch_entered: Some(Arc::clone(&entered)),
            prevout_fetch_continue: Some(Arc::clone(&proceed)),
            ..Default::default()
        }));
        let now = request.expiry - 100;
        let node = Arc::new(node);
        let worker_node = Arc::clone(&node);
        let worker = std::thread::spawn(move || super::handle_sign(&worker_node, &request, now));

        entered.wait();
        assert_eq!(
            node.duress_arm_count(),
            1,
            "the safety hook must commit before the first backend lookup can block"
        );
        assert!(
            node.sign_state.try_lock().is_ok(),
            "the chain preflight must not hold the lock needed by Lockdown-at-T"
        );
        proceed.wait();
        assert!(matches!(
            worker.join().expect("sign worker").expect("valid request"),
            SignResponse::Accepted(_)
        ));
    }

    /// A coordinator reaches one honest node whose bitcoind is down: its prevout preflight
    /// fails and the node refuses fail-closed, registering no candidate. Bead f91 (C) adds
    /// the other half — that NODE-LOCAL refusal now also forwards the carrier, so a
    /// selectively-delivered duress request is not swallowed by one node's dead backend.
    /// The forward's ordering and its self-hold are pinned in `preflight_concurrency`.
    #[test]
    fn a_prevout_fetch_failure_refuses_fail_closed() {
        let (mut node, request) = node_and_valid_request();
        node.set_chain_backend(Arc::new(MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        }));
        let now = request.expiry - 100;
        let response = super::handle_sign(&node, &request, now).expect("valid request");
        assert!(
            matches!(&response, SignResponse::Refusal(r) if r.code == RefusalCode::PsbtInconsistent),
            "a node whose backend is down refuses fail-closed: {response:?}"
        );
        assert_eq!(
            node.sign_state.lock().expect("sign state").pending.len(),
            0,
            "a fail-closed preflight refusal must register no candidate"
        );
    }

    #[test]
    fn captured_nonce_replay_is_rejected_before_any_additional_chain_rpc() {
        let (mut node, request) = node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture spend");
        let outpoint = psbt.unsigned_tx.input[0].previous_output;
        let declared = psbt.inputs[0]
            .witness_utxo
            .clone()
            .expect("fixture witness_utxo");
        let backend = Arc::new(MockBackend {
            prevouts: [(
                outpoint,
                Prevout {
                    txout: declared,
                    confirmed: true,
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        node.set_chain_backend(backend.clone());
        let now = request.expiry - 100;

        assert!(matches!(
            super::handle_sign(&node, &request, now).expect("first request"),
            SignResponse::Accepted(_)
        ));
        let first_lookups = backend
            .prevout_lookups
            .lock()
            .expect("prevout lookups")
            .len();
        assert_eq!(first_lookups, 2, "spend and escape each fetch once");

        let replay = super::handle_sign(&node, &request, now).expect("replayed request");
        assert!(matches!(
            replay,
            SignResponse::Refusal(ref refusal)
                if refusal.code == RefusalCode::NonceReplayed
        ));
        assert_eq!(
            backend
                .prevout_lookups
                .lock()
                .expect("prevout lookups")
                .len(),
            first_lookups,
            "freshness rejection must precede both prevout batches"
        );
    }
}

#[cfg(test)]
mod preflight_concurrency {
    //! Bead btc-policy-f91: the concurrency window `/sign` opens by running its chain
    //! preflight OUTSIDE `sign_state`.
    //!
    //! That hoist is itself load-bearing (a round-2 P0: chain I/O under the lock let a
    //! hung bitcoind delay the deadline driver's unconditional Lockdown-at-`T`), so the
    //! preflight STAYS out of the lock and these tests pin the consequences instead:
    //!
    //!  - **(A)** a spend inside that window subordinates concurrent refreshes, and the
    //!    marker that does it cannot leak on any exit path;
    //!  - **(B)** the peer fan-out is deferred by the preflight, and that deferral is a
    //!    bounded DELAY (two batch RPCs, each under one [`chain::RPC_TIMEOUT`]) rather
    //!    than a miss;
    //!  - **(C)** a node-local prevout FETCH failure forwards the carrier, without
    //!    overriding an already-accepted verdict and without turning the
    //!    federation-uniform value MISMATCH into a propagating refusal.
    //!
    //! Every race here is driven by the mock backend's one-shot preflight barrier, never
    //! by sleeps: the spend thread parks INSIDE the preflight until the test releases it.

    use std::str::FromStr;
    use std::sync::{Arc, Barrier};

    use bitcoin::{Amount, Psbt};

    use crate::chain::mock::MockBackend;
    use crate::chain::Prevout;
    use crate::test_support::{
        coord_sign, node_and_valid_request, theft_request, valid_refresh_request,
    };
    use vault_proto::{RefusalCode, SignRequest, SignResponse};

    /// A backend whose chain view confirms every prevout the fixture spend and its
    /// mandatory escape declare (both spend outpoint `7:0`), optionally parking the
    /// FIRST lookup on `entered`/`proceed` so a test can hold a `/sign` call inside its
    /// out-of-lock preflight.
    fn fixture_backend(
        request: &SignRequest,
        pause: Option<(Arc<Barrier>, Arc<Barrier>)>,
    ) -> MockBackend {
        let psbt = Psbt::from_str(&request.psbt).expect("fixture spend");
        let (entered, proceed) = match pause {
            Some((entered, proceed)) => (Some(entered), Some(proceed)),
            None => (None, None),
        };
        MockBackend {
            prevouts: [(
                psbt.unsigned_tx.input[0].previous_output,
                Prevout {
                    txout: psbt.inputs[0]
                        .witness_utxo
                        .clone()
                        .expect("fixture witness_utxo"),
                    confirmed: true,
                },
            )]
            .into_iter()
            .collect(),
            prevout_fetch_entered: entered,
            prevout_fetch_continue: proceed,
            ..Default::default()
        }
    }

    /// Drive a spend with `pin` into its out-of-lock preflight, submit a refresh over
    /// the input that spend's mandatory escape needs, and return
    /// `(refresh response, spend response)`.
    ///
    /// The refresh runs while the spend is parked in the backend, which is precisely the
    /// window `state.pending` does not cover — the test asserts that emptiness itself, so
    /// a pass here cannot be earned by the pre-existing registered-spend rule.
    fn race_a_refresh_against_a_spend_preflight(pin: &str) -> (SignResponse, SignResponse) {
        let (mut node, mut request) = node_and_valid_request();
        request.pin = pin.into();
        coord_sign(&mut request, &node.wallet_id, "f91-race-spend");
        let refresh = valid_refresh_request(&node, &request, "f91-race-refresh");

        let entered = Arc::new(Barrier::new(2));
        let proceed = Arc::new(Barrier::new(2));
        node.set_chain_backend(Arc::new(fixture_backend(
            &request,
            Some((Arc::clone(&entered), Arc::clone(&proceed))),
        )));
        let now = request.expiry - 100;
        let node = Arc::new(node);

        let spend_node = Arc::clone(&node);
        let spend = std::thread::spawn(move || {
            crate::handle_sign(&spend_node, &request, now).expect("decodable spend")
        });

        // The spend is now parked inside its preflight: past the arm hook, before
        // candidate registration.
        entered.wait();
        assert_eq!(
            node.sign_state.lock().expect("sign state").pending.len(),
            0,
            "the racing spend must NOT be registered yet — otherwise this test would be \
             passing on the old registered-spend rule instead of the in-flight marker"
        );
        assert!(
            node.spend_preflight_in_flight(),
            "a spend inside its out-of-lock preflight must hold an in-flight slot"
        );

        let refreshed = crate::handle_refresh(&node, &refresh, now).expect("decodable refresh");
        proceed.wait();
        (refreshed, spend.join().expect("spend worker"))
    }

    /// (A) The honest-reachable race. A refresh that overtakes a spend's out-of-lock
    /// preflight must NOT be able to consume an input that spend's MANDATORY ESCAPE
    /// needs: if it did, the escape could no longer cover at `T`, the best-effort sweep
    /// would fail, and the vault would exit through recovery — funds frozen, not stolen,
    /// but avoidably so.
    ///
    /// The fixture refresh spends outpoint `7:0`, which is exactly the input the racing
    /// spend's escape sweeps, so this is the invalidating refresh and not a bystander.
    #[test]
    fn a_refresh_racing_an_in_flight_spend_is_subordinated() {
        let (refreshed, spend) = race_a_refresh_against_a_spend_preflight("1234");
        assert!(
            matches!(&refreshed, SignResponse::Refusal(r)
                if r.code == RefusalCode::RefreshSubordinated),
            "a refresh over the in-flight spend's escape input must be subordinated: \
             {refreshed:?}"
        );
        assert!(
            matches!(spend, SignResponse::Accepted(_)),
            "the spend itself still completes once its preflight returns: {spend:?}"
        );
    }

    /// (A) SILENCE. The in-flight claim is taken on the one code path both matching pin
    /// classes take, before the verdict can branch any observable, so a refresh
    /// subordinated by a DURESS spend's preflight must be byte-identical to one
    /// subordinated by a NORMAL spend's. Compared on the serialized wire form, which is
    /// what the coordinator actually sees.
    #[test]
    fn the_in_flight_subordination_refusal_is_identical_under_both_pin_classes() {
        let (normal, _) = race_a_refresh_against_a_spend_preflight("1234");
        let (duress, _) = race_a_refresh_against_a_spend_preflight("9999");
        assert_eq!(
            serde_json::to_string(&normal).expect("encode normal refusal"),
            serde_json::to_string(&duress).expect("encode duress refusal"),
            "the racing spend's pin class must not be readable from the refresh refusal"
        );
        assert!(matches!(&normal, SignResponse::Refusal(r)
            if r.code == RefusalCode::RefreshSubordinated));
    }

    /// (A) The marker is an RAII claim, so no exit can leak it — a leaked claim would
    /// subordinate every refresh on this node until it died. Three structurally distinct
    /// exits from the preflight window: the accepted path, a federation-uniform policy
    /// refusal, and a phase-2 early return that never reaches validation at all.
    #[test]
    fn the_in_flight_marker_is_released_on_every_exit_path() {
        // 1. ACCEPTED.
        let (mut node, request) = node_and_valid_request();
        node.set_chain_backend(Arc::new(fixture_backend(&request, None)));
        let now = request.expiry - 100;
        assert!(matches!(
            crate::handle_sign(&node, &request, now).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        assert!(
            !node.spend_preflight_in_flight(),
            "the accepted path must release its in-flight slot"
        );

        // 2. A POLICY REFUSAL (`DEST_NOT_ALLOWED`), which returns from the middle of
        //    phase 2. The refused theft registers nothing, so once the slot is released
        //    a refresh must be servable again — the end-to-end form of "not leaked".
        let (mut node, request) = node_and_valid_request();
        node.set_chain_backend(Arc::new(fixture_backend(&request, None)));
        let theft = theft_request(&node, &request);
        let refresh = valid_refresh_request(&node, &request, "f91-release-refresh");
        let now = request.expiry - 100;
        assert!(
            matches!(crate::handle_sign(&node, &theft, now).expect("decodable"),
                SignResponse::Refusal(r) if r.code == RefusalCode::DestNotAllowed)
        );
        assert!(
            !node.spend_preflight_in_flight(),
            "a policy refusal must release its in-flight slot"
        );
        assert!(
            matches!(
                crate::handle_refresh(&node, &refresh, now).expect("decodable refresh"),
                SignResponse::Accepted(_)
            ),
            "with the slot released and nothing pending, a refresh is servable again"
        );

        // 3. AN EARLY RETURN that never reaches validation: the node-local prevout FETCH
        //    failure, which returns as soon as the preflight result is inspected.
        let (mut node, request) = node_and_valid_request();
        node.set_chain_backend(Arc::new(MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        }));
        let now = request.expiry - 100;
        assert!(matches!(
            crate::handle_sign(&node, &request, now).expect("decodable"),
            SignResponse::Refusal(_)
        ));
        assert!(
            !node.spend_preflight_in_flight(),
            "a phase-2 early return must release its in-flight slot too"
        );
    }

    /// (B) The fan-out cost of keeping the preflight out of the lock, made explicit.
    ///
    /// `stage_spend_carrier` first becomes possible only AFTER the preflight, so a node
    /// with a stalled backend adds that stall to peer fan-out latency. This pins that
    /// the OUT-OF-LOCK PREFLIGHT component is BOUNDED and that the fan-out is DELAYED,
    /// never dropped:
    ///
    ///  - the safety INTENT is already recorded while the backend is still parked (it is
    ///    chain-independent, and the arm hook runs before the preflight);
    ///  - the preflight issues exactly TWO batch RPCs — one for the spend, one for the
    ///    escape, the ladder reusing the escape's — each a single loopback HTTP request
    ///    under one [`chain::RPC_TIMEOUT`]. The COUNT is what this pins, and it is the
    ///    half a hostile coordinator could otherwise attack: this component does not
    ///    scale with the number of inputs or ladder rungs it declares; and
    ///  - the carrier IS staged once the preflight returns.
    ///
    /// Total ingress-to-fan-out latency also contains the phase-2 `sign_state` wait and
    /// validation/signing before staging. That separate term can grow under concurrent
    /// authenticated traffic and is deliberately outside this two-RPC preflight bound.
    ///
    /// The alternative — fanning the request out BEFORE validation — is invariant-blocked
    /// (it would propagate federation-uniform policy and MISMATCH refusals), so the bound
    /// is the accepted answer and this test is what keeps it honest.
    #[test]
    fn the_preflight_defers_fan_out_by_a_bounded_stall_and_never_drops_it() {
        let (mut node, mut request) = node_and_valid_request();
        request.pin = "9999".into();
        coord_sign(&mut request, &node.wallet_id, "f91-bounded-stall");
        let entered = Arc::new(Barrier::new(2));
        let proceed = Arc::new(Barrier::new(2));
        let backend = Arc::new(fixture_backend(
            &request,
            Some((Arc::clone(&entered), Arc::clone(&proceed))),
        ));
        node.set_chain_backend(backend.clone());
        let now = request.expiry - 100;
        let node = Arc::new(node);

        let spend_node = Arc::clone(&node);
        let spend = std::thread::spawn(move || {
            crate::handle_sign(&spend_node, &request, now).expect("decodable spend")
        });

        entered.wait();
        assert_eq!(
            node.duress_arm_count(),
            1,
            "the safety intent is chain-independent and exists before the stall"
        );
        assert!(
            node.outbox.lock().expect("outbox").is_empty(),
            "fan-out is what the stall defers — this is the cost being bounded, not a bug"
        );
        proceed.wait();

        assert!(matches!(
            spend.join().expect("spend worker"),
            SignResponse::Accepted(_)
        ));
        assert_eq!(
            node.outbox.lock().expect("outbox").len(),
            1,
            "the deferred fan-out must still happen: a DELAY, not a MISS"
        );
        assert_eq!(
            *backend.prevout_batches.lock().expect("batches"),
            vec![1, 1],
            "the preflight is exactly two batch RPCs — the spend's and the escape's"
        );
    }

    /// (B), the half that is exactly true rather than merely typical: the preflight
    /// component does not SCALE with either input count or ladder length. A hostile
    /// coordinator cannot lengthen it by declaring more inputs because each PSBT is one
    /// batch, and fee-bump rungs reuse the base escape's fetched ground truth. Two inputs
    /// per PSBT plus one real bump rung must still be exactly two batches.
    #[test]
    fn the_preflight_stall_does_not_scale_with_the_request() {
        let (mut node, mut request) = crate::test_support::node_and_valid_multi_request();
        let mut escape = Psbt::from_str(&request.escape_psbt).expect("fixture escape");
        for input in &mut escape.unsigned_tx.input {
            input.sequence = bitcoin::Sequence::from_consensus(crate::ESCAPE_RBF_SEQUENCE);
        }
        crate::test_support::user_sign_all(&node, &mut escape);
        let mut bump = escape.clone();
        let bumped_value = bump.unsigned_tx.output[0].value.to_sat() - 1_000_000;
        bump.unsigned_tx.output[0].value = Amount::from_sat(bumped_value);
        crate::test_support::user_sign_all(&node, &mut bump);
        request.escape_psbt = escape.to_string();
        request.escape_bumps = vec![bump.to_string()];
        coord_sign(&mut request, &node.wallet_id, "f91-multi-with-bump");

        let backend = Arc::new(MockBackend::default());
        node.set_chain_backend(backend.clone());
        let now = request.expiry - 100;
        assert!(matches!(
            crate::handle_sign(&node, &request, now).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        assert_eq!(
            *backend.prevout_batches.lock().expect("batches"),
            vec![2, 2],
            "two inputs per PSBT and a bump rung must still cost exactly two batch RPCs"
        );
    }

    /// (C) A node whose own backend is down cannot evaluate the request, but it must not
    /// swallow the carrier: it refuses fail-closed AND forwards, exactly like the
    /// node-local expiry and delivery-horizon refusals. Otherwise a coordinator that
    /// selectively delivers a duress request to a node with a dead bitcoind gets a node
    /// that recorded an intent it can never confirm.
    #[test]
    fn a_node_local_prevout_fetch_failure_forwards_the_carrier() {
        let (mut node, mut request) = node_and_valid_request();
        request.pin = "9999".into();
        coord_sign(&mut request, &node.wallet_id, "f91-fetch-failure");
        node.set_chain_backend(Arc::new(MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        }));
        let now = request.expiry - 100;

        let response = crate::handle_sign(&node, &request, now).expect("decodable");
        assert!(
            matches!(&response, SignResponse::Refusal(r)
                if r.code == RefusalCode::PsbtInconsistent),
            "a dead backend still refuses fail-closed: {response:?}"
        );
        assert_eq!(
            node.outbox.lock().expect("outbox").len(),
            1,
            "a NODE-LOCAL refusal must still fan the carrier out to peers"
        );
    }

    /// (C) The early fetch-failure branch runs before `verify_escape`, so it must add
    /// the same `escape:` attribution itself when only the mandatory escape's batch
    /// fails. Without this, operators cannot tell which half of the pair lost its chain
    /// view.
    #[test]
    fn an_escape_only_prevout_fetch_failure_keeps_escape_attribution() {
        let (mut node, mut request) = node_and_valid_request();
        // Make the spend's batch empty and therefore infallible; the backend's first
        // actual lookup is then the escape, isolating the escape-only failure path.
        let mut spend = Psbt::from_str(&request.psbt).expect("fixture spend");
        spend.unsigned_tx.input.clear();
        spend.inputs.clear();
        request.psbt = spend.to_string();
        coord_sign(&mut request, &node.wallet_id, "f91-escape-fetch-failure");
        node.set_chain_backend(Arc::new(MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        }));
        let now = request.expiry - 100;

        let response = crate::handle_sign(&node, &request, now).expect("decodable");
        assert!(
            matches!(&response, SignResponse::Refusal(r)
                if r.code == RefusalCode::PsbtInconsistent
                    && r.check == "escape:prevout_ground_truth"),
            "the early escape fetch failure must remain attributable: {response:?}"
        );
        assert_eq!(
            node.outbox.lock().expect("outbox").len(),
            1,
            "an escape fetch failure is still node-local and must forward"
        );
    }

    /// (C) The ordering that made two earlier attempts a regression (codex 9y5.3 pass-5
    /// P1): the forward must sit AFTER the accepted-replay lookup. A coordinator retrying
    /// an ALREADY-ACCEPTED request while this node's backend happens to be down must get
    /// its cached ACCEPTED verdict back — a transient local failure cannot retract an
    /// acceptance the node already made and registered.
    #[test]
    fn a_fetch_failure_does_not_override_an_already_accepted_replay() {
        let (mut node, mut request) = node_and_valid_request();
        node.set_chain_backend(Arc::new(fixture_backend(&request, None)));
        let now = request.expiry - 100;
        assert!(matches!(
            crate::handle_sign(&node, &request, now).expect("decodable"),
            SignResponse::Accepted(_)
        ));

        // The backend dies, and the coordinator retries the SAME pair with a fresh
        // nonce (the nonce is single-use per transmission; idempotency lives on the pair).
        node.set_chain_backend(Arc::new(MockBackend {
            prevout_error: Some("backend unavailable".into()),
            ..Default::default()
        }));
        coord_sign(&mut request, &node.wallet_id, "f91-accepted-retry");
        let replayed = crate::handle_sign(&node, &request, now).expect("decodable");
        assert!(
            matches!(replayed, SignResponse::Accepted(_)),
            "the cached ACCEPTED verdict must win over a transient backend failure: \
             {replayed:?}"
        );
    }

    /// (C) The other half of the split. A `witness_utxo`-vs-chain MISMATCH is
    /// FEDERATION-UNIFORM — every honest node derives it from the same consensus data —
    /// so propagating it would hand an attacker a theft-recognition signal. It must
    /// refuse WITHOUT forwarding, while the fetch failure above forwards.
    #[test]
    fn a_prevout_value_mismatch_still_does_not_propagate() {
        let (mut node, mut request) = node_and_valid_request();
        request.pin = "9999".into();
        coord_sign(&mut request, &node.wallet_id, "f91-mismatch");
        let psbt = Psbt::from_str(&request.psbt).expect("fixture spend");
        let declared = psbt.inputs[0]
            .witness_utxo
            .clone()
            .expect("fixture witness_utxo");
        let mut on_chain = declared.clone();
        on_chain.value = Amount::from_sat(declared.value.to_sat() - 1);
        node.set_chain_backend(Arc::new(MockBackend {
            prevouts: [(
                psbt.unsigned_tx.input[0].previous_output,
                Prevout {
                    txout: on_chain,
                    confirmed: true,
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        }));
        let now = request.expiry - 100;

        let response = crate::handle_sign(&node, &request, now).expect("decodable");
        assert!(
            matches!(&response, SignResponse::Refusal(r)
                if r.code == RefusalCode::PsbtInconsistent
                    && r.check == "prevout_ground_truth"),
            "a forged witness_utxo is refused: {response:?}"
        );
        assert!(
            node.outbox.lock().expect("outbox").is_empty(),
            "a FEDERATION-UNIFORM refusal must never propagate — every honest node reaches \
             it alone, and forwarding it would leak theft recognition"
        );
    }
}

/// Shared test fixtures: a signable node and a valid `SignRequest`. Used by the
/// `server` HTTP regression tests, which drive the real handler over a real
/// socket (so the handler reads the system clock, unlike the direct-call unit
/// tests that pass a fixed `now`). Mirrors `watchtower_wiring::signed_node`'s
/// vault.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hex::DisplayHex;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn key(i: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[i; 32]).expect("32 nonzero bytes");
        (sk, PublicKey::new(sk.public_key(&secp)))
    }

    /// Argon2id cost every fixture derives its node key at: the implementation
    /// FLOOR. The suite stands up hundreds of nodes, and a production-cost pass
    /// (~1s each, [`nodekey::DEFAULT_KDF_OPS`]) would turn a fast test run into a
    /// coffee break while proving nothing extra — the cost parameter is not what any
    /// invariant here rests on.
    pub(crate) const FIXTURE_KDF_OPS: u32 = 1;
    pub(crate) const FIXTURE_KDF_MEM_KIB: u32 = 8;

    /// The one preimage every fixture node derives from. Fixtures separate their
    /// nodes by SALT rather than by preimage, which is a real production shape too
    /// (nothing in the node cares which of the two varies) and keeps a single
    /// constant standing in for "the operator typed the right secret".
    pub(crate) fn fixture_preimage() -> nodekey::Preimage {
        nodekey::Preimage::from_hex("00000000000000ff").expect("fixture preimage")
    }

    /// A fixture node key: the public derivation parameters plus the secret and
    /// public halves [`fixture_preimage`] yields under them. `seed` separates nodes.
    pub(crate) fn fixture_node_key(seed: u8) -> (nodekey::KdfParams, SecretKey, PublicKey) {
        let params = nodekey::KdfParams::new(
            [seed; nodekey::SALT_BYTES],
            FIXTURE_KDF_OPS,
            FIXTURE_KDF_MEM_KIB,
        )
        .expect("fixture kdf params");
        let seckey = nodekey::derive(&fixture_preimage(), &params).expect("fixture derivation");
        let secp = Secp256k1::new();
        let pubkey = PublicKey::new(seckey.public_key(&secp));
        (params, seckey, pubkey)
    }

    /// The `node_key_*` config lines for a fixture node — the PUBLIC derivation
    /// parameters that replaced `node_seckey`.
    pub(crate) fn node_key_toml(params: &nodekey::KdfParams) -> String {
        format!(
            "node_key_salt = \"{}\"\nnode_key_ops = {}\nnode_key_mem_kib = {}\n",
            params.salt_hex(),
            params.ops(),
            params.mem_kib(),
        )
    }

    /// `Node::from_toml_str` with the fixture preimage — the test-side stand-in for
    /// the operator typing their secret at `vault-node` startup. Every in-crate test
    /// loads through this, so a config that does not name the fixture derivation
    /// fails exactly as a production config paired with the wrong preimage would.
    pub(crate) fn load_node(raw: &str) -> Result<Node, Error> {
        Node::from_toml_str(raw, &fixture_preimage())
    }

    /// The two-branch vault descriptor (ADR-0013 §1) for a `t = node_keys.len()`
    /// fixture: `user` + all `node_keys` on the normal branch, plus a fixed
    /// throwaway 2-of-3 recovery keyset (seeds 0x30..=0x32). The recovery branch is
    /// off the path these node-side tests drive; it exists so `from_toml_str`'s
    /// template parse accepts the descriptor.
    fn test_vault_descriptor(user: &PublicKey, node_keys: &[PublicKey]) -> String {
        let nodes: Vec<String> = node_keys.iter().map(|k| k.to_string()).collect();
        let recovery: Vec<String> = (0x30u8..=0x32).map(|i| key(i).1.to_string()).collect();
        policy_core::vault_descriptor_string(&user.to_string(), nodes.len(), &nodes, &recovery)
    }

    /// The coordinator this fixture's vault is sealed to (ADR-0013 §2).
    fn coord_key() -> (SecretKey, PublicKey) {
        key(0xC0)
    }

    /// A full absent-channel config with the three timing bounds parameterized and
    /// `extra` appended verbatim — used to exercise the load-time combine-window
    /// invariants (`combine_slack_secs > 0`, `hold + slack <= max_commitment_age`).
    pub(crate) fn config_with_bounds(
        hold_secs: u64,
        max_commitment_age_secs: u64,
        extra: &str,
    ) -> String {
        let (_, user) = key(1);
        let (node_kdf, _, node_pub) = fixture_node_key(2);
        let (_, hot_key) = key(10);
        let (_, escape_key) = key(11);
        let descriptor = test_vault_descriptor(&user, &[node_pub]);
        format!(
            "listen_port = 0\n{}descriptor = \"{descriptor}\"\n\
             allowlist = [\"wpkh({hot_key})\", \"wpkh({escape_key})\"]\n\
             escape_descriptor = \"wpkh({escape_key})\"\n\
             max_derivation_index = 5\nhold_secs = {hold_secs}\n\
             hot_max_per_tx = {}\nhot_max_per_window = {}\n\
             hot_window_secs = {}\n\
             max_commitment_age_secs = {max_commitment_age_secs}\npolicy_version = 1\n\
             pin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n\
             coordinator_auth_pubkey = \"{}\"\n{extra}",
            node_key_toml(&node_kdf),
            channel::TEST_HOT_BUDGET.max_per_tx_sat,
            channel::TEST_HOT_BUDGET.max_per_window_sat,
            // The velocity window must cover the commitment lifetime, and this
            // helper parameterizes that lifetime, so track it rather than pinning a
            // constant a caller could raise past the floor.
            max_commitment_age_secs.max(channel::TEST_HOT_BUDGET.window_secs),
            argon2id_normal_phc("1234"),
            argon2id_duress_phc("9999"),
            coord_key().1,
        )
    }

    /// Attach a fresh `nonce` and the coordinator signature over the canonical
    /// request bytes — exactly what vault-cli does before relaying. Every request
    /// must clear the ingress coord-auth gate, so tests that RE-send a request
    /// (a coordinator retrying a timed-out or lost call) re-sign with a fresh
    /// nonce: the nonce is single-use per transmission, while idempotency lives on
    /// the commitment, so the same spend re-sent this way still returns the one
    /// recorded verdict from the anti-replay log.
    pub(crate) fn coord_sign(request: &mut SignRequest, wallet_id: &[u8; 32], nonce: &str) {
        request.nonce = nonce.to_string();
        // `coord_request()` selects the signed fields; coord_sig is never part of
        // its own preimage, so it needs no clearing before the digest. `wallet_id`
        // is bound into the digest as a domain separator (H2), so it MUST be the id
        // the receiving node re-derives — pass `node.wallet_id`.
        let digest = request.coord_request().auth_digest(wallet_id);
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &coord_key().0);
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
    }

    /// Refresh counterpart to [`coord_sign`]: the same coordinator key and
    /// freshness contract, over the Refresh variant's canonical bytes (bound to the
    /// receiving node's `wallet_id`, H2).
    pub(crate) fn coord_sign_refresh(
        request: &mut RefreshRequest,
        wallet_id: &[u8; 32],
        nonce: &str,
    ) {
        request.nonce = nonce.to_string();
        let digest = request.coord_request().auth_digest(wallet_id);
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &coord_key().0);
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
    }

    /// The `wallet_id` (sha256 of the canonical descriptor) of the standard
    /// single-node test vault `node_and_valid_request`/`config_with_bounds` build.
    /// Coordinator signatures are domain-separated by `wallet_id` (H2), so a fixture
    /// that signs WITHOUT a `node` in scope must bind the SAME id `Node::load`
    /// re-derives from this exact descriptor. Callers that DO hold the node pass
    /// `&node.wallet_id` directly.
    pub(crate) fn test_wallet_id() -> [u8; 32] {
        // The node key is the DERIVED one (`fixture_node_key`), not a raw seed:
        // `wallet_id` is the hash of the descriptor these fixtures actually build,
        // and it is the coord-auth digest's domain separator, so a stale copy here
        // makes every request fail `CoordAuthInvalid` instead of reaching the pin.
        let descriptor = Descriptor::<PublicKey>::from_str(&test_vault_descriptor(
            &key(1).1,
            &[fixture_node_key(2).2],
        ))
        .expect("standard test descriptor parses");
        sha256::Hash::hash(descriptor.to_string().as_bytes()).to_byte_array()
    }

    pub(crate) fn user_sign_all(node: &Node, psbt: &mut Psbt) {
        let unsigned = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&unsigned);
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            let value = input.witness_utxo.as_ref().expect("witness utxo").value;
            let sighash = cache
                .p2wsh_signature_hash(index, &node.witness_script, value, EcdsaSighashType::All)
                .expect("sighash");
            let signature = Secp256k1::new()
                .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &key(1).0);
            input.partial_sigs.clear();
            input.partial_sigs.insert(
                node.user_pubkey,
                bitcoin::ecdsa::Signature {
                    signature,
                    sighash_type: EcdsaSighashType::All,
                },
            );
        }
    }

    /// Derive a valid pin-less refresh from the fixture spend: only the output is
    /// changed to pay the vault, then the user and coordinator re-sign the exact
    /// refresh bytes.
    pub(crate) fn valid_refresh_request(
        node: &Node,
        spend: &SignRequest,
        nonce: &str,
    ) -> RefreshRequest {
        let mut psbt = Psbt::from_str(&spend.psbt).expect("fixture psbt");
        psbt.unsigned_tx.output[0].script_pubkey = node.vault_scripts()[0].clone();
        // A realistic self-spend fee. The fixture spend's flat 10_000 sat would
        // read as ~106 sat/vB over this tiny transaction and trip the refresh fee
        // cap (ADR-0013 §6) — correctly: a real refresh pays a normal feerate.
        psbt.unsigned_tx.output[0].value = Amount::from_sat(99_999_000);
        user_sign_all(node, &mut psbt);
        let mut request = RefreshRequest {
            refresh_psbt: psbt.to_string(),
            nonce: String::new(),
            expiry: spend.expiry,
            policy_version: spend.policy_version,
            coord_sig: String::new(),
        };
        coord_sign_refresh(&mut request, &node.wallet_id, nonce);
        request
    }

    /// A 1-of-1 vault (user key + one node key, `hold_secs = 0`) bound to
    /// `listen_port = 0`, plus a valid, coordinator-signed hot-spend `SignRequest`
    /// that `handle_sign` signs on first submission. The request's `expiry` is set
    /// against the REAL clock and sits well inside `max_commitment_age_secs`. The
    /// enrolled normal pin is `1234`, the duress pin `9999`.
    pub(crate) fn node_and_valid_request() -> (Node, SignRequest) {
        node_and_valid_request_with_budget("")
    }

    /// The same accepted fixture expanded to two distinct inputs and two distinct
    /// output amounts in BOTH the spend and escape. Mutation properties use this so
    /// index selection, dropping, and reordering exercise nonzero positions through
    /// the real ingress instead of collapsing every index onto a 1×1 transaction.
    pub(crate) fn node_and_valid_multi_request() -> (Node, SignRequest) {
        fn expand(node: &Node, psbt_text: &str) -> Psbt {
            let mut psbt = Psbt::from_str(psbt_text).expect("fixture psbt");
            let mut txin = psbt.unsigned_tx.input[0].clone();
            txin.previous_output = OutPoint::new(Txid::from_byte_array([8; 32]), 0);
            psbt.unsigned_tx.input.push(txin);
            psbt.inputs.push(psbt.inputs[0].clone());

            let mut txout = psbt.unsigned_tx.output[0].clone();
            txout.value = Amount::from_sat(100_000_000);
            psbt.unsigned_tx.output.push(txout);
            psbt.outputs.push(bitcoin::psbt::Output::default());
            user_sign_all(node, &mut psbt);
            psbt
        }

        let (node, mut request) = node_and_valid_request();
        request.psbt = expand(&node, &request.psbt).to_string();
        request.escape_psbt = expand(&node, &request.escape_psbt).to_string();
        coord_sign(
            &mut request,
            &node.wallet_id,
            "test-support-multi-first-send",
        );
        (node, request)
    }

    /// [`node_and_valid_request`] with an explicit `[pin_attempt_budget]` TOML block
    /// appended (empty ⇒ the defaulted budget), so the attempt-budget tests can
    /// enrol a small `max_attempts` with a zero backoff (no real sleeping).
    pub(crate) fn node_and_valid_request_with_budget(budget_toml: &str) -> (Node, SignRequest) {
        let (_, user) = key(1);
        let (node_kdf, _, node_pub) = fixture_node_key(2);
        let (_, hot_key) = key(10);
        let (_, escape_key) = key(11);
        let descriptor = test_vault_descriptor(&user, &[node_pub]);
        let hot = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({hot_key})"))
            .expect("hot descriptor");
        let escape = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({escape_key})"))
            .expect("escape descriptor");
        let hot_spk = hot
            .at_derivation_index(0)
            .expect("definite")
            .script_pubkey();
        let config = format!(
            "listen_port = 0\n{}descriptor = \"{descriptor}\"\n\
             allowlist = [\"{hot}\", \"{escape}\"]\nescape_descriptor = \"{escape}\"\n\
             max_derivation_index = 5\nhold_secs = 0\n\
             hot_max_per_tx = {}\nhot_max_per_window = {}\nhot_window_secs = {}\n\
             max_commitment_age_secs = 172800\npolicy_version = 1\n\
             pin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n\
             coordinator_auth_pubkey = \"{}\"\n{budget_toml}",
            node_key_toml(&node_kdf),
            channel::TEST_HOT_BUDGET.max_per_tx_sat,
            channel::TEST_HOT_BUDGET.max_per_window_sat,
            channel::TEST_HOT_BUDGET.window_secs,
            argon2id_normal_phc("1234"),
            argon2id_duress_phc("9999"),
            coord_key().1,
        );
        let node = load_node(&config).expect("valid config");
        let escape_spk = escape
            .at_derivation_index(0)
            .expect("definite")
            .script_pubkey();
        // The spend and its MANDATORY escape (§4): one vault input, paid to the hot
        // wallet and to the escape wallet respectively. Both user-signed, as a real
        // coordinator composes them.
        let spend = spend_to(&node, hot_spk);
        let escape_psbt = spend_to(&node, escape_spk);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut request = SignRequest {
            psbt: spend.to_string(),
            escape_psbt: escape_psbt.to_string(),
            escape_bumps: Vec::new(),
            pin: "1234".into(),
            nonce: String::new(),
            expiry: now + 3_600,
            policy_version: 1,
            coord_sig: String::new(),
        };
        coord_sign(&mut request, &node.wallet_id, "test-support-first-send");
        (node, request)
    }

    /// The fixture spend redirected to a NON-allowlisted destination, re-signed by
    /// the user and the coordinator over the theft's exact bytes. Everything a
    /// thief holding the user key and the PIN can produce; only the allowlist stops
    /// it, so the node's verdict is `DEST_NOT_ALLOWED` and nothing else.
    pub(crate) fn theft_request(node: &Node, spend: &SignRequest) -> SignRequest {
        let mut psbt = Psbt::from_str(&spend.psbt).expect("fixture psbt");
        // A P2WSH of a hash no descriptor in this vault can derive.
        psbt.unsigned_tx.output[0].script_pubkey =
            ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([0xEE; 32]));
        user_sign_all(node, &mut psbt);
        let mut request = SignRequest {
            psbt: psbt.to_string(),
            ..spend.clone()
        };
        coord_sign(&mut request, &node.wallet_id, "test-support-theft");
        request
    }

    /// A user-signed one-input vault spend paying `dest_spk`.
    fn spend_to(node: &Node, dest_spk: ScriptBuf) -> Psbt {
        let value = Amount::from_sat(100_000_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                script_pubkey: dest_spk,
                value: Amount::from_sat(99_990_000),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: node.vault_scripts()[0].clone(),
            value,
        });
        psbt.inputs[0].witness_script = Some(node.witness_script.clone());
        user_sign_all(node, &mut psbt);
        psbt
    }
}

#[cfg(test)]
mod commitment_parity_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::Sequence;

    #[test]
    fn commitment_serialization_round_trips_and_id_is_stable() {
        // T4 round-trip: the canonical encoding is deterministic and total, so
        // a commitment that is serialized and deserialized re-derives the
        // identical `commitment_id`. (A hand-copied "coordinator" builder was
        // dropped in review — with no independent producer before V0-8 it only
        // tested a copy against itself; the real coordinator-vs-node parity
        // test lands in V0-8a where vault-cli first builds a Commitment. The
        // three mutation tests below carry the load-bearing proof that each new
        // tx field changes the id.)
        let (node, request) = test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let built = commitment_of(&node, &psbt, request.expiry);
        let id = built.commitment_id();

        let json = serde_json::to_string(&built).expect("serialize commitment");
        let restored: Commitment = serde_json::from_str(&json).expect("deserialize commitment");

        assert_eq!(
            restored, built,
            "serde round-trip must preserve the commitment value"
        );
        assert_eq!(
            restored.commitment_id(),
            id,
            "serde round-trip must preserve the canonical commitment id"
        );
    }

    #[test]
    fn changing_only_tx_version_changes_the_commitment_id() {
        let (node, request) = test_support::node_and_valid_request();
        let base = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let mut variant = base.clone();
        variant.unsigned_tx.version = Version::ONE;

        assert_ne!(
            commitment_of(&node, &base, request.expiry).commitment_id(),
            commitment_of(&node, &variant, request.expiry).commitment_id(),
            "nVersion must change the commitment id"
        );
    }

    #[test]
    fn changing_only_lock_time_changes_the_commitment_id() {
        let (node, request) = test_support::node_and_valid_request();
        let base = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let mut variant = base.clone();
        variant.unsigned_tx.lock_time = LockTime::from_consensus(500_000);

        assert_ne!(
            commitment_of(&node, &base, request.expiry).commitment_id(),
            commitment_of(&node, &variant, request.expiry).commitment_id(),
            "nLockTime must change the commitment id"
        );
    }

    #[test]
    fn changing_only_one_input_sequence_changes_the_commitment_id() {
        let (node, request) = test_support::node_and_valid_request();
        let base = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let mut variant = base.clone();
        variant.unsigned_tx.input[0].sequence = Sequence::from_consensus(0xffff_fffd);

        assert_ne!(
            commitment_of(&node, &base, request.expiry).commitment_id(),
            commitment_of(&node, &variant, request.expiry).commitment_id(),
            "a single input's nSequence must change the commitment id"
        );
    }
}

#[cfg(test)]
mod config_bounds_tests {
    use super::test_support::{
        config_with_bounds, fixture_node_key, fixture_preimage, load_node, node_key_toml,
    };
    use super::{nodekey, Node, PublicKey, Secp256k1};

    /// The wskdf key path, end to end and on the node's own terms: the config names
    /// a DERIVATION, and the key the node ends up holding is exactly the descriptor
    /// key that derivation produces.
    #[test]
    fn the_wskdf_derived_key_is_the_node_key_the_descriptor_names() {
        let config = config_with_bounds(0, 172_800, "");
        assert!(
            !config.contains("node_seckey"),
            "the retired at-rest key field must not be in any config"
        );
        let (params, expected_seckey, expected_pubkey) = fixture_node_key(2);
        assert!(config.contains(&format!("node_key_salt = \"{}\"", params.salt_hex())));
        assert!(
            !config.contains(&expected_seckey.display_secret().to_string()),
            "no key material at rest"
        );

        let node = load_node(&config).expect("the right preimage loads");
        assert_eq!(
            node.pubkey, expected_pubkey,
            "the node holds the key its config's derivation produces"
        );
        assert!(
            config.contains(&expected_pubkey.to_string()),
            "and that key is one the frozen descriptor names"
        );
    }

    /// FAIL CLOSED on the wrong secret. A node that booted with a key no descriptor
    /// names would authenticate, validate, and "sign" every request while producing
    /// partials that can never combine: the federation would look healthy and no
    /// spend would ever complete, with nothing on the wire to say why. It must
    /// refuse to start instead.
    #[test]
    fn a_wrong_preimage_refuses_to_start_rather_than_signing_with_a_stranger_key() {
        let config = config_with_bounds(0, 172_800, "");
        let wrong = nodekey::Preimage::from_hex("0000000000000001").expect("a valid preimage");
        let err = Node::from_toml_str(&config, &wrong)
            .err()
            .expect("a key the descriptor does not name must not boot");
        assert!(
            err.to_string()
                .contains("not one of the vault descriptor's"),
            "the refusal must name the cause: {err}"
        );
    }

    /// The derivation parameters are load-time validated like every other config
    /// bound, so nonsense fails at startup rather than inside Argon2id.
    #[test]
    fn malformed_node_key_derivation_parameters_are_a_fatal_config() {
        let (params, _, _) = fixture_node_key(2);
        let good = node_key_toml(&params);
        for (what, broken) in [
            ("salt", good.replace(&params.salt_hex(), "00")),
            ("ops", good.replace("node_key_ops = 1", "node_key_ops = 0")),
            (
                "memory",
                good.replace("node_key_mem_kib = 8", "node_key_mem_kib = 1"),
            ),
        ] {
            let config = config_with_bounds(0, 172_800, "").replace(&good, &broken);
            assert!(
                Node::from_toml_str(&config, &fixture_preimage()).is_err(),
                "a broken {what} must be a fatal config"
            );
        }
        // And the fixture's own parameters really do derive the fixture key, so the
        // negatives above are about the mutation and not about a broken baseline.
        let secp = Secp256k1::new();
        let derived = nodekey::derive(&fixture_preimage(), &params).expect("derive");
        assert_eq!(
            PublicKey::new(derived.public_key(&secp)),
            fixture_node_key(2).2
        );
    }

    /// A zero-width combine window is a silent broadcast trap, so it is a fatal
    /// config, not a runtime surprise.
    #[test]
    fn a_zero_combine_slack_is_a_fatal_config() {
        let err = load_node(&config_with_bounds(0, 172_800, "combine_slack_secs = 0\n"))
            .err()
            .expect("zero combine slack must be rejected at load");
        assert!(
            err.to_string().contains("combine_slack_secs"),
            "unexpected config error: {err}"
        );
    }

    /// A combine window shorter than TWICE the vault cache refresh interval
    /// (`SCAN_INTERVAL`) is a silent duress-to-recovery trap: a block near the fire event
    /// leaves the cache stale for the whole window, so the escape coverage check fails
    /// every tick and the armed escape is pruned before the next refresh. The floor is 2×
    /// (not 1×) because the refresher ticks from pass completion, so the worst-case gap
    /// exceeds one interval (v0-exit 9y5.3 review, codex/Fable pass 4). A value of exactly
    /// one interval — accepted under the old 1× floor — must now be rejected.
    #[test]
    fn a_combine_slack_shorter_than_twice_the_cache_refresh_interval_is_a_fatal_config() {
        let short = 2 * crate::watchtower::SCAN_INTERVAL.as_secs() - 1;
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            &format!("combine_slack_secs = {short}\n"),
        ))
        .err()
        .expect("a sub-refresh-interval combine window must be rejected at load");
        assert!(
            err.to_string().contains("combine_slack_secs"),
            "unexpected config error: {err}"
        );
    }

    /// Zero makes every refresh mark prune immediately and the interval predicate
    /// impossible to trip, disabling ADR-0013 §6's burn-rate bound.
    #[test]
    fn a_zero_refresh_interval_is_a_fatal_config() {
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            "refresh_min_interval_secs = 0\n",
        ))
        .err()
        .expect("zero refresh interval must be rejected at load");
        assert!(
            err.to_string().contains("refresh_min_interval_secs"),
            "unexpected config error: {err}"
        );
    }

    /// If the EXPIRY_TOO_SHORT floor (`hold + slack`) exceeds the node's own expiry
    /// cap, every hot spend is silently refused — also a fatal config.
    #[test]
    fn hold_plus_slack_past_max_commitment_age_is_a_fatal_config() {
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            "combine_slack_secs = 200000\n",
        ))
        .err()
        .expect("hold + slack past the expiry cap must be rejected at load");
        let err = err.to_string();
        assert!(
            err.contains("combine_slack_secs") && err.contains("max_commitment_age_secs"),
            "unexpected config error: {err}"
        );
    }

    /// The default combine slack (60) leaves a usable window, so the same config
    /// with no override loads.
    #[test]
    fn the_default_combine_slack_still_loads() {
        load_node(&config_with_bounds(0, 172_800, ""))
            .expect("a config on the default combine slack is valid");
    }

    /// A `duress_delay_secs` past the node's own commitment-age cap keeps the
    /// constant-observable escape slot's expiry exemption (`prune`'s
    /// `exempt_delayed_context`) open beyond the candidates' OWN expiry, so ordinary
    /// traffic could accumulate un-prunable escape+spend pairs and exhaust the bounded
    /// candidate store — a silent break of requirement 7's capacity-cap guarantee.
    /// Reject it at load (Reviewer round-12 P1).
    #[test]
    fn duress_delay_past_max_commitment_age_is_a_fatal_config() {
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            "duress_delay_secs = 172801\n",
        ))
        .err()
        .expect("a duress delay past the commitment-age cap must be rejected at load");
        let err = err.to_string();
        assert!(
            err.contains("duress_delay_secs") && err.contains("max_commitment_age_secs"),
            "unexpected config error: {err}"
        );
    }

    /// A duress delay exactly at the cap is the boundary the guard permits: the escape
    /// slot's exemption then closes within the same `combine_slack` overrun the
    /// armed-escape reconciliation already grants, adding no capacity pressure beyond
    /// ordinary operation.
    #[test]
    fn duress_delay_at_max_commitment_age_still_loads() {
        load_node(&config_with_bounds(
            0,
            172_800,
            "duress_delay_secs = 172800\n",
        ))
        .expect("a duress delay equal to the commitment-age cap is valid");
    }

    /// A positive panic feerate requires a positive fee, while 100% output coverage
    /// leaves no protected satoshi available to pay it. The pair is unsatisfiable.
    #[test]
    fn full_coverage_with_a_positive_feerate_floor_is_a_fatal_config() {
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            "escape_coverage_pct = 100\nescape_feerate_floor = 1\n",
        ))
        .err()
        .expect("an impossible coverage/fee pair must be rejected at load");
        let err = err.to_string();
        assert!(
            err.contains("escape_coverage_pct") && err.contains("escape_feerate_floor"),
            "unexpected config error: {err}"
        );
    }

    /// Security-sensitive top-level options must fail closed when misspelled,
    /// rather than being silently ignored by serde.
    #[test]
    fn an_unknown_top_level_config_field_is_fatal() {
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            "max_commitment_age_sec = 86400\n",
        ))
        .err()
        .expect("an unknown top-level field must be rejected at load");
        assert!(
            err.to_string().contains("max_commitment_age_sec"),
            "unexpected config error: {err}"
        );
    }

    /// A misspelled budget key must not fall back to the default attempt limit.
    #[test]
    fn an_unknown_pin_attempt_budget_field_is_fatal() {
        let err = load_node(&config_with_bounds(
            0,
            172_800,
            "[pin_attempt_budget]\nmax_attemps = 2\n",
        ))
        .err()
        .expect("an unknown pin-attempt-budget field must be rejected at load");
        assert!(
            err.to_string().contains("max_attemps"),
            "unexpected config error: {err}"
        );
    }
}

#[cfg(test)]
mod sign_clock_tests {
    use super::{handle_sign_after_lock, test_support::node_and_valid_request};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    #[test]
    fn queued_sign_reads_the_clock_only_after_acquiring_sign_state() {
        let (node, request) = node_and_valid_request();
        let now = request.expiry;
        let node = Arc::new(node);
        let worker_node = Arc::clone(&node);
        let state = node.sign_state.lock().expect("sign_state lock");
        let (started_tx, started_rx) = mpsc::channel();
        let (clock_tx, clock_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("worker started");
            handle_sign_after_lock(&worker_node, &request, || {
                clock_tx.send(()).expect("clock read");
                now
            })
        });

        started_rx.recv().expect("worker start");
        assert!(clock_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(state);
        clock_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("clock read after lock");
        worker
            .join()
            .expect("worker thread")
            .expect("valid request");
    }
}

/// V0-4a substrate: the constant-cost pin compare, the per-node attempt budget, and
/// terminal Lockdown, exercised through the real `handle_sign`/`handle_refresh`
/// handlers. The transition-table arithmetic and the digest validation live in
/// [`pin`]'s own unit tests; this module proves the node GLUE — that the handler
/// runs two Argon2 evaluations per SpendRequest, charges the budget only on wrong
/// pins, refuses a locked-out node while still arming under a valid duress pin, and
/// answers FRAUD_SUSPECTED once locked down.
#[cfg(test)]
mod pin_substrate_tests {
    use super::pin::{PinEvaluator, PinSlot};
    use super::test_support::{
        coord_sign, load_node, node_and_valid_request, node_and_valid_request_with_budget,
        test_wallet_id, valid_refresh_request,
    };
    use super::{handle_refresh, handle_sign, Node};
    use std::sync::Arc;
    use subtle::Choice;
    use vault_proto::{RefusalCode, SignRequest, SignResponse, MAX_PIN_BYTES};

    /// The normal pin every fixture node enrols (`node_and_valid_request`).
    const NORMAL: &str = "1234";
    /// The enrolled duress pin.
    const DURESS: &str = "9999";
    /// A pin that matches neither.
    const WRONG: &str = "0000";

    /// A small attempt budget with a ZERO backoff, so the handler tests exercise
    /// lockout without any real sleeping.
    const SMALL_BUDGET: &str = "[pin_attempt_budget]\nmax_attempts = 3\nwindow_secs = 3600\n\
         backoff_schedule = [0, 0, 0]\nlockout_secs = 100\n";

    /// Clone `base`, set `pin`, and re-coord-sign under a fresh `nonce` (changing the
    /// pin invalidates the coordinator signature, since the pin is in its preimage).
    fn with_pin(base: &SignRequest, pin: &str, nonce: &str) -> SignRequest {
        let mut request = base.clone();
        request.pin = pin.into();
        // `with_pin` holds no `node`; every fixture here feeds the standard test
        // vault, whose id is `test_wallet_id()` (== that node's `wallet_id`).
        coord_sign(&mut request, &test_wallet_id(), nonce);
        request
    }

    fn expect_refusal(response: SignResponse) -> vault_proto::Refusal {
        match response {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    /// PRIMARY structural constant-cost test: every SpendRequest — normal, duress, or
    /// wrong — runs EXACTLY two Argon2 evaluations, in the fixed order [Normal,
    /// Duress]. A short-circuit compare would make duress run only one (or one
    /// more), which the counting evaluator would catch here without a flaky clock.
    #[test]
    fn every_spendrequest_runs_two_argon2_evaluations_in_a_fixed_order() {
        use super::pin::test_util::CountingEvaluator;
        let (mut node, base) = node_and_valid_request();
        let now = base.expiry - 3_600;
        let counting = Arc::new(CountingEvaluator::new(node.pin_evaluator()));
        let calls = Arc::clone(&counting.calls);
        node.set_pin_evaluator(counting);

        for (i, pin) in [NORMAL, DURESS, WRONG].into_iter().enumerate() {
            calls.lock().expect("calls").clear();
            let request = with_pin(&base, pin, &format!("count-{i}"));
            let _ = handle_sign(&node, &request, now).expect("decodable");
            assert_eq!(
                *calls.lock().expect("calls"),
                vec![PinSlot::Normal, PinSlot::Duress],
                "pin {pin} must run exactly two Argon2 evaluations, Normal then Duress"
            );
        }

        calls.lock().expect("calls").clear();
        let over_length = "x".repeat(MAX_PIN_BYTES + 1);
        let request = with_pin(&base, &over_length, "count-over-length");
        let _ = handle_sign(&node, &request, now).expect("decodable");
        assert_eq!(
            *calls.lock().expect("calls"),
            vec![PinSlot::Normal, PinSlot::Duress],
            "an over-length authenticated SpendRequest must not bypass either evaluation"
        );
    }

    /// The memory-hard carrier identity exists solely for channel confirmation.
    /// Absent-channel fixtures have no intent map or receipt path, so computing a
    /// third Argon2 result there would be pure cost with no security effect.
    #[test]
    fn absent_channel_mode_does_not_derive_an_unused_carrier_id() {
        let (node, request) = node_and_valid_request();
        assert_eq!(node.carrier_derivation_count(), 0);
        assert!(matches!(
            handle_sign(&node, &request, request.expiry - 3_600).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        assert_eq!(
            node.carrier_derivation_count(),
            0,
            "no channel means no carrier identity consumer"
        );
    }

    /// An omitted PIN decodes as empty. Even if provisioning enrolled the empty
    /// plaintext, the protocol boundary must classify it as Wrong only AFTER both
    /// evaluations, so omission can never authenticate or bypass the budget.
    #[test]
    fn an_empty_pin_is_wrong_even_if_the_enrolled_normal_digest_matches_it() {
        struct EmptyMatchesNormal;

        impl PinEvaluator for EmptyMatchesNormal {
            fn evaluate(&self, slot: PinSlot, pin: &[u8]) -> Choice {
                Choice::from((slot == PinSlot::Normal && pin.is_empty()) as u8)
            }
        }

        use super::pin::test_util::CountingEvaluator;
        let (mut node, base) = node_and_valid_request();
        let counting = Arc::new(CountingEvaluator::new(Arc::new(EmptyMatchesNormal)));
        let calls = Arc::clone(&counting.calls);
        node.set_pin_evaluator(counting);

        let response = handle_sign(
            &node,
            &with_pin(&base, "", "empty-enrolled-normal"),
            base.expiry - 3_600,
        )
        .expect("decodable");
        assert_eq!(expect_refusal(response).code, RefusalCode::BadPin);
        assert_eq!(
            *calls.lock().expect("calls"),
            vec![PinSlot::Normal, PinSlot::Duress],
            "empty input still performs both fixed-order evaluations"
        );
        assert_eq!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pin_budget
                .fails(),
            1,
            "empty input consumes the wrong-pin budget"
        );
        assert_eq!(node.duress_arm_count(), 0, "empty input never arms duress");
    }

    /// Budget instrumentation: the budget is touched exactly once per SpendRequest,
    /// and normal and duress leave IDENTICAL budget state (both no-ops) — only a
    /// wrong pin changes the logical wrong-count. This is the same-shaped-work
    /// property (codex C3): the two SILENT classes are indistinguishable in the
    /// budget, and only a wrong pin (which is neither PIN) diverges.
    #[test]
    fn the_budget_is_charged_once_and_normal_equals_duress() {
        let read = |node: &Node| {
            let state = node.sign_state.lock().expect("sign_state");
            (
                state.pin_budget.charges(),
                state.pin_budget.fails(),
                state.pin_budget.locked_until(),
            )
        };

        let (node_n, base_n) = node_and_valid_request();
        let now = base_n.expiry - 3_600;
        handle_sign(&node_n, &with_pin(&base_n, NORMAL, "n"), now).expect("decodable");

        let (node_d, base_d) = node_and_valid_request();
        handle_sign(&node_d, &with_pin(&base_d, DURESS, "d"), now).expect("decodable");

        let (node_w, base_w) = node_and_valid_request();
        handle_sign(&node_w, &with_pin(&base_w, WRONG, "w"), now).expect("decodable");

        assert_eq!(
            read(&node_n),
            (1, 0, 0),
            "a normal pin charges once and consumes nothing"
        );
        assert_eq!(
            read(&node_n),
            read(&node_d),
            "normal and duress leave identical budget state — no observable difference"
        );
        assert_eq!(
            read(&node_w),
            (1, 1, 0),
            "only a wrong pin advances the wrong-count"
        );
    }

    /// The attempt-budget lifecycle through the handler (the normative table): a
    /// wrong-pin flood reaches lockout; a locked-out node refuses a valid NORMAL pin
    /// while a valid DURESS pin STILL invokes the arm-hook (fail-closed); and the
    /// node recovers after `lockout_secs`.
    #[test]
    fn wrong_pin_flood_locks_out_then_recovers_and_duress_still_arms_while_locked() {
        let (node, base) = node_and_valid_request_with_budget(SMALL_BUDGET);
        let now = base.expiry - 3_600;

        // Three wrong pins (max_attempts = 3) trip the lockout.
        for i in 0..3 {
            let refusal = expect_refusal(
                handle_sign(&node, &with_pin(&base, WRONG, &format!("wrong-{i}")), now)
                    .expect("decodable"),
            );
            assert_eq!(refusal.code, RefusalCode::BadPin, "a wrong pin is BAD_PIN");
        }

        // A valid NORMAL pin is now refused (locked out) — and its refusal is the
        // same BAD_PIN a wrong pin gets, so lockout leaks nothing about the pin.
        let locked_normal = expect_refusal(
            handle_sign(&node, &with_pin(&base, NORMAL, "normal-locked"), now).expect("decodable"),
        );
        assert_eq!(locked_normal.code, RefusalCode::BadPin);
        assert_eq!(
            locked_normal.check, "pin_attempt_budget",
            "a locked-out refusal is a rate-limit denial, not an ordinary bad pin"
        );

        // A valid DURESS pin is ALSO refused while locked, but STILL arms (fail-closed).
        let arm_before = node.duress_arm_count();
        let locked_duress = expect_refusal(
            handle_sign(&node, &with_pin(&base, DURESS, "duress-locked"), now).expect("decodable"),
        );
        assert_eq!(locked_duress.code, RefusalCode::BadPin);
        assert_eq!(
            node.duress_arm_count(),
            arm_before + 1,
            "a valid duress pin must record its arm intent even when the node is locked out, so \
             it can still arm on t-confirmation (fail-closed)"
        );

        // After lockout_secs the node recovers and a valid normal pin signs again.
        let recovered = handle_sign(
            &node,
            &with_pin(&base, NORMAL, "normal-recovered"),
            now + 100,
        )
        .expect("decodable");
        assert!(
            matches!(recovered, SignResponse::Accepted(_)),
            "the node must recover after lockout_secs: got {recovered:?}"
        );
    }

    /// Fail-closed / subordination: a pin-less refresh never touches the pin budget
    /// (it performs no pin compare at all — codex C2), so a refresh flood can neither
    /// consume the budget nor lock the node out of signing.
    #[test]
    fn a_refresh_never_touches_the_pin_budget() {
        let (node, spend) = node_and_valid_request();
        let refresh = valid_refresh_request(&node, &spend, "refresh-budget");
        let now = spend.expiry - 3_600;
        let response = handle_refresh(&node, &refresh, now).expect("decodable");
        assert!(
            matches!(response, SignResponse::Accepted(_)),
            "the refresh is valid"
        );
        assert_eq!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pin_budget
                .charges(),
            0,
            "the pin-less refresh path performs NO pin compare and cannot touch the budget"
        );
    }

    /// Lockdown is terminal (ADR-0008): once entered, every spend AND refresh answers
    /// FRAUD_SUSPECTED for the node's lifetime, with no reset.
    #[test]
    fn lockdown_refuses_every_spend_and_refresh_with_fraud_suspected() {
        let (node, spend) = node_and_valid_request();
        let refresh = valid_refresh_request(&node, &spend, "lockdown-refresh");
        let now = spend.expiry - 3_600;

        node.enter_lockdown();

        let spend_refusal = expect_refusal(
            handle_sign(&node, &with_pin(&spend, NORMAL, "ld-spend"), now).expect("decodable"),
        );
        assert_eq!(spend_refusal.code, RefusalCode::FraudSuspected);
        let refresh_refusal =
            expect_refusal(handle_refresh(&node, &refresh, now).expect("decodable"));
        assert_eq!(refresh_refusal.code, RefusalCode::FraudSuspected);

        // No reset: a second attempt is still FRAUD_SUSPECTED.
        assert!(node.is_locked_down());
        let again = expect_refusal(
            handle_sign(&node, &with_pin(&spend, NORMAL, "ld-again"), now).expect("decodable"),
        );
        assert_eq!(again.code, RefusalCode::FraudSuspected);
    }

    /// A locked-down node does not even reach the budget: FRAUD_SUSPECTED short-
    /// circuits before the pin compare, so Lockdown is not gated by (nor does it
    /// interact with) the attempt budget.
    #[test]
    fn lockdown_short_circuits_before_the_pin_budget() {
        let (node, spend) = node_and_valid_request();
        let now = spend.expiry - 3_600;
        node.enter_lockdown();
        handle_sign(&node, &with_pin(&spend, WRONG, "ld-wrong"), now).expect("decodable");
        assert_eq!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pin_budget
                .charges(),
            0,
            "Lockdown answers FRAUD_SUSPECTED before any pin/budget work runs"
        );
    }

    /// The config-validation wiring: a non-argon2id pin digest (the old SHA-256
    /// placeholder) is a fatal config error, not a silently-weakened compare.
    #[test]
    fn a_non_argon2id_pin_digest_is_a_fatal_config() {
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        let bad = config.replacen(&crate::argon2id_normal_phc("1234"), "deadbeef", 1);
        let err = load_node(&bad)
            .err()
            .expect("a SHA-256 digest must be rejected");
        assert!(
            err.to_string().contains("pin_normal_hash"),
            "unexpected error: {err}"
        );
    }

    /// A `max_attempts = 0` budget is fatal (the table's `max_attempts-1` index would
    /// be undefined).
    #[test]
    fn a_zero_max_attempts_budget_is_a_fatal_config() {
        let err = load_node(&super::test_support::config_with_bounds(
            0,
            172_800,
            "[pin_attempt_budget]\nmax_attempts = 0\n",
        ))
        .err()
        .expect("max_attempts = 0 must be rejected");
        assert!(
            err.to_string().contains("max_attempts"),
            "unexpected error: {err}"
        );
    }

    /// An empty `backoff_schedule` is fatal (`len-1` would be undefined).
    #[test]
    fn an_empty_backoff_schedule_is_a_fatal_config() {
        let err = load_node(&super::test_support::config_with_bounds(
            0,
            172_800,
            "[pin_attempt_budget]\nbackoff_schedule = []\n",
        ))
        .err()
        .expect("an empty backoff_schedule must be rejected");
        assert!(
            err.to_string().contains("backoff_schedule"),
            "unexpected error: {err}"
        );
    }
}

/// Reboot-death (codex C5): the entire node deployment — OS image, binary, config
/// (the wskdf derivation PARAMETERS; the signing key itself is derived into RAM from
/// the operator's stdin preimage and is never at rest, bead 9y5.5), and every piece
/// of runtime state — lives on tmpfs (ADR-0007), so a reboot leaves a BARE machine.
/// The attempt budget dies with the in-RAM signing key in the same stroke; the node
/// cannot restart or rejoin the vault.
///
/// Lockdown and the pin-independent one-shot generation marker are attributes on the
/// tmpfs config inode, with durability EQUAL to the derivation parameters' — and thus
/// to the in-RAM signing key's, which cannot outlive them. A MACHINE
/// reboot wipes all three (node death), while a PROCESS restart cannot reload the key
/// after RAM-only Armed/candidate state may have existed. The latch remains
/// independently verified below: any explicit lower-level adoption of surviving
/// tmpfs state observes Lockdown rather than an unlocked state.
#[cfg(test)]
mod reboot_death_tests {
    use super::test_support::load_node;
    use super::{read_xattr, File, Node, GENERATION_XATTR, LOCKDOWN_XATTR};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btc-policy-v04a-reboot-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch RAMDISK dir");
        dir
    }

    #[test]
    fn a_reboot_destroys_the_config_and_the_node_cannot_rejoin() {
        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config).expect("write config to the RAMDISK");

        // While the RAMDISK holds its config (the derivation parameters) the node
        // loads — deriving its key in RAM from the fixture preimage — and can be
        // driven into terminal Lockdown.
        let node =
            load_node(&std::fs::read_to_string(&path).expect("read config")).expect("valid config");
        node.enter_lockdown();
        assert!(node.is_locked_down());

        // Reboot = tmpfs wiped: destroy the config (the derivation parameters and
        // their inode-attached lifecycle attributes; the signing key was only ever in
        // RAM) and the whole deployment dir.
        std::fs::remove_file(&path).expect("wipe config");
        std::fs::remove_dir(&dir).expect("wipe RAMDISK dir");

        // The rebooted machine is bare — no config, no key, no Lockdown flag. It
        // cannot restart against the vault; `load` has nothing to read. This is the
        // machine-reboot edge (config GONE), strictly stronger than Lockdown.
        let err = Node::load(path.to_str().expect("utf-8 path"))
            .err()
            .expect("a rebooted node with no config cannot restart");
        assert!(
            err.to_string().contains("cannot read config"),
            "a rebooted node holds no key/config/budget/lockdown and cannot rejoin: {err}"
        );
    }

    /// Armed/candidate state is process memory while the signing key is in the
    /// tmpfs config. A supervisor respawn before T must therefore be node death,
    /// not an unarmed signer reload. The marker is present on every launch (never a
    /// duress bit), atomic across competing processes, and dies with the key when
    /// the deployment tmpfs is wiped.
    #[test]
    fn a_second_process_generation_cannot_reload_the_live_signing_key() {
        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let symlink = dir.join("node-symlink.toml");
        let hardlink = dir.join("node-hardlink.toml");
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config).expect("write config to the RAMDISK");
        std::os::unix::fs::symlink(&path, &symlink).expect("create config symlink");
        std::fs::hard_link(&path, &hardlink).expect("create config hardlink");

        let mut first = load_node(&config).expect("valid config");
        first
            .apply_persisted_lockdown(
                File::open(&path).expect("open config inode"),
                path.as_path(),
            )
            .expect("bind first generation");
        first
            .claim_process_generation()
            .expect("first generation claims the key");
        assert_eq!(
            read_xattr(
                first.lifecycle_file.as_ref().expect("lifecycle file"),
                GENERATION_XATTR,
            )
            .expect("read generation marker")
            .as_deref(),
            Some(b"claimed\n".as_slice())
        );

        let err = first
            .claim_process_generation()
            .expect_err("a process restart must not reconstruct an empty Armed overlay");
        assert!(
            err.to_string().contains("refusing to reload a signing key"),
            "the fail-closed refusal must name the lost RAM-only state: {err}"
        );

        for alias in [&symlink, &hardlink] {
            let mut through_alias = load_node(&config).expect("valid config");
            through_alias
                .apply_persisted_lockdown(
                    File::open(alias).expect("open config alias"),
                    alias.as_path(),
                )
                .expect("bind alias to lifecycle inode");
            let err = through_alias
                .claim_process_generation()
                .expect_err("an alias must not bypass the one-shot generation gate");
            assert!(
                err.to_string().contains("refusing to reload a signing key"),
                "symlink/hardlink alias selected a different generation gate: {err}"
            );
        }

        // Machine reboot: config/key inode + attributes disappear together.
        drop(first);
        std::fs::remove_file(symlink).expect("reboot wipes symlink");
        std::fs::remove_file(hardlink).expect("reboot wipes hardlink");
        std::fs::remove_file(path).expect("reboot wipes config and key");
        std::fs::remove_dir(dir).expect("reboot wipes deployment tmpfs");
    }

    /// A startup that fails AFTER `load` but BEFORE the generation is claimed — the
    /// classic transient listener-bind failure on a node that never served and never
    /// armed — must NOT consume the one-shot generation, or a single flaky bind would
    /// permanently brick the tmpfs key. The public serving boundary claims the
    /// generation only once the bind succeeds; `Node::load` deliberately does NOT
    /// claim it. This exercises the `apply_persisted_lockdown` +
    /// `claim_process_generation` seam that `load` drives, minus the deferred claim.
    #[test]
    fn a_startup_that_fails_before_claiming_leaves_the_generation_available() {
        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config).expect("write config to the RAMDISK");

        // Attempt 1 does everything `load` does — parse + adopt any latch — then a
        // later fallible startup step (the listener bind) fails, so the process exits
        // WITHOUT ever reaching `claim_process_generation`.
        let mut attempt1 = load_node(&config).expect("valid config");
        attempt1
            .apply_persisted_lockdown(File::open(&path).expect("open config"), path.as_path())
            .expect("attempt 1 adopts the latch");
        drop(attempt1); // bind failed → the generation was never claimed.

        // Attempt 2 (the operator's retry) reloads cleanly and CAN claim the still
        // -available generation: the failed first attempt did not brick the key.
        let mut attempt2 = load_node(&config).expect("valid config");
        attempt2
            .apply_persisted_lockdown(File::open(&path).expect("open config"), path.as_path())
            .expect("attempt 2 adopts the latch");
        attempt2
            .claim_process_generation()
            .expect("the retry claims the still-available one-shot generation");

        // The one-shot property is intact: once claimed, a second claim is refused,
        // so a post-serve restart is still node death.
        let err = attempt2
            .claim_process_generation()
            .expect_err("the generation is one-shot once actually claimed");
        assert!(
            err.to_string().contains("refusing to reload a signing key"),
            "the one-shot refusal must name the lost RAM-only state: {err}"
        );

        drop(attempt2);
        std::fs::remove_file(&path).expect("reboot wipes config and key");
        std::fs::remove_dir(&dir).expect("reboot wipes deployment tmpfs");
    }

    /// `/healthz`'s `generation_claimed` field IS this marker, not a proxy for it
    /// (bead btc-policy-9y5.6): an operator reads it as "this is the sealed node that
    /// was provisioned", so it must be true exactly when the inode records a claim.
    ///
    /// A FAILED claim reporting `true` would be the damaging direction — it would
    /// vouch for reboot-death on a node that never took the generation — so the
    /// path-less and refused-second-claim cases are both pinned here.
    #[test]
    fn health_reports_the_claimed_process_generation() {
        // Path-less construction: no config inode, so no generation, and the field
        // says so rather than assuming the daemon shape.
        let unclaimed = load_node(&super::test_support::config_with_bounds(0, 172_800, ""))
            .expect("valid config");
        assert!(!unclaimed.health().generation_claimed);
        assert!(
            unclaimed.claim_process_generation().is_err(),
            "a node with no config inode cannot claim a generation"
        );
        assert!(
            !unclaimed.health().generation_claimed,
            "a failed claim must never report a claimed generation"
        );

        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config).expect("write config to the RAMDISK");
        let mut node = load_node(&config).expect("valid config");
        node.apply_persisted_lockdown(File::open(&path).expect("open config"), path.as_path())
            .expect("bind the lifecycle inode");
        assert!(
            !node.health().generation_claimed,
            "binding the inode is not claiming the generation"
        );

        node.claim_process_generation()
            .expect("the first generation is claimable");
        assert!(node.health().generation_claimed);
        assert_eq!(
            read_xattr(
                node.lifecycle_file.as_ref().expect("lifecycle file"),
                GENERATION_XATTR,
            )
            .expect("read generation marker")
            .as_deref(),
            Some(b"claimed\n".as_slice()),
            "the reported field must match what the inode actually records"
        );

        // The one-shot refusal must not un-claim what this process already holds.
        assert!(node.claim_process_generation().is_err());
        assert!(node.health().generation_claimed);

        drop(node);
        std::fs::remove_file(&path).expect("reboot wipes config and key");
        std::fs::remove_dir(&dir).expect("reboot wipes deployment tmpfs");
    }

    /// Independently verify the Lockdown latch primitive. Production's generation
    /// gate rejects this second process before it can serve; directly exercising
    /// `apply_persisted_lockdown` proves that any lower-level state adoption still
    /// cannot turn a surviving terminal latch into an unlocked signer.
    #[test]
    fn a_surviving_lockdown_latch_is_adopted_before_any_state_reuse() {
        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let config_str = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config_str).expect("write config to the RAMDISK");
        let alias = dir.join("node-hardlink.toml");
        std::fs::hard_link(&path, &alias).expect("create config hardlink");

        // Process 1 boots clean: apply_persisted_lockdown binds the config inode and
        // creates its empty latch attribute, then Lockdown fires.
        let mut p1 = load_node(&config_str).expect("valid config");
        p1.apply_persisted_lockdown(File::open(&path).expect("open config"), path.as_path())
            .expect("read latch");
        assert!(!p1.is_locked_down(), "a fresh node starts unlocked");
        assert!(
            read_xattr(
                p1.lifecycle_file.as_ref().expect("lifecycle file"),
                LOCKDOWN_XATTR,
            )
            .expect("read fresh latch")
            .is_some_and(|value| value.is_empty()),
            "the inode latch is empty (not locked) before enter_lockdown"
        );
        p1.enter_lockdown();
        assert!(p1.is_locked_down());
        assert!(
            read_xattr(
                p1.lifecycle_file.as_ref().expect("lifecycle file"),
                LOCKDOWN_XATTR,
            )
            .expect("read locked latch")
            .is_some_and(|value| !value.is_empty()),
            "enter_lockdown must persist a non-empty marker (durability = key durability)"
        );
        drop(p1); // the process dies — tmpfs (config + latch) is untouched.

        // A second in-memory object adopts the SURVIVING inode latch THROUGH A
        // HARDLINK. Production
        // would subsequently reject its process-generation claim, but even this
        // lower-level seam MUST read terminal Lockdown first.
        let mut p2 = load_node(&config_str).expect("valid config");
        assert!(
            !p2.is_locked_down(),
            "in-RAM default is unlocked before the flag is consulted"
        );
        p2.apply_persisted_lockdown(File::open(&alias).expect("open hardlink"), alias.as_path())
            .expect("read latch through hardlink");
        assert!(
            p2.is_locked_down(),
            "a process restart while locked (config survived) must reload LOCKED — \
             else a bare respawn resurrects an unlocked signer"
        );

        // Now a real reboot wipes the inode (and therefore the attribute) with
        // everything else. Recreate the config on a fresh inode: it starts unlocked.
        drop(p2);
        std::fs::remove_file(&alias).expect("reboot wipes hardlink");
        std::fs::remove_file(&path).expect("reboot wipes old config inode");
        std::fs::write(&path, &config_str).expect("fresh boot recreates config");
        let mut p3 = load_node(&config_str).expect("valid config");
        p3.apply_persisted_lockdown(
            File::open(&path).expect("open fresh config"),
            path.as_path(),
        )
        .expect("read fresh latch");
        assert!(
            !p3.is_locked_down(),
            "with the flag gone (reboot), a node is not spuriously locked"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
