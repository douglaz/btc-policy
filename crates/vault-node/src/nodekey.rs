//! The node's federation signing key: **wskdf-derived at startup, in memory only**.
//!
//! This module is what retires `node_seckey`-at-rest (DESIGN.md D4/T1; bead
//! btc-policy-9y5.5). The per-node config no longer carries a key — it carries the
//! PUBLIC derivation parameters (`node_key_salt`, `node_key_ops`,
//! `node_key_mem_kib`). The one secret, the **preimage**, is held by the operator
//! and reaches the daemon on **stdin** at startup, never on disk.
//!
//! ```text
//!   setup node-keygen (on the node host)      vault-node --config … (startup)
//!   ─────────────────────────────────────     ────────────────────────────────
//!   preimage  ← random, 63 bits               preimage  ← operator, on stdin
//!   salt      ← random, 16 bytes              salt/ops/mem ← config (public)
//!   seckey    = wskdf(preimage, salt, …)      seckey = wskdf(preimage, salt, …)
//!   PRINT the preimage once; publish only     the derived pubkey must be one of
//!   the PUBKEY + salt/ops/mem                 the descriptor's node keys, or fatal
//! ```
//!
//! ## Why a preimage at all, and why 63 bits
//!
//! The ceremony has to publish the node's PUBLIC key before the vault descriptor
//! exists, and the daemon that will use the matching secret is a *later process*.
//! Something has to carry the key across that gap without being at rest on the
//! host — so it is carried by the operator, and a wskdf preimage is small enough to
//! be carried on paper.
//!
//! wskdf is *deliberately* able to trade entropy for brute-force recoverability
//! (its README's central idea: lose the preimage, spend predictable CPU, get the
//! key back). **This use wants the opposite end of that dial.** A node whose
//! preimage is lost is a node that cannot start, and under reboot-death (ADR-0007)
//! a node that cannot start is simply dead — the federation absorbs it and the
//! vault rotates. There is nothing to recover, so recoverability buys nothing and
//! costs brute-force margin. [`PREIMAGE_BITS`] is therefore wskdf's MAXIMUM WIDTH
//! (63; its generator pins the top bit, so 62 bits of entropy — a 2^62 search
//! space), and the Argon2id cost below it — at a mandatory production floor — is
//! defence-in-depth on top of that, not the primary barrier.
//!
//! ## What is public and what is not
//!
//! `salt`, `ops`, and `mem_kib` are public: they sit in the per-node config, which
//! is a tmpfs artifact a host-level attacker already reads. They are not a second
//! secret and are not treated as one. The preimage is the whole secret, and the
//! only place it exists on the node is this process's memory, inside a
//! [`Zeroizing`] buffer, for the length of one derivation.
//!
//! One residual, stated rather than hidden: `wskdf_core::wskdf_derive_key` returns
//! the derived key by value and rust-argon2 allocates internally, so a copy of the
//! key material is dropped un-zeroized inside the derivation call. That copy lives
//! in the same address space that is about to hold the `SecretKey` itself, on a
//! host whose entire deployment is RAM-only and dies with the machine, so it widens
//! nothing: it is the same secret, in the same RAM, for the same node lifetime.

use std::io::Read;
use std::str::FromStr;

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::PublicKey;
use zeroize::Zeroizing;

use crate::Error;

/// Preimage width, in bytes — wskdf's fixed size.
pub const PREIMAGE_BYTES: usize = wskdf_core::PREIMAGE_SIZE;
/// Salt width, in bytes — wskdf's fixed size.
pub const SALT_BYTES: usize = wskdf_core::SALT_SIZE;

/// WIDTH of a node preimage: wskdf's maximum. wskdf's generator pins the top bit
/// (its recovery search treats this as an exact-width value), so the ENTROPY is one
/// bit less — 62 bits, a 2^62 search space — which stays infeasible under the
/// memory-hard Argon2id floor. See the module doc: this deployment wants no
/// brute-force recovery path, so it takes wskdf's widest preimage rather than
/// dialing the width down for recoverability.
pub const PREIMAGE_BITS: u8 = 63;

/// The ceremony's default Argon2id pass count and memory, and the PRODUCTION FLOOR
/// `setup node-keygen` enforces (below it refuses without `--allow-weak-kdf`). Chosen
/// for a pass on the order of a second on an ordinary host: enough that an offline
/// guesser pays real memory-hard cost per candidate, without making a node's one
/// startup derivation a visible outage. The 63-bit preimage is the primary barrier,
/// but security is the PRODUCT of preimage width and per-guess cost — after the
/// ceremony the public bundle exposes salt/ops/mem, so a cheap cost shrinks every
/// key's margin. The cost is therefore a required floor, not a free knob to lower.
pub const DEFAULT_KDF_OPS: u32 = 4;
/// Default Argon2id memory, in KiB (256 MiB).
pub const DEFAULT_KDF_MEM_KIB: u32 = 262_144;

/// Argon2id's own floor: rust-argon2 rejects less than 8 KiB per lane, and a zero
/// pass count is not a KDF at all. This is only the IMPLEMENTATION minimum — the
/// point below which the KDF will not run at all — so that test fixtures can derive
/// cheaply and a suite that builds hundreds of nodes stays fast. The PRODUCTION floor
/// (the defaults above) is a separate, higher bar enforced at the CLI in
/// `setup node-keygen`, which refuses below it unless a test/automation host opts in
/// with `--allow-weak-kdf`. Keeping the two apart is what lets fixtures stay fast
/// without letting a real ceremony silently seal an under-costed key.
const MIN_KDF_MEM_KIB: u32 = 8;

/// The operator-held wskdf preimage. Never written at rest by the daemon, never
/// logged, and wiped when it drops.
pub struct Preimage(Zeroizing<[u8; PREIMAGE_BYTES]>);

impl Preimage {
    /// A fresh preimage from wskdf's own generator: a value uniform in
    /// `[2^62, 2^63)` — a [`PREIMAGE_BITS`]-bit-WIDE number whose top bit wskdf pins.
    /// That pinning is the exact-width guarantee wskdf's recovery search relies on;
    /// here it means the ENTROPY is 62 bits (2^62 distinct values), not 63. wskdf
    /// caps the width at 63, so this is the most entropy its generator yields, and the
    /// security argument rests on 2^62 memory-hard Argon2id evaluations over the
    /// public bundle — which stays infeasible.
    pub fn generate() -> Result<Preimage, Error> {
        let bytes = wskdf_core::gen_rand_preimage(PREIMAGE_BITS)
            .map_err(|e| format!("cannot generate a node-key preimage: {e}"))?;
        Ok(Preimage(Zeroizing::new(bytes)))
    }

    /// Parse the operator's hand-carried form: exactly [`PREIMAGE_BYTES`] bytes as
    /// lowercase hex. Strict — a truncated or over-long preimage is a typo, and a
    /// typo that silently derived a DIFFERENT key would boot a node holding a key
    /// no descriptor names.
    pub fn from_hex(text: &str) -> Result<Preimage, Error> {
        let text = text.trim();
        if text.len() != PREIMAGE_BYTES * 2 {
            return Err(format!(
                "node-key preimage must be exactly {} hex characters ({PREIMAGE_BYTES} bytes), \
                 got {}",
                PREIMAGE_BYTES * 2,
                text.len()
            )
            .into());
        }
        let bytes = <[u8; PREIMAGE_BYTES]>::from_hex(text)
            .map_err(|e| format!("node-key preimage is not hex: {e}"))?;
        Ok(Preimage(Zeroizing::new(bytes)))
    }

    /// The operator's copy, to be written down and never stored. Zeroizing, so a
    /// caller that prints it does not leave it in a freed allocation.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.to_lower_hex_string())
    }

    /// Read one line of preimage from `reader` — the daemon's startup path, with
    /// `reader` being stdin.
    ///
    /// Reads a BYTE AT A TIME, stopping at the first newline, for two reasons that
    /// both bite:
    ///
    ///  * A bulk `read_to_end` would block a real operator forever. At a terminal
    ///    stdin does not reach EOF when they press Enter, so the daemon would sit
    ///    there until someone thought to press Ctrl-D — on the one startup a node
    ///    ever gets, before its host is sealed.
    ///  * A `BufReader` would fix that and then read AHEAD past the newline into a
    ///    buffer this code does not own and cannot wipe.
    ///
    /// Sixty-four single-byte reads on a once-per-node-lifetime path is not a cost
    /// worth optimizing. The buffer is over-reserved and the loop is capped below
    /// its capacity so it can never grow: a `Vec` that reallocated mid-read would
    /// free an allocation still holding preimage bytes, and the zeroizing wrapper
    /// only wipes the allocation it ends up owning.
    pub fn read_line(reader: &mut impl Read) -> Result<Preimage, Error> {
        const MAX_LINE: usize = 64;
        let mut buffer = Zeroizing::new(Vec::<u8>::with_capacity(4 * MAX_LINE));
        let allocation = buffer.as_ptr();
        let mut byte = [0u8; 1];
        while buffer.len() < MAX_LINE {
            match reader.read(&mut byte) {
                Ok(0) => break, // EOF — a piped preimage with no trailing newline.
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => buffer.push(byte[0]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("cannot read the node-key preimage: {e}").into()),
            }
        }
        debug_assert_eq!(
            buffer.as_ptr(),
            allocation,
            "the preimage buffer must not reallocate"
        );
        // On the error path `String::from_utf8` hands the bytes back inside the
        // `FromUtf8Error`, which owns them; `map_err(|_| …)` would drop that error and
        // free the allocation UN-WIPED. A mistyped preimage with one stray non-ASCII
        // byte is still almost all of the real secret, so wrap the recovered bytes in
        // a zeroizing guard before returning. (`buffer` still owns and wipes its own
        // copy either way.)
        let text = match String::from_utf8(buffer.to_vec()) {
            Ok(text) => Zeroizing::new(text),
            Err(e) => {
                let _wiped = Zeroizing::new(e.into_bytes());
                return Err("node-key preimage is not valid UTF-8 text".into());
            }
        };
        Preimage::from_hex(&text)
    }

    /// Read a preimage from stdin, disabling terminal ECHO while stdin is a TTY.
    ///
    /// The preimage is a signing secret. On the documented interactive paths — a
    /// daemon started at a terminal, and `setup node-endorse` — echoing it would
    /// copy it to the display, the terminal's scrollback, and any session recording.
    /// When stdin is a terminal, clear the ECHO bit for the duration of the read and
    /// restore it after (the discipline `sudo`/`ssh`/`gpg` use for secret entry);
    /// ICANON stays on, so line editing still works, the bytes are just not shown.
    ///
    /// Piped or redirected stdin has no terminal — the regtest harness feeds each
    /// node its `--preimage-file` kernel-to-kernel via `Stdio::from(File)`, and
    /// automation redirects a file — so `isatty` is false and the read proceeds
    /// exactly as before, preserving every non-interactive path.
    pub fn read_from_stdin() -> Result<Preimage, Error> {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        if !is_tty(libc::STDIN_FILENO) {
            return Preimage::read_line(&mut lock);
        }
        // The guard restores the original terminal settings on drop, including the
        // error path below, so echo is never left disabled.
        let _echo_off = EchoGuard::disable(libc::STDIN_FILENO)?;
        let result = Preimage::read_line(&mut lock);
        // The operator's Enter was not echoed either; move to a fresh line so later
        // output does not run onto the prompt line.
        eprintln!();
        result
    }
}

/// True when `fd` refers to a terminal.
fn is_tty(fd: libc::c_int) -> bool {
    // SAFETY: `isatty` only inspects the fd; it has no memory-safety preconditions.
    unsafe { libc::isatty(fd) == 1 }
}

/// Clears the terminal ECHO bit for `fd`, restoring the prior settings on drop.
///
/// Drop covers the normal return and an unwinding panic (this workspace unwinds; it
/// does not set `panic = "abort"`). It does NOT cover death by signal: a SIGINT/SIGTERM
/// while the operator is mid-entry kills the process before Drop runs and leaves the
/// terminal with echo off (recovered with `stty echo` / `reset`). Restoring across a
/// signal would need an async-signal-safe handler, which is disproportionate for this
/// once-per-node-lifetime interactive step and buys no secret-safety — the preimage is
/// not exposed either way — so it is a documented residual, not a bug.
struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
}

impl EchoGuard {
    fn disable(fd: libc::c_int) -> Result<Self, Error> {
        // SAFETY: `termios` is a plain-old-data struct; `tcgetattr` fills the pointee
        // and reports success/failure via its return value.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(format!(
                "cannot read terminal settings to disable echo for the node-key preimage: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
        let mut quiet = original;
        quiet.c_lflag &= !libc::ECHO;
        // TCSAFLUSH: apply after queued output drains and discard pending input, so a
        // character typed in the race before the mode change is not read under echo.
        // SAFETY: `quiet` is a valid termios for `fd`.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err(format!(
                "cannot disable terminal echo for the node-key preimage: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
        Ok(EchoGuard { fd, original })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Best effort: restore the operator's original terminal settings. There is
        // nothing useful to do if this fails, and it must not panic in a destructor.
        // SAFETY: `self.original` is the termios captured from this same fd.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

/// The PUBLIC half of a node's key derivation: everything except the preimage.
/// Lives in the per-node config and in the ceremony's public bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    salt: [u8; SALT_BYTES],
    ops: u32,
    mem_kib: u32,
}

impl KdfParams {
    /// Validate a parameter set. `ops`/`mem_kib` are checked against Argon2id's own
    /// minimums so a nonsense config fails at load rather than panicking inside the
    /// KDF on a node that is otherwise about to serve.
    pub fn new(salt: [u8; SALT_BYTES], ops: u32, mem_kib: u32) -> Result<KdfParams, Error> {
        if ops == 0 {
            return Err(
                "node_key_ops must be at least 1: a zero-pass Argon2id is not a KDF".into(),
            );
        }
        if mem_kib < MIN_KDF_MEM_KIB {
            return Err(format!(
                "node_key_mem_kib must be at least {MIN_KDF_MEM_KIB}: Argon2id rejects a smaller \
                 memory cost"
            )
            .into());
        }
        Ok(KdfParams { salt, ops, mem_kib })
    }

    /// Fresh ceremony parameters: a random salt at the given cost.
    pub fn generate_with(ops: u32, mem_kib: u32) -> Result<KdfParams, Error> {
        let mut salt = [0u8; SALT_BYTES];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut salt))
            .map_err(|e| format!("cannot read a node-key salt from /dev/urandom: {e}"))?;
        KdfParams::new(salt, ops, mem_kib)
    }

    /// The config/bundle form: a hex salt plus the two cost numbers.
    pub fn from_hex_salt(salt_hex: &str, ops: u32, mem_kib: u32) -> Result<KdfParams, Error> {
        let salt = <[u8; SALT_BYTES]>::from_hex(salt_hex.trim()).map_err(|e| {
            format!(
                "node_key_salt must be {} hex characters: {e}",
                SALT_BYTES * 2
            )
        })?;
        KdfParams::new(salt, ops, mem_kib)
    }

    pub fn salt_hex(&self) -> String {
        self.salt.to_lower_hex_string()
    }

    pub fn ops(&self) -> u32 {
        self.ops
    }

    pub fn mem_kib(&self) -> u32 {
        self.mem_kib
    }
}

/// Derive this node's federation signing key. The ONE place a node key comes into
/// existence, on the node itself, in RAM.
pub fn derive(preimage: &Preimage, params: &KdfParams) -> Result<SecretKey, Error> {
    let key = Zeroizing::new(
        wskdf_core::wskdf_derive_key(&preimage.0, &params.salt, params.ops, params.mem_kib)
            .map_err(|e| format!("wskdf node-key derivation failed: {e}"))?,
    );
    // Astronomically unlikely (a uniform 32-byte value is out of range with
    // probability ~2^-128), but it is a fatal config error rather than a panic:
    // this runs on the startup path of a daemon that must fail closed.
    SecretKey::from_slice(key.as_slice()).map_err(|e| {
        format!(
            "the wskdf-derived node key is not a valid secp256k1 scalar ({e}); re-run the setup \
             ceremony for this node"
        )
        .into()
    })
}

/// The public identity a derivation yields: what the ceremony publishes and what
/// the descriptor must name.
pub fn public_identity(seckey: &SecretKey) -> (PublicKey, PublicKey) {
    let secp = Secp256k1::new();
    (
        PublicKey::new(seckey.public_key(&secp)),
        crate::channel::ceremony::channel_pubkey(seckey),
    )
}

/// Parse a compressed-pubkey hex string, rejecting anything that is not a 33-byte
/// compressed secp256k1 point. Shared by the config loader and the ceremony so a
/// bundle and a config cannot disagree about what a key expression is.
pub fn parse_compressed_pubkey(text: &str) -> Result<PublicKey, Error> {
    if text.len() != 66 {
        return Err(format!(
            "expected a 33-byte compressed secp256k1 public key (66 hex characters), got {}",
            text.len()
        )
        .into());
    }
    Ok(PublicKey::from_str(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::new([7u8; SALT_BYTES], 1, MIN_KDF_MEM_KIB).expect("fixture params")
    }

    #[test]
    fn derivation_is_deterministic_and_salt_separated() {
        let preimage = Preimage::from_hex("00000000000000ff").expect("hex");
        let a = derive(&preimage, &params()).expect("derive");
        let b = derive(&preimage, &params()).expect("derive again");
        assert_eq!(a, b, "the same preimage + params must re-derive the key");

        let other = KdfParams::new([8u8; SALT_BYTES], 1, MIN_KDF_MEM_KIB).expect("params");
        assert_ne!(
            a,
            derive(&preimage, &other).expect("derive"),
            "a different salt must give a different node key"
        );
    }

    #[test]
    fn a_different_preimage_gives_a_different_key() {
        let a = derive(
            &Preimage::from_hex("0000000000000001").expect("hex"),
            &params(),
        )
        .expect("derive");
        let b = derive(
            &Preimage::from_hex("0000000000000002").expect("hex"),
            &params(),
        )
        .expect("derive");
        assert_ne!(a, b);
    }

    #[test]
    fn a_generated_preimage_round_trips_through_its_written_down_form() {
        let preimage = Preimage::generate().expect("generate");
        let hex = preimage.to_hex();
        let parsed = Preimage::from_hex(&hex).expect("re-read what the operator wrote down");
        assert_eq!(
            derive(&preimage, &params()).expect("derive"),
            derive(&parsed, &params()).expect("derive"),
        );
        // wskdf pins the top bit of the requested width, so the full 63 bits are
        // really there rather than a value that happened to land small.
        let bytes = u64::from_be_bytes(*preimage.0);
        assert!(
            bytes >= 1u64 << (PREIMAGE_BITS - 1),
            "preimage is full width"
        );
    }

    #[test]
    fn a_mistyped_preimage_is_refused_rather_than_deriving_some_other_key() {
        for bad in [
            "",
            "abc",
            "00000000000000f",
            "00000000000000fff",
            "zz00000000000000",
        ] {
            assert!(
                Preimage::from_hex(bad).is_err(),
                "{bad:?} must not parse as a preimage"
            );
        }
    }

    #[test]
    fn the_daemon_reads_a_preimage_line_from_its_input() {
        let expected = derive(
            &Preimage::from_hex("00000000000000ff").expect("hex"),
            &params(),
        )
        .expect("derive");
        // A typed line, a piped file with no trailing newline, and a line with more
        // behind it — the read stops at the newline in every case, and in particular
        // does NOT wait for EOF (which at a terminal never comes).
        for input in [
            "00000000000000ff\n",
            "00000000000000ff",
            "00000000000000ff\nand more that must not be consumed",
        ] {
            let mut bytes = input.as_bytes();
            let read = Preimage::read_line(&mut bytes).expect("read");
            assert_eq!(
                derive(&read, &params()).expect("derive"),
                expected,
                "{input:?}"
            );
        }
        // An over-long line is refused rather than silently truncated to something
        // that would derive a different key.
        let mut long = "0".repeat(200);
        long.push('\n');
        assert!(Preimage::read_line(&mut long.as_bytes()).is_err());
    }

    #[test]
    fn nonsense_kdf_costs_are_config_errors_not_panics() {
        assert!(KdfParams::new([0u8; SALT_BYTES], 0, 1024).is_err());
        assert!(KdfParams::new([0u8; SALT_BYTES], 1, 0).is_err());
        assert!(KdfParams::from_hex_salt("00", 1, 1024).is_err());
    }
}
