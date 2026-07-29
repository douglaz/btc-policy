//! The per-node chain backend (DESIGN.md, "Per-node chain backend"; ADR-0001).
//!
//! A deliberately small trait the node uses for two jobs:
//!
//!  1. **broadcast** — push a fully-signed transaction to the network. V0-4's
//!     node-distributed duress broadcast (ADR-0008) needs each node able to
//!     broadcast on its own; this task provides the primitive, nothing more.
//!  2. **spends_of** — the watchtower scan (ADR-0001): spends of the vault's
//!     watched scriptPubKeys, as seen by THIS node's own chain view.
//!
//! v0 ships the trait seam plus one minimal `bitcoind`-RPC impl for regtest.
//! Vault-node's `/sign` preflight uses [`ChainBackend::prevouts`] to verify confirmed
//! inputs before pure policy evaluation; unconfirmed authorized parents remain
//! subject to the fire-time package checks. Being a trait, unit tests use a mock
//! and never need bitcoind.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{
    consensus, Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness,
};
use serde_json::{json, Value};

use crate::Error;

/// One on-chain spend of a watched scriptPubKey, from the watchtower scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendSeen {
    /// Txid of the transaction that spent the watched output.
    pub spend_txid: Txid,
    /// The watched output that was consumed (the vault UTXO).
    pub outpoint: OutPoint,
    /// scriptPubKey of the spent output — one of the queried `scripts`.
    ///
    /// The vault descriptor puts recovery as an alternate BRANCH inside the SAME
    /// `wsh(...)` (ADR-0013 §1; DESIGN.md, Wallet Topology — recovery is "an
    /// alternate spend path over the same coins"), so a recovery spend and a
    /// normal spend share this prevout scriptPubKey and CANNOT be told apart by
    /// it. The distinguishing signal is [`Self::witness`] (which script branch the
    /// spend satisfied), not this script.
    pub script: ScriptBuf,
    /// The witness stack of the input that spent the watched output. The
    /// watchtower reads it to tell a recovery-branch spend from a normal-branch
    /// spend (they share `script`): the template's top-level `or_i` puts an
    /// explicit branch selector immediately before the witness script, so the
    /// second-from-last element is `01` for the normal branch and EMPTY for the
    /// recovery branch (see `watchtower::is_recovery_branch`).
    pub witness: Witness,
}

/// The result of a [`ChainBackend::spends_of`] traversal: the watched spends seen,
/// plus the `(height, hash)` chain the SAME traversal proved to be a contiguous
/// prefix of the ACTIVE chain — every block chained onto its parent, the terminal
/// block still active, and (when an `expected_parent` was supplied) the first block
/// rooted on it. The watchtower binds its cursor anchors to `blocks` instead of
/// re-reading the hashes independently, so an anchor can NEVER come from a fork the
/// classifying scan did not actually traverse (v0-exit 9y5.3 review, [P1] BOTH): a
/// second, unvalidated hash fetch is exactly where a racing reorg would otherwise
/// slip a mixed-fork anchor past the terminal re-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTraversal {
    /// Spends of the queried scripts within the traversed range.
    pub spends: Vec<SpendSeen>,
    /// The `(height, hash)` of every block traversed, ascending and contiguous,
    /// proven active by the same reads that produced `spends`.
    pub blocks: Vec<(u32, BlockHash)>,
}

/// One prevout as this node sees it across its confirmed chain AND its own
/// mempool (ADR-0012, "build over the mempool UTXO set, not confirmed-only").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prevout {
    /// The output being spent.
    pub txout: TxOut,
    /// Whether the transaction that created this output is confirmed. An
    /// UNCONFIRMED prevout is spendable by a vault transaction only when its
    /// parent is vault-authorized (see [`assemble_package`]).
    pub confirmed: bool,
}

/// The outcome of a full package mempool-acceptance test (ADR-0012: "the
/// assembled package passes the node backend's full package-mempool-acceptance
/// test, not merely relay-standard").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageVerdict {
    /// Every transaction in the package is acceptable to this node's mempool.
    Accepted,
    /// At least one is not; the reason is the backend's, verbatim.
    Rejected(String),
}

/// The per-txid fallback shape of [`ChainBackend::mempool_resident`]: the first of
/// `txids`, in order, that `lookup` answers for.
///
/// A free function rather than an inherent method because Rust offers no way to call a
/// shadowed default implementation: the trait default and the test mock would otherwise
/// each carry their own copy of this loop, and a later change to the pick semantics would
/// silently apply to only one of them — leaving every mock-based test proving the OLD
/// contract (Fable nvr review).
fn first_resident_by_lookup(
    txids: &[Txid],
    mut lookup: impl FnMut(&Txid) -> Result<Option<Vec<u8>>, Error>,
) -> Result<Option<(Txid, Vec<u8>)>, Error> {
    for txid in txids {
        if let Some(raw) = lookup(txid)? {
            return Ok(Some((*txid, raw)));
        }
    }
    Ok(None)
}

/// A node's own view of the chain (DESIGN.md, "Per-node chain backend"). Serves
/// broadcast, the watchtower scan (ADR-0001), and V0-8b's package-gated combine.
/// Kept small on purpose so unit tests substitute a mock.
pub trait ChainBackend {
    /// Push a fully-signed, consensus-serialized transaction to the network,
    /// returning its txid. A malformed transaction is an `Err`, never a panic.
    fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error>;

    /// The height of this node's chain tip. The watchtower driver (V0-6b) reads
    /// it to advance its scan cursor past already-scanned blocks instead of
    /// re-scanning from height 0 every pass.
    fn tip_height(&self) -> Result<u32, Error>;

    /// The block hash at `height` in this node's ACTIVE chain, or `None` if no
    /// block occupies that height (beyond the tip, or pruned). The reorg-aware
    /// watchtower cursor ([`watchtower::ScanCursor`](crate::watchtower::ScanCursor))
    /// reads it to confirm the block it last scanned at a height still matches the
    /// chain; a mismatch is a reorg, and the cursor rewinds to the fork point
    /// rather than silently advancing past re-orged blocks it never re-classified.
    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, Error>;

    /// The **median feerate, in sat/vB, of the block at `height`** in this node's
    /// ACTIVE chain — the one fee signal the escape fee-bump selector is allowed to
    /// read (bead btc-policy-9y5.7).
    ///
    /// It is a *confirmed-chain* reading on purpose. The armed escape's bump target
    /// must be a pure function of consensus-observable state, because every honest
    /// node has to land on the SAME target or their partials cover different
    /// transactions and the sweep never reaches `t` signatures. A node's own mempool
    /// — `mempoolminfee`, `estimatesmartfee`, local eviction history — is exactly the
    /// per-node state that would split them, so no bump input may come from it.
    ///
    /// `None` means "this node has no fee reading here" (no such block, or a backend
    /// that does not report fee statistics). The selector treats `None` as *no
    /// observed fee pressure* and stays on the base escape, which is the pre-9y5.7
    /// behaviour — never an excuse to bump. The default implementation returns `None`
    /// so mocks and alternate backends opt in rather than having to stub it.
    fn block_median_feerate(&self, _height: u32) -> Result<Option<u64>, Error> {
        Ok(None)
    }

    /// Spends of any of `scripts` observed in the inclusive block range
    /// `from_height..=through_height`, against this node's own chain data, together
    /// with the validated `(height, hash)` chain of the blocks traversed (see
    /// [`ScanTraversal`]). Fixing the terminal height lets the watchtower bind alerts
    /// and cursor anchors to the same captured chain prefix even if a new block
    /// arrives mid-pass.
    ///
    /// `expected_parent`, when `Some`, is the hash the block at `from_height` must
    /// name as its `previousblockhash`: the newest cursor anchor the scan is
    /// extending. Supplying it makes the traversal refuse a range that does not chain
    /// ONTO the existing cursor — the reorg that forks below `from_height` and rebuilds
    /// taller within the window between the caller's pre-scan anchor check and this
    /// call (v0-exit 9y5.3 review, [P1] BOTH). `None` skips the root check: the first
    /// scan (empty cursor) or a post-reset genesis re-scan has no anchor to root on.
    fn spends_of(
        &self,
        scripts: &[ScriptBuf],
        from_height: u32,
        through_height: u32,
        expected_parent: Option<BlockHash>,
    ) -> Result<ScanTraversal, Error>;

    /// The unspent output at `outpoint` as this node sees it, **including its own
    /// mempool**. `None` ⇒ this node cannot see the output (unknown or already
    /// spent). Confirmed-only would strand the common case: spend-change and
    /// refresh outputs are usually still unconfirmed (ADR-0012).
    fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error>;

    /// Resolve several prevouts as one logical preflight. Backends may override
    /// this to batch transport; the default preserves the small trait seam for
    /// mocks and alternate backends while aborting on the first error.
    fn prevouts(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<Prevout>>, Error> {
        outpoints
            .iter()
            .map(|outpoint| self.prevout(outpoint))
            .collect()
    }

    /// Every currently-unspent output paying one of `scripts` in this node's
    /// confirmed UTXO set, plus unconfirmed outputs whose parent txid is in the
    /// node's validated-and-policy-accepted `authorized` set. This is the
    /// fire-time whole-vault denominator for ADR-0012/0013 coverage. External
    /// unconfirmed deposits are deliberately excluded (toxic-deposit safe).
    fn vault_unspent(
        &self,
        scripts: &[ScriptBuf],
        authorized: &HashSet<Txid>,
    ) -> Result<Vec<(OutPoint, Prevout)>, Error>;

    /// Refresh any backend-side confirmed-vault cache outside the fire/combine path.
    /// The default is a no-op for mocks and indexed backends; the Core backend reads
    /// its node-owned watch-only descriptor wallet, falling back to a cold
    /// `scantxoutset` snapshot (advanced by bounded block deltas) whenever that wallet
    /// is missing, failed, or unrecognized.
    fn refresh_vault_unspent_cache(&self, _scripts: &[ScriptBuf]) -> Result<(), Error> {
        Ok(())
    }

    /// Periodic live-node form of [`Self::refresh_vault_unspent_cache`]. Backends whose
    /// reconciliation includes slow maintenance may move that maintenance off the
    /// single cache-refresher thread; the default keeps the ordinary synchronous
    /// behavior.
    fn refresh_vault_unspent_cache_live(&self, scripts: &[ScriptBuf]) -> Result<(), Error> {
        self.refresh_vault_unspent_cache(scripts)
    }

    /// Raw consensus bytes of `txid` iff it is in this node's mempool. This is the
    /// ancestor lookup used after the first package level: a mempool parent's own
    /// inputs are already spent, so `gettxout` cannot inspect them. Membership in
    /// the mempool distinguishes another unconfirmed ancestor from a confirmed
    /// parent without requiring `-txindex`.
    fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error>;

    /// The FIRST of `txids`, in the caller's order, that is in this node's mempool,
    /// with its raw consensus bytes — one batched membership read instead of one per
    /// candidate (bead btc-policy-nvr).
    ///
    /// [`ChainBackend::mempool_transaction`] answers for ONE txid, and the Core backend
    /// implements it by pulling the ENTIRE `getrawmempool` set on every call. A fee-bump
    /// ladder asks about up to `MAX_ESCAPE_BUMPS + 1` rungs on the escape's fire path, so
    /// a per-rung loop parses the whole mempool up to four times per tick — worst exactly
    /// under the congestion that makes the combine window tight, and pointless because a
    /// single snapshot answers for every rung. Order matters: rungs are asked
    /// cheapest-first, and the resident rung is the one the replacement path builds its
    /// ancestry proof against.
    ///
    /// The default implementation keeps the old per-txid behaviour, so mocks and any
    /// future backend stay correct without opting in; the Core backend overrides it.
    fn mempool_resident(&self, txids: &[Txid]) -> Result<Option<(Txid, Vec<u8>)>, Error> {
        first_resident_by_lookup(txids, |txid| self.mempool_transaction(txid))
    }

    /// Whether `txid` is confirmed in this node's active chain. A candidate may
    /// move from the mempool into a block before this node's redundant fire pass;
    /// recognizing that confirmation is what lets the node settle its local Hold
    /// instead of mistaking already-spent inputs for a package-assembly failure.
    fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error>;

    /// Test whether the candidate package would be accepted into this node's
    /// mempool. [`assemble_package`] supplies the new candidate alone after
    /// verifying that every unconfirmed ancestor is already present and
    /// vault-authorized; Core evaluates that full in-mempool ancestry when testing
    /// the candidate. Broadcast is gated on this.
    fn test_package_accept(&self, raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error>;
}

/// Cap on the unconfirmed ancestors one broadcast package may absorb (ADR-0012:
/// "package/ancestor limits cap how many unconfirmed chains one escape can
/// absorb — deep/numerous unconfirmed value may need a follow-up sweep"). Sits
/// just under Core's default 25-ancestor mempool limit, which the package would
/// hit anyway; exceeding it is a clean `Err` (no broadcast), never a hang or a
/// package the backend will reject after the fact.
pub const MAX_PACKAGE_ANCESTORS: usize = 24;

/// Highest Bitcoin Core `incrementalfee` this build supports, in sat/kvB.
///
/// Escape-ladder ingress requires each rung to raise the absolute fee by at least
/// one sat/vB of its maximum finalized size. A backend configured above that rate
/// would accept the ladder while being unable to relay its replacements, so the
/// production startup check rejects it.
pub const MAX_SUPPORTED_INCREMENTAL_RELAY_SAT_KVB: u64 = 1_000;

/// Assemble the mempool-acceptance package for `tx` after validating every
/// unconfirmed ancestor it chains off (ADR-0012, "build over the mempool UTXO
/// set"). The returned package contains `tx` alone: every discovered ancestor is
/// already in this node's mempool by construction, and Core's package policy
/// rejects packages that re-list multi-generation/already-present ancestry. A
/// singleton `testmempoolaccept` still evaluates the candidate against that full
/// mempool ancestor set.
///
/// `authorized` is this node's validated-AND-policy-ACCEPTED transaction set. It
/// is what separates the two kinds of unconfirmed parent, and the distinction is
/// load-bearing:
///
/// - a **vault-authorized** unconfirmed parent (this vault's own spend-change or
///   refresh) may be chained onto, because it cannot be pulled out from under the
///   child: replacing it needs a conflicting vault spend, which needs the user key
///   AND `t`-of-`n` node signatures a post-wrench attacker cannot obtain. So the
///   parent confirms, so the child confirms.
/// - an **external** unconfirmed deposit is EXCLUDED (an `Err` here, so nothing is
///   broadcast). Its parent is not vault-authorized and can be replaced at will —
///   a "toxic deposit" an attacker double-spends to poison whatever chains off it.
///   A genuine deposit arriving at this moment is a straggler: it is swept by the
///   next escape or recovered via the timelock. Funds-safe either way.
///
/// A confirmed prevout needs no ancestor. `Err` means "do not broadcast" — an
/// unknown prevout, an excluded external deposit, or an over-deep chain — and is
/// always a refusal to act, never a panic.
pub fn assemble_package(
    backend: &dyn ChainBackend,
    tx: &Transaction,
    authorized: &HashSet<Txid>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut seen = HashSet::new();
    validate_ancestors(backend, tx, authorized, &mut seen, true)?;
    Ok(vec![consensus::serialize(tx)])
}

/// Assemble a package for `replacement` when `replaced` is an exact, authorized
/// lower fee-ladder rung already in this node's mempool.
///
/// Core's `gettxout(..., include_mempool=true)` hides every input spent by
/// `replaced`, so [`assemble_package`] cannot distinguish this legitimate RBF case
/// from an unrelated double spend. The resident lower rung supplies that missing
/// proof: the two transactions must spend the exact same outpoints, and walking the
/// resident transaction with `inputs_are_unspent = false` validates the same
/// confirmed-or-authorized ancestry without asking `gettxout` for outputs the
/// mempool deliberately hides.
pub fn assemble_replacement_package(
    backend: &dyn ChainBackend,
    replacement: &Transaction,
    replaced: &Transaction,
    authorized: &HashSet<Txid>,
) -> Result<Vec<Vec<u8>>, Error> {
    let replacement_inputs: Vec<OutPoint> = replacement
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    let replaced_inputs: Vec<OutPoint> = replaced
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    if replacement_inputs != replaced_inputs {
        return Err(format!(
            "replacement {} does not spend the exact input set of resident rung {}",
            replacement.compute_txid(),
            replaced.compute_txid()
        )
        .into());
    }
    let mut seen = HashSet::new();
    validate_ancestors(backend, replaced, authorized, &mut seen, false)?;
    Ok(vec![consensus::serialize(replacement)])
}

/// Walk `tx`'s unconfirmed authorized ancestors. `seen` dedups diamond ancestry
/// and bounds both recursion depth and total ancestry checked. The raw ancestors
/// are read to continue validation, not returned to `testmempoolaccept`: their
/// successful mempool lookup proves they are already part of the chain view Core
/// will evaluate for the singleton candidate.
fn validate_ancestors(
    backend: &dyn ChainBackend,
    tx: &Transaction,
    authorized: &HashSet<Txid>,
    seen: &mut HashSet<Txid>,
    inputs_are_unspent: bool,
) -> Result<(), Error> {
    for input in &tx.input {
        let outpoint = input.previous_output;
        let parent_txid = outpoint.txid;
        let raw = if inputs_are_unspent {
            // Only the candidate's own inputs are unspent in this node's mempool
            // view, so gettxout can tell confirmed from unconfirmed here.
            let prevout = backend.prevout(&outpoint)?.ok_or_else(|| {
                format!(
                    "prevout {outpoint} is unknown to this node's chain view (unknown or spent)"
                )
            })?;
            if prevout.confirmed {
                continue;
            }
            backend.mempool_transaction(&parent_txid)?.ok_or_else(|| {
                format!("unconfirmed parent {parent_txid} disappeared from this node's mempool")
            })?
        } else {
            // `tx` is itself in the mempool, so its inputs are spent there and
            // gettxout would return null. An input's parent that is also in the
            // mempool is an unconfirmed ancestor; absence means that parent is
            // confirmed (Core admits no orphan inputs to its mempool).
            let Some(raw) = backend.mempool_transaction(&parent_txid)? else {
                continue;
            };
            raw
        };
        if !authorized.contains(&parent_txid) {
            return Err(format!(
                "input {outpoint} chains off unconfirmed transaction {parent_txid}, which this \
                 node never validated and policy-accepted: an external unconfirmed deposit is \
                 excluded because its parent can be replaced out from under this spend"
            )
            .into());
        }
        if !seen.insert(parent_txid) {
            continue;
        }
        if seen.len() > MAX_PACKAGE_ANCESTORS {
            return Err(format!(
                "package for {} exceeds the {MAX_PACKAGE_ANCESTORS}-ancestor bound; the \
                 unconfirmed chain must confirm before this spend can broadcast",
                tx.compute_txid()
            )
            .into());
        }
        let parent: Transaction = consensus::deserialize(&raw)
            .map_err(|e| format!("parent {parent_txid} is malformed: {e}"))?;
        validate_ancestors(backend, &parent, authorized, seen, false)?;
    }
    Ok(())
}

/// Minimal bitcoind JSON-RPC backend over loopback (regtest). Mirrors the demo's
/// RPC client style (`crates/vault-cli/src/bitcoind.rs`) — no HTTP crate lands in
/// the node. Talks to an already-running bitcoind; spawning one is the caller's
/// job (the demo already does, and the opt-in integration test does its own).
#[derive(Clone)]
pub struct BitcoindBackend {
    rpc_addr: SocketAddr,
    /// base64 of `<user>:<password>` (or `__cookie__:<pw>`), exactly as the
    /// `Authorization: Basic` header carries it.
    auth: String,
    /// Node-derived identity; sibling nodes watching one vault get different wallets.
    wallet_owner: [u8; 32],
    /// Confirmed vault-UTXO cache maintained only by
    /// [`ChainBackend::refresh_vault_unspent_cache`], never by the fire/combine hot
    /// path. It is served from the node-owned watch-only descriptor wallet
    /// ([`Self::wallet_confirmed_scan`]), with `scantxoutset` kept as the cold-start
    /// and reconciliation fallback. `vault_unspent` either consumes a cache at the
    /// current tip or fails fast, so no whole-set scan can consume the escape's
    /// finite combine window.
    scan_cache: Arc<Mutex<Option<VaultUnspentCache>>>,
    /// The node-owned watch-only wallet after its descriptors are verified.
    vault_wallet: Arc<Mutex<Option<VaultWallet>>>,
    /// Keeps a reorg-blind wallet out of use until a cold-scan re-import repairs it.
    wallet_reimport_pending: Arc<Mutex<bool>>,
    /// At most one slow descriptor import runs away from the periodic cache refresher.
    /// While it is set, the scan-derived cache may still advance by bounded block
    /// deltas, so a new tip does not make coverage unavailable for the whole rescan.
    wallet_reimport_in_progress: Arc<AtomicBool>,
    /// Whole-UTXO-set scans this backend has issued, counting one that then failed:
    /// the cost is the scan slot Core serializes, not the reply. Both sources produce
    /// the SAME view, so no equality check can tell a wallet-served refresh from one
    /// that silently fell back — and a fallback nobody notices is this bead's failure
    /// mode, not a correctness bug. The live-Core regression asserts on this count.
    full_scans: Arc<AtomicU64>,
}

/// The cached confirmed vault-UTXO scan (deliverable 9y5.3-c). `candidates` is
/// mempool-agnostic active-chain membership; each entry is re-checked through
/// batched `gettxout(..., include_mempool)` on use, so a confirmed output a mempool
/// tx has since spent is still dropped.
#[derive(Clone)]
struct VaultUnspentCache {
    bestblock: BlockHash,
    height: u32,
    scripts: Vec<ScriptBuf>,
    candidates: HashSet<OutPoint>,
}

/// A cold scan and the oldest live output height, used as the wallet birthday.
/// A reorg can resurrect an older output, so reorg repair re-derives this value.
#[derive(Clone)]
struct ColdScan {
    cache: VaultUnspentCache,
    oldest_unspent_height: u32,
}

/// A located-and-verified node-owned watch-only wallet.
struct VaultWallet {
    name: String,
    /// Script set verified for this handle.
    scripts: Vec<ScriptBuf>,
    /// The active-chain `(height, hash)` this wallet's history was proved to rest on
    /// — its completion marker, or the cold anchor a repair imported from. Only a
    /// reorg that unseats THIS can resurrect an output older than the wallet's
    /// birthday, so [`ChainBackend::refresh_vault_unspent_cache`] uses it as the reorg
    /// guard: while it holds, the wallet can see everything a reorg can undo.
    anchor: (u32, BlockHash),
}

/// Maximum active-chain blocks one background cache refresh parses. A node that
/// starts far behind advances over successive passes; until it catches the tip the
/// fire path fails fast rather than doing unbounded catch-up inside the combine
/// window. The cold full scan and any reorg fallback also run only in that background
/// task.
const MAX_VAULT_SCAN_DELTA_BLOCKS: u32 = 32;

/// Prefix for a name derived from the node identity and watched scripts.
const VAULT_WALLET_PREFIX: &str = "vaultnode-";

/// Non-daemon identity; the daemon supplies its public key.
const STANDALONE_WALLET_IDENTITY: &[u8] = b"vault-node-standalone-backend";

impl BitcoindBackend {
    /// Standalone backend; production nodes use [`Self::new_for_node`].
    pub fn new(rpc_addr: SocketAddr, auth: String) -> BitcoindBackend {
        Self::new_for_node(rpc_addr, auth, STANDALONE_WALLET_IDENTITY)
    }

    /// Construct a backend with one stable node identity.
    pub(crate) fn new_for_node(
        rpc_addr: SocketAddr,
        auth: String,
        node_identity: &[u8],
    ) -> BitcoindBackend {
        BitcoindBackend {
            rpc_addr,
            auth,
            wallet_owner: sha256::Hash::hash(node_identity).to_byte_array(),
            scan_cache: Arc::new(Mutex::new(None)),
            vault_wallet: Arc::new(Mutex::new(None)),
            wallet_reimport_pending: Arc::new(Mutex::new(false)),
            wallet_reimport_in_progress: Arc::new(AtomicBool::new(false)),
            full_scans: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Whole-UTXO-set scans issued so far — the cost bead btc-policy-hn8 exists to
    /// remove. A wallet-served refresh leaves this unchanged.
    pub fn full_scan_count(&self) -> u64 {
        self.full_scans.load(Ordering::Relaxed)
    }

    /// One JSON-RPC call with its structured `result`/`error` fields intact.
    /// Most callers use [`Self::call`], while confirmation lookup needs Core's
    /// numeric not-found code to distinguish absence from a backend failure.
    fn call_reply(&self, method: &str, params: Value) -> Result<Value, Error> {
        self.call_reply_within(method, params, RPC_TIMEOUT)
    }

    /// Root-endpoint call with an explicit deadline for synchronous wallet catch-up.
    fn call_reply_within(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, Error> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "vault-node",
            "method": method,
            "params": params,
        });
        let body = post_json_to(
            self.rpc_addr,
            "/",
            &request.to_string(),
            &self.auth,
            timeout,
        )?;
        serde_json::from_str(&body)
            .map_err(|e| format!("bitcoind {method}: unparseable reply: {e}").into())
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let reply = self.call_reply(method, params)?;
        if !reply["error"].is_null() {
            return Err(format!("bitcoind {method}: {}", reply["error"]).into());
        }
        Ok(reply["result"].clone())
    }

    /// Call Core's wallet endpoint; generated names need no URL escaping.
    fn wallet_call(&self, wallet: &str, method: &str, params: Value) -> Result<Value, Error> {
        self.wallet_call_within(wallet, method, params, RPC_TIMEOUT)
    }

    /// Wallet call with an explicit deadline for descriptor rescans.
    fn wallet_call_within(
        &self,
        wallet: &str,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, Error> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "vault-node",
            "method": method,
            "params": params,
        });
        let body = post_json_to(
            self.rpc_addr,
            &format!("/wallet/{wallet}"),
            &request.to_string(),
            &self.auth,
            timeout,
        )?;
        let reply: Value = serde_json::from_str(&body)
            .map_err(|e| format!("bitcoind {method} on wallet {wallet}: unparseable reply: {e}"))?;
        if !reply["error"].is_null() {
            return Err(format!("bitcoind {method} on wallet {wallet}: {}", reply["error"]).into());
        }
        Ok(reply["result"].clone())
    }

    fn best_block_hash(&self) -> Result<BlockHash, Error> {
        let text = self
            .call("getbestblockhash", json!([]))?
            .as_str()
            .ok_or("getbestblockhash: expected a block hash")?
            .to_string();
        BlockHash::from_str(&text).map_err(|e| format!("getbestblockhash: bad hash: {e}").into())
    }

    /// Return the height only if `block` is still active there.
    fn confirm_active_height(&self, block: BlockHash) -> Result<u32, Error> {
        let header = self.call("getblockheader", json!([block.to_string(), true]))?;
        let height = header["height"]
            .as_u64()
            .ok_or("getblockheader: no block height")?;
        let height =
            u32::try_from(height).map_err(|_| "getblockheader: block height exceeds u32")?;
        if self.block_hash_at(height)? != Some(block) {
            return Err(format!(
                "block {block} is no longer active at height {height}; discarding the vault \
                 UTXO snapshot anchored to it"
            )
            .into());
        }
        Ok(height)
    }

    fn parse_prevout(result: &Value) -> Result<Option<Prevout>, Error> {
        if result.is_null() {
            return Ok(None);
        }
        let spk_hex = result["scriptPubKey"]["hex"]
            .as_str()
            .ok_or("gettxout: no scriptPubKey hex")?;
        let btc = result["value"].as_f64().ok_or("gettxout: no value")?;
        // `confirmations = 0` is exactly bitcoind's "in the mempool, not mined".
        let confirmations = result["confirmations"]
            .as_u64()
            .ok_or("gettxout: no confirmations")?;
        Ok(Some(Prevout {
            txout: TxOut {
                script_pubkey: ScriptBuf::from_hex(spk_hex)
                    .map_err(|e| format!("gettxout: bad scriptPubKey: {e}"))?,
                value: Amount::from_btc(btc).map_err(|e| format!("gettxout: bad value: {e}"))?,
            },
            confirmed: confirmations > 0,
        }))
    }

    /// Fail startup unless Core's transaction index is present and caught up, the
    /// node has left initial block download, AND its incremental relay fee is no
    /// higher than the escape ladder's ingress bound. Escape-class union coverage
    /// must distinguish a paired spend that confirmed from one absent from the
    /// mempool; `getrawtransaction(txid, true)` cannot make that distinction reliably
    /// without `-txindex=1`, and neither lookup is reliable against a stale IBD chain
    /// view. A higher `incrementalfee` would make a locally accepted ladder
    /// unreplaceable when it is needed.
    pub fn verify_required_indexes(&self) -> Result<(), Error> {
        // `getindexinfo`'s `synced` only means the txindex has caught up to THIS
        // node's current tip. During initial block download that tip still lags the
        // network, so the index can report `synced` over a stale chain view — the
        // confirmed vault-UTXO scan would then miss outputs in not-yet-downloaded
        // blocks (understating the coverage denominator) and `transaction_confirmed`
        // would misread an already-mined paired spend as absent. `initialblockdownload`
        // is the authoritative "chain view is current" signal, so require it cleared
        // before this node consumes its key's one process generation.
        let chain = self.call("getblockchaininfo", json!([]))?;
        if chain.get("initialblockdownload").and_then(Value::as_bool) != Some(false) {
            return Err(
                "bitcoind is still in initial block download: refusing to start until the chain \
                 view is current (escape coverage and confirmation lookup would be computed \
                 against a stale tip)"
                    .into(),
            );
        }
        let indexes = self.call("getindexinfo", json!([]))?;
        let txindex = indexes.get("txindex").and_then(Value::as_object).ok_or(
            "bitcoind must run with -txindex=1: escape-class union coverage requires confirmed \
             transaction lookup",
        )?;
        if txindex.get("synced").and_then(Value::as_bool) != Some(true) {
            return Err(
                "bitcoind txindex is not synced: refusing to start until escape-class \
                 confirmation lookup is reliable"
                    .into(),
            );
        }
        let network = self.call("getnetworkinfo", json!([]))?;
        let incremental_btc_kvb = network["incrementalfee"]
            .as_f64()
            .ok_or("getnetworkinfo: incrementalfee is not a number")?;
        let incremental_sat_kvb = Amount::from_btc(incremental_btc_kvb)
            .map_err(|e| format!("getnetworkinfo: bad incrementalfee: {e}"))?
            .to_sat();
        if incremental_sat_kvb > MAX_SUPPORTED_INCREMENTAL_RELAY_SAT_KVB {
            return Err(format!(
                "bitcoind incrementalfee is {incremental_sat_kvb} sat/kvB, above the supported \
                 {MAX_SUPPORTED_INCREMENTAL_RELAY_SAT_KVB} sat/kvB escape-replacement bound"
            )
            .into());
        }
        Ok(())
    }

    /// Cold/reconciliation fallback, including a chain-derived wallet birthday.
    fn full_confirmed_scan(&self, scripts: &[ScriptBuf]) -> Result<ColdScan, Error> {
        let scan_objects: Vec<Value> = scripts
            .iter()
            .map(|script| json!({ "desc": raw_descriptor(script) }))
            .collect();
        self.full_scans.fetch_add(1, Ordering::Relaxed);
        let scan = self.call("scantxoutset", json!(["start", scan_objects]))?;
        if scan["success"].as_bool() != Some(true) {
            return Err("scantxoutset: scan did not complete successfully".into());
        }
        let bestblock_text = scan["bestblock"]
            .as_str()
            .ok_or("scantxoutset: bestblock is not a hash")?;
        let bestblock = BlockHash::from_str(bestblock_text)
            .map_err(|e| format!("scantxoutset: bad bestblock hash: {e}"))?;
        let unspents = scan["unspents"]
            .as_array()
            .ok_or("scantxoutset: unspents is not an array")?;
        let mut candidates = HashSet::with_capacity(unspents.len());
        let mut oldest_unspent_height: Option<u32> = None;
        for entry in unspents {
            let txid = entry["txid"]
                .as_str()
                .ok_or("scantxoutset: unspent has no txid")?;
            let vout = entry["vout"]
                .as_u64()
                .ok_or("scantxoutset: unspent has no vout")?;
            let vout = u32::try_from(vout).map_err(|_| "scantxoutset: vout exceeds u32")?;
            let entry_height = entry["height"]
                .as_u64()
                .ok_or("scantxoutset: unspent has no height")?;
            let entry_height =
                u32::try_from(entry_height).map_err(|_| "scantxoutset: height exceeds u32")?;
            oldest_unspent_height =
                Some(oldest_unspent_height.map_or(entry_height, |old: u32| old.min(entry_height)));
            candidates.insert(OutPoint::new(
                Txid::from_str(txid).map_err(|e| format!("scantxoutset: bad txid: {e}"))?,
                vout,
            ));
        }
        let height = self.confirm_active_height(bestblock).map_err(|e| {
            format!("scantxoutset: best block is no longer active, discarding the cold cache: {e}")
        })?;
        Ok(ColdScan {
            // With no live output, the tip is the earliest required birthday.
            oldest_unspent_height: oldest_unspent_height.unwrap_or(height),
            cache: VaultUnspentCache {
                bestblock,
                height,
                scripts: scripts.to_vec(),
                candidates,
            },
        })
    }

    /// Locate and verify this node's wallet, returning its name and the active-chain
    /// anchor its history was proved against. Only a cold scan may create/repair it;
    /// wallet-only failure therefore degrades to `scantxoutset`.
    fn ensure_vault_wallet(
        &self,
        scripts: &[ScriptBuf],
        cold_scan: Option<&ColdScan>,
    ) -> Result<(String, (u32, BlockHash)), Error> {
        if let Some(wallet) = self
            .vault_wallet
            .lock()
            .expect("vault wallet lock poisoned")
            .as_ref()
            .filter(|wallet| wallet.scripts == scripts)
        {
            return Ok((wallet.name.clone(), wallet.anchor));
        }
        let name = vault_wallet_name(&self.wallet_owner, scripts);
        // Loading a wallet that fell behind while bitcoind was offline synchronously
        // catches it up to the active tip, so it needs the same budget as an import
        // rescan rather than the ordinary one-minute RPC deadline.
        let reply =
            self.call_reply_within("loadwallet", json!([name]), WALLET_BUILD_RPC_TIMEOUT)?;
        if !reply["error"].is_null() {
            match reply["error"]["code"].as_i64() {
                Some(-35) => {}
                Some(-18) => {
                    let cold_scan = cold_scan.ok_or(
                        "this backend has no node-owned vault wallet yet; the scantxoutset \
                         fallback creates it",
                    )?;
                    self.create_vault_wallet(&name, scripts, cold_scan)?;
                }
                _ => return Err(format!("bitcoind loadwallet {name}: {}", reply["error"]).into()),
            }
        }
        let anchor = self.verify_vault_wallet(&name, scripts, cold_scan)?;
        *self
            .vault_wallet
            .lock()
            .expect("vault wallet lock poisoned") = Some(VaultWallet {
            name: name.clone(),
            scripts: scripts.to_vec(),
            anchor,
        });
        Ok((name, anchor))
    }

    /// Build or repair from a proved birthday. Failed repair leaves the latch set,
    /// preventing a possibly incomplete wallet from under-reporting coverage.
    fn seed_vault_wallet(&self, scripts: &[ScriptBuf], cold_scan: &ColdScan) -> Result<(), Error> {
        let (name, _) = self.ensure_vault_wallet(scripts, Some(cold_scan))?;
        if *self
            .wallet_reimport_pending
            .lock()
            .expect("wallet reimport lock poisoned")
        {
            self.import_vault_descriptors(&name, scripts, cold_scan)?;
            // A repaired wallet rests on the anchor the fresh scan proved, not on the
            // marker the cached handle was originally verified against.
            if let Some(wallet) = self
                .vault_wallet
                .lock()
                .expect("vault wallet lock poisoned")
                .as_mut()
            {
                wallet.anchor = (cold_scan.cache.height, cold_scan.cache.bestblock);
            }
            *self
                .wallet_reimport_pending
                .lock()
                .expect("wallet reimport lock poisoned") = false;
        }
        Ok(())
    }

    /// Run a slow wallet build/repair without occupying the single periodic cache
    /// refresher. The scan-derived cache was published before this is called; later
    /// passes can therefore advance that cache while Core rescans wallet history.
    fn spawn_vault_wallet_seed(&self, scripts: Vec<ScriptBuf>, cold_scan: ColdScan) {
        if self
            .wallet_reimport_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let backend = self.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("vault-wallet-repair".to_string())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    backend.seed_vault_wallet(&scripts, &cold_scan)
                }));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!(
                        "vault descriptor wallet not established, scantxoutset stays in use: {e}"
                    ),
                    Err(_) => eprintln!(
                        "vault descriptor wallet repair panicked; scantxoutset stays in use"
                    ),
                }
                backend
                    .wallet_reimport_in_progress
                    .store(false, Ordering::Release);
            })
        {
            self.wallet_reimport_in_progress
                .store(false, Ordering::Release);
            eprintln!(
                "could not start vault descriptor wallet repair, scantxoutset stays in use: {e}"
            );
        }
    }

    /// Create a blank watch-only wallet and import the scan's exact raw descriptors.
    fn create_vault_wallet(
        &self,
        name: &str,
        scripts: &[ScriptBuf],
        cold_scan: &ColdScan,
    ) -> Result<(), Error> {
        // disable_private_keys, blank, descriptors; do not alter Core's startup list.
        self.call(
            "createwallet",
            json!([name, true, true, "", false, true, false]),
        )?;
        self.import_vault_descriptors(name, scripts, cold_scan)
    }

    /// Import from the cold birthday, then record completion and its chain anchor.
    fn import_vault_descriptors(
        &self,
        name: &str,
        scripts: &[ScriptBuf],
        cold_scan: &ColdScan,
    ) -> Result<(), Error> {
        // The birthday MUST come from the same branch the cold scan ran against, and
        // `block_time_at` reads whatever block occupies that height on the CURRENTLY
        // active chain (codex hn8 review, P1). If a reorg replaces the block at
        // `oldest_unspent_height` between the scan and this call, the timestamp is the
        // replacement branch's — and if it is more than Core's two-hour import grace
        // window LATER, the descriptor rescan begins after the scan branch's actual
        // oldest output. The marker written below still records the SCAN branch, so after
        // a restart that wallet verifies happily while permanently omitting that UTXO.
        //
        // That is not merely a stale cache. The vault balance is the DENOMINATOR of the
        // fire-time escape coverage guard, so understating it INFLATES apparent coverage:
        // an escape that should have been refused looks admissible. It is precisely the
        // inversion this bead was constrained against.
        //
        // Bracket the read with the scan's own anchor. A block hash commits to its entire
        // ancestry, so if `cache.bestblock` still sits at `cache.height` on the active
        // chain, the block at `oldest_unspent_height` — an ancestor of it — is the one the
        // scan saw, and the timestamp is from the right branch. If the anchor has moved,
        // the scan is stale: fail here and let the caller re-scan rather than import
        // against a birthday we cannot vouch for. Failing is safe; importing is not.
        let timestamp = self.block_time_at(cold_scan.oldest_unspent_height)?;
        let anchor_still_active = self
            .block_hash_at(cold_scan.cache.height)?
            .is_some_and(|hash| hash == cold_scan.cache.bestblock);
        if !anchor_still_active {
            return Err(format!(
                "the cold scan's anchor {} at height {} left the active chain before its \
                 birthday could be imported: the descriptor birthday would come from a \
                 different branch, so a vault output could be left permanently unwatched \
                 and the coverage denominator understated. Re-scan.",
                cold_scan.cache.bestblock, cold_scan.cache.height
            )
            .into());
        }
        let mut requests = Vec::with_capacity(scripts.len());
        for script in scripts {
            requests.push(json!({
                "desc": self.checksummed_descriptor(&raw_descriptor(script))?,
                "timestamp": timestamp,
                "active": false,
            }));
        }
        self.import_descriptors(name, &requests)?;
        let marker = self.checksummed_descriptor(&vault_wallet_marker(
            &self.wallet_owner,
            cold_scan.cache.height,
            cold_scan.cache.bestblock,
        ))?;
        self.import_descriptors(
            name,
            &[json!({ "desc": marker, "timestamp": "now", "active": false })],
        )
    }

    /// Accept only a watch-only wallet with the exact vault descriptors and a
    /// node-owned active-chain marker. Repair requires a fresh cold scan. Returns the
    /// `(height, hash)` this wallet's history is proved to rest on.
    fn verify_vault_wallet(
        &self,
        name: &str,
        scripts: &[ScriptBuf],
        cold_scan: Option<&ColdScan>,
    ) -> Result<(u32, BlockHash), Error> {
        let info = self.wallet_call(name, "getwalletinfo", json!([]))?;
        let watch_only = info["private_keys_enabled"].as_bool() == Some(false);
        let expected: HashSet<String> = scripts.iter().map(raw_descriptor).collect();
        let found = self.wallet_descriptors(name)?;
        let scripts_complete = expected.iter().all(|descriptor| found.contains(descriptor));
        // `Some` only when EVERY descriptor this wallet holds beyond the vault's own
        // parses as one of this node's markers, which is also what makes it repairable:
        // repair never imports into a wallet containing a foreign descriptor.
        let anchors: Option<Vec<(u32, BlockHash)>> = found
            .iter()
            .filter(|descriptor| !expected.contains(*descriptor))
            .map(|descriptor| parse_vault_wallet_marker(&self.wallet_owner, descriptor))
            .collect();
        let only_owned_descriptors = anchors.is_some();
        let mut active_marker = None;
        if watch_only {
            for (height, hash) in anchors.unwrap_or_default() {
                if self.block_hash_at(height)? == Some(hash) {
                    active_marker = Some((height, hash));
                    break;
                }
            }
        }
        if let Some(anchor) = active_marker.filter(|_| scripts_complete && only_owned_descriptors) {
            return Ok(anchor);
        }
        let repairable = watch_only && only_owned_descriptors;
        let Some(cold_scan) = cold_scan.filter(|_| repairable) else {
            return Err(format!(
                "wallet {name} is not a complete node-owned vault wallet (watch-only: \
                 {watch_only}, vault descriptors complete: {scripts_complete}, active completion \
                 anchor: {}); refusing to read the vault balance from it",
                active_marker.is_some()
            )
            .into());
        };
        self.import_vault_descriptors(name, scripts, cold_scan)?;
        let repaired = self.wallet_descriptors(name)?;
        let marker = vault_wallet_marker(
            &self.wallet_owner,
            cold_scan.cache.height,
            cold_scan.cache.bestblock,
        );
        if !expected
            .iter()
            .all(|descriptor| repaired.contains(descriptor))
            || !repaired.contains(&marker)
        {
            return Err(
                format!("wallet {name} is still incomplete after finishing its build").into(),
            );
        }
        // `seed_vault_wallet` called us with the same cold scan that just completed
        // this repair. Clear the latch here so it does not import the same descriptors
        // a second time after `ensure_vault_wallet` returns.
        *self
            .wallet_reimport_pending
            .lock()
            .expect("wallet reimport lock poisoned") = false;
        Ok((cold_scan.cache.height, cold_scan.cache.bestblock))
    }

    /// Wallet descriptors without Core's appended checksums.
    fn wallet_descriptors(&self, name: &str) -> Result<HashSet<String>, Error> {
        let listed = self.wallet_call(name, "listdescriptors", json!([]))?;
        let entries = listed["descriptors"]
            .as_array()
            .ok_or("listdescriptors: descriptors is not an array")?;
        entries
            .iter()
            .map(|entry| {
                let desc = entry["desc"]
                    .as_str()
                    .ok_or("listdescriptors: descriptor is not a string")?;
                Ok(desc.split('#').next().unwrap_or(desc).to_string())
            })
            .collect()
    }

    /// Require every import and its rescan to complete.
    fn import_descriptors(&self, wallet: &str, requests: &[Value]) -> Result<(), Error> {
        let results = self.wallet_call_within(
            wallet,
            "importdescriptors",
            json!([requests]),
            WALLET_BUILD_RPC_TIMEOUT,
        )?;
        let entries = results
            .as_array()
            .ok_or("importdescriptors: expected an array")?;
        if entries.len() != requests.len() {
            return Err(format!(
                "importdescriptors into {wallet}: expected {} results, got {}",
                requests.len(),
                entries.len()
            )
            .into());
        }
        for entry in entries {
            if entry["success"].as_bool() != Some(true) {
                return Err(format!("importdescriptors into {wallet} failed: {entry}").into());
            }
        }
        Ok(())
    }

    /// Ask Core for the checksum required by `importdescriptors`.
    fn checksummed_descriptor(&self, descriptor: &str) -> Result<String, Error> {
        let info = self.call("getdescriptorinfo", json!([descriptor]))?;
        info["descriptor"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                format!("getdescriptorinfo {descriptor}: no checksummed descriptor").into()
            })
    }

    /// The active-chain anchor the currently held wallet handle was proved against.
    fn wallet_anchor(&self) -> Option<(u32, BlockHash)> {
        self.vault_wallet
            .lock()
            .expect("vault wallet lock poisoned")
            .as_ref()
            .map(|wallet| wallet.anchor)
    }

    /// Re-prove the active-chain anchor a completed wallet read rests on: the one
    /// [`Self::verify_vault_wallet`] proved for the handle this read just used, which
    /// was active before the read. A `false` here means a reorg deep enough to
    /// invalidate that proof straddled the read, so its result must not be installed.
    fn wallet_read_anchor_held(&self) -> Result<bool, Error> {
        // A successful read always leaves a handle; treat its absence as a lost anchor
        // and repair rather than trusting a read nothing vouches for.
        let Some((height, hash)) = self.wallet_anchor() else {
            return Ok(false);
        };
        Ok(self.block_hash_at(height)? == Some(hash))
    }

    /// Convert the chain-derived birthday height to Core's timestamp form.
    fn block_time_at(&self, height: u32) -> Result<u64, Error> {
        let hash = self
            .block_hash_at(height)?
            .ok_or_else(|| format!("no active block at height {height} for the wallet birthday"))?;
        let header = self.call("getblockheader", json!([hash.to_string(), true]))?;
        header["time"]
            .as_u64()
            .ok_or_else(|| format!("getblockheader {hash}: no block time").into())
    }

    /// Produce a scan-equivalent confirmed candidate superset with `listunspent`.
    /// Reconcile it with wallet history anchored by `listsinceblock.lastblock`:
    /// Bitcoin Core produces that transaction list and anchor under the same wallet
    /// lock, so even an A→B→A reorg around `listunspent` cannot hide an A output.
    /// Downstream `gettxout(include_mempool=true)` removes spent or foreign extras.
    /// The inputs of CONFIRMED wallet debits are dropped, which is what keeps the
    /// carried-forward superset from growing with lifetime deposits.
    fn wallet_confirmed_scan(
        &self,
        scripts: &[ScriptBuf],
        cached: Option<&VaultUnspentCache>,
    ) -> Result<VaultUnspentCache, Error> {
        let (wallet, _) = self.ensure_vault_wallet(scripts, None)?;
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        // Bracket the wallet snapshot by one unchanged active-chain tip.
        for attempt in 0..2 {
            let bestblock = self.best_block_hash()?;
            let unspents = self.wallet_call(
                &wallet,
                "listunspent",
                json!([1, 9_999_999, [], true, { "include_immature_coinbase": true }]),
            )?;
            let mut candidates = HashSet::new();
            for entry in unspents
                .as_array()
                .ok_or("listunspent: expected an array")?
            {
                let script_hex = entry["scriptPubKey"]
                    .as_str()
                    .ok_or("listunspent: unspent has no scriptPubKey")?;
                let script = ScriptBuf::from_hex(script_hex)
                    .map_err(|e| format!("listunspent: bad scriptPubKey: {e}"))?;
                if !watched.contains(&script) {
                    continue;
                }
                candidates.insert(parse_outpoint(entry, "listunspent")?);
            }
            if let Some(cache) = cached {
                candidates.extend(cache.candidates.iter().copied());
            }
            // Add inputs hidden by wallet-known, unconfirmed transactions that DEBIT
            // the vault. Also add confirmed wallet credits since the cache anchor — or
            // from all wallet history after a process restart. The latter makes this
            // transaction list a complete, wallet-anchored candidate source when there
            // is no in-memory superset to preserve.
            //
            // Core reports a debit as a `send` entry. The credit-only categories are
            // listed here rather than testing for `send`, so an entry carrying any
            // OTHER category — a future Core, a shape this code does not know — is
            // both expanded when unconfirmed and treated as a candidate when confirmed:
            // this can only over-collect (the watched-script check in `vault_unspent`
            // discards extras), never under-report the coverage denominator. The
            // confirmed-debit pruning below tests for `send` for the same reason from
            // the other side: an unrecognized category prunes nothing, which costs
            // growth rather than completeness.
            //
            // Verified against Core v31 on regtest: a third-party deposit lists
            // `receive` alone, while a spend of a watched output lists `send` — and so
            // does a spend paying only back to the vault script, because
            // `importdescriptors` gives the descriptor an address-book entry, which
            // keeps its outputs out of Core's change class.
            const CREDIT_ONLY: [&str; 4] = ["receive", "generate", "immature", "orphan"];
            let since = cached
                .map(|cache| Value::String(cache.bestblock.to_string()))
                .unwrap_or(Value::Null);
            let pending = self.wallet_call(
                &wallet,
                "listsinceblock",
                // `include_change=true` ensures a vault output remains visible even if
                // Core classifies it as change. `since` may name a block a reorg has
                // orphaned — Core then answers from the fork point, which is what makes
                // this read reconcile a reorg the wallet can see through; a reorg below
                // the WALLET's anchor never reaches this call, being latched out before
                // it and re-proved after it. Removed-fork entries are unnecessary on top
                // of that: an output a dropped block's transaction spent comes back
                // through `listunspent`, or — while that transaction is still wallet-known
                // but neither confirmed nor resident — through the debit expansion below.
                json!([since, 1, true, false, true]),
            )?;
            let wallet_block_text = pending["lastblock"]
                .as_str()
                .ok_or("listsinceblock: lastblock is not a hash")?;
            let wallet_block = BlockHash::from_str(wallet_block_text)
                .map_err(|e| format!("listsinceblock: bad lastblock hash: {e}"))?;
            let mut pending_txids: HashSet<Txid> = HashSet::new();
            let mut confirmed_debits: HashSet<Txid> = HashSet::new();
            for entry in pending["transactions"]
                .as_array()
                .ok_or("listsinceblock: transactions is not an array")?
            {
                let category = entry["category"]
                    .as_str()
                    .ok_or("listsinceblock: transaction has no category")?;
                let confirmations = entry["confirmations"]
                    .as_i64()
                    .ok_or("listsinceblock: transaction has no confirmations")?;
                if confirmations > 0 {
                    if category == "send" {
                        confirmed_debits.insert(entry_txid(entry)?);
                    } else {
                        candidates.insert(parse_outpoint(entry, "listsinceblock")?);
                    }
                    continue;
                }
                if CREDIT_ONLY.contains(&category) {
                    continue;
                }
                pending_txids.insert(entry_txid(entry)?);
            }
            // One `gettransaction` per wallet transaction whose INPUTS matter, in a
            // stable order so the read sequence stays deterministic. An unconfirmed
            // debit's inputs are added: `listunspent` hides them, but the chain may
            // still hold them (its spender can leave the mempool). A CONFIRMED debit's
            // inputs are collected to be dropped instead.
            let mut expand: Vec<(Txid, bool)> = pending_txids
                .iter()
                .map(|txid| (*txid, false))
                .chain(confirmed_debits.iter().map(|txid| (*txid, true)))
                .collect();
            expand.sort();
            let mut spent: HashSet<OutPoint> = HashSet::new();
            for (txid, confirmed) in &expand {
                let tx = self.wallet_call(
                    &wallet,
                    "gettransaction",
                    json!([txid.to_string(), true, true]),
                )?;
                // Malformed input data must fall back, never silently under-report.
                let inputs = tx["decoded"]["vin"]
                    .as_array()
                    .ok_or_else(|| format!("gettransaction {txid}: decoded.vin is not an array"))?;
                for vin in inputs {
                    if vin.get("txid").is_none() {
                        continue;
                    }
                    let outpoint = parse_outpoint(vin, "gettransaction")?;
                    if *confirmed {
                        spent.insert(outpoint);
                    } else {
                        candidates.insert(outpoint);
                    }
                }
            }
            // Prune LAST, so a confirmed spend overrides every other source. Without
            // this the wallet-derived set only grows: `listunspent` stops reporting a
            // spent output, but the carried-forward cache — and, after a restart, every
            // confirmed credit in the wallet's whole history — puts it back, and the
            // fire path's batched `gettxout` would then scale with lifetime deposits
            // instead of live outputs. Dropping them is safe in both directions: the
            // active chain has consumed them, so `gettxout` answers null for each, and
            // a reorg that un-spends one either leaves the wallet's completion anchor
            // active (so `listunspent`, or the unconfirmed-debit expansion above,
            // reports it again on the next pass) or unseats that anchor and latches the
            // wallet out for a full rescan. An output the WALLET does not know — one
            // only a fallback scan ever saw, below the birthday — is not pruned here,
            // because its spender is no debit of this wallet.
            candidates.retain(|outpoint| !spent.contains(outpoint));
            if self.best_block_hash()? == bestblock {
                return Ok(VaultUnspentCache {
                    height: self.confirm_active_height(wallet_block)?,
                    bestblock: wallet_block,
                    scripts: scripts.to_vec(),
                    candidates,
                });
            }
            if attempt == 1 {
                return Err(
                    "the chain tip moved again while reading the vault wallet's unspent view"
                        .into(),
                );
            }
        }
        unreachable!("the bounded snapshot loop always returns or errors")
    }

    /// Advance a warm confirmed-vault cache through at most
    /// [`MAX_VAULT_SCAN_DELTA_BLOCKS`] active blocks. Transactions add watched
    /// outputs and remove every spent outpoint. Parent linkage plus a terminal
    /// active-hash re-read makes the update transactional across a racing reorg.
    fn advance_confirmed_scan(
        &self,
        mut cache: VaultUnspentCache,
    ) -> Result<VaultUnspentCache, Error> {
        let tip = self.tip_height()?;
        if tip <= cache.height {
            return Ok(cache);
        }
        let through = tip.min(cache.height.saturating_add(MAX_VAULT_SCAN_DELTA_BLOCKS));
        let watched: HashSet<ScriptBuf> = cache.scripts.iter().cloned().collect();
        let mut parent = cache.bestblock;
        for height in cache.height + 1..=through {
            let hash = self.block_hash_at(height)?.ok_or_else(|| {
                format!("vault scan delta: active block at height {height} vanished")
            })?;
            let block = self.call("getblock", json!([hash.to_string(), 2]))?;
            let expected_parent = parent.to_string();
            if block["previousblockhash"].as_str() != Some(expected_parent.as_str()) {
                return Err(format!(
                    "vault scan delta: block {hash} at height {height} does not chain to \
                     cached parent {parent}; discarding the raced update"
                )
                .into());
            }
            let txs = block["tx"]
                .as_array()
                .ok_or("vault scan delta: getblock tx is not an array")?;
            for tx in txs {
                for vin in tx["vin"].as_array().into_iter().flatten() {
                    let (Some(txid), Some(vout)) = (vin["txid"].as_str(), vin["vout"].as_u64())
                    else {
                        // Coinbase has no previous outpoint.
                        continue;
                    };
                    let vout = u32::try_from(vout)
                        .map_err(|_| "vault scan delta: input vout exceeds u32")?;
                    cache.candidates.remove(&OutPoint::new(
                        Txid::from_str(txid)
                            .map_err(|e| format!("vault scan delta: bad input txid: {e}"))?,
                        vout,
                    ));
                }
                let txid_text = tx["txid"]
                    .as_str()
                    .ok_or("vault scan delta: transaction has no txid")?;
                let txid = Txid::from_str(txid_text)
                    .map_err(|e| format!("vault scan delta: bad transaction txid: {e}"))?;
                let outputs = tx["vout"]
                    .as_array()
                    .ok_or("vault scan delta: transaction vout is not an array")?;
                for (vout, output) in outputs.iter().enumerate() {
                    let script_hex = output["scriptPubKey"]["hex"]
                        .as_str()
                        .ok_or("vault scan delta: output has no scriptPubKey hex")?;
                    let script = ScriptBuf::from_hex(script_hex)
                        .map_err(|e| format!("vault scan delta: bad output scriptPubKey: {e}"))?;
                    if watched.contains(&script) {
                        let vout = u32::try_from(vout)
                            .map_err(|_| "vault scan delta: output index exceeds u32")?;
                        cache.candidates.insert(OutPoint::new(txid, vout));
                    }
                }
            }
            parent = hash;
        }
        if self.block_hash_at(through)? != Some(parent) {
            return Err(format!(
                "vault scan delta: terminal block {parent} at height {through} is no longer active"
            )
            .into());
        }
        cache.bestblock = parent;
        cache.height = through;
        Ok(cache)
    }

    /// The current confirmed-UTXO membership paying `scripts`, read only from the
    /// background-maintained cache. Cold or stale is an immediate error — never a
    /// synchronous `scantxoutset` or wallet read on the fire/combine path.
    fn confirmed_candidates(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<(BlockHash, Vec<OutPoint>), Error> {
        let tip = self.best_block_hash()?;
        let cache = self.scan_cache.lock().expect("scan cache lock poisoned");
        let cached = cache
            .as_ref()
            .filter(|cache| cache.scripts == scripts && cache.bestblock == tip)
            .ok_or_else(|| {
                "confirmed vault cache is cold or behind the active tip; refusing the fire-time \
                 coverage check without running scantxoutset on the combine path"
                    .to_string()
            })?;
        let mut candidates: Vec<_> = cached.candidates.iter().copied().collect();
        candidates.sort();
        Ok((tip, candidates))
    }

    /// The node's current mempool txid set. Coverage snapshots compare the complete
    /// set before and after enumeration: any membership change can alter whether
    /// `gettxout(..., true)` exposes a confirmed vault output.
    fn mempool_txids(&self) -> Result<HashSet<Txid>, Error> {
        let mempool = self.call("getrawmempool", json!([]))?;
        let entries = mempool
            .as_array()
            .ok_or("getrawmempool: expected an array")?;
        entries
            .iter()
            .map(|entry| {
                let txid = entry
                    .as_str()
                    .ok_or("getrawmempool: entry is not a txid string")?;
                Txid::from_str(txid)
                    .map_err(|e| format!("getrawmempool: bad txid {txid}: {e}").into())
            })
            .collect()
    }

    /// The node's current mempool txid set together with Core's monotonic
    /// `mempool_sequence`. The sequence increments on EVERY mempool add and remove,
    /// so an unchanged sequence across two reads proves nothing entered or left in
    /// between — including a transient transaction that both enters and leaves
    /// between the reads, which comparing the txid-set endpoints alone would miss.
    fn mempool_snapshot(&self) -> Result<(HashSet<Txid>, u64), Error> {
        // `getrawmempool false true`: the non-verbose txid list plus the sequence.
        let reply = self.call("getrawmempool", json!([false, true]))?;
        let sequence = reply
            .get("mempool_sequence")
            .and_then(Value::as_u64)
            .ok_or("getrawmempool: missing mempool_sequence")?;
        let entries = reply
            .get("txids")
            .and_then(Value::as_array)
            .ok_or("getrawmempool: txids is not an array")?;
        let txids = entries
            .iter()
            .map(|entry| {
                let txid = entry
                    .as_str()
                    .ok_or("getrawmempool: txid entry is not a string")?;
                Txid::from_str(txid)
                    .map_err(|e| format!("getrawmempool: bad txid {txid}: {e}").into())
            })
            .collect::<Result<HashSet<Txid>, Error>>()?;
        Ok((txids, sequence))
    }

    fn refresh_vault_unspent_cache_mode(
        &self,
        scripts: &[ScriptBuf],
        seed_in_background: bool,
    ) -> Result<(), Error> {
        let cached = self
            .scan_cache
            .lock()
            .expect("scan cache lock poisoned")
            .as_ref()
            .filter(|cache| cache.scripts == scripts)
            .cloned();
        // A reorg can resurrect a vault output created BEFORE the wallet's birthday —
        // spent in a dropped block by a transaction that paid the vault nothing, so
        // the wallet neither watched the output nor holds that transaction and no
        // wallet-only read can ever surface it again. Latch the wallet out until a
        // cold scan and re-import repair it.
        //
        // The boundary for that is the WALLET's own completion anchor, not the last
        // pass's tip. A block hash commits to its whole ancestry, so while the
        // anchor's `(height, hash)` is still active no block at or below that height
        // has moved: every output a higher reorg can resurrect was unspent AT the
        // anchor, is therefore at or after the birthday that anchor's own import
        // proved (`ColdScan::oldest_unspent_height`), and is therefore already
        // watched. Latching on the tip instead would make a routine 1-block reorg pay
        // a whole-set scan AND an `importdescriptors` rescan of the vault's history,
        // during which the fire path has no current cache to read — a far wider
        // outage than the event warrants. A pass holding no handle needs no check
        // here: [`Self::verify_vault_wallet`] re-proves an active marker before that
        // wallet may serve.
        let reorged = match self.wallet_anchor() {
            Some((height, hash)) => self.block_hash_at(height)? != Some(hash),
            None => false,
        };
        let mut repair_pending = {
            let mut pending = self
                .wallet_reimport_pending
                .lock()
                .expect("wallet reimport lock poisoned");
            *pending |= reorged;
            *pending
        };
        let repair_in_progress = self.wallet_reimport_in_progress.load(Ordering::Acquire);
        // Primary path: one wallet `listunspent`, no whole-set scan on restart. Do
        // not race a wallet read against a descriptor import this process started.
        if !repair_pending && !repair_in_progress {
            match self.wallet_confirmed_scan(scripts, cached.as_ref()) {
                Ok(cache) => {
                    // The reorg check above ran BEFORE that read. Re-prove the same
                    // anchor now that it has finished, because a reorg landing DURING
                    // the read is not a transient loss: the wallet-blind result would
                    // be installed and serve the coverage denominator until the next
                    // pass — a silent understatement, i.e. inflated escape coverage,
                    // in exactly the window an attacker who can reorg controls.
                    if self.wallet_read_anchor_held()? {
                        *self.scan_cache.lock().expect("scan cache lock poisoned") = Some(cache);
                        return Ok(());
                    }
                    *self
                        .wallet_reimport_pending
                        .lock()
                        .expect("wallet reimport lock poisoned") = true;
                    repair_pending = true;
                    eprintln!(
                        "a reorg landed while reading the vault wallet; discarding that read and \
                         re-importing the descriptors from a fresh scan"
                    );
                }
                // Missing, failed, or unrecognized wallets fall back, never to empty.
                Err(e) => {
                    // Drop the verified handle too. bitcoind restarting unloads a wallet
                    // this node created with `load_on_startup=false`, and a cached name
                    // would keep every later wallet call failing — pinning the node to
                    // the fallback until the NODE restarts — instead of re-`loadwallet`ing.
                    *self
                        .vault_wallet
                        .lock()
                        .expect("vault wallet lock poisoned") = None;
                    eprintln!(
                        "vault descriptor-wallet read unavailable, falling back to scantxoutset: {e}"
                    )
                }
            }
        }
        // Deltas preserve the candidate superset regardless of its source, but the
        // walk can only EXTEND an anchor that is still active: a reorg that unseated
        // the cache's own anchor (shallower than the wallet's, so it does not latch)
        // leaves nothing for the delta to chain onto, and rescanning is the only way
        // to reconcile it. Pending repair normally must rescan too, to re-derive the
        // birthday. Once that cold scan has launched a background repair, however, its
        // complete scan-derived cache is a safe delta base while the import runs.
        // This check costs an RPC only on the fallback path — a served wallet read
        // has already returned above.
        let delta_base = match cached {
            Some(cache)
                if (!repair_pending || repair_in_progress)
                    && self.block_hash_at(cache.height)? == Some(cache.bestblock) =>
            {
                Some(cache)
            }
            _ => None,
        };
        let refreshed = match delta_base {
            Some(cache) => self.advance_confirmed_scan(cache)?,
            None => {
                let cold = self.full_confirmed_scan(scripts)?;
                // Publish the complete scan-derived view BEFORE building the wallet.
                // `importdescriptors` rescans, which this backend budgets minutes for
                // ([`WALLET_BUILD_RPC_TIMEOUT`]), and withholding the cache for that long
                // would leave `confirmed_candidates` cold — no escape sweep can run —
                // exactly when a reorg forced this branch.
                *self.scan_cache.lock().expect("scan cache lock poisoned") =
                    Some(cold.cache.clone());
                // A failed seed leaves that scan-derived cache serving, and which pass
                // retries it depends on whether the latch is set — the two cases differ:
                //
                // - Seeding a wallet this backend never had (no latch). The next pass
                //   finds a warm cache and a clear latch, so it takes the delta arm above
                //   and never re-enters this branch; the wallet is re-attempted only on a
                //   later reorg or a process restart. That is deliberate. This branch
                //   opens with a whole-set scan, so re-entering it every pass would turn
                //   one transient failure into the very scan storm this bead removes, and
                //   the price of not retrying is bounded: the cache stays complete and
                //   scan-derived, advanced by cheap deltas.
                // - Repairing after a reorg below the WALLET's completion anchor (latch
                //   set). Only a successful import clears the latch. A live-node refresh
                //   moves that slow import off this cache-refresher thread, allowing the
                //   scan-derived cache to advance by deltas meanwhile; a failed import
                //   clears the in-progress flag, so the next pass scans and retries.
                if seed_in_background {
                    self.spawn_vault_wallet_seed(scripts.to_vec(), cold.clone());
                } else if let Err(e) = self.seed_vault_wallet(scripts, &cold) {
                    eprintln!(
                        "vault descriptor wallet not established, scantxoutset stays in use: {e}"
                    );
                }
                cold.cache
            }
        };
        *self.scan_cache.lock().expect("scan cache lock poisoned") = Some(refreshed);
        Ok(())
    }

    /// Fetch raw transaction bytes without taking another complete mempool
    /// snapshot. Callers either already proved membership from their own snapshot
    /// or tolerate a concurrent eviction/confirmation as `None` and reconcile it.
    fn raw_transaction_if_available(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
        let reply = self.call_reply("getrawtransaction", json!([txid.to_string()]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-5) {
                return Ok(None);
            }
            return Err(format!("bitcoind getrawtransaction: {}", reply["error"]).into());
        }
        let hex = reply["result"]
            .as_str()
            .ok_or("getrawtransaction: expected a hex string")?;
        Ok(Some(
            Vec::<u8>::from_hex(hex).map_err(|e| format!("getrawtransaction: bad hex: {e}"))?,
        ))
    }
}

impl ChainBackend for BitcoindBackend {
    fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
        // Validate locally so a malformed tx is a clean Err instead of garbage on
        // the wire: deserialize, then hand bitcoind the canonical hex.
        let tx: Transaction =
            consensus::deserialize(raw_tx).map_err(|e| format!("malformed transaction: {e}"))?;
        let result = self.call("sendrawtransaction", json!([serialize_hex(&tx)]))?;
        let txid = result
            .as_str()
            .ok_or("sendrawtransaction: expected a txid string")?;
        Txid::from_str(txid)
            .map_err(|e| format!("sendrawtransaction returned a bad txid: {e}").into())
    }

    fn tip_height(&self) -> Result<u32, Error> {
        Ok(self
            .call("getblockcount", json!([]))?
            .as_u64()
            .ok_or("getblockcount: not a number")? as u32)
    }

    fn block_median_feerate(&self, height: u32) -> Result<Option<u64>, Error> {
        // `feerate_percentiles[2]` is Core's 50th-percentile feerate for the block at
        // `height` on its ACTIVE chain, in sat/vB. Two nodes agreeing on the chain
        // therefore agree on this number exactly, which is the property the escape
        // bump target rests on. Code -8 is "block height out of range" (above the tip
        // / a chain shortened by a reorg); that means "no reading here", so the
        // selector simply does not bump. Every other RPC error surfaces.
        let reply = self.call_reply("getblockstats", json!([height, ["feerate_percentiles"]]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-8) {
                return Ok(None);
            }
            return Err(format!("bitcoind getblockstats: {}", reply["error"]).into());
        }
        let percentiles = reply["result"]["feerate_percentiles"]
            .as_array()
            .ok_or("getblockstats: feerate_percentiles is not an array")?;
        let median = percentiles
            .get(2)
            .and_then(Value::as_u64)
            .ok_or("getblockstats: no integer 50th-percentile feerate")?;
        Ok(Some(median))
    }

    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, Error> {
        // `getblockhash` errors with code -8 ("Block height out of range") for a
        // height above the active tip. That is the reorg-shortened-chain case the
        // cursor must read as "no block here" (→ rewind), NOT a backend failure, so
        // fold -8 to `None` and surface every other RPC error.
        let reply = self.call_reply("getblockhash", json!([height]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-8) {
                return Ok(None);
            }
            return Err(format!("bitcoind getblockhash: {}", reply["error"]).into());
        }
        let hash = reply["result"]
            .as_str()
            .ok_or("getblockhash: expected a hash string")?;
        Ok(Some(
            BlockHash::from_str(hash).map_err(|e| format!("getblockhash: bad hash: {e}"))?,
        ))
    }

    fn spends_of(
        &self,
        scripts: &[ScriptBuf],
        from_height: u32,
        through_height: u32,
        expected_parent: Option<BlockHash>,
    ) -> Result<ScanTraversal, Error> {
        // Scan blocks through the caller's captured terminal height; a watched script is spent
        // when some input's prevout carries it. `getblock` verbosity 3 (Core v25+)
        // inlines each input's `prevout`, so no per-input `getrawtransaction` is
        // needed. Bounded work on regtest; the Core/Electrum/filter tradeoff for
        // real networks is v1 (T6).
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        let mut seen = Vec::new();
        // Mid-scan reorg guard (deliverable 9y5.3-a): the per-height reads below are
        // NOT an atomic chain snapshot, so a reorg that swaps the active block at some
        // height while this loop straddles it could read a fork this node no longer
        // follows and silently miss the spends of the one it does. THREE checks together
        // make the traversed range provably a contiguous extension of the caller's
        // cursor along the ACTIVE chain:
        //
        //  0. the FIRST block must chain onto `expected_parent`, the newest cursor
        //     anchor the caller is extending. Without it, a reorg that forks BELOW
        //     `from_height` and rebuilds taller — landing between the caller's pre-scan
        //     anchor check and this scan — leaves a new-fork `from_height` block whose
        //     ancestors this scan never traversed; checks 1 and 2 both pass on the new
        //     fork alone, and the anchor it is appended to no longer chains (9y5.3 [P1]);
        //  1. consecutive scanned blocks must CHAIN (`block[h].previousblockhash ==
        //     block[h-1].hash`), so a MIXED-fork straddle breaks the linkage; and
        //  2. after the loop, the LAST block actually traversed must STILL be the
        //     active block at its height (below). Headers chain backwards, so that one
        //     re-read proves every earlier traversed block is its ancestor and so also
        //     active.
        //
        // Check 2 is what closes the case check 1 cannot see: a loop that read a single
        // foreign fork END-TO-END is internally consistent, and an A→B→A that returns to
        // the original tip also slips past `scan_pass`'s post-scan tip-hash check, so
        // without it a whole scan could be bound to a fork the node has abandoned. The
        // returned `blocks` carry the proven `(height, hash)` chain so the watchtower
        // binds its anchors to exactly what this scan traversed, never a second re-read.
        //
        // Any failure is an error, so the pass discards its results and retries from
        // an unadvanced cursor rather than binding one fork's spends and skipping the
        // active chain's.
        let mut last_scanned: Option<(u32, String)> = None;
        let mut blocks: Vec<(u32, BlockHash)> = Vec::new();
        for height in from_height..=through_height {
            let hash = self
                .call("getblockhash", json!([height]))?
                .as_str()
                .ok_or("getblockhash: expected a hash string")?
                .to_string();
            let block = self.call("getblock", json!([hash, 3]))?;
            // The block at `from_height` must chain onto `expected_parent` (the cursor
            // anchor being extended); every later block must chain onto the one just
            // scanned. Together with the terminal re-check below, this proves the whole
            // traversal is a contiguous extension of the caller's cursor along THIS
            // active chain — closing BOTH the mixed-fork straddle (check 1) and the
            // taller-fork reorg that races between the caller's pre-scan anchor read and
            // this scan, whose new `from_height` block does not chain onto the anchor.
            let required_parent = match &last_scanned {
                Some((_, prev)) => Some(prev.clone()),
                None => expected_parent.map(|parent| parent.to_string()),
            };
            if let Some(required) = required_parent {
                let parent = block["previousblockhash"]
                    .as_str()
                    .ok_or("getblock: block has no previousblockhash (verbosity 3 required)")?;
                if parent != required {
                    return Err(format!(
                        "getblock: block at height {height} does not chain onto the \
                         expected parent {required} (a reorg raced the scan); refusing to \
                         bind a mixed-fork or unrooted scan and re-scanning next pass"
                    )
                    .into());
                }
            }
            last_scanned = Some((height, hash.clone()));
            blocks.push((
                height,
                BlockHash::from_str(&hash)
                    .map_err(|e| format!("getblockhash: bad block hash at height {height}: {e}"))?,
            ));
            let txs = block["tx"].as_array().ok_or("getblock: tx not an array")?;
            for tx in txs {
                let spend_txid = tx["txid"].as_str().ok_or("getblock: tx has no txid")?;
                for vin in tx["vin"].as_array().into_iter().flatten() {
                    // A coinbase input spends nothing and carries a `coinbase`
                    // field in place of a prevout; skip only genuine coinbase
                    // inputs. EVERY other input must carry its prevout (getblock
                    // verbosity 3 inlines it): a missing/malformed prevout here
                    // would silently drop a possibly-watched spend and make the
                    // watchtower miss its alert, so surface it as an error, never
                    // a false negative.
                    if vin.get("coinbase").is_some() {
                        continue;
                    }
                    let prevout = vin.get("prevout").ok_or(
                        "getblock: non-coinbase input has no prevout (verbosity 3 required)",
                    )?;
                    let spk_hex = prevout["scriptPubKey"]["hex"]
                        .as_str()
                        .ok_or("getblock: prevout has no scriptPubKey hex")?;
                    let spk = ScriptBuf::from_hex(spk_hex)
                        .map_err(|e| format!("getblock: bad prevout scriptPubKey: {e}"))?;
                    if !watched.contains(&spk) {
                        continue;
                    }
                    let prev_txid = vin["txid"].as_str().ok_or("getblock: input has no txid")?;
                    let vout = vin["vout"].as_u64().ok_or("getblock: input has no vout")? as u32;
                    // The spending witness (verbosity 3 inlines `txinwitness` for
                    // segwit inputs), so the watchtower can tell WHICH branch of the
                    // two-branch `wsh(...)` this spend took — a recovery spend and a
                    // normal spend share the prevout script and differ only here. A
                    // non-segwit input has no `txinwitness`; that never matches a
                    // vault P2WSH, so an empty witness (classified as non-recovery)
                    // is the safe default.
                    let mut witness_items = Vec::new();
                    for item in vin
                        .get("txinwitness")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let hex = item
                            .as_str()
                            .ok_or("getblock: txinwitness item is not a string")?;
                        witness_items.push(
                            Vec::<u8>::from_hex(hex)
                                .map_err(|e| format!("getblock: bad txinwitness item: {e}"))?,
                        );
                    }
                    seen.push(SpendSeen {
                        spend_txid: Txid::from_str(spend_txid)
                            .map_err(|e| format!("getblock: bad spend txid: {e}"))?,
                        outpoint: OutPoint::new(
                            Txid::from_str(prev_txid)
                                .map_err(|e| format!("getblock: bad prevout txid: {e}"))?,
                            vout,
                        ),
                        script: spk,
                        witness: Witness::from_slice(&witness_items),
                    });
                }
            }
        }
        // Check 2 (see above): the newest block this loop actually READ must still be
        // the active block at its height. A scan that ran entirely on a fork the node
        // has since abandoned fails here instead of returning that fork's spends as if
        // they were the active chain's.
        if let Some((height, hash)) = last_scanned {
            let active = self.call("getblockhash", json!([height]))?;
            if active.as_str() != Some(hash.as_str()) {
                return Err(format!(
                    "getblockhash: block {hash} scanned at height {height} is no longer the \
                     active block there (a reorg raced the scan); refusing to bind an \
                     abandoned fork's spends and re-scanning next pass"
                )
                .into());
            }
        }
        Ok(ScanTraversal {
            spends: seen,
            blocks,
        })
    }

    fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
        // `include_mempool = true` is the whole point: an unconfirmed vault
        // spend-change or refresh output is the COMMON case (ADR-0012), and
        // `gettxout` would not see it otherwise. A spent or unknown output comes
        // back as JSON null.
        let result = self.call(
            "gettxout",
            json!([outpoint.txid.to_string(), outpoint.vout, true]),
        )?;
        Self::parse_prevout(&result)
    }

    fn prevouts(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<Prevout>>, Error> {
        if outpoints.is_empty() {
            return Ok(Vec::new());
        }
        // One HTTP request and one fixed RPC timeout for the complete PSBT
        // preflight. The hostile coordinator therefore cannot
        // multiply a slow/down backend's network timeout by the number of inputs
        // while `/sign` holds its serialization lock.
        let requests: Vec<Value> = outpoints
            .iter()
            .enumerate()
            .map(|(id, outpoint)| {
                json!({
                    "jsonrpc": "1.0",
                    "id": id,
                    "method": "gettxout",
                    "params": [outpoint.txid.to_string(), outpoint.vout, true],
                })
            })
            .collect();
        let body = post_json(
            self.rpc_addr,
            &Value::Array(requests).to_string(),
            &self.auth,
        )?;
        let replies: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("bitcoind gettxout batch: unparseable reply: {e}"))?;
        if replies.len() != outpoints.len() {
            return Err(format!(
                "bitcoind gettxout batch: expected {} replies, got {}",
                outpoints.len(),
                replies.len()
            )
            .into());
        }
        let mut ordered = vec![None; outpoints.len()];
        for reply in replies {
            let id = reply["id"]
                .as_u64()
                .and_then(|id| usize::try_from(id).ok())
                .filter(|id| *id < outpoints.len())
                .ok_or("bitcoind gettxout batch: missing or out-of-range reply id")?;
            if ordered[id].is_some() {
                return Err(format!("bitcoind gettxout batch: duplicate reply id {id}").into());
            }
            if !reply["error"].is_null() {
                return Err(
                    format!("bitcoind gettxout batch item {id}: {}", reply["error"]).into(),
                );
            }
            ordered[id] = Some(Self::parse_prevout(&reply["result"])?);
        }
        ordered
            .into_iter()
            .enumerate()
            .map(|(id, result)| {
                result
                    .ok_or_else(|| format!("bitcoind gettxout batch: missing reply id {id}").into())
            })
            .collect()
    }

    fn vault_unspent(
        &self,
        scripts: &[ScriptBuf],
        authorized: &HashSet<Txid>,
    ) -> Result<Vec<(OutPoint, Prevout)>, Error> {
        // Confirmed balance: scan the node's own UTXO set for the exact vault
        // script(s), then re-read each result through `gettxout(..., true)` so an
        // output already spent by a mempool transaction is not double-counted.
        //
        // SCALING (deliverable 9y5.3-c; bead btc-policy-hn8): no confirmed-set read of
        // ANY kind happens on this hot path. A dedicated background task maintains the
        // cache — from the node-owned descriptor wallet, or from the `scantxoutset`
        // fallback — and here [`Self::confirmed_candidates`] accepts only a cache
        // already at the active tip; cold/stale fails immediately (no sweep; Lockdown
        // already latched) rather than consuming the finite combine window.
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        // There is no atomic chain+mempool JSON-RPC snapshot. Take bounded full
        // passes instead, bracketing each with Core's monotonic `mempool_sequence`
        // (bumped on EVERY add and remove). An unchanged sequence AND an unchanged
        // tip across the pass prove the scan/gettxout reads saw one consistent
        // chain+mempool view — including that no transaction transiently entered and
        // left between the two reads (an ABA that comparing the txid-set endpoints
        // alone would miss). A changed sequence or tip retries once; a second
        // unstable pass fails closed (no sweep; Lockdown already latched) rather than
        // admit an escape against an understated coverage denominator.
        for attempt in 0..2 {
            // Snapshot the FULL mempool, not just its intersection with the
            // authorized set. An unauthorized mempool transaction can temporarily
            // suppress a confirmed vault output from `gettxout(..., true)`; any such
            // membership motion during the pass bumps the sequence below and forces a
            // retry, whether the suppressor stays or is evicted before the pass ends,
            // so an understated confirmed denominator is never accepted.
            let (mempool_before, sequence_before) = self.mempool_snapshot()?;
            // The confirmed-set candidates from the current-tip cache, then one
            // batched `gettxout(..., include_mempool=true)` re-validation that drops any
            // confirmed output a mempool transaction has since spent — exactly as
            // before the cache existed; the cache only skips the whole-set scan.
            let (scan_tip, candidates) = self.confirmed_candidates(scripts)?;
            let mut found: HashMap<OutPoint, Prevout> = HashMap::new();
            let confirmed_prevouts = self.prevouts(&candidates)?;
            if confirmed_prevouts.len() != candidates.len() {
                return Err(format!(
                    "chain backend returned {} confirmed-candidate prevouts for {} outpoints",
                    confirmed_prevouts.len(),
                    candidates.len()
                )
                .into());
            }
            for (outpoint, prevout) in candidates.iter().zip(confirmed_prevouts) {
                if let Some(prevout) = prevout {
                    if watched.contains(&prevout.txout.script_pubkey) && prevout.confirmed {
                        found.insert(*outpoint, prevout);
                    }
                }
            }

            // Authorized-unconfirmed balance: only transactions this node accepted may
            // contribute. Reading just those txids avoids scanning unrelated mempool
            // traffic and structurally excludes external unconfirmed deposits.
            for txid in mempool_before.intersection(authorized) {
                let Some(raw) = self.raw_transaction_if_available(txid)? else {
                    continue;
                };
                let tx: Transaction = consensus::deserialize(&raw).map_err(|e| {
                    format!("authorized mempool transaction {txid} is malformed: {e}")
                })?;
                for (vout, output) in tx.output.iter().enumerate() {
                    if !watched.contains(&output.script_pubkey) {
                        continue;
                    }
                    let vout = u32::try_from(vout).map_err(|_| {
                        format!("authorized transaction {txid} has too many outputs")
                    })?;
                    let outpoint = OutPoint::new(*txid, vout);
                    if let Some(prevout) = self.prevout(&outpoint)? {
                        if !prevout.confirmed {
                            found.insert(outpoint, prevout);
                        }
                    }
                }
            }
            let tip_after = self.best_block_hash()?;
            let (_, sequence_after) = self.mempool_snapshot()?;
            if scan_tip == tip_after && sequence_before == sequence_after {
                let mut found: Vec<_> = found.into_iter().collect();
                found.sort_by_key(|(outpoint, _)| *outpoint);
                return Ok(found);
            }

            if attempt == 1 {
                return Err("chain tip or mempool membership changed again while \
                     reconciling the vault UTXO snapshot"
                    .into());
            }
        }
        unreachable!("the bounded snapshot loop always returns or errors")
    }

    fn refresh_vault_unspent_cache(&self, scripts: &[ScriptBuf]) -> Result<(), Error> {
        self.refresh_vault_unspent_cache_mode(scripts, false)
    }

    fn refresh_vault_unspent_cache_live(&self, scripts: &[ScriptBuf]) -> Result<(), Error> {
        self.refresh_vault_unspent_cache_mode(scripts, true)
    }

    fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
        // Query membership explicitly instead of probing an English RPC error or
        // relying on `-txindex`. A confirmed parent is absent here; an unconfirmed
        // ancestor is present and getrawtransaction can always read mempool data.
        if !self.mempool_txids()?.contains(txid) {
            return Ok(None);
        }
        self.raw_transaction_if_available(txid)
    }

    /// ONE `getrawmempool` for the whole batch, then at most one
    /// `getrawtransaction` for the rung that is actually resident (bead
    /// btc-policy-nvr). The default implementation would call
    /// [`Self::mempool_transaction`] per txid, and each of those pulls the entire
    /// mempool — four full snapshots per fire tick for a full ladder, precisely when
    /// the mempool is largest and the combine window tightest.
    ///
    /// Membership is resolved against a SINGLE snapshot, which is also more coherent
    /// than the per-call version: every rung is judged against one instant of the
    /// mempool rather than against up to four successive ones.
    fn mempool_resident(&self, txids: &[Txid]) -> Result<Option<(Txid, Vec<u8>)>, Error> {
        if txids.is_empty() {
            return Ok(None);
        }
        let resident = self.mempool_txids()?;
        let Some(found) = txids.iter().find(|txid| resident.contains(*txid)) else {
            return Ok(None);
        };
        // A txid that was in the snapshot can still be gone by the time this reads it (a
        // block arrived — though `-txindex` still answers for a just-mined rung — or it
        // was evicted by a peer's higher rung). Absence then answers `None` for the WHOLE
        // batch rather than falling through to the remaining txids against a fresh
        // snapshot, which the per-rung loop would have done. That is deliberate and
        // fail-closed: a `None` while a rung is in fact resident makes the fire pass find
        // Core hiding the prevouts that rung spends, so coverage/package assembly errors
        // out, no share is released, and the latch (committed only after the fallible
        // checks) is untouched — the next 1 Hz tick simply reads the newer snapshot. The
        // per-rung loop reached the same terminal state whenever the race hit the last
        // rung it checked, so this widens a benign existing window rather than opening a
        // new class of failure.
        Ok(self
            .raw_transaction_if_available(found)?
            .map(|raw| (*found, raw)))
    }

    fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error> {
        // Production startup verifies a fully-synced `-txindex=1`, so this can
        // distinguish a mined transaction from one that is merely absent.
        // Preserve Core's structured -5 "not found" result as ordinary `false`;
        // every other RPC failure remains an error and leaves the candidate for a
        // later retry.
        let reply = self.call_reply("getrawtransaction", json!([txid.to_string(), true]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-5) {
                return Ok(false);
            }
            return Err(format!("bitcoind getrawtransaction: {}", reply["error"]).into());
        }
        let result = reply["result"]
            .as_object()
            .ok_or("getrawtransaction: expected a verbose transaction object")?;
        Ok(result
            .get("confirmations")
            .and_then(Value::as_u64)
            .is_some_and(|confirmations| confirmations > 0))
    }

    fn test_package_accept(&self, raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error> {
        if raw_txs.is_empty() {
            return Err("cannot package-test an empty package".into());
        }
        let hexes: Vec<String> = raw_txs
            .iter()
            .map(|raw| raw.to_lower_hex_string())
            .collect();
        let result = self.call("testmempoolaccept", json!([hexes]))?;
        let entries = result
            .as_array()
            .ok_or("testmempoolaccept: expected an array")?;
        for entry in entries {
            if entry["allowed"].as_bool() == Some(true) {
                continue;
            }
            let reason = entry["reject-reason"].as_str().unwrap_or("unknown");
            // An ancestor we carried into the package is ALREADY in this node's
            // mempool — that is the normal case for a vault-authorized
            // unconfirmed parent, and bitcoind reports it as a per-entry
            // rejection. It means the parent is present and valid, which is
            // exactly what the package needs, so it is not a reason to withhold
            // the broadcast.
            if reason == "txn-already-in-mempool" {
                continue;
            }
            let txid = entry["txid"].as_str().unwrap_or("?");
            return Ok(PackageVerdict::Rejected(format!("{txid}: {reason}")));
        }
        Ok(PackageVerdict::Accepted)
    }
}

/// Read/write deadline on one bitcoind JSON-RPC call. Fixed loopback-regtest
/// value, never a config knob; the connect deadline below is shorter.
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Wallet loading/catch-up and `importdescriptors` may synchronously scan history.
const WALLET_BUILD_RPC_TIMEOUT: Duration = Duration::from_secs(600);

/// Exact descriptor shared by the wallet and `scantxoutset`.
fn raw_descriptor(script: &ScriptBuf) -> String {
    format!("raw({})", script.as_bytes().to_lower_hex_string())
}

/// Inert completion marker persisting the owner and cold-scan anchor across restarts.
fn vault_wallet_marker(
    wallet_owner: &[u8; 32],
    anchor_height: u32,
    anchor_hash: BlockHash,
) -> String {
    format!(
        "raw(6a4c44{}{:08x}{})",
        wallet_owner.to_lower_hex_string(),
        anchor_height,
        anchor_hash
    )
}

fn parse_vault_wallet_marker(
    wallet_owner: &[u8; 32],
    descriptor: &str,
) -> Option<(u32, BlockHash)> {
    let prefix = format!("raw(6a4c44{}", wallet_owner.to_lower_hex_string());
    let payload = descriptor.strip_prefix(&prefix)?.strip_suffix(')')?;
    if payload.len() != 72 {
        return None;
    }
    let height = u32::from_str_radix(&payload[..8], 16).ok()?;
    let hash = BlockHash::from_str(&payload[8..]).ok()?;
    Some((height, hash))
}

/// Name derived from the stable owner and canonical script set.
fn vault_wallet_name(wallet_owner: &[u8; 32], scripts: &[ScriptBuf]) -> String {
    let mut ordered: Vec<&[u8]> = scripts.iter().map(|script| script.as_bytes()).collect();
    ordered.sort_unstable();
    ordered.dedup();
    let mut engine = sha256::Hash::engine();
    engine.input(wallet_owner);
    for script in ordered {
        engine.input(&(script.len() as u64).to_le_bytes());
        engine.input(script);
    }
    let digest = sha256::Hash::from_engine(engine).to_byte_array();
    format!("{VAULT_WALLET_PREFIX}{}", digest[..8].to_lower_hex_string())
}

/// Parse an RPC outpoint, retaining its source in errors.
fn parse_outpoint(entry: &Value, context: &str) -> Result<OutPoint, Error> {
    let txid = entry["txid"]
        .as_str()
        .ok_or_else(|| format!("{context}: entry has no txid"))?;
    let vout = entry["vout"]
        .as_u64()
        .ok_or_else(|| format!("{context}: entry has no vout"))?;
    Ok(OutPoint::new(
        Txid::from_str(txid).map_err(|e| format!("{context}: bad txid {txid}: {e}"))?,
        u32::try_from(vout).map_err(|_| format!("{context}: vout exceeds u32"))?,
    ))
}

/// Parse a `listsinceblock` entry's transaction id.
fn entry_txid(entry: &Value) -> Result<Txid, Error> {
    let txid = entry["txid"]
        .as_str()
        .ok_or("listsinceblock: transaction has no txid")?;
    Txid::from_str(txid).map_err(|e| format!("listsinceblock: bad txid {txid}: {e}").into())
}

/// One HTTP/1.1 POST to bitcoind's JSON-RPC over loopback, `Connection: close`,
/// returning the response body. A single loopback JSON-RPC peer does not buy an
/// HTTP crate its keep (same reasoning as the /sign server).
fn post_json(addr: SocketAddr, body: &str, auth: &str) -> Result<String, Error> {
    post_json_to(addr, "/", body, auth, RPC_TIMEOUT)
}

/// [`post_json`] to a specific request path and deadline. Core routes wallet RPCs by
/// path (`/wallet/<name>`); everything else goes to `/`.
fn post_json_to(
    addr: SocketAddr,
    path: &str,
    body: &str,
    auth: &str,
    timeout: Duration,
) -> Result<String, Error> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Basic {auth}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read from {addr}: {e}"))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response from {addr}"))?;
    Ok(String::from_utf8_lossy(&raw[split + 4..]).into_owned())
}

#[cfg(test)]
pub(crate) mod mock {
    //! A mock chain backend for the unit tests — no bitcoind, no sockets.

    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    use bitcoin::hashes::Hash;
    use bitcoin::{consensus, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};

    use super::{ChainBackend, PackageVerdict, Prevout, ScanTraversal, SpendSeen};
    use crate::Error;

    /// A deterministic per-height block hash for the mock's chain view. `epoch`
    /// distinguishes chain histories: the default view is epoch 0, and
    /// [`MockBackend::reorg_at`] rewrites a suffix to epoch 1 so a hash that was
    /// recorded before the reorg no longer matches — exactly what the reorg-aware
    /// cursor keys off. Encoding the height keeps every height's hash distinct.
    pub(crate) fn mock_block_hash(height: u32, epoch: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        bytes[4] = epoch;
        BlockHash::from_byte_array(bytes)
    }

    /// Records every broadcast and replays a canned spend set to the scan. Each
    /// spend's `script` is what the watchtower classifies against.
    ///
    /// For the watchtower-driver tests the mock models block height: `tip` is the
    /// reported chain tip and `spend_block` is the height the canned spends sit
    /// at, so `spends_of` returns them only when the requested `from_height`
    /// still covers that block. The defaults (`tip = 0`, `spend_block = 0`) make
    /// a `from_height = 0` scan return every canned spend, matching the simple
    /// classification/cursor tests. `scanned_from` records each `from_height` the
    /// driver asked for, so a test can prove the cursor advanced instead of
    /// re-scanning from 0.
    ///
    /// Interior mutability is a `Mutex` (not a `RefCell`) so the mock is
    /// `Send + Sync`: the async watchtower driver (V0-6b) runs each scan pass on
    /// `spawn_blocking`, which requires a `Send + Sync` backend.
    /// `prevouts`/`raw_txs` are the canned chain+mempool view the package
    /// assembler reads; an outpoint absent from `prevouts` reads as unknown.
    /// `package_rejection` forces the backend to refuse every package (the
    /// "backend rejects the package → no broadcast, no panic" case), and
    /// `packages_tested` records each package so a test can prove the gate ran
    /// BEFORE the broadcast.
    #[derive(Default)]
    pub(crate) struct MockBackend {
        pub spends: Vec<SpendSeen>,
        pub broadcasts: Mutex<Vec<Vec<u8>>>,
        pub tip: u32,
        /// Optional failure for the deterministic fee-target tip read.
        pub tip_error: Option<String>,
        pub spend_block: u32,
        /// Per-height block-hash overrides for the reorg-cursor tests. A height
        /// absent here reads its deterministic epoch-0 [`mock_block_hash`];
        /// [`Self::reorg_at`] inserts epoch-1 hashes to model a reorg.
        pub block_hashes: HashMap<u32, BlockHash>,
        /// Per-height median feerate (sat/vB) for the escape fee-bump target (bead
        /// btc-policy-9y5.7). A height absent here reports `None` — "no reading" —
        /// which is what every test that is not about fee bumping wants: no observed
        /// pressure, so the sweep stays on its base rung.
        pub median_feerates: HashMap<u32, u64>,
        /// Optional failure for the deterministic fee-target block-stat read.
        pub median_feerate_error: Option<String>,
        /// If set, the first completed `spends_of` switches every hash at and above
        /// this height to a distinct epoch. This models the scan/hash-collection
        /// reorg race without mutating the mock through `&self`.
        pub scan_reorg_from: Option<u32>,
        pub scan_completed: AtomicBool,
        /// If set, the first `tip_height` read of a pass commits a reorg forking at
        /// `reorg_from_on_tip_read - 1` and rebuilding to `reorg_new_tip` (a distinct
        /// epoch-3 history at and above the fork). This models the taller fork that
        /// lands in the reconcile→scan GAP — AFTER reconcile matched the old anchor but
        /// BEFORE the scan reads the new blocks — the case the root/boundary check
        /// closes (v0-exit 9y5.3 [P1]). `tip_read_reorg_fired` records the trigger so
        /// `block_hash_at`/`block_hash_of` return the new fork for the rest of the pass.
        pub reorg_from_on_tip_read: Option<u32>,
        pub reorg_new_tip: Option<u32>,
        pub tip_read_reorg_fired: AtomicBool,
        pub scanned_from: Mutex<Vec<u32>>,
        pub prevouts: HashMap<OutPoint, Prevout>,
        /// Every `prevout` lookup, in order, so the preflight tests can prove a
        /// backend failure aborts rather than multiplying one timeout per input.
        pub prevout_lookups: Mutex<Vec<OutPoint>>,
        /// The SIZE of every `prevouts` BATCH, in order. `prevout_lookups` counts
        /// individual outpoints and so cannot tell one batch of five from five batches
        /// of one; this records the grouping the real backend actually issues as HTTP
        /// requests. Bead f91 (B) reads it to pin that `/sign`'s out-of-lock preflight
        /// costs exactly two batch RPCs no matter how many inputs a request declares —
        /// the property that stops a hostile coordinator multiplying the fan-out stall.
        pub prevout_batches: Mutex<Vec<usize>>,
        /// Optional failure injected after recording a `prevout` lookup.
        pub prevout_error: Option<String>,
        /// Optional one-shot pause on the first prevout lookup. Handler-level tests
        /// use it to prove the duress intent exists and `sign_state` is free while
        /// chain preflight is blocked.
        pub prevout_fetch_entered: Option<Arc<Barrier>>,
        pub prevout_fetch_continue: Option<Arc<Barrier>>,
        pub prevout_fetch_paused: AtomicBool,
        pub raw_txs: HashMap<Txid, Vec<u8>>,
        /// Every `mempool_resident` BATCH, in order, so a test can prove the escape's
        /// ladder residency check issues ONE batched read for the whole ladder rather
        /// than one lookup per rung (bead btc-policy-nvr). The Core backend answers a
        /// batch with a single `getrawmempool`, so the batch count IS the snapshot count.
        pub mempool_resident_batches: Mutex<Vec<Vec<Txid>>>,
        /// When true, model Core's `gettxout(..., include_mempool=true)` semantics:
        /// an outpoint spent by any transaction in `raw_txs` is absent from both
        /// `prevout` and `vault_unspent`.
        pub hide_mempool_spent_prevouts: bool,
        pub confirmed_txs: HashSet<Txid>,
        pub package_rejection: Option<String>,
        /// Forces `broadcast` to fail AFTER package acceptance (the "quorum +
        /// admissibility + package-accept all pass, but `sendrawtransaction` itself
        /// errors" branch). Distinct from `package_rejection`, which fails earlier at
        /// `test_package_accept`. Lets a test exercise the `broadcast_package` `Err`
        /// arm and prove Lockdown at `T` is still unconditional there.
        pub broadcast_error: Option<String>,
        pub packages_tested: Mutex<Vec<Vec<Vec<u8>>>>,
        /// Optional deterministic pause around package acceptance. A concurrency
        /// test uses this to land a duress arm after finalization but before the
        /// final broadcast-authorization boundary.
        pub package_test_entered: Option<Arc<Barrier>>,
        pub package_test_continue: Option<Arc<Barrier>>,
    }

    impl MockBackend {
        /// The block hash this mock reports at `height`: an override if present,
        /// else the deterministic epoch-0 hash.
        fn block_hash_of(&self, height: u32) -> BlockHash {
            self.block_hashes.get(&height).copied().unwrap_or_else(|| {
                // A taller-fork reorg committed in this pass's reconcile→scan gap:
                // heights at and above the fork read the new fork (epoch 3).
                if self.tip_read_reorg_fired.load(Ordering::Relaxed)
                    && self
                        .reorg_from_on_tip_read
                        .is_some_and(|from_height| height >= from_height)
                {
                    return mock_block_hash(height, 3);
                }
                let raced = self.scan_completed.load(Ordering::Relaxed)
                    && self
                        .scan_reorg_from
                        .is_some_and(|from_height| height >= from_height);
                mock_block_hash(height, if raced { 2 } else { 0 })
            })
        }

        /// The tip this mock reports now, accounting for a committed tip-read reorg
        /// that rebuilt the chain taller.
        fn effective_tip(&self) -> u32 {
            if self.tip_read_reorg_fired.load(Ordering::Relaxed) {
                self.reorg_new_tip.unwrap_or(self.tip)
            } else {
                self.tip
            }
        }

        /// Rewrite the active chain from `from_height` up to the current `tip` to a
        /// distinct (epoch-1) history, modelling a reorg whose fork point is
        /// `from_height - 1`. Every block hash at or above `from_height` then
        /// differs from what a pre-reorg scan recorded, so the cursor detects the
        /// reorg and rewinds. Set `tip` first if the reorg also changes the height.
        pub(crate) fn reorg_at(&mut self, from_height: u32) {
            for height in from_height..=self.tip {
                self.block_hashes.insert(height, mock_block_hash(height, 1));
            }
        }
    }

    impl ChainBackend for MockBackend {
        fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
            // Parse like the real backend so a malformed tx surfaces an error
            // (no panic) — and so the returned txid is the real one.
            let tx: Transaction = consensus::deserialize(raw_tx)
                .map_err(|e| format!("malformed transaction: {e}"))?;
            // A forced broadcast failure never records the transaction — mirroring a
            // real backend whose `sendrawtransaction` rejected it.
            if let Some(reason) = &self.broadcast_error {
                return Err(reason.clone().into());
            }
            self.broadcasts
                .lock()
                .expect("broadcasts lock")
                .push(raw_tx.to_vec());
            Ok(tx.compute_txid())
        }

        fn tip_height(&self) -> Result<u32, Error> {
            if let Some(reason) = &self.tip_error {
                return Err(reason.clone().into());
            }
            // A pass reads the tip once, right after reconcile: that read commits the
            // armed tip-read reorg, so the subsequent tip-hash capture and scan see the
            // new (taller) fork while reconcile already matched the pre-reorg anchor.
            if self.reorg_from_on_tip_read.is_some() {
                self.tip_read_reorg_fired.store(true, Ordering::Relaxed);
            }
            Ok(self.effective_tip())
        }

        fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, Error> {
            // No block occupies a height above the tip — the reorg-shortened-chain
            // signal the cursor reads as a mismatch.
            if height > self.effective_tip() {
                return Ok(None);
            }
            Ok(Some(self.block_hash_of(height)))
        }

        fn block_median_feerate(&self, height: u32) -> Result<Option<u64>, Error> {
            if let Some(reason) = &self.median_feerate_error {
                return Err(reason.clone().into());
            }
            Ok(self.median_feerates.get(&height).copied())
        }

        fn spends_of(
            &self,
            _scripts: &[ScriptBuf],
            from_height: u32,
            through_height: u32,
            expected_parent: Option<BlockHash>,
        ) -> Result<ScanTraversal, Error> {
            self.scanned_from
                .lock()
                .expect("scanned_from lock")
                .push(from_height);
            // Model check 0 (the root/boundary linkage): the block at `from_height`
            // must chain onto the caller's cursor anchor. In this linear mock, the
            // parent of block[h] is `block_hash_of(h - 1)`. A reorg that lands in the
            // reconcile→scan gap (e.g. via `reorg_from_on_tip_read`) makes this differ
            // from the anchor the caller passed, so the scan refuses — exactly as the
            // real backend's `previousblockhash` check does.
            if let Some(parent) = expected_parent {
                if from_height > 0 && self.block_hash_of(from_height - 1) != parent {
                    return Err(format!(
                        "mock spends_of: block at height {from_height} does not chain onto \
                         expected parent {parent} (a reorg raced the scan)"
                    )
                    .into());
                }
            }
            // The canned spends live in `spend_block`; a scan whose cursor has
            // advanced past it sees nothing, so a re-alert can only come from a
            // cursor that failed to advance (never dedup).
            let result = if from_height <= self.spend_block && self.spend_block <= through_height {
                self.spends.clone()
            } else {
                Vec::new()
            };
            // The validated (height, hash) chain the watchtower binds its anchors to,
            // captured from the SAME view that classified the spends.
            let blocks: Vec<(u32, BlockHash)> = (from_height..=through_height)
                .map(|height| (height, self.block_hash_of(height)))
                .collect();
            if self.scan_reorg_from.is_some() {
                self.scan_completed.store(true, Ordering::Relaxed);
            }
            Ok(ScanTraversal {
                spends: result,
                blocks,
            })
        }

        /// Records the batch's SIZE, then behaves exactly like the trait default (map
        /// `prevout` over the outpoints, aborting on the first error). The override
        /// exists only to make the grouping observable — the real backend answers a
        /// batch in ONE HTTP request, and `prevout_lookups` alone cannot distinguish
        /// that from one request per input.
        fn prevouts(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<Prevout>>, Error> {
            self.prevout_batches
                .lock()
                .expect("prevout_batches lock")
                .push(outpoints.len());
            outpoints
                .iter()
                .map(|outpoint| self.prevout(outpoint))
                .collect()
        }

        fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
            self.prevout_lookups
                .lock()
                .expect("prevout_lookups lock")
                .push(*outpoint);
            if self
                .prevout_fetch_paused
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                if let Some(entered) = &self.prevout_fetch_entered {
                    entered.wait();
                }
                if let Some(proceed) = &self.prevout_fetch_continue {
                    proceed.wait();
                }
            }
            if let Some(reason) = &self.prevout_error {
                return Err(reason.clone().into());
            }
            if self.hide_mempool_spent_prevouts
                && self.raw_txs.values().any(|raw| {
                    consensus::deserialize::<Transaction>(raw).is_ok_and(|tx| {
                        tx.input
                            .iter()
                            .any(|input| input.previous_output == *outpoint)
                    })
                })
            {
                return Ok(None);
            }
            Ok(self.prevouts.get(outpoint).cloned())
        }

        fn vault_unspent(
            &self,
            scripts: &[ScriptBuf],
            authorized: &HashSet<Txid>,
        ) -> Result<Vec<(OutPoint, Prevout)>, Error> {
            let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
            let mut found: Vec<_> = self
                .prevouts
                .iter()
                .filter(|(outpoint, prevout)| {
                    watched.contains(&prevout.txout.script_pubkey)
                        && (prevout.confirmed || authorized.contains(&outpoint.txid))
                        && (!self.hide_mempool_spent_prevouts
                            || !self.raw_txs.values().any(|raw| {
                                consensus::deserialize::<Transaction>(raw).is_ok_and(|tx| {
                                    tx.input
                                        .iter()
                                        .any(|input| input.previous_output == **outpoint)
                                })
                            }))
                })
                .map(|(outpoint, prevout)| (*outpoint, prevout.clone()))
                .collect();
            found.sort_by_key(|(outpoint, _)| *outpoint);
            Ok(found)
        }

        fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.raw_txs.get(txid).cloned())
        }

        /// Record the batch, then answer through the SAME helper the trait default uses,
        /// so this mock cannot drift from the contract it is standing in for. Recording
        /// is the whole point: the caller's batching is what this mock observes, while
        /// the Core backend's one-snapshot-per-batch is its own concern.
        fn mempool_resident(&self, txids: &[Txid]) -> Result<Option<(Txid, Vec<u8>)>, Error> {
            self.mempool_resident_batches
                .lock()
                .expect("mempool_resident_batches lock")
                .push(txids.to_vec());
            super::first_resident_by_lookup(txids, |txid| self.mempool_transaction(txid))
        }

        fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error> {
            Ok(self.confirmed_txs.contains(txid))
        }

        fn test_package_accept(&self, raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error> {
            self.packages_tested
                .lock()
                .expect("packages_tested lock")
                .push(raw_txs.to_vec());
            if let Some(entered) = &self.package_test_entered {
                entered.wait();
            }
            if let Some(proceed) = &self.package_test_continue {
                proceed.wait();
            }
            Ok(match &self.package_rejection {
                Some(reason) => PackageVerdict::Rejected(reason.clone()),
                None => PackageVerdict::Accepted,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockBackend;
    use super::{
        assemble_package, BitcoindBackend, ChainBackend, ColdScan, Prevout, VaultUnspentCache,
        MAX_PACKAGE_ANCESTORS, MAX_SUPPORTED_INCREMENTAL_RELAY_SAT_KVB,
        MAX_VAULT_SCAN_DELTA_BLOCKS,
    };

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::DisplayHex;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::Ordering;

    /// A tiny scripted JSON-RPC peer for exercising the real bitcoind backend's
    /// cross-call snapshot ordering without launching bitcoind.
    fn scripted_rpc(
        replies: Vec<(&'static str, serde_json::Value)>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let (addr, handle, _) = scripted_rpc_recording(replies);
        (addr, handle)
    }

    /// [`scripted_rpc`] that also hands back every JSON-RPC request body it served, so
    /// a test can assert on the PARAMETERS a call carried and not just its name.
    #[allow(clippy::type_complexity)]
    fn scripted_rpc_recording(
        replies: Vec<(&'static str, serde_json::Value)>,
    ) -> (
        std::net::SocketAddr,
        std::thread::JoinHandle<()>,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        scripted_rpc_gated(replies, None)
    }

    /// [`scripted_rpc_recording`] that can also PAUSE mid-script: with
    /// `Some((method, hit, resume))` it serves normally until the first call to
    /// `method`, then signals `hit` and blocks on `resume` before answering it. That
    /// suspends the backend INSIDE that call, which is how a test observes state the
    /// backend is required to have published before it (no sleeps, no polling).
    #[allow(clippy::type_complexity)]
    fn scripted_rpc_gated(
        replies: Vec<(&'static str, serde_json::Value)>,
        mut gate: Option<(
            &'static str,
            std::sync::mpsc::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    ) -> (
        std::net::SocketAddr,
        std::thread::JoinHandle<()>,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted RPC");
        let addr = listener.local_addr().expect("scripted RPC address");
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let requests = std::sync::Arc::clone(&recorded);
        let handle = std::thread::spawn(move || {
            for (expected_method, result) in replies {
                let (mut stream, _) = listener.accept().expect("accept RPC call");
                let mut request = Vec::new();
                let (header_end, content_len) = loop {
                    let mut chunk = [0u8; 4096];
                    let read = stream.read(&mut chunk).expect("read RPC request");
                    assert!(read > 0, "RPC request ended before its headers");
                    request.extend_from_slice(&chunk[..read]);
                    let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let headers =
                        std::str::from_utf8(&request[..header_end]).expect("HTTP headers");
                    let content_len = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("content length"))
                        })
                        .expect("Content-Length");
                    break (header_end, content_len);
                };
                while request.len() < header_end + content_len {
                    let mut chunk = [0u8; 4096];
                    let read = stream.read(&mut chunk).expect("read RPC body");
                    assert!(read > 0, "RPC request ended before its body");
                    request.extend_from_slice(&chunk[..read]);
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&request[header_end..header_end + content_len])
                        .expect("JSON-RPC request");
                requests
                    .lock()
                    .expect("recorded requests lock")
                    .push(body.clone());
                if gate
                    .as_ref()
                    .is_some_and(|(method, ..)| body["method"] == *method)
                {
                    let (_, hit, resume) = gate.take().expect("the gate was just matched");
                    hit.send(()).expect("signal the gated call");
                    resume
                        .recv()
                        .expect("wait for the test to release the gate");
                }
                let response = if let Some(batch) = body.as_array() {
                    assert!(
                        batch
                            .iter()
                            .all(|request| request["method"] == expected_method),
                        "unexpected JSON-RPC batch: {body}"
                    );
                    if let Some(raw) = result.get("__raw_batch") {
                        raw.clone()
                    } else if let Some(by_outpoint) = result.get("__by_outpoint") {
                        // Answer a `gettxout` batch per REQUEST, keyed `"<txid>:<vout>"`,
                        // rather than positionally. An outpoint the script does not name
                        // reads as null (spent or unknown), so a test states the chain's
                        // answer for each outpoint and stays valid however many
                        // candidates the caller batches.
                        batch
                            .iter()
                            .map(|request| {
                                let key = format!(
                                    "{}:{}",
                                    request["params"][0].as_str().unwrap_or_default(),
                                    request["params"][1]
                                );
                                serde_json::json!({
                                    "result": by_outpoint
                                        .get(&key)
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null),
                                    "error": serde_json::Value::Null,
                                    "id": request["id"],
                                })
                            })
                            .collect::<Vec<_>>()
                            .into()
                    } else {
                        let results = result.as_array().cloned().unwrap_or_else(|| vec![result]);
                        assert_eq!(
                            results.len(),
                            batch.len(),
                            "scripted batch needs one result per request"
                        );
                        results
                            .into_iter()
                            .enumerate()
                            .map(|(id, result)| {
                                serde_json::json!({
                                    "result": result,
                                    "error": serde_json::Value::Null,
                                    "id": id,
                                })
                            })
                            .collect::<Vec<_>>()
                            .into()
                    }
                } else {
                    assert_eq!(body["method"], expected_method);
                    // `{"__error": {...}}` scripts a structured JSON-RPC failure, which
                    // is how bitcoind reports "no such wallet" (-18), "already loaded"
                    // (-35) and friends.
                    match result.get("__error") {
                        Some(error) => serde_json::json!({
                            "result": serde_json::Value::Null,
                            "error": error,
                            "id": "vault-node",
                        }),
                        None => serde_json::json!({
                            "result": result,
                            "error": serde_json::Value::Null,
                            "id": "vault-node",
                        }),
                    }
                }
                .to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .expect("write RPC response");
            }
        });
        (addr, handle, recorded)
    }

    /// bitcoind's structured "no such wallet" failure, as `scripted_rpc` scripts it.
    fn wallet_not_found() -> serde_json::Value {
        serde_json::json!({"__error": {"code": -18, "message": "Wallet file verification failed"}})
    }

    fn completion_marker(height: u32, hash: &str) -> String {
        let owner =
            bitcoin::hashes::sha256::Hash::hash(super::STANDALONE_WALLET_IDENTITY).to_byte_array();
        format!(
            "{}#hgfedcba",
            super::vault_wallet_marker(
                &owner,
                height,
                hash.parse::<BlockHash>()
                    .expect("test completion-marker hash"),
            )
        )
    }

    /// One cold refresh against a backend that has NO node-owned vault wallet: the
    /// wallet read fails closed, the `scantxoutset` fallback runs, and the seeding
    /// attempt that follows the scan is refused too — so these replies exercise the
    /// pre-hn8 scan path end to end.
    fn cold_cache_replies(
        scan: serde_json::Value,
        bestblock: &str,
        height: u32,
    ) -> Vec<(&'static str, serde_json::Value)> {
        let mut replies = vec![("loadwallet", wallet_not_found())];
        replies.extend(scan_fallback_replies(scan, bestblock, height));
        replies
    }

    /// The `scantxoutset` fallback itself, without the wallet read that precedes it:
    /// the scan, its anchor check, and a wallet-seeding attempt that bitcoind refuses.
    /// Tests whose wallet read fails AFTER `loadwallet` (verification, say) start here.
    fn scan_fallback_replies(
        scan: serde_json::Value,
        bestblock: &str,
        height: u32,
    ) -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("scantxoutset", scan),
            ("getblockheader", serde_json::json!({"height": height})),
            ("getblockhash", serde_json::json!(bestblock)),
            ("loadwallet", wallet_not_found()),
            (
                "createwallet",
                serde_json::json!({"__error": {"code": -4, "message": "Database already exists"}}),
            ),
        ]
    }

    /// A minimal but well-formed 1-in/1-out transaction to broadcast.
    fn sample_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(1_000),
            }],
        }
    }

    #[test]
    fn block_median_feerate_reads_cores_50th_percentile_statistic() {
        let (addr, server) = scripted_rpc(vec![(
            "getblockstats",
            serde_json::json!({
                "feerate_percentiles": [2, 7, 19, 31, 55]
            }),
        )]);
        let backend = BitcoindBackend::new(addr, "ignored".into());
        assert_eq!(
            backend.block_median_feerate(42).expect("block stats"),
            Some(19)
        );
        server.join().expect("scripted RPC server");
    }

    // -- package assembly over the authorized set (§5) -----------------------

    /// A transaction spending `parents` (each an outpoint) and paying `value`.
    /// `tag` makes otherwise-identical txs distinct.
    fn tx_spending(parents: &[OutPoint], value: u64, tag: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: parents
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(value),
            }],
        }
    }

    fn prevout(confirmed: bool) -> Prevout {
        Prevout {
            txout: TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(100_000),
            },
            confirmed,
        }
    }

    #[test]
    fn required_index_check_accepts_a_synced_txindex() {
        let (addr, server) = scripted_rpc(vec![
            (
                "getblockchaininfo",
                serde_json::json!({ "initialblockdownload": false }),
            ),
            (
                "getindexinfo",
                serde_json::json!({
                    "txindex": { "synced": true, "best_block_height": 321 }
                }),
            ),
            (
                "getnetworkinfo",
                serde_json::json!({ "incrementalfee": 0.00001000 }),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .verify_required_indexes()
            .expect("a current, synced txindex satisfies the production backend contract");
        server.join().expect("scripted RPC completed");
    }

    #[test]
    fn required_index_check_rejects_an_unsupported_incremental_relay_fee() {
        let (addr, server) = scripted_rpc(vec![
            (
                "getblockchaininfo",
                serde_json::json!({ "initialblockdownload": false }),
            ),
            (
                "getindexinfo",
                serde_json::json!({
                    "txindex": { "synced": true, "best_block_height": 321 }
                }),
            ),
            (
                "getnetworkinfo",
                serde_json::json!({ "incrementalfee": 0.00002000 }),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .verify_required_indexes()
            .expect_err("a relay fee above the ladder's bound must fail startup")
            .to_string();
        assert!(
            error.contains("incrementalfee")
                && error.contains(&MAX_SUPPORTED_INCREMENTAL_RELAY_SAT_KVB.to_string()),
            "the startup failure must state the unsupported relay policy: {error}"
        );
        server.join().expect("scripted RPC completed");
    }

    #[test]
    fn required_index_check_rejects_a_missing_or_unsynced_txindex() {
        for (result, expected) in [
            (serde_json::json!({}), "-txindex=1"),
            (
                serde_json::json!({ "txindex": { "synced": false } }),
                "not synced",
            ),
        ] {
            let (addr, server) = scripted_rpc(vec![
                (
                    "getblockchaininfo",
                    serde_json::json!({ "initialblockdownload": false }),
                ),
                ("getindexinfo", result),
            ]);
            let backend = BitcoindBackend::new(addr, String::new());
            let error = backend
                .verify_required_indexes()
                .expect_err("an unavailable confirmation index must fail startup")
                .to_string();
            assert!(
                error.contains(expected),
                "unexpected index failure for {expected}: {error}"
            );
            server.join().expect("scripted RPC completed");
        }
    }

    /// A `synced` txindex over a chain view that is still in initial block download
    /// must NOT pass: the tip lags the network, so the confirmed vault-UTXO scan and
    /// `transaction_confirmed` would both read a stale view. The check must reject
    /// BEFORE consulting `getindexinfo` (only `getblockchaininfo` is scripted).
    #[test]
    fn required_index_check_rejects_a_backend_in_initial_block_download() {
        let (addr, server) = scripted_rpc(vec![(
            "getblockchaininfo",
            serde_json::json!({ "initialblockdownload": true }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .verify_required_indexes()
            .expect_err("an IBD chain view must fail startup")
            .to_string();
        assert!(
            error.contains("initial block download"),
            "the IBD failure must name its reason: {error}"
        );
        server.join().expect("scripted RPC completed");
    }

    #[test]
    fn production_prevout_batch_reorders_ids_and_preserves_null_entries() {
        let first = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0);
        let second = OutPoint::new(Txid::from_byte_array([0x22; 32]), 1);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let (addr, server) = scripted_rpc(vec![(
            "gettxout",
            serde_json::json!({
                "__raw_batch": [
                    {"result": null, "error": null, "id": 1},
                    {
                        "result": {
                            "scriptPubKey": {"hex": script.as_bytes().to_lower_hex_string()},
                            "value": 0.001,
                            "confirmations": 3
                        },
                        "error": null,
                        "id": 0
                    }
                ]
            }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());

        let prevouts = backend
            .prevouts(&[first, second])
            .expect("the production batch parser accepts out-of-order ids");
        server.join().expect("scripted RPC completed");
        assert_eq!(prevouts.len(), 2);
        assert_eq!(
            prevouts[0]
                .as_ref()
                .map(|prevout| &prevout.txout.script_pubkey),
            Some(&script)
        );
        assert!(prevouts[0]
            .as_ref()
            .is_some_and(|prevout| prevout.confirmed));
        assert_eq!(prevouts[1], None);
    }

    #[test]
    fn production_prevout_batch_refuses_duplicate_reply_ids() {
        let first = OutPoint::new(Txid::from_byte_array([0x33; 32]), 0);
        let second = OutPoint::new(Txid::from_byte_array([0x44; 32]), 1);
        let (addr, server) = scripted_rpc(vec![(
            "gettxout",
            serde_json::json!({
                "__raw_batch": [
                    {"result": null, "error": null, "id": 0},
                    {"result": null, "error": null, "id": 0}
                ]
            }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());

        let error = backend
            .prevouts(&[first, second])
            .expect_err("duplicate batch ids must fail closed")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(error.contains("duplicate reply id 0"), "{error}");
    }

    /// A fire-time read never chases a stale cache. The background refresher advances
    /// the cold scan by block delta, after which the same hot-path read succeeds.
    #[test]
    fn vault_unspent_fails_fast_until_the_background_delta_reaches_the_tip() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let txid = Txid::from_byte_array([0xA5; 32]);
        let old_tip = "11".repeat(32);
        let new_tip = "22".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let confirmed_output = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let scan = serde_json::json!({
            "success": true,
            "bestblock": old_tip,
            "unspents": []
        });
        let mut replies = cold_cache_replies(scan, &old_tip, 0);
        replies.extend([
            // Fire-time: one mempool snapshot plus one best-tip read, then fail fast.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            ("getbestblockhash", serde_json::json!(new_tip)),
            // Background delta: no wallet handle to reorg-check, so the wallet read is
            // attempted and fails closed again; the cache anchor is then proved still
            // active (nothing for a delta to chain onto otherwise) and one new block
            // adds the watched output, which the terminal active-hash re-read commits.
            ("loadwallet", wallet_not_found()),
            ("getblockhash", serde_json::json!(old_tip)),
            ("getblockcount", serde_json::json!(1)),
            ("getblockhash", serde_json::json!(new_tip)),
            (
                "getblock",
                serde_json::json!({
                    "previousblockhash": old_tip,
                    "tx": [{
                        "txid": txid.to_string(),
                        "vin": [{"coinbase": "00"}],
                        "vout": [{"scriptPubKey": {"hex": script_hex}}]
                    }]
                }),
            ),
            ("getblockhash", serde_json::json!(new_tip)),
            // Fire-time after refresh: current cache, one batched prevout lookup, and
            // a stable chain+mempool bracket.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
            ("getbestblockhash", serde_json::json!(new_tip)),
            ("gettxout", confirmed_output),
            ("getbestblockhash", serde_json::json!(new_tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("cold cache warm");
        let stale = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect_err("the hot path must not perform its own catch-up");
        assert!(stale.to_string().contains("cold or behind"), "{stale}");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("bounded one-block delta");
        let unspent = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    #[test]
    fn one_cache_refresh_applies_at_most_the_bounded_block_delta() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let hash_at = |height: u32| format!("{height:064x}");
        let genesis = hash_at(0);
        let scan = serde_json::json!({"success": true, "bestblock": genesis, "unspents": []});
        let mut replies = cold_cache_replies(scan, &genesis, 0);
        // The wallet read failing closed again, the cache-anchor check that gates the
        // delta, then the bounded delta itself.
        replies.push(("loadwallet", wallet_not_found()));
        replies.push(("getblockhash", serde_json::json!(genesis)));
        replies.push(("getblockcount", serde_json::json!(33)));
        for height in 1..=MAX_VAULT_SCAN_DELTA_BLOCKS {
            let hash = hash_at(height);
            let parent = hash_at(height - 1);
            replies.push(("getblockhash", serde_json::json!(hash)));
            replies.push((
                "getblock",
                serde_json::json!({"previousblockhash": parent, "tx": []}),
            ));
        }
        replies.push((
            "getblockhash",
            serde_json::json!(hash_at(MAX_VAULT_SCAN_DELTA_BLOCKS)),
        ));
        // The active tip is still one block beyond the bounded update, so fire-time
        // coverage refuses without fetching or parsing block 33.
        replies.push((
            "getrawmempool",
            serde_json::json!({"txids": [], "mempool_sequence": 1}),
        ));
        replies.push(("getbestblockhash", serde_json::json!(hash_at(33))));
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("cold cache warm");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("bounded delta");
        let stale = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect_err("one pass must not exceed the delta bound");
        server.join().expect("scripted RPC completed");
        assert!(stale.to_string().contains("cold or behind"), "{stale}");
    }

    /// An authorized mempool transaction can be evicted after `gettxout(..., true)`
    /// suppresses its confirmed input but before the authorized pass enumerates its
    /// unconfirmed output. With a stable tip, tip-only reconciliation misses that
    /// transition and undercounts both sides. Authorized-mempool membership snapshots
    /// must force a complete retry, which restores the now-unspent confirmed input.
    #[test]
    fn vault_unspent_reconciles_authorized_mempool_eviction_without_a_tip_change() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0xB4; 32]);
        let authorized_txid = Txid::from_byte_array([0xC5; 32]);
        let tip = "33".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let mut authorized_tx = sample_tx();
        authorized_tx.output[0].script_pubkey = script.clone();
        let authorized_tx_hex = serialize(&authorized_tx).to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0, "height": 1}],
        });
        let confirmed_parent = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Snapshot 1: the authorized child initially spends the confirmed parent.
            (
                "getrawmempool",
                serde_json::json!({"txids": [authorized_txid.to_string()], "mempool_sequence": 10}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", serde_json::Value::Null),
            // Evicted while its outputs are enumerated; the tip does not change, but
            // the eviction bumps the sequence, so the pass is not accepted.
            ("getrawtransaction", serde_json::json!(authorized_tx_hex)),
            ("gettxout", serde_json::Value::Null),
            ("getbestblockhash", serde_json::json!("33".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
            // Snapshot 2 is stable and sees the confirmed parent unspent again.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("33".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let authorized: HashSet<Txid> = [authorized_txid].into_iter().collect();

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &authorized)
            .expect("eviction-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// An unauthorized mempool spend suppresses its confirmed vault prevout from
    /// `gettxout(..., true)` just like an authorized spend does. If it is evicted
    /// during the snapshot, comparing only the authorized intersection sees no
    /// change and accepts an understated balance. Full-mempool reconciliation must
    /// retry and restore the now-unspent confirmed output.
    #[test]
    fn vault_unspent_reconciles_unauthorized_mempool_eviction() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0xD6; 32]);
        let unauthorized_txid = Txid::from_byte_array([0xE7; 32]);
        let tip = "44".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0, "height": 1}],
        });
        let confirmed_parent = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Snapshot 1: an UNAUTHORIZED mempool tx suppresses the confirmed
            // parent. The authorized set is empty throughout this test.
            (
                "getrawmempool",
                serde_json::json!({"txids": [unauthorized_txid.to_string()], "mempool_sequence": 20}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", serde_json::Value::Null),
            ("getbestblockhash", serde_json::json!("44".repeat(32))),
            // Eviction with no tip change bumps the sequence, so the complete pass
            // is not accepted even though the authorized intersection never changed.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
            // Snapshot 2 is stable and sees the confirmed parent unspent again.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("44".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &HashSet::new())
            .expect("unauthorized-eviction-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// The ABA the txid-set endpoints alone cannot see: a transaction is absent at
    /// the first snapshot, ENTERS and suppresses a confirmed vault output from
    /// `gettxout(..., true)` while the scan runs, then LEAVES before the second
    /// snapshot. Both endpoint sets are empty and the tip never moves, so a
    /// set-only comparison would accept the understated (here, empty) balance.
    /// Core's `mempool_sequence` still advances across the enter+leave, so the pass
    /// is retried and the now-unspent confirmed output is restored.
    #[test]
    fn vault_unspent_retries_when_a_transient_mempool_tx_races_the_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0xF8; 32]);
        let tip = "88".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0, "height": 1}],
        });
        let confirmed_parent = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Snapshot 1: empty mempool. A transient tx then enters, suppresses the
            // confirmed parent, and leaves — all before snapshot 2, so BOTH sets are
            // empty. Only the sequence records the enter (+1) and leave (+1).
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 50}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", serde_json::Value::Null),
            ("getbestblockhash", serde_json::json!("88".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
            // Snapshot 2 is stable and sees the confirmed parent unspent again.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("88".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &HashSet::new())
            .expect("transient-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// Deliverable 9y5.3-c: a second `vault_unspent` call with an UNCHANGED tip
    /// reuses the cached confirmed-set candidates and SKIPS `scantxoutset`. The
    /// scripted peer offers no second `scantxoutset`, so the test passing at all is
    /// the proof the whole-set scan was not re-run — the bound that keeps a
    /// multi-minute mainnet scan from repeating on every combine-window tick.
    #[test]
    fn vault_unspent_reuses_the_confirmed_scan_while_the_tip_is_unchanged() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0x5A; 32]);
        let tip = "aa".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0, "height": 1}],
        });
        let confirmed = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 3,
        });
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Calls 1 and 2 both consume the already-warm cache. Neither can issue
            // `scantxoutset`; only the stable chain+mempool bracket repeats.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed.clone()),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("cold cache warm");
        let first = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("first scan");
        let second = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("cached scan (no scantxoutset)");
        server.join().expect("scripted RPC completed");
        assert_eq!(
            first, second,
            "the cached pass returns the identical balance"
        );
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, OutPoint::new(parent_txid, 0));
        assert!(first[0].1.confirmed);
    }

    #[test]
    fn vault_unspent_rejects_an_incomplete_confirmed_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let (addr, server) = scripted_rpc(vec![
            ("loadwallet", wallet_not_found()),
            (
                "scantxoutset",
                serde_json::json!({
                    "success": false,
                    "bestblock": "55".repeat(32),
                    "unspents": [],
                }),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());

        let error = backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect_err("an aborted scan must fail closed");
        server.join().expect("scripted RPC completed");
        assert!(
            error.to_string().contains("scan did not complete"),
            "the incomplete-scan reason must be preserved: {error}"
        );
    }

    #[test]
    fn vault_unspent_fetches_raw_transactions_only_for_the_mempool_intersection() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let current_txid = Txid::from_byte_array([0x66; 32]);
        let current_raw = serialize(&sample_tx()).to_lower_hex_string();
        let tip = "77".repeat(32);
        let scan = serde_json::json!({"success": true, "bestblock": tip, "unspents": []});
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            (
                "getrawmempool",
                serde_json::json!({"txids": [current_txid.to_string()], "mempool_sequence": 40}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getrawtransaction", serde_json::json!(current_raw)),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [current_txid.to_string()], "mempool_sequence": 40}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let mut authorized: HashSet<Txid> = (0..128)
            .map(|tag| Txid::from_byte_array([tag; 32]))
            .collect();
        authorized.insert(current_txid);

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &authorized)
            .expect("stable snapshot");
        server.join().expect("scripted RPC completed");
        assert!(unspent.is_empty());
    }

    // -- the watchtower scan's mid-scan reorg guard (9y5.3-a) ----------------

    /// One empty block, verbosity-3 shaped, for the scripted scan below.
    fn scanned_block(parent: Option<&str>) -> serde_json::Value {
        match parent {
            Some(parent) => {
                serde_json::json!({"previousblockhash": parent, "tx": []})
            }
            None => serde_json::json!({"tx": []}),
        }
    }

    /// The control: a scan whose blocks chain and whose newest block is still the
    /// active one at its height returns its spends. Without this the two rejection
    /// tests below could pass for the wrong reason (any error at all).
    #[test]
    fn a_stable_scan_returns_its_spends() {
        let first = "a1".repeat(32);
        let second = "a2".repeat(32);
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!(first)),
            ("getblock", scanned_block(None)),
            ("getblockhash", serde_json::json!(second)),
            ("getblock", scanned_block(Some(&"a1".repeat(32)))),
            // The terminal re-read: block 2 is still the active block there.
            ("getblockhash", serde_json::json!("a2".repeat(32))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let seen = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 2, None)
            .expect("a stable scan");
        server.join().expect("scripted RPC completed");
        assert!(
            seen.spends.is_empty(),
            "the scripted blocks carry no spends"
        );
    }

    /// A reorg that swaps the active block PART-WAY through the scan: block 2 comes
    /// back from a different fork and so does not chain onto block 1. Binding that
    /// mixed read would classify one fork's spends and silently skip the other's.
    #[test]
    fn a_mixed_fork_scan_is_refused_rather_than_bound() {
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!("a1".repeat(32))),
            ("getblock", scanned_block(None)),
            ("getblockhash", serde_json::json!("b2".repeat(32))),
            // B's block 2 chains onto B's block 1, not the A block just scanned.
            ("getblock", scanned_block(Some(&"b1".repeat(32)))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 2, None)
            .expect_err("a mixed-fork scan must not be bound")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(
            error.contains("does not chain onto"),
            "the refusal must name the broken linkage: {error}"
        );
    }

    /// A scan that ran END-TO-END on a fork the node has since abandoned is
    /// internally consistent — every block chains — so only the terminal re-read
    /// catches it. This is the A→B→A case that also returns the original tip hash
    /// and so slips past the watchtower's own post-scan tip check.
    #[test]
    fn a_scan_bound_to_an_abandoned_fork_is_refused() {
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!("b1".repeat(32))),
            ("getblock", scanned_block(None)),
            ("getblockhash", serde_json::json!("b2".repeat(32))),
            ("getblock", scanned_block(Some(&"b1".repeat(32)))),
            // The chain returned to A before the terminal re-read.
            ("getblockhash", serde_json::json!("a2".repeat(32))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 2, None)
            .expect_err("an abandoned fork's spends must not be bound")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(
            error.contains("no longer the active block"),
            "the refusal must name the abandoned fork: {error}"
        );
    }

    /// Check 0 (v0-exit 9y5.3 [P1], BOTH reviewers): the FIRST scanned block must chain
    /// onto `expected_parent` — the cursor anchor the caller is extending. A reorg that
    /// forks below `from_height` and rebuilds taller in the reconcile→scan gap leaves a
    /// new-fork `from_height` block whose parent is NOT the anchor; without this check,
    /// binding it appends an anchor that no longer chains, and a later flip back to that
    /// fork resumes above a block this node never scanned there — silently skipping its
    /// spends forever.
    #[test]
    fn a_scan_that_does_not_root_on_the_cursor_anchor_is_refused() {
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!("b1".repeat(32))),
            // Block at `from_height` names a DIFFERENT parent than the cursor anchor.
            ("getblock", scanned_block(Some(&"b0".repeat(32)))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        // A cursor anchor on a DIFFERENT fork than the scanned block's parent (`b0…`).
        let anchor = BlockHash::from_byte_array([0xa0; 32]);
        let error = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 1, Some(anchor))
            .expect_err("a scan not rooted on the cursor anchor must be refused")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(
            error.contains("does not chain onto the expected parent"),
            "the refusal must name the broken root linkage: {error}"
        );
    }

    #[test]
    fn a_spend_over_confirmed_prevouts_packages_as_itself_alone() {
        let tx = sample_tx();
        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(tx.input[0].previous_output, prevout(true));

        let package = assemble_package(&backend, &tx, &HashSet::new()).expect("confirmed prevout");
        assert_eq!(
            package,
            vec![serialize(&tx)],
            "a confirmed prevout needs no ancestor in the package"
        );
    }

    #[test]
    fn a_spend_over_a_vault_authorized_unconfirmed_parent_tests_the_child_against_the_mempool() {
        // The common case (ADR-0012): the spend chains off this vault's own
        // unconfirmed spend-change, which cannot be replaced without t-of-n.
        let parent = tx_spending(
            &[OutPoint::new(Txid::from_byte_array([1; 32]), 0)],
            90_000,
            1,
        );
        let parent_txid = parent.compute_txid();
        let child = tx_spending(&[OutPoint::new(parent_txid, 0)], 80_000, 2);

        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(child.input[0].previous_output, prevout(false));
        backend.raw_txs.insert(parent_txid, serialize(&parent));
        let authorized: HashSet<Txid> = [parent_txid].into_iter().collect();

        let package = assemble_package(&backend, &child, &authorized).expect("authorized parent");
        assert_eq!(
            package,
            vec![serialize(&child)],
            "the parent is already in the mempool; Core tests the child against it"
        );
        // Deliberately no `prevout` entry for the parent's input. In real Core it
        // is spent by this mempool parent, so gettxout returns null; ancestry must
        // use mempool membership instead.
    }

    /// The toxic-deposit rule: an unconfirmed parent this node never authorized
    /// can be replaced out from under the spend, so the spend is not broadcast at
    /// all. Excluded, not merely deprioritized.
    #[test]
    fn a_spend_over_an_external_unconfirmed_deposit_is_excluded() {
        let deposit_txid = Txid::from_byte_array([0xEE; 32]);
        let child = tx_spending(&[OutPoint::new(deposit_txid, 0)], 80_000, 3);

        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(child.input[0].previous_output, prevout(false));
        backend
            .raw_txs
            .insert(deposit_txid, serialize(&sample_tx()));

        // The authorized set is empty: this node never validated that deposit.
        let error = assemble_package(&backend, &child, &HashSet::new())
            .expect_err("an external unconfirmed deposit must not be chained onto");
        assert!(
            error.to_string().contains("external unconfirmed deposit"),
            "the exclusion must name its reason: {error}"
        );
    }

    #[test]
    fn a_multi_level_authorized_chain_is_fully_validated_but_not_relisted() {
        let grandparent = tx_spending(
            &[OutPoint::new(Txid::from_byte_array([1; 32]), 0)],
            90_000,
            10,
        );
        let gp_txid = grandparent.compute_txid();
        let parent = tx_spending(&[OutPoint::new(gp_txid, 0)], 85_000, 11);
        let parent_txid = parent.compute_txid();
        let child = tx_spending(&[OutPoint::new(parent_txid, 0)], 80_000, 12);

        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(parent.input[0].previous_output, prevout(false));
        backend
            .prevouts
            .insert(child.input[0].previous_output, prevout(false));
        backend.raw_txs.insert(gp_txid, serialize(&grandparent));
        backend.raw_txs.insert(parent_txid, serialize(&parent));
        let authorized: HashSet<Txid> = [gp_txid, parent_txid].into_iter().collect();

        let package = assemble_package(&backend, &child, &authorized).expect("authorized chain");
        assert_eq!(
            package,
            vec![serialize(&child)],
            "already-present multi-generation ancestors must not be re-listed in Core's package"
        );
    }

    #[test]
    fn an_unknown_prevout_refuses_to_package_rather_than_guessing() {
        let tx = sample_tx();
        // No prevout registered: this node cannot see the output at all.
        let error = assemble_package(&MockBackend::default(), &tx, &HashSet::new())
            .expect_err("an unknown prevout must not be packaged");
        assert!(error.to_string().contains("unknown to this node"));
    }

    #[test]
    fn an_over_deep_unconfirmed_chain_is_bounded_rather_than_recursing_forever() {
        // A chain longer than the ancestor bound: every link is authorized and
        // unconfirmed, so only the bound stops the walk.
        let mut backend = MockBackend::default();
        let mut authorized = HashSet::new();
        let root = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let mut previous = root;
        let mut last_tx = None;
        for i in 0..(MAX_PACKAGE_ANCESTORS as u32 + 5) {
            let tx = tx_spending(&[previous], 90_000, i);
            let txid = tx.compute_txid();
            backend.prevouts.insert(previous, prevout(false));
            backend.raw_txs.insert(txid, serialize(&tx));
            authorized.insert(txid);
            previous = OutPoint::new(txid, 0);
            last_tx = Some(tx);
        }
        // The chain's own root prevout is confirmed; everything above is not.
        backend.prevouts.insert(root, prevout(true));

        let error = assemble_package(&backend, &last_tx.expect("chain built"), &authorized)
            .expect_err("an over-deep chain must be refused, not packaged");
        assert!(
            error.to_string().contains("ancestor bound"),
            "the bound must name itself: {error}"
        );
    }

    #[test]
    fn broadcast_records_the_raw_tx_and_returns_its_txid() {
        let backend = MockBackend::default();
        let tx = sample_tx();
        let raw = serialize(&tx);
        let txid = backend.broadcast(&raw).expect("valid tx broadcasts");
        assert_eq!(txid, tx.compute_txid());
        assert_eq!(
            backend
                .broadcasts
                .lock()
                .expect("broadcasts lock")
                .as_slice(),
            &[raw],
            "the backend must record the exact raw tx it was handed"
        );
    }

    #[test]
    fn a_malformed_tx_surfaces_the_backend_error_without_panicking() {
        let backend = MockBackend::default();
        // Not a valid consensus-serialized transaction.
        let result = backend.broadcast(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(
            result.is_err(),
            "a malformed tx must be an Err, not a panic"
        );
        assert!(
            backend
                .broadcasts
                .lock()
                .expect("broadcasts lock")
                .is_empty(),
            "a rejected tx is never recorded as broadcast"
        );
    }

    // -- the node-owned watch-only descriptor wallet (bead btc-policy-hn8) ---------

    /// The chain+mempool state both vault-unspent sources below are read against:
    ///
    ///  - `confirmed` — a confirmed vault output, unspent. In BOTH views.
    ///  - `mempool_spent` — a confirmed vault output that a mempool transaction
    ///    (`spender`) spends. `gettxout(..., include_mempool=true)` hides it, so it is
    ///    in NEITHER view — but the two sources reach that answer differently, which is
    ///    exactly the divergence this fixture pins down.
    ///  - `authorized` — an unconfirmed, vault-authorized transaction paying the vault.
    ///    In BOTH views, as an unconfirmed output.
    struct VaultViewFixture {
        script: ScriptBuf,
        tip: String,
        confirmed: OutPoint,
        mempool_spent: OutPoint,
        evicted_spent: OutPoint,
        spender: Transaction,
        evicted: Transaction,
        authorized: Transaction,
    }

    impl VaultViewFixture {
        fn new() -> VaultViewFixture {
            let script = ScriptBuf::from_bytes(vec![0x51]);
            // Chosen so the sorted candidate batch is `confirmed`, `mempool_spent`,
            // `evicted_spent`, then the authorized transaction's own input.
            let confirmed = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0);
            let mempool_spent = OutPoint::new(Txid::from_byte_array([0x22; 32]), 0);
            let evicted_spent = OutPoint::new(Txid::from_byte_array([0x33; 32]), 0);
            let spender = tx_spending(&[mempool_spent], 90_000, 1);
            let evicted = tx_spending(&[evicted_spent], 70_000, 3);
            let mut authorized = tx_spending(
                &[OutPoint::new(Txid::from_byte_array([0x44; 32]), 7)],
                80_000,
                2,
            );
            authorized.output[0].script_pubkey = script.clone();
            VaultViewFixture {
                script,
                tip: "ab".repeat(32),
                confirmed,
                mempool_spent,
                evicted_spent,
                spender,
                evicted,
                authorized,
            }
        }

        fn script_hex(&self) -> String {
            self.script.as_bytes().to_lower_hex_string()
        }

        /// The `vault_unspent` reads themselves — byte-identical for both sources. The
        /// batched `gettxout` is scripted per outpoint, so it states what the CHAIN
        /// says about each one and does not care how many candidates a source batched:
        /// the wallet path also carries an unconfirmed wallet transaction's own inputs,
        /// and those answer null and are dropped.
        fn read_replies(&self) -> Vec<(&'static str, serde_json::Value)> {
            let mempool = serde_json::json!({
                // `evicted` is deliberately absent: it left this node's mempool.
                "txids": [
                    self.spender.compute_txid().to_string(),
                    self.authorized.compute_txid().to_string(),
                ],
                "mempool_sequence": 41,
            });
            let vault_output = |confirmations: u64| {
                serde_json::json!({
                    "scriptPubKey": {"hex": self.script_hex()},
                    "value": 0.001,
                    "confirmations": confirmations,
                })
            };
            vec![
                ("getrawmempool", mempool.clone()),
                ("getbestblockhash", serde_json::json!(self.tip)),
                // Batched re-read of the candidates. `confirmed` survives;
                // `mempool_spent` is absent, exactly as Core hides it; `evicted_spent`
                // comes back CONFIRMED, because the transaction that spent it is gone
                // from the mempool — the case where the wallet's own spent-tracking and
                // `gettxout` disagree. Anything else reads as null.
                (
                    "gettxout",
                    serde_json::json!({"__by_outpoint": {
                        format!("{}:{}", self.confirmed.txid, self.confirmed.vout):
                            vault_output(4),
                        format!("{}:{}", self.evicted_spent.txid, self.evicted_spent.vout):
                            vault_output(5),
                    }}),
                ),
                // The authorized-unconfirmed leg: its raw bytes, then its vault output.
                (
                    "getrawtransaction",
                    serde_json::json!(serialize(&self.authorized).to_lower_hex_string()),
                ),
                (
                    "gettxout",
                    serde_json::json!({
                        "scriptPubKey": {"hex": self.script_hex()},
                        "value": 0.0008,
                        "confirmations": 0,
                    }),
                ),
                ("getbestblockhash", serde_json::json!(self.tip)),
                ("getrawmempool", mempool),
            ]
        }

        /// Refresh replies for the descriptor-wallet source. `listunspent` reports only
        /// `confirmed`: the wallet knows `spender`, so it hides `mempool_spent` — and it
        /// still holds `evicted`, so it hides `evicted_spent` too, even though that
        /// output is unspent again as far as the chain is concerned.
        ///
        /// `listsinceblock` carries the confirmed credits from all wallet history plus
        /// Core's current unconfirmed categories. `spender` and `evicted` DEBIT the
        /// vault and so are expanded for their prevouts; `authorized` only pays it, so
        /// it is credit-only and no `gettransaction` is scripted for it — an extra call
        /// would find no scripted reply and fail this fixture's tests.
        fn wallet_replies(&self) -> Vec<(&'static str, serde_json::Value)> {
            let debiting = [&self.spender, &self.evicted];
            let mut pending: Vec<Txid> = debiting.iter().map(|tx| tx.compute_txid()).collect();
            pending.sort();
            let decoded = |txid: Txid| {
                let tx = debiting
                    .iter()
                    .find(|tx| tx.compute_txid() == txid)
                    .expect("a scripted pending transaction");
                serde_json::json!({
                    "decoded": {
                        "vin": tx.input.iter().map(|input| serde_json::json!({
                            "txid": input.previous_output.txid.to_string(),
                            "vout": input.previous_output.vout,
                        })).collect::<Vec<_>>()
                    }
                })
            };
            let mut replies = vec![
                ("loadwallet", serde_json::json!({"name": "vaultnode"})),
                (
                    "getwalletinfo",
                    serde_json::json!({"private_keys_enabled": false}),
                ),
                (
                    "listdescriptors",
                    serde_json::json!({"descriptors": [
                        {"desc": format!("raw({})#abcdefgh", self.script_hex())},
                        {"desc": completion_marker(12, &self.tip)},
                    ]}),
                ),
                ("getblockhash", serde_json::json!(self.tip)),
                ("getbestblockhash", serde_json::json!(self.tip)),
                (
                    "listunspent",
                    serde_json::json!([{
                        "txid": self.confirmed.txid.to_string(),
                        "vout": self.confirmed.vout,
                        "scriptPubKey": self.script_hex(),
                    }]),
                ),
                (
                    "listsinceblock",
                    serde_json::json!({
                        "transactions": [
                            {
                                "txid": self.confirmed.txid.to_string(),
                                "vout": self.confirmed.vout,
                                "category": "receive",
                                "confirmations": 4,
                            },
                            {
                                "txid": self.mempool_spent.txid.to_string(),
                                "vout": self.mempool_spent.vout,
                                "category": "receive",
                                "confirmations": 5,
                            },
                            {
                                "txid": self.evicted_spent.txid.to_string(),
                                "vout": self.evicted_spent.vout,
                                "category": "receive",
                                "confirmations": 6,
                            },
                            {
                                "txid": self.spender.compute_txid().to_string(),
                                "vout": 0,
                                "category": "send",
                                "confirmations": 0,
                            },
                            {
                                "txid": self.evicted.compute_txid().to_string(),
                                "vout": 0,
                                "category": "send",
                                "confirmations": 0,
                            },
                            {
                                "txid": self.authorized.compute_txid().to_string(),
                                "vout": 0,
                                "category": "receive",
                                "confirmations": 0,
                            },
                        ],
                        "lastblock": self.tip,
                    }),
                ),
            ];
            for txid in pending {
                replies.push(("gettransaction", decoded(txid)));
            }
            replies.extend([
                ("getbestblockhash", serde_json::json!(self.tip)),
                ("getblockheader", serde_json::json!({"height": 12})),
                ("getblockhash", serde_json::json!(self.tip)),
                // The post-read anchor re-check. This pass has no warm cache, so the
                // anchor is the completion marker the handle verified against.
                ("getblockhash", serde_json::json!(self.tip)),
            ]);
            replies
        }

        fn scan(&self) -> serde_json::Value {
            serde_json::json!({
                "success": true,
                "bestblock": self.tip,
                "unspents": [
                    {"txid": self.confirmed.txid.to_string(), "vout": self.confirmed.vout, "height": 9},
                    {"txid": self.mempool_spent.txid.to_string(), "vout": self.mempool_spent.vout, "height": 10},
                    {"txid": self.evicted_spent.txid.to_string(), "vout": self.evicted_spent.vout, "height": 11},
                ],
            })
        }

        /// Refresh replies for the `scantxoutset` source over the SAME chain state.
        /// The scan is mempool-agnostic, so it reports all three confirmed outputs.
        fn scan_replies(&self) -> Vec<(&'static str, serde_json::Value)> {
            cold_cache_replies(self.scan(), &self.tip, 12)
        }

        /// The same fallback for a test whose wallet read fails after `loadwallet`.
        fn scan_fallback_replies(&self) -> Vec<(&'static str, serde_json::Value)> {
            scan_fallback_replies(self.scan(), &self.tip, 12)
        }

        fn vault_unspent_through(
            &self,
            refresh_replies: Vec<(&'static str, serde_json::Value)>,
        ) -> Vec<(OutPoint, Prevout)> {
            let mut replies = refresh_replies;
            replies.extend(self.read_replies());
            let (addr, server) = scripted_rpc(replies);
            let backend = BitcoindBackend::new(addr, String::new());
            let scripts = std::slice::from_ref(&self.script);
            backend
                .refresh_vault_unspent_cache(scripts)
                .expect("cache refresh");
            let authorized = HashSet::from([self.authorized.compute_txid()]);
            let unspent = backend
                .vault_unspent(scripts, &authorized)
                .expect("vault unspent");
            server.join().expect("scripted RPC completed");
            unspent
        }
    }

    /// LOAD-BEARING (bead btc-policy-hn8, constraints 1 and 2): the vault-unspent view
    /// the descriptor wallet produces must EQUAL the one `scantxoutset` produces for
    /// the same chain state — confirmed, unconfirmed, and mempool-spent alike.
    /// Anything less complete understates the coverage denominator and inflates
    /// apparent escape coverage; anything different splits honest nodes' verdicts.
    ///
    /// `evicted_spent` is the case that makes this more than a formality. `listunspent`
    /// alone would hide it — the wallet still holds the transaction that spent it, even
    /// though that transaction has left the mempool — while the chain says it is
    /// unspent and confirmed. Dropping it would understate the protected balance from
    /// per-node mempool history, so the wallet source adds every unconfirmed wallet
    /// transaction's inputs back; without that, this test fails on a value mismatch.
    #[test]
    fn the_wallet_derived_vault_unspent_view_equals_the_scan_derived_one() {
        let fixture = VaultViewFixture::new();
        let from_wallet = fixture.vault_unspent_through(fixture.wallet_replies());
        let from_scan = fixture.vault_unspent_through(fixture.scan_replies());

        assert_eq!(
            from_wallet, from_scan,
            "the wallet-derived and scan-derived vault-unspent views must agree exactly"
        );
        // And the agreed view is the RIGHT one, not two matching mistakes: both
        // confirmed-and-unspent outputs plus the authorized unconfirmed one, never the
        // output a mempool transaction has already spent.
        let mut outpoints: Vec<OutPoint> =
            from_wallet.iter().map(|(outpoint, _)| *outpoint).collect();
        outpoints.sort();
        let mut expected = vec![
            fixture.confirmed,
            fixture.evicted_spent,
            OutPoint::new(fixture.authorized.compute_txid(), 0),
        ];
        expected.sort();
        assert_eq!(outpoints, expected);
        let unconfirmed: Vec<OutPoint> = from_wallet
            .iter()
            .filter(|(_, prevout)| !prevout.confirmed)
            .map(|(outpoint, _)| *outpoint)
            .collect();
        assert_eq!(
            unconfirmed,
            vec![OutPoint::new(fixture.authorized.compute_txid(), 0)],
            "only the authorized mempool transaction's output is unconfirmed"
        );
    }

    /// A backend with no node-owned wallet must degrade to the scan and report the
    /// vault's REAL balance. Reporting an empty vault here would read as "everything is
    /// covered" at fire time, which is precisely the fail-open this bead forbids.
    #[test]
    fn a_missing_wallet_falls_back_to_the_scan_rather_than_an_empty_vault() {
        let fixture = VaultViewFixture::new();
        let unspent = fixture.vault_unspent_through(fixture.scan_replies());
        assert!(
            !unspent.is_empty(),
            "a wallet-less backend must still see the vault's coins"
        );
        assert_eq!(unspent[0].0, fixture.confirmed);
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
    }

    /// A wallet sitting at the derived name that is NOT the one this node's creation
    /// procedure builds is refused outright — the node reads no balance from it and
    /// never writes to it. Here it holds private keys; the scan serves instead.
    #[test]
    fn a_wallet_this_node_did_not_create_is_refused_and_the_scan_serves_instead() {
        let fixture = VaultViewFixture::new();
        let mut replies = vec![
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": true}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({})#abcdefgh", fixture.script_hex())},
                    {"desc": completion_marker(12, &fixture.tip)},
                ]}),
            ),
        ];
        replies.extend(fixture.scan_fallback_replies());
        let unspent = fixture.vault_unspent_through(replies);
        assert_eq!(
            unspent.len(),
            3,
            "the scan fallback must still report the whole vault"
        );
        assert_eq!(unspent[0].0, fixture.confirmed);
    }

    /// A wallet whose descriptor set is not exactly this vault's scripts plus the
    /// completion marker is refused too — the interrupted-build case, where the wallet
    /// exists but its history may not reach its birthday.
    #[test]
    fn a_wallet_without_the_completion_marker_is_refused() {
        let fixture = VaultViewFixture::new();
        let mut replies = vec![
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({})#abcdefgh", fixture.script_hex())},
                ]}),
            ),
        ];
        replies.extend(fixture.scan_fallback_replies());
        let unspent = fixture.vault_unspent_through(replies);
        assert_eq!(
            unspent.len(),
            3,
            "an unmarked wallet must not serve the vault balance; the scan does"
        );
    }

    /// **A reorg between the cold scan and its import is REFUSED, not imported**
    /// (codex hn8 review, P1).
    ///
    /// `block_time_at` reads whatever block occupies the birthday height on the
    /// CURRENTLY active chain. If a reorg replaces that block after `scantxoutset`
    /// returned, the birthday comes from the replacement branch while the completion
    /// marker still records the scan branch — and if that timestamp is more than Core's
    /// two-hour import grace window later, the descriptor rescan begins AFTER the scan
    /// branch's oldest output. That output is then never watched, yet the marker verifies
    /// on every later restart, so the omission is PERMANENT and silent.
    ///
    /// It matters because the vault balance is the DENOMINATOR of the fire-time escape
    /// coverage guard: understating it inflates apparent coverage, so an escape that
    /// should have been refused looks admissible.
    ///
    /// Driven against `import_vault_descriptors` directly rather than through a full
    /// refresh, because the scripted RPC server accepts exactly one connection per
    /// scripted reply: a test that scripts the calls the UNGUARDED path would make would
    /// hang on `join` once the guard correctly stops early. Asserting on the refusal's
    /// own words is what makes this bite — delete the guard and the failure becomes a
    /// transport error from the exhausted script instead, with a different message.
    #[test]
    fn a_reorg_between_the_cold_scan_and_its_import_refuses_to_seed_the_wallet() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let scan_tip = BlockHash::from_byte_array([0xcd; 32]);
        // The chain moved: the scan's anchor height now holds a DIFFERENT block.
        let reorged_at_scan_height = BlockHash::from_byte_array([0xee; 32]);
        let cold_scan = ColdScan {
            cache: VaultUnspentCache {
                bestblock: scan_tip,
                height: 12,
                scripts: vec![script.clone()],
                candidates: HashSet::new(),
            },
            oldest_unspent_height: 9,
        };
        let replies = vec![
            // The birthday read: block hash at the oldest unspent's height, then its time.
            ("getblockhash", serde_json::json!("07".repeat(32))),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The anchor re-verify: a DIFFERENT hash now sits at the scan's height.
            (
                "getblockhash",
                serde_json::json!(reorged_at_scan_height.to_string()),
            ),
        ];
        let (addr, server, _requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        let error = backend
            .import_vault_descriptors("vaultnode", std::slice::from_ref(&script), &cold_scan)
            .expect_err("a birthday the scan anchor no longer certifies must not be imported")
            .to_string();
        server.join().expect("scripted RPC completed");

        assert!(
            error.contains("left the active chain"),
            "the refusal must name the stale anchor rather than fail incidentally: {error}"
        );
    }

    /// Cold start on a fresh backend: the scan runs once, and the wallet it seeds is
    /// rescanned from the OLDEST unspent's block — not from genesis, and not from the
    /// tip (which would miss the coins the vault already holds). The completion marker
    /// is imported last, in its own call.
    #[test]
    fn a_cold_start_creates_the_wallet_with_a_birthday_from_the_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let tip = "cd".repeat(32);
        let birthday_hash = "07".repeat(32);
        let marker = completion_marker(12, &tip);
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [
                {"txid": Txid::from_byte_array([0x11; 32]).to_string(), "vout": 0, "height": 9},
                {"txid": Txid::from_byte_array([0x22; 32]).to_string(), "vout": 1, "height": 7},
            ],
        });
        let replies = vec![
            ("loadwallet", wallet_not_found()),
            ("scantxoutset", scan),
            ("getblockheader", serde_json::json!({"height": 12})),
            ("getblockhash", serde_json::json!(tip)),
            // Seeding: still absent, so create it and import from the birthday.
            ("loadwallet", wallet_not_found()),
            ("createwallet", serde_json::json!({"name": "vaultnode"})),
            ("getblockhash", serde_json::json!(birthday_hash)),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The post-birthday anchor re-verify: the scan tip is still active.
            ("getblockhash", serde_json::json!(tip.clone())),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": format!("raw({script_hex})#abcdefgh")}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": marker.clone()}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({script_hex})#abcdefgh")},
                    {"desc": marker.clone()},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip)),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold start warms the cache and seeds the wallet");
        server.join().expect("scripted RPC completed");

        let requests = requests.lock().expect("recorded requests lock");
        let created = requests
            .iter()
            .position(|request| request["method"] == "createwallet")
            .expect("the wallet was created");
        let birthday_read = requests[created..]
            .iter()
            .find(|request| request["method"] == "getblockhash")
            .expect("the birthday block hash was read");
        assert_eq!(
            birthday_read["params"][0], 7,
            "the rescan must start at the OLDEST unspent's height, not the scan tip"
        );
        let imports: Vec<&serde_json::Value> = requests
            .iter()
            .filter(|request| request["method"] == "importdescriptors")
            .collect();
        assert_eq!(imports.len(), 2, "the vault import, then the marker");
        assert_eq!(
            imports[0]["params"][0][0]["desc"],
            serde_json::json!(format!("raw({script_hex})#abcdefgh"))
        );
        assert_eq!(
            imports[0]["params"][0][0]["timestamp"],
            serde_json::json!(1_700_000_000u64),
            "the vault descriptor is imported with the derived birthday"
        );
        assert_eq!(
            imports[1]["params"][0][0]["desc"],
            serde_json::json!(completion_marker(12, &tip)),
        );
        assert_eq!(
            imports[1]["params"][0][0]["timestamp"],
            serde_json::json!("now"),
            "the completion marker is inert and needs no rescan of its own"
        );
    }

    /// A second startup against the same backend — a fresh process, so a fresh
    /// `BitcoindBackend` with no cached wallet handle. It must find the wallet, verify
    /// it, and serve from it: no `createwallet`, no `importdescriptors` (so no rescan),
    /// and no `scantxoutset`. `scripted_rpc` asserts the exact method sequence, so any
    /// of those calls fails this test.
    #[test]
    fn a_second_startup_reuses_the_wallet_without_re_creating_or_rescanning_it() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let tip = "ef".repeat(32);
        let txid = Txid::from_byte_array([0x44; 32]);
        let replies = vec![
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({script_hex})#abcdefgh")},
                    {"desc": completion_marker(31, &tip)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "listunspent",
                serde_json::json!([
                    {"txid": txid.to_string(), "vout": 0, "scriptPubKey": script_hex},
                ]),
            ),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip)),
            // Post-read anchor re-check: no warm cache this pass, so it re-proves the
            // completion marker the handle verified against.
            ("getblockhash", serde_json::json!(tip)),
            // A SECOND refresh in the same process: the anchor check finds no reorg, so
            // the wallet still serves — and reuses the verified handle, so there is no
            // repeat of the locate/verify handshake either.
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "listunspent",
                serde_json::json!([
                    {"txid": txid.to_string(), "vout": 0, "scriptPubKey": script_hex},
                ]),
            ),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip)),
            // …and re-proves the warm cache anchor it checked before the read.
            ("getblockhash", serde_json::json!(tip)),
            // And the cache it left serves the fire-time read.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 3}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "gettxout",
                serde_json::json!({
                    "scriptPubKey": {"hex": script_hex},
                    "value": 0.001,
                    "confirmations": 6,
                }),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 3}),
            ),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("a restart against an existing wallet needs no scan");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("a second pass reuses the verified handle");
        let unspent = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("vault unspent");
        server.join().expect("scripted RPC completed");

        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(txid, 0));
        let methods: Vec<String> = requests
            .lock()
            .expect("recorded requests lock")
            .iter()
            .map(|request| request["method"].as_str().unwrap_or_default().to_string())
            .collect();
        for forbidden in ["scantxoutset", "createwallet", "importdescriptors"] {
            assert!(
                !methods.iter().any(|method| method == forbidden),
                "a restart must not {forbidden}; issued {methods:?}"
            );
        }
    }

    /// A process that was offline during a reorg has no in-memory cache anchor to
    /// compare. The completion marker persists the cold scan's anchor in Core's
    /// wallet, so the fresh process still detects the stale wallet and takes the
    /// full-scan fallback before serving it.
    #[test]
    fn a_restart_after_an_offline_reorg_falls_back_before_using_the_wallet() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let vault_desc = format!("raw({script_hex})#abcdefgh");
        let old_tip = "aa".repeat(32);
        let replacement_at_old_height = "bb".repeat(32);
        let new_tip = "cc".repeat(32);
        let old_marker = completion_marker(20, &old_tip);
        let new_marker = completion_marker(30, &new_tip);
        let txid = Txid::from_byte_array([0x44; 32]);
        let old_wallet = serde_json::json!({"descriptors": [
            {"desc": vault_desc.clone()},
            {"desc": old_marker.clone()},
        ]});
        let repaired_wallet = serde_json::json!({"descriptors": [
            {"desc": vault_desc.clone()},
            {"desc": old_marker},
            {"desc": new_marker.clone()},
        ]});
        let watch_only = serde_json::json!({"private_keys_enabled": false});
        let replies = vec![
            // Fresh process: the persisted marker's block is no longer active.
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            ("getwalletinfo", watch_only.clone()),
            ("listdescriptors", old_wallet.clone()),
            ("getblockhash", serde_json::json!(replacement_at_old_height)),
            // The wallet is not read. A cold scan finds the resurrected output.
            (
                "scantxoutset",
                serde_json::json!({
                    "success": true,
                    "bestblock": new_tip,
                    "unspents": [{"txid": txid.to_string(), "vout": 0, "height": 4}],
                }),
            ),
            ("getblockheader", serde_json::json!({"height": 30})),
            ("getblockhash", serde_json::json!(new_tip)),
            // Seeding recognizes the owned-but-stale wallet and repairs it.
            (
                "loadwallet",
                serde_json::json!({"__error": {"code": -35, "message": "already loaded"}}),
            ),
            ("getwalletinfo", watch_only),
            ("listdescriptors", old_wallet),
            ("getblockhash", serde_json::json!(replacement_at_old_height)),
            ("getblockhash", serde_json::json!("04".repeat(32))),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The post-birthday anchor re-verify: the scan tip is still active.
            ("getblockhash", serde_json::json!(new_tip.clone())),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": vault_desc}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": new_marker}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            ("listdescriptors", repaired_wallet),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("the stale wallet degrades to the scan and is repaired");
        server.join().expect("scripted RPC completed");

        let requests = requests.lock().expect("recorded requests lock");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "scantxoutset")
                .count(),
            1,
            "the offline reorg must force one reconciliation scan"
        );
        assert!(
            !requests
                .iter()
                .any(|request| request["method"] == "listunspent"),
            "the stale wallet must not serve before the repair"
        );
    }

    /// Re-loading a stale owned wallet during a latched reorg repair must import each
    /// descriptor set exactly once. `verify_vault_wallet` performs the repair while
    /// locating the handle; `seed_vault_wallet` must observe that the latch was cleared
    /// rather than repeating the same potentially long rescan.
    #[test]
    fn locating_a_stale_wallet_does_not_repeat_the_same_repair_import() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let vault_desc = format!("raw({script_hex})#abcdefgh");
        let old_tip = "aa".repeat(32);
        let replacement = "bb".repeat(32);
        let new_tip = "cc".repeat(32);
        let old_marker = completion_marker(20, &old_tip);
        let new_marker = completion_marker(31, &new_tip);
        let replies = vec![
            (
                "loadwallet",
                serde_json::json!({"__error": {"code": -35, "message": "already loaded"}}),
            ),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": vault_desc.clone()},
                    {"desc": old_marker.clone()},
                ]}),
            ),
            ("getblockhash", serde_json::json!(replacement)),
            ("getblockhash", serde_json::json!("04".repeat(32))),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The post-birthday anchor re-verify: the scan tip is still active.
            ("getblockhash", serde_json::json!(new_tip.clone())),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": vault_desc.clone()}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": new_marker.clone()}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": vault_desc},
                    {"desc": old_marker},
                    {"desc": new_marker},
                ]}),
            ),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        *backend
            .wallet_reimport_pending
            .lock()
            .expect("wallet reimport lock poisoned") = true;
        let cold = ColdScan {
            cache: VaultUnspentCache {
                bestblock: new_tip.parse().expect("new tip"),
                height: 31,
                scripts: vec![script.clone()],
                candidates: HashSet::new(),
            },
            oldest_unspent_height: 4,
        };

        backend
            .seed_vault_wallet(std::slice::from_ref(&script), &cold)
            .expect("one repair establishes the wallet");
        server.join().expect("scripted RPC completed");

        let requests = requests.lock().expect("recorded requests lock");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "importdescriptors")
                .count(),
            2,
            "repair imports the vault descriptor set and completion marker once each"
        );
        assert!(
            !*backend
                .wallet_reimport_pending
                .lock()
                .expect("wallet reimport lock poisoned"),
            "a completed repair clears the latch before seed_vault_wallet resumes"
        );
    }

    /// LOAD-BEARING (bead btc-policy-hn8, constraints 1 and 3): a reorg below the
    /// WALLET's completion anchor latches the wallet OUT until a re-import repairs it.
    ///
    /// A reorg can un-spend a vault output created before the wallet's birthday, in a
    /// dropped block, by a transaction that paid the vault nothing — so the wallet
    /// neither watched the output nor holds the transaction, and no wallet-only read
    /// can ever surface it again. That is a permanent under-report of the coverage
    /// denominator, i.e. permanently INFLATED escape coverage. `scantxoutset` has no
    /// such blind spot, so the reorg pass takes it and re-imports the descriptors from
    /// the birthday that fresh scan proves; only then does the wallet serve again.
    #[test]
    fn a_reorg_below_the_wallet_anchor_latches_the_wallet_out_until_it_is_re_imported() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let vault_desc = format!("raw({script_hex})#abcdefgh");
        let tip = "ef".repeat(32);
        let reorged_tip = "fe".repeat(32);
        let txid = Txid::from_byte_array([0x44; 32]);
        let unspent = serde_json::json!([
            {"txid": txid.to_string(), "vout": 0, "scriptPubKey": script_hex},
        ]);
        let replies = vec![
            // Pass 1 — no cache yet, so no reorg to detect; the wallet serves and
            // anchors the cache at height 31.
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": vault_desc.clone()},
                    {"desc": completion_marker(31, &tip)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            ("listunspent", unspent.clone()),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip)),
            // Post-read anchor re-check, against the marker this handle verified.
            ("getblockhash", serde_json::json!(tip)),
            // Pass 2 — height 31, where this wallet's completion marker sits, now holds
            // a DIFFERENT block, so the wallet may be blind to what the reorg
            // resurrected. No `listunspent` may appear until the repair lands.
            ("getblockhash", serde_json::json!(reorged_tip)),
            (
                "scantxoutset",
                serde_json::json!({
                    "success": true,
                    "bestblock": reorged_tip,
                    "unspents": [{"txid": txid.to_string(), "vout": 0, "height": 4}],
                }),
            ),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(reorged_tip)),
            // The repair: re-import from the birthday the fresh scan proves, even
            // though this wallet already verified as complete.
            ("getblockhash", serde_json::json!("04".repeat(32))),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The post-birthday anchor re-verify: the scan tip is still active.
            ("getblockhash", serde_json::json!(reorged_tip.clone())),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": vault_desc}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": completion_marker(31, &reorged_tip)}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            // Pass 3 — repaired, so the wallet serves again and the scan is gone.
            ("getblockhash", serde_json::json!(reorged_tip)),
            ("getbestblockhash", serde_json::json!(reorged_tip)),
            ("listunspent", unspent),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": reorged_tip}),
            ),
            ("getbestblockhash", serde_json::json!(reorged_tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(reorged_tip)),
            // …and re-proves the warm cache anchor after that read.
            ("getblockhash", serde_json::json!(reorged_tip)),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the wallet serves the first pass");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the reorg pass falls back to the scan and repairs the wallet");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the repaired wallet serves again");
        server.join().expect("scripted RPC completed");

        // The cache still holds the vault's coin: a reorg degrades this node to the
        // slow source, never to an empty vault.
        let cached = backend.scan_cache.lock().expect("scan cache lock poisoned");
        assert_eq!(
            cached.as_ref().expect("a warm cache").candidates,
            HashSet::from([OutPoint::new(txid, 0)])
        );
        let methods: Vec<String> = requests
            .lock()
            .expect("recorded requests lock")
            .iter()
            .map(|request| request["method"].as_str().unwrap_or_default().to_string())
            .collect();
        let scan = methods
            .iter()
            .position(|method| method == "scantxoutset")
            .expect("the reorg pass scanned");
        let repair = methods
            .iter()
            .position(|method| method == "importdescriptors")
            .expect("the reorg pass re-imported the descriptors");
        let served_again = methods
            .iter()
            .rposition(|method| method == "listunspent")
            .expect("the wallet served again");
        assert!(
            scan < repair && repair < served_again,
            "the wallet may only serve again AFTER the repair: {methods:?}"
        );
        assert_eq!(
            methods.iter().filter(|m| *m == "listunspent").count(),
            2,
            "the reorg pass itself must not read the wallet: {methods:?}"
        );
    }

    /// The other side of that guard: a reorg ABOVE the wallet's completion anchor —
    /// the routine 1-block kind — must NOT latch, must not scan, and must not
    /// re-import.
    ///
    /// A block hash commits to its whole ancestry, so while height 31 still holds the
    /// marker's block nothing at or below 31 has moved: every output such a reorg can
    /// resurrect was unspent at 31, hence at or after the birthday that marker's import
    /// proved, hence already watched. Latching on the last pass's tip instead would pay
    /// a whole-set scan AND an `importdescriptors` rescan of the vault's history for
    /// every one-block reorg — and `confirmed_candidates` refuses every fire-time read
    /// until that finishes, so the fail-closed cost of over-latching is an escape-path
    /// outage on a routine chain event.
    #[test]
    fn a_reorg_above_the_wallet_anchor_is_reconciled_by_the_wallet_without_a_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let marker_block = "31".repeat(32);
        let tip_a = "ef".repeat(32);
        let tip_b = "fe".repeat(32);
        let held = OutPoint::new(Txid::from_byte_array([0x44; 32]), 0);
        let unspent = serde_json::json!([
            {"txid": held.txid.to_string(), "vout": held.vout, "scriptPubKey": script_hex},
        ]);
        let replies = vec![
            // Pass 1 — the wallet serves and anchors the CACHE at (40, tip_a), while
            // the wallet's own completion anchor stays at (31, marker_block).
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({script_hex})#abcdefgh")},
                    {"desc": completion_marker(31, &marker_block)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(marker_block)),
            ("getbestblockhash", serde_json::json!(tip_a)),
            ("listunspent", unspent.clone()),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip_a}),
            ),
            ("getbestblockhash", serde_json::json!(tip_a)),
            ("getblockheader", serde_json::json!({"height": 40})),
            ("getblockhash", serde_json::json!(tip_a)),
            ("getblockhash", serde_json::json!(marker_block)),
            // Pass 2 — a reorg replaced the block at height 40, so the CACHE anchor is
            // gone; the marker at 31 is untouched, so the wallet still serves. It is
            // handed the orphaned anchor as `listsinceblock`'s `since`, which Core
            // answers from the fork point.
            ("getblockhash", serde_json::json!(marker_block)),
            ("getbestblockhash", serde_json::json!(tip_b)),
            ("listunspent", unspent),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip_b}),
            ),
            ("getbestblockhash", serde_json::json!(tip_b)),
            ("getblockheader", serde_json::json!({"height": 40})),
            ("getblockhash", serde_json::json!(tip_b)),
            ("getblockhash", serde_json::json!(marker_block)),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the wallet serves the first pass");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("a reorg above the wallet anchor is served by the wallet too");
        server.join().expect("scripted RPC completed");

        let cached = backend.scan_cache.lock().expect("scan cache lock poisoned");
        let cached = cached.as_ref().expect("a warm cache");
        assert_eq!(cached.candidates, HashSet::from([held]));
        assert_eq!(
            (cached.height, cached.bestblock.to_string()),
            (40, tip_b),
            "the cache re-anchors on the new chain"
        );
        assert_eq!(
            backend.full_scan_count(),
            0,
            "a reorg the wallet can see through costs no whole-set scan"
        );
        let requests = requests.lock().expect("recorded requests lock");
        let methods: Vec<String> = requests
            .iter()
            .map(|request| request["method"].as_str().unwrap_or_default().to_string())
            .collect();
        for forbidden in ["scantxoutset", "importdescriptors", "createwallet"] {
            assert!(
                !methods.iter().any(|method| method == forbidden),
                "a reorg above the wallet anchor must not {forbidden}: {methods:?}"
            );
        }
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "listsinceblock")
                .filter_map(|request| request["params"][0].as_str().map(str::to_string))
                .collect::<Vec<String>>(),
            vec![tip_a],
            "the second pass asks Core to reconcile from the orphaned cache anchor"
        );
    }

    /// A repair that FAILS keeps the wallet latched out and is retried on the next
    /// pass. The latch is what makes the reorg guard fail closed: while it is set the
    /// pass takes the full scan even from a live cache anchor, because only that scan
    /// re-derives the birthday the repair needs. Without the retry a single failed
    /// import would pin this node to `scantxoutset` for the rest of its life.
    #[test]
    fn a_failed_repair_keeps_the_wallet_out_until_a_later_pass_succeeds() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let vault_desc = format!("raw({script_hex})#abcdefgh");
        let tip = "ef".repeat(32);
        let reorged_tip = "fe".repeat(32);
        let txid = Txid::from_byte_array([0x44; 32]);
        let unspent = serde_json::json!([
            {"txid": txid.to_string(), "vout": 0, "scriptPubKey": script_hex},
        ]);
        let scan = || {
            serde_json::json!({
                "success": true,
                "bestblock": reorged_tip,
                "unspents": [{"txid": txid.to_string(), "vout": 0, "height": 4}],
            })
        };
        // The scan, its anchor check, and the birthday read that opens every repair.
        let scan_and_birthday = || {
            vec![
                ("scantxoutset", scan()),
                ("getblockheader", serde_json::json!({"height": 31})),
                ("getblockhash", serde_json::json!(reorged_tip)),
                ("getblockhash", serde_json::json!("04".repeat(32))),
                (
                    "getblockheader",
                    serde_json::json!({"time": 1_700_000_000u64}),
                ),
                // The post-birthday anchor re-verify: the scan tip is still active.
                ("getblockhash", serde_json::json!(reorged_tip.clone())),
                (
                    "getdescriptorinfo",
                    serde_json::json!({"descriptor": vault_desc.clone()}),
                ),
            ]
        };
        let mut replies = vec![
            // Pass 1 — the wallet serves and anchors the cache at height 31.
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": vault_desc.clone()},
                    {"desc": completion_marker(31, &tip)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            ("listunspent", unspent.clone()),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip)),
            // Post-read anchor re-check, against the marker this handle verified.
            ("getblockhash", serde_json::json!(tip)),
            // Pass 2 — a reorg below the anchor; the repair's import FAILS.
            ("getblockhash", serde_json::json!(reorged_tip)),
        ];
        replies.extend(scan_and_birthday());
        replies.push((
            "importdescriptors",
            serde_json::json!([{"success": false, "error": {"code": -1, "message": "aborted"}}]),
        ));
        // Pass 3 — the anchor is live again, so nothing here re-detects the reorg: only
        // the latch keeps the wallet out and drives the full scan that retries the
        // repair. This time it lands.
        replies.push(("getblockhash", serde_json::json!(reorged_tip)));
        replies.extend(scan_and_birthday());
        replies.extend([
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": completion_marker(31, &reorged_tip)}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            // Pass 4 — repaired, so the wallet serves again.
            ("getblockhash", serde_json::json!(reorged_tip)),
            ("getbestblockhash", serde_json::json!(reorged_tip)),
            ("listunspent", unspent),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": reorged_tip}),
            ),
            ("getbestblockhash", serde_json::json!(reorged_tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(reorged_tip)),
            // …and re-proves the warm cache anchor after that read.
            ("getblockhash", serde_json::json!(reorged_tip)),
        ]);
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        for pass in 1..=4 {
            backend
                .refresh_vault_unspent_cache(scripts)
                .unwrap_or_else(|e| panic!("pass {pass} must still warm the cache: {e}"));
        }
        server.join().expect("scripted RPC completed");

        let methods: Vec<String> = requests
            .lock()
            .expect("recorded requests lock")
            .iter()
            .map(|request| request["method"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(
            methods.iter().filter(|m| *m == "scantxoutset").count(),
            2,
            "the failed repair must be retried by a second scan: {methods:?}"
        );
        assert_eq!(
            methods.iter().filter(|m| *m == "listunspent").count(),
            2,
            "the wallet serves only before the reorg and after the repair: {methods:?}"
        );
    }

    /// A wallet whose build was interrupted before the completion marker landed — a
    /// rescan cut short in an earlier process generation — is FINISHED by the
    /// cold-scan seeding path rather than abandoned. Without this the node would
    /// refuse its own half-built wallet forever and never leave the `scantxoutset`
    /// fallback.
    #[test]
    fn an_interrupted_wallet_build_is_finished_by_the_next_cold_scan() {
        let fixture = VaultViewFixture::new();
        let vault_desc = format!("raw({})#abcdefgh", fixture.script_hex());
        let unmarked = serde_json::json!({"descriptors": [{"desc": vault_desc.clone()}]});
        let complete = serde_json::json!({"descriptors": [
            {"desc": vault_desc.clone()},
            {"desc": completion_marker(12, &fixture.tip)},
        ]});
        let watch_only = serde_json::json!({"private_keys_enabled": false});
        let mut replies = vec![
            // The wallet read finds the half-built wallet and refuses it: no birthday
            // here, so it cannot be finished, and the scan fallback runs.
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            ("getwalletinfo", watch_only.clone()),
            ("listdescriptors", unmarked.clone()),
            ("scantxoutset", fixture.scan()),
            ("getblockheader", serde_json::json!({"height": 12})),
            ("getblockhash", serde_json::json!(fixture.tip)),
            // Seeding, now WITH a birthday: the wallet is already loaded, is watch-only,
            // and holds a subset of what this node imports — so finish the build.
            (
                "loadwallet",
                serde_json::json!({"__error": {"code": -35, "message": "already loaded"}}),
            ),
            ("getwalletinfo", watch_only),
            ("listdescriptors", unmarked),
            ("getblockhash", serde_json::json!("09".repeat(32))),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The post-birthday anchor re-verify: the scan tip is still active.
            ("getblockhash", serde_json::json!(fixture.tip.clone())),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": vault_desc}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": completion_marker(12, &fixture.tip)}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            ("listdescriptors", complete),
        ];
        replies.extend(fixture.read_replies());
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&fixture.script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the cold scan warms the cache and finishes the wallet");
        let authorized = HashSet::from([fixture.authorized.compute_txid()]);
        let unspent = backend
            .vault_unspent(scripts, &authorized)
            .expect("vault unspent");
        server.join().expect("scripted RPC completed");

        assert_eq!(unspent.len(), 3, "the scan still served this pass");
        let requests = requests.lock().expect("recorded requests lock");
        assert!(
            !requests
                .iter()
                .any(|request| request["method"] == "createwallet"),
            "an existing wallet is finished, never re-created"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "importdescriptors")
                .count(),
            2,
            "the vault descriptors are re-imported from the birthday, then the marker"
        );
    }

    /// The repair is bounded by a SUBSET test, so a wallet holding anything this node
    /// would not import is left completely alone — no import, no balance read.
    #[test]
    fn a_wallet_holding_a_foreign_descriptor_is_never_repaired() {
        let fixture = VaultViewFixture::new();
        let foreign = serde_json::json!({"descriptors": [
            {"desc": format!("raw({})#abcdefgh", fixture.script_hex())},
            {"desc": "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#5cwmnzsm"},
        ]});
        let watch_only = serde_json::json!({"private_keys_enabled": false});
        let mut replies = vec![
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            ("getwalletinfo", watch_only.clone()),
            ("listdescriptors", foreign.clone()),
            ("scantxoutset", fixture.scan()),
            ("getblockheader", serde_json::json!({"height": 12})),
            ("getblockhash", serde_json::json!(fixture.tip)),
            // Seeding sees the same foreign wallet and, having a birthday, still
            // refuses: the subset test fails, so nothing is imported into it.
            (
                "loadwallet",
                serde_json::json!({"__error": {"code": -35, "message": "already loaded"}}),
            ),
            ("getwalletinfo", watch_only),
            ("listdescriptors", foreign),
        ];
        replies.extend(fixture.read_replies());
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&fixture.script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the scan serves even though the wallet is unusable");
        let authorized = HashSet::from([fixture.authorized.compute_txid()]);
        let unspent = backend
            .vault_unspent(scripts, &authorized)
            .expect("vault unspent");
        server.join().expect("scripted RPC completed");

        assert_eq!(
            unspent.len(),
            3,
            "the scan reports the whole vault; the foreign wallet reports nothing"
        );
        assert!(
            !requests
                .lock()
                .expect("recorded requests lock")
                .iter()
                .any(|request| request["method"] == "importdescriptors"),
            "a wallet this node did not build must never be written to"
        );
    }

    /// The vault's script is PUBLIC, so anyone may pay it. Such a deposit is
    /// credit-only: it holds no vault prevout that `listunspent` could be hiding, so
    /// nothing about it belongs in the confirmed-candidate set. Expanding it anyway
    /// would hand an attacker a cheap lever on the FIRE path — every input of every
    /// unconfirmed deposit would land in the batched `gettxout` that the coverage read
    /// must finish inside the combine window — and one `gettransaction` per deposit on
    /// every refresh besides.
    ///
    /// `scripted_rpc` serves an exact method sequence, so the absence of a
    /// `gettransaction` reply for the deposit is itself the assertion: expanding it
    /// fails this test.
    #[test]
    fn an_unconfirmed_deposit_to_the_vault_does_not_expand_the_candidate_set() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let tip = "ef".repeat(32);
        let held = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0);
        let spent = OutPoint::new(Txid::from_byte_array([0x22; 32]), 0);
        // The vault's own unconfirmed spend, which DOES hide a vault output.
        let spend = tx_spending(&[spent], 90_000, 1);
        // An unrelated deposit paying the vault, carrying many inputs of its own.
        let deposit_inputs: Vec<OutPoint> = (0..16)
            .map(|i| OutPoint::new(Txid::from_byte_array([0x90 + i as u8; 32]), i))
            .collect();
        let mut deposit = tx_spending(&deposit_inputs, 10_000, 2);
        deposit.output[0].script_pubkey = script.clone();
        let replies = vec![
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({script_hex})#abcdefgh")},
                    {"desc": completion_marker(31, &tip)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "listunspent",
                serde_json::json!([
                    {"txid": held.txid.to_string(), "vout": held.vout, "scriptPubKey": script_hex},
                ]),
            ),
            (
                "listsinceblock",
                serde_json::json!({
                    "transactions": [
                        {
                            "txid": deposit.compute_txid().to_string(),
                            "vout": 0,
                            "category": "receive",
                            "confirmations": 0,
                        },
                        {
                            "txid": spend.compute_txid().to_string(),
                            "vout": 0,
                            "category": "send",
                            "confirmations": 0,
                        },
                    ],
                    "lastblock": tip,
                }),
            ),
            // Exactly one expansion: the vault-debiting spend.
            (
                "gettransaction",
                serde_json::json!({"decoded": {"vin": [
                    {"txid": spent.txid.to_string(), "vout": spent.vout},
                ]}}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip)),
            ("getblockhash", serde_json::json!(tip)),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("the wallet serves this pass");
        server.join().expect("scripted RPC completed");

        let cached = backend.scan_cache.lock().expect("scan cache lock poisoned");
        assert_eq!(
            cached.as_ref().expect("a warm cache").candidates,
            HashSet::from([held, spent]),
            "the vault's own held and mempool-hidden outputs, and nothing the deposit dragged in"
        );
        let expanded: Vec<serde_json::Value> = requests
            .lock()
            .expect("recorded requests lock")
            .iter()
            .filter(|request| request["method"] == "gettransaction")
            .map(|request| request["params"][0].clone())
            .collect();
        assert_eq!(
            expanded,
            vec![serde_json::json!(spend.compute_txid().to_string())],
            "only vault-debiting transactions are read; a deposit costs no RPC at all"
        );
    }

    /// The carried-forward candidate set must SHRINK when the chain spends a vault
    /// output, not just grow. `listunspent` simply stops reporting a spent output, and
    /// the union with the previous cache (and, after a restart, with every confirmed
    /// credit in the wallet's whole history) would otherwise put it back forever — so
    /// the fire path's batched `gettxout`, the one read that must finish inside the
    /// combine window, would scale with LIFETIME deposits instead of live outputs.
    /// Only a confirmed debit prunes: an unconfirmed one is still expanded, because
    /// its spender can leave the mempool and the chain still holds the output.
    #[test]
    fn a_confirmed_vault_spend_prunes_the_outputs_it_consumed() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let tip_a = "ef".repeat(32);
        let tip_b = "fe".repeat(32);
        let first = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0);
        let second = OutPoint::new(Txid::from_byte_array([0x22; 32]), 0);
        // A confirmed vault spend consuming both, paying the vault back once.
        let spend = tx_spending(&[first, second], 190_000, 1);
        let change = OutPoint::new(spend.compute_txid(), 0);
        let both = serde_json::json!([
            {"txid": first.txid.to_string(), "vout": first.vout, "scriptPubKey": script_hex},
            {"txid": second.txid.to_string(), "vout": second.vout, "scriptPubKey": script_hex},
        ]);
        let replies = vec![
            // Pass 1 — the wallet reports both outputs and anchors the cache at tip_a.
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({script_hex})#abcdefgh")},
                    {"desc": completion_marker(31, &tip_a)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip_a)),
            ("getbestblockhash", serde_json::json!(tip_a)),
            ("listunspent", both),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip_a}),
            ),
            ("getbestblockhash", serde_json::json!(tip_a)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip_a)),
            ("getblockhash", serde_json::json!(tip_a)),
            // Pass 2 — the spend confirmed. `listunspent` now reports only its change,
            // and wallet history carries the confirmed debit plus the credit it paid.
            ("getblockhash", serde_json::json!(tip_a)),
            ("getbestblockhash", serde_json::json!(tip_b)),
            (
                "listunspent",
                serde_json::json!([
                    {"txid": change.txid.to_string(), "vout": change.vout, "scriptPubKey": script_hex},
                ]),
            ),
            (
                "listsinceblock",
                serde_json::json!({
                    "transactions": [
                        {
                            "txid": spend.compute_txid().to_string(),
                            "vout": 0,
                            "category": "send",
                            "confirmations": 1,
                        },
                        {
                            "txid": spend.compute_txid().to_string(),
                            "vout": 0,
                            "category": "receive",
                            "confirmations": 1,
                        },
                    ],
                    "lastblock": tip_b,
                }),
            ),
            // The confirmed debit is read for its inputs, exactly like an unconfirmed
            // one — but to REMOVE them.
            (
                "gettransaction",
                serde_json::json!({"decoded": {"vin": [
                    {"txid": first.txid.to_string(), "vout": first.vout},
                    {"txid": second.txid.to_string(), "vout": second.vout},
                ]}}),
            ),
            ("getbestblockhash", serde_json::json!(tip_b)),
            ("getblockheader", serde_json::json!({"height": 32})),
            ("getblockhash", serde_json::json!(tip_b)),
            ("getblockhash", serde_json::json!(tip_a)),
        ];
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the wallet serves the first pass");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the wallet serves the pass that sees the spend confirm");
        server.join().expect("scripted RPC completed");

        assert_eq!(
            backend
                .scan_cache
                .lock()
                .expect("scan cache lock poisoned")
                .as_ref()
                .expect("a warm cache")
                .candidates,
            HashSet::from([change]),
            "the two consumed outputs must be gone, not carried forward forever"
        );
    }

    /// The endpoint tip comparison alone cannot detect A→B→A around `listunspent`.
    /// Here that call returns B's empty view while both endpoint reads see A. Core's
    /// `listsinceblock` response is modeled at A: its transaction list and `lastblock`
    /// come from one wallet-locked snapshot, so the confirmed A output is restored and
    /// the cache cannot be published empty.
    #[test]
    fn an_aba_reorg_around_listunspent_cannot_understate_the_vault_cache() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let tip_a = "ef".repeat(32);
        let held = OutPoint::new(Txid::from_byte_array([0x44; 32]), 0);
        let replies = vec![
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": format!("raw({script_hex})#abcdefgh")},
                    {"desc": completion_marker(31, &tip_a)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip_a)),
            // Endpoint A before the wallet read.
            ("getbestblockhash", serde_json::json!(tip_a)),
            // The interleaved B snapshot omits A's output.
            ("listunspent", serde_json::json!([])),
            // Wallet processing has returned to A. The all-history read restores the
            // confirmed credit and binds it to A in this same RPC response.
            (
                "listsinceblock",
                serde_json::json!({
                    "transactions": [{
                        "txid": held.txid.to_string(),
                        "vout": held.vout,
                        "category": "receive",
                        "confirmations": 6,
                    }],
                    "lastblock": tip_a,
                }),
            ),
            // Endpoint A again: the old bracket alone would accept the empty view.
            ("getbestblockhash", serde_json::json!(tip_a)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip_a)),
            ("getblockhash", serde_json::json!(tip_a)),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("the wallet-anchored history reconciles the ABA read");
        server.join().expect("scripted RPC completed");

        assert_eq!(
            backend
                .scan_cache
                .lock()
                .expect("scan cache lock poisoned")
                .as_ref()
                .expect("a warm cache")
                .candidates,
            HashSet::from([held]),
            "the A output omitted by listunspent must remain in the A-anchored cache"
        );
        let requests = requests.lock().expect("recorded requests lock");
        let history = requests
            .iter()
            .find(|request| request["method"] == "listsinceblock")
            .expect("wallet history request");
        assert!(
            history["params"][0].is_null(),
            "a restart has no in-memory candidate superset, so it must read all wallet history"
        );
    }

    /// The reorg check that keeps a wallet-blind view out of the cache runs BEFORE the
    /// wallet read, so it must be re-proved after it. A reorg landing inside that window
    /// is not a transient loss: the blind result would be installed anchored to the NEW
    /// tip, every later pass would find that anchor active, the latch would never fire,
    /// and the resurrected pre-birthday output would be missing from the protected
    /// balance for good — permanently INFLATED escape coverage.
    #[test]
    fn a_reorg_landing_while_the_wallet_is_read_discards_that_read() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let vault_desc = format!("raw({script_hex})#abcdefgh");
        let tip = "ef".repeat(32);
        let new_tip = "fe".repeat(32);
        let replacement_at_31 = "dc".repeat(32);
        let held = OutPoint::new(Txid::from_byte_array([0x44; 32]), 0);
        // Older than the wallet's birthday, so only the scan can see it once the reorg
        // un-spends it. This is the output the wallet is blind to.
        let resurrected = OutPoint::new(Txid::from_byte_array([0x55; 32]), 1);
        let unspent = serde_json::json!([
            {"txid": held.txid.to_string(), "vout": held.vout, "scriptPubKey": script_hex},
        ]);
        let replies = vec![
            // Pass 1 — the wallet serves and anchors the cache at (31, tip).
            ("loadwallet", serde_json::json!({"name": "vaultnode"})),
            (
                "getwalletinfo",
                serde_json::json!({"private_keys_enabled": false}),
            ),
            (
                "listdescriptors",
                serde_json::json!({"descriptors": [
                    {"desc": vault_desc.clone()},
                    {"desc": completion_marker(31, &tip)},
                ]}),
            ),
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            ("listunspent", unspent.clone()),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": tip}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getblockheader", serde_json::json!({"height": 31})),
            ("getblockhash", serde_json::json!(tip)),
            ("getblockhash", serde_json::json!(tip)),
            // Pass 2 — the pre-read check still sees height 31 holding `tip`, so the
            // wallet is read. The reorg lands DURING that read: it replaces 31 and
            // builds to 32, which the read's own bracket accepts as a stable tip.
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(new_tip)),
            ("listunspent", unspent),
            (
                "listsinceblock",
                serde_json::json!({"transactions": [], "lastblock": new_tip}),
            ),
            ("getbestblockhash", serde_json::json!(new_tip)),
            ("getblockheader", serde_json::json!({"height": 32})),
            ("getblockhash", serde_json::json!(new_tip)),
            // The post-read re-check of the SAME anchor: height 31 has changed.
            ("getblockhash", serde_json::json!(replacement_at_31)),
            // So the wallet's answer is discarded and the scan re-derives the truth,
            // including the output the reorg resurrected below the wallet's birthday.
            (
                "scantxoutset",
                serde_json::json!({
                    "success": true,
                    "bestblock": new_tip,
                    "unspents": [
                        {"txid": held.txid.to_string(), "vout": held.vout, "height": 20},
                        {
                            "txid": resurrected.txid.to_string(),
                            "vout": resurrected.vout,
                            "height": 4,
                        },
                    ],
                }),
            ),
            ("getblockheader", serde_json::json!({"height": 32})),
            ("getblockhash", serde_json::json!(new_tip)),
            // …and the descriptors are re-imported from that fresh birthday.
            ("getblockhash", serde_json::json!("04".repeat(32))),
            (
                "getblockheader",
                serde_json::json!({"time": 1_700_000_000u64}),
            ),
            // The post-birthday anchor re-verify: the scan tip is still active.
            ("getblockhash", serde_json::json!(new_tip.clone())),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": vault_desc}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
            (
                "getdescriptorinfo",
                serde_json::json!({"descriptor": completion_marker(32, &new_tip)}),
            ),
            ("importdescriptors", serde_json::json!([{"success": true}])),
        ];
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the wallet serves the first pass");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("the raced pass falls back to the scan");
        server.join().expect("scripted RPC completed");

        let cached = backend.scan_cache.lock().expect("scan cache lock poisoned");
        let cached = cached.as_ref().expect("a warm cache");
        assert_eq!(
            cached.candidates,
            HashSet::from([held, resurrected]),
            "the installed cache must be the scan's, which sees the resurrected output"
        );
        assert_eq!(
            (cached.height, cached.bestblock.to_string()),
            (32, new_tip),
            "and it must be anchored where the scan proved it, not where the wallet read"
        );
        assert!(
            requests
                .lock()
                .expect("recorded requests lock")
                .iter()
                .any(|request| request["method"] == "importdescriptors"),
            "the raced read must also latch the wallet out until it is re-imported"
        );
    }

    /// The live refresher must RETURN after publishing the cold scan's cache, without
    /// waiting for the wallet build it seeds. `importdescriptors` is budgeted in
    /// minutes, and a reorg below the wallet anchor forces the same build path — so
    /// merely publishing before a synchronous build is insufficient: the one refresher
    /// could not advance that cache when the next block lands. The gate suspends the
    /// background seed inside `createwallet`; reaching it after the live refresh already
    /// returned proves the slow work no longer occupies the refresher.
    #[test]
    fn the_live_refresher_returns_after_publishing_before_the_wallet_build() {
        let fixture = VaultViewFixture::new();
        let (hit_tx, hit_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let (addr, server, _) = scripted_rpc_gated(
            fixture.scan_replies(),
            Some(("createwallet", hit_tx, resume_rx)),
        );
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = vec![fixture.script.clone()];

        backend
            .refresh_vault_unspent_cache_live(&scripts)
            .expect("the live refresh returns after publishing the cold cache");
        hit_rx
            .recv()
            .expect("the background seed reached the wallet build");
        let candidates = backend
            .scan_cache
            .lock()
            .expect("scan cache lock poisoned")
            .as_ref()
            .map(|cache| cache.candidates.clone());
        resume_tx.send(()).expect("release the wallet build");
        server.join().expect("scripted RPC completed");
        while backend.wallet_reimport_in_progress.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        assert_eq!(
            candidates,
            Some(HashSet::from([
                fixture.confirmed,
                fixture.mempool_spent,
                fixture.evicted_spent,
            ])),
            "the whole scan-derived vault view must already be serving mid-build"
        );
    }

    /// Once a cold reorg scan has launched the slow descriptor repair, later live
    /// passes must keep its complete scan-derived cache at the active tip. Otherwise
    /// `confirmed_candidates` rejects the cache at the first new block and no escape
    /// can pass coverage until the up-to-ten-minute import returns.
    #[test]
    fn a_background_wallet_repair_does_not_stop_scan_cache_delta_advancement() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let old_tip = "ab".repeat(32);
        let new_tip = "cd".repeat(32);
        let held = OutPoint::new(Txid::from_byte_array([0x44; 32]), 0);
        let replies = vec![
            // The cached scan anchor is still active.
            ("getblockhash", serde_json::json!(old_tip)),
            ("getblockcount", serde_json::json!(32)),
            ("getblockhash", serde_json::json!(new_tip)),
            (
                "getblock",
                serde_json::json!({
                    "previousblockhash": old_tip,
                    "tx": [],
                }),
            ),
            // Transactional terminal check for the delta, then the fire-time tip read.
            ("getblockhash", serde_json::json!(new_tip)),
            ("getbestblockhash", serde_json::json!(new_tip)),
        ];
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        *backend.scan_cache.lock().expect("scan cache lock poisoned") = Some(VaultUnspentCache {
            bestblock: old_tip.parse().expect("old tip"),
            height: 31,
            scripts: vec![script.clone()],
            candidates: HashSet::from([held]),
        });
        *backend
            .wallet_reimport_pending
            .lock()
            .expect("wallet reimport lock poisoned") = true;
        backend
            .wallet_reimport_in_progress
            .store(true, Ordering::Release);

        backend
            .refresh_vault_unspent_cache_live(std::slice::from_ref(&script))
            .expect("the scan-derived cache advances while repair is in progress");
        let (tip, candidates) = backend
            .confirmed_candidates(std::slice::from_ref(&script))
            .expect("the advanced cache serves coverage at the new tip");
        backend
            .wallet_reimport_in_progress
            .store(false, Ordering::Release);
        server.join().expect("scripted RPC completed");

        assert_eq!(tip.to_string(), new_tip);
        assert_eq!(candidates, vec![held]);
        assert_eq!(
            backend.full_scan_count(),
            0,
            "an in-progress repair advances its scan cache by cheap block deltas"
        );
    }

    /// bitcoind restarting unloads a wallet this node created with
    /// `load_on_startup=false`. The cached handle would then name a wallet Core no
    /// longer has, so every wallet call fails — and without dropping it, the node stays
    /// on the fallback until the NODE restarts. `scripted_rpc` asserts the exact method
    /// sequence, so the `loadwallet` scripted for pass 3 IS the assertion.
    #[test]
    fn a_failed_wallet_read_drops_the_handle_so_the_next_pass_reloads_it() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let tip = "ef".repeat(32);
        let txid = Txid::from_byte_array([0x44; 32]);
        let unspent = serde_json::json!([
            {"txid": txid.to_string(), "vout": 0, "scriptPubKey": script_hex},
        ]);
        let locate = || {
            vec![
                ("loadwallet", serde_json::json!({"name": "vaultnode"})),
                (
                    "getwalletinfo",
                    serde_json::json!({"private_keys_enabled": false}),
                ),
                (
                    "listdescriptors",
                    serde_json::json!({"descriptors": [
                        {"desc": format!("raw({script_hex})#abcdefgh")},
                        {"desc": completion_marker(31, &tip)},
                    ]}),
                ),
                ("getblockhash", serde_json::json!(tip)),
            ]
        };
        let read = |unspent: serde_json::Value| {
            vec![
                ("getbestblockhash", serde_json::json!(tip)),
                ("listunspent", unspent),
                (
                    "listsinceblock",
                    serde_json::json!({"transactions": [], "lastblock": tip}),
                ),
                ("getbestblockhash", serde_json::json!(tip)),
                ("getblockheader", serde_json::json!({"height": 31})),
                ("getblockhash", serde_json::json!(tip)),
                ("getblockhash", serde_json::json!(tip)),
            ]
        };
        // Pass 1 — locate, verify, serve.
        let mut replies = locate();
        replies.extend(read(unspent.clone()));
        // Pass 2 — bitcoind has restarted: the wallet is gone from its loaded set.
        replies.extend([
            ("getblockhash", serde_json::json!(tip)),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "listunspent",
                serde_json::json!({
                    "__error": {"code": -18, "message": "Requested wallet does not exist or is not loaded"},
                }),
            ),
            // The fallback proves the cache anchor is still active — a delta can only
            // extend a live anchor — and then finds no new block, so the cache is
            // unchanged.
            ("getblockhash", serde_json::json!(tip)),
            ("getblockcount", serde_json::json!(31)),
        ]);
        // Pass 3 — the dropped handle means this pass has no anchor to reorg-check and
        // instead re-`loadwallet`s, re-proving the marker as it verifies the wallet.
        replies.extend(locate());
        replies.extend(read(unspent));
        let (addr, server, requests) = scripted_rpc_recording(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        for pass in 1..=3 {
            backend
                .refresh_vault_unspent_cache(scripts)
                .unwrap_or_else(|e| panic!("pass {pass} must still warm the cache: {e}"));
        }
        server.join().expect("scripted RPC completed");

        let methods: Vec<String> = requests
            .lock()
            .expect("recorded requests lock")
            .iter()
            .map(|request| request["method"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(
            methods
                .iter()
                .filter(|method| *method == "loadwallet")
                .count(),
            2,
            "the failed read must be followed by a fresh loadwallet: {methods:?}"
        );
        assert!(
            !methods.iter().any(|method| method == "scantxoutset"),
            "recovering the wallet must not cost a whole-set scan: {methods:?}"
        );
        assert_eq!(
            backend
                .scan_cache
                .lock()
                .expect("scan cache lock poisoned")
                .as_ref()
                .expect("a warm cache")
                .candidates,
            HashSet::from([OutPoint::new(txid, 0)]),
            "and the vault's coin is never lost along the way"
        );
    }

    /// The wallet name is a pure function of the node owner and watched script set:
    /// restarts converge on one wallet, while sibling nodes and different vaults do
    /// not share it.
    #[test]
    fn the_wallet_name_is_derived_from_the_node_and_watched_scripts() {
        let first = ScriptBuf::from_bytes(vec![0x51]);
        let second = ScriptBuf::from_bytes(vec![0x52]);
        let owner = [1; 32];
        let name = super::vault_wallet_name(&owner, std::slice::from_ref(&first));

        assert!(name.starts_with(super::VAULT_WALLET_PREFIX), "{name}");
        assert!(
            name.strip_prefix(super::VAULT_WALLET_PREFIX)
                .is_some_and(|tail| tail.len() == 16 && tail.chars().all(|c| c.is_ascii_hexdigit())),
            "the name must be the prefix plus a fixed hex digest: {name}"
        );
        assert_eq!(
            name,
            super::vault_wallet_name(&owner, std::slice::from_ref(&first)),
            "the same node and script set must always derive the same wallet"
        );
        assert_ne!(
            name,
            super::vault_wallet_name(&[2; 32], std::slice::from_ref(&first)),
            "sibling nodes must never share a wallet"
        );
        assert_ne!(
            name,
            super::vault_wallet_name(&owner, std::slice::from_ref(&second)),
            "a different vault must never share the wallet"
        );
        // Order and duplication in the caller's list are not part of the identity.
        assert_eq!(
            super::vault_wallet_name(&owner, &[first.clone(), second.clone()]),
            super::vault_wallet_name(&owner, &[second, first.clone(), first]),
        );
    }
}
