use super::*;
use crate::setup::tests::{ceremony_through_endorse, Ceremony};
use bitcoin::hashes::{sha256, Hash};
use vault_proto::SignRequest;

/// The exact captured pre-M1 artifact and the checksum its provenance record states,
/// so a fixture edited in place fails HERE rather than quietly weakening the one test
/// whose whole point is that these bytes are historical.
const PRE_M1: &str = include_str!("../fixtures/pre-m1-manifest.json");
const PRE_M1_SHA256: &str = "1758a90253c220e579a1fd759644dc572694e9e01065beb6217135ec620e87a9";

/// A REAL sealed set: the production `assemble` → per-device endorse →
/// `finalize` path, then its `sealed/backup/` operator artifact directory.
fn sealed_set() -> (Ceremony, std::path::PathBuf) {
    let ceremony = ceremony_through_endorse(3, 2);
    ceremony.finalize().expect("finalize");
    let backup = ceremony.sealed("backup");
    (ceremony, backup)
}

fn manifest_of(backup: &Path) -> ParsedManifest {
    parse_manifest(&read(backup, "manifest.json").expect("manifest.json")).expect("parses")
}

/// The network-I/O sentinel: the fixture's OWN listeners, bound on every endpoint the
/// manifest pins and held since before the ceremony chose them, are still un-accepted
/// when `run` returns. A dialled or probed node would land on one, and nothing is bound
/// and released here, so no parallel test can race this for a port.
fn without_network_io<T>(ceremony: &Ceremony, run: impl FnOnce() -> T) -> T {
    let out = run();
    for listener in &ceremony.listeners {
        let idle =
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock);
        assert!(idle, "loading a sealed artifact set must open no socket");
    }
    out
}

/// This vault's manifest with `pointer` replaced by `literal`, or by the OTHER vault's value.
fn spliced(original: &[u8], other: &[u8], pointer: &str, literal: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(original).expect("json");
    let foreign: serde_json::Value = serde_json::from_slice(other).expect("json");
    *value.pointer_mut(pointer).expect("field") = match literal {
        "" => foreign.pointer(pointer).expect("foreign field").clone(),
        text => serde_json::from_str(text).expect("literal"),
    };
    value.to_string().into_bytes()
}

/// The refusal `what` must earn. `LiveVault` deliberately carries no `Debug`,
/// so the tests do not ask a vault-bearing type to print itself.
fn refused(artifacts: &Path, what: &str) -> String {
    match LiveVault::load_artifacts(artifacts) {
        Ok(_) => panic!("{what} must be refused"),
        Err(e) => e.to_string(),
    }
}

/// The CAPTURED pre-M1 `manifest.json` — revision 0, byte-for-byte from the ceremony
/// at 5c05a6d, provenance beside it — PARSES for cold inspection, which is the whole
/// point of a syntax-tolerant reader. Live conversion still refuses it on the REVISION,
/// and it does so in a directory holding NOTHING else with no credential path passed:
/// a refusal naming a sibling artifact would prove the version gate ran too late.
#[test]
fn the_captured_pre_m1_manifest_parses_but_fails_conversion_on_its_version_first() {
    assert_eq!(
        sha256::Hash::hash(PRE_M1.as_bytes()).to_string(),
        PRE_M1_SHA256,
        "the fixture is not the bytes its provenance record names"
    );
    let old = parse_manifest(PRE_M1).expect("a pre-M1 manifest still parses");
    assert_eq!(old.protocol_version, 0);
    assert_eq!(old.recovery_timelock, 4_224_679, "a field revision 0 had");
    assert_eq!(old.escape_bump_max_fee_pct, 0, "a field revision 1 added");
    assert!(old.network.is_empty(), "a field revision 2 added");

    let temp = crate::fed::TempDir::new("pre-m1").expect("temp dir");
    std::fs::write(temp.path.join("manifest.json"), PRE_M1).expect("write");
    let error = refused(&temp.path, "a pre-M1 manifest");
    assert!(error.contains("protocol_version 0"), "{error}");
    // Every needle here is a LATER stage's own diagnostic, so the list is only as
    // complete as those diagnostics' current wording. Child B made [`read_secret`]
    // shared and reworded its three refusals from "credential" to "secret file", which
    // is accurate — it now reads the USER scalar too — and which left the open/mode/
    // read boundary named by nothing in this list. So "secret file" joins it, and
    // "credential" stays for [`CoordinatorCredential::load_file`]'s own two.
    for later in [
        "descriptor.txt",
        "recomputed hash",
        "credential",
        "secret file",
        "older(",
    ] {
        assert!(!error.contains(later), "the version comes first: {error}");
    }

    // Nor can a malformed CURRENT field outrank that diagnostic: a version gate placed
    // after the full decode answers "invalid type: string" for this file instead.
    let mut broken: serde_json::Value = serde_json::from_str(PRE_M1).expect("json");
    broken["recovery_timelock"] = "not a number".into();
    std::fs::write(temp.path.join("manifest.json"), broken.to_string()).expect("write");
    let error = refused(&temp.path, "an old manifest with a malformed current field");
    assert!(error.contains("protocol_version 0"), "{error}");
}

/// One artifact at a time — a whole file, a JSON pointer taking another vault's value,
/// or one taking a literal: each is caught by its OWN cross-check, none reaches the
/// network, and the exact restored bytes convert again.
#[test]
fn each_independently_tampered_artifact_is_refused_before_any_network_io() {
    // A leading `/` is a JSON pointer into manifest.json and a third column splices a
    // literal, for a value two regtest vaults share; anything else is a file. Neither
    // manifest anchor copy is authenticated by the file of that name, and `/network` is
    // refused by the FLAVOUR guard — which runs before the anchor, so it proves itself.
    // `/recovery_timelock` is answered by the descriptor-derived template, which is
    // authoritative for all three consensus facts the manifest reads back.
    const TAMPERS: [(&str, &str, &str); 12] = [
        ("descriptor.txt", "vault_descriptor", ""),
        ("wallet-id.txt", "wallet-id.txt", ""),
        ("manifest-hash.txt", "manifest-hash.txt", ""),
        ("coordinator-auth.pubkey", "coordinator_auth_pubkey", ""),
        ("/nodes/0/signing_pubkey", "at that position", ""),
        ("/nodes/0/transport_endpoints", "recomputed hash", ""),
        ("/nodes/0/channel_endorsement", "does not verify", ""),
        ("/wallet_id", "manifest wallet_id", ""),
        ("/manifest_hash", "manifest manifest_hash", ""),
        ("/recovery_timelock", "under older(1) is not", "1"),
        ("/network", "test-kind (tpub)", "\"bitcoin\""),
        ("/max_msg_bytes", "recomputed hash", "999999"),
    ];
    let (ceremony, backup) = sealed_set();
    let (other, foreign) = sealed_set();
    LiveVault::load_artifacts(&backup).expect("the untampered set converts");

    for (target, needle, literal) in TAMPERS {
        let json = target.starts_with('/');
        let file = if json { "manifest.json" } else { target };
        let original = std::fs::read(backup.join(file)).expect("artifact");
        let mut swap = std::fs::read(foreign.join(file)).expect("the other vault's");
        if json {
            swap = spliced(&original, &swap, target, literal);
        }
        assert_ne!(original, swap, "{target} must change the sealed value");
        std::fs::write(backup.join(file), &swap).expect("tamper");
        // BOTH fixtures' listeners: this row swaps node 0's endpoints for the OTHER
        // vault's, so a loader that dialled only that node lands solely on ITS listeners.
        let quiet = || without_network_io(&other, || refused(&backup, target));
        let error = without_network_io(&ceremony, quiet);
        assert!(error.contains(needle), "{target}: {error}");
        std::fs::write(backup.join(file), &original).expect("restore");
        LiveVault::load_artifacts(&backup).expect("the exact restored bytes convert again");
    }
}

/// The complete set converts, and every value the vault carries is one the
/// artifacts proved — including the endpoints, in node/endpoint order.
#[test]
fn a_complete_sealed_set_converts_and_carries_only_cross_checked_values() {
    let (ceremony, backup) = sealed_set();
    let vault = without_network_io(&ceremony, || {
        LiveVault::load_artifacts(&backup).expect("converts")
    });
    let m = manifest_of(&backup);
    assert_eq!(vault.wallet_id.to_lower_hex_string(), m.wallet_id);
    assert_eq!(vault.manifest_hash.to_lower_hex_string(), m.manifest_hash);
    assert_eq!(vault.descriptor.to_string(), m.vault_descriptor);
    assert_eq!(vault.network, Network::Regtest);
    assert_eq!(vault.escape_bump_max_fee_pct, 0);
    // Type-checked and carried, NOT hash-authenticated — see the field's docs.
    assert_eq!(vault.policy_version, m.policy_version);
    // `max_msg_bytes` IS hash-authenticated — the tamper table above splices it and
    // the anchor catches it — and reaches a `usize` only through the checked
    // conversion, never an `as` that could truncate a sealed value.
    assert_eq!(vault.max_msg_bytes, m.max_msg_bytes);
    let cap = vault
        .channel_body_cap()
        .expect("the sealed cap fits this host");
    assert_eq!(u64::try_from(cap), Ok(m.max_msg_bytes));
    assert_eq!(vault.template.threshold, m.t);
    assert_eq!(vault.template.recovery_timelock, m.recovery_timelock);
    assert_eq!(vault.check_params.allowed.len(), m.hot_allowlist.len() + 1);
    let pinned = vault.coordinator_pubkey.to_string();
    assert_eq!(pinned, m.coordinator_auth_pubkey);
    let nodes = m.nodes.iter();
    let pinned: Vec<String> = nodes.flat_map(|n| n.transport_endpoints.clone()).collect();
    let loaded: Vec<String> = vault.endpoints.iter().map(SocketAddr::to_string).collect();
    assert_eq!(loaded, pinned);
}

/// The runtime artifact directory is NON-SECRET. Built from the exact finalized bytes
/// with `coordinator-auth.secret` absent it still converts; a malformed decoy of that
/// name dropped beside the artifacts changes nothing, because the loader never forms
/// that path; and the credential the operator actually selected — stored elsewhere, as
/// the ceremony's own README instructs — still pairs with the vault. Any mutation that
/// reinstates `artifacts.join("coordinator-auth.secret")` dies on one of the three.
#[test]
fn artifacts_load_without_the_secret_and_an_adjacent_decoy_is_never_opened() {
    let (ceremony, backup) = sealed_set();
    let runtime = ceremony.sealed("runtime");
    std::fs::create_dir_all(&runtime).expect("runtime dir");
    for entry in std::fs::read_dir(&backup).expect("backup") {
        let path = entry.expect("entry").path();
        let name = path.file_name().expect("name").to_owned();
        if name != "coordinator-auth.secret" {
            std::fs::copy(&path, runtime.join(name)).expect("the exact finalized bytes");
        }
    }
    assert!(!runtime.join("coordinator-auth.secret").exists());
    let vault = without_network_io(&ceremony, || {
        LiveVault::load_artifacts(&runtime).expect("the secret is not a runtime artifact")
    });

    std::fs::write(runtime.join("coordinator-auth.secret"), "not a key\n").expect("decoy");
    LiveVault::load_artifacts(&runtime).expect("a decoy beside the artifacts is never read");

    let elsewhere = crate::fed::TempDir::new("credential").expect("temp dir");
    let selected = elsewhere.path.join("coordinator-auth.secret");
    std::fs::copy(backup.join("coordinator-auth.secret"), &selected).expect("copy");
    let credential = CoordinatorCredential::load_file(&selected, &vault.coordinator_pubkey)
        .expect("the explicitly selected credential pairs with the vault");
    // The pairing is proved the only way the credential still allows: an
    // authentication that verifies against the manifest-pinned PUBLIC half.
    authenticated(&credential, &vault, "pairs");
}

/// Authenticate a request through `cred`, verify the result against the vault's
/// manifest-pinned coordinator public key, and hand the authenticated request back.
fn authenticated(cred: &CoordinatorCredential, vault: &LiveVault, psbt: &str) -> SignRequest {
    let mut request = SignRequest {
        psbt: psbt.to_string(),
        escape_psbt: "escape".to_string(),
        escape_bumps: Vec::new(),
        pin: Default::default(),
        nonce: String::new(),
        expiry: 1_752_000_000,
        policy_version: vault.policy_version,
        coord_sig: String::new(),
    };
    cred.authenticate_spend(&mut request, &vault.wallet_id)
        .expect("the credential authenticates in place");
    let signature = request.coord_sig.clone();
    assert!(
        verifies(vault, &request, &signature),
        "under the pinned key"
    );
    request
}

/// Whether `coord_sig` verifies as the coordinator's authentication of `request`'s
/// canonical bytes under the vault's manifest-pinned PUBLIC half.
fn verifies(vault: &LiveVault, request: &SignRequest, coord_sig: &str) -> bool {
    let digest = Message::from_digest(request.coord_request().auth_digest(&vault.wallet_id));
    let der = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(coord_sig).expect("hex");
    let sig = Signature::from_der(&der).expect("DER");
    let secp = Secp256k1::verification_only();
    secp.verify_ecdsa(&digest, &sig, &vault.coordinator_pubkey.inner)
        .is_ok()
}

/// The credential AUTHENTICATES and hands nothing else back: each call draws its own
/// single-use nonce and signs the canonical bytes that nonce belongs to, verifiably under
/// the manifest-pinned public half. That it returns no key, scalar, bytes or callback is a
/// property of the DECLARATION, so it is checked on the production source.
#[test]
fn the_credential_authenticates_in_place_and_hands_back_no_secret_authority() {
    let (_ceremony, backup) = sealed_set();
    let vault = LiveVault::load_artifacts(&backup).expect("converts");
    let selected = backup.join("coordinator-auth.secret");
    let credential = CoordinatorCredential::load_file(&selected, &vault.coordinator_pubkey)
        .expect("the sealed credential");

    let first = authenticated(&credential, &vault, "one");
    let second = authenticated(&credential, &vault, "one");
    assert_ne!(first.nonce, second.nonce, "each call draws a fresh nonce");
    assert_ne!(first.coord_sig, second.coord_sig, "over its own nonce");
    // BODY-bound, not merely key-bound: a fresh nonce alone would make any two
    // signatures differ, so the claim is checked the other way round — this exact
    // signature over a request whose canonical bytes moved does not verify.
    let mut tampered = first.clone();
    tampered.psbt = "two".to_string();
    let bound = !verifies(&vault, &tampered, &first.coord_sig);
    assert!(bound, "the authentication is bound to the request bytes");

    let code = production_half();
    let block = impl_block(code, "CoordinatorCredential");
    assert_eq!(
        public_signatures(block),
        [
            "pub(crate) fn load_file(path: &Path, pinned: &PublicKey) -> Result<Self, Error> {",
            "pub(crate) fn authenticate_spend(",
        ],
        "the credential's public surface moved"
    );
    // No return in the whole impl — public or not, single- or multi-line — hands out
    // key material or the guard that holds it.
    for banned in ["SecretKey", "-> Scalar", "-> Zeroizing", "-> [u8"] {
        assert!(!block.contains(banned), "the credential returns {banned}");
    }
}

/// Every way the selected credential can be wrong, each at its own boundary. The
/// symlink row is the sharpest: its TARGET is the control that loads, so the only
/// thing that can refuse the link is the no-follow open itself.
#[test]
fn the_credential_refuses_a_symlink_a_directory_a_loose_mode_and_a_foreign_key() {
    let (_ceremony, backup) = sealed_set();
    let vault = LiveVault::load_artifacts(&backup).expect("converts");
    let temp = crate::fed::TempDir::new("credential").expect("temp dir");
    let secret = std::fs::read_to_string(backup.join("coordinator-auth.secret")).expect("read");
    let write = |name: &str, body: &str, mode: u32| -> std::path::PathBuf {
        let path = temp.path.join(name);
        std::fs::write(&path, body).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
        path
    };

    let good = write("good", &secret, 0o600);
    CoordinatorCredential::load_file(&good, &vault.coordinator_pubkey).expect("the control");
    std::os::unix::fs::symlink(&good, temp.path.join("link")).expect("symlink");
    std::fs::create_dir(temp.path.join("dir")).expect("dir");
    write("group", &secret, 0o640);
    write("world", &secret, 0o604);
    write("malformed", "not a key\n", 0o600);
    write("foreign", &format!("{}\n", "11".repeat(32)), 0o600);
    for (name, needle) in [
        ("link", "cannot open"),
        ("dir", "not a regular file"),
        ("group", "mode 0640"),
        ("world", "mode 0604"),
        ("malformed", "does not parse"),
        ("foreign", "does not derive the manifest-pinned"),
    ] {
        let path = temp.path.join(name);
        let error = match CoordinatorCredential::load_file(&path, &vault.coordinator_pubkey) {
            Ok(_) => panic!("{name} must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(error.contains(needle), "{name}: {error}");
        assert!(!error.contains(secret.trim()), "{name} printed the secret");
    }
}

/// The PRODUCTION half only: scanning the whole file would let a test's own assertion
/// literals satisfy the scans below, which is how one of them once passed vacuously.
fn production_half() -> &'static str {
    let source = include_str!("../../src/sealed.rs");
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

/// The body of `impl <name> {` in `code`, up to its closing column-0 brace.
fn impl_block(code: &'static str, name: &str) -> &'static str {
    let (_, body) = code
        .split_once(&format!("impl {name} {{\n"))
        .expect("the impl block");
    body.split("\n}\n").next().expect("its end")
}

/// Every non-private function signature line in one impl block, in source order.
fn public_signatures(block: &'static str) -> Vec<&'static str> {
    block
        .lines()
        .map(str::trim)
        .filter(|line| {
            (line.starts_with("pub ") || line.starts_with("pub(")) && line.contains(" fn ")
        })
        .collect()
}

/// Whether a signature is one the guard may expose: no `SecretKey` in or out, no borrowed
/// or bare byte view, no raw-key callback, no `Deref`, and a CONSUMING byte exposure only.
fn permitted_surface(signature: &str) -> bool {
    let (params, returned) = signature.split_once("->").unwrap_or((signature, ""));
    !["SecretKey", "&[u8", "-> [u8", "Fn(", "dyn ", "Deref"]
        .iter()
        .any(|banned| signature.contains(banned))
        && (!returned.contains("Zeroizing<[u8; 32]>") || params.contains("(self)"))
}

/// Every Rust source in the workspace, sorted: the scan below must reach files this
/// crate cannot `include_str!`, and a generated per-crate `target/` is not source.
fn workspace_sources() -> Vec<std::path::PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates");
    let (mut found, mut stack) = (Vec::new(), vec![crates.to_path_buf()]);
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("a workspace directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() && path.file_name().is_some_and(|name| name != "target") {
                stack.push(path);
            } else if path.extension().is_some_and(|kind| kind == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    assert!(found.len() > 20, "the workspace scan found almost nothing");
    found
}

/// The milestone scalar guard: its complete operational surface, the shapes that surface
/// may never take, and — WORKSPACE-WIDE — that exactly one implementation anywhere owns a
/// secret under that name, at its intended private definition here. The local check alone
/// is evadable: a parallel secret-owning `Scalar` in any other normal-build file would hand
/// out everything this one refuses to, and a scan of this file alone would not notice.
#[test]
fn the_scalar_guard_is_the_sole_secret_owner_and_exposes_only_its_pinned_surface() {
    let code = production_half();
    let block = impl_block(code, "Scalar");
    assert_eq!(
        public_signatures(block),
        [
            "pub(crate) fn parse(text: &str, what: &str) -> Result<Scalar, Error> {",
            "pub(crate) fn from_bytes(raw: &Zeroizing<[u8; 32]>) -> Result<Scalar, Error> {",
            "pub(crate) fn public_key(&self) -> PublicKey {",
            "pub(crate) fn sign_ecdsa(&self, message: &Message) -> Signature {",
            "pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<[u8; 32]> {",
        ],
        "the guard's surface moved"
    );
    // The rule that judges those, exercised on BOTH answers so it cannot pass
    // vacuously: the one permitted consuming conversion is accepted, and every escape
    // the guard forbids — the key itself, a borrow of it, a non-consuming or
    // non-zeroizing byte owner, a raw-key callback — is refused by that same rule.
    assert!(permitted_surface(
        "pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<[u8; 32]> {"
    ));
    for escape in [
        "pub(crate) fn seckey(&self) -> SecretKey {",
        "pub(crate) fn key(&self) -> &SecretKey {",
        "pub(crate) fn bytes(&self) -> &[u8; 32] {",
        "pub(crate) fn raw(&self) -> [u8; 32] {",
        "pub(crate) fn peek(&self) -> Zeroizing<[u8; 32]> {",
        "pub(crate) fn with_key<R>(&self, f: impl Fn(&SecretKey) -> R) -> R {",
    ] {
        assert!(!permitted_surface(escape), "the rule admits {escape}");
    }
    for signature in public_signatures(block) {
        assert!(
            permitted_surface(signature),
            "the guard exposes {signature}"
        );
    }
    // The ONE route a plain key takes in is private, and it wipes the `Copy` value it
    // was handed; `Drop` is what makes every other exit — success, refusal, unwind —
    // erase; and no `Clone`, `Debug` or `Deref` copies or prints what it holds.
    assert!(block.contains("fn guarding(mut inbound: SecretKey) -> Scalar {"));
    assert!(block.contains("inbound.non_secure_erase();"));
    // Every raw-key mention in the block is a route INTO that guard: its own private
    // parameter, plus the two constructors that hand their parse straight to it. A
    // fourth would be a key built or held outside it.
    let named = |l: &&str| !l.trim_start().starts_with("///") && l.contains("SecretKey");
    let raw = block.lines().filter(named).count();
    let guarded = block.matches("Scalar::guarding(").count();
    assert_eq!(
        (raw, guarded),
        (3, 2),
        "a raw key outside the guarding route"
    );
    let erasing = "impl Drop for Scalar {\n    fn drop(&mut self) {\n        \
                   self.0.non_secure_erase();\n    }\n}";
    assert!(code.contains(erasing), "the guard stopped erasing on drop");
    for spelling in ["Clone for Scalar", "Debug for Scalar", "Deref for Scalar"] {
        assert!(!code.contains(spelling), "Scalar implements {spelling}");
    }
    // A DERIVE grants what those three forbid while writing no `impl` line, so the
    // declaration itself is pinned, from the fragments the ownership scan also uses.
    let (owner, secret) = (format!("struct {}", "Scalar"), format!("Secret{}", "Key"));
    let sole = format!("`Debug`.\npub(crate) {owner}({secret});\n");
    assert!(code.contains(&sole), "an attribute on the guard");

    // WORKSPACE-WIDE OWNERSHIP. The needles are assembled from fragments so this
    // test's own bytes are never one of the declarations it counts.
    let mut owners = Vec::new();
    for path in workspace_sources() {
        let text = std::fs::read_to_string(&path).expect("a workspace source");
        for (offset, _) in text.match_indices(&owner) {
            // The declaration ends at whichever comes first: the `;` of a tuple or
            // unit struct, or the `}` closing a braced one.
            let rest = &text[offset..];
            let end = rest.find(';').unwrap_or(rest.len());
            let braced = rest.find('}').unwrap_or(rest.len());
            if rest[..end.min(braced)].contains(&secret) {
                owners.push(path.clone());
            }
        }
    }
    let intended = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sealed.rs");
    assert_eq!(
        owners,
        vec![intended],
        "exactly one workspace implementation may own a secret under this name"
    );
}

/// The two halves are separate BY DECLARATION, which is a property of shape and so is
/// checked on the source: the policy half child B consumes declares no secret owner and
/// no credential FIELD, the credential owns its scalar in a zeroize-on-drop buffer, and
/// neither type derives `Debug`, so no diagnostic can print what a credential holds.
#[test]
fn the_policy_half_declares_no_secret_and_the_credential_erases_its_own() {
    let code = production_half();
    let declaration = code
        .split("pub(crate) struct LiveVault {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("the LiveVault declaration");
    for banned in ["SecretKey", "seckey", "Zeroizing", "Credential"] {
        // FIELDS only: the field docs NAME the credential type, so a scan over the
        // whole declaration would answer for the comment rather than for a field.
        let owns = declaration
            .lines()
            .filter(|line| !line.trim_start().starts_with("///"))
            .any(|line| line.contains(banned));
        assert!(!owns, "LiveVault owns {banned}");
    }
    assert!(
        code.contains("seckey: Zeroizing<[u8; 32]>"),
        "the credential's scalar must be owned by a zeroize-on-drop buffer"
    );
    // Every spelling, not one literal: a reordered derive list, an extra derive, or a
    // hand-written impl would print a `Zeroizing` scalar in full (zeroize derives it).
    for kind in ["LiveVault", "CoordinatorCredential"] {
        // `split_once`, not `split().next()`: the latter answers with the WHOLE
        // half when the name is absent, so a renamed type would pass vacuously.
        let (above, _) = code
            .split_once(&format!("struct {kind} {{"))
            .expect("the declaration");
        let attributes = above.rsplit("\n\n").next().unwrap_or("");
        let prints = attributes
            .lines()
            .any(|l| l.starts_with("#[") && l.contains("Debug"))
            || code.contains(&format!("Debug for {kind}"));
        assert!(!prints, "{kind} must not print itself");
    }
}
