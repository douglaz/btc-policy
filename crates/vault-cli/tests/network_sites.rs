//! The driver address-site audit (bead btc-policy-sealed-network-v2-mn6 A7).
//!
//! This is the SOURCE half: it counts, per file, how many vault-address renders follow
//! the sealed `NodeParams.network` and how many stay explicitly `Network::Regtest`, and
//! it is what catches a NEW literal site added later, which no behavioural test can see.
//! The BEHAVIOUR half — that the renderer really does distinguish the three networks,
//! against frozen full addresses and an independent Bitcoin Core oracle — lives in
//! `crates/vault-node/tests/bitcoind_backend.rs`. Neither half is evidence alone.

/// `(file, source, ceremony-backed sites, deliberate explicit-Regtest sites)`.
///
/// The seven ceremony-backed sites render an address for a vault whose descriptor a
/// ceremony froze and whose network a manifest sealed. The two explicit ones do not:
/// `recovery.rs` builds its own throwaway descriptor and runs no ceremony, and
/// `attack.rs`'s detector control pays a throwaway script on a private chain. Binding
/// either to a sealed network would claim a relation it does not have, so they stay
/// literal — WITH a comment saying so, which the last column asserts.
const SITES: [(&str, &str, usize, usize); 4] = [
    ("demo.rs", include_str!("../src/demo.rs"), 2, 0),
    ("signet.rs", include_str!("../src/signet.rs"), 2, 0),
    ("attack.rs", include_str!("../src/attack.rs"), 3, 1),
    ("recovery.rs", include_str!("../src/recovery.rs"), 0, 1),
];

#[test]
fn exactly_the_seven_ceremony_backed_address_sites_follow_the_sealed_network() {
    let mut threaded = 0;
    let mut explicit = 0;
    for (file, source, expected_threaded, expected_explicit) in SITES {
        // The two spellings that render a vault address today; a THIRD constructor would
        // count in neither total. So the assertion below also reads the sealed network
        // POSITIVELY: from the render TOTAL alone a site taking a locally-bound `Network`
        // — `let n = Network::Regtest; d.address(n)` — would pass while hardcoding a chain.
        let renders =
            source.matches(".address(").count() + source.matches("Address::from_script(").count();
        let literal = source.matches("Network::Regtest)").count()
            + source.matches("Network::Signet)").count()
            + source.matches("Network::Bitcoin)").count();
        assert_eq!(
            (renders, source.matches(".network)").count()),
            (expected_threaded + expected_explicit, expected_threaded),
            "{file}: address sites following the sealed network, both ways"
        );
        assert_eq!(
            literal, expected_explicit,
            "{file}: address sites that stay explicitly literal"
        );
        // A literal site without a comment saying WHY is indistinguishable from one
        // that was simply missed, which is the failure this audit exists to prevent.
        assert_eq!(
            source.matches("EXPLICIT Regtest, deliberately NOT").count(),
            expected_explicit,
            "{file}: each deliberate literal must say it is deliberate"
        );
        threaded += expected_threaded;
        explicit += expected_explicit;
    }
    assert_eq!(threaded, 7, "the bead's seven ceremony-backed sites");
    assert_eq!(explicit, 2, "and its two named private-Regtest sites");
}
