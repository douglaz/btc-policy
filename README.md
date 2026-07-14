# btc-policy

Project to develop a self-hostable, Rust-based Bitcoin "soft vault": standard multisig + Miniscript descriptors, an isolated policy co-signer that inspects exact PSBTs, approval workflows, and a delayed sovereign recovery path — with a future upgrade path to CTV/CCV covenant vaults.

See [IDEA.md](IDEA.md) for the full design document (taxonomy, project survey, proposed architecture, implementation phases).

## Reference repositories

All referenced projects are shallow-cloned under `repos/`:

| Directory | Upstream | Role in the design |
|---|---|---|
| `repos/liana` | https://github.com/wizardsardine/liana | Timelocked recovery wallet; policy compiler reused by walletrs |
| `repos/specter-desktop` | https://github.com/cryptoadvance/specter-desktop | Collaborative multisig coordinator (Swan Vault) |
| `repos/libnunchuk` | https://github.com/nunchuk-io/libnunchuk | C++ multisig/Miniscript wallet library |
| `repos/gdk` | https://github.com/Blockstream/gdk | Blockstream Green wallet SDK (service-assisted multisig) |
| `repos/keep` | https://github.com/privkeyio/keep | FROST threshold signing + programmable signer policies |
| `repos/cb-mpc` | https://github.com/coinbase/cb-mpc | MPC cryptographic library |
| `repos/bdk` | https://github.com/bitcoindevkit/bdk | Rust wallet library (core of proposed stack) |
| `repos/rust-miniscript` | https://github.com/rust-bitcoin/rust-miniscript | Descriptors, policy compilation, satisfaction |
| `repos/walletrs` | https://github.com/n1rna/walletrs | Rust multisig/Miniscript wallet service (base to fork/extend) |
| `repos/sigvault-desktop` | https://github.com/n1rna/sigvault-desktop | Hardware-wallet multisig coordinator UI |
| `repos/revaultd` | https://github.com/revault/revaultd | Presigned reactive vault daemon |
| `repos/simple-ctv-vault` | https://github.com/jamesob/simple-ctv-vault | Single-hop CTV vault proof of concept |
| `repos/mccv` | https://github.com/LNHANCE-Expedition/mccv | More Complicated CTV Vaults (precomputed graph) |
| `repos/HWI` | https://github.com/bitcoin-core/HWI | Hardware Wallet Interface (signer integration) |

Clones are `--depth 1`; run `git fetch --unshallow` inside a repo if full history is needed.
