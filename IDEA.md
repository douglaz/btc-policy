# Bitcoin Vaults, MPC, Multisig and Programmable Signing Policies

Status: July 12, 2026

## Executive summary

Bitcoin custody systems discussed here fall into four broad categories:

1. Recovery wallets, such as Liana, which add timelocked recovery or inheritance paths.
2. Collaborative multisig systems, such as Swan Vault, Nunchuk and SigVault, which distribute keys among users, devices or services.
3. Programmable signing systems, such as Keep, Blockstream Green and a custom policy co-signer, which inspect a transaction before contributing a signature.
4. Reactive covenant vaults, such as proposed CTV or CCV vaults, which constrain the future movement of coins at the Bitcoin consensus level.

The central distinction is:

«Multisig, MPC and signing policies control who may sign. Covenants control what transactions may exist even after the signing keys are compromised.»

For a system deployable under current Bitcoin consensus rules, the most promising open-source Rust architecture is:

```
walletrs + BDK + rust-miniscript
    +
user hardware key
    +
isolated policy co-signer
    +
delayed multisig recovery path
```

This would provide a Keep-like policy engine using standard Bitcoin multisig and Miniscript instead of FROST.

It would not fully replace a CTV or CCV vault because compromise of the complete primary signing quorum would still allow immediate theft.

---

## 1. Custody model taxonomy

### 1.1 Timelocked recovery

Example:

```
Primary key or multisig
OR
recovery multisig after 6 months
```

This protects against lost keys, inaccessible signers and inheritance problems.

It does not stop an attacker who obtains the active signing threshold.

### 1.2 Collaborative multisig

Example:

```
2-of-3:

user key A
user key B
service key C
```

This protects against compromise or loss of one key.

The service can also enforce additional rules before contributing its signature. Those additional rules are off-chain and are not visible to Bitcoin.

### 1.3 MPC or threshold signatures

Example:

```
2-of-3 FROST shares
    ↓
one BIP340 Schnorr signature
```

Bitcoin sees one public key and one signature. The threshold protocol happens outside Bitcoin.

MPC can support share refresh, hidden signer thresholds and distributed key generation, but cannot itself restrict transaction destinations.

### 1.4 Presigned reactive vault

Example:

```
Deposit
    ↓
presigned unvault
    ↓
delay
    ├── normal withdrawal
    └── cancellation or emergency
```

This is possible under current consensus rules, but requires careful handling of presigned transactions, fee management, monitoring and backups.

### 1.5 Covenant vault

Example:

```
Vault UTXO
    ↓ only a predetermined transition is valid
Unvault UTXO
    ├── delayed hot spend
    └── immediate cold recovery
```

The restriction is enforced by Bitcoin, not by a wallet server.

---

## 2. Projects

### Liana

Language: Rust
Category: Timelocked recovery and inheritance wallet
Mainnet: Yes

Liana supports a primary spending path and one or more delayed recovery paths. Either path may use singlesig or multisig. The timelocks are enforced by Bitcoin Script.

Example:

```
Primary:
    2-of-3 active keys

Recovery after 12 months:
    2-of-3 inheritance keys

Second recovery after 15 months:
    recovery service
```

Strengths

- Production-oriented GUI and daemon
- Rust implementation
- Miniscript-based descriptors
- Hardware-wallet support
- Useful for inheritance and loss recovery
- No dependency on a recovery provider for normal spending

Limitations

The primary threshold can immediately spend to any destination. If the primary quorum is compromised, the delayed recovery path cannot cancel the theft.

Liana is best understood as a recovery wallet, not a reactive theft-interception vault.

---

### Specter Desktop and Swan Vault

Category: Conventional collaborative multisig
Mainnet: Yes

Swan acquired Specter Solutions in 2022 while committing to keep Specter Desktop open source and independently usable.

Swan Vault currently uses a 2-of-3 multisig:

```
Key 1: user hardware wallet
Key 2: user hardware wallet
Key 3: Swan Cloud Key
```

Swan says transactions using the Cloud Key receive a 72-hour hold. The user can bypass Swan entirely by using both locally held hardware keys and importing the recovery information into Specter Desktop or Bitcoin Core.

Strengths

- Conventional, understandable 2-of-3 multisig
- Two user-controlled hardware keys
- Service cannot spend alone
- User can recover without the service
- Off-chain delay when the Cloud Key is used

Limitations

The 72-hour hold is not enforced by Bitcoin.

The user-controlled two-key quorum bypasses the service and its policy. If both user keys are compromised, an attacker can spend immediately.

---

### Nunchuk and libnunchuk

Languages: C++ core, Kotlin Android, Qt/QML desktop
Category: Multisig and Miniscript wallet platform
Mainnet: Yes

"libnunchuk" is a cross-platform C++ multisig wallet library built using Bitcoin Core components. It supports wallet creation, hardware signers, PSBTs and multisig coordination.

Nunchuk also contains support for creating group wallets from Miniscript templates rather than only conventional "m-of-n" descriptors.

Strengths

- Complete multisig wallet ecosystem
- Hardware-wallet integration
- PSBT coordination
- Miniscript wallet support
- Mobile and desktop clients
- Collaborative group wallet workflows

Limitations

- Core is C++, not Rust
- No general-purpose Keep-like transaction policy engine
- Hardware-wallet support for unusual Miniscript policies may vary
- Off-chain limits and allowlists require a separate policy-aware signer

Nunchuk is the closest existing full application for custom Bitcoin Script policies, but it does not match the desired all-Rust stack.

---

### Blockstream Green

Languages: C/C++ SDK, Rust components, Kotlin Android, Swift/iOS bindings
Category: Service-assisted multisig
Mainnet: Yes

Blockstream Green advertises a multisig security model with spending limits and observer or watch-only access.

Its GDK wallet core is a cross-platform C/C++ SDK with Rust dependencies and bindings for Java, Python and Swift.

Strengths

- Mature wallet implementation
- Demonstrates practical service-assisted policy signing
- Mobile and desktop support
- Recovery mechanisms if the service becomes unavailable

Limitations

- Policies are primarily built-in Green policies
- Not a general user-defined policy engine
- Production co-signing infrastructure is not presented as a simple self-hostable policy server
- Not primarily Rust

---

### Keep

Language: Primarily Rust, with Kotlin mobile and TypeScript SDK components
Category: FROST threshold signing and programmable signer policies
Mainnet: Technically capable, but experimental

Keep provides:

- BIP340 FROST threshold signing
- Distributed key generation
- Network signing over Nostr
- Bitcoin PSBT support
- Desktop, CLI, mobile and headless co-signer components
- Hardware and AWS Nitro Enclave integration

Its Bitcoin signer supports:

```
max_amount_sats
address_allowlist
address_blocklist
require_change_output
```

The signer analyzes the PSBT and applies those policies before producing a signature.

Keep's agent SDK also implements operation restrictions, expiring sessions and per-minute, hourly and daily request limits.

Strengths

- Rust implementation
- Closest open-source equivalent to an MPC policy signer
- FROST threshold keys appear as ordinary Taproot keys
- Share refresh under the same group public key
- Distributed key generation
- Programmable PSBT checks
- Headless and hardware-isolated deployments

Limitations

- Pre-1.0
- No independent third-party cryptographic audit
- Policy features are still experimental
- A policy is bypassable if another valid FROST quorum excludes policy-enforcing participants
- Dynamic signer membership is not currently supported under the same group key

Keep explicitly warns that its cryptography has only received internal review and that it should not yet secure substantial funds.

Signer refresh

Keep can refresh all shares while retaining the same public key:

```
Before:
    A1, B1, C1

After:
    A2, B2, C2

Same group public key
Same threshold
Same participants
```

The current implementation requires all shares and refuses partial refresh because absent participants would otherwise be silently removed.

It cannot currently replace:

```
A, B, C
```

with:

```
A, B, D
```

under the same group public key.

---

### Coinbase cb-mpc

Language: C++17 with C API and Go wrappers
Category: MPC cryptographic library
Mainnet: Application-dependent

Coinbase's "cb-mpc" supports distributed key generation, threshold signing, share refresh, derivation and backup primitives.

It explicitly does not provide:

- A wallet backend
- A hosted signer service
- Authentication
- Secure transport
- Key storage
- An access-control policy engine
- A decision about what transactions may be signed

Strengths

- Serious cryptographic implementation
- Derived from Coinbase's internal work
- Supports multiple threshold protocols
- Suitable as a foundation for a custom institutional system

Limitations

- Not a complete wallet or custody platform
- Significant integration work
- C++, not Rust
- Application must implement every operational and policy layer

---

### BDK and rust-miniscript

Language: Rust
Category: Wallet and Script libraries
Mainnet: Yes

"rust-miniscript" supports descriptors, abstract policy compilation, semantic analysis, witness construction and transaction satisfaction.

BDK supplies wallet functionality such as:

- Descriptor wallets
- Address derivation
- Chain synchronization
- Coin selection
- Transaction construction
- PSBT signing
- Persistence

Strengths

- Established Rust Bitcoin ecosystem
- Good foundation for custom wallet services
- Flexible descriptors and Miniscript
- No requirement to adopt a complete third-party custody application

Limitations

- Libraries, not a complete institutional policy service
- Approval workflows, audit logs and secure remote signing must be built separately
- Hardware-wallet coordination requires additional integration

---

### walletrs

Language: Rust
Category: Multisig and Miniscript wallet service
Mainnet: Technically supported, pre-1.0

"walletrs" is a standalone Bitcoin wallet service exposing gRPC and HTTP/JSON APIs. It is built using BDK, rust-miniscript and a vendored Liana policy compiler.

It supports:

- Singlesig
- Segwit "sortedmulti"
- Taproot "multi_a"
- Primary plus timelocked recovery
- Multiple recovery paths
- Unspendable primary paths
- Customer-managed xpubs
- Server-managed encrypted keys
- PSBT funding, signing, finalization and broadcasting
- Local or S3-compatible storage

Its supported descriptor shapes include:

```
wpkh(K)
tr(K)
wsh(sortedmulti(t, K1, K2, ...))
tr(NUMS, multi_a(t, K1, K2, ...))
Liana-style primary + delayed recovery
```

The "policy-core" crate represents policies with structured spending conditions:

```rust
struct SpendingCondition {
    id: String,
    is_primary: bool,
    timelock: u16,
    threshold: usize,
    policy: Single | Multi,
    managed_key_ids: Vec<String>,
}
```

Strengths

- Closest Rust multisig and Miniscript equivalent to Keep
- Reusable "policy-core" and "wallet-runtime" crates
- Full PSBT lifecycle
- HTTP and gRPC APIs
- Supports server-managed and externally managed keys
- Active testing with integration tests, property tests and fuzzing

Limitations

- Pre-1.0 and young
- Structured policy model rather than arbitrary Miniscript input
- No built-in destination allowlists or amount limits
- No approval workflow
- No immutable audit log
- No native rate limiting
- No native TLS
- A bearer token can authorize signing with server-managed keys
- Host compromise means compromise of server-managed funds

---

### SigVault Desktop

Languages: Rust/Tauri backend and React frontend
Category: Hardware-wallet multisig coordinator
Mainnet: Yes, subject to project maturity

SigVault Desktop connects hardware-wallet users through remote multisig signing sessions. It supports devices including Trezor, Ledger, BitBox02, Jade, Coldcard and Specter DIY.

Strengths

- Hardware-wallet support
- Rust backend
- Remote PSBT signing ceremonies
- Natural frontend for a "walletrs" wallet service

Limitations

- Relies on a coordination service
- Does not itself implement a general policy co-signer
- Security still depends on users verifying transactions on hardware devices

---

### Revault

Language: Rust implementations and protocol components
Category: Presigned reactive vault
Mainnet: Compatible with current consensus, but not mature as a retail product

Revault separates participants into:

- Stakeholders, who retain deep control
- Managers, who handle routine operations
- Watchtowers, which monitor and cancel unauthorized activity
- Co-signing servers, which restrict manager spending behavior

Revault supports delayed manager withdrawals, cancellation, emergency destinations and arbitrary off-chain business policies.

Its transaction graph uses presigned Emergency, Unvault, Cancel and Unvault Emergency transactions. Managers must wait for an unvault timelock before spending, allowing stakeholders or watchtowers to cancel the withdrawal.

Strengths

- Closest current-consensus design to a genuine reactive vault
- On-chain withdrawal delay
- Cancellation and emergency paths
- Organizational separation between stakeholders and managers
- Watchtower and co-signer policy enforcement

Limitations

- Interactive presigning setup
- Critical transaction backups
- Difficult fee management
- Complex monitoring infrastructure
- Pinning and denial-of-service concerns
- Reference implementations are not currently mature consumer products

Revault demonstrates the desired security model, but with substantial operational complexity.

---

## 3. Covenant proposals

### OP_CHECKTEMPLATEVERIFY

BIP: 119
Status: Draft
Category: Static transaction-template covenant

CTV commits a UTXO to a transaction template containing fields such as version, locktime, input count, sequences and outputs.

The BIP's motivation includes reducing the trust, storage and interactivity requirements of presigned transaction protocols.

Simple CTV Vault

The "simple-ctv-vault" proof of concept implements a single-hop vault:

```
Vault
    ↓ mandatory unvault transaction
Unvault
    ├── immediate cold recovery
    └── delayed hot-wallet spend
```

An attacker controlling the hot key must reveal the theft attempt by broadcasting the unvault transaction, giving the owner time to sweep to cold storage.

CTV removes the need to preserve critical presigned transactions and prove that ephemeral setup keys were destroyed.

Limitations

- Not activated on Bitcoin
- Static transaction templates
- Simple design unvaults the full value
- Limited or one-shot behavior
- Fee management is difficult
- Destinations and transaction structure may need to be predetermined

---

### More Complicated CTV Vaults

Project: MCCV
Category: Large precomputed CTV transaction graph
Mainnet: No

MCCV explores whether CTV can support:

- Repeated deposits
- Repeated withdrawals
- Recovery
- Withdrawal velocity controls
- A large or effectively unbounded number of operations

The design precomputes a large set of possible future transactions, creating practical computational limits.

Strengths

- Shows that CTV vaults can be much more capable than a simple one-shot vault
- Supports velocity-control concepts
- Retains consensus-enforced transaction restrictions

Limitations

- Large transaction graph
- Significant precomputation
- Complex backup and state representation
- Proof of concept
- Requires a CTV-enabled Bitcoin implementation

---

### OP_CHECKCONTRACTVERIFY

BIP: 443
Status: Draft
Category: Stateful covenant primitive

CCV allows Taproot UTXOs to carry commitments to data and constrain the key, taptree and amounts of future outputs. It is intended to support state machines and dynamically evolving contracts.

Compared with CTV, CCV more naturally supports:

- Reusable vaults
- Partial withdrawals
- State carried into new vault UTXOs
- Splitting and aggregating funds
- Dynamic state transitions
- Continuing the vault policy in change outputs

Strengths

- Better fit for flexible, reusable vaults
- More direct state-machine model
- Better handling of partial value transitions

Limitations

- Broader and more complex consensus change
- Not activated
- Larger review and implementation surface
- External fee inputs or anchors are generally required

---

## 4. Comparison

| Project | Mainnet now | Rust | Multisig/MPC | On-chain delay | Off-chain policies | Cancel after initiation |
|---|---|---|---|---|---|---|
| Liana | Yes | Yes | Multisig | Recovery only | No | No |
| Swan/Specter | Yes | No | 2-of-3 multisig | Cloud-key hold is off-chain | Limited | No |
| Nunchuk | Yes | No | Multisig/Miniscript | Script-dependent | Requires extension | No |
| Blockstream Green | Yes | Partial | Service multisig | Service-dependent | Built-in | No |
| Keep | Experimental | Yes | FROST | Script-dependent | Yes | No |
| cb-mpc | Library | No | MPC library | Application-dependent | Application-dependent | No |
| BDK/rust-miniscript | Library | Yes | Multisig/Miniscript | Yes | Requires application | No |
| walletrs | Pre-1.0 | Yes | Multisig/Miniscript | Yes | Requires extension | No |
| SigVault Desktop | Yes | Rust backend | Multisig coordinator | Descriptor-dependent | No | No |
| Revault | Technically | Yes | Presigned multisig | Yes | Yes | Yes |
| Simple CTV Vault | No | Prototype-dependent | Keys inside covenant | Yes | Mostly on-chain | Yes |
| MCCV | No | Yes | Covenant graph | Yes | Velocity rules | Yes |
| CCV Vault | No | Future | Keys inside state machine | Yes | Mostly on-chain | Yes |

---

## 5. Proposed design: Rust multisig and Miniscript policy vault

### 5.1 Goal

Build a self-hostable open-source system with:

- Rust implementation
- Standard Bitcoin multisig
- Miniscript and Taproot policies
- Hardware-wallet support
- Custom transaction rules
- Approval workflows
- Delayed sovereign recovery
- No proprietary MPC share format
- Compatibility with Bitcoin mainnet today

The system should resemble Keep operationally while using explicit Bitcoin multisig instead of FROST.

---

### 5.2 Recommended on-chain policy

A simple initial policy:

```
Primary path:
    user hardware key
    AND
    policy-server key

Recovery path after 90 days:
    2-of-3 offline recovery keys
```

Conceptually:

```
or(
    and(
        pk(user),
        pk(policy_server)
    ),
    and(
        older(12960),
        thresh(2, recovery_a, recovery_b, recovery_c)
    )
)
```

The exact block count depends on the intended recovery period.

Why 2-of-2 for the primary path?

A standard 2-of-3 containing a policy key does not guarantee that the policy key participates:

```
2-of-3:
    user A
    user B
    policy server
```

User A and user B can bypass the policy server.

Using a 2-of-2 primary path ensures that every normal transaction requires policy approval.

The delayed recovery path prevents the policy service from permanently freezing the funds.

---

### 5.3 Components

```
┌──────────────────────────────┐
│ User wallet / SigVault UI    │
│ Hardware-wallet integration  │
└──────────────┬───────────────┘
               │
               │ PSBT request
               ▼
┌──────────────────────────────┐
│ Wallet coordinator           │
│ walletrs + BDK               │
│                              │
│ - descriptors                │
│ - UTXOs                      │
│ - coin selection             │
│ - PSBT lifecycle             │
└──────────────┬───────────────┘
               │
               │ canonical PSBT
               ▼
┌──────────────────────────────┐
│ Policy engine                │
│                              │
│ - amount limits              │
│ - allowlists                 │
│ - fee checks                 │
│ - approval workflow          │
│ - waiting periods            │
│ - audit log                  │
└──────────────┬───────────────┘
               │ signed authorization
               ▼
┌──────────────────────────────┐
│ Isolated policy signer       │
│                              │
│ HSM / TPM / Nitro / StartOS  │
│ Holds one multisig key       │
└──────────────┬───────────────┘
               │ partial signature
               ▼
┌──────────────────────────────┐
│ User hardware signer         │
│ verifies and signs PSBT      │
└──────────────┬───────────────┘
               │
               ▼
       Finalize and broadcast
```

---

### 5.4 Wallet coordinator

Use:

- "walletrs"
- "wallet-runtime"
- BDK
- rust-miniscript
- Liana's policy compiler where appropriate

Responsibilities:

- Maintain descriptors
- Synchronize chain state
- Track UTXOs
- Construct PSBTs
- Select the intended Miniscript path
- Combine signatures
- Finalize transactions
- Broadcast transactions

Ideally, the coordinator holds no private signing key.

---

### 5.5 Policy engine

The policy engine evaluates the complete transaction before the policy key signs.

Possible policy fields:

```rust
struct SigningPolicy {
    destination_allowlist: Vec<ScriptBuf>,
    destination_blocklist: Vec<ScriptBuf>,

    max_transaction_sats: Option<u64>,
    max_daily_sats: Option<u64>,
    max_weekly_sats: Option<u64>,

    max_fee_sats: Option<u64>,
    max_fee_rate: Option<FeeRate>,

    minimum_confirmations: Option<u32>,
    require_known_change: bool,
    require_change_output: bool,

    allowed_utxos: Option<Vec<OutPoint>>,
    blocked_utxos: Vec<OutPoint>,

    approval_threshold: Option<ApprovalThreshold>,
    minimum_wait: Option<Duration>,

    allowed_hours: Option<BusinessHours>,
    freeze_all: bool,
}
```

Example policy

```yaml
destinations:
  allowlist:
    - cold_storage
    - exchange_account

limits:
  per_transaction: 10000000
  per_day: 25000000

fees:
  maximum_rate: 100 sat/vB
  maximum_absolute: 500000 sats

approvals:
  threshold: 2
  approvers:
    - allan
    - finance_manager
    - security_officer

delay:
  above_5000000_sats: 24h

change:
  require_wallet_descriptor_match: true
```

---

### 5.6 Preventing TOCTOU attacks

The policy authorization must be bound to the exact PSBT or unsigned transaction.

The policy engine should sign an authorization object containing:

```
wallet ID
descriptor ID
unsigned transaction hash
input outpoints
output scripts and amounts
fee
fee rate
selected Miniscript path
expiry
policy version
approval identities
```

The isolated signer must independently:

1. Decode the PSBT.
2. Recompute the transaction commitment.
3. Verify the policy authorization signature.
4. Confirm that the authorization has not expired.
5. Confirm that the authorization has not been used before.
6. Sign only the exact approved transaction.

The signer must not trust transaction summaries supplied by the coordinator.

---

### 5.7 Approval workflow

Transaction states:

```
PROPOSED
    ↓
POLICY_CHECKED
    ↓
WAITING_FOR_APPROVALS
    ↓
WAITING_FOR_DELAY
    ↓
AUTHORIZED
    ↓
POLICY_SIGNED
    ↓
USER_SIGNED
    ↓
FINALIZED
    ↓
BROADCAST
```

Terminal states:

```
REJECTED
CANCELLED
EXPIRED
FROZEN
```

An append-only audit log should record every transition.

---

### 5.8 Key isolation

The policy key should not live directly inside the HTTP wallet process.

Preferred options:

1. Dedicated hardware security module
2. TPM-backed local signer
3. AWS Nitro Enclave
4. Separate StartOS appliance
5. Minimal offline or semi-online signing daemon

The isolated signer should expose one narrow operation:

```
sign_psbt_if_authorized(
    psbt,
    policy_authorization
)
```

It should not expose arbitrary-message signing.

---

### 5.9 Monitoring

An independent watchtower should monitor:

- Wallet UTXOs
- Transactions entering the mempool
- Unexpected spends
- Policy-server health
- Recovery timelocks
- Descriptor changes
- Changes to allowlists and policies

For a normal multisig wallet, monitoring cannot cancel a fully signed malicious spend.

It can still:

- Alert operators
- Freeze future policy signatures
- Trigger migration to recovery wallets
- Detect compromise
- Provide forensic records

With a future CTV or CCV vault, the same watchtower could broadcast an actual cancellation or recovery transaction.

---

### 5.10 Signer changes

Standard multisig does not allow changing a key without changing the descriptor.

Replacing a signer requires:

1. Create new keys
2. Create a new descriptor
3. Verify the new descriptor on every device
4. Spend all funds to the new wallet
5. Retire the old descriptor

This is less convenient than MPC share refresh, but it is explicit and auditable on-chain.

A migration feature should generate:

- New descriptor
- Descriptor checksum
- Recovery document
- Migration PSBT
- Independent address verification instructions
- Audit event linking old and new wallet IDs

---

### 5.11 Security properties

Protects against

- Theft of only the user hardware key
- Theft of only the policy-server key
- Policy service disappearing
- User losing normal signing access
- Unauthorized destinations when the policy signer remains honest
- Excessive transaction amounts
- High or manipulated fees
- Missing organizational approvals
- Accidental signing outside defined business procedures

Does not protect against

- Simultaneous compromise of user and policy keys
- Malicious recovery quorum after its timelock expires
- Compromise of all approvers and both primary signers
- Consensus-valid replacement transactions signed by the full primary quorum
- Immediate theft after full primary-quorum compromise
- A malicious coordinator if both actual signers fail to verify the PSBT

This is therefore a soft vault, not a covenant vault.

---

## 6. Future covenant upgrade

The architecture should isolate the vault policy from the descriptor compiler so that the signing system can later support:

```
Current backend:
    Miniscript multisig

Future backend:
    CTV vault
    CCV vault
```

The policy API could remain similar:

```
propose withdrawal
approve withdrawal
wait
cancel
execute
```

Under ordinary multisig, the delay is enforced by the policy server.

Under CTV or CCV, the delay and cancellation state would be enforced by Bitcoin.

This allows the project to provide useful functionality now while remaining compatible with stronger future covenant vaults.

---

## 7. Implementation path

### Phase 1: regtest prototype

- Fork or extend "walletrs"
- Add external signer support
- Add PSBT policy checks
- Add destination allowlists
- Add per-transaction amount limits
- Add known-change validation
- Add append-only audit events
- Implement 2-of-2 primary plus delayed recovery descriptor
- Integrate SigVault Desktop or HWI
- Test exclusively on regtest

### Phase 2: signet pilot

- Multiple independent user devices
- Policy signer on a separate host
- Authenticated policy approvals
- Waiting periods
- Daily cumulative limits
- Signer authorization bound to exact PSBT hash
- Watchtower monitoring
- Failure and disaster-recovery exercises

### Phase 3: hardened deployment

- HSM, TPM or Nitro-backed policy key
- Reproducible builds
- External security review
- Immutable remote audit storage
- Formal policy state-machine tests
- Fuzzing of all PSBT and policy inputs
- Independent descriptor verification
- Mainnet pilot with limited value

### Phase 4: covenant integration

- CTV signet backend
- CCV prototype backend
- Actual unvault and cancellation states
- Watchtower-triggered recovery
- Migration from soft-vault descriptors to covenant vault outputs

---

## 8. Recommended stack

```
Language:
    Rust

Wallet:
    BDK

Script and descriptors:
    rust-miniscript

Wallet service:
    walletrs

Timelocked recovery:
    Liana policy compiler

Hardware wallet UI:
    SigVault Desktop or HWI integration

API:
    axum + tonic

Policy storage:
    PostgreSQL or SQLite for prototype

Audit:
    append-only hash-chained events
    remote replicated copy

Signer isolation:
    TPM, HSM, Nitro Enclave or StartOS appliance

Chain backend:
    Bitcoin Core + compact block filters
    or Electrum during initial development

Monitoring:
    independent Rust watchtower
```

---

## 9. Conclusion

The projects solve different parts of the problem:

- Liana provides robust timelocked recovery.
- Swan/Specter provides user-friendly collaborative multisig.
- Nunchuk provides a mature multisig and Miniscript application.
- Blockstream Green demonstrates service-assisted signing policies.
- Keep demonstrates open-source FROST and programmable signing controls.
- cb-mpc provides lower-level MPC building blocks.
- BDK and rust-miniscript provide the core Rust wallet and Script ecosystem.
- walletrs and SigVault provide the closest Rust multisig platform for the proposed system.
- Revault demonstrates a reactive vault under current consensus using presigned transactions.
- CTV and CCV would allow stronger consensus-enforced vaults in the future.

The most practical current design is:

```
2-of-2 primary:
    user hardware key
    policy-server key

Delayed recovery:
    2-of-3 independent offline keys
```

Build the wallet and descriptor layer on "walletrs", BDK and rust-miniscript. Add a separate policy engine and isolated signer that inspect and authorize exact PSBTs.

This gives a useful, self-hostable and standards-based soft vault today, while leaving a clear upgrade path to a true covenant vault later.

A shorter BitDevs-ready version would be the natural next cut.
