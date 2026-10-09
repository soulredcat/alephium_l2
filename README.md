**Latest auditable GPU benchmark:** [1,000 / 10,000 / 100,000 TX results and evidence](test/benchmarks/2026-10-09-gpu-tps/README.md). Local service throughput with the original logical-CPU-minus-one profile; no ZK or L1 TPS claim.

# Alephium EVM L2

**P5.2.3 offline bootstrap preparation qualified (8 October 2026).** The Rust planner reuses two pinned caller-template compilations, validates one current funding bundle and prepares four conditional unsigned transactions: three contract deployments and initialization. Independent official native-protocol decoding and persisted-byte reconciliation passed for four distinct confirmed inputs, exact fee/deposit/change accounting and three conditional contract-ID predictions; initialization creates no contract. The bootstrap ceiling is 2 ALPH fee plus 0.3 ALPH deposit; actual gas is unmeasured. This preparation performs no signing, submission or deployment. Public P5 acceptance remains open.

**P5.2.2 local funding validation qualified (8 October 2026).** The SDK now correlates confirmed creator transactions on their actual source-group-to-group-zero chain, authenticates fixed-output bytes, applies native effective lock time `max(committed lock, canonical creator timestamp)`, and accepts only the two exact native projection forms while enforcing effective maturity. Source-policy V4 commits these semantics and bounded canonical head progress; older source identities cannot silently renew an approval. One aggregate passed 496 reader/funding checks. Actual configured public-testnet reads and independent native-protocol reconciliation qualified the bounded development preparation flow; no signing, deployment or settlement is claimed. The remaining P5 public acceptance, factory-domain proofs, DA reconstruction and P6-P8 gates remain open.

Rust EVM development node, SDK, transition proof components and Ralph verifier tooling. **P4 is complete for the recorded fresh 10-transaction development proving fixture.** Public Alephium settlement, bridge and permissionless recovery, release qualification and mainnet operation remain incomplete.

[docs/HANDOFF.md](docs/HANDOFF.md) defines the accepted scope, reproduction prerequisites and remaining P5-P8 checklist. [handoff/status.json](handoff/status.json) contains curated results. This repository distributes source and public reference fixtures; current private databases, signed witnesses, receipts, proof binaries, local identities, tool installations and raw execution evidence are excluded. Source publication does not deploy or settle a chain.

## P5 local integration preparation checkpoint

The latest source adds [GET-only public-testnet observations](l2/sdk/src/alephium/read_node/mod.rs), an explicit [current fixed-output funding profile](l2/sdk/src/alephium/current_funding/mod.rs), [private publisher file handoff](l2/node/src/publisher/handoff/mod.rs) and an [offline draft planner CLI](l2/verifier-tool/src/testnet_plan_cli/mod.rs). These are locally qualified preparation interfaces. **P5.1-P5.3 remain unchecked**: two actual consecutive public-testnet batches, proofs for the deployed network/factory domain, available data and independent reconstruction are still required.

The existing exact-head snapshot API remains intact. The new current profile validates confirmed creator transactions and fixed-output provenance, then checks latest mempool-aware availability around matching head observations. It rejects mempool creators and generated outputs. Its source commitment binds the canonical HTTPS origin, chain genesis and all three independently selected confirmation thresholds. Multiple trusted-node GETs do not establish an atomic or historical UTXO snapshot, a light-client proof or real funding by themselves.

Publisher record schema 2 explicitly retains the funding model; schema-1 records fail closed rather than being reinterpreted. Retain an appropriate old binary and isolated data for recovery. `FileOutbox` contains no keys, signer or broadcast client: an export records an unavailable/ambiguous external outcome, and an imported acknowledgement cannot establish inclusion, expected effects or confirmations. Directory privacy/Windows ACLs require explicit provisioning; Windows directory-sync limitations are reported without claiming a successful durable handoff.

Earlier integration aggregates passed **233 SDK read/current-funding checks**, **71 publisher/file-handoff cases**, and **two pinned-compiler template scripts plus 29 pure planner checks**. Later SourceV4 qualification passed 496 reader/funding checks; the metadata-only head-diagnostic delta passed its 37-check affected aggregate without repeating those unchanged checks. All-target SDK/node/verifier Clippy with warnings denied and owned-process cleanup passed. Earlier observations and publisher signatures were simulated development fixtures; newer unsigned preparation separately used actual configured public-testnet reads. None of these bundles signed, deployed or settled a chain. These results are correctness evidence, not throughput measurements or physical power-loss qualification.

The offline CLI validates explicit policy/checkpoint/artifact pins, compiles two template scripts and emits a private source-only prerequisite report. Fresh compiler-derived script pins qualify syntax/mock fixtures only; independent **live** compiled-script review remains pending. It emits no final signable plan or actual deployment identities. Actual funding/deployments, two domain-bound receipts and all **30 operation scripts** (three deployments, initialization and two sets of 13 batch operations) remain required. See [manual reproduction and draft policy schema](docs/HANDOFF.md#p5-integration-preparation-and-offline-draft-reproduction).

## P5.2 publisher and detached-signing source checkpoint

The source adds a narrow Alephium v4.7.0/post-Rhone **ALPH-only full-P2PKH detached-signing profile** in [the SDK](l2/sdk/src/alephium/mod.rs), plus a [durable publisher](l2/node/src/publisher/mod.rs) backed by the existing Store. It checks canonical unsigned bytes, exact approved script/context, input ownership/funding observations, fee/deposit/change limits and compact low-S signatures over the native transaction ID. This is not a general wallet or arbitrary Alephium transaction implementation.

Publisher intents, signing/submission attempt markers and responses are durably recorded; revisions/fencing reject stale owners, recovery does not automatically repeat a callback, and reorg reconciliation invalidates affected descendants. Canonical funding and receipt/effect observations come from explicitly configured **trusted consensus sources**, not a cryptographic light-client proof. Default external signer/submitter implementations are disabled; no live wallet, key custody, broadcast or settlement client is shipped.

The first aggregate real-Store bundle passed **36 local logical cases**, including before/after durable-return gaps and reopen/recovery. It used development detached signatures and simulated canonical observations, not live L1 signing/submission or public settlement. These are repository-return fault checks around actual `SyncAll`, not physical power-loss qualification. The revised aggregate passed **47 local logical cases**, including refreshed-head recovery and late canonical inclusion after abandonment. Independent source/recovery review and all-target node/SDK Clippy with warnings denied passed; owned-process cleanup was verified. Original outcomes remain preserved.

The existing generic wallet DTO still refuses opaque L1 signed responses; the new typed `sdk::alephium` profile is a separate explicit validation path. MetaMask-compatible EVM semantics and the future external wallet scaffold remain intact. Full P5 matched-domain/public two-batch acceptance remains pending.

## P5.1 source checkpoint

The published source adds strict schema-four settlement journal decoding, independently pinned domain/profile/accepted-parent policy, contiguous ancestry checks and L1-relative timestamp validation. Native core/host aggregate checks passed. New Ralph settlement/data sources compose the unchanged staged proof child with a persistent accepted head/root, hash-keyed candidate children and immutable inline reconstruction data. Registration does not reserve or advance the head; finalization rechecks proof/data/identity/parent predicates before updating it. The guest and staged arithmetic child are unchanged.

The latest target bundle passed **21 local checks and compiled three contracts, with zero VM execution requests**. Its valid existing receipt belonged to a foreign settlement domain, so the adapter refused it before VM execution and reported `MATCHED_DOMAIN_PROOF_REQUIRED`. This is an authority-boundary result, **not a positive settlement case**. The compiled factory, staged child and data contract were 3,330 / 31,216 / 85 bytes.

This checkpoint supports **at most 3,000 inline DA bytes**, with combined contract fields required to stay **strictly below 3,072 bytes**. It is a partial transport/session implementation: no chunked large-data transport, pruning/refund/bridge activation or proven public consecutive-batch flow is claimed. P5.1-P5.3 remain unchecked. Positive qualification requires proofs bound to the intended actual network and factory; public P5 acceptance still requires **two consecutive real public-testnet batches** and independent retrieval/reconstruction. The old P4 journal cannot be edited or relabelled to supply that domain.

[Settlement interfaces and CLI templates](docs/HANDOFF.md#p51-source-checkpoint-and-settlement-cli) describe the current boundary. Local publisher qualification has progressed as described above; actual adapter operation and public acceptance remain pending. No P5.2 completion is implied.

## Accepted P4 scope

| Area | Recorded development result |
| --- | --- |
| Workload | Exactly 10 transactions across five blocks: six genesis-funded wallet transfers plus root transfer, contract deployment, write and revert. No setup funding transactions. |
| Node correctness | Actual CUDA recovery/address derivation with full CPU oracle; 10 durable ACKs/receipts, exact accounting, reopen and actual service restart. Seven initial / 16 final accounts; 295,496 executed gas; 2,326-byte final checkpoint. |
| Current guest and proof | Real Groth16 receipt, development mode disabled, exact independent native/guest/receipt journal: 30,194,287 user cycles / 68 segments. |
| Canonical target | Independent native BN254 pairing and 69 same-receipt synthetic VM cases: 47 positive executions / 22 expected rejections. Changed image/journal/proof, forged origin, payload hijack and stage-order failures rejected. |
| Target bounds | Maximum positive VM gas 1,642,428 under a 5,000,000 bound; child executable 31,216 bytes under 32,768. |
| Statement | All 30 canonical journal fields reconciled, including domains, ancestry, profile, old/new state, ordered transactions/context/receipts, empty inbox/outbox and DA commitment. |
| Cleanup | Owned fixture services, prover and verifier/compiler processes were stopped and checked after the bundle. |

**Ten is a proving-test input count, not a node/block/system limit.** The fixture used fresh genesis with 3,000,000,000 block gas, 32 MiB payload, 1,000 pending and an 8 MiB producer checkpoint ceiling. Numerical capacity settings do not establish throughput or proofability for arbitrary contracts at those maxima.

A retained 1,000-transaction execution-only preflight halted successfully at **2,878,176,684 cycles / 6,397 segments**; it has no accepted proof. Qualification of 1,000-TX+ proving and the **1M-TX/block target** remains open. That target is not a qualified capacity result or a new node setting.

The target result is read-only synthetic VM acceptance. It establishes neither live deployment, public-testnet acceptance, persistent settlement continuity, backing, independent release audit nor mainnet readiness.

## Source map and dependencies

| Path | Responsibility |
| --- | --- |
| `l2/node` | Ordered REVM execution, durable Fjall storage, bounded development RPC, sequencing, recovery/export and integration fixtures. |
| `l2/sdk` | Rust client with trusted chain/genesis pins, transaction preparation, single submission and reconciliation. |
| `l2/gpu` | CUDA driver boundary, cacheable pinned host staging, explicit recovery/Keccak device artifact and vendor provenance. |
| `l2/proof` | Separate core/guest/host workspace, official guest packaging, SDK/dependency patches, qualification sources and native DA tools. |
| `l2/verifier-tool` | Compiler integration and canonical synthetic verifier/factory harness. |
| `l2/contracts/alephium/verifier` | Ralph arithmetic, receipt verifier and staged factory sources. |

The root workspace contains node, SDK and verifier tool. The GPU crate is excluded from that workspace and used as the node's optional dependency. Run proof commands from `l2/proof`, which has its own lockfile and target configuration.

Host Rust is pinned to **1.97.1**; guest baseline is **RISC Zero r0.1.94.1**. Locks retain REVM 43.0.3, Fjall 3.1.12, Alloy consensus/signing 2.5.0 and primitives 1.6.0. RISC Zero 3.0.3, the stable legacy-syscall k256/crypto-bigint forks and source revisions are declared in [proof Cargo.toml](l2/proof/Cargo.toml).

The host/runtime interfaces are Rust. The explicit CUDA device artifact uses C++17/PTX; NVIDIA NVCC/driver, native secp256k1 C, native Groth16 components and Scala/JVM Ralph compilation are separate dependencies. The complete stack is not pure Rust.

## Build and local development

This ordinary example selects the **CPU/default development profile**, a fresh directory and an illustrative development identity:

```powershell
cargo build --workspace --locked
New-Item -ItemType Directory -Force .local/devnet | Out-Null
cargo run -p alephium-l2-node --locked -- --make-genesis .local/devnet/genesis.json --chain-id 424245
cargo run -p alephium-l2-node --locked -- --chain-id 424245 --genesis .local/devnet/genesis.json --data-dir .local/devnet/data --listen 127.0.0.1:19745 --verification-backend cpu
```

Use a free loopback port. The node runs in the foreground; Ctrl+C stops the owned process. Restart with the same genesis, identity and data. Genesis refuses overwrite; incompatible stores are refused. Execution/storage schema 2 requires fresh state and rejects schema-1 stores/backups before opening Fjall. No development-state migration is provided. Public fixture signers are insecure development identities; keep real assets separate.

CUDA builds use:

```powershell
cargo build --release -p alephium-l2-node --features cuda --locked
```

NVCC and a supported host C++ compiler are required. `CUDA_PATH`, optional `L2_CUDA_HOST_COMPILER` and numeric `L2_CUDA_ARCH` (default/minimum 75) select installed tools. A CUDA-feature node defaults to CUDA; `--verification-backend cpu` chooses the reference/fallback and `--gpu-device` chooses the device. The [handoff](docs/HANDOFF.md#reproduction-prerequisites) supplies the declared P4 capacity parameters.

Node CUDA performs secp256k1 recovery and Ethereum Keccak address derivation; authoritative REVM execution and durable `SyncAll` remain ordered. Startup failure refuses to open data; a runtime mismatch/error disables CUDA before using independently validated CPU outcomes. Health exposes selected/active/verified/failure counters. This is signature/address acceleration, not full GPU EVM execution. Node CUDA and RISC Zero CUDA proving have independent build paths.

The L2 RPC client accepts loopback development endpoints and stores no signer/key. Pin chain and genesis from trusted configuration; do not trust an unknown endpoint to select its own expected identity. `submit_once` submits once; `reconcile` and `wait` query the original hash without rebroadcast. A durable admission ACK is distinct from a successful receipt.

RPC provides bounded raw admission, receipts, balances/nonces, code/storage, calls/gas estimation, blocks/logs and fee/connection queries. Full Ethereum provider compatibility is incomplete: transaction objects omit signature fields, local commit hashes are not consensus headers, and `stateRoot` is zero. Loopback access, development fees/context and incomplete public RPC policy remain release boundaries.

## Reproducibility and remaining work

Original-host GPU fixtures contain explicit **E-drive/mount guards** and require separately supplied local inputs/tools/output roots. They are not portable or public-CI qualification. Default source CI covers CPU/native paths; it does not prove CUDA hardware execution, GPU proving, power-loss behavior or production capacity. External-input integration harnesses such as `da_package` require manually supplied fixtures and are excluded from automatic prover CI, which uses library/binary checks. Execute relevant checks as one coherent bulk bundle and stop all owned test processes afterward.

The corrected prover has **nine ordered SDK patches plus one cumulative Sppark 0.1.12 patch**, with separate patch/source/package checksums and schema-2 executable/component pins. Source/manifest matching alone is not build-lineage attestation. See [prover reproduction](docs/HANDOFF.md#patched-cuda-prover).

Native canonical DA export/reconstruction and retain-unsettled packages are present. P5.1 now also has the locally qualified settlement source checkpoint described above; matched-domain positive execution, public availability and consecutive-batch acceptance remain pending.

Preserve file-specific licenses. GPU headers/reference data retain MIT provenance; Gnark-derived arithmetic retains Apache-2.0; applicable receipt/key/factory/tooling files retain GPL-3.0-or-later notices. See [GPU provenance](l2/gpu/vendor/provenance.json) and [license](l2/gpu/vendor/LICENSE). These notices do not declare a blanket license for all first-party code.

## External wallet adapter scaffold

The SDK provides a version-1 adapter contract for a future Alephium wallet on both Alephium L1 and EVM L2, preserving standard Legacy/EIP-1559 transaction semantics for a MetaMask-compatible EVM adapter. The external wallet adapts to the repository interface; no wallet product or account connection is assumed.

See [adapter types](l2/sdk/src/wallet/types.rs), [request/response validation](l2/sdk/src/wallet/validation.rs) and the [external adapter template](l2/sdk/examples/wallet_adapter_template.rs). Keep Alephium addresses and Ethereum/EVM accounts in their distinct namespaces. Persist caller-selected request/intent/network/account/transaction context before requesting a signature; compare the returned response to that retained request, then use the existing explicit submit-once/reconcile interfaces.

The shipped template returns `Unsupported` and does not hold keys, sign, connect a wallet or broadcast. EVM signed responses are checked for canonical encoding, chain ID, signer and the exact intended Legacy/EIP-1559 transaction, including nonce, gas, recipient, value, calldata, fee fields and ordered access list. Ethereum signatures bind transaction fields and chain ID, not genesis or adapter request IDs; genesis remains a separately trusted caller/RPC pin. Adapter intent/payload Keccak domains are distinct from Alephium transaction IDs and settlement SHA-256 commitments.

The generic wallet DTO's L1 signed responses remain `UnsupportedL1Validation`; echoed opaque bytes/hashes are not spending correctness. The separate `sdk::alephium` API now validates only its explicitly approved v4.7.0 ALPH/P2PKH detached profile, with trusted funding/approval adapters. The external wallet template still returns `Unsupported`, performs no signing/broadcast and has no connected-wallet claim. EVM adapter validation and examples retain their recorded local qualification; P5 public settlement remains pending.
