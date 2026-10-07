# Alephium EVM L2

Rust EVM development node, SDK, transition proof components and Ralph verifier tooling. **P4 is complete for the recorded fresh 10-transaction development proving fixture.** Public Alephium settlement, bridge and permissionless recovery, release qualification and mainnet operation remain incomplete.

[docs/HANDOFF.md](docs/HANDOFF.md) defines the accepted scope, reproduction prerequisites and remaining P5-P8 checklist. [handoff/status.json](handoff/status.json) contains curated results. This repository distributes source and public reference fixtures; current private databases, signed witnesses, receipts, proof binaries, local identities, tool installations and raw execution evidence are excluded. Source publication does not deploy or settle a chain.

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

The SDK accepts loopback development endpoints and stores no signer/key. Pin chain and genesis from trusted configuration; do not trust an unknown endpoint to select its own expected identity. `submit_once` submits once; `reconcile` and `wait` query the original hash without rebroadcast. A durable admission ACK is distinct from a successful receipt.

RPC provides bounded raw admission, receipts, balances/nonces, code/storage, calls/gas estimation, blocks/logs and fee/connection queries. Full Ethereum provider compatibility is incomplete: transaction objects omit signature fields, local commit hashes are not consensus headers, and `stateRoot` is zero. Loopback access, development fees/context and incomplete public RPC policy remain release boundaries.

## Reproducibility and remaining work

Original-host GPU fixtures contain explicit **E-drive/mount guards** and require separately supplied local inputs/tools/output roots. They are not portable or public-CI qualification. Default source CI covers CPU/native paths; it does not prove CUDA hardware execution, GPU proving, power-loss behavior or production capacity. External-input integration harnesses such as `da_package` require manually supplied fixtures and are excluded from automatic prover CI, which uses library/binary checks. Execute relevant checks as one coherent bulk bundle and stop all owned test processes afterward.

The corrected prover has **nine ordered SDK patches plus one cumulative Sppark 0.1.12 patch**, with separate patch/source/package checksums and schema-2 executable/component pins. Source/manifest matching alone is not build-lineage attestation. See [prover reproduction](docs/HANDOFF.md#patched-cuda-prover).

Native canonical DA export/reconstruction and retain-unsettled packages are present. This is a retained local P5.1 foundation; P5 settlement/public availability and consecutive-batch acceptance remain pending.

Preserve file-specific licenses. GPU headers/reference data retain MIT provenance; Gnark-derived arithmetic retains Apache-2.0; applicable receipt/key/factory/tooling files retain GPL-3.0-or-later notices. See [GPU provenance](l2/gpu/vendor/provenance.json) and [license](l2/gpu/vendor/LICENSE). These notices do not declare a blanket license for all first-party code.
