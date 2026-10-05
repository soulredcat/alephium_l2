# Alephium EVM Development Runtime

A standalone Rust EVM development node and Rust SDK. The node executes supported EVM transactions and contract deployments, persists state and receipts, and exposes a bounded JSON-RPC interface. **Alephium settlement, a live bridge, and mainnet operation are not implemented by this package. This is development software, not a production-ready rollup.**

## Workspace

| Path | Responsibility |
| --- | --- |
| `l2/node` | Sequential EVM execution, durable storage, RPC, development helpers, offline operator commands, and integration tests. |
| `l2/sdk` | Blocking Rust client with pinned chain/genesis identity, transaction preparation, one-time submission, and receipt reconciliation. |
| `l2/node/fixtures` | Pinned third-party EVM reference data and a historical verifier compatibility fixture, with sources and licenses. |

This package contains the runtime and SDK. It does not include a transition prover, Alephium verifier service, settlement contracts, or an existing chain database. The node's transition-export commands export development execution inputs; exporting them does not generate or settle a proof.

The toolchain is pinned to Rust `1.97.1`. Core dependencies include REVM `43.0.3`, Fjall `3.1.12`, Alloy consensus/signing `2.5.0`, and Alloy primitives `1.6.0`; `Cargo.lock` pins the resolved dependency graph. First-party implementation is Rust. The enabled secp256k1 dependency includes native C code, so an appropriate native build toolchain is also required.

## Build and run

Run these PowerShell commands from the repository root. Use a free loopback port and a new directory for each separate chain. The example selects chain ID `424245` and port `19745`; it does not connect to or assume an existing deployment.

```powershell
cargo build --workspace --locked
New-Item -ItemType Directory -Force .local/devnet | Out-Null

cargo run -p alephium-l2-node --locked -- --make-genesis .local/devnet/genesis.json --chain-id 424245
cargo run -p alephium-l2-node --locked -- --chain-id 424245 --genesis .local/devnet/genesis.json --data-dir .local/devnet/data --listen 127.0.0.1:19745
```

The node runs in the foreground. Press **Ctrl+C** to stop it gracefully. To restart, repeat only the final command with the same chain ID, genesis, and data directory. Genesis creation refuses to overwrite an existing file; opening a database with a different chain/genesis/profile is rejected. Never run two processes against one data directory.

On Linux or macOS, create the directory with `mkdir -p .local/devnet`; the Cargo commands are the same. This is not a claim of production storage qualification on every platform.

From a second terminal, inspect the node you just started:

```powershell
$health = Invoke-RestMethod http://127.0.0.1:19745/health
if ($health.chain_id -ne 424245) { throw 'Unexpected chain identity' }
$health
```

The development genesis funds a deliberately public, insecure fixture signer used by the helpers and tests. A separate public fixture signer also appears in lifecycle tests. These are development identities only; do not send real assets to them. Runtime data, local genesis files, and signing/publication records are not distributed with the source.

## SDK identity and usage

The SDK accepts literal loopback HTTP endpoints and the `development/c5-v1` RPC profile. It holds no signer or private key. Applications supply canonical signed transaction bytes themselves.

Pin both the chain ID and expected genesis ID. For this local setup, the health response may establish the initial expected genesis only after you have verified that the endpoint belongs to the process you launched with your chosen genesis. Record that identity in trusted local configuration. When connecting to another endpoint, obtain its expected identity through a trusted configuration or operator handoff; do not blindly adopt that endpoint's response as its own verification.

For the owned node inspected above:

```powershell
$expectedGenesis = $health.genesis_id
cargo run -p alephium-l2-sdk --locked --example inspect -- http://127.0.0.1:19745 424245 $expectedGenesis
```

Rust applications connect with `Client::connect(endpoint, ExpectedNetwork { chain_id, genesis_id, rpc_profile })`. `PreparedTransaction::new` checks the supported envelope, chain, signature, and fee encoding. `submit_once` sends one request; `reconcile` and `wait` query the original transaction hash without rebroadcasting. An ambiguous response requires reconciliation, not automatic resubmission. A durable admission acknowledgement is distinct from a successful execution receipt.

## Runtime profile

- Cancun execution with canonical replay-protected legacy and EIP-1559/type-2 transactions, including access lists. Supported contract deployment is permissionless.
- Target block interval: **200 ms**. This is a scheduling target, not a measured latency guarantee or Alephium finality.
- Block gas limit: 30 million; logical transaction block size: 1 MiB; pending limit: 256 with one pending intent per sender.
- Fixed zero development base fee, zero beneficiary/PREVRANDAO, and recorded Unix-second block timestamps. This is not Ethereum's dynamic fee market or consensus.
- Atomic Fjall batches with `SyncAll` for genesis, admission, and committed state/receipts/head; immutable committed read views and restart reconciliation.
- Loopback-only RPC and SDK access. The node rejects non-loopback binding.

`GET /health` reports identity, head, pending count, failure state, and the unimplemented settlement status. JSON-RPC at `/` supports chain/fee queries, raw transaction admission, transaction/receipt lookup, balances/nonces, contract calls and gas estimation, code/storage reads, block lookup, and bounded log queries. Genesis-pinned `l2_*` methods support SDK identity checks. State reads use the latest committed view; pending nonce reservations are also available. Subscriptions, filter lifecycle, historical state queries, and a complete Ethereum provider interface are not implemented.

Block hashes are local commit identities, not Ethereum consensus headers or authenticated L1 settlement roots. Local durable commitment does not prove Alephium settlement. Physical power-loss qualification, independent audit, public-network security, and mainnet recovery guarantees are outside the accepted development scope.

## Smoke verification

The existing default smoke test creates an isolated temporary development node and data directory. It exercises a signed transfer, contract deployment/call/write/revert, receipt/accounting checks, and restart consistency. It does not need a retained node or contact Alephium.

Use a fresh terminal without inherited `L2_SMOKE_*` variables; clear those variables explicitly before selecting the default isolated mode:

```powershell
Get-ChildItem Env:L2_SMOKE_* | Remove-Item
cargo test -p alephium-l2-node --locked --test smoke
```

Other existing focused integration targets include `identity`, `sdk`, `wallet`, `recovery`, `lifecycle`, `transition`, `precompile_transition`, and `risc0_oracle`. Run the affected target when changing its behavior. SDK unit checks use `cargo test -p alephium-l2-sdk --locked`. Tests and public fixture vectors provide bounded evidence; they are not a full Ethereum conformance suite or a production audit.

## Fixture provenance and licenses

The Ethereum reference fixture in `l2/node/fixtures/reference` is unchanged data from [ethereum/legacytests revision `1f581b8ccdc4c63acf5f2c5c1b155c690c32a8eb`](https://github.com/ethereum/legacytests/tree/1f581b8ccdc4c63acf5f2c5c1b155c690c32a8eb). `manifest.json` pins its source and hashes; the MIT `LICENSE` is retained. The test selects one Geth-filled Cancun case and compares gas and complete post-state through the runtime's normalizer/private overlay. It does not establish full execution conformance.

The historical receipt oracle in `l2/node/fixtures/risc0-groth16` retains nine unchanged Solidity files from [RISC Zero Ethereum revision `365e7b2db4f620fa256580c27558d2623362b9ae`](https://github.com/risc0/risc0-ethereum/tree/365e7b2db4f620fa256580c27558d2623362b9ae) and [OpenZeppelin revision `acd4ff74de833399287ed6b31b4debf6b2b35527`](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/acd4ff74de833399287ed6b31b4debf6b2b35527). `sources.json` records exact source URLs, hashes, lengths, and licenses. Two Groth16 verifier files carry GPL-3.0 notices; other RISC Zero files are Apache-2.0, and OpenZeppelin SafeCast is MIT. Original notices and the separate `LICENSE-GPL-3.0`, `LICENSE-APACHE-2.0`, and `LICENSE-MIT-OPENZEPPELIN` texts are retained. These third-party licenses do not declare a license for all first-party code.

The committed `artifact.json` is required by the EVM oracle test. It contains a public historical receipt, not a proof authorizing this L2's transitions. Public signed transaction/proof vectors are fixture data; tools should not print signatures, signing material, signed envelopes, or proof payloads.

Normal builds and tests do not require Solidity compilation. Optional rebuilding uses `examples/compile_risc0_oracle.rs` with an externally supplied, hash-pinned Windows solc `0.8.30+commit.73712a01.Windows.msvc` binary (SHA-256 `ccbd3ed44d5fbd26fe039702d403421f1212d2e8752e3cbe3bfd074986911586`):

```powershell
cargo run -p alephium-l2-node --locked --example compile_risc0_oracle -- <path-to-pinned-solc.exe>
```

The rebuild verifies source/license hashes and compiler identity, then regenerates the artifact and local compiler records. Generated `compiler-input.json`, `compiler-output.json`, and `compilation.json` are omitted from this package. The local build uses via-IR, 10,000 optimizer runs, Cancun, and no metadata bytecode hash; it does not claim byte-for-byte equivalence with upstream published binaries.
