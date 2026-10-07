# Development proof handoff

Updated 7 October 2026. **P4.1-P4.3 are complete for one fresh 10-TX development proving fixture.** Mainnet and P5-P8 acceptance remain incomplete. This document describes published source interfaces and curated recorded outcomes; private execution inputs, databases, receipts, proofs, local identities, binary installations and raw evidence are not distributed.

## Acceptance boundary

The ten transactions consist of six genesis-funded wallet transfers and root transfer/deploy/write/revert, with no setup funding transactions. Actual CUDA recovery/address derivation retained the full CPU oracle; ordered REVM, exact integer accounting, durable ACK/receipts, reopen and service restart passed. The five-block fixture has seven initial/16 final accounts, 295,496 executed gas and a 2,326-byte final checkpoint.

The current guest produced a real Groth16 receipt with development mode disabled: **30,194,287 user cycles / 68 segments**, matching the independently derived native journal. Independent native BN254 pairing and **69 same-receipt canonical synthetic target cases** passed, with 47 successes/22 expected rejections. Maximum positive VM gas was 1,642,428; child code was 31,216 bytes. All 30 canonical journal fields and source/P6 message rules were reconciled.

These are development proof and synthetic VM results. Public settlement, persistent canonical continuity, available public data, backing/exits, independent release audit and mainnet are not accepted. Ten is a test input count, not a capacity limit. The retained 1,000-TX Halted(0) execution at 2,878,176,684 cycles/6,397 segments is not proven; 1,000-TX+ proving and the 1M-TX/block target remain unqualified.

## Statement, messages and time

The canonical statement is defined in [batch_journal.rs](../l2/proof/core/src/batch_journal.rs), with schema-four execution in [large_checkpoint.rs](../l2/proof/core/src/large_checkpoint.rs). It binds version/scope/RPC/engine, explicit L1 domain, L2 chain/genesis, execution profile, batch/parent/new head, old/new state, counts/balance digests, ordered transactions/context/receipts, inbox/outbox and DA. The proof image authenticates the program; consumers independently pin the intended image/domain/genesis/profile and accepted old root/parent.

Schema-four roots bind the exact capacity-derived limits and complete canonical checkpoint. The DA commitment covers domain/profile/limits, parent checkpoint, ordered contexts and raw inputs. A transition-file hash or output checkpoint hash cannot replace this reconstruction commitment.

Current inbox/outbox counts are zero. Their empty commitments include message kind, L1 domain and L2 genesis; arbitrary host-supplied nonempty roots/events cannot authorize credit or withdrawal. P6 must implement and repin runtime/guest/settlement together:

- Deposits bind canonical escrow/event identity, both domains, asset/exact amount, recipient and ordered inbox position; confirmed credit and consumption occur once.
- Withdrawals arise from authorized execution, debit/burn liability once and bind destination, asset, amount, sequence and complete domain.
- L1 release uses eligible proved outbox and atomic domain-bound nullifiers, with backing separate from fees and orphan handling.
- Forced inputs preserve execution/ordering/replay semantics without privileged cooperation; enforced inclusion/recovery and custody parameters remain P6/P7 work.

Producer timestamps are Unix seconds clamped to the preceding timestamp. Replay requires exact parent/next height, nondecreasing timestamp and matching gas profile; timestamp/number/gas are committed. This does not authenticate L1 time. **A3** remains open for P6 forced-input execution or guest-validated rejection; local unproven discards cannot satisfy it. **A6** remains open for P5.1 L1-relative timestamp eligibility with a declared drift. P4 binding/specification does not resolve those later enforcement requirements.

## Reproduction prerequisites

Root Rust is 1.97.1; guest baseline is RISC Zero r0.1.94.1, RISC Zero SDK 3.0.3 at revision `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`, with official v1compat kernel packaging. [Proof Cargo.toml](../l2/proof/Cargo.toml) pins stable legacy-syscall k256/crypto-bigint forks. NVCC/NVIDIA driver, host C++ compiler, native secp256k1 C, local Groth16 components and Java/official Ralph v4.7.0 compiler are external dependencies.

The recorded node capacity was **3,000,000,000 gas / 33,554,432 payload bytes / 1,000 pending**, with explicit `--max-checkpoint-bytes 8388608`. Its schema-four limits are 16,777,216 checkpoint bytes, 35,115,008 transcript bytes, 52,940,800 input bytes and 8,388,608-byte frames. The producer allowance and checkpoint transport ceiling are distinct. Profile/genesis changes require fresh state; schema-1 stores/backups are not migrated.

Original-host fixtures enforce project E-drive/mount and ownership guards. Provide fresh absolute local output roots, supported CUDA hardware and installed pinned tools yourself; no private original input is included. Inspect [storage guards](../l2/node/tests/support/p4_development_storage.rs). Platform portability, private ACLs/directory synchronization and physical-power-loss durability require their own qualification. CPU/native CI does not accept GPU/proving/maximum-capacity behavior. External-input harnesses, including `da_package`, are manual integration targets excluded from automatic prover library/binary CI checks.

For a fresh matching GPU fixture, the existing ignored aggregate target is:

```powershell
$env:L2_P4_DEVELOPMENT_OUTPUT = '<new absolute owned project-drive output>'
cargo test --release -p alephium-l2-node --features cuda --locked --test p4_closure -- --ignored
```

The output root must be new and its parent must exist. The source harness persists unsigned intent before signing, uses development-only identities, starts no HTTP listener, stops/joins owned services and exports a private backup/witness. This command is an interface template, not a claim that a public runner reproduced the recorded receipt. Supply local inputs explicitly for native/proof stages; do not upload or print signed envelopes, signing material or proof payloads.

Build/package the guest from `l2/proof`:

```bash
cargo +"${RISC0_RUST_TOOLCHAIN:?set reviewed guest toolchain}" build \
  --locked --release -p alephium-l2-transition-guest --target riscv32im-risc0-zkvm-elf
cargo run -p alephium-l2-transition-prover --locked --example package_guest -- \
  --user-elf "$built_guest_elf" --output "$new_guest_package"
```

Raw ELF alone is not the packaged program. Review the generated image/program and derive the native expected journal independently from your fresh fixture; retain approved pins in trusted local configuration. A receipt or downloaded manifest cannot select its own trusted image/domain/parent.

## Patched CUDA prover

The source authority is [SDK patches.rs](../l2/proof/host/src/backend/patches.rs), in this exact order:

1. `risc0-3.0.3-sppark-init.patch`
2. `risc0-3.0.3-private-prove-error-chain.patch`
3. `risc0-3.0.3-combos-prepare-sync.patch`
4. `risc0-3.0.3-private-division-diagnostic.patch`
5. `risc0-3.0.3-zeroize-kernels.patch`
6. `risc0-3.0.3-zeroize-declarations.patch`
7. `risc0-3.0.3-zeroize-ffi.patch`
8. `risc0-3.0.3-production-private-division.patch`
9. `risc0-3.0.3-safe-proof-progress.patch`

Use an owned pristine SDK checkout. Verify each patch file and before/after source SHA-256 against the authority; check then apply with `git -C "$sdk_checkout" apply --check "$patch_path"` followed by the same command without `--check`. Order matters: zeroize-ffi starts from combos-prepare-sync, and production division starts from the diagnostic source.

The separate [dependency authority](../l2/proof/host/src/backend/dependency_patches.rs) requires the single cumulative `sppark-0.1.12-division-reader-completion.patch`. Verify pristine package checksum and exact header before/after hashes. Apply only that original-to-cumulative patch to an owned dependency source; ensure the SDK build resolves it. Do not apply the historical block-only patch as well or modify shared caches. Four block barriers and loop-end cooperative grid completion protect shared/global scratch reader epochs.

The production division patch removes diagnostic CPU copies/readbacks while retaining GPU zero-remainder checks, synchronization fixes and receipt integrity. This is separate from the **node's full CPU oracle**, which remains enabled. Do not describe historical diagnostic-prover results as the current production profile.

Rebuild the owned native `risc0-sys` package after native changes, then relink the selected CUDA-only/no-default-feature `r0vm`. Preserve compiler/toolkit/profile/lock consistency; inspect actual rebuilt native code and run only the affected coherent qualification bundle. Source declarations and Cargo fingerprints are not reproducible-build attestation. Never qualify skipped kernels, development/fake receipts or disabled assertions.

[backend.rs](../l2/proof/host/src/backend.rs) requires a locally reviewed **schema-2 build manifest**: SDK version/revision, exact nine SDK declarations, one dependency declaration, executable SHA-256, backend CUDA, `cargo_features=["cuda"]`, default features false, circuit debug false, and local `Risc0Groth16` 0.1.0 directory/file pins. Required component files are `preprocessed_coeffs.bin`, `fuzzed_msm_results.bin`, `stark_verify_final.zkey` and `stark_verify_graph.bin`. Compute/review your own executable/component/manifest hashes locally; a matching manifest does not prove native build lineage. Do not distribute manifests containing installation paths or private execution evidence.

The recorded proof profile used two workers within the detected CPU budget, segment po2 19, cycle ceiling 4,294,967,296 and an **external aggregate resident-RAM cap of 6 GiB with no swap**. The proof CLI itself does not enforce that RSS cap. Configure owned isolation/cancellation/cleanup before running; measure elapsed time without an inherited overall deadline.

Use explicit local IPC, absolute local `RISC0_SERVER_PATH`, tracing/backtraces off, and remove development mode, Bonsai/remote routing and inherited dump/profiler/work-directory overrides. Under that configured resource policy, from `l2/proof`:

```bash
RISC0_PROVER=ipc RISC0_EXECUTOR=ipc RUST_LOG=off \
RUST_BACKTRACE=0 RUST_LIB_BACKTRACE=0 \
cargo run -p alephium-l2-transition-prover --locked -- \
  --input "$private_transition" --guest "$packaged_guest" \
  --expected-image-id "$reviewed_image_id" --prover-sha256 "$reviewed_prover_sha256" \
  --prover-backend cuda --prover-build-manifest "$local_build_manifest" \
  --prover-build-manifest-sha256 "$reviewed_manifest_sha256" \
  --workers 2 --max-cycles 4294967296 --execute-only
```

For an appropriately reviewed proof job, replace `--execute-only` with `--output "$new_private_proof_directory"`. Verify the actual receipt and exact independently derived journal; do not infer success from process exit alone. The actual-target harness requires independent image/journal pins and a separately verified read-only route; it uses a fixed loopback network-0 synthetic VM path, not deployment. Offline `--staged-factory-compile` is available. Reuse one verified receipt for the aggregate rejection cases.

## Retained native DA foundation

`l2-da` exports canonical schema-four reconstruction bytes and reconstructs without a sequencer database. The transcript's SHA-256 equals the statement's DA commitment; transition-input/output-checkpoint hashes do not substitute. Capacity, identity, ancestry, framing, exact lengths and EOF are checked. Package completion/retention metadata is create-only and synchronized; missing/conflicting markers refuse reuse.

```bash
# From l2/proof:
cargo run --release --locked -p alephium-l2-transition-prover --bin l2-da -- \
  export --input "$private_transition" --output "$new_package"
cargo run --release --locked -p alephium-l2-transition-prover --bin l2-da -- \
  reconstruct --package "$package" --expected "$reviewed_candidate_json" \
  --expected-sha256 "$reviewed_candidate_json_sha256" \
  --block-gas 3000000000 --block-bytes 33554432 --max-pending 1000 \
  --output "$new_reconstruction"
```

Select the candidate journal independently from trusted genesis/profile/runtime context; the manifest cannot choose its own pins. Native package reports deliberately keep `proof_accepted=false`, `settlement_eligible=false` and `public_data_available=false`. Public retention/retrieval and canonical L1 parent eligibility remain P5/P6 work. This local foundation does not complete P5.

## Fixed phase checklist

| Done | Task | Required output / current boundary |
| --- | --- | --- |
| [x] | P4.1 Actual execution | Actual state/witness and all canonical statement bindings reconciled for the 10-TX fixture; current empty-message policy and P6 message rules specified. |
| [x] | P4.2 Real proof | Current guest/program/prover and real Groth16 receipt match independent native execution under the declared development profile. |
| [x] | P4.3 Staged acceptance | Independent pairing and same-receipt canonical synthetic positive/negative target bundle passed within target bounds. |
| [ ] | P5.1 Settlement and data | Consecutive canonical batches, bounded publication, authenticated clean reconstruction and eligibility/retention; local DA preparation is not public acceptance. |
| [ ] | P5.2 Publisher lifecycle | Durable intent before signing, single submission, ambiguity reconciliation, confirmation/reorg handling and bounded session abandonment/progress. |
| [ ] | P5.3 Public-testnet integration | Two consecutive real settled batches, stale-parent/replay rejection, independent reconstruction and bounded recovery evidence. |
| [ ] | P6.1 Custody/deposits | Authenticated confirmed domain-bound one-asset inbox, exact backing/reorg handling, credit once and matching runtime/guest messages. |
| [ ] | P6.2 Withdrawals/recovery | Eligible-root atomic nullifiers and permissionless continuation/exits for account and supported contract-held rights with forced-input enforcement. |
| [ ] | P6.3 Round trip | Approved public-testnet deposit/execution/proof/data/withdrawal, independent recovery and invalid/replayed/orphan handling. |
| [ ] | P7.1 Release profile | Reproducible fresh mainnet identity/configuration, explicit economics/confirmation parameters and matching qualified semantics. |
| [ ] | P7.2 Security/recovery | Independent exact-artifact audit/remediation, restore/failure qualification and no unresolved material release blocker. |
| [ ] | P7.3 Launch package | Separate authorities, upgrades/exits, RPC/backlog/retention/alerts/runbooks, cost/backing separation and operational bounds. |
| [ ] | P8.1 Authorized deployment | Verified mainnet release/network/authorities/funding scope and fresh approved state. |
| [ ] | P8.2 Actual mainnet flow | Canonical real proofs, independently reconstructed data and bounded real-asset flow with exact backing. |
| [ ] | P8.3 Operational handover | Observed declared operation, reconciliation/alerts/recovery readiness and usable handover. |

Additional release risks include the singleton verifier's lack of reusable/abandonment lifecycle, DA retention/availability, timestamp eligibility, forced-message censorship, fee funding, typed/public RPC compatibility and platform privacy/durability. No independent release audit, general maximum-capacity guarantee or mainnet acceptance follows from the P4 result. Preserve file-specific third-party licenses; no blanket first-party license is declared.
