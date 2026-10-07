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

## P5.1 source checkpoint and settlement CLI

This is a locally qualified **source checkpoint**, not P5 acceptance. [Native settlement policy](../l2/proof/core/src/settlement/policy.rs) checks independently pinned network/genesis/factory, L2 identity/profile, exact accepted parent/head/root, contiguous batch/end heights and overflow-safe L1-relative timestamp bounds. [Journal decoding](../l2/proof/core/src/settlement/journal.rs) enforces the existing exact thirty-field schema-four encoding and empty-message policy. Native core/host aggregate checks passed; the guest image and staged arithmetic child have not changed.

[Ralph settlement factory](../l2/contracts/alephium/settlement/settlement_factory.ral) derives the initial root with its actual contract identity, keeps the accepted head/root and creates canonical hash-keyed proof/data children. Identical proposals reuse checked children; distinct stalled proposals do not reserve the head. Finalization rechecks ancestry, policy, data identity/hash and completed child statement before the persistent update. [Immutable batch data](../l2/contracts/alephium/settlement/batch_data.ral) exposes complete inline bytes/hash/length. These are implemented source responsibilities, not a proven live lifecycle.

The latest aggregate target result consists of **18 native policy/bootstrap checks, two compiled ABI/resource checks and one foreign-domain refusal: 21 checks, zero VM execution requests**. Three contracts compiled: settlement factory 3,330 bytes, unchanged staged verifier 31,216 bytes and batch data 85 bytes. The reused real receipt was independently checked, but its journal domain did not match the fixed network-zero adapter. The harness returned `MATCHED_DOMAIN_PROOF_REQUIRED`, `canonicalSyntheticAccepted=false` and `publicTestnetAccepted=false`. Its top-level local `passed=true` must not be interpreted as positive settlement execution.

The implemented inline data bound is **3,000 bytes**; local source/layout checks require combined immutable/mutable fields **strictly below 3,072 bytes**. This does not qualify the retained larger DA fixture or arbitrary configured node capacity for L1 transport. Chunked large-data publication, pruning/refund policy, bridge messages and release operating guarantees remain outside this checkpoint. No matching-domain positive VM trajectory or two-batch public-testnet flow has passed.

The following source interfaces use a separately supplied pinned Ralph compiler, new local output directories and externally provided private inputs. `--no-run-time-limit` must be first; ordinary request failure timeouts remain separate. Compilation-only mode does not contact the node:

```bash
cargo run -p alephium-l2-verifier-tool --locked -- \
  --no-run-time-limit --mainnet-readonly --settlement-compile \
  "$pinned_ralphc_jar" "$new_compile_output"
```

The actual-receipt mode has seven positional arguments after the mode: compiler, new output, receipt directory, independently reviewed image ID, independently reviewed journal SHA-256, canonical reconstruction data file, and original parent-checkpoint SHA-256:

```bash
cargo run -p alephium-l2-verifier-tool --locked -- \
  --no-run-time-limit --mainnet-readonly --settlement-actual \
  "$pinned_ralphc_jar" "$new_target_output" "$private_receipt_directory" \
  "$reviewed_image_id" "$reviewed_journal_sha256" \
  "$canonical_da_data_file" "$reviewed_original_parent_checkpoint_sha256"
```

The last pin comes from the receipt's independently reviewed **original input parent checkpoint**, not its final output checkpoint and not a package-selected trust anchor. The data file is the exact canonical reconstruction preimage for the journal's DA commitment, not `transition.bin`. The current adapter uses a separately verified fixed network-zero loopback read-only route. A foreign-domain receipt is refused before VM calls; this command is neither public-testnet deployment nor a route for relabelling the existing P4 proof.

A positive synthetic flow needs a receipt for its actual matching factory/network. Completing public P5 requires the approved real public-testnet deployment/domain and **two new correctly scoped consecutive proofs**, reusable-session acceptance, stale-parent/replay rejection, available public data and independent matching reconstruction. Real deployment/funding/signing authority and publisher ambiguity/reorg handling are separate requirements. Reuse accepted P4/source evidence; do not mutate an old journal or synthesize proof success.

## P5.2 publisher and narrow L1 codec

**Local verification checkpoint:** the first real-Store aggregate publisher bundle passed **36 logical cases**. SDK aggregate checks also passed. The revised aggregate passed **47 logical cases** after fixing late canonical receipt reconciliation following abandonment and adding refreshed-head signature/submission coverage. Independent source/recovery review and all-target node/SDK Clippy with warnings denied passed, with complete owned-process cleanup. Public signing/deployment/submission, matching-domain positive settlement and P5 acceptance remain unestablished.

The separate [SDK Alephium API](../l2/sdk/src/alephium/mod.rs) supports the named `alephium-v4.7.0/p2pkh-alph/post-rhone/v1` profile, not arbitrary wallet-produced bytes. It uses ordinary unsigned version-0 encoding, the standard four-group context and ALPH-only full P2PKH unlocks. Every input uses the approved compressed public key; duplicate references, nonminimal compact integers, extra bytes, alternate unlock/key forms, token/additional-data outputs and unsupported scripts are rejected.

[Validation](../l2/sdk/src/alephium/validation.rs) requires exact separately approved StatefulScript bytes (or an explicitly approved script-free/zero-deposit operation), fixed network/group/head funding context and matching previous outputs. Fee, declared contract deposit, total debit and optional same-owner change must agree exactly within approved bounds. StatefulScript effects remain the trusted local approval/compiler adapter's responsibility; echoed hashes or builder metadata cannot grant spending permission. The publisher path requires a nonempty approved script.

Transaction ID uses protocol Blake2b-256 with a 256-bit output parameter. Detached signatures are exactly 64-byte low-S `r||s` over that ID as the ECDSA prehash: no Ethereum prefix, recovery byte or extra hash. A signature binds unsigned bytes; local intent, genesis, artifact and approval metadata still require independent caller/context validation.

`LocalScriptApproval` and `CanonicalFundingSource` are deliberately explicit trust interfaces. The latter must resolve unspent outputs at the pinned network/group/head and reject unavailable, spent, stale or reorged context. SDK consistency/signature checks do not prove L1 consensus or UTXO authenticity. No key custody, signer, reservation or RPC/broadcast client is built into this pure validation API.

[Publisher orchestration](../l2/node/src/publisher/service.rs) uses valid revision/fence/head-bound memory, then repositories on misses/conflicts. [Store persistence](../l2/node/src/storage/publisher.rs) commits snapshot/audit changes with `SyncAll`; recovery validates the durable transition history. [Dispatch](../l2/node/src/publisher/dispatch.rs) persists intent and at-most-one attempt marker before each external callback, validates returned detached signatures against the retained unsigned operation, and records response/ambiguity. An acknowledgement hash is not inclusion or finality.

[Canonical observations](../l2/node/src/publisher/observation.rs) require an independently configured consensus-validating source with stable head snapshots and actual script/effect extraction. Identity, ancestry, receipt block, expected effect and confirmation counts are checked. This configurable trusted-node boundary is not an installed production client, wallet receipt or cryptographic light-client verifier.

[Reconciliation](../l2/node/src/publisher/reconciliation.rs) handles stale fences, signer/submission ambiguity, confirmations and reorg/descendant invalidation. Restart does not clear attempted operations or automatically re-sign/rebroadcast. Explicit reviewed abandonment retains/quarantines reservations once signing may have occurred; a not-found response cannot prove a transaction will never land.

`ExternalSigner::enabled()` and `ExternalSubmitter::enabled()` default to false; `DisabledExternal` rejects operations. A real integration must separately supply approved detached signer, funding/canonical source and single-submission adapters. The existing generic wallet `SignedAlephium` response path remains `UnsupportedL1Validation`; it must not be silently replaced by an opaque signature echo. The narrow typed SDK profile does not claim that any wallet is currently connected or supports this interface.

The ignored coherent publisher harness requires a new original-host project-drive output and independently compiled/pinned fixture bytes. The portable [fixture source](../l2/node/tests/fixtures/publisher_signing_fixture.ral) is a minimal network assertion; it does not call production P5 contracts. No compiled private script binary is distributed. Compile it into fresh caller-owned source/artifact directories with the separately pinned compiler, using its existing interface:

```bash
java -Dfile.encoding=UTF-8 -jar "$pinned_ralphc_jar" \
  -c "$fresh_fixture_sources" -a "$fresh_fixture_artifacts" -w
```

Review the resulting StatefulScript bytes and record their SHA-256 independently. Then supply that external fixture and a fresh E-drive/checked-mount output:

```powershell
$env:L2_PUBLISHER_OUTPUT = '<new absolute owned project-drive output>'
$env:L2_PUBLISHER_SCRIPT_FILE = '<reviewed local compiled fixture script>'
$env:L2_PUBLISHER_SCRIPT_SHA256 = '<independently reviewed fixture artifact SHA-256>'
cargo test -p alephium-l2-node --locked --test publisher -- --ignored
```

This is a manual external-input interface, not an automatic CI or live-operation command. Local source qualification covers durable-return failures before/after actual Store barriers, fencing, recovery, wrong signatures/effects, ambiguity, confirmations, reorg descendants and input quarantine. It does not cover physical power loss, malicious trusted-node consensus, a live wallet/network client or real public-testnet settlement. Default external clients remain disabled.

## Fixed phase checklist

| Done | Task | Required output / current boundary |
| --- | --- | --- |
| [x] | P4.1 Actual execution | Actual state/witness and all canonical statement bindings reconciled for the 10-TX fixture; current empty-message policy and P6 message rules specified. |
| [x] | P4.2 Real proof | Current guest/program/prover and real Groth16 receipt match independent native execution under the declared development profile. |
| [x] | P4.3 Staged acceptance | Independent pairing and same-receipt canonical synthetic positive/negative target bundle passed within target bounds. |
| [ ] | P5.1 Settlement and data | Local journal/policy/Ralph source checkpoint qualified; matching-domain positive VM, consecutive canonical batches, public data/reconstruction and eligibility/retention acceptance remain pending. |
| [ ] | P5.2 Publisher lifecycle | Source implements durable attempts/fencing/recovery; first 36-case and revised 47-case real-Store bundles, independent review and warnings-denied lint passed. Live adapters and public lifecycle acceptance remain unestablished. |
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

Additional release risks include qualification of the new hash-keyed session lifecycle, public DA completeness/retention, L1-time eligibility, forced-message censorship, fee funding, typed/public RPC compatibility and platform privacy/durability. No refund/pruning/bridge or positive public settlement is accepted by the local source checkpoint. No independent release audit, general maximum-capacity guarantee or mainnet acceptance follows from these results. Preserve file-specific third-party licenses; no blanket first-party license is declared.

## Wallet adapter contract

The SDK provides a version-1 adapter contract for a future Alephium wallet on both Alephium L1 and EVM L2, preserving standard Legacy/EIP-1559 transaction semantics for a MetaMask-compatible EVM adapter. The external wallet adapts to the repository interface; no wallet product or account connection is assumed.

See [adapter types](../l2/sdk/src/wallet/types.rs), [request/response validation](../l2/sdk/src/wallet/validation.rs) and the [external adapter template](../l2/sdk/examples/wallet_adapter_template.rs). Keep Alephium addresses and Ethereum/EVM accounts in their distinct namespaces. Persist caller-selected request/intent/network/account/transaction context before requesting a signature; compare the returned response to that retained request, then use the existing explicit submit-once/reconcile interfaces.

The shipped template returns `Unsupported` and does not hold keys, sign, connect a wallet or broadcast. EVM signed responses are checked for canonical encoding, chain ID, signer and the exact intended Legacy/EIP-1559 transaction, including nonce, gas, recipient, value, calldata, fee fields and ordered access list. Ethereum signatures bind transaction fields and chain ID, not genesis or adapter request IDs; genesis remains a separately trusted caller/RPC pin. Adapter intent/payload Keccak domains are distinct from Alephium transaction IDs and settlement SHA-256 commitments.

The generic wallet DTO's L1 signed responses remain `UnsupportedL1Validation`; echoed opaque bytes/hashes are not spending correctness. The separate `sdk::alephium` API now validates only its explicitly approved v4.7.0 ALPH/P2PKH detached profile, with trusted funding/approval adapters. The external wallet template still returns `Unsupported`, performs no signing/broadcast and has no connected-wallet claim. EVM adapter validation and examples retain their recorded local qualification; P5 public settlement remains pending.
