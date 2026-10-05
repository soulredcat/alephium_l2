# Continuation handoff: P4-P8

Updated 5 October 2026. **MAINNET RUNNING is incomplete; mainnet implementation and proving remain paused.** The operator authorized sequential PR review, necessary fixes and scoped tests for #2-#11. This does not authorize deployment, spending or resuming the interrupted proof. WSL and the original development instances remain untouched by this review.

Read [README](../README.md) and [portable status/pins](../handoff/status.json). Extend the existing implementation without repeating P1-P3 or replacing the runtime/proof system. Every P4-P8 item remains unchecked.

## What the evidence establishes

| Area | Accepted evidence and remaining boundary |
| --- | --- |
| P1-P3 | Original-host development transfer, deploy/call/write/revert, four receipts, exact accounting and restart consistency passed. No Alephium settlement, real funds, or current public endpoint is established. |
| C16 | Historical receipt passed synthetic staged VM and canonical factory creation/acceptance. This is neither an L2 transition proof nor live/public-testnet settlement. |
| P4 schema 2 | Four runtime blocks matched native portable-core replay, suffix chaining and mutations. Older guest compilation/kernel packaging passed. Proving was interrupted without a receipt. |
| Current witness schema 3 / execution schema 2 | CI regenerated runtime fixtures and passed portable-core batch, checkpoint/suffix/mutation and 11-case ecrecover agreement checks. Local Windows profile/replay and SDK/restart tests passed. Guest compilation/execution and an actual proof remain unverified. |

Continuation transport permits **8 MiB checkpoint input within a 16 MiB binary witness**, with bounded batches, storage epochs and rolling BLOCKHASH history. Producer admission budgets, state-growth/recovery headroom and release operating limits remain unqualified.

The historical schema-2 image beginning `16b7cbb0` is not the current guest identity. Rebuild, package, review and repin schema 3; historical compilation does not validate changed shared code.

The runtime's **execution/storage schema 2** removes phantom account tombstones and requires a fresh development chain. This version is distinct from transition witness schemas 1/2/3 and is bound into genesis, local commits, and proof profiles. Old execution-schema-1 stores/backups are refused before opening Fjall; keep their original binaries/data intact, including the P1-P3 baseline. Never relabel their ownership markers. Regenerate transition fixtures for the new profile and rebuild/repin the guest; previous genesis IDs, replay evidence and guest pins do not validate this profile.

## Source map and toolchains

| Component | Existing implementation / pin |
| --- | --- |
| Runtime and SDK | `l2/node`, `l2/sdk`; root Rust 1.97.1 and locked REVM 43.0.3/Fjall 3.1.12/Alloy dependencies. |
| Export and encoding | Node `operator/transition*`, `protocol/checkpoint*`, `protocol/{encoding,head_codec,receipt_codec}`. |
| Proof | Independent workspace `l2/proof/{core,guest,host}` with its own lockfile and `.cargo/config.toml`; core reuses node source through explicit path modules. |
| Guest/prover | RISC Zero 3.0.3 at revision `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`; guest Rust baseline 1.94.1; official v1compat kernel packaging. See status metadata for historical artifact pins, not current acceptance. |
| Target verification | `l2/verifier-tool`, `l2/contracts/alephium/verifier`; Java and caller-supplied official Ralph compiler v4.7.0, SHA-256 `a8b221ee71b36a1a960da17b0eb32a490ebf8c4a034414a46d0ed57957e832ac`. |

Required source/reference fixtures are under `l2/`. Private witnesses, databases, signing records, receipts and tool binaries/toolchains are excluded. Recreate fixtures after resumption. Preserve licenses: receipt/key compositions and some tooling are GPL-3.0-or-later; Gnark-derived arithmetic retains Apache-2.0.

## Next concrete sequence after human resumption

1. Confirm source/pins/resources; assign one build/ports/integration coordinator and bounded independent reviewers.
2. Reuse the native agreement CI from PR #6. If shared execution changes, rebuild affected packages and regenerate fixtures to recheck binary encoding, hidden state, suffix roots, mutations and native secp256k1 versus portable k256.
3. Build, package, review and repin the current guest; historical guest artifacts do not cover execution schema 2.
4. Run bounded **execution-only preflight** with `--execute-only` in place of `--output`. It uses the pinned `ExternalProver` with shared input framing/cycle ceiling, requires `Halted(0)` and the exact native journal, writes no artifacts and needs no Docker. Ordinary `r0vm` CLI and `--receipt-kind composite` still prove. Check checkpoint/precompile and representative boundary inputs; resolve disagreement and recovery headroom before proving, without a benchmark campaign.
5. Generate a real bounded local Groth16 receipt; independently verify image/journal and exercise `--staged-actual`. Close P4 before public settlement; preserve failures and distinguish synthetic from actual network evidence.

These Bash templates require configured toolchains and explicit resumption; they do not claim current-source success. Start at repository root, use new private directories, and never print inputs:

```bash
umask 077
work="$PWD/.local/handoff-repro"
mkdir -p "$work"   # Children below must not already exist.
L2_TRANSITION_OUTPUT="$work/transition" \
  cargo test -p alephium-l2-node --locked --test transition
L2_PRECOMPILE_OUTPUT="$work/precompile" \
  cargo test -p alephium-l2-node --locked --test precompile_transition
L2_CHECKPOINT_FIXTURE="$work/transition" \
L2_CHECKPOINT_OUTPUT="$work/checkpoint" \
  cargo test -p alephium-l2-node --locked --test checkpoint_transition -- --ignored
(
  cd l2/proof
  L2_TRANSITION_INPUT="$work/transition/export/transition.json" \
    cargo test -p alephium-l2-transition-core --locked --test batch
  L2_PRECOMPILE_INPUT="$work/precompile/export/transition.json" \
    cargo test -p alephium-l2-transition-core --locked --test precompile
  L2_CHECKPOINT_INPUT_ROOT="$work/checkpoint" \
    cargo test -p alephium-l2-transition-core --locked --test checkpoint
)
```

Core tests require those variables; blanket workspace tests are insufficient. Checkpoint export consumes the four-block backup and creates genesis/height-two inputs. Keep outputs private; verify filesystem access restrictions. Historical DrvFS reported 0777 despite requested Unix modes.

Keep one consistent Cargo home/toolchain per target directory. Switching source-cache roots into a shared target caused duplicate fingerprints and shared build-script output invalidation; do not clean caches or repeat unaffected builds to work around it.

Build from `l2/proof` to apply its target configuration. Set `RISC0_RUST_TOOLCHAIN` to the reviewed guest toolchain, not the ordinary host compiler:

```bash
(
  cd l2/proof
  CARGO_TARGET_DIR="$work/guest-target" \
    cargo +"${RISC0_RUST_TOOLCHAIN:?set reviewed guest toolchain}" build \
      --locked --release -p alephium-l2-transition-guest \
      --target riscv32im-risc0-zkvm-elf
  cargo run -p alephium-l2-transition-prover --locked --example package_guest -- \
    --user-elf "$work/guest-target/riscv32im-risc0-zkvm-elf/release/alephium-l2-transition-guest" \
    --output "$work/guest-package"
)
```

The helper converts raw ELF to official kernel-packaged `ProgramBinary`. Review its manifest/image and pass execution-only preflight before continuing.

Preflight the packaged guest with the same environment restrictions as the proof command below, replacing `--output "$work/proof"` with `--execute-only`. It prints only the exit status, user cycles/segments against the ceiling and the public journal SHA-256.

For an authorized proof, supply independent reviewed `expected_image_id` and `prover_sha256` values, plus an absolute local `RISC0_SERVER_PATH`. Use only local IPC and a local Docker socket. Remove development mode, Bonsai configuration, inherited profiler/work-directory overrides, and remote Docker routing; disable tracing/backtraces. The host enforces these restrictions and an existing 268,435,456-cycle ceiling, which is not a qualified runtime SLA.

```bash
(
  cd l2/proof
  RISC0_PROVER=ipc RISC0_EXECUTOR=ipc RUST_LOG=off \
  RUST_BACKTRACE=0 RUST_LIB_BACKTRACE=0 \
    cargo run -p alephium-l2-transition-prover --locked -- \
      --input "$work/checkpoint/export/transition.bin" \
      --guest "$work/guest-package/guest.bin" \
      --expected-image-id "${expected_image_id:?review current program identity}" \
      --prover-sha256 "${prover_sha256:?review local r0vm identity}" \
      --output "$work/proof"
)
```

Verifier input is private `seal.bin`, `imageid.bin`, `journal.bin`, `journal_digest.bin`, and `report.json`. Independently pin canonical journal SHA-256; receipt-supplied identity pins are not trusted L2 identity.

**Only on the original host with its existing read-only authorization and verified endpoint**, the target template is:

```bash
cargo run -p alephium-l2-verifier-tool --locked -- \
  --mainnet-readonly --staged-actual "$ralphc_jar" "$work/target-evidence" \
  "$work/proof" "$expected_image_id" "$expected_journal_sha256"
```

The current transport hardcodes synchronized network 0 at `127.0.0.1:12973` and performs synthetic `contracts/test-contract`, with no signing/deployment. A cloud runner has no such endpoint by assumption. Do not run this command there or silently substitute networks. `--staged-factory-compile` is the available offline compilation mode. Public-testnet simulation previously returned HTTP 403; accessible public testnet and applicable live authority are still required for P5/P6.

## Fixed remaining checklist

Maintain this checklist and `handoff/status.json`; the operator requested limited documentation, so do not recreate the historical planning archive. Current schemas accept empty inbox/outbox commitments only. P6 must authenticate confirmed, domain-bound deposits and derive authorized withdrawal debits/outbox entries in both runtime and guest; host-supplied message roots never substitute for execution.

The current factory is a development singleton. A cloned verifier can initialize forged accepted state, so consumers must pin the canonical factory/template/derived child and exact statement, not merely a matching code hash. Reusable sessions and abandonment policy remain P5 work.

| Done | Task | Required output |
| --- | --- | --- |
| [ ] | P4.1 Actual execution | Authenticated state/witnesses and versioned statement binding L1/L2 identity, profile, ancestry, old/new state, inputs/context, inbox/outbox and DA; define P6 message rules. |
| [ ] | P4.2 Real proof | Pin current guest/program/prover; prove actual transfer and supported contracts, matching native/guest execution and resource/continuation bounds with unchanged security parameters. |
| [ ] | P4.3 Staged acceptance | Canonical factory accepts the actual proof; changed state/statement/proof, forged origin and invalid order fail within target limits. Historical receipt success is insufficient. |
| [ ] | P5.1 Settlement and data | Consecutive batches with canonical ancestry and authenticated independent reconstruction. Missing data blocks eligibility; retain unsettled and withdrawal/recovery data through sequencer loss. |
| [ ] | P5.2 Publisher lifecycle | Durable intent before signing, submit once, reconcile ambiguity, canonical confirmations, reorg/descendant invalidation, bounded progress/abandonment; stuck singleton sessions cannot prevent later eligible batches. |
| [ ] | P5.3 Public-testnet integration | Actually settle two consecutive real batches through reusable sessions; reject stale parents/replay; independently reconstruct matching state; check bounded restart/ambiguity/reorg behavior with honest observation labels. |
| [ ] | P6.1 Custody/deposits | One approved ALPH asset: authenticated confirmed domain-bound inbox, credit once, exact backing and reorg handling; separate escrow from fees; enforce identical runtime/guest message semantics and repin affected artifacts. |
| [ ] | P6.2 Withdrawals/recovery | Eligible-root release with atomic nullifiers; permissionless continuation/exit for accounts and supported contract-held rights; enforced forced-input deadline or proven equivalent defeating active censorship without privileged cooperation. |
| [ ] | P6.3 Round trip | Authorized public-testnet deposit/execution/proof/data/withdrawal; sequencer outage/censorship and independent recovery; invalid claims, duplicate credit/release and orphaned inputs preserve backing; revalidate changed proof/settlement semantics. |
| [ ] | P7.1 Release profile | Reproducible existing-code release, fresh mainnet identities/genesis/allocations; explicit gas/fee/asset/confirmation parameters; matching VM/guest semantics and targeted reference checks. No development-state/key migration. |
| [ ] | P7.2 Security/recovery | Independent audit of exact proof/settlement/bridge/recovery artifacts, remediation and affected retests; independent restore/failure qualification on actual OS/filesystem/storage; no unresolved critical/material release blocker. |
| [ ] | P7.3 Launch package | Separate authorities; safe upgrade/pause/rotation and exits; bounded RPC/backlogs, alerts, retention/restore/reconciliation; gas versus backing, exact rounding and proof/DA payer; declared operating window, funding caps and fail-closed financial stops. |
| [ ] | P8.1 Authorized deployment | Verify explicit mainnet deployment/funding/asset authority, network/code identities and caps; deploy approved artifacts and start the existing runtime with fresh state; preserve development/shared nodes. |
| [ ] | P8.2 Actual mainnet flow | Usable public EVM client path; actual canonically accepted mainnet proofs, independent authenticated reconstruction, authorized bounded ALPH deposit/withdrawal with exact backing and no duplicate release. |
| [ ] | P8.3 Bounded handover | Observe the declared window, settlement, alerts and reconciliation; verify recovery readiness and deliver endpoint, identities, commands, evidence and ownership. No inferred throughput claim. |

Public-testnet acceptance cannot be replaced by mainnet read-only simulation. Independent audit and real-value launch require their actual evidence and approvals; this document does not authorize purchases, signing, funding or deployment.

Final completion requires all six: **running approved mainnet runtime/contracts and usable RPC; actual canonical settlement; independently available/reconstructible data; backing plus withdrawals and permissionless recovery; qualified recovery and observed operation; approved audited release with no material blocker.** Mark complete only when each has actual evidence, then stop without expanding scope.

## Open audit findings (5 October 2026)

Internal source review plus scoped native checks; this is not the independent release audit required by P7.2. PRs #2-#10 contain the reviewed fixes and their checks. The remaining findings below require protocol work, an operator decision, target tooling or qualified execution evidence. None closes a checklist item.

| ID | Severity | Finding and evidence | Direction | Items |
| --- | --- | --- | --- | --- |
| A1 | Critical | The staged verifier is one fixed child (`CHILD_PATH`) whose `begin` is permissionless, accepts any admissible seal/image/journal and has no reset. Whoever calls `begin` first, including a front-runner, fixes its statement; a seal that fails the final pairing leaves it stuck before phase 3. `accepted(expected)` then fails permanently. | Bind each session to its expected statement before `begin` (for example a child path derived from the statement and checked by `begin`), so sessions cannot be hijacked and an abandoned one cannot block later batches. | P4.3, P5.1, P5.2 |
| A2 | Critical | The producer has no admission guard for the 8 MiB continuation checkpoint (`MAX_CONTINUATION_CHECKPOINT_BYTES`). State growth can exceed export/proof bounds and prevent settlement. Schema 2 removes phantom tombstones, and #4 adds an optional price floor; neither enforces the checkpoint bound. | Enforce the encoded checkpoint bound before commit and qualify recovery/exit headroom. Pricing alone is insufficient. | P4.1, P7.1 |
| A3 | High | A block containing a rejected intent can never be proven: the core always rebuilds `rejected: []`, and batch/checkpoint export refuse any rejected intent anywhere in replayed history. Rejection at execution is near-unreachable today, but P6 messages or admission changes can make one block block all later settlement. | Either never commit rejected intents (drop them before commit) or make rejection part of the witness that the guest re-validates. | P4.1, P6.1 |
| A4 | High | `checkpoint_batch_data` (the DA commitment preimage) includes the complete checkpoint, up to 8 MiB, for every batch; public transport, cost and retrieval at that bound are unqualified. Checkpoint export also requires zero pending intents. | Qualify one bounded DA path, including suffix/delta reconstruction from accepted data and export from a committed boundary while admission continues. | P5.1 |
| A5 | High | Worst-case guest cost is unmeasured. The guest re-encodes and hashes the full checkpoint several times and recomputes Keccak for all code against a 268,435,456-cycle ceiling. Native agreement passed small fixtures; current guest execution remains pending. | Use execution-only preflight (#7) on representative boundary inputs before qualifying the producer bound; lower the bound or fix the cost if it fails. | P4.2 |
| A6 | High | Block timestamps are the sequencer's clock, checked only as non-decreasing; the statement does not relate them to L1 time, and a far-future value is irreversible. | Bound `context.timestamp` against L1 time at settlement (or in the statement) with a declared drift. | P4.1, P5.1 |
| A7 | Medium | Fees are credited to the zero address (beneficiary zero), so fee revenue cannot pay proof/DA costs. | Choose a fee recipient and accounting in runtime and guest together; repin. | P7.3 |
| A8 | Medium | Transaction objects omit `v/r/s/yParity` by policy, so typed clients cannot read transactions or full blocks (Alloy/Foundry `get_transaction_by_hash`, ethers `getTransaction`). The DA payload publishes the signed envelopes anyway. | Operator decision on exposing signatures for a public RPC. | P8.2 |
| A9 | Medium | Every node start validates all retained commits and reconstructs expected records in memory (`storage/recovery.rs`); this is not EVM re-execution. Offline EVM replay and transition export are limited to 10,000 blocks. | Qualify bounded startup/recovery from authenticated checkpoints; retain full replay as an operator command. | P7.2 |
| A10 | Medium | Runtime and SDK are development-bound: loopback-only access, development profile/health handshake, and one pending intent per sender with 256 total. The RPC server has no explicit request deadline or rate limit; the SDK already bounds connect/request/wait time. | Define the release profile and public RPC front (TLS, server deadlines, rate limits) and the mempool policy explicitly. | P7.1, P7.3 |
| A11 | Low | Fail-stop classification depends on error message prefixes (`is_infrastructure_error`, `Storage read failed`). | Typed infrastructure errors. | P7.2 |
| A12 | Release | No license is declared for first-party code; existing third-party license obligations still apply. | Operator choice before licensing the code for external reuse. | P7.3 |

## Operating rules

- Make implementation changes on a topic branch and open a PR; do not push work directly to `main`. Include scope, exact checks/results, unresolved risks and affected phase items. The implementation AI owns implementation; the designated reviewing assistant tests/reviews and merges to `main` only after relevant checks pass and material findings are resolved, which closes the PR. Failed PRs remain open with actionable findings. Implementation agents do not self-approve. A source-handoff merge does not accept unfinished P4-P8 features or authorize live deployment.
- Preserve the existing sequential runtime, worker, committed views, exact accounting, validation and Fjall `SyncAll`. Extend existing Rust code; no replacement runtime, speculative dependency migration, cluster, optional features, or speed/load/soak benchmarks.
- Keep authored source at most 400 physical lines with cohesive modules. Business logic belongs in services/usecases; raw database access belongs in stores/repositories. Check valid version-bound memory first, then storage, and refresh memory. No Prisma or first-party TypeScript/Go.
- Use bounded independent sub-agents with explicit file ownership and one build coordinator. Build affected packages; reuse existing harnesses and retest failures/affected risks only. Record concise evidence, not repeated suites or reports per file.
- Original-host ports `19745` and `19545` identify preserved L2 development instances; `12973` is the shared Alephium bot RPC. These are not remote/cloud endpoints. Never stop, restart, reconfigure or synchronize the shared node; never create a local Alephium testnet. Public Alephium testnet uses public nodes only.
- Use fresh isolated development assets/data for fixtures and separate mainnet genesis/state/authorities. Never print keys, secrets, signatures or signed/proof payloads. Persist intent before signing, submit once, and reconcile ambiguity without automatic rebroadcast. Keep sequencer, publisher, bridge and treasury authorities separate.
