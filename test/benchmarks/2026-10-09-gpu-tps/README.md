# Local CUDA service benchmark — 9 October 2026

One fresh sequential aggregate: 1,000 / 10,000 / 100,000 transactions. All three passed. Auditable benchmark evidence only; no new ZK receipt, HTTP throughput, L1 settlement or production-capacity claim.

| Offered / committed | Completion seconds | Completion TPS | Receipt p99 (ms) | Original block+1 | Ledger / reopen |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1000 / 1000 | 0.247006 | 4048.49 | 246.901 | 1000 | PASS |
| 10000 / 10000 | 0.432218 | 23136.46 | 431.566 | 10000 | PASS |
| 100000 / 100000 | 5.368574 | 18626.92 | 5275.586 | 24599 | PASS |

## Method and limits

- Completion TPS = unique successful committed transaction hashes × 1,000,000,000 / monotonic nanoseconds from before the first offer through the last observed committed receipt. ACK rate is separate.
- Direct NodeHandle service calls; no HTTP server. CUDA signature recovery is real and checked against the full CPU oracle. Authoritative ordered EVM execution remains on CPU.
- Same distinct-sender/recipient native-transfer workload and capacity for all sizes; each starts in a fresh isolated database. Funding, signing, shutdown, exact accounting/reopen and CSV serialization are outside the measured interval.
- Every offered transaction durably ACKed and committed successfully. Exact receipt/accounting verification was repeated after Store reopen and state digest/head matched. Original block+1 is a reported target, not a silently changed acceptance gate.
- Single run per size in one bundle, without retries or overall time cutoff. This is a burst result, not a sustained-load percentile, universal SLA or mainnet capacity qualification.
- 16 logical CPUs; original CPU-minus-one client and node verification pools each have15 workers. This does not promise one CPU remains idle globally. Two Cargo build jobs, BelowNormal priority and4GiB aggregate Windows commit cap. The protected shared mainnet/bot node and operator wallets were not used.
- Each compressed CSV contains per-transaction hash, value, timing, inclusion, gas, fee and acceptance fields. Public copies omit sender/recipient columns; signatures/raw envelopes, databases, env and operational identities remain private. Result JSON records SHA256 for compressed/uncompressed CSV.
- Independent CSV audit checked uniqueness/count, successful receipt/durable ACK, inclusion after arrival head, receipt-after-ACK, last-receipt denominator and exact21,000-wei fee per transfer. Hashes/CSV are audit evidence, not a ZK or third-party execution attestation.
- Source closure is included because the measured Node/SDK compiled local publisher/storage additions. Unrelated verifier-tool changes, CI changes, env, live bootstrap payloads and private history are excluded. See source-manifest.json.
- Historical P4 proof/preflight results are not proofs of these runs. Bootstrap/public P5 acceptance is separate.

## Reproduce

Use the source in this commit, Rust1.97.1 and a supported CUDA toolkit/GPU (this run used CUDA13.0, compute86, MSVC14.44 host tools). Create the parent test/private directory and choose a fresh L2_TPS_OUTPUT beneath it. Keep the OS logical CPU availability unchanged to reproduce15-worker pools.

```powershell
$env:L2_TPS_OUTPUT = Join-Path (Get-Location) 'test/private/your-fresh-tps-output'
$env:L2_CUDA_ARCH = '86'
cargo test -p alephium-l2-node --release --features cuda --test tps_bulk --locked --jobs 2 -- --ignored --nocapture
```

All three sizes run sequentially in one aggregate. Output directories must not exist; every dataset, including failures, is retained. The original runner additionally enforced its Windows job resource/cleanup policy; apply equivalent process controls when reproducing. Published source includes an unrelated ignored funding-preparation fixture with an original-host E-drive path; it is not executed by this command.

## Audit files

See summary.json, result-1000.json, result-10000.json, result-100000.json, source-manifest.json, and the three transactions-*.csv.gz files. Decompress a CSV and recompute count/uniqueness, last receipt_offset_ns, fees and the TPS formula. Check hashes against its result JSON and files.sha256. No new ZK receipt was requested in the final operator scope.