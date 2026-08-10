# BouncyCastle mine-path wall-clock proof

Proves the full mining CLI path stays under the crypto-mining-service job budget
on the pathological provider corpus that previously timed out at 30 minutes.

| Item | Value |
|------|--------|
| Ticket | [#216](https://github.com/scanoss/crypto-finder/issues/216) |
| Corpus | `org.bouncycastle:bcprov-jdk18on:1.84` (Maven Central `-sources.jar` + pom) |
| Command | `crypto-finder scan --export-graph-fragment --output …` |
| Budget | **10 minutes** wall clock (mining `JOB_TIMEOUT` is 30m; target is single-digit minutes) |
| Default CI | **off** (opt-in only) |

## Run

```bash
# one-shot (downloads sources into the test temp/cache, builds the CLI)
make proof-bcprov-mine

# or explicitly
CRYPTO_FINDER_BCPROV_MINE_PROOF=1 \
  go test -count=1 -timeout 15m -run TestMinePathBcprovJdk18on184_WallClockBudget ./internal/scan/
```

Optional env:

| Env | Purpose |
|-----|---------|
| `CRYPTO_FINDER_BCPROV_SRC` | Pre-unpacked sources tree (skip download) |
| `CRYPTO_FINDER_BCPROV_CACHE` | Cache dir for downloaded jar/workspace |
| `CRYPTO_FINDER_BIN` | Prebuilt `crypto-finder` binary |
| `SCANOSS_API_KEY` / `SCANOSS_API_URL` | Remote rules (production-like); otherwise local/cached rules |

## What is asserted

1. Process exits 0 within **10m** wall clock.
2. Findings file has a dense-library floor (`findings` files ≥ 400).
3. Fragment has floors: `functions` ≥ 20k, `crypto_annotations` ≥ 2k, non-empty `crypto_entry_points`.
4. Verbose log contains healthy phase markers: callgraph built, fragment export started **and completed**, findings write completed.

Related no-regression data gate (always on in CI): `TestMinePathFragment_*` (#215).

## Recorded result (post-#214 / #215)

On an Apple Silicon developer laptop (2026-08-10), after the mine-path export fixes (#214):

| Run | Wall clock | Notes |
|-----|------------|--------|
| Manual CLI | **~100s** | OpenGrep ~60–75s, callgraph ~10s, fragment export ~22s |
| `make proof-bcprov-mine` / gated test | **~2m31s** | Includes `go build` of the CLI + full scan; still well under the **10m** budget |

Floors observed: `functions=24231`, `crypto_annotations=2515`, `crypto_entry_points=2781`, `findings` files=479.

Before #214 the same corpus cancelled at **30m** (`crypto-finder timed out`) with fragment export crawling for tens of minutes.

## Why this corpus

`bcprov-jdk18on` is a dense crypto library (~24k functions, thousands of annotations). It is on the IBM showcase seed list and was the clearest production timeout signal for the mine path.
