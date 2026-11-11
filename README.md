# Fuzzforge

A working prototype of a Solana fuzzing service: a customer submits an Anchor
program bundle, a job is queued, a worker runs it under
[Trident](https://github.com/Ackee-Blockchain/trident) inside a locked-down
Docker container, and the customer gets a Markdown report with reproducible
failing cases and exact replay seeds.

> **Read this first:** a fuzzing service is a remote code execution service
> pointed at your infrastructure. The sandbox in this repository is a starting
> point, not a finished security posture. Do not accept a stranger's code until
> you have read [Security](#security) and validated the boundary yourself.

---

## Layout

```
fuzzforge/
├── Cargo.toml                  # Rust workspace
├── docker-compose.yml          # local dev: postgres + api + worker + frontend
├── Makefile
├── migrations/
│   └── 0001_init.sql
├── common/                     # shared job/report types + Postgres queue
│   └── src/{lib,queue}.rs
├── api/
│   ├── Dockerfile
│   └── src/
│       ├── main.rs             # axum server
│       ├── config.rs
│       ├── routes.rs           # intake, status, report download
│       ├── auth.rs             # opaque bearer job tokens
│       ├── validate.rs         # tar intake validation (no extraction)
│       ├── storage.rs          # content-addressed local storage
│       ├── db.rs
│       └── error.rs
├── worker/
│   ├── Dockerfile
│   └── src/
│       ├── main.rs             # claim → run → report loop
│       ├── config.rs
│       ├── db.rs
│       ├── runner.rs           # docker run + Trident invocation
│       ├── minimizer.rs        # delta debugging against the sandbox
│       └── report.rs           # Markdown + JSON report builder
├── sandbox/
│   ├── Dockerfile              # pinned Trident toolchain, non-root
│   └── bin/
│       ├── fuzzforge-run       # version-specific Trident → result.json adapter
│       └── fuzzforge-reproduce # single-case replay contract (exit 42)
├── frontend/                   # Next.js app router, three pages
│   ├── app/page.tsx
│   ├── app/submit/page.tsx
│   └── app/jobs/[id]/page.tsx
├── examples/scripts/make-sample-bundle.sh
├── scenarios/                  # hostile-scenario library for Crucible harnesses
│                               #   (Token-2022 mint matrix, invariant ledgers,
│                               #   upgrade-diff, compute profile)
├── tools/cu-profile.sh         # merge a campaign's compute-unit profile
└── targets/<program>/          # one standalone Crucible harness per engagement,
                                #   with findings/ (minimized cases) and REPORT.md
```

`scenarios/` and `targets/*` are standalone Cargo workspaces, so Crucible's
LiteSVM dependency graph never unifies with the API/worker crates. See
[targets/token_vault/REPORT.md](targets/token_vault/REPORT.md) for a sample
deliverable.

The only deliberate deviation from the original sketch is `common/`: the API
and worker are separate binaries, and the queue/job contract must not exist
twice. `common` owns both.

---

## Quick start (local)

Prerequisites: Rust 1.89+, Docker, Docker Compose v2, Node 22+ (only if you
run the frontend outside Compose).

```bash
cp .env.example .env

# 1. Build the sandbox image. This is the expensive step (Trident + toolchain).
make sandbox-build

# 2. Start Postgres, the API, the worker, and the frontend.
make up
```

Open <http://localhost:3000>, submit a bundle, and watch the job page.

The sample bundle is useful for exercising intake, **not** for producing a real
report:

```bash
make sample-bundle
# submit examples/sample-bundle.tar.gz through the UI
```

### Running the Rust binaries directly

```bash
# Postgres only
docker compose up -d postgres

export DATABASE_URL=postgres://fuzzforge:fuzzforge@localhost:5432/fuzzforge
export STORAGE_DIR=./data
cargo run -p fuzzforge-api

# in another shell
export ALLOW_UNPINNED_IMAGE=1   # local only
export SANDBOX_IMAGE=fuzzforge/sandbox:latest
cargo run -p fuzzforge-worker
```

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The build does **not** need a live database: SQLx queries are runtime-checked,
not compile-time macros.

---

## The loop

1. `POST /jobs` streams the upload to disk, hashes it, and validates the tar
   without extracting it. It rejects traversal paths, links, device entries,
   oversized expansion, and archives without `Anchor.toml` + `programs/*.rs`.
2. The bundle lands at `<storage>/bundles/<sha256>.tar[.gz]`; a `jobs` row is
   inserted with status `queued` and a hash of a 256-bit opaque token.
3. A worker claims a job with `UPDATE … FOR UPDATE SKIP LOCKED`, increments
   `attempts`, and launches the sandbox.
4. The sandbox writes `/out/result.json`. The worker parses it, replays
   seed-identified cases through `fuzzforge-reproduce` (byte/blob inputs are
   delta-debugged), and writes the report to Postgres.
5. `GET /jobs/{id}` returns status; `GET /jobs/{id}/report[.json]` returns the
   deliverables. Both require `Authorization: Bearer <token>` or `?token=`.

### Why Postgres is the queue

`SELECT … FOR UPDATE SKIP LOCKED` is a correct multi-worker queue with zero
extra infrastructure. It caps you at a few hundred concurrent workers before
you would want a broker, and you will not have that problem for a long time.
The `jobs_queued_idx` partial index keeps the claim query cheap as finished
jobs accumulate.

### Why the report is the product

Every report contains:

- the pinned sandbox image digest, Trident version, and bundle SHA-256;
- the invariant specification exactly as submitted;
- every failing case, minimized when a smaller input was observed to fail
  (Trident 0.12 seed cases are replayed exactly, not shrunk);
- a copy-paste command that reproduces the whole run or one case using only
  Docker, that image, and the customer's bundle;
- an explicit statement that a clean run is not a proof of safety.

The reproducibility contract is the trust argument: **if a case does not
reproduce with the printed digest, the report is void and we re-run it at our
cost.** That is why the worker refuses an unpinned `SANDBOX_IMAGE` unless
`ALLOW_UNPINNED_IMAGE=1` is set for local development.

---

## Sandbox contract

The worker runs the image with:

| Control | Setting |
| --- | --- |
| Network | `--network none` |
| Root filesystem | `--read-only` + tmpfs `/work` and `/tmp`, both `mode=1777` |
| Capabilities | `--cap-drop ALL` |
| Privilege escalation | `no-new-privileges:true` |
| User | `1000:1000`, non-root |
| IPC | `--ipc none` |
| Memory | 4 GB by default (`SANDBOX_MEMORY`), swap disabled |
| CPU | 2 (`SANDBOX_CPUS`) |
| PIDs | 256 (`SANDBOX_PIDS`) |
| `/work` tmpfs | 8 GB by default (`SANDBOX_WORK_SIZE`); cold builds need it |
| Time | 30 min hard cap, then `docker kill` via cidfile |
| Mounts | bundle `:ro` at `/in`, output dir `:rw` at `/out` |

`mode=1777` matters: the container runs as uid 1000, so the root-owned tmpfs
mounts are otherwise not writable and the adapter cannot create `/work/project`.

`/out/result.json` is the version-agnostic seam:

```json
{
  "executions": 50,
  "trident_version": "Trident 0.12.0",
  "failures": [
    {
      "invariant": "Assertion failed at fuzz_0/test_fuzz.rs:26:9: total supply != sum of balances",
      "reproducer": "{\"test\":\"fuzz_0\",\"seed\":\"507783bc…5533fc\"}",
      "note": "replay: cd trident-tests && trident fuzz debug fuzz_0 507783bc…5533fc",
      "minimized": false
    }
  ],
  "log_tail": "…"
}
```

`sandbox/bin/fuzzforge-run` is the only version-specific file. It locates the
project, runs from `trident-tests/` when Trident 0.12 is in use, executes the
fuzzer under a pty (`script`) so assertion lines survive the progress bar,
parses seeds, and translates them into the JSON above. Trident 0.12 reports a
failure as `Assertion failed … (seed: <64 hex>)`, and that seed is replayed with
`trident fuzz debug <test> <seed>`. **Re-check it every time you bump
`TRIDENT_VERSION`.**

Minimization re-runs candidates through `fuzzforge-reproduce`, which follows a
simple contract: exit `42` means the invariant still fails, exit `0` means it
does not. Seed-based cases are recognized and deliberately **not** minimized:
the seed is the case, and changing it runs a different iteration. Byte/blob
cases still go through delta debugging. `TRIDENT_REPRO_CMD` overrides replay for
a Trident version whose replay API differs.

### Offline builds

The sandbox has no network. Trident and the Anchor program need their
dependencies available **before** the sandbox starts. The scaffold does not
bake an offline Cargo registry; that is deliberate, because guessing the
customer's dependency closure is how you get a flaky service. The included
test bundle vendors its dependency closure and points `.cargo/config.toml` at
it, which is the simplest pattern to follow. Before taking money, choose one of:

- require a `Cargo.lock` and vendor dependencies into the bundle;
- bake a warm registry cache into the image for the crates you support;
- run a separately sandboxed, network-enabled **build** phase and keep the
  actual fuzz run offline. Note that the build phase is itself untrusted code.

Cold release builds are large: the sample Anchor + Trident project needs
roughly 8 GB of `/work` tmpfs and 4 GB of RAM to compile from scratch. In a
measured run on 2 CPUs, the cold build took about 4m45s and the fuzz campaign
itself took under a second; warm-target replays are fast. If you do not
pre-build, raise `SANDBOX_MEMORY` and `SANDBOX_WORK_SIZE` rather than letting
the build fail midway. Whichever you choose, document it in the offer. "We run
arbitrary Anchor projects" is not true until dependency resolution works.

---

## API

### `POST /jobs`

`multipart/form-data`:

| Field | Required | Notes |
| --- | --- | --- |
| `bundle` | yes | `.tar` or `.tar.gz`, capped at 100 MB |
| `invariant_spec` | no | ≤ 8,000 chars, printed verbatim in the report |
| `email` | no | contact only; there are no accounts |

Returns `201`:

```json
{
  "id": "…",
  "token": "…64 hex chars…",
  "status": "queued",
  "notice": "Prototype: compute starts immediately…"
}
```

The token is returned exactly once. Only its SHA-256 is stored.

### `GET /jobs/{id}`

Returns status, timestamps, bundle hash, invariant, executions, failure count,
and `report_available`.

### `GET /jobs/{id}/report` and `/report.json`

Markdown and JSON deliverables. `409` until the job is done. `Cache-Control:
private, no-store` and `X-Content-Type-Options: nosniff`.

Auth is `Authorization: Bearer <token>` or `?token=` for a pasteable link. The
frontend stores the token in `localStorage` and sends the header for downloads.

---

## Security

This section is the important one.

**What the prototype does**

- Intake validation rejects traversal paths, symlinks/hardlinks, device/FIFO
  entries, oversized archives, and non-Anchor bundles.
- Bundles are content-addressed and stored once.
- The sandbox has no network, no capabilities, a read-only root, a non-root
  user, resource limits, and a hard timeout.
- A crashed worker's `running` jobs are requeued (or failed after
  `MAX_ATTEMPTS`).
- Internal errors are logged, never returned to the customer.
- Job tokens are 256 bits of OS randomness, stored only as hashes, compared in
  constant time.

**What it does not do**

- **A container is not a security boundary against hostile code.** Kernel
  exploits, Docker/runc bugs, and cgroup escapes exist. A fuzzing service is an
  RCE service. Before a paid job, either put a VM-level boundary in front of
  execution (gVisor, Firecracker, Kata) or use a dedicated host that holds
  nothing else and is treated as compromised by design.
- **The Compose worker mounts `/var/run/docker.sock`.** That is root-equivalent
  on the host. It exists so the prototype is runnable. Do not run it on a
  laptop with personal keys, a shared CI runner, or a host with other tenants.
  Production should run the worker directly on a dedicated host.
- There is no rate limiting, no virus scanning, no egress filtering at the
  network layer (there is no network), and no audit log beyond process logs.
- There is no payment integration. The prototype starts compute immediately;
  production must gate `queued` on payment or manual approval.
- There is no authentication beyond the job token. That is intentional for v1:
  accounts add a signup step between a customer and their first report.
- The frontend puts the token in the URL. It sets `Referrer-Policy:
  no-referrer`, but URLs still appear in browser history and server logs. If
  that is unacceptable, switch to a POST-based exchange.

**Minimum bar before a real customer**

1. Dedicated host, nothing else on it, no long-lived cloud credentials.
2. A VM-level boundary or a documented, tested acceptance of container risk.
3. Pin the sandbox image and base images by digest; record the digest.
4. Test the printed reproduction command on a fresh VM.
5. Decide what the customer's harness must contain and reject everything else.
6. Have the customer confirm they are allowed to send you the code.

---

## What is deliberately deferred

- **Subscriptions.** You are selling engagements; a subscription implies
  ongoing value you cannot promise yet.
- **A multi-agent audit layer.** It competes on subjective judgment. Fuzzing
  wins on objective failure.
- **Enterprise dashboards.** No customer asks before their first report.
- **Accounts and auth.** Signed/opaque job links are enough for v1.
- **A custom object store.** Local disk on one box plus a nightly backup is
  fine until ten paying customers.
- **Kubernetes, Kafka, Celery.** Postgres + `SKIP LOCKED` + one worker.

---

## The questions this scaffold cannot answer

1. **What is the per-engagement compute ceiling, and what does a 30-minute,
   2-CPU, 4 GB run actually cost?** Until you know, $500 may be a loss.
2. **Is Docker enough, or do you need a VM-level boundary before accepting
   customer code?** Decide before the first paid job.
3. **What exactly must the customer's harness contain, and will you accept a
   harness you did not write?** A required template narrows the market and
   reduces risk. Arbitrary harnesses do the opposite.
4. **Who is the first named customer, and have you shown them a sample
   report?** Run this against one of your own programs and use that output as
   the sales artifact.
5. **Does the reproduction command work on a clean machine** with no Trident
   installed beyond the printed image? Test it on a fresh VM before promising
   it in writing.

## The smallest shippable v1

If you cut this to the bone: a Rust binary that takes a tarball, runs it in the
pinned sandbox, and writes a Markdown report with one reproducible case and
one reproduction command — plus a one-page site and a payment link. No queue,
no database, no status page. You run it by hand and email the report. The queue
and web app are what you add after the second customer, when demand has a
shape.

---

## License

MIT.
