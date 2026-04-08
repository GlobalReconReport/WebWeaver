# WebWeaver

<!-- Run this in your terminal to display the banner with colour: -->
<!--
printf "\033[1;38;5;99m"
cat << 'BANNER'

 _       __     __  _       __
| |     / /__  / /_| |     / /__  ____ __   _____  _____
| | /| / / _ \/ __ \ | /| / / _ \/ __ `/ | / / _ \/ ___/
| |/ |/ /  __/ /_/ / |/ |/ /  __/ /_/ /| |/ /  __/ /
|__/|__/\___/_.___/|__/|__/\___/\__,_/ |___/\___/_/

     Web2 bug-bounty capture & analysis toolkit — Kali Linux

BANNER
printf "\033[0m"
-->

```
 _       __     __  _       __
| |     / /__  / /_| |     / /__  ____ __   _____  _____
| | /| / / _ \/ __ \ | /| / / _ \/ __ `/ | / / _ \/ ___/
| |/ |/ /  __/ /_/ / |/ |/ /  __/ /_/ /| |/ /  __/ /
|__/|__/\___/_.___/|__/|__/\___/\__,_/ |___/\___/_/

     Web2 bug-bounty capture & analysis toolkit — Kali Linux
```

---

## ⚠️  Legal Notice — Authorized Testing Only

> **WebWeaver is a security research and bug-bounty tool.**
> You are solely responsible for ensuring you have explicit, written
> authorization from the system owner before pointing this tool at any
> target.  Unauthorized interception, scanning, or exploitation of
> computer systems is illegal in most jurisdictions, including under the
> Computer Fraud and Abuse Act (USA), the Computer Misuse Act (UK), and
> equivalent statutes worldwide.
>
> **Permitted use cases only:**
> - Targets listed in an active bug-bounty programme (HackerOne, Bugcrowd, etc.)
> - Systems you own or operate
> - Explicit written-authorization penetration-testing engagements
> - Controlled lab / CTF environments
>
> The authors accept no liability for misuse.  If in doubt — do not run it.

---

## What is WebWeaver?

WebWeaver is a Kali Linux toolkit for **Web2 API security research**.  It
sits between your browser and a target API, records every HTTP/S and
WebSocket transaction, and then systematically hunts for:

| Module | What it finds |
|---|---|
| **IDOR scanner** | Object IDs from session B substituted into session A's requests while keeping A's auth — flags cross-user data leakage |
| **Sequence breaker** | Skip, reorder, or replay workflow steps — flags missing prerequisite enforcement and replay vulnerabilities |
| **Race condition tester** | N concurrent identical requests — flags status divergence, numeric anomalies, and duplicate-processing keywords |
| **Auth boundary checker** | Cross-session response comparison — flags unauthenticated or under-privileged access |
| **Report generator** | Produces HackerOne, Bugcrowd, or generic Markdown reports with redacted evidence and curl repro steps |

---

## System Requirements

- **OS:** Kali Linux (rolling) — also works on Debian/Ubuntu
- **Rust:** 1.70 or later (installed via `rustup`)
- **Python:** 3.10 or later (ships with Kali)
- **mitmproxy:** 10.x or later
- **SQLite:** bundled (compiled into the binary — no system SQLite needed)
- Disk: ~50 MB for the compiled binary; database grows with captured traffic

---

## Installation

### 1 — Install the Rust toolchain

```bash
# Install rustup (skip if already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow the prompts (choose option 1 — default install)
# Then reload your shell environment:
source "$HOME/.cargo/env"

# Verify
rustc --version   # should show 1.70+
cargo --version
```

### 2 — Install mitmproxy

```bash
# Kali repositories (recommended)
sudo apt update && sudo apt install -y mitmproxy

# Or via pip if you need the latest version
pip3 install --user mitmproxy

# Verify
mitmproxy --version   # should show 10.x+
```

### 3 — Clone and build WebWeaver

```bash
# Clone into your working directory
git clone https://github.com/your-org/webweaver.git
cd webweaver

# Build the release binary (~90 seconds on first build)
source "$HOME/.cargo/env"
cargo build --release

# The binary lands here:
ls -lh target/release/lw

# Optionally put it on your PATH:
sudo cp target/release/lw /usr/local/bin/lw
```

### 4 — Install the mitmproxy CA certificate (one-time)

```bash
# Start mitmproxy once to generate its CA
mitmproxy &
sleep 2 && pkill mitmproxy

# Trust the CA so HTTPS decryption works
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates

# For Firefox/Burp-style browser proxy: import ~/.mitmproxy/mitmproxy-ca-cert.pem
# into your browser's certificate store manually.
```

---

## Architecture Overview

```
Browser / Mobile App
        |
        | HTTP/S  (proxy: 127.0.0.1:8080)
        v
  lw-proxy/addon.py        ← mitmproxy addon
  (writes to staging DB)
        |
        | SQLite WAL  (500 ms poll)
        v
  webweaver_staging.db
        |
        | lw sync
        v
  webweaver.db             ← main database (all analysis lives here)
        |
        +---> lw analyze-deps      (value-flow dependency graph)
        +---> lw build-graph       (Graphviz / JSON state graph)
        +---> lw diff-sessions     (cross-session IDOR candidates)
        +---> lw check-auth        (unauthenticated / under-priv access)
        +---> lw scan-idor         (active IDOR confirmation)
        +---> lw break-sequence    (workflow bypass / replay)
        +---> lw race-test         (race condition / double-spend)
        +---> lw run-all           (all three attack modules)
        +---> lw generate-report   (HackerOne / Bugcrowd / Markdown)
```

---

## Quick Start (5 minutes)

```bash
# Terminal 1 — start the proxy, tag traffic as "admin-session"
mitmproxy -s lw-proxy/addon.py \
    --set ww_session=admin \
    --set ww_db=webweaver_staging.db \
    -p 8080

# Terminal 2 — create sessions and start syncing
lw session new --name admin --role admin
lw session new --name guest --role user
lw sync --staging webweaver_staging.db --watch &

# Browse the target app as the admin user in your proxy-configured browser.
# Then change ww_session to "guest" and browse as the guest user.

# Terminal 3 — run all attack modules and generate a report
lw run-all --session-a admin --session-b guest
lw generate-report --session-a admin --session-b guest \
    --format hackerone --output report.md
```

---

## Step-by-Step Guide

### Step 1 — Create capture sessions

Sessions are named buckets that group captured traffic by user role.

```bash
# Create a session for the high-privilege user
lw session new --name admin --role admin

# Create a session for the low-privilege / unauthenticated user
lw session new --name guest --role user

# List all sessions
lw session list

# Show request / response / entity counts for a session
lw session stats admin

# Export a session to JSON for offline analysis
lw session export admin --output admin-session.json
```

### Step 2 — Start the mitmproxy capture

Open **two terminal windows** — one per user role.

**Terminal A — admin user:**
```bash
mitmproxy -s lw-proxy/addon.py \
    --set ww_session=admin \
    --set ww_db=webweaver_staging.db \
    -p 8080
```

**Terminal B — guest user** (different port so you can run both simultaneously):
```bash
mitmproxy -s lw-proxy/addon.py \
    --set ww_session=guest \
    --set ww_db=webweaver_staging.db \
    -p 8081
```

Configure your browser or `curl` to use `127.0.0.1:8080` (admin) or
`127.0.0.1:8081` (guest) as the HTTP proxy.  Browse the target application
fully — account pages, API calls, object listings, checkout flows, etc.

**Optional flags:**
```bash
# Also log a warning whenever a GraphQL introspection query is detected:
--set ww_graphql_introspect=true

# Store the staging DB in a custom location:
--set ww_db=/tmp/target-app/staging.db

# Run headless (no TUI) — useful in scripts:
mitmdump -s lw-proxy/addon.py --set ww_session=admin -p 8080
```

### Step 3 — Sync traffic into the main database

The sync command merges the staging DB (written by Python) into the main DB
(read by all Rust analysis tools).

```bash
# One-shot sync
lw sync --staging webweaver_staging.db

# Watch mode — runs forever, merging every 500 ms (use while capturing)
lw sync --staging webweaver_staging.db --watch

# Use a custom filter rules file to drop noise (assets, analytics, etc.)
lw sync --staging webweaver_staging.db --filter filter_rules.toml --watch
```

**`filter_rules.toml` example** — drop static assets and third-party domains:

```toml
# filter_rules.toml
[[deny_url_patterns]]
pattern = "\\.(js|css|png|jpg|jpeg|gif|ico|woff2?|svg)(\\?.*)?$"

[[deny_url_patterns]]
pattern = "^https://(www\\.google-analytics\\.com|fonts\\.googleapis\\.com)"

[[deny_methods]]
method = "OPTIONS"
```

### Step 4 — Analyze request-response dependencies

Detects which values flow from a response into a later request (e.g., CSRF
tokens, session IDs, object IDs).

```bash
# Analyse and print dependency edges for the admin session
lw analyze-deps --session admin

# Save edges to the database for later graph building
lw analyze-deps --session admin --save

# Export edges as JSON
lw analyze-deps --session admin --save --output admin-deps.json
```

### Step 5 — Build and visualise the state graph

```bash
# Print a Graphviz DOT representation to stdout
lw build-graph --session admin

# Write DOT and JSON files
lw build-graph --session admin \
    --dot admin-graph.dot \
    --json admin-graph.json

# Render to PNG (requires graphviz package)
sudo apt install -y graphviz
dot -Tpng admin-graph.dot -o admin-graph.png
```

### Step 6 — Diff sessions to surface IDOR candidates

Compares two sessions structurally.  When the same endpoint appears in both
sessions and the response body contains the other user's entity values, it
is flagged as a candidate IDOR.

```bash
# Diff admin (privileged) vs guest (target under test)
lw diff-sessions --privileged admin --target guest

# Save the full diff report to JSON
lw diff-sessions --privileged admin --target guest --output diff-report.json
```

### Step 7 — Detect auth boundary violations

Looks for unauthenticated access, privilege escalation, and cross-session
data leakage using response comparison heuristics.

```bash
# Analyse a single session (checks for missing auth / token replay)
lw check-auth --session admin

# Analyse all sessions in the database
lw check-auth

# Save findings to the database
lw check-auth --save

# Save findings to a JSON file
lw check-auth --session admin --save --output auth-findings.json
```

---

## Attack Modules

### IDOR Scanner

Substitutes session B's object IDs (UUIDs, numeric IDs) into session A's
requests while preserving A's authentication tokens.  Analyses responses for
cross-user data leakage using HTTP status, body content, and structural
similarity.

```bash
# Basic scan — session A owns the objects, session B should not see them
lw scan-idor --session-a admin --session-b guest

# Dry run — build and print every test request without sending any
lw scan-idor --session-a admin --session-b guest --dry-run

# Limit to 50 HTTP tests (default 100; 0 = unlimited)
lw scan-idor --session-a admin --session-b guest --max-tests 50

# Accept self-signed TLS certificates on the target
lw scan-idor --session-a admin --session-b guest --insecure

# Route through Burp Suite for manual inspection
lw scan-idor --session-a admin --session-b guest \
    --proxy http://127.0.0.1:8080

# Save full results to JSON
lw scan-idor --session-a admin --session-b guest \
    --output idor-results.json
```

**Reading the output:**
```
3 attempt(s), 1 confirmed IDOR finding(s).
  [conf=85%] GET /api/v1/invoices/{id} — '550e8400-...' → 'f47ac10b-...' @ 'id' (req#12)
     HTTP 200 (success); Response body contains B's value; 72% structurally similar to B's baseline
```

### Sequence Breaker

Tests three mutation types against every step in a captured session:

| Mutation | What is tested |
|---|---|
| `skip_step` | Execute step N+1 without completing step N — prerequisite bypass |
| `reorder_with_next` | Send step N+1 before step N — ordering enforcement |
| `replay_step` | Send step N twice — idempotency / replay protection |

```bash
# Test all mutations for the first 20 steps (default)
lw break-sequence --session admin

# Test up to 40 steps
lw break-sequence --session admin --max-steps 40

# Test all steps (0 = no limit)
lw break-sequence --session admin --max-steps 0

# Accept self-signed TLS
lw break-sequence --session admin --insecure

# Route through a proxy
lw break-sequence --session admin --proxy http://127.0.0.1:8080

# Save results to JSON
lw break-sequence --session admin --output sequence-results.json
```

### Race Condition Tester

Fires a single request N times simultaneously using Tokio async tasks.
Analyses responses for status code divergence, numeric field differences
across concurrent responses, and duplicate-processing keywords.

```bash
# First, identify which requests are good race candidates
# (write-method requests: POST, PUT, PATCH, DELETE)
lw session stats admin   # note the request IDs from --output JSON

# Race request #42 with 15 concurrent tasks
lw race-test --session admin --request-id 42 --concurrency 15

# Adjust per-request timeout (default 10 000 ms)
lw race-test --session admin --request-id 42 \
    --concurrency 20 --timeout-ms 5000

# Accept self-signed TLS
lw race-test --session admin --request-id 42 --insecure

# Route through a proxy (e.g., Burp to capture the concurrent requests)
lw race-test --session admin --request-id 42 \
    --proxy http://127.0.0.1:8080

# Save full race result to JSON
lw race-test --session admin --request-id 42 --output race-result.json
```

**Reading the output:**
```
10 response(s) received, 1 finding(s).
  [0] HTTP 200 — 143ms
  [1] HTTP 200 — 147ms
  [2] HTTP 409 — 152ms
  ...

  ⚠  [HIGH] status_divergence
     8/10 requests succeeded and 2/10 returned errors — possible race condition on POST
```

### Run All Modules

Chains IDOR scanner → sequence breaker → race condition tester and prints a
unified ranked findings table.

```bash
# Run all three modules with default settings
lw run-all --session-a admin --session-b guest

# Tune each module
lw run-all \
    --session-a admin \
    --session-b guest \
    --idor-max-tests 200 \
    --seq-max-steps 30 \
    --race-concurrency 15 \
    --race-limit 5 \
    --insecure

# Save the ranked findings to JSON
lw run-all \
    --session-a admin \
    --session-b guest \
    --output findings.json
```

**Sample output:**
```
=== WebWeaver run-all ===
  session-a : admin
  session-b : guest

[1/3] IDOR scan...
    -> 48 attempt(s), 2 IDOR finding(s)
[2/3] Sequence break for 'admin'...
    -> 57 mutation(s), 3 finding(s)
[3/3] Race tests for 'admin'...
    -> 3 target(s) tested, 1 finding(s)

┌─ Ranked findings (6 total) ──────────────────────────────────────────
│ #1   [95.5] [CRITICAL ] [race] Race condition: POST /api/payments/charge
│      Concurrent execution anomaly — 9/10 succeeded, duplicate-processing keyword found
│ #2   [82.0] [HIGH     ] [idor] IDOR: GET /api/invoices/{id}
│      HTTP 200; body contains B's UUID; 79% structurally similar to B's baseline
│ #3   [70.0] [HIGH     ] [sequence_break] Sequence break [replay_step @ step 3]
│      Replaying POST step 3 twice: both returned 2xx (200, 200)
...
└──────────────────────────────────────────────────────────────────────
```

---

## Report Generation

The `generate-report` command runs all attack modules, presents a draft
summary for analyst review, then renders a fully-redacted report.

```bash
# Interactive workflow (analyst checkpoint before writing the file)
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format hackerone \
    --output report.md

# Skip the analyst checkpoint (useful in CI / automated pipelines)
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format hackerone \
    --no-confirm \
    --output report.md

# Bugcrowd format
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format bugcrowd \
    --output bugcrowd-report.md

# Generic Markdown (for your own notes or internal disclosure)
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format markdown \
    --output findings.md

# With custom redaction rules (see redact.toml below)
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format hackerone \
    --redact-config redact.toml \
    --output report.md

# Tune the underlying scan parameters
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format hackerone \
    --idor-max-tests 200 \
    --seq-max-steps 40 \
    --race-concurrency 20 \
    --race-limit 5 \
    --insecure \
    --output report.md
```

**Analyst checkpoint — what it looks like:**
```
=== DRAFT FINDINGS SUMMARY ===
────────────────────────────────────────────────────────────────────────────────
  #1   [95.5] CRITICAL  [race]           Race condition: POST /api/payments/charge
       Concurrent execution anomaly detected — duplicate-processing keyword found
  #2   [82.0] HIGH      [idor]           IDOR: GET /api/invoices/{id}
       HTTP 200 returned B's invoice data using A's auth token
  #3   [70.0] HIGH      [sequence_break] Sequence break [replay_step @ step 3]
       Replaying POST step 3 twice: both returned 2xx (200, 200)
────────────────────────────────────────────────────────────────────────────────
Enter finding NUMBERS to EXCLUDE (comma-separated), or press ENTER to include all:
> 3
Excluding 1 finding(s). 2 finding(s) will appear in the report.
Generating report (2 finding(s))...
Report written to report.md
```

### Built-in redaction rules

Before any evidence reaches the report template the redaction engine
automatically masks:

| Data type | Before | After |
|---|---|---|
| Authorization header | `Bearer eyJhbGciOiJIUzI1NiJ9…` | `Bearer eyJhbGci…REDACTED` |
| Cookie values | `session=abc123; user=bob` | `session=[REDACTED]; user=[REDACTED]` |
| Email addresses | `alice@example.com` | `al***@***.com` |
| Phone numbers | `(555) 123-4567` | `***-***-4567` |
| SSN | `123-45-6789` | `[REDACTED-SSN]` |
| Card numbers | `4111111111111111` | `[REDACTED-CARD]` |

Curl reproduction commands use shell variables instead of real credentials:
`$AUTH_TOKEN_A`, `$SESSION_COOKIE_A`, `$CSRF_TOKEN_A`.

### Custom redaction rules (`redact.toml`)

Create a `redact.toml` file to add application-specific patterns:

```toml
# redact.toml — add to --redact-config when generating reports

[[custom_patterns]]
name        = "internal_api_key"
regex       = "X-Internal-Key:\\s*[A-Za-z0-9_\\-]{16,}"
replacement = "X-Internal-Key: [REDACTED]"

[[custom_patterns]]
name        = "employee_id"
regex       = "emp_[0-9]{6,}"
replacement = "[REDACTED-EMP-ID]"

[[custom_patterns]]
name        = "aws_access_key"
regex       = "AKIA[0-9A-Z]{16}"
replacement = "[REDACTED-AWS-KEY]"
```

---

## Full CLI Reference

```
lw [--db <path>] <COMMAND>

Global options:
  --db <path>   SQLite database file  [default: webweaver.db]

Commands:
  session new       --name <n> [--role <r>]
  session list
  session stats     [<name>]
  session export    <name> [--output <file>]

  sync              [--staging <file>] [--filter <file>] [--watch]

  analyze-deps      --session <n> [--save] [--output <file>]
  build-graph       --session <n> [--dot <file>] [--json <file>]
  diff-sessions     --privileged <n> --target <n> [--output <file>]
  check-auth        [--session <n>] [--save] [--output <file>]

  scan-idor         --session-a <n> --session-b <n>
                    [--dry-run] [--max-tests <N>]
                    [--insecure] [--proxy <url>] [--output <file>]

  break-sequence    --session <n>
                    [--max-steps <N>]
                    [--insecure] [--proxy <url>] [--output <file>]

  race-test         --session <n> --request-id <id>
                    [--concurrency <N>] [--timeout-ms <N>]
                    [--insecure] [--proxy <url>] [--output <file>]

  run-all           --session-a <n> --session-b <n>
                    [--idor-max-tests <N>] [--seq-max-steps <N>]
                    [--race-concurrency <N>] [--race-limit <N>]
                    [--insecure] [--proxy <url>] [--output <file>]

  generate-report   --session-a <n> --session-b <n>
                    --format markdown|hackerone|bugcrowd
                    [--output <file>] [--redact-config <file>]
                    [--idor-max-tests <N>] [--seq-max-steps <N>]
                    [--race-concurrency <N>] [--race-limit <N>]
                    [--insecure] [--proxy <url>] [--no-confirm]
```

---

## Typical Full Engagement Workflow

```bash
# ── 0. Set up ─────────────────────────────────────────────────────────────────
cd ~/webweaver
source "$HOME/.cargo/env"

# ── 1. Create sessions ────────────────────────────────────────────────────────
lw session new --name admin --role admin
lw session new --name guest --role user

# ── 2. Capture admin traffic ──────────────────────────────────────────────────
# Configure browser to use 127.0.0.1:8080 as HTTP proxy, then browse as admin.
mitmdump -s lw-proxy/addon.py \
    --set ww_session=admin \
    --set ww_db=webweaver_staging.db \
    -p 8080 &

lw sync --staging webweaver_staging.db --watch &

# Browse the application as the admin user — account settings, API calls,
# object listings, file uploads, payment flows, etc.

# ── 3. Capture guest traffic ──────────────────────────────────────────────────
# Reconfigure browser to 127.0.0.1:8081, log in as a lower-privilege user.
mitmdump -s lw-proxy/addon.py \
    --set ww_session=guest \
    --set ww_db=webweaver_staging.db \
    -p 8081 &

# Browse the same pages as guest so the tool has a baseline for comparison.

# ── 4. Stop the proxies when done ─────────────────────────────────────────────
pkill -f mitmdump
wait   # let the sync background job finish

# ── 5. Passive analysis ───────────────────────────────────────────────────────
lw session stats          # overview of captured traffic
lw analyze-deps --session admin --save
lw build-graph --session admin --dot admin.dot
lw diff-sessions --privileged admin --target guest
lw check-auth --save

# ── 6. Active attack phase ────────────────────────────────────────────────────
lw run-all \
    --session-a admin \
    --session-b guest \
    --idor-max-tests 300 \
    --seq-max-steps 40 \
    --race-concurrency 20 \
    --race-limit 5 \
    --insecure \
    --output findings.json

# ── 7. Generate the report ────────────────────────────────────────────────────
lw generate-report \
    --session-a admin \
    --session-b guest \
    --format hackerone \
    --redact-config redact.toml \
    --output hackerone-report.md

# Review and edit hackerone-report.md before submitting.
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Session 'admin' not found` | Run `lw session new --name admin` before syncing |
| HTTPS traffic not captured | Ensure the mitmproxy CA is trusted by your browser (see Installation §4) |
| `cargo: command not found` | Run `source "$HOME/.cargo/env"` or add `~/.cargo/bin` to `PATH` |
| Database locked error | Only one `lw sync` process should be running at a time |
| No IDOR findings despite mismatched sessions | Ensure both sessions browse the same endpoints; try `--dry-run` to check substitution candidates |
| Race test shows all identical responses | The endpoint may already be idempotent; try a higher `--concurrency` value or a different `--request-id` |
| TLS certificate errors | Pass `--insecure` to skip TLS verification on lab/staging targets |
| `mitmproxy: command not found` | Run `pip3 install --user mitmproxy` and ensure `~/.local/bin` is on `PATH` |

---

*WebWeaver — built for authorized security research on Kali Linux.*
