# VulnBounty — AI-triaged bug bounty payouts

A standalone **GenLayer Intelligent Contract** (Python, GenVM). It is a
reusable primitive — bounty pool + AI triage + deterministic settlement —
not a demo app and not a hello-world contract. There is no frontend in
this repo: the contract *is* the submission.

## The problem

Bug bounties are paid on human triage. A researcher finds a flaw, writes
it up, and waits — sometimes weeks — for a person to read the code,
decide whether the flaw is real, grade its severity, and check it is not
a copy of a report that was already paid. That triage bottleneck is why
good reports go stale, duplicates get paid twice, and small programs
never start a bounty at all. A normal smart contract cannot fix it: it
cannot read source code, cannot tell a real vulnerability from a false
alarm, and cannot compare two reports for the same root cause.

## What this contract does

1. **A bounty owner funds a pool** (`create_bounty`, payable) for a
   codebase, with a scope, per-severity rewards (critical / high /
   medium / low), and a deadline. Anyone may add to the pool later
   (`top_up`).
2. **A researcher submits a report** (`submit_report`) with a link to
   the affected code, a title, a description, steps to reproduce, a
   claimed severity, and a payout wallet — before the bounty deadline.
3. **Anyone calls `request_triage`**. GenLayer's AI validators fetch the
   *real* code from the URL, check whether the claimed flaw is really
   there, grade its severity, and compare it against the already-paid
   (confirmed) reports for that bounty for duplicates. They agree on a
   structured verdict through consensus. The verdict and severity score
   are stored on-chain.
4. **`settle` pays out deterministically from the stored verdict** — no
   LLM call at settlement time:
   - duplicate → status `duplicate`, **0** paid
   - severity **≥ 80** (critical) → the critical reward
   - severity **60–79** (high) → the high reward
   - severity **40–59** (medium) → the medium reward
   - severity **20–39** (low) → the low reward
   - severity **< 20** or invalid → status `rejected`, **0** paid
   - if the pool is short of the reward, settlement fails and the
     bounty owner must top it up first
5. **Reports that never get triaged still end.** If a report sits
   `reported` for more than 3 days with no triage, anyone may call
   `expire_report` and it becomes `unverifiable` — nobody is paid. This
   is the deterministic escape for the consensus hole found while
   building DeliveryEscrow: a failed consensus writes nothing on-chain,
   so an attempt-based escape can never fire when consensus itself
   fails. The escape has to be time-based. See `CONSENSUS.md`.
6. **The bounty owner can close the bounty** (`close_bounty`) once no
   report is still waiting for a decision, and the remaining pool is
   refunded to them.

## Why it needs GenLayer consensus

| Question | Normal contract | VulnBounty |
|---|---|---|
| Read source code? | No | Validators fetch the real code URL |
| Tell a real flaw from a false alarm? | No | Validators judge it against the code |
| Grade severity? | No | Validators score it 0–100 on a rubric |
| Spot a duplicate of a paid report? | No | Validators compare against confirmed reports |
| Move the money? | Yes | Deterministic band rewards on the stored verdict |

The AI never touches money directly: it only produces a verdict. The
money logic is pure integer arithmetic on that verdict, so settlement is
reproducible and auditable.

## State design

`contracts/vuln_bounty.py` — one contract class, `VulnBounty`.

- **Storage** (class-level annotations only): `owner`,
  `bounties: TreeMap[u256, Bounty]`, `bounty_order: DynArray[u256]`,
  `reports: TreeMap[u256, Report]`, `report_order: DynArray[u256]`,
  `counters: TreeMap[str, u256]`, `total_paid_out_atto`,
  `total_refunded_atto`. No Python dict/list in storage; money is `u256`
  atto-GEN (1 GEN = 10¹⁸ atto), never floats; status is `str`, never Enum.
- **Bounty record** (`@allow_storage @dataclass`): id, owner, repo_url,
  scope, title, reward_critical, reward_high, reward_medium, reward_low,
  pool, deadline, status, created_at.
- **Report record** (`@allow_storage @dataclass`): id, bounty_id,
  researcher, payout_wallet, code_url, title, description, steps,
  claimed_severity, status, verdict (stored JSON), severity_score,
  attempts, created_at.
- **Status machines:** bounty `open → closed` (with pool refund);
  report `reported → triaged → paid | rejected | duplicate`;
  `reported → unverifiable` (3 failed triage attempts, or the 3-day
  expiry).
- **Access control** via `gl.message.sender_address` (an `Address`,
  compared directly against the stored bounty owner / researcher),
  raising `gl.vm.UserError` for business errors (wrong caller, wrong
  status, past deadline, zero amount, bad severity, empty fields).
- **Payouts** are direct transfers of the GEN locked in the bounty pool
  by the payable `create_bounty` / `top_up` calls. They go out through
  `_PayoutTarget.emit_transfer` on an `@gl.evm.contract_interface`
  (the faucet pattern: `emit_transfer` takes only `value=`, and the
  destination is the address passed to the constructor). No Arbiter
  and no setup call are needed — `settle` and `close_bounty` pay out
  as soon as they run. See `DEPLOY.md`.

## How consensus and equivalence work here

All web fetches and LLM calls happen inside a leader function passed to
`gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`. The leader fetches
the code with `gl.nondet.web.render(url, mode="text")` and triages it
with `gl.nondet.exec_prompt(prompt, response_format="json")`, using the
severity rubric written into the prompt (critical = RCE / fund theft /
auth bypass / unrestricted admin; high = secret or PII exposure,
privilege escalation, fund loss needing preconditions; medium = limited
impact or unlikely preconditions; low = minor / info / best practice).

The validator is **custom, not `strict_eq`** — strict equality always
fails consensus on LLM output, because two honest validators word the
same conclusion differently. Instead the validator re-runs the leader's
work and compares the *structured* verdict. It receives the leader's
outcome as a `gl.vm.Result`: on `gl.vm.Return` the verdict JSON is on
`.calldata`; on any other Result the leader failed, and the validator
re-runs the leader's work and compares the failure under the error
taxonomy below:

- `valid` must match exactly;
- `duplicate` must match exactly;
- `severity_score` must agree within **±10**;
- if either side says `cannot_verify`, both must agree on it;
- reasoning text is never compared, and neither is `duplicate_of` (two
  validators may point at different confirmed reports for the same
  duplicate; the settlement is the same either way).

Leader-side failures are classified with an error taxonomy
(`[EXPECTED]` business logic, `[EXTERNAL]` 4xx, `[TRANSIENT]` network/5xx,
`[LLM_ERROR]` malformed LLM output). Transient failures agree with each
other, expected/external failures must match exactly, and LLM errors
always disagree so the leader is rotated. Full design: `CONSENSUS.md`.

## Worked example

**Bounty** (owner locks 10 GEN, deadline +7 days):

> Shop web app bounty — Python web app in `shop/`: command runner,
> auth, and payment handling.
> Rewards: critical 4 GEN, high 2 GEN, medium 1 GEN, low 0.25 GEN.

**Report 1 — the vulnerable demo file** (`demo/vulnerable.py`):

> "RCE via eval() in run_command" — `run_command` passes user input
> straight to `eval()`, so anyone can run arbitrary Python, including
> `os.system` commands. Steps: send
> `GET /run?cmd=__import__('os').system('id')`.

**Expected verdict:** `{"valid": true, "severity_score": 92,
"duplicate": false, ...}` — `eval()` on user input is textbook RCE.
**Settlement:** 92 ≥ 80, so the researcher's payout wallet receives the
**4 GEN** critical reward; the pool drops to 6 GEN.

**Report 2 — the same flaw again, from another researcher:**

> Same `eval()` flaw, same file, reported after report 1 was paid.

**Expected verdict:** `{"valid": true, "severity_score": 90,
"duplicate": true, "duplicate_of": 1, ...}` — same file, same root
cause as a confirmed report. **Settlement:** status `duplicate`,
**0 GEN** paid.

**Report 3 — the secure demo file** (`demo/secure.py`):

> "Command injection in run_command" — claims the same endpoint is
> vulnerable. But the file uses `ast.literal_eval` and an arithmetic-only
> evaluator: no `eval()`, no `exec()`, no names, no imports.

**Expected verdict:** `{"valid": false, "severity_score": 0, ...}`.
**Settlement:** status `rejected`, **0 GEN** paid.

## Files

| File | What it is |
|---|---|
| `contracts/vuln_bounty.py` | The contract |
| `tests/test_vuln_bounty.py` | 124 pytest tests (see below) |
| `tests/conftest.py` | Minimal fake `genlayer` module (stub) |
| `demo/vulnerable.py` | Intentional critical flaw (eval on input) |
| `demo/secure.py` | Same feature written safely |
| `CONSENSUS.md` | Equivalence design in depth |
| `DEPLOY.md` | Studio → testnet → portal, step by step |
| `pyproject.toml` / `requirements.txt` | pytest only |

## Tests

The `genlayer` package is not installed in this environment (see Linting
below), so the contract is structured with module-level pure helpers
(`_band_for_score`, `_reward_for_band`, `_parse_verdict`,
`_verdicts_agree`, `_handle_leader_error`, `_errors_agree`) and
`tests/conftest.py` stubs the `genlayer` module (a minimal fake `gl`
with Contract, TreeMap, DynArray, public decorators, message,
nondet, eq_principle, vm with `gl.vm.Return` / `gl.vm.UserError` Result
types, and the stdlib clock pinned to the transaction datetime) so the
contract file imports cleanly and the lifecycle runs end-to-end under
the stub — including the consensus flow (leader + validator
agreement/disagreement) and payout calls, which are recorded by
patching `_PayoutTarget.emit_transfer`.

```sh
pip install -r requirements.txt
python3 -m pytest tests/ -q
# 124 passed
```

Coverage: severity bands and band boundaries (80/79/60/59/40/39/20/19),
reward mapping, verdict parsing (aliases, string/float scores, invalid
forcing score 0, `cannot_verify` normalization, malformed JSON →
`[LLM_ERROR]`), agreement rules (±10 tolerance, pass at 10, fail at 11,
`valid`/`duplicate` exact, `cannot_verify` rules, reasoning ignored),
error taxonomy, creation guards (zero pool, empty fields, non-http URLs,
zero rewards, past deadline), top-up rules, report guards (closed
bounty, past deadline, bad severity, empty fields), triage paths
(critical/high/duplicate/invalid/cannot_verify ×3 → unverifiable, fetch
failure ×3 → unverifiable, consensus disagreement), the 3-day
`expire_report` (before/at/after the boundary), settlement tiers and
pool shortfall (owner must top up), close rules (owner-only, blocked by
undecided reports, pool refund), pagination, stats, and three full
lifecycles (happy path, invalid path, duplicate path).

## Linting

`genvm-lint` is **not available in this environment** and the contract
could not be lint-checked here:

- `pip install genvm-lint` → no such package on PyPI.
- `pip install py-genlayer` → no such package on PyPI.
- `pip install genlayer` → installs version 0.0.1, which is an empty
  placeholder package ("A minimal empty PyPI package for genlayer") with
  no `gl` API at all.

The contract was written to follow the linted patterns from the official
write-contract guidance (single contract per file, storage annotations,
TreeMap/DynArray, no floats for money, all nondeterminism inside
`run_nondet_unsafe`, custom validator instead of `strict_eq`), and it
compiles cleanly with `python3 -m py_compile`. **Before submitting, run
`genvm-lint check contracts/vuln_bounty.py`** from the official
GenLayer tooling (GenLayer Studio runs the same checks on deploy) and
fix anything it flags — in particular confirm the transaction-datetime
deadline clock (`datetime.now(timezone.utc)`) and the
`_PayoutTarget.emit_transfer` payout wiring against the target network.

## Deploy

See `DEPLOY.md`: GenLayer Studio (studio.genlayer.com, 5 simulated
validators) → Bradbury testnet (faucet) → submit via the GenLayer portal
(portal.genlayer.foundation) under the Builders / standalone contracts
category.

## Honest limits

- **Settlement interface:** payouts use `_PayoutTarget.emit_transfer`
  (the faucet pattern, copied from GenLayer Studio's bundled
  `faucet.py`). `settle` and `close_bounty` pay out directly with no
  setup call — confirm the payout wiring in Studio testing before
  mainnet use.
- **Triage is only as good as what validators can fetch.** The contract
  judges the code at the submitted URL; it cannot check code that needs
  a login or is not publicly fetchable (that lands as `cannot_verify`),
  and it cannot prove the researcher found the flaw independently.
- **Duplicate detection only sees paid reports.** A report that is
  still undecided does not count as confirmed, so two near-identical
  reports submitted at the same time are both triaged on their own
  merits; the second one to settle is the duplicate.
- **No appeal flow in the contract itself.** Disagreement is handled by
  GenLayer's consensus: validators that disagree force re-execution /
  leader rotation. Appeal of a settled verdict is GenLayer's own
  mechanism, not something this contract re-implements.
- **Deadlines use the transaction datetime** —
  `int(datetime.now(timezone.utc).timestamp())` in Unix seconds. GenLayer
  exposes no block timestamp (no block number or hash in the transaction
  context); the stdlib clock is wired to the transaction datetime, so
  every validator sees the same value.
- **`get_stats` iterates all bounties and reports.** Fine for a
  primitive's expected scale; a deployment expecting thousands of
  either should paginate or maintain running counters instead.
