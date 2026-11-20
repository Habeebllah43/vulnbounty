# Consensus and equivalence design

This note explains how VulnBounty reaches agreement on a subjective
question — "is this flaw real, how bad is it, and is it a copy?" — and
what happens when validators disagree. It is the design behind
`contracts/vuln_bounty.py`; function names below refer to that file.

## The problem with LLM output and consensus

GenLayer's validators must agree on the outcome of a nondeterministic
call. A language model never returns byte-identical text twice: two
honest validators triaging the same report will write different
reasoning, different word order, sometimes a different but equivalent
score ("88" vs "88.0"). Comparing raw strings therefore fails consensus
on honest work. That is why this contract **never uses `strict_eq`** on
LLM output.

## The leader / validator split

`request_triage` runs one call:

```python
gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
```

- **Leader** (`_leader_triage`): fetches the code with
  `gl.nondet.web.render(url, mode="text")`, builds the triage prompt
  (`_build_triage_prompt` — bounty scope, report, the list of
  already-confirmed reports, and the fetched code, plus the severity
  rubric), calls `gl.nondet.exec_prompt(prompt,
  response_format="json")`, parses the reply with `_parse_verdict`, and
  returns the normalized verdict as a sorted JSON string.
- **Validator** (`_validate_triage`): receives the leader's outcome
  as a `gl.vm.Result` — on `gl.vm.Return` it reads the leader's verdict
  from `.calldata`; on any other Result (the leader failed) it re-runs
  the leader's work and compares the failure under the error taxonomy.
  On a verdict it re-runs the leader's work itself, parses both
  verdicts, and compares them with `_verdicts_agree`. It returns a
  boolean — agree or disagree. It never trusts the leader's text.

All web fetches and LLM calls happen inside these two functions. Nothing
outside `run_nondet_unsafe` is nondeterministic, and `settle` makes no
LLM call at all: it settles from the stored, already-agreed verdict.

## The comparison rules (`_verdicts_agree`)

The verdict is a small structured object:

```json
{"valid": true, "severity_score": 92, "duplicate": false, "duplicate_of": 0, "reasoning": "...", "cannot_verify": false}
```

Agreement requires:

1. **`cannot_verify` must match.** If either side says the report
   cannot be verified, both must say so. A verdict of "I can't tell"
   from one validator and "it is RCE, 92" from another is a real
   disagreement, not a wording difference.
2. **`valid` must match exactly.** There is no tolerance on the
   yes/no question of whether the flaw is real.
3. **`duplicate` must match exactly.** Likewise, whether the report
   copies a confirmed one is a yes/no question.
4. **`severity_score` must agree within ±10.** Severity grading is
   genuinely subjective; two honest triagers may give 78 and 85 for
   the same flaw. A gap of 11 or more is treated as disagreement.
   (The boundary is tested: diff 10 agrees, diff 11 does not.)
5. **Reasoning is never compared.** It is evidence for humans, not part
   of the consensus value.
6. **`duplicate_of` is never compared.** Two validators may point at
   different confirmed reports for the same duplicate; the settlement
   outcome is identical either way (the report is a duplicate and
   pays 0), so forcing agreement on which one would fail consensus
   for no benefit.

## Defensive parsing (`_parse_verdict`, `_coerce_score`)

LLM output is hostile input until proven otherwise. The parser:

- requires a JSON object (a list, a bare string, or invalid JSON is
  rejected);
- accepts `valid` and `duplicate` as booleans or as
  "true"/"false"/"yes"/"no";
- accepts the score under aliases (`severity_score`, `score`,
  `severity`, `rating`, `points`, `value`) and coerces it aggressively
  — ints, floats, `"88"`, `" 77% "` all work;
- rejects booleans-as-scores, non-numeric strings, and scores outside
  0–100;
- normalizes `cannot_verify: true` to `valid: false,
  severity_score: 0, duplicate: false`, so a failed verification can
  never smuggle a payout score with it;
- normalizes `valid: false` to `severity_score: 0`, so an invalid
  report can never smuggle a payout score with it either.

Every rejection raises `ValueError("[LLM_ERROR] ...")` — see the error
taxonomy below.

## Error taxonomy (`_handle_leader_error`, `_errors_agree`)

The leader's work can fail in four different ways, and the validators
must agree on *what kind* of failure it was — not on the exact error
text, which varies between runs and networks.

| Prefix | Meaning | Agreement rule |
|---|---|---|
| `[EXPECTED]` | Business-logic failure | Exact string match |
| `[EXTERNAL]` | Bad code URL / HTTP 4xx (404, 403, …) | Exact string match |
| `[TRANSIENT]` | Network failure / HTTP 5xx / timeout | Agree if both are transient, wording ignored |
| `[LLM_ERROR]` | Malformed LLM output | **Always disagree** — forces leader rotation |

Classification (`_handle_leader_error`): an already-prefixed error
passes through unchanged. Otherwise the message is inspected — 4xx /
"not found" / "forbidden" become `[EXTERNAL]`; 5xx / timeout /
connection problems become `[TRANSIENT]`; anything unrecognized is
treated as `[TRANSIENT]` (retryable) rather than failing the report
permanently. A `ValueError` from `_parse_verdict` already carries
`[LLM_ERROR]`, so it passes through as such.

Why LLM errors always disagree: a malformed verdict is a property of
the leader's run, not of the world. If validators agreed "the leader's
output was garbage", a bad leader could stall every triage. Forcing
disagreement rotates the leader, and the next leader's output is judged
fresh.

## What happens on each outcome

| Situation | On-chain result |
|---|---|
| Validators agree on a verdict | Verdict + score stored, status `triaged`; `settle` can now run |
| Verdict is `cannot_verify` | Attempt counted; status stays `reported` (attempts < 3) or becomes `unverifiable` (3rd attempt); nobody paid |
| Leader fails, validators agree it is transient/external | Attempt counted; status stays `reported` (or `unverifiable` on 3rd); nobody paid; the caller may retry |
| Validators disagree (scores > 10 apart, `valid`/`duplicate` differ, LLM error) | **No consensus.** The triage does not finalize; the report stays `reported` with its attempt count unchanged, and the call can be retried. In the stubbed tests this surfaces as a failed `run_nondet_unsafe` call, which `request_triage` records as an attempt — on a live network a true consensus failure means the transaction does not finalize, so no attempt is consumed. Confirm the exact behaviour in Studio testing. |
| 3 failed attempts | Status `unverifiable`; nobody paid |
| 3 days pass with no triage | `expire_report` (anyone) moves the report to `unverifiable`; nobody paid |

In every failure path the money stays locked in the pool. The contract
fails closed: there is no path from a failed or unverifiable triage to
a payout.

## The UNDETERMINED hole — and the expire_report escape

This design exists because of a hole found while building
DeliveryEscrow (a freelance-delivery escrow on the same consensus
pattern): when validators cannot reach consensus at all, the judgment
comes back UNDETERMINED — "Failed to reach consensus" — and **nothing
is written on-chain**. The attempt is not counted, the status does not
change, and the escrow simply stays open forever. Any escape that
depends on counting failed attempts can therefore never fire when
consensus itself is the thing failing.

VulnBounty fixes that with a second, independent escape that does not
depend on consensus at all: `expire_report` is a purely deterministic
method. Anyone may call it once a report has sat `reported` for more
than 3 days (259200 seconds) with no triage. The only input is the
transaction datetime (`int(datetime.now(timezone.utc).timestamp())`),
which every validator sees identically, so it cannot fail consensus —
there is no nondeterministic work in it. The report becomes
`unverifiable`, the bounty can then be closed, and the pool is
protected. The 3-day window is deliberately generous: it gives
researchers and callers time to retry triage, and it only fires on
reports nobody has managed to triage at all.

## What this design deliberately does not do

- **No appeal inside the contract.** A settled verdict is final as far
  as this contract is concerned. Re-triage of a *settled* report is
  not possible — that would let a loser re-roll until they win. Appeal
  of a consensus outcome is GenLayer's own mechanism (validator
  rotation, and ultimately the network's dispute process), not something
  a single contract should re-implement.
- **No reputation or staking for triagers.** Validators are GenLayer's;
  this contract does not add its own validator set or slashing.
- **No partial re-triage.** A triage is one verdict for the whole
  report. If the researcher has more evidence, they submit a new
  report — but only while the bounty is `open` and before its deadline.
- **Duplicate detection only sees paid reports.** A report that is
  still undecided does not count as confirmed, so two near-identical
  reports submitted at the same time are both triaged on their own
  merits; the second one to settle is the duplicate.

## Open questions (confirm in Studio testing)

1. **Payout interface.** Payouts use `_PayoutTarget.emit_transfer`
   (the faucet pattern from Studio's bundled `faucet.py`); confirm
   the payout wiring in Studio testing (see README).

2. **Consensus-failure behaviour.** Confirm that a genuine
   UNDETERMINED triage leaves the report `reported` with attempts
   unchanged (as observed in DeliveryEscrow), and that `expire_report`
   then closes it as designed.

The following were open questions in an earlier draft and are now
resolved against the official docs (docs.genlayer.com):

- **Error propagation shape / validator argument (resolved).** The
  validator receives a `gl.vm.Result`, not the raw verdict — see
  "Error Patterns for Consensus" in the Non-determinism / Equivalence
  Principle docs: `validator_fn(leaders_res: gl.vm.Result) -> bool`.
  On `gl.vm.Return` the leader's value is on `.calldata`; on
  `gl.vm.UserError` / `gl.vm.VMError` the leader failed and its message
  is on `.message`. `_validate_triage` follows that pattern exactly.
- **Time source (resolved).** There is no block timestamp in GenLayer
  — the Transaction Context docs state "No block number, no block
  hash." Deadlines and the 3-day expiry use
  `int(datetime.now(timezone.utc).timestamp())` (Unix seconds, the docs'
  own form for "Arithmetic, expiries, deltas"): the stdlib clock is
  wired to the transaction datetime, so every validator sees the same
  value.
