# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

# Always put above lines as first in the contract file.
# (GenLayer Studio / GenVM require this runner header; without it schema
# loading fails with "invalid contract absent_runner_comment".)
"""
VulnBounty — AI-triaged bug bounty payouts.

A standalone GenLayer Intelligent Contract primitive: a bounty owner locks
GEN in a pool for a codebase, researchers submit vulnerability reports
with a link to the affected code, GenLayer's AI validators fetch the
*real* code, check whether the claimed flaw is really there, grade its
severity, and check it against already-confirmed reports for duplicates.
Validators agree on a structured verdict through consensus, and the
contract settles deterministically from that verdict — pay the
severity-band reward, or pay nothing for a duplicate, an invalid report,
or one that cannot be verified.

Why this needs GenLayer (and why a normal smart contract cannot do it):
a normal contract cannot read source code, cannot tell whether a
reported flaw is real, cannot grade severity, and cannot tell a genuine
report from a copy of one already paid. Here the validators do that
reading, reasoning and comparing, and Optimistic Democracy turns their
agreement into an on-chain verdict the contract can settle from. The
money logic itself — severity bands, tiered rewards, pool accounting —
is fully deterministic and runs on the stored verdict only; the AI never
touches money directly.

Severity bands, from the stored severity_score:
    score >= 80  -> critical  (RCE, fund theft, auth bypass, admin)
    60 <= score < 80 -> high  (secret/PII exposure, privilege escalation)
    40 <= score < 60 -> medium (limited impact, unlikely preconditions)
    20 <= score < 40 -> low   (minor / info / best practice)
    score < 20   -> invalid   (not a real vulnerability)

Report status machine:
    reported -> triaged -> paid       (valid report, band reward)
    reported -> triaged -> rejected   (invalid report, score < 20)
    reported -> triaged -> duplicate  (same flaw as a confirmed report)
    reported -> unverifiable          (3 failed triage attempts, or the
                                       3-day expiry — see expire_report)

Money is u256 atto-GEN (1 GEN = 10**18 atto). No floats are ever used for
money. Fail closed: if the code cannot be fetched, or the validators
cannot verify the report, nobody is paid.

Payouts are direct transfers of the GEN locked in the bounty pool by the
payable create_bounty / top_up calls. They go out through the
faucet-pattern EVM interface below (_PayoutTarget): the
@gl.evm.contract_interface decorator provides emit_transfer, which
takes only value=, and the destination is the address passed to the
constructor. No Arbiter or setup call is needed.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from genlayer import *

# ---------------------------------------------------------------------------
# Error taxonomy for consensus (see CONSENSUS.md for the full design)
#
# The leader's nondeterministic work can fail in four different ways, and
# the validators must agree on *what kind* of failure it was — not on the
# exact wording of an error message, which differs between runs.
# ---------------------------------------------------------------------------
ERROR_EXPECTED = "[EXPECTED]"      # business-logic failure, exact match
ERROR_EXTERNAL = "[EXTERNAL]"      # bad code URL / 4xx, exact match
ERROR_TRANSIENT = "[TRANSIENT]"     # network / 5xx, agree if both transient
ERROR_LLM = "[LLM_ERROR]"          # malformed LLM output, always disagree

MAX_TRIAGE_ATTEMPTS = 3
SCORE_TOLERANCE = 10               # validators must agree within +/-10
EXPIRE_AFTER_SECONDS = 259200      # 3 days: a "reported" report with no
                                   # triage becomes expirable (see
                                   # expire_report / CONSENSUS.md)
MAX_TRIAGE_CONTENT_CHARS = 12000   # cap on fetched code sent to the LLM

BAND_CRITICAL = 80
BAND_HIGH = 60
BAND_MEDIUM = 40
BAND_LOW = 20


# ---------------------------------------------------------------------------
# Pure helpers (module level, so they are unit-testable without GenVM)
# ---------------------------------------------------------------------------
def _coerce_score(value):
    """Coerce an LLM score value to an int in 0..100.

    Accepts ints, floats, and numeric strings (with whitespace and a
    trailing "%" tolerated). Raises ValueError(ERROR_LLM ...) on anything
    missing, non-numeric, boolean, or out of range.
    """
    if isinstance(value, bool):
        raise ValueError(ERROR_LLM + " severity_score must be a number, got a boolean")
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        text = value.strip().rstrip("%").strip()
        try:
            num = float(text)
        except ValueError:
            raise ValueError(ERROR_LLM + " severity_score is not numeric: %r" % (value,))
    else:
        raise ValueError(ERROR_LLM + " severity_score has an unsupported type")
    score = int(round(num))
    if score < 0 or score > 100:
        raise ValueError(ERROR_LLM + " severity_score out of range 0-100: %r" % (value,))
    return score


def _parse_verdict(raw):
    """Parse and validate a triage verdict into a normalized dict.

    Accepts a JSON string or an already-parsed dict. The triage judge
    must return an object with:
        valid:           bool (or "true"/"false"/"yes"/"no")
        severity_score:  number 0..100 (aliases: score, severity, rating,
                         points, value)
        duplicate:       bool (optional, default false)
        duplicate_of:    report id the report duplicates (optional, 0)
        reasoning:       string (optional)
        cannot_verify:   bool (optional, default false)

    A verdict of cannot_verify=True is normalized to valid=False,
    severity_score=0, duplicate=False. A verdict of valid=False is
    normalized to severity_score=0, so an invalid report can never
    smuggle a payout score with it. Anything malformed raises
    ValueError(ERROR_LLM ...), which the consensus error taxonomy
    treats as "always disagree" so the leader is rotated instead of a
    bad verdict being settled on.
    """
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except Exception:
            raise ValueError(ERROR_LLM + " verdict is not valid JSON")
    if not isinstance(data, dict):
        raise ValueError(ERROR_LLM + " verdict is not a JSON object")

    cannot_verify = data.get("cannot_verify", False)
    if isinstance(cannot_verify, str):
        cannot_verify = cannot_verify.strip().lower() in ("true", "yes", "1")
    cannot_verify = bool(cannot_verify)
    if cannot_verify:
        reasoning = data.get("reasoning", "")
        return {
            "valid": False,
            "severity_score": 0,
            "duplicate": False,
            "duplicate_of": 0,
            "cannot_verify": True,
            "reasoning": reasoning if isinstance(reasoning, str) else str(reasoning),
        }

    if "valid" not in data:
        raise ValueError(ERROR_LLM + " verdict is missing 'valid'")
    valid = data["valid"]
    if isinstance(valid, str):
        lowered = valid.strip().lower()
        if lowered in ("true", "yes", "1"):
            valid = True
        elif lowered in ("false", "no", "0"):
            valid = False
        else:
            raise ValueError(ERROR_LLM + " 'valid' is not a boolean")
    elif not isinstance(valid, bool):
        raise ValueError(ERROR_LLM + " 'valid' is not a boolean")

    score = None
    for key in ("severity_score", "score", "severity", "rating", "points", "value"):
        if key in data and data[key] is not None:
            score = _coerce_score(data[key])
            break
    if score is None:
        raise ValueError(ERROR_LLM + " verdict is missing a numeric severity score")

    duplicate = data.get("duplicate", False)
    if isinstance(duplicate, str):
        duplicate = duplicate.strip().lower() in ("true", "yes", "1")
    duplicate = bool(duplicate)
    duplicate_of = data.get("duplicate_of", 0)
    try:
        duplicate_of = int(duplicate_of)
    except Exception:
        duplicate_of = 0
    if duplicate_of < 0:
        duplicate_of = 0

    reasoning = data.get("reasoning", "")
    if not isinstance(reasoning, str):
        reasoning = str(reasoning)

    if not valid:
        score = 0
    return {
        "valid": valid,
        "severity_score": score,
        "duplicate": duplicate,
        "duplicate_of": duplicate_of,
        "cannot_verify": False,
        "reasoning": reasoning,
    }


def _verdicts_agree(a, b):
    """Equivalence check for two structured triage verdicts.

    - If either side says cannot_verify, both must agree on it.
    - Otherwise `valid` must match exactly.
    - `duplicate` must match exactly.
    - `severity_score` must agree within +/- SCORE_TOLERANCE.
    Reasoning text is never compared, and `duplicate_of` is not
    compared either (two validators may point at different confirmed
    reports for the same duplicate; the settlement outcome is the
    same either way — the report is a duplicate and pays 0).
    """
    if a.get("cannot_verify") or b.get("cannot_verify"):
        return bool(a.get("cannot_verify")) == bool(b.get("cannot_verify"))
    if a.get("valid") != b.get("valid"):
        return False
    if a.get("duplicate") != b.get("duplicate"):
        return False
    return abs(int(a.get("severity_score", 0)) - int(b.get("severity_score", 0))) <= SCORE_TOLERANCE


def _band_for_score(score):
    """Severity band for a 0..100 score. < 20 is 'invalid'."""
    if score >= BAND_CRITICAL:
        return "critical"
    if score >= BAND_HIGH:
        return "high"
    if score >= BAND_MEDIUM:
        return "medium"
    if score >= BAND_LOW:
        return "low"
    return "invalid"


def _reward_for_band(bounty, band):
    """The bounty reward for a severity band, in atto. Invalid pays 0."""
    if band == "critical":
        return bounty.reward_critical
    if band == "high":
        return bounty.reward_high
    if band == "medium":
        return bounty.reward_medium
    if band == "low":
        return bounty.reward_low
    return 0


def _handle_leader_error(err):
    """Normalize a leader-side failure to one of the error-taxonomy strings.

    Already-prefixed errors pass through unchanged. HTTP 4xx / "not found" /
    "forbidden" become [EXTERNAL]; network and 5xx failures become
    [TRANSIENT]; anything unrecognized is treated as [TRANSIENT] (retryable)
    rather than failing the report permanently.
    """
    text = err if isinstance(err, str) else str(err)
    for prefix in (ERROR_EXPECTED, ERROR_EXTERNAL, ERROR_TRANSIENT, ERROR_LLM):
        if text.startswith(prefix):
            return text
    lowered = text.lower()
    if any(code in lowered for code in ("404", "403", "400", "401", "410", "not found", "forbidden", "gone")):
        return ERROR_EXTERNAL + " " + text
    if any(code in lowered for code in ("500", "502", "503", "504", "timeout", "timed out", "connection", "network", "temporarily", "unreachable")):
        return ERROR_TRANSIENT + " " + text
    return ERROR_TRANSIENT + " " + text


def _error_prefix(normalized):
    """Return the "[...]" prefix token of a normalized error string."""
    if "]" in normalized:
        return normalized[: normalized.index("]") + 1]
    return normalized


def _errors_agree(a, b):
    """Do two leader-side failures agree under the error taxonomy?

    - [LLM_ERROR] always disagrees (forces leader rotation).
    - [TRANSIENT] agrees with [TRANSIENT], whatever the wording.
    - [EXPECTED] / [EXTERNAL] must match exactly.
    """
    na = _handle_leader_error(a)
    nb = _handle_leader_error(b)
    pa = _error_prefix(na)
    pb = _error_prefix(nb)
    if pa == ERROR_LLM or pb == ERROR_LLM:
        return False
    if pa != pb:
        return False
    if pa == ERROR_TRANSIENT:
        return True
    return na == nb


def _validate_create_bounty(repo_url, scope, title, rewards, deadline, now):
    """Business-rule checks for create_bounty. Raises gl.vm.UserError."""
    if not repo_url or not repo_url.strip():
        raise gl.vm.UserError("repo_url must not be empty")
    if not (repo_url.startswith("http://") or repo_url.startswith("https://")):
        raise gl.vm.UserError("repo_url must be an http(s) URL")
    if not scope or not scope.strip():
        raise gl.vm.UserError("scope must not be empty")
    if not title or not title.strip():
        raise gl.vm.UserError("title must not be empty")
    for name, amount in rewards:
        if amount <= 0:
            raise gl.vm.UserError("reward_%s must be greater than zero" % name)
    if deadline <= now:
        raise gl.vm.UserError("deadline must be in the future")


def _require_status(record, *allowed):
    if record.status not in allowed:
        raise gl.vm.UserError(
            "record %d is '%s', expected one of %s"
            % (record.id, record.status, ", ".join(allowed))
        )


def _build_triage_prompt(bounty, report, confirmed, content):
    """The triage prompt: bounty scope + report + fetched code + confirmed
    reports, strict JSON out.

    The prompt is deliberately narrow — it asks for one JSON object and
    nothing else, so the verdict can be parsed and compared
    deterministically. The severity rubric is written into the prompt so
    every validator grades on the same scale.
    """
    if confirmed:
        confirmed_lines = "\n".join(
            "- report %d: %s (%s)" % (item["id"], item["title"], item["code_url"])
            for item in confirmed
        )
    else:
        confirmed_lines = "None yet — no confirmed reports for this bounty."
    trimmed = content[:MAX_TRIAGE_CONTENT_CHARS]
    return (
        "You are an expert security triage analyst for a bug bounty "
        "program. A researcher reported a vulnerability in a codebase. "
        "Read the fetched code below and decide whether the claimed flaw "
        "is really there, how severe it is, and whether it duplicates an "
        "already-confirmed report.\n\n"
        "BOUNTY:\n"
        "Repository: %s\n"
        "Scope: %s\n"
        "Title: %s\n\n"
        "ALREADY-CONFIRMED (paid) REPORTS FOR THIS BOUNTY — a report is a "
        "duplicate only if it is the same file AND the same root cause as "
        "one of these:\n%s\n\n"
        "REPORT TO TRIAGE:\n"
        "Title: %s\n"
        "Claimed severity: %s\n"
        "Description: %s\n"
        "Steps to reproduce: %s\n\n"
        "FETCHED CODE (from %s):\n%s\n\n"
        "Return ONLY a JSON object with exactly these fields, nothing else:\n"
        '{"valid": true or false, '
        '"severity_score": an integer 0-100, '
        '"duplicate": true or false, '
        '"duplicate_of": the confirmed report id it duplicates, or 0, '
        '"reasoning": a short explanation, '
        '"cannot_verify": true or false}\n\n'
        "Severity rubric — score the real impact of the flaw in this code:\n"
        "- critical (80-100): remote code execution, fund theft, auth "
        "bypass, unrestricted admin access.\n"
        "- high (60-79): secret or PII exposure, privilege escalation, "
        "fund loss that needs preconditions.\n"
        "- medium (40-59): limited impact, or an attack that needs "
        "unlikely preconditions.\n"
        "- low (20-39): minor impact, information disclosure, best "
        "practice.\n"
        "- invalid (0-19): not a real vulnerability in this code — set "
        "valid to false and severity_score to 0.\n\n"
        "Rules: valid is true only if the fetched code genuinely contains "
        "the claimed flaw. If the code is unreadable, unrelated to the "
        "report, or there is not enough evidence to judge, set "
        "cannot_verify to true, valid to false and severity_score to 0."
        % (
            bounty.repo_url,
            bounty.scope,
            bounty.title,
            confirmed_lines,
            report.title,
            report.claimed_severity,
            report.description,
            report.steps,
            report.code_url,
            trimmed,
        )
    )


# ---------------------------------------------------------------------------
# Storage records
# ---------------------------------------------------------------------------
@allow_storage
@dataclass
class Bounty:
    id: u256
    owner: Address
    repo_url: str
    scope: str
    title: str
    reward_critical: u256
    reward_high: u256
    reward_medium: u256
    reward_low: u256
    pool: u256
    deadline: u256
    status: str
    created_at: u256


@allow_storage
@dataclass
class Report:
    id: u256
    bounty_id: u256
    researcher: Address
    payout_wallet: str
    code_url: str
    title: str
    description: str
    steps: str
    claimed_severity: str
    status: str
    verdict: str
    severity_score: u256
    attempts: u256
    created_at: u256


# ---------------------------------------------------------------------------
# Payout interface (faucet pattern)
#
# Payouts are direct transfers of the GEN locked in the bounty pool by
# the payable create_bounty / top_up calls. The @gl.evm.contract_interface
# decorator provides emit_transfer: it takes only value=, and the
# destination is the address passed to the constructor. No methods are
# declared here — the nested View and Write classes are required by the
# decorator, and declaring emit_transfer (or any method) breaks schema
# generation in GenLayer Studio ("'IEscrowArbiter' has no attribute
# 'View'"). This contract never holds private keys and never pays out
# without a stored, consensus-reached verdict.
# ---------------------------------------------------------------------------
@gl.evm.contract_interface
class _PayoutTarget:
    class View:
        pass

    class Write:
        pass


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------
class VulnBounty(gl.Contract):
    owner: Address
    bounties: TreeMap[u256, Bounty]
    bounty_order: DynArray[u256]
    reports: TreeMap[u256, Report]
    report_order: DynArray[u256]
    counters: TreeMap[str, u256]
    total_paid_out_atto: u256
    total_refunded_atto: u256

    def __init__(self, owner_address: str):
        # The owner is passed in as a constructor argument on purpose:
        # reading the sender inside __init__ breaks deployment on
        # GenLayer Studio. When deploying, pass your own wallet address
        # as a hex string — GenLayer constructors never take Address
        # parameters, so it is converted to Address here.
        self.owner = Address(owner_address)
        self.counters["bounty_count"] = 0
        self.counters["report_count"] = 0
        self.counters["paid_count"] = 0
        self.counters["closed_count"] = 0
        self.total_paid_out_atto = 0
        self.total_refunded_atto = 0

    # -- internal -----------------------------------------------------------
    def _now(self) -> u256:
        # Transaction datetime, in Unix seconds. GenLayer exposes NO block
        # timestamp (docs: Transaction Context — "No block number, no block
        # hash"). Instead the stdlib clock is wired to the transaction
        # datetime, so datetime.now(timezone.utc) returns the same value
        # on every validator, and int(...timestamp()) is the documented
        # form for arithmetic / expiries. Deadlines are u256 Unix seconds,
        # so both sides of every deadline comparison are in seconds.
        return int(datetime.now(timezone.utc).timestamp())

    def _get_bounty(self, bounty_id: u256) -> Bounty:
        if bounty_id <= 0 or bounty_id > self.counters["bounty_count"]:
            raise gl.vm.UserError("bounty not found")
        return self.bounties[bounty_id]

    def _get_report(self, report_id: u256) -> Report:
        if report_id <= 0 or report_id > self.counters["report_count"]:
            raise gl.vm.UserError("report not found")
        return self.reports[report_id]

    def _pay(self, to: Address, amount: u256) -> None:
        if amount <= 0:
            return
        _PayoutTarget(to).emit_transfer(value=amount)

    def _confirmed_reports(self, bounty_id: u256):
        """Already-paid reports for a bounty, for duplicate detection.

        Only "paid" reports count as confirmed: a rejected or duplicate
        report is not a flaw anyone was paid for, so it cannot make a
        new report a duplicate.
        """
        out = []
        for report_id in self.report_order:
            report = self.reports[report_id]
            if report.bounty_id == bounty_id and report.status == "paid":
                out.append(
                    {
                        "id": report.id,
                        "code_url": report.code_url,
                        "title": report.title,
                    }
                )
        return out

    def _leader_triage(self, bounty: Bounty, report: Report, confirmed) -> str:
        """Fetch the code and triage the report. Runs on leader AND validators.

        Returns the normalized verdict as a sorted JSON string. Raises
        ValueError with an error-taxonomy prefix on any failure, so the
        validator side can classify and compare the failure.
        """
        try:
            content = gl.nondet.web.render(report.code_url, mode="text")
        except Exception as e:
            raise ValueError(_handle_leader_error(e))
        if not content or not content.strip():
            raise ValueError(ERROR_EXTERNAL + " code fetched but was empty")
        prompt = _build_triage_prompt(bounty, report, confirmed, content)
        try:
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
        except Exception as e:
            raise ValueError(ERROR_LLM + " exec_prompt failed: " + str(e))
        verdict = _parse_verdict(raw)
        return json.dumps(verdict, sort_keys=True)

    def _validate_triage(self, bounty: Bounty, report: Report, confirmed, leaders_res) -> bool:
        """Custom equivalence validator for the triage (see CONSENSUS.md).

        The validator receives a gl.vm.Result, not the raw verdict (docs:
        Non-determinism / Equivalence Principle, "Error Patterns for
        Consensus" — validator_fn(leaders_res: gl.vm.Result) -> bool):
        - gl.vm.Return: the leader succeeded; its verdict is on .calldata.
        - anything else (gl.vm.UserError / gl.vm.VMError): the leader
          failed; re-run the leader's work and compare the failure
          against the leader's message under the error taxonomy.
        On success it re-runs the leader's work and compares the
        STRUCTURED verdict — never the raw text, which two honest
        validators will word differently.
        """
        if not isinstance(leaders_res, gl.vm.Return):
            leader_msg = leaders_res.message if hasattr(leaders_res, "message") else ""
            try:
                self._leader_triage(bounty, report, confirmed)
            except Exception as e:
                return _errors_agree(leader_msg, e)
            return False
        try:
            mine = self._leader_triage(bounty, report, confirmed)
        except Exception:
            return False
        try:
            theirs = _parse_verdict(leaders_res.calldata)
            mine_v = _parse_verdict(mine)
        except Exception:
            return False
        return _verdicts_agree(theirs, mine_v)

    def _run_triage(self, bounty: Bounty, report: Report, confirmed) -> str:
        """Run the leader/validator consensus for one triage."""
        def leader_fn():
            return self._leader_triage(bounty, report, confirmed)

        def validator_fn(leaders_res):
            return self._validate_triage(bounty, report, confirmed, leaders_res)

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

    # -- bounty lifecycle ---------------------------------------------------
    @gl.public.write.payable
    def create_bounty(
        self,
        repo_url: str,
        scope: str,
        title: str,
        reward_critical: u256,
        reward_high: u256,
        reward_medium: u256,
        reward_low: u256,
        deadline: u256,
    ) -> dict:
        """Fund a bug bounty pool. The attached GEN is the pool; the
        caller becomes the bounty owner and may top it up or close it."""
        owner = gl.message.sender_address
        amount = gl.message.value
        if amount <= 0:
            raise gl.vm.UserError("bounty pool must be greater than zero")
        _validate_create_bounty(
            repo_url,
            scope,
            title,
            [
                ("critical", reward_critical),
                ("high", reward_high),
                ("medium", reward_medium),
                ("low", reward_low),
            ],
            deadline,
            self._now(),
        )
        bounty_id = self.counters["bounty_count"] + 1
        self.counters["bounty_count"] = bounty_id
        bounty = Bounty(
            id=bounty_id,
            owner=owner,
            repo_url=repo_url,
            scope=scope,
            title=title,
            reward_critical=reward_critical,
            reward_high=reward_high,
            reward_medium=reward_medium,
            reward_low=reward_low,
            pool=amount,
            deadline=deadline,
            status="open",
            created_at=self._now(),
        )
        self.bounties[bounty_id] = bounty
        self.bounty_order.append(bounty_id)
        return {"bounty_id": bounty_id, "status": "open", "pool_atto": amount}

    @gl.public.write.payable
    def top_up(self, bounty_id: u256) -> dict:
        """Add GEN to an open bounty pool. Anyone may call it."""
        bounty = self._get_bounty(bounty_id)
        if bounty.status != "open":
            raise gl.vm.UserError("bounty is not open")
        amount = gl.message.value
        if amount <= 0:
            raise gl.vm.UserError("top-up amount must be greater than zero")
        bounty.pool = bounty.pool + amount
        self.bounties[bounty_id] = bounty
        return {"bounty_id": bounty_id, "pool_atto": bounty.pool}

    @gl.public.write
    def submit_report(
        self,
        bounty_id: u256,
        code_url: str,
        title: str,
        description: str,
        steps: str,
        claimed_severity: str,
        payout_wallet: str,
    ) -> dict:
        """Submit a vulnerability report against an open bounty, before
        its deadline. The researcher is the caller; the payout wallet is
        a hex string (GenLayer public methods never take Address
        parameters) and is converted to Address at payout time."""
        bounty = self._get_bounty(bounty_id)
        if bounty.status != "open":
            raise gl.vm.UserError("bounty is not open")
        if self._now() >= bounty.deadline:
            raise gl.vm.UserError("bounty deadline has passed")
        if claimed_severity not in ("critical", "high", "medium", "low"):
            raise gl.vm.UserError(
                "claimed_severity must be one of critical, high, medium, low"
            )
        if not code_url or not code_url.strip():
            raise gl.vm.UserError("code_url must not be empty")
        if not (code_url.startswith("http://") or code_url.startswith("https://")):
            raise gl.vm.UserError("code_url must be an http(s) URL")
        if not title or not title.strip():
            raise gl.vm.UserError("title must not be empty")
        if not description or not description.strip():
            raise gl.vm.UserError("description must not be empty")
        if not payout_wallet or not payout_wallet.strip():
            raise gl.vm.UserError("payout_wallet must not be empty")
        report_id = self.counters["report_count"] + 1
        self.counters["report_count"] = report_id
        report = Report(
            id=report_id,
            bounty_id=bounty_id,
            researcher=gl.message.sender_address,
            payout_wallet=payout_wallet,
            code_url=code_url,
            title=title,
            description=description,
            steps=steps,
            claimed_severity=claimed_severity,
            status="reported",
            verdict="",
            severity_score=0,
            attempts=0,
            created_at=self._now(),
        )
        self.reports[report_id] = report
        self.report_order.append(report_id)
        return {"report_id": report_id, "status": "reported"}

    @gl.public.write
    def request_triage(self, report_id: u256) -> dict:
        """Anyone may call once a report exists. Runs validator consensus.

        On a reached verdict the report becomes "triaged" with the
        verdict and severity score stored. On a cannot_verify verdict,
        or a leader-side failure the validators agree is
        transient/external, the attempt is counted and the report stays
        open ("reported") until the 3rd failure, when it becomes
        "unverifiable" and nobody is paid. A report that never reaches
        consensus at all is not stuck forever: expire_report (below)
        closes it deterministically after 3 days.
        """
        report = self._get_report(report_id)
        _require_status(report, "reported")
        if report.attempts >= MAX_TRIAGE_ATTEMPTS:
            raise gl.vm.UserError("triage attempts exhausted")
        bounty = self._get_bounty(report.bounty_id)
        confirmed = self._confirmed_reports(report.bounty_id)
        try:
            verdict_json = self._run_triage(bounty, report, confirmed)
        except Exception as e:
            normalized = _handle_leader_error(e)
            report.attempts = report.attempts + 1
            if report.attempts >= MAX_TRIAGE_ATTEMPTS:
                report.status = "unverifiable"
            self.reports[report_id] = report
            return {
                "report_id": report_id,
                "status": report.status,
                "attempts": report.attempts,
                "error": normalized,
            }
        verdict = _parse_verdict(verdict_json)
        report.verdict = json.dumps(verdict, sort_keys=True)
        report.severity_score = verdict["severity_score"]
        report.attempts = report.attempts + 1
        if verdict["cannot_verify"]:
            if report.attempts >= MAX_TRIAGE_ATTEMPTS:
                report.status = "unverifiable"
            else:
                report.status = "reported"
            self.reports[report_id] = report
            return {
                "report_id": report_id,
                "status": report.status,
                "attempts": report.attempts,
                "cannot_verify": True,
            }
        report.status = "triaged"
        self.reports[report_id] = report
        return {
            "report_id": report_id,
            "status": "triaged",
            "valid": verdict["valid"],
            "duplicate": verdict["duplicate"],
            "severity_score": verdict["severity_score"],
        }

    @gl.public.write
    def expire_report(self, report_id: u256) -> dict:
        """Deterministic escape for a report that never gets triaged.

        Anyone may call it once the report has sat "reported" for more
        than 3 days (259200 seconds) with no triage. This is the fix for
        the hole found in DeliveryEscrow: a failed consensus writes
        nothing on-chain, so an attempt-based escape can never fire when
        consensus itself fails — the escape has to be time-based, using
        the transaction datetime, which every validator sees identically.
        The report becomes "unverifiable" and nobody is paid.
        """
        report = self._get_report(report_id)
        _require_status(report, "reported")
        if self._now() <= report.created_at + EXPIRE_AFTER_SECONDS:
            raise gl.vm.UserError(
                "report is not yet expirable; 3 days must pass with no triage"
            )
        report.status = "unverifiable"
        self.reports[report_id] = report
        return {"report_id": report_id, "status": "unverifiable"}

    @gl.public.write
    def settle(self, report_id: u256) -> dict:
        """Settle deterministically from the stored verdict. Once only.

        No LLM call happens here: the verdict was already agreed by
        consensus in request_triage, so settlement is pure arithmetic
        on the stored score. Duplicate reports and invalid reports pay
        0. A valid report pays its severity-band reward from the bounty
        pool; if the pool is short, settlement fails and the bounty
        owner must top it up first.
        """
        report = self._get_report(report_id)
        _require_status(report, "triaged")
        verdict = _parse_verdict(report.verdict)
        bounty = self._get_bounty(report.bounty_id)
        if verdict["duplicate"]:
            report.status = "duplicate"
            self.reports[report_id] = report
            return {"report_id": report_id, "status": "duplicate", "paid_atto": 0}
        band = _band_for_score(report.severity_score)
        if band == "invalid":
            report.status = "rejected"
            self.reports[report_id] = report
            return {"report_id": report_id, "status": "rejected", "paid_atto": 0}
        reward = _reward_for_band(bounty, band)
        if bounty.pool < reward:
            raise gl.vm.UserError(
                "bounty pool (%d atto) is below the %s reward (%d atto); "
                "the bounty owner must top up the bounty"
                % (bounty.pool, band, reward)
            )
        self._pay(Address(report.payout_wallet), reward)
        bounty.pool = bounty.pool - reward
        self.bounties[bounty.id] = bounty
        self.total_paid_out_atto = self.total_paid_out_atto + reward
        self.counters["paid_count"] = self.counters["paid_count"] + 1
        report.status = "paid"
        self.reports[report_id] = report
        return {
            "report_id": report_id,
            "status": "paid",
            "band": band,
            "paid_atto": reward,
        }

    @gl.public.write
    def close_bounty(self, bounty_id: u256) -> dict:
        """Bounty-owner-only close. Requires no reports still waiting for
        a decision ("reported" or "triaged"). Refunds the remaining pool
        to the bounty owner and closes the bounty. Reports that ended
        "unverifiable" do not block closing."""
        bounty = self._get_bounty(bounty_id)
        if gl.message.sender_address != bounty.owner:
            raise gl.vm.UserError("only the bounty owner can close it")
        if bounty.status != "open":
            raise gl.vm.UserError("bounty is not open")
        for report_id in self.report_order:
            report = self.reports[report_id]
            if report.bounty_id == bounty_id and report.status in ("reported", "triaged"):
                raise gl.vm.UserError(
                    "bounty has undecided reports; triage and settle them first"
                )
        refund = bounty.pool
        if refund > 0:
            self._pay(bounty.owner, refund)
            self.total_refunded_atto = self.total_refunded_atto + refund
        bounty.pool = 0
        bounty.status = "closed"
        self.bounties[bounty_id] = bounty
        self.counters["closed_count"] = self.counters["closed_count"] + 1
        return {"bounty_id": bounty_id, "status": "closed", "refunded_atto": refund}

    # -- views --------------------------------------------------------------
    @gl.public.view
    def get_bounty(self, bounty_id: u256) -> dict:
        return _bounty_to_dict(self._get_bounty(bounty_id))

    @gl.public.view
    def list_bounties(self, offset: u256, limit: u256) -> dict:
        """Paginated list (max 100 per call), oldest first."""
        total = self.counters["bounty_count"]
        if limit > 100:
            limit = 100
        end = offset + limit
        if end > total:
            end = total
        out = []
        i = offset + 1
        while i <= end:
            out.append(_bounty_to_dict(self.bounties[i]))
            i = i + 1
        return {"total": total, "offset": offset, "bounties": out}

    @gl.public.view
    def get_report(self, report_id: u256) -> dict:
        return _report_to_dict(self._get_report(report_id))

    @gl.public.view
    def list_reports(self, offset: u256, limit: u256) -> dict:
        """Paginated list (max 100 per call), oldest first."""
        total = self.counters["report_count"]
        if limit > 100:
            limit = 100
        end = offset + limit
        if end > total:
            end = total
        out = []
        i = offset + 1
        while i <= end:
            out.append(_report_to_dict(self.reports[i]))
            i = i + 1
        return {"total": total, "offset": offset, "reports": out}

    @gl.public.view
    def get_stats(self) -> dict:
        """Counts by report status, GEN currently locked in open bounty
        pools, and GEN paid/refunded."""
        counts = {
            "reported": 0,
            "triaged": 0,
            "paid": 0,
            "rejected": 0,
            "duplicate": 0,
            "unverifiable": 0,
        }
        locked = 0
        for bounty_id in self.bounty_order:
            bounty = self.bounties[bounty_id]
            if bounty.status == "open":
                locked = locked + bounty.pool
        for report_id in self.report_order:
            report = self.reports[report_id]
            if report.status in counts:
                counts[report.status] = counts[report.status] + 1
        return {
            "total_bounties": self.counters["bounty_count"],
            "total_reports": self.counters["report_count"],
            "reports_by_status": counts,
            "total_pool_locked_atto": locked,
            "total_paid_out_atto": self.total_paid_out_atto,
            "total_refunded_atto": self.total_refunded_atto,
        }


def _bounty_to_dict(bounty: Bounty) -> dict:
    """Public-safe serialization of a bounty."""
    return {
        "id": bounty.id,
        "owner": bounty.owner,
        "repo_url": bounty.repo_url,
        "scope": bounty.scope,
        "title": bounty.title,
        "reward_critical": bounty.reward_critical,
        "reward_high": bounty.reward_high,
        "reward_medium": bounty.reward_medium,
        "reward_low": bounty.reward_low,
        "pool": bounty.pool,
        "deadline": bounty.deadline,
        "status": bounty.status,
        "created_at": bounty.created_at,
    }


def _report_to_dict(report: Report) -> dict:
    """Public-safe serialization of a report."""
    return {
        "id": report.id,
        "bounty_id": report.bounty_id,
        "researcher": report.researcher,
        "payout_wallet": report.payout_wallet,
        "code_url": report.code_url,
        "title": report.title,
        "description": report.description,
        "steps": report.steps,
        "claimed_severity": report.claimed_severity,
        "status": report.status,
        "verdict": report.verdict,
        "severity_score": report.severity_score,
        "attempts": report.attempts,
        "created_at": report.created_at,
    }
