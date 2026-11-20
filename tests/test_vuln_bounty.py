"""Tests for VulnBounty's pure helpers and its lifecycle (stubbed GenVM).

Run: python3 -m pytest tests/ -q
"""
import json

import pytest

from conftest import (
    CREATOR,
    NOW,
    ONE_GEN,
    OWNER,
    PAYOUT,
    RESEARCHER,
    RESEARCHER2,
    SECURE_CODE_URL,
    VULN_CODE_URL,
    cannot_verify_verdict,
    critical_verdict,
    duplicate_verdict,
    invalid_verdict,
    record_transfers,
    set_now,
    set_sender,
    stub_triage,
    stub_triage_sequence,
    vuln_bounty,
)

m = vuln_bounty  # the contract module
UserError = vuln_bounty.gl.vm.UserError


def _make_bounty(contract, gl, value=10 * ONE_GEN, deadline=NOW + 7 * 86_400):
    set_sender(gl, CREATOR, value)
    bounty_id = contract.create_bounty(
        "https://github.com/example/shop",
        "Python web app in shop/",
        "Shop web app bounty",
        4 * ONE_GEN,
        2 * ONE_GEN,
        1 * ONE_GEN,
        ONE_GEN // 4,
        deadline,
    )["bounty_id"]
    set_sender(gl, CREATOR, 0)
    return bounty_id


def _make_report(contract, gl, bounty_id, code_url=VULN_CODE_URL, severity="critical",
                 sender=RESEARCHER, payout=PAYOUT, title="RCE via eval()"):
    set_sender(gl, sender)
    report_id = contract.submit_report(
        bounty_id,
        code_url,
        title,
        "run_command passes user input straight to eval().",
        "1. Send GET /run?cmd=__import__('os').system('id')",
        severity,
        payout,
    )["report_id"]
    set_sender(gl, sender, 0)
    return report_id


# ---------------------------------------------------------------------------
# Severity bands and rewards
# ---------------------------------------------------------------------------
class TestSeverityBands:
    @pytest.mark.parametrize(
        "score,band",
        [
            (100, "critical"),
            (80, "critical"),   # boundary: critical
            (79, "high"),
            (60, "high"),       # boundary: high
            (59, "medium"),
            (40, "medium"),     # boundary: medium
            (39, "low"),
            (20, "low"),        # boundary: low
            (19, "invalid"),
            (0, "invalid"),
        ],
    )
    def test_bands(self, score, band):
        assert m._band_for_score(score) == band

    def test_rewards_map_to_bounty_fields(self, contract, gl, bounty):
        b = contract.get_bounty(bounty)
        assert m._reward_for_band(contract.bounties[bounty], "critical") == 4 * ONE_GEN
        assert m._reward_for_band(contract.bounties[bounty], "high") == 2 * ONE_GEN
        assert m._reward_for_band(contract.bounties[bounty], "medium") == 1 * ONE_GEN
        assert m._reward_for_band(contract.bounties[bounty], "low") == ONE_GEN // 4
        assert m._reward_for_band(contract.bounties[bounty], "invalid") == 0


# ---------------------------------------------------------------------------
# Score coercion
# ---------------------------------------------------------------------------
class TestCoerceScore:
    def test_int(self):
        assert m._coerce_score(85) == 85

    def test_float_rounds(self):
        assert m._coerce_score(82.6) == 83

    def test_string_with_percent(self):
        assert m._coerce_score(" 77% ") == 77

    def test_bool_rejected(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._coerce_score(True)

    def test_non_numeric_rejected(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._coerce_score("high")

    def test_above_range_rejected(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._coerce_score(101)

    def test_below_range_rejected(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._coerce_score(-1)


# ---------------------------------------------------------------------------
# Verdict parsing
# ---------------------------------------------------------------------------
class TestParseVerdict:
    def test_valid_json(self):
        v = m._parse_verdict(
            '{"valid": true, "severity_score": 92, "duplicate": false, '
            '"duplicate_of": 0, "reasoning": "RCE", "cannot_verify": false}'
        )
        assert v == {
            "valid": True,
            "severity_score": 92,
            "duplicate": False,
            "duplicate_of": 0,
            "cannot_verify": False,
            "reasoning": "RCE",
        }

    def test_dict_input_accepted(self):
        v = m._parse_verdict({"valid": True, "severity_score": 70})
        assert v["valid"] is True and v["severity_score"] == 70
        assert v["duplicate"] is False and v["duplicate_of"] == 0

    def test_alias_keys(self):
        assert m._parse_verdict('{"valid": true, "score": 71}')["severity_score"] == 71
        assert m._parse_verdict('{"valid": true, "severity": 64}')["severity_score"] == 64
        assert m._parse_verdict('{"valid": true, "rating": 55}')["severity_score"] == 55

    def test_string_booleans(self):
        v = m._parse_verdict('{"valid": "yes", "severity_score": 60, "duplicate": "true", "duplicate_of": "2"}')
        assert v["valid"] is True and v["duplicate"] is True and v["duplicate_of"] == 2

    def test_cannot_verify_normalizes(self):
        v = m._parse_verdict(cannot_verify_verdict())
        assert v == {
            "valid": False,
            "severity_score": 0,
            "duplicate": False,
            "duplicate_of": 0,
            "cannot_verify": True,
            "reasoning": "code unreadable",
        }

    def test_invalid_forces_score_zero(self):
        # An invalid report must never smuggle a payout score with it.
        v = m._parse_verdict('{"valid": false, "severity_score": 70}')
        assert v["valid"] is False and v["severity_score"] == 0

    def test_duplicate_fields(self):
        v = m._parse_verdict(duplicate_verdict(3))
        assert v["duplicate"] is True and v["duplicate_of"] == 3

    def test_missing_valid_raises(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._parse_verdict('{"severity_score": 80}')

    def test_missing_score_raises(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._parse_verdict('{"valid": true}')

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._parse_verdict("not json at all")

    def test_list_json_raises(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._parse_verdict("[1, 2, 3]")

    def test_score_out_of_range_raises(self):
        with pytest.raises(ValueError, match=r"\[LLM_ERROR\]"):
            m._parse_verdict('{"valid": true, "severity_score": 150}')

    def test_duplicate_of_negative_becomes_zero(self):
        v = m._parse_verdict(
            '{"valid": true, "severity_score": 90, "duplicate": true, "duplicate_of": -5}'
        )
        assert v["duplicate_of"] == 0


# ---------------------------------------------------------------------------
# Verdict agreement
# ---------------------------------------------------------------------------
class TestVerdictsAgree:
    def test_identical_agree(self):
        a = m._parse_verdict(critical_verdict(90))
        b = m._parse_verdict(critical_verdict(90))
        assert m._verdicts_agree(a, b)

    def test_score_diff_10_agrees(self):
        a = m._parse_verdict(critical_verdict(80))
        b = m._parse_verdict(critical_verdict(90))
        assert m._verdicts_agree(a, b)

    def test_score_diff_11_disagrees(self):
        a = m._parse_verdict(critical_verdict(79))
        b = m._parse_verdict(critical_verdict(90))
        assert not m._verdicts_agree(a, b)

    def test_valid_differs_disagrees(self):
        a = m._parse_verdict(critical_verdict(90))
        b = m._parse_verdict(invalid_verdict())
        assert not m._verdicts_agree(a, b)

    def test_duplicate_differs_disagrees(self):
        a = m._parse_verdict(critical_verdict(90))
        b = m._parse_verdict(duplicate_verdict(1))
        assert not m._verdicts_agree(a, b)

    def test_cannot_verify_both_agree(self):
        a = m._parse_verdict(cannot_verify_verdict())
        b = m._parse_verdict(cannot_verify_verdict())
        assert m._verdicts_agree(a, b)

    def test_cannot_verify_one_side_disagrees(self):
        a = m._parse_verdict(cannot_verify_verdict())
        b = m._parse_verdict(critical_verdict(90))
        assert not m._verdicts_agree(a, b)

    def test_reasoning_ignored(self):
        a = m._parse_verdict(critical_verdict(90))
        b = dict(a)
        b["reasoning"] = "completely different words, same conclusion"
        assert m._verdicts_agree(a, b)

    def test_duplicate_of_ignored(self):
        a = m._parse_verdict(duplicate_verdict(1))
        b = m._parse_verdict(duplicate_verdict(2))
        assert m._verdicts_agree(a, b)


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------
class TestErrorTaxonomy:
    def test_prefixed_passthrough(self):
        assert m._handle_leader_error("[TRANSIENT] boom") == "[TRANSIENT] boom"

    def test_404_is_external(self):
        assert m._handle_leader_error("HTTP 404 not found").startswith("[EXTERNAL]")

    def test_500_is_transient(self):
        assert m._handle_leader_error("HTTP 500 server error").startswith("[TRANSIENT]")

    def test_timeout_is_transient(self):
        assert m._handle_leader_error("connection timed out").startswith("[TRANSIENT]")

    def test_unknown_is_transient(self):
        assert m._handle_leader_error("something odd happened").startswith("[TRANSIENT]")

    def test_llm_error_always_disagrees(self):
        assert not m._errors_agree("[LLM_ERROR] bad json", "[LLM_ERROR] bad json")

    def test_transient_agrees_with_transient(self):
        assert m._errors_agree("HTTP 500", "gateway timeout")

    def test_expected_exact_match(self):
        assert m._errors_agree("[EXPECTED] x", "[EXPECTED] x")
        assert not m._errors_agree("[EXPECTED] x", "[EXPECTED] y")

    def test_external_exact_match(self):
        assert m._errors_agree("[EXTERNAL] 404", "[EXTERNAL] 404")
        assert not m._errors_agree("[EXTERNAL] 404", "[EXTERNAL] 403")


# ---------------------------------------------------------------------------
# Bounty creation
# ---------------------------------------------------------------------------
class TestCreateBounty:
    def test_success_fields(self, contract, gl):
        set_sender(gl, CREATOR, 10 * ONE_GEN)
        res = contract.create_bounty(
            "https://github.com/example/shop",
            "shop/ web app",
            "Shop bounty",
            4 * ONE_GEN, 2 * ONE_GEN, 1 * ONE_GEN, ONE_GEN // 4,
            NOW + 7 * 86_400,
        )
        assert res == {"bounty_id": 1, "status": "open", "pool_atto": 10 * ONE_GEN}
        b = contract.get_bounty(1)
        assert b["owner"] == CREATOR
        assert b["pool"] == 10 * ONE_GEN
        assert b["status"] == "open"
        assert b["deadline"] == NOW + 7 * 86_400
        assert b["reward_critical"] == 4 * ONE_GEN
        assert b["reward_low"] == ONE_GEN // 4

    def test_ids_increment(self, contract, gl, bounty):
        assert _make_bounty(contract, gl, value=1 * ONE_GEN) == 2

    def test_zero_value_raises(self, contract, gl):
        set_sender(gl, CREATOR, 0)
        with pytest.raises(UserError, match="greater than zero"):
            contract.create_bounty(
                "https://github.com/example/shop", "scope", "t",
                1, 1, 1, 1, NOW + 100,
            )

    @pytest.mark.parametrize("field", ["repo_url", "scope", "title"])
    def test_empty_string_raises(self, contract, gl, field):
        kwargs = {
            "repo_url": "https://github.com/example/shop",
            "scope": "scope",
            "title": "t",
        }
        kwargs[field] = "   "
        set_sender(gl, CREATOR, 1 * ONE_GEN)
        with pytest.raises(UserError):
            contract.create_bounty(
                kwargs["repo_url"], kwargs["scope"], kwargs["title"],
                1, 1, 1, 1, NOW + 100,
            )

    def test_non_http_repo_url_raises(self, contract, gl):
        set_sender(gl, CREATOR, 1 * ONE_GEN)
        with pytest.raises(UserError, match="http"):
            contract.create_bounty(
                "git@github.com:example/shop.git", "scope", "t",
                1, 1, 1, 1, NOW + 100,
            )

    @pytest.mark.parametrize("tier", [0, 1, 2, 3])
    def test_zero_reward_raises(self, contract, gl, tier):
        rewards = [1, 1, 1, 1]
        rewards[tier] = 0
        set_sender(gl, CREATOR, 1 * ONE_GEN)
        with pytest.raises(UserError, match="reward_"):
            contract.create_bounty(
                "https://github.com/example/shop", "scope", "t",
                *rewards, NOW + 100,
            )

    def test_deadline_now_raises(self, contract, gl):
        set_sender(gl, CREATOR, 1 * ONE_GEN)
        with pytest.raises(UserError, match="future"):
            contract.create_bounty(
                "https://github.com/example/shop", "scope", "t",
                1, 1, 1, 1, NOW,
            )

    def test_deadline_past_raises(self, contract, gl):
        set_sender(gl, CREATOR, 1 * ONE_GEN)
        with pytest.raises(UserError, match="future"):
            contract.create_bounty(
                "https://github.com/example/shop", "scope", "t",
                1, 1, 1, 1, NOW - 1,
            )


# ---------------------------------------------------------------------------
# Top-up
# ---------------------------------------------------------------------------
class TestTopUp:
    def test_top_up_adds_to_pool(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER, 2 * ONE_GEN)
        res = contract.top_up(bounty)
        assert res == {"bounty_id": bounty, "pool_atto": 12 * ONE_GEN}
        assert contract.get_bounty(bounty)["pool"] == 12 * ONE_GEN

    def test_zero_value_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER, 0)
        with pytest.raises(UserError, match="greater than zero"):
            contract.top_up(bounty)

    def test_nonexistent_bounty_raises(self, contract, gl):
        set_sender(gl, RESEARCHER, 1 * ONE_GEN)
        with pytest.raises(UserError, match="not found"):
            contract.top_up(99)

    def test_closed_bounty_raises(self, contract, gl, bounty):
        set_sender(gl, CREATOR)
        contract.close_bounty(bounty)
        set_sender(gl, RESEARCHER, 1 * ONE_GEN)
        with pytest.raises(UserError, match="not open"):
            contract.top_up(bounty)


# ---------------------------------------------------------------------------
# Report submission
# ---------------------------------------------------------------------------
class TestSubmitReport:
    def test_success_fields(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        res = contract.submit_report(
            bounty, VULN_CODE_URL, "RCE via eval()", "desc", "steps",
            "critical", PAYOUT,
        )
        assert res == {"report_id": 1, "status": "reported"}
        r = contract.get_report(1)
        assert r["bounty_id"] == bounty
        assert r["researcher"] == RESEARCHER
        assert r["payout_wallet"] == PAYOUT
        assert r["claimed_severity"] == "critical"
        assert r["status"] == "reported"
        assert r["attempts"] == 0
        assert r["severity_score"] == 0
        assert r["created_at"] == NOW

    def test_ids_increment(self, contract, gl, bounty):
        assert _make_report(contract, gl, bounty) == 1
        assert _make_report(contract, gl, bounty, sender=RESEARCHER2) == 2

    def test_closed_bounty_raises(self, contract, gl, bounty):
        set_sender(gl, CREATOR)
        contract.close_bounty(bounty)
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="not open"):
            contract.submit_report(
                bounty, VULN_CODE_URL, "t", "d", "s", "low", PAYOUT
            )

    def test_after_deadline_raises(self, contract, gl, bounty):
        set_now(NOW + 7 * 86_400)
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="deadline has passed"):
            contract.submit_report(
                bounty, VULN_CODE_URL, "t", "d", "s", "low", PAYOUT
            )

    def test_at_deadline_raises(self, contract, gl, bounty):
        set_now(NOW + 7 * 86_400 - 1)
        set_sender(gl, RESEARCHER)
        contract.submit_report(bounty, VULN_CODE_URL, "t", "d", "s", "low", PAYOUT)
        assert contract.get_report(1)["status"] == "reported"

    def test_bad_severity_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="claimed_severity"):
            contract.submit_report(
                bounty, VULN_CODE_URL, "t", "d", "s", "urgent", PAYOUT
            )

    def test_empty_code_url_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="code_url"):
            contract.submit_report(bounty, "  ", "t", "d", "s", "low", PAYOUT)

    def test_non_http_code_url_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="http"):
            contract.submit_report(
                bounty, "file:///tmp/app.py", "t", "d", "s", "low", PAYOUT
            )

    def test_empty_title_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="title"):
            contract.submit_report(bounty, VULN_CODE_URL, "", "d", "s", "low", PAYOUT)

    def test_empty_description_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="description"):
            contract.submit_report(bounty, VULN_CODE_URL, "t", "", "s", "low", PAYOUT)

    def test_empty_payout_wallet_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="payout_wallet"):
            contract.submit_report(bounty, VULN_CODE_URL, "t", "d", "s", "low", "")

    def test_nonexistent_bounty_raises(self, contract, gl):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="not found"):
            contract.submit_report(99, VULN_CODE_URL, "t", "d", "s", "low", PAYOUT)


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------
class TestRequestTriage:
    def test_critical_verdict_triaged(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(92))
        res = contract.request_triage(report)
        assert res["status"] == "triaged"
        assert res["valid"] is True
        assert res["duplicate"] is False
        assert res["severity_score"] == 92
        r = contract.get_report(report)
        assert r["status"] == "triaged"
        assert r["severity_score"] == 92
        assert r["attempts"] == 1
        assert json.loads(r["verdict"])["reasoning"] == "eval on user input is RCE"

    def test_high_verdict_triaged(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(70))
        res = contract.request_triage(report)
        assert res["status"] == "triaged" and res["severity_score"] == 70

    def test_duplicate_verdict_triaged(self, contract, gl, bounty, report):
        stub_triage(gl, duplicate_verdict(0))
        res = contract.request_triage(report)
        assert res["status"] == "triaged" and res["duplicate"] is True

    def test_invalid_verdict_triaged(self, contract, gl, bounty, report):
        stub_triage(gl, invalid_verdict())
        res = contract.request_triage(report)
        assert res["status"] == "triaged"
        assert res["valid"] is False and res["severity_score"] == 0

    def test_cannot_verify_stays_reported(self, contract, gl, bounty, report):
        stub_triage(gl, cannot_verify_verdict())
        res = contract.request_triage(report)
        assert res == {
            "report_id": report, "status": "reported",
            "attempts": 1, "cannot_verify": True,
        }
        assert contract.get_report(report)["status"] == "reported"

    def test_third_cannot_verify_unverifiable(self, contract, gl, bounty, report):
        stub_triage(gl, cannot_verify_verdict())
        for _ in range(2):
            contract.request_triage(report)
        res = contract.request_triage(report)
        assert res["status"] == "unverifiable" and res["attempts"] == 3
        assert contract.get_report(report)["status"] == "unverifiable"

    def test_fetch_failure_counts_attempt(self, contract, gl, bounty, report):
        gl.nondet.web.render = staticmethod(
            lambda url, mode="text": (_ for _ in ()).throw(
                RuntimeError("HTTP 404 not found")
            )
        )
        res = contract.request_triage(report)
        assert res["status"] == "reported" and res["attempts"] == 1
        assert res["error"].startswith("[EXTERNAL]")

    def test_third_fetch_failure_unverifiable(self, contract, gl, bounty, report):
        gl.nondet.web.render = staticmethod(
            lambda url, mode="text": (_ for _ in ()).throw(
                RuntimeError("connection timed out")
            )
        )
        for _ in range(2):
            contract.request_triage(report)
        res = contract.request_triage(report)
        assert res["status"] == "unverifiable" and res["attempts"] == 3
        assert res["error"].startswith("[TRANSIENT]")

    def test_consensus_disagreement_counts_attempt(self, contract, gl, bounty, report):
        stub_triage_sequence(gl, [critical_verdict(90), critical_verdict(50)])
        res = contract.request_triage(report)
        assert res["status"] == "reported" and res["attempts"] == 1
        assert res["error"].startswith("[TRANSIENT]")

    def test_triage_non_reported_raises(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(92))
        contract.request_triage(report)
        with pytest.raises(UserError, match="expected one of"):
            contract.request_triage(report)

    def test_triage_nonexistent_raises(self, contract, gl):
        with pytest.raises(UserError, match="not found"):
            contract.request_triage(99)

    def test_prompt_includes_confirmed_reports(self, contract, gl, bounty):
        # Build a confirmed (paid) report, then check the next triage
        # prompt names it — that is how duplicate detection gets its input.
        set_sender(gl, RESEARCHER)
        stub_triage(gl, critical_verdict(92))
        first = contract.submit_report(
            bounty, VULN_CODE_URL, "RCE via eval()", "desc", "steps",
            "critical", PAYOUT,
        )["report_id"]
        contract.request_triage(first)
        contract.settle(first)
        bounty_rec = contract.bounties[bounty]
        report_rec = contract.reports[first]
        confirmed = contract._confirmed_reports(bounty)
        assert len(confirmed) == 1 and confirmed[0]["id"] == first
        prompt = m._build_triage_prompt(
            bounty_rec, report_rec, confirmed, "def run_command(cmd): return eval(cmd)"
        )
        assert "report %d" % first in prompt
        assert "RCE via eval()" in prompt
        assert VULN_CODE_URL in prompt

    def test_prompt_includes_rubric(self, contract, gl, bounty, report):
        prompt = m._build_triage_prompt(
            contract.bounties[bounty], contract.reports[report], [], "code"
        )
        assert "unrestricted admin" in prompt
        assert "remote code execution" in prompt.lower()
        assert "secret or PII exposure" in prompt
        assert "cannot_verify" in prompt


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------
class TestExpireReport:
    def test_expire_after_three_days(self, contract, gl, bounty, report):
        set_now(NOW + 259200 + 1)
        res = contract.expire_report(report)
        assert res == {"report_id": report, "status": "unverifiable"}
        assert contract.get_report(report)["status"] == "unverifiable"

    def test_before_three_days_raises(self, contract, gl, bounty, report):
        set_now(NOW + 86_400)
        with pytest.raises(UserError, match="not yet expirable"):
            contract.expire_report(report)

    def test_exactly_three_days_raises(self, contract, gl, bounty, report):
        set_now(NOW + 259200)
        with pytest.raises(UserError, match="not yet expirable"):
            contract.expire_report(report)

    def test_triaged_report_raises(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(92))
        contract.request_triage(report)
        set_now(NOW + 259200 + 1)
        with pytest.raises(UserError, match="expected one of"):
            contract.expire_report(report)

    def test_nonexistent_raises(self, contract, gl):
        with pytest.raises(UserError, match="not found"):
            contract.expire_report(99)


# ---------------------------------------------------------------------------
# Settlement
# ---------------------------------------------------------------------------
class TestSettle:
    def _triaged(self, contract, gl, bounty, report, verdict):
        stub_triage(gl, verdict)
        contract.request_triage(report)

    def test_critical_pays_full_reward(self, contract, gl, bounty, report, monkeypatch):
        calls = record_transfers(monkeypatch)
        self._triaged(contract, gl, bounty, report, critical_verdict(92))
        res = contract.settle(report)
        assert res == {
            "report_id": report, "status": "paid",
            "band": "critical", "paid_atto": 4 * ONE_GEN,
        }
        assert calls == [(PAYOUT, 4 * ONE_GEN)]
        assert contract.get_bounty(bounty)["pool"] == 6 * ONE_GEN
        assert contract.get_report(report)["status"] == "paid"
        stats = contract.get_stats()
        assert stats["total_paid_out_atto"] == 4 * ONE_GEN
        assert stats["total_pool_locked_atto"] == 6 * ONE_GEN

    @pytest.mark.parametrize(
        "score,band,reward",
        [(70, "high", 2 * ONE_GEN), (50, "medium", 1 * ONE_GEN), (30, "low", ONE_GEN // 4)],
    )
    def test_other_bands_pay_their_reward(self, contract, gl, bounty, report,
                                          monkeypatch, score, band, reward):
        calls = record_transfers(monkeypatch)
        self._triaged(contract, gl, bounty, report, critical_verdict(score))
        res = contract.settle(report)
        assert res["status"] == "paid" and res["band"] == band
        assert res["paid_atto"] == reward
        assert calls == [(PAYOUT, reward)]

    def test_band_boundaries(self, contract, gl, bounty, monkeypatch):
        # 80 -> critical, 79 -> high, 60 -> high, 59 -> medium,
        # 40 -> medium, 39 -> low, 20 -> low, 19 -> rejected.
        # The seven payouts total 10.5 GEN, so top the 10 GEN pool up
        # by 5 GEN first.
        set_sender(gl, CREATOR, 5 * ONE_GEN)
        contract.top_up(bounty)
        cases = [
            (80, "critical", 4 * ONE_GEN), (79, "high", 2 * ONE_GEN),
            (60, "high", 2 * ONE_GEN), (59, "medium", 1 * ONE_GEN),
            (40, "medium", 1 * ONE_GEN), (39, "low", ONE_GEN // 4),
            (20, "low", ONE_GEN // 4),
        ]
        for i, (score, band, reward) in enumerate(cases):
            calls = record_transfers(monkeypatch)
            rid = _make_report(contract, gl, bounty, sender=RESEARCHER if i % 2 == 0 else RESEARCHER2)
            self._triaged(contract, gl, bounty, rid, critical_verdict(score))
            res = contract.settle(rid)
            assert res["band"] == band and res["paid_atto"] == reward, score
            assert calls == [(PAYOUT, reward)]
        rid = _make_report(contract, gl, bounty)
        self._triaged(contract, gl, bounty, rid, critical_verdict(19))
        res = contract.settle(rid)
        assert res == {"report_id": rid, "status": "rejected", "paid_atto": 0}

    def test_duplicate_pays_zero(self, contract, gl, bounty, report, monkeypatch):
        calls = record_transfers(monkeypatch)
        self._triaged(contract, gl, bounty, report, duplicate_verdict(0))
        res = contract.settle(report)
        assert res == {"report_id": report, "status": "duplicate", "paid_atto": 0}
        assert calls == []
        assert contract.get_bounty(bounty)["pool"] == 10 * ONE_GEN

    def test_invalid_pays_zero(self, contract, gl, bounty, report, monkeypatch):
        calls = record_transfers(monkeypatch)
        self._triaged(contract, gl, bounty, report, invalid_verdict())
        res = contract.settle(report)
        assert res == {"report_id": report, "status": "rejected", "paid_atto": 0}
        assert calls == []

    def test_settle_reported_raises(self, contract, gl, bounty, report):
        with pytest.raises(UserError, match="expected one of"):
            contract.settle(report)

    def test_settle_twice_raises(self, contract, gl, bounty, report):
        self._triaged(contract, gl, bounty, report, critical_verdict(92))
        contract.settle(report)
        with pytest.raises(UserError, match="expected one of"):
            contract.settle(report)

    def test_pool_shortfall_raises(self, contract, gl, monkeypatch):
        small = _make_bounty(contract, gl, value=1 * ONE_GEN)
        rid = _make_report(contract, gl, small)
        self._triaged(contract, gl, small, rid, critical_verdict(92))
        with pytest.raises(UserError, match="top up"):
            contract.settle(rid)
        assert contract.get_report(rid)["status"] == "triaged"

    def test_top_up_then_settle_works(self, contract, gl, monkeypatch):
        calls = record_transfers(monkeypatch)
        small = _make_bounty(contract, gl, value=1 * ONE_GEN)
        rid = _make_report(contract, gl, small)
        self._triaged(contract, gl, small, rid, critical_verdict(92))
        set_sender(gl, CREATOR, 5 * ONE_GEN)
        contract.top_up(small)
        res = contract.settle(rid)
        assert res["status"] == "paid" and res["paid_atto"] == 4 * ONE_GEN
        assert calls == [(PAYOUT, 4 * ONE_GEN)]
        assert contract.get_bounty(small)["pool"] == 2 * ONE_GEN

    def test_payout_goes_to_payout_wallet_not_researcher(
        self, contract, gl, bounty, monkeypatch
    ):
        calls = record_transfers(monkeypatch)
        other_wallet = "0x6666666666666666666666666666666666666666"
        rid = _make_report(contract, gl, bounty, payout=other_wallet)
        self._triaged(contract, gl, bounty, rid, critical_verdict(92))
        contract.settle(rid)
        assert calls == [(other_wallet, 4 * ONE_GEN)]


# ---------------------------------------------------------------------------
# Closing a bounty
# ---------------------------------------------------------------------------
class TestCloseBounty:
    def test_close_refunds_pool(self, contract, gl, bounty, monkeypatch):
        calls = record_transfers(monkeypatch)
        set_sender(gl, CREATOR)
        res = contract.close_bounty(bounty)
        assert res == {"bounty_id": bounty, "status": "closed", "refunded_atto": 10 * ONE_GEN}
        assert calls == [(CREATOR, 10 * ONE_GEN)]
        b = contract.get_bounty(bounty)
        assert b["status"] == "closed" and b["pool"] == 0
        assert contract.get_stats()["total_refunded_atto"] == 10 * ONE_GEN

    def test_non_owner_raises(self, contract, gl, bounty):
        set_sender(gl, RESEARCHER)
        with pytest.raises(UserError, match="only the bounty owner"):
            contract.close_bounty(bounty)

    def test_pending_reported_blocks(self, contract, gl, bounty, report):
        set_sender(gl, CREATOR)
        with pytest.raises(UserError, match="undecided reports"):
            contract.close_bounty(bounty)

    def test_pending_triaged_blocks(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(92))
        contract.request_triage(report)
        set_sender(gl, CREATOR)
        with pytest.raises(UserError, match="undecided reports"):
            contract.close_bounty(bounty)

    def test_unverifiable_report_does_not_block(self, contract, gl, bounty, report):
        set_now(NOW + 259200 + 1)
        contract.expire_report(report)
        set_sender(gl, CREATOR)
        res = contract.close_bounty(bounty)
        assert res["status"] == "closed"

    def test_paid_report_does_not_block(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(92))
        contract.request_triage(report)
        contract.settle(report)
        set_sender(gl, CREATOR)
        res = contract.close_bounty(bounty)
        assert res["status"] == "closed" and res["refunded_atto"] == 6 * ONE_GEN

    def test_close_twice_raises(self, contract, gl, bounty):
        set_sender(gl, CREATOR)
        contract.close_bounty(bounty)
        with pytest.raises(UserError, match="not open"):
            contract.close_bounty(bounty)


# ---------------------------------------------------------------------------
# Views and stats
# ---------------------------------------------------------------------------
class TestViewsStats:
    def test_get_bounty(self, contract, gl, bounty):
        b = contract.get_bounty(bounty)
        assert b["id"] == bounty and b["repo_url"] == "https://github.com/example/shop"
        assert b["created_at"] == NOW

    def test_get_bounty_nonexistent_raises(self, contract, gl):
        with pytest.raises(UserError, match="not found"):
            contract.get_bounty(99)

    def test_list_bounties_pagination(self, contract, gl, bounty):
        _make_bounty(contract, gl, value=1 * ONE_GEN)
        _make_bounty(contract, gl, value=2 * ONE_GEN)
        page = contract.list_bounties(1, 1)
        assert page["total"] == 3 and len(page["bounties"]) == 1
        assert page["bounties"][0]["id"] == 2
        assert contract.list_bounties(0, 100)["total"] == 3
        assert contract.list_bounties(0, 500)["bounties"][0]["id"] == 1  # limit capped at 100
        assert contract.list_bounties(3, 10)["bounties"] == []

    def test_get_report(self, contract, gl, bounty, report):
        r = contract.get_report(report)
        assert r["id"] == report and r["title"] == "RCE via eval() in run_command"

    def test_list_reports_pagination(self, contract, gl, bounty):
        _make_report(contract, gl, bounty)
        _make_report(contract, gl, bounty, sender=RESEARCHER2)
        page = contract.list_reports(0, 1)
        assert page["total"] == 2 and page["reports"][0]["id"] == 1
        assert contract.list_reports(1, 1)["reports"][0]["id"] == 2

    def test_get_stats(self, contract, gl, bounty, report):
        stub_triage(gl, critical_verdict(92))
        contract.request_triage(report)
        contract.settle(report)
        _make_report(contract, gl, bounty, sender=RESEARCHER2)
        stats = contract.get_stats()
        assert stats["total_bounties"] == 1
        assert stats["total_reports"] == 2
        assert stats["reports_by_status"]["paid"] == 1
        assert stats["reports_by_status"]["reported"] == 1
        assert stats["total_paid_out_atto"] == 4 * ONE_GEN
        assert stats["total_pool_locked_atto"] == 6 * ONE_GEN
        assert stats["total_refunded_atto"] == 0


# ---------------------------------------------------------------------------
# End-to-end lifecycles
# ---------------------------------------------------------------------------
class TestLifecycle:
    def test_happy_path(self, contract, gl, monkeypatch):
        calls = record_transfers(monkeypatch)
        bounty = _make_bounty(contract, gl, value=10 * ONE_GEN)
        set_sender(gl, CREATOR, 1 * ONE_GEN)
        contract.top_up(bounty)
        rid = _make_report(contract, gl, bounty)
        stub_triage(gl, critical_verdict(95))
        assert contract.request_triage(rid)["status"] == "triaged"
        assert contract.settle(rid)["paid_atto"] == 4 * ONE_GEN
        set_sender(gl, CREATOR)
        assert contract.close_bounty(bounty)["refunded_atto"] == 7 * ONE_GEN
        assert calls == [(PAYOUT, 4 * ONE_GEN), (CREATOR, 7 * ONE_GEN)]
        stats = contract.get_stats()
        assert stats["total_paid_out_atto"] == 4 * ONE_GEN
        assert stats["total_refunded_atto"] == 7 * ONE_GEN
        assert stats["total_pool_locked_atto"] == 0

    def test_invalid_path(self, contract, gl, bounty, monkeypatch):
        calls = record_transfers(monkeypatch)
        rid = _make_report(
            contract, gl, bounty, code_url=SECURE_CODE_URL, severity="high",
            title="Command injection in run_command",
        )
        stub_triage(
            gl, invalid_verdict(),
            fetched_code="import ast\n\ndef run_command(cmd):\n    return ast.literal_eval(cmd)\n",
        )
        assert contract.request_triage(rid)["status"] == "triaged"
        assert contract.settle(rid)["status"] == "rejected"
        assert calls == []
        set_sender(gl, CREATOR)
        assert contract.close_bounty(bounty)["refunded_atto"] == 10 * ONE_GEN

    def test_duplicate_path(self, contract, gl, bounty, monkeypatch):
        calls = record_transfers(monkeypatch)
        first = _make_report(contract, gl, bounty)
        stub_triage(gl, critical_verdict(92))
        contract.request_triage(first)
        contract.settle(first)
        second = _make_report(contract, gl, bounty, sender=RESEARCHER2)
        stub_triage(gl, duplicate_verdict(first))
        assert contract.request_triage(second)["status"] == "triaged"
        assert contract.settle(second)["status"] == "duplicate"
        assert calls == [(PAYOUT, 4 * ONE_GEN)]
        set_sender(gl, CREATOR)
        assert contract.close_bounty(bounty)["refunded_atto"] == 6 * ONE_GEN
