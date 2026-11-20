"""Pytest fixtures: a minimal fake `genlayer` module so the contract file
imports and runs without GenVM installed.

The stub mirrors the parts of the real API the contract uses:
- `gl` namespace: public.write / public.write.payable / public.view,
  evm.contract_interface, nondet.web.render, nondet.exec_prompt,
  vm.run_nondet_unsafe (with gl.vm.Return / gl.vm.UserError Result
  types), eq_principle, message, Contract.
- Top-level types: u256, Address, TreeMap, DynArray, allow_storage.

There is deliberately NO `gl.block`: GenLayer exposes no block number,
hash or timestamp (docs: Transaction Context). Time comes from the
stdlib clock, which GenVM wires to the transaction datetime — the stub
pins the contract module's `datetime.now(timezone.utc)` to the test's
NOW via _FixedDateTime (see set_now).

`run_nondet_unsafe` here models the real flow in miniature: run the
leader, wrap its outcome in a gl.vm.Result (Return with the value on
.calldata, or gl.vm.UserError carrying the leader's message), hand that
Result to the validator, and raise if the validator disagrees. If the
leader errored and the validator agrees it failed, the leader's error
is re-raised, as errors flow from nondet to deterministic code. Tests
override `gl.nondet.web.render` / `exec_prompt` with canned responses,
and patch `_PayoutTarget.emit_transfer` to record payouts.
"""
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Build the fake genlayer module
# ---------------------------------------------------------------------------

class _Deco:
    """A no-op decorator that is also usable as `.payable`.

    Plain functions stored as class attributes would get `self` bound when
    accessed through an instance; this object avoids that.
    """

    def __call__(self, fn):
        return fn

    @property
    def payable(self):
        return self


class _InterfaceDeco:
    """Decorator for @gl.evm.contract_interface classes.

    In real GenVM, an interface class is instantiated with the payout
    destination's address: ``_PayoutTarget(recipient).emit_transfer(value=v)``.
    The stub emulates that by giving the class an address-taking constructor.
    """

    def __call__(self, cls):
        class Wrapped(cls):
            def __init__(self, address=None):
                self._address = address

            def emit_transfer(self, value):
                # Default no-op: real GenVM provides this on the
                # interface. Tests that care about payouts override it
                # via record_transfers(); tests that don't simply let
                # the transfer succeed silently.
                return None

        Wrapped.__name__ = cls.__name__
        Wrapped.__qualname__ = cls.__qualname__
        return Wrapped


class _Public:
    write = _Deco()
    view = _Deco()


class _Evm:
    contract_interface = _InterfaceDeco()


class _Web:
    @staticmethod
    def render(url, mode="text"):
        raise RuntimeError("nondet web.render not stubbed for this test")


class _Nondet:
    web = _Web()

    @staticmethod
    def exec_prompt(prompt, response_format="json"):
        raise RuntimeError("nondet exec_prompt not stubbed for this test")


class _Vm:
    class Return:
        """A successful leader outcome; the value is on .calldata."""

        def __init__(self, calldata):
            self.calldata = calldata

    class UserError(Exception):
        """A leader application error, delivered to the validator as a
        gl.vm.Result carrying the leader's message on .message."""

        def __init__(self, message):
            super().__init__(message)
            self.message = message

    @staticmethod
    def run_nondet_unsafe(leader_fn, validator_fn):
        try:
            result = leader_fn()
        except Exception as e:
            leaders_res = _Vm.UserError(str(e))
            if not validator_fn(leaders_res):
                raise RuntimeError("consensus failed: validator disagreed with leader")
            raise  # validators agreed the leader failed — propagate its error
        leaders_res = _Vm.Return(result)
        if not validator_fn(leaders_res):
            raise RuntimeError("consensus failed: validator disagreed with leader")
        return result


class _EqPrinciple:
    @staticmethod
    def strict_eq(a, b):
        return a == b

    @staticmethod
    def custom_eq(a, b, fn):
        return fn(a, b)


class _Message:
    sender_address = "0x0000000000000000000000000000000000000000"
    value = 0


class _Gl:
    public = _Public()
    evm = _Evm()
    nondet = _Nondet()
    vm = _Vm()
    eq_principle = _EqPrinciple()
    message = _Message()

    class Contract:
        pass


class TreeMap(dict):
    def __class_getitem__(cls, params):
        return cls


class DynArray(list):
    def __class_getitem__(cls, params):
        return cls


genlayer = types.ModuleType("genlayer")
genlayer.gl = _Gl()
genlayer.u256 = int
genlayer.Address = str
genlayer.TreeMap = TreeMap
genlayer.DynArray = DynArray
genlayer.allow_storage = _Deco()
genlayer.__all__ = ["gl", "u256", "Address", "TreeMap", "DynArray", "allow_storage"]
sys.modules["genlayer"] = genlayer

# ---------------------------------------------------------------------------
# Import the contract file by path (no package needed)
# ---------------------------------------------------------------------------
CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "vuln_bounty.py"

import importlib.util

_spec = importlib.util.spec_from_file_location("vuln_bounty", CONTRACT_PATH)
vuln_bounty = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vuln_bounty)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

OWNER = "0x1111111111111111111111111111111111111111"
CREATOR = "0x2222222222222222222222222222222222222222"
RESEARCHER = "0x3333333333333333333333333333333333333333"
RESEARCHER2 = "0x4444444444444444444444444444444444444444"
PAYOUT = "0x5555555555555555555555555555555555555555"
NOW = 1_800_000_000  # fixed "now" for deterministic deadline tests

ONE_GEN = 10**18
VULN_CODE_URL = "https://raw.githubusercontent.com/example/shop/main/app.py"
SECURE_CODE_URL = "https://raw.githubusercontent.com/example/shop/main/app_secure.py"

from datetime import datetime as _RealDateTime, timezone as _RealTimezone


class _FixedDateTime:
    """Stand-in for the contract module's `datetime` name.

    Real GenVM wires the stdlib clock to the transaction datetime, so
    `datetime.now(timezone.utc)` returns the same value on every
    validator (docs: Transaction Context). The stub pins it to NOW;
    set_now() moves it, which is how tests simulate time passing.
    Only `now()` is modeled — the contract uses nothing else from
    `datetime`.
    """

    _now = _RealDateTime.fromtimestamp(NOW, tz=_RealTimezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls._now

    @classmethod
    def set_now(cls, ts):
        cls._now = _RealDateTime.fromtimestamp(ts, tz=_RealTimezone.utc)


vuln_bounty.datetime = _FixedDateTime


def set_now(ts):
    """Move the stub's pinned transaction datetime to Unix seconds `ts`."""
    _FixedDateTime.set_now(ts)


@pytest.fixture(autouse=True)
def _reset_nondet(gl):
    """Every test starts with the nondet calls un-stubbed (raising), so a
    test that forgets to stub a verdict fails loudly instead of silently
    reusing the previous test's canned response."""
    gl.nondet.web.render = staticmethod(
        lambda url, mode="text": (_ for _ in ()).throw(
            RuntimeError("nondet web.render not stubbed for this test")
        )
    )
    gl.nondet.exec_prompt = staticmethod(
        lambda prompt, response_format="json": (_ for _ in ()).throw(
            RuntimeError("nondet exec_prompt not stubbed for this test")
        )
    )
    yield


@pytest.fixture
def gl():
    return genlayer.gl


@pytest.fixture
def contract(gl):
    """A freshly deployed contract with sender=owner and a fixed clock.

    Storage maps are created by hand here: real GenVM auto-creates them,
    but the stub needs them to exist before __init__ runs.
    """
    gl.message.sender_address = OWNER
    gl.message.value = 0
    set_now(NOW)
    c = object.__new__(vuln_bounty.VulnBounty)
    c.bounties = {}
    c.bounty_order = []
    c.reports = {}
    c.report_order = []
    c.counters = {}
    c.__init__(OWNER)
    return c


@pytest.fixture
def bounty(contract, gl):
    """An open bounty funded by CREATOR: 10 GEN pool, deadline +7 days.
    Rewards: critical 4 GEN, high 2 GEN, medium 1 GEN, low 0.25 GEN."""
    gl.message.sender_address = CREATOR
    gl.message.value = 10 * ONE_GEN
    bounty_id = contract.create_bounty(
        "https://github.com/example/shop",
        "Python web app in shop/ — command runner, auth, and payment handling",
        "Shop web app bounty",
        4 * ONE_GEN,
        2 * ONE_GEN,
        1 * ONE_GEN,
        ONE_GEN // 4,
        NOW + 7 * 86_400,
    )["bounty_id"]
    gl.message.value = 0
    return bounty_id


@pytest.fixture
def report(contract, gl, bounty):
    """A report by RESEARCHER against `bounty`, claiming a critical RCE
    in the demo vulnerable file. Status: reported."""
    gl.message.sender_address = RESEARCHER
    report_id = contract.submit_report(
        bounty,
        VULN_CODE_URL,
        "RCE via eval() in run_command",
        "run_command passes user input straight to eval(), so anyone can "
        "run arbitrary Python, including os.system commands.",
        "1. Send GET /run?cmd=__import__('os').system('id')\n"
        "2. The server executes it and returns the output.",
        "critical",
        PAYOUT,
    )["report_id"]
    gl.message.value = 0
    return report_id


def set_sender(gl, account, value=0):
    gl.message.sender_address = account
    gl.message.value = value


def stub_triage(gl, verdict_json, fetched_code=None):
    """Make the stub's nondet calls return a fixed verdict for everyone.

    web.render returns `fetched_code` (a snippet of the demo vulnerable
    file by default); exec_prompt always returns `verdict_json`, so the
    leader and the validator agree.
    """
    code = (
        fetched_code
        if fetched_code is not None
        else "def run_command(cmd):\n    return eval(cmd)\n"
    )
    gl.nondet.web.render = staticmethod(lambda url, mode="text": code)
    gl.nondet.exec_prompt = staticmethod(
        lambda prompt, response_format="json": verdict_json
    )


def stub_triage_sequence(gl, verdicts, fetched_code=None):
    """Like stub_triage, but exec_prompt returns the queued verdicts in
    order (the last one repeats once the queue is exhausted) — so a test
    can make the leader and the validator disagree."""
    queue = list(verdicts)
    code = (
        fetched_code
        if fetched_code is not None
        else "def run_command(cmd):\n    return eval(cmd)\n"
    )
    gl.nondet.web.render = staticmethod(lambda url, mode="text": code)

    def _next(prompt, response_format="json"):
        if len(queue) > 1:
            return queue.pop(0)
        if queue:
            return queue[0]
        raise RuntimeError("no more canned verdicts")

    gl.nondet.exec_prompt = staticmethod(_next)


def record_transfers(monkeypatch):
    """Patch _PayoutTarget.emit_transfer to record (destination, value) calls.

    emit_transfer takes only value=; the destination is the address the
    interface was constructed with, stored on the instance as _address.
    """
    calls = []
    monkeypatch.setattr(
        vuln_bounty._PayoutTarget,
        "emit_transfer",
        lambda self, value: calls.append((self._address, value)),
        raising=False,
    )
    return calls


def critical_verdict(score=92):
    return (
        '{"valid": true, "severity_score": %d, "duplicate": false, '
        '"duplicate_of": 0, "reasoning": "eval on user input is RCE", '
        '"cannot_verify": false}' % score
    )


def invalid_verdict():
    return (
        '{"valid": false, "severity_score": 0, "duplicate": false, '
        '"duplicate_of": 0, "reasoning": "no flaw in the code", '
        '"cannot_verify": false}'
    )


def duplicate_verdict(of_id):
    return (
        '{"valid": true, "severity_score": 90, "duplicate": true, '
        '"duplicate_of": %d, "reasoning": "same eval flaw as report %d", '
        '"cannot_verify": false}' % (of_id, of_id)
    )


def cannot_verify_verdict():
    return (
        '{"valid": false, "severity_score": 0, "duplicate": false, '
        '"duplicate_of": 0, "reasoning": "code unreadable", '
        '"cannot_verify": true}'
    )
