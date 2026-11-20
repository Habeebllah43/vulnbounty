# Deploying VulnBounty

No wallet, account, or deployment has been created for you — these are
the steps to run yourself. Nothing here costs real money until mainnet,
and the first two stages are free.

## 0. What you need

- The repo in this folder (`contracts/vuln_bounty.py` and the docs).
- A browser. No local toolchain is needed for Studio; the testnet steps
  use the GenLayer CLI if you prefer it to Studio's UI.
- A GenLayer-compatible wallet (the Studio / portal will prompt you).
  Never paste a private key or seed phrase anywhere except your own
  wallet.
- The demo code files (`demo/vulnerable.py`, `demo/secure.py`) hosted
  somewhere validators can fetch them — a public GitHub repo's
  `raw.githubusercontent.com` URL works. A localhost URL does not
  (validators cannot reach your machine), and some file hosts refuse
  validator requests (a muse.ai-hosted file returned HTTP 418 to
  validators in an earlier project — use raw.githubusercontent.com).

## 1. Lint first (before you deploy anywhere)

```sh
genvm-lint check contracts/vuln_bounty.py
```

> Note: `genvm-lint` could not be installed in the environment this
> project was written in (`pip install genvm-lint` and `pip install
> py-genlayer` find no such packages; the `genlayer` package on PyPI is
> an empty placeholder). Install it from GenLayer's official tooling
> instructions and run the check before deploying. Fix anything it
> flags — in particular confirm the transaction-datetime deadline clock
> (`datetime.now(timezone.utc)`) and the `_PayoutTarget.emit_transfer`
> payout wiring (see step 2).

Also run the unit tests once more, so you know the logic you are
deploying is the logic that passed:

```sh
pip install -r requirements.txt
python3 -m pytest tests/ -q
# 124 passed
```

## 2. GenLayer Studio — deploy and play with 5 simulated validators

1. Open **https://studio.genlayer.com** and connect your wallet.
2. Create a new contract and paste in `contracts/vuln_bounty.py`
   (one contract per file — this file is the whole contract).
   When Studio asks for the constructor argument, enter your own wallet
   address as `owner_address` (a hex string — the constructor takes it
   as `str` and converts it to `Address` inside, because reading the
   sender inside `__init__` breaks deployment on Studio).
3. Deploy to **studionet**. Studio deploys with 5 simulated validators,
   so `request_triage` actually runs consensus.
4. **No payout setup needed.** Payouts are direct transfers of the
   GEN locked by `create_bounty` / `top_up`, through
   `_PayoutTarget.emit_transfer` (the faucet pattern) — there is no
   Arbiter address to confirm and no `set_arbiter` call. `settle` and
   `close_bounty` pay out as soon as they run.
5. Walk the full flow on studionet (amounts are play money). Use two
   Studio accounts: the bounty owner (account A) and a researcher
   (account B, also used as the payout wallet).
   - **Create:** from account A, call `create_bounty` attaching
     10 GEN (the `value` field):
     - repo_url: `https://github.com/example/shop`
     - scope: `Python web app in shop/ — command runner, auth, and payment handling`
     - title: `Shop web app bounty`
     - reward_critical: 4 GEN, reward_high: 2 GEN, reward_medium: 1 GEN,
       reward_low: 0.25 GEN (in atto: 4000000000000000000,
       2000000000000000000, 1000000000000000000, 250000000000000000)
     - deadline: a Unix timestamp 7 days ahead
   - **Report 1 (critical path):** from account B, call `submit_report`:
     - code_url: the raw GitHub URL of `demo/vulnerable.py`
       (e.g. `https://raw.githubusercontent.com/<user>/<repo>/main/demo/vulnerable.py`)
     - title: `RCE via eval() in run_command`
     - description: `run_command passes user input straight to eval(), so anyone can run arbitrary Python, including os.system commands.`
     - steps: `1. Send GET /run?cmd=__import__('os').system('id') 2. The server executes it and returns the output.`
     - claimed_severity: `critical`
     - payout_wallet: account B's address
   - **Triage:** call `request_triage` (any account may call it).
     Expected verdict: `valid: true, severity_score: 90–100,
     duplicate: false`. The report should become `triaged`.
   - **Settle:** call `settle` and check the researcher is paid the
     **4 GEN** critical reward and the pool drops to 6 GEN.
   - **Report 2 (duplicate path):** submit the same flaw again from
     another account, triage it, and settle it. Expected: verdict
     `duplicate: true`, status `duplicate`, **0 GEN** paid.
   - **Report 3 (invalid path):** submit a report against
     `demo/secure.py` claiming command injection, triage it, settle it.
     Expected: verdict `valid: false, severity_score: 0`, status
     `rejected`, **0 GEN** paid.
   - **Try the failure paths too:** a report against a 404 code URL
     (attempt counted, nobody paid), and a report left `reported` for
     3 days followed by `expire_report` (status `unverifiable`).
   - **Close:** call `close_bounty` from account A and check the
     remaining pool is refunded to account A.
6. Note the deployed contract address and the transaction hashes — you
   will need them for the portal submission.

## 3. Bradbury testnet

1. In Studio, switch the network to **Bradbury** (GenLayer testnet).
2. Get testnet GEN from the faucet (linked in Studio / the GenLayer
   docs). Testnet funds have no real value.
3. Redeploy the contract and repeat the full flow from step 2.5 (no
   payout setup call is needed on Bradbury either).
4. Record: contract address, a `create_bounty` transaction, a
   `request_triage` transaction showing a stored verdict, and a
   `settle` transaction. These are your evidence for the portal.

## 4. Submit to the GenLayer portal

1. Open **https://portal.genlayer.foundation** and sign in.
2. Submit under the **Builders / standalone contracts** category with:
   - **Link:** this repository (or a public GitHub copy of it), and
     the deployed contract address(es) from Studio and Bradbury.
   - **Title:** "VulnBounty — AI-triaged bug bounty payouts".
   - **Description:** the README's first two sections (problem + what
     the contract does), plus the worked example and its expected
     outcome.
   - **Evidence:** the transaction hashes from step 3.4 and a note
     that the 124 unit tests pass (`python3 -m pytest tests/ -q`).
   - **Docs:** point reviewers at `README.md` (purpose, state design,
     worked example) and `CONSENSUS.md` (equivalence design, including
     the UNDETERMINED hole and the `expire_report` escape).
3. Keep the repository public and do not change the contract after
   submitting — reviewers check the submitted code against the deployed
   address.

## 5. Mainnet (only when you are ready)

- Confirm the payout wiring (`_PayoutTarget.emit_transfer`) against the
  official GenLayer docs for mainnet, and redeploy.
- Re-run `genvm-lint` against the exact file you deploy.
- Start with small bounty pools: the settlement bands are
  deterministic, but the triage quality depends on the live validators
  and the quality of the reports and code links submitted.
