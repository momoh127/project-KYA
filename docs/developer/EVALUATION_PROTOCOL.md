# External developer evaluation protocol (time-to-integration)

**Target:** an external developer reaches a **settled sandbox payment** in **≤ 30 minutes** from signup, using only
the public docs and SDKs, without help from us.

We measure this with real external developers, not with our own team, because our own tests can't tell us whether
the documentation is good enough.

## What the sandbox measures automatically

Every sandbox records a funnel with timestamps, which the platform operator can read:

```bash
curl -s -H "x-agenttrust-bootstrap-token: $AGENTTRUST_BOOTSTRAP_TOKEN" $BASE_URL/v1/sandbox/metrics
```

| Step | Meaning |
|---|---|
| `signedUp` | sandbox created (t = 0) |
| `agentRegistered` | first agent registered |
| `instructionApproved` | first purchase instruction approved |
| `firstAuthorization` | first authorization request (any decision) |
| `firstAllow` | first ALLOW |
| `firstExecution` | first gateway execution |
| `firstSettledPayment` | first settled payment (**done**) |

The response also includes `medianMinutesToFirstSettledPayment` and `under30Minutes`. A developer can see their own
funnel at `GET /v1/sandbox/progress`.

> [!NOTE]
> "Minutes from signup" includes any time spent reading before writing code, which is what we want: it's the real
> experience. The clock starts at signup, not when they first see the docs, so also note in the session log when they
> started reading.

## Session protocol (per developer)

1. **Recruit** an engineer at a design-partner prospect who has never seen AgentTrust. Offer a thank-you for 45 minutes.
2. **Give them only:** the sandbox URL, a link to `/docs` (Quickstart, Integration Guide, API reference), and the SDK
   download links. No walkthrough.
3. **Observe silently** (screen share, recording with consent). Answer only "I can't help with that during the test."
   If they're completely stuck for **10 minutes**, give the smallest possible hint and **log it**. A hint means that
   run counts as "assisted".
4. **Log** every point of confusion with a timestamp: the doc section, what they expected, what happened.
5. **Debrief (10 min):**
   - "What was the hardest step?"
   - "What would you need to do this against your real payment flow?" (This is the Pattern B signal.)
   - "Where do approved purchase instructions come from in your company?"
   - "What latency could a pre-payment check add?"
   - "On a scale of 1–10, how likely are you to try this on a real workflow?"
6. **Record** the funnel from `/v1/sandbox/metrics` next to the session notes.

## Scorecard

| Run | Company | Language | Unassisted? | Minutes to first settled payment | Stuck points | Pattern B needed? | 1–10 |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |
| 2 | | | | | | | |
| 3 | | | | | | | |

**Success:** at least 2 of 3 unassisted runs ≤ 30 minutes. **After each run:** fix the top confusion point in the docs
or SDK before the next run, and note the change in the CHANGELOG.
