# AgentTrust: 90-second demo voice-over

Recorded terminal: `demo/video/agenttrust-90s.tape` (render with `vhs`, output in `demo/video/out/`).
Read at a calm pace (about 150 words per minute). The rendered recording is about 77 s (PACE=2600). Hold the closing frame or raise PACE to land at 85–90 s with narration.

| Time | On screen | Voice-over |
|---|---|---|
| 0:00–0:07 | Command typed; title line | "AI agents are starting to pay suppliers. The question every finance team asks: what stops one from paying the wrong thing?" |
| 0:07–0:13 | "Acme approved: 1 cordless drill, $500…" | "Here, Acme has approved one purchase, a five-hundred-dollar drill from a verified supplier, for one specific agent." |
| 0:13–0:22 | **1 · The approved purchase**: ALLOW, accepted → settled | "The agent pays it. AgentTrust checks the payment against what the business approved: the instruction, supplier, bank account, PO and invoice. It's allowed, and the payment settles." |
| 0:22–0:31 | **2 · Ten times the approval**: DENY | "Now the supplier claims the price went up, and the agent tries to pay five thousand. The agent has the budget, but nobody approved that amount. Denied." |
| 0:31–0:40 | **3 · A supplier nobody approved**: REVIEW | "It finds a cheaper vendor on a website. That isn't automatically wrong, but no one approved it, so it goes to a human. No money moves." |
| 0:40–0:52 | **4 · "We changed our bank account"**: DENY PAYEE_MISMATCH | "This is the classic invoice scam: an email saying the supplier's bank details changed. The agent believes it. AgentTrust doesn't, because the account doesn't match the one a second person verified. Denied." |
| 0:52–1:01 | **5 · Paying the same invoice twice**: DENY | "The same invoice shows up again. Already paid. Denied." |
| 1:01–1:12 | **6 · Skipping the check**: BLOCKED | "Finally, the agent tries to skip the check and call the payment gateway with a made-up approval. It can't: the gateway is the only way to move money, and it enforces the decision." |
| 1:12–1:25 | "One payment made… Five stopped." | "One payment made, the one the business approved. Five stopped. Spending limits tell you how much an agent can spend. AgentTrust checks that each payment matches what the business actually authorized." |
| 1:25–1:30 | Hold | "We're looking for three AI-finance teams to try the sandbox. Link below." |

**Honesty notes for the recording:** say "sandbox" at least once (already in the title line). Don't say "secure",
"compliant" or "production-ready". The sandbox simulates the payment provider; no real money moves.

**Variants**
- *30-second cut* (social): beats 1, 4 and 6 plus the closing line.
- *Silent GIF* (email/README): `agenttrust-90s.gif`. The on-screen text carries the story without audio.
