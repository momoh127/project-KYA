# Third-Party Notice

## open-kya/kya-standard (Apache-2.0)

The [KYA (Know Your Agent) Manifest Standard](https://github.com/open-kya/kya-standard), Copyright 2025
Lars Kæraa Lücke, licensed under the Apache License 2.0, was reviewed as background research.

**No files, schemas or code from that project are included in this repository.** The following *concepts*
informed our independent, clean-room implementation (concepts are not subject to copyright):

- Separating agent key purposes (authentication vs. action signing vs. governance)
- Expressing operational limits as per-transaction caps and per-period spend limits
- Conditional human-approval requirements above value thresholds
- Content-hashing referenced evidence documents

"KYA" and "Open-KYA" are names of that project; AgentTrust does not use them as brand names and does not
claim endorsement. If any file from that project is ever vendored (for example to validate imported KYA
manifests), it will be placed under `third_party/kya-standard/` with its original LICENSE and copyright notice,
and modified files will carry a change notice, per Apache-2.0 §4.

## Runtime dependencies

All npm dependencies retain their own licenses (see each package's `LICENSE` in `node_modules`). Principal
dependencies: NestJS (MIT), Prisma (Apache-2.0), Zod (MIT), Vitest (MIT), TypeScript (Apache-2.0).
