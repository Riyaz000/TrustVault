# Five-minute TrustVault demo video plan

Use synthetic documents and temporary demo credentials only. Do not record real personal data, secrets, or production credentials.

- **0:00–0:30 — Problem and design.** Explain that the product is about document-level authorization and evidence, not just CRUD. Show the landing page and dark violet/cyan theme.
- **0:30–1:10 — Roles.** Sign in as the owner. Show the dashboard and upload a synthetic `sample-contract.txt` under Contract.
- **1:10–2:00 — Named grant.** Share the document with the seeded viewer using Read. Sign out and sign in as the viewer; show the document is visible and can be downloaded.
- **2:00–2:45 — Attack attempt.** While signed in as an ungranted account (or use the automated test output), try the same document ID in the detail and download URLs. Show the request is denied. Explain that the server performs the authorization check on each route.
- **2:45–3:25 — Revocation.** Return as the owner and revoke the viewer's grant. Sign in as the viewer and retry the same download URL; it should now be denied. Explain that revocation affects subsequent requests, not copies already downloaded.
- **3:25–4:10 — Audit.** Sign in as admin and show upload, download, permission grant/revoke and denied-attempt events. Explain hash chaining and its known database-privilege limitation.
- **4:10–4:40 — Tests and threat model.** Show `pytest -q`, the security test names, `THREATS.md` and `API.md`. Only state test results after actually running them.
- **4:40–5:00 — Close honestly.** Summarise what is implemented and name unfinished production controls: independent immutable audit sink, malware scanning, rate limiting, MFA, backups and external review.

## Recording checklist

- Use a clean browser profile and synthetic data.
- Hide unrelated tabs, bookmarks, account details and environment variables.
- Do not show `.env`, passwords in terminal history, or private file contents.
- Record the deployed URL only after deployment and security configuration are verified.
