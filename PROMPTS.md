# PROMPTS.md

Maintain this file throughout development. Entries below document the initial project scaffold generated with AI. Replace or extend them with the actual prompts, observed mistakes, verification, dates, and real commit links from your own work. Do not invent commits or claim tests passed unless you ran them.

## Entry 1 — 2026-10-24 — Initial scaffold and role model

### Request / prompt summary
Create a Flask document-sharing prototype with Admin, Owner, and Viewer roles, a database schema, private storage, and basic pages.

### What it produced
An initial application structure with user, document, permission, and audit models plus templates.

### What needs review
A scaffold cannot establish security by itself. The role model and every route need to be checked against the intended policy. In particular, admin content access must not be assumed.

### What I did / verification
Review `can_access`, route decorators, and the route access table. Run the security tests and inspect every endpoint before deployment.

### Fix commit
Add the actual commit URL after committing the verified change.

## Entry 2 — 2026-10-24 — Authorisation and object-level access

### Request / prompt summary
Implement document-level read/edit permissions and protect document detail, download, edit, delete, and share endpoints.

### What it produced
A shared access-check function and a decorator for routes that take a document ID.

### What was wrong / what must be checked
Centralising checks is useful, but it is easy to forget a new route or give an Edit grant more powers than intended. The current scaffold's edit/delete policy must be reviewed carefully because the challenge's intended product rule is that only the owner controls destructive actions.

### What I did / verification
Run tests for another owner, an ungranted viewer, a read-only viewer, and a revoked grant. Add tests for any route not yet covered. Record the actual result.

### Fix commit
Add the real commit URL after the fix and test are committed.

## Entry 3 — 2026-10-24 — Revocation semantics

### Request / prompt summary
Make access revocation effective for subsequent document requests.

### What it produced
Permission records have a revocation timestamp, and the active permission lookup excludes revoked records.

### What was wrong / what must be checked
Revocation cannot retrieve previously downloaded copies. An in-flight response may also continue after revocation. Public or long-lived pre-signed URLs would bypass per-request checks until expiry.

### What I did / verification
Use private storage and an authenticated download endpoint. Test a successful download before revocation and a denied download after revocation. Add concurrency tests before making stronger guarantees.

### Fix commit
Add the real commit URL after verification.

## Entry 4 — 2026-10-24 — Audit trail integrity

### Request / prompt summary
Record uploads, downloads, edits, deletions, permission changes, login events, and denied document-access attempts.

### What it produced
An audit table with actor, document, action, outcome, timestamp, request identifier, previous hash, and event hash.

### What was wrong / limitation
Hash chaining alone is not tamper-proof. An attacker with sufficient database privileges may rewrite all events and recompute the chain. Some application operations also need stronger transactional coupling with audit writes.

### What I did / verification
Document this limitation in `THREATS.md`. Plan separate audit credentials and independently anchored or immutable checkpoints for production. Verify that denied access creates an event.

### Fix commit
Add the actual commit URL after implementation and tests.

## Entry 5 — 2026-10-24 — Upload validation

### Request / prompt summary
Validate uploads and store files privately.

### What it produced
An extension allowlist, a 10 MB limit, generated storage keys, and basic signature checks for selected file types.

### What was wrong / limitation
Extension and signature checks do not detect all malicious content or malformed files. MIME types supplied by clients are untrusted. Malware scanning and robust format parsing are not included.

### What I did / verification
Test disallowed extensions, oversized content, empty files, and mismatched PDF/PNG/JPEG signatures. Keep the files outside public directories and document remaining gaps.

### Fix commit
Add the actual commit URL after tests and fixes.

## Reusable project instruction

Treat all document metadata and file bytes as confidential. Enforce object-level authorization on the server for every request. Deny by default. Do not trust client-supplied roles, owner IDs, filenames, or MIME types. Never expose private storage paths. Record successful and denied security-relevant actions. State limitations honestly and write a regression test for every security bug.


## Entry 6 — 2026-10-25 — Admin metadata isolation and UI refresh

### Request / prompt summary
Review the full challenge requirements and existing TrustVault code; improve the visual theme, check for authorization gaps, add regression tests, and align the threat model and API documentation with actual route policy.

### What it produced
A dark Obsidian/Violet/Cyan theme; a more descriptive landing page and dashboard; expanded security tests; updated route/role documentation; schema reference, demo script, and write-up.

### What was wrong in the existing implementation
The search route treated the admin role as permission to search every document's metadata, despite the stated least-privilege rule that admins do not automatically get document access. This was a metadata disclosure path even though direct download still had an authorization check. Existing API docs also incorrectly described editor deletion as possible.

### What I changed and how to verify
The search query now filters every role to documents owned by the current user or covered by an active grant. A regression test checks that admin search does not reveal an ungranted title. Added tests cover denied-attempt audit records, editor-vs-owner actions, owner revocation, and upload extension/signature validation. API/README role policy was corrected. The tests have not run in this authoring environment because Flask dependencies could not be installed without package-index network access; run `python -m pytest -q` locally before claiming they pass.

### Fix commit
**Pending real commit.** After committing this change in the project repository, replace this line with the actual GitHub commit URL. No commit hash is fabricated here.
