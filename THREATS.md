# TrustVault Threat Model

Status: initial draft for a learning prototype. Update this file as implementation and testing progress. Do not claim a mitigation is complete unless it has been verified.

## Assets

- Confidential document contents and metadata
- User credentials and sessions
- Per-document grants
- Audit events
- Availability and integrity of documents

## Trust boundaries

- Browser to Flask application
- Flask application to database
- Flask application to private file storage
- Application audit writer to audit storage
- Administrator account to ordinary user accounts

## Threats, controls, and known limitations

| Threat | Current control | Verification / accepted limitation |
|---|---|---|
| Insecure direct object reference (change document ID) | Central access check used by detail/download/edit/delete routes | Security tests cover other-owner and ungranted-viewer cases. Extend to every new route. |
| Unauthenticated access | Flask-Login protects document routes | Test anonymous requests. |
| Read grant used to edit/delete | Read grants only authorise read in central policy | Tests verify read-only cannot edit. Review any new action. |
| Revoked permission reused | Active grant is queried from DB for each request | Subsequent requests are denied. Already downloaded copies cannot be recalled. |
| Admin implicitly reads every file | Admin does not automatically bypass document grants | This is a deliberate least-privilege choice; emergency access is not implemented. |
| Publicly exposed file storage | Random storage key outside `static`; downloads go through authorised route | Verify deployment volume is not served by web server. |
| Malicious upload | Extension allowlist, size cap, random storage key; signature checks for PDF/PNG/JPEG | Accepted limitation: no malware scanner, full format parser, or quarantine service. Do not use with untrusted production uploads yet. |
| Filename/path traversal | `secure_filename` and random storage key | Keep all file operations based on generated key, not user-provided paths. |
| Forged admin role at registration | Public registration restricts role to owner/viewer | Admin creation must remain a controlled setup operation. |
| CSRF against state-changing routes | Flask-WTF CSRF protection | Production tests must verify CSRF enabled. |
| Session theft / insecure transport | HttpOnly and SameSite cookies; configurable Secure flag | HTTPS and `COOKIE_SECURE=1` are required in deployment. Session theft cannot be fully prevented by these flags alone. |
| SQL injection | SQLAlchemy query parameters and ORM | Review any future raw SQL. |
| Search metadata leakage | Search is restricted to owned/shared document IDs for every role, including admins, and results are checked again | Regression test asserts admin search does not reveal an ungranted document title. Add separate owner/category/date filter tests before production. |
| Duplicate active grants | Partial unique index on `(document_id, user_id)` where `revoked_at IS NULL` | Defined for SQLite/PostgreSQL. Confirm the production database supports and creates this partial index; other engines need an equivalent constraint. |
| Audit log editing by DB administrator | Hash chaining in application | **Accepted prototype limitation:** a privileged attacker could rewrite the chain or database. Hash chain is not independently tamper-proof. Production needs separate credentials and externally anchored/immutable audit storage. |
| Audit event lost due to app failure | Audit records are stored in the same database | **Known gap:** critical action and audit writes are not transactionally coupled in every route. Production should use a transaction/outbox pattern and independent monitoring. |
| Race between revocation and a request | Permission is checked at request time | Already-started downloads may continue; strict revocation semantics need coordinated streaming/storage and concurrency tests. |
| Account deactivation | Login checks active status | Existing session requests should be tested after deactivation; loader returns account state, but immediate session invalidation requires more work. |
| Cross-site scripting | Jinja autoescaping for normal templates | Avoid marking user content safe; add a restrictive Content Security Policy before production. |
| Brute-force login | Generic login errors | **Known gap:** rate limiting and lockout monitoring not yet implemented. |
| Secret leakage | `.env` ignored by Git | Rotate any secret accidentally committed; use a secret manager in deployment. |
| Data loss / deletion | Soft delete metadata | **Known gap:** recovery workflow and backups are not fully implemented. |
| Admin abuse | Admin can manage accounts and see audit metadata | Admin actions themselves are audited, but independent audit protection is not yet implemented. |
| Public demo credentials | Synthetic demo accounts for local use only | Do not use these credentials on a public deployment; create unique temporary demo credentials. |

## Out of scope / not yet built

- External immutable audit sink and independently signed checkpoints
- Malware scanning and content disarm/reconstruction
- SSO/MFA
- Document version recovery UI
- Retention/legal hold policy
- Encrypted-at-rest object storage with managed key rotation
- Formal penetration test

## Release gate

Do not upload real confidential documents or claim production readiness until all known critical gaps are resolved, tests pass, secrets and deployment are configured safely, and an independent security review has been completed.
