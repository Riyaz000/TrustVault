# TrustVault — short project write-up

## What was built

TrustVault is a Flask web application for managing sensitive documents. It supports Administrator, Document Owner and Viewer accounts; uploads with a size and extension allowlist; per-document Read/Edit grants to existing named users; owner-controlled revocation; search by title, owner, category and date; a private file directory; account administration; and an audit view for document and permission activity.

## Permission model in my own words

Every document has one owner. Other users receive an explicit grant for that specific document. A Read grant permits metadata viewing and download. An Edit grant permits those same actions plus title/category changes. Only the owner may delete, share, or revoke. Administrators can manage account status and review audit metadata but do not get automatic access to document contents. The server loads the target document and checks the current grant on each document route; the interface is not trusted to enforce permissions.

## Revocation and storage

Uploaded bytes are stored under a random generated key outside the public static directory. The original filename is only used as the download name. Download requests pass through the authenticated route and re-check the current active grant. Revocation blocks later requests. It cannot recall a previously downloaded copy, and a transfer already in progress may finish; this limitation is stated rather than hidden.

## Audit design and limitation

Events record actor, document, action, outcome, details, timestamp, request ID, previous hash and event hash. This hash chain can reveal some edits or missing/reordered events, but it is not an immutable audit system: a database-privileged attacker can rewrite records and recompute the chain. A production system should write to a separately permissioned, append-only or externally anchored audit sink, and atomically couple security-sensitive changes to audit events.

## AI use and review

AI was used to help scaffold routes, tests, documentation and the UI. AI output is not accepted as proof of security. The important review case in this iteration was the admin search path: an administrator could initially receive metadata for all documents even though admin content access was intended to require an explicit grant. The search query was changed to filter to owned or actively granted documents for every role, and a regression test was added. Another important check is that hash chaining is not described as tamper-proof; that limitation is documented in `THREATS.md`.

## Deliberately not built

This assessment prototype does not include malware scanning, full format parsing, MFA/SSO, rate limiting, document version recovery, legal hold/retention workflows, external immutable audit storage, or a full cloud object-storage/KMS integration. These were kept out to prioritise a clear per-document authorization model and test coverage.

## What is unfinished

The automated tests need to be run on a machine with dependencies installed. A public deployment still needs HTTPS and secure cookies, strong secrets, unique demo accounts, persistent private storage, database backups, rate limiting, external audit protection and independent security testing. No real confidential documents should be uploaded until those controls are in place.
