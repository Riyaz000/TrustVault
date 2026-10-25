# TrustVault endpoint and authorisation reference

All document IDs are untrusted input. The server loads the document and checks current ownership/grants on every request. A hidden button is not an access-control boundary. HTML state-changing requests require a CSRF token.

| Endpoint | Method | Who may call it | Security rule |
|---|---|---|---|
| `/` | GET | Anyone | Public landing page |
| `/register` | GET/POST | Anyone | Creates `owner` or `viewer`; submitted `admin` role is downgraded to viewer |
| `/login` | GET/POST | Anyone | Generic failure response; password hash checked; inactive accounts denied |
| `/logout` | POST | Authenticated users | CSRF-protected session logout |
| `/dashboard` | GET | Authenticated users | Lists only owned documents and documents with an active grant |
| `/documents/upload` | GET/POST | Owner or admin | Extension allowlist, 10 MB cap, generated private storage key; PDF/PNG/JPEG signature checks |
| `/documents/<id>` | GET | Owner or active Read/Edit grantee | Metadata is returned only after server-side object authorization |
| `/documents/<id>/download` | GET | Owner or active Read/Edit grantee | Current grant is checked before private file bytes are returned |
| `/documents/<id>/edit` | GET/POST | Owner or active Edit grantee | Only title/category metadata can be changed |
| `/documents/<id>/delete` | POST | Owner only | Soft-delete; editor grants do not permit deletion |
| `/documents/<id>/share` | GET/POST | Owner only | Grant/update Read or Edit for an existing active account |
| `/documents/<id>/revoke/<user_id>` | POST | Owner only | Revokes the active grant; subsequent requests are denied |
| `/search` | GET | Authenticated users | Searches only owned or actively shared documents, including for admins |
| `/admin/audit` | GET | Admin only | Latest 500 audit events, including denied attempts |
| `/admin/users` | GET/POST | Admin only | List accounts and activate/deactivate other accounts |

## Role model

- **Administrator:** manages account activation and reads audit metadata. No automatic document-content bypass and no ability to grant themselves access merely by being an admin. Can upload only when explicitly using an account with the admin role; uploaded documents are owned by that account.
- **Document owner:** uploads, reads, downloads, edits metadata, soft-deletes, grants and revokes access to their own documents.
- **Viewer:** reads/downloads documents for which they have an active Read or Edit grant. Cannot edit metadata unless the grant is Edit.
- **Editor grant:** may read/download and edit title/category metadata, but cannot delete or re-share the document.

## Audit fields

Each audit event includes actor ID (nullable for anonymous events), document ID (nullable for non-document events), action, outcome, details, request identifier, timestamp, previous hash and event hash. The hash chain helps detect accidental or partial edits. It is **not** independently tamper-proof against an attacker who can rewrite the database and recompute the chain; see `THREATS.md`.

This is a server-rendered web app, not a versioned public JSON API. Add explicit route-level policy and regression tests before introducing new endpoints.
