# TrustVault

TrustVault is a security-focused document management prototype. It combines account authentication, per-document named-user Read/Edit grants, private file storage, immediate checks of active permissions, document search, and an audit log that records successful and denied security-relevant actions.

## Security status — read before using

This is a **demo/assessment project, not a production-certified secure document platform**. Do not upload real confidential documents until the limitations in `THREATS.md` are addressed and an independent security review is complete.

- The administrator role does not automatically grant document-content access.
- Files are stored under `PRIVATE_STORAGE`, outside Flask's public `static` directory. Downloads pass through a route that checks authorization on each request.
- Revocation blocks subsequent requests. It cannot retrieve copies already downloaded by a user, and a download already in progress may continue.
- Audit events are hash-chained, but the chain is not independently tamper-proof if an attacker can rewrite the database. Production needs independently protected/anchored audit storage.
- File extension/signature checks are not malware scanning or full format validation.
- Rate limiting, MFA/SSO, independent audit storage, version recovery, and malware scanning are not implemented.

## Roles and permissions

| Capability | Admin | Owner | Viewer | User with Edit grant |
|---|---:|---:|---:|---:|
| Manage account activation | Yes | No | No | No |
| View audit metadata | Yes | No | No | No |
| Upload a document | Yes | Yes | No | No |
| Read/download own document | If owner | Yes | N/A | N/A |
| Read/download a granted document | Only with explicit grant | Only with explicit grant | Read or Edit grant | Yes |
| Edit title/category | Only if owner or Edit grant | Yes | No | Yes |
| Delete document | Only if owner | Yes | No | No |
| Grant/revoke access | Only as owner | Yes | No | No |

Public registration can create Owner or Viewer accounts; it cannot create an Administrator. Admin accounts should be created through the controlled seed/setup process, not by trusting a form field.

## Requirements

- Python 3.11+
- pip
- SQLite for local development; optional MySQL via `DATABASE_URL`

## Run locally on Windows

Open PowerShell in the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/seed_demo.py
python app.py
```

Open `http://127.0.0.1:5000`. The built-in Flask server is for local development only; do not expose it publicly. Set a long random `SECRET_KEY`, use HTTPS, and set `COOKIE_SECURE=1` for deployment.

### Demo accounts (local only)

Run `python scripts/seed_demo.py` to create synthetic users:

- Admin: `admin@trustvault.local` / `DemoAdminPassword!2026`
- Owner: `owner@trustvault.local` / `DemoOwnerPassword!2026`
- Viewer: `viewer@trustvault.local` / `DemoViewerPassword!2026`

These known credentials are for local demo only. Do not deploy them as public credentials. For a live demo, use unique temporary credentials and remove or disable the seed accounts afterwards.

## Tests

```powershell
python -m pip install -r requirements.txt
python -m pytest -q
```

The test suite includes anonymous access, cross-owner IDOR attempts, ungranted viewers, read/edit separation, owner-only deletion/sharing, revocation, audit records for denied attempts, admin metadata isolation, and upload validation. The tests have **not been executed in the authoring environment** because the environment could not reach the package index to install Flask dependencies. Run them locally and record the real result before submission.

## Database and private files

- `app.py` defines the SQLAlchemy models and creates missing tables on startup for the prototype.
- `schema.sql` documents the relational schema.
- `private_uploads/` is the default private object directory; it must never be configured as a static/public web directory.
- `DATABASE_URL` can be set to a MySQL URI such as `mysql+pymysql://USER:PASSWORD@HOST/DATABASE`. Keep credentials in environment variables, not Git.

For a production database, use migrations, a least-privilege database account, backups, encryption at rest, and a separate audit-write/read boundary.

## Documentation and submission materials

- `API.md` — endpoint-level access policy.
- `THREATS.md` — threats, controls, accepted risks and release gates.
- `PROMPTS.md` — dated AI-use log. Replace pending commit references with real commit links after each change; never invent commit IDs.
- `WRITEUP.md` — short project write-up and honest limitations.
- `DEMO_SCRIPT.md` — five-minute walkthrough plan.

## Git workflow for an honest prompt log

After reviewing and testing a change:

```powershell
git status
git add .
git commit -m "Harden TrustVault authorization and refresh UI"
git push origin main
git rev-parse HEAD
```

Use the actual commit hash returned by Git to update the relevant `PROMPTS.md` entry. Keep commits spread across real development sessions; do not fabricate a history.
