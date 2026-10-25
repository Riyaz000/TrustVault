# TrustVault — final submission checklist

## Implementation included in this bundle

- [x] Flask application, SQLAlchemy models and private file storage path
- [x] Admin, Owner and Viewer roles; public registration cannot create Admin
- [x] Per-document Read/Edit grants and owner-only revoke/share/delete
- [x] Authorization check on detail, download, edit, delete, share and revoke routes
- [x] Search scoped to documents the current user owns or is actively granted
- [x] Audit events for document actions, permission changes and denied document-access attempts
- [x] Hash-chain verification shown in the admin audit view (detects some edits; does not prevent privileged rewriting)
- [x] Upload allowlist, 10 MB cap, generated storage keys, and basic PDF/PNG/JPEG signature checks
- [x] Security tests and regression tests
- [x] `THREATS.md`, `PROMPTS.md`, `API.md`, `schema.sql`, `WRITEUP.md`, `DEMO_SCRIPT.md`
- [x] Dark Obsidian + Electric Violet + Ice Cyan UI theme

## Still required before submission

- [ ] On your Windows machine, install dependencies and run `python -m pytest -q`; record the actual result in `TEST_STATUS.md`.
- [ ] Test every security case in `THREATS.md` against the running application.
- [ ] Commit the changes in your Git repository and replace the pending prompt-log commit reference with the real GitHub commit URL.
- [ ] Maintain honest development commits across real work sessions; do not fabricate history.
- [ ] Deploy to a public HTTPS URL with unique temporary demo credentials and synthetic seed data.
- [ ] Verify the deployed URL from a clean browser and test that the viewer loses access immediately after revocation.
- [ ] Record the five-minute demo following `DEMO_SCRIPT.md`.
- [ ] Do not publish `.env`, real passwords, personal data, or real confidential files.

## Run on Windows

1. Extract the ZIP to a folder, for example `C:\TrustVault`.
2. Open PowerShell in the extracted `TrustVault` folder.
3. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. Create local environment settings and set a unique, strong secret:

   ```powershell
   Copy-Item .env.example .env
   ```

6. Seed synthetic demo accounts and a sample contract:

   ```powershell
   python scripts/seed_demo.py
   ```

7. Start the app:

   ```powershell
   python app.py
   ```

8. Open `http://127.0.0.1:5000`.
9. In another activated PowerShell window, run `python -m pytest -q`.

## Final security verification

- Owner can view and download their document.
- A user without a grant cannot view or download it, including by manually entering a document ID.
- Read grant permits viewing/downloading but not editing metadata.
- Edit grant permits metadata edits but not deletion or re-sharing.
- After owner revokes a grant, the same viewer's next document request is denied.
- Public registration cannot create an administrator account.
- Admin search does not reveal ungranted document metadata.
- Denied document-access attempts appear in the audit view.
- Changing an audit event breaks the displayed hash-chain verification.

## Honest status

The source syntax was checked in the authoring environment. Automated tests were not run there because dependencies could not be downloaded from the package index. This is an educational prototype and must not be presented as production-certified. Review the accepted risks in `THREATS.md` before using real confidential documents.
