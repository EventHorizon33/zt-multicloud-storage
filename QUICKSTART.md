# Quick start

Everything runs locally. No cloud accounts and no Docker are needed: the three providers are local
emulators (moto for S3, Azurite for Azure Blob, gcp-storage-emulator for GCS) driven by the real
AWS, Azure and Google SDKs.

**Requirements:** Linux or macOS (Windows: use WSL), Python 3.11+, Node.js 20+ with npm.

## 1. One-time setup

```bash
cd zt-multicloud-storage
bash scripts/setup.sh
```

## 2. Run the automated demonstration (fastest way to see everything)

```bash
scripts/demo.sh
```

Starts the emulators and the backend by itself, runs the 16 steps (two users, upload, chunk
distribution, raw ciphertext at each provider, verified download, denied access, chunk tampering,
audit tampering, a real provider outage, the audit trail), prints every check, and cleans up.

## 3. Run the application and use the web UI

Terminal 1 (backend + emulators):

```bash
export ZT_BOOTSTRAP_ADMIN_USERNAME=admin
export ZT_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-password-here'
scripts/run-dev.sh
```

Terminal 2 (web UI):

```bash
cd frontend && npm run dev
```

Open http://localhost:5173.

1. Sign in as `admin`. MFA is mandatory: the session is restricted until you enrol. Go to
   **Account**, scan the QR code with an authenticator app (Google Authenticator, Authy,
   Microsoft Authenticator…), enter a code to activate, then **sign out and sign in again** with
   the password and a code.
2. Register more users from the sign-in page; each enrols MFA the same way within 24 hours.
3. Upload files under **Files**, watch where chunks go under **Storage distribution**, look at
   **Security centre** and **Audit explorer** (run "Verify chain").
4. To demonstrate a provider outage: `scripts/emulators.sh stop-one gcs` (and `start-one gcs`), or
   use the admin's simulated-fault controls on the Storage distribution page.

Stop: Ctrl-C in both terminals, then `scripts/emulators.sh stop`.
To start over with empty data: `rm -rf backend/data && scripts/emulators.sh reset`.

## 4. Run the tests

```bash
scripts/emulators.sh start
cd backend && .venv/bin/python -m pytest -q        # whole suite
cd .. && scripts/attacks/run_all.sh                # attack scenarios as a table
scripts/emulators.sh stop
cd frontend && npm run build && npx vitest run      # frontend
```

Without the emulators running, the emulator tests are skipped (with a reason), not passed.
