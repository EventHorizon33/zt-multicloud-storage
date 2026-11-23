# Module contracts and build rules

Read `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` and `docs/adr/README.md` first.

## Shared foundation (do not edit without coordinating)

- `backend/app/contracts.py`: interfaces and value types every module codes against.
- `backend/app/config.py`: `Settings` (env prefix `ZT_`). Add fields only if truly needed; never add a default secret.
- `backend/app/models.py`: metadata DB models. The audit module owns its own models in `app/audit/models.py` on a separate declarative base and engine.
- `backend/app/db.py`, `backend/app/errors.py`.

## Ownership

| Package | Owner phase | Depends on (interfaces only) |
|---|---|---|
| `app/auth`, `app/policy`, `app/ratelimit.py` | 2 | `KeyManagementService`, `AuditSink`, models |
| `app/kms`, `app/cryptoengine` | 3 | nothing outside contracts/errors |
| `app/storage` | 4 | `AuditSink` (optional, injected) |
| `app/audit` | 5 | `KeyManagementService`, `StorageProvider` (for anchors, injected) |
| `app/files`, `app/detection`, `app/api`, `app/container.py`, `app/main.py` | 6 | all of the above |

A module may import `app.contracts`, `app.config`, `app.models`, `app.db`, `app.errors` and its own package. It must **not** import another subsystem's package; collaborators are passed in through constructors. In unit tests, use small in-test fakes that implement the contract.

## Rules for all code

1. Synchronous Python (FastAPI runs sync endpoints in a threadpool). No asyncio in subsystems.
2. Python 3.11+ syntax; type hints on public functions; docstrings that state the security property a function provides.
3. Randomness from `secrets` / `os.urandom` only. Comparisons of secrets with `hmac.compare_digest`.
4. Never log or put into exceptions: passwords, tokens, keys, TOTP codes/seeds, plaintext, filenames, connection strings.
5. No placeholder implementations. If something is not implemented, it is absent and listed in the module's `NOTES.md`.
6. Tests live in `backend/tests/unit/<module>/` (and `tests/integration/` for emulator-backed tests, marked `@pytest.mark.emulator`). Run with `cd backend && .venv/bin/python -m pytest tests/unit/<module> -q`. Tests must not depend on wall-clock sleeps longer than ~1s: inject a clock.
7. Every module leaves `backend/app/<module>/NOTES.md`: public API summary (class and function signatures an integrator needs), what is fully implemented, what is not, and the exact test command with the real pass/fail count from the last run.
8. Do not install packages globally. The virtualenv is `backend/.venv`; if you add a dependency, add it to `backend/requirements.txt` pinned.
9. Do not edit files outside your package and its tests, except `requirements.txt` and (if unavoidable) an additive change to the shared foundation, which you must report.
