"""/api/admin: users, KMS keys, pseudonym re-identification. No route here
returns file content or keys (separation of duties, R5)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import Caller, get_caller
from app.api.schemas import CidrsIn, ClearanceIn, PseudonymIn, RoleIn, RotateIn

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _a(caller: Caller):
    return caller.container.admin


@router.get("/users")
def users(caller: Caller = Depends(get_caller)) -> dict:
    return {"users": _a(caller).list_users(caller.db, caller.subject, caller.context)}


@router.put("/users/{user_id}/role")
def set_role(user_id: str, body: RoleIn, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).set_role(caller.db, caller.subject, caller.context, user_id[:32], body.role)


@router.put("/users/{user_id}/clearance")
def set_clearance(user_id: str, body: ClearanceIn, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).set_clearance(caller.db, caller.subject, caller.context, user_id[:32], body.clearance)


@router.post("/users/{user_id}/disable")
def disable(user_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).set_active(caller.db, caller.subject, caller.context, user_id[:32], False)


@router.post("/users/{user_id}/enable")
def enable(user_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).set_active(caller.db, caller.subject, caller.context, user_id[:32], True)


@router.put("/users/{user_id}/allowed-cidrs")
def set_cidrs(user_id: str, body: CidrsIn, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).set_cidrs(caller.db, caller.subject, caller.context, user_id[:32], body.cidrs)


@router.post("/users/{user_id}/revoke-sessions")
def revoke_sessions(user_id: str, caller: Caller = Depends(get_caller)) -> dict:
    n = _a(caller).revoke_sessions(caller.db, caller.subject, caller.context, user_id[:32])
    return {"sessions_revoked": n}


@router.post("/users/{user_id}/mfa-enrollment-code")
def mfa_enrollment_code(user_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).issue_mfa_enrollment_code(caller.db, caller.subject, caller.context, user_id[:32])


@router.post("/users/{user_id}/mfa-reset")
def mfa_reset(user_id: str, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).reset_mfa(caller.db, caller.subject, caller.context, user_id[:32])


@router.get("/kms/keys")
def kms_keys(caller: Caller = Depends(get_caller)) -> dict:
    return {"keys": _a(caller).list_keys(caller.db, caller.subject, caller.context)}


@router.post("/kms/rotate")
def kms_rotate(body: RotateIn, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).rotate_key(caller.db, caller.subject, caller.context, body.purpose)


@router.post("/pseudonym-lookup")
def pseudonym_lookup(body: PseudonymIn, caller: Caller = Depends(get_caller)) -> dict:
    return _a(caller).reidentify(caller.db, caller.subject, caller.context, body.pseudonym)
