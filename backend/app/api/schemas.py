"""Pydantic request/response models. Requests forbid unknown fields and cap
every string; responses document the exact shapes in docs/API.md."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

USERNAME_PATTERN = r"^[A-Za-z0-9_.-]{3,64}$"
TOTP_PATTERN = r"^[0-9]{6}$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- auth ---- #
class RegisterIn(Strict):
    username: str = Field(pattern=USERNAME_PATTERN, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, pattern=TOTP_PATTERN)


class CodeIn(Strict):
    code: str = Field(pattern=TOTP_PATTERN)


class MfaEnrollIn(Strict):
    """Optional body of POST /api/auth/mfa/enroll (ADR-0010)."""
    enrollment_code: str | None = Field(default=None, min_length=16, max_length=32,
                                        pattern=r"^[A-Za-z0-9 -]{16,32}$")
    current_code: str | None = Field(default=None, pattern=TOTP_PATTERN)


class PasswordChangeIn(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class RegisterOut(BaseModel):
    status: Literal["accepted"] = "accepted"


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    clearance: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime | None


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    session_id: str
    mfa_verified: bool
    user: UserOut


class SessionOut(BaseModel):
    id: str
    created_at: datetime | None
    last_seen_at: datetime | None
    expires_at: datetime | None
    mfa_verified: bool
    current: bool


class MeOut(BaseModel):
    user: UserOut
    session: SessionOut
    audit_pseudonym: str
    restricted: bool
    mfa_fresh: bool


class MfaEnrollOut(BaseModel):
    secret: str
    otpauth_uri: str


# ---------------------------------------------------------------- files --- #
class ShareIn(Strict):
    username: str = Field(min_length=1, max_length=64)


# --------------------------------------------------------------- storage --- #
FaultMode = Literal["none", "unavailable", "timeout", "corrupt-reads", "fail-n", "drop-writes", "slow"]


class FaultIn(Strict):
    mode: FaultMode
    delay: float | None = Field(default=None, ge=0, le=30)
    n: int | None = Field(default=None, ge=1, le=1000)


# ----------------------------------------------------------------- audit --- #
class VerifyIn(Strict):
    from_seq: int | None = Field(default=None, ge=1, le=2**63 - 1)
    to_seq: int | None = Field(default=None, ge=1, le=2**63 - 1)
    check_anchors: bool = True


# -------------------------------------------------------------- security --- #
class PolicyUpdateIn(Strict):
    changes: dict[str, Any] = Field(min_length=1, max_length=16)


# ----------------------------------------------------------------- admin --- #
class RoleIn(Strict):
    role: Literal["user", "auditor", "admin"]


class ClearanceIn(Strict):
    clearance: Literal["public", "internal", "confidential", "restricted"]


class CidrsIn(Strict):
    cidrs: list[str] = Field(max_length=32)


class RotateIn(Strict):
    purpose: Literal["file-dek-wrap", "secret-encryption", "token-signing", "audit-signing",
                     "audit-pseudonym", "lookup-hmac"]


class PseudonymIn(Strict):
    pseudonym: str = Field(pattern=r"^u_[0-9a-f]{32}$")
