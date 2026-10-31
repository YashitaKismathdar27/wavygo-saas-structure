
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated

import pyotp
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.modules.auth.security import (
    create_access_token,
    get_vendors_collection,
    normalize_email,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = normalize_email(value)

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Enter a valid email address.")

        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/login", response_model=TokenResponse)
def login(
    credentials: LoginRequest,
    request: Request,
    vendors: Annotated[
        Collection[dict],
        Depends(get_vendors_collection)
    ],
) -> TokenResponse:

    # Get database if available
    db = getattr(request.app.state, "database", None)

    attempts = (
        db["security_login_attempts"]
        if db is not None
        else None
    )

    now = datetime.now(timezone.utc)

    attempt_key = credentials.email + ":" + (
        request.client.host
        if request.client
        else "unknown"
    )

    # Check failed login attempts
    recent_failures = (
        attempts.count_documents({
            "key": attempt_key,
            "created_at": {
                "$gte": now - timedelta(minutes=15)
            }
        })
        if attempts is not None
        else 0
    )

    if recent_failures >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again in 15 minutes."
        )

    # Find vendor
    try:
        vendor = vendors.find_one({
            "email_normalized": credentials.email
        })

    except PyMongoError as exc:
        logger.exception("Vendor authentication lookup failed.")

        raise HTTPException(
            status_code=503,
            detail="Authentication service is unavailable."
        ) from exc

    # Verify credentials
    valid = (
        vendor is not None
        and vendor.get("is_active") is True
        and isinstance(vendor.get("password_hash"), str)
        and verify_password(
            credentials.password,
            vendor["password_hash"]
        )
    )

    # Verify two-factor authentication
    if valid and vendor.get("two_factor_enabled"):
        try:
            valid = bool(
                credentials.totp_code
                and vendor.get("two_factor_secret")
                and pyotp.TOTP(
                    vendor["two_factor_secret"]
                ).verify(
                    credentials.totp_code,
                    valid_window=1
                )
            )

        except Exception:
            logger.exception("Two-factor authentication failed.")
            valid = False

    # Handle invalid login
    if not valid:

        if db is not None:

            attempts.insert_one({
                "key": attempt_key,
                "created_at": now
            })

            db["security_login_history"].insert_one({
                "vendor_id": vendor["_id"] if vendor else None,
                "email": credentials.email,
                "success": False,
                "ip_address": (
                    request.client.host
                    if request.client
                    else None
                ),
                "user_agent": request.headers.get(
                    "user-agent", ""
                )[:500],
                "created_at": now
            })

            prefs = (
                db["security_settings"].find_one({
                    "vendor_id": vendor["_id"]
                }) or {}
                if vendor
                else {}
            )

            if vendor and prefs.get("login_alerts", True):

                db["security_events"].insert_one({
                    "vendor_id": vendor["_id"],
                    "type": "failed_login",
                    "severity": "warning",
                    "message": "A failed sign-in attempt was detected.",
                    "ip_address": (
                        request.client.host
                        if request.client
                        else None
                    ),
                    "resolved": False,
                    "created_at": now
                })

        raise unauthorized()

    # Compatibility fallback for tests using injected fake collections.
    # Production login requires a configured MongoDB database.
    if db is None:

        session_id = ObjectId()

        token, expires_in = create_access_token(
            str(vendor["_id"]),
            str(session_id)
        )

        return TokenResponse(
            access_token=token,
            expires_in=expires_in
        )

    # Check previous session and device
    previous_session = db["security_sessions"].find_one({
        "vendor_id": vendor["_id"]
    })

    prefs = db["security_settings"].find_one({
        "vendor_id": vendor["_id"]
    }) or {}

    current_ip = (
        request.client.host
        if request.client
        else None
    )

    current_agent = request.headers.get(
        "user-agent", ""
    )[:500]

    # Detect new device or network
    if previous_session and prefs.get("new_device_alerts", True):

        if (
            previous_session.get("ip_address") != current_ip
            or previous_session.get("user_agent") != current_agent
        ):

            db["security_events"].insert_one({
                "vendor_id": vendor["_id"],
                "type": "new_device",
                "severity": "warning",
                "message": "A sign-in from a new device or network was detected.",
                "ip_address": current_ip,
                "user_agent": current_agent,
                "resolved": False,
                "created_at": now
            })

    # Create new session
    session_id = ObjectId()

    expires_at = now + timedelta(
        minutes=settings.jwt_access_token_minutes
    )

    db["security_sessions"].insert_one({
        "_id": session_id,
        "vendor_id": vendor["_id"],
        "ip_address": current_ip,
        "user_agent": current_agent,
        "created_at": now,
        "last_seen_at": now,
        "expires_at": expires_at,
        "revoked_at": None
    })

    # Save successful login history
    db["security_login_history"].insert_one({
        "vendor_id": vendor["_id"],
        "email": credentials.email,
        "success": True,
        "ip_address": current_ip,
        "user_agent": current_agent,
        "created_at": now
    })

    # Clear failed login attempts after successful login
    attempts.delete_many({
        "key": attempt_key
    })

    # Generate access token
    token, expires_in = create_access_token(
        str(vendor["_id"]),
        str(session_id)
    )

    return TokenResponse(
        access_token=token,
        expires_in=expires_in
    )
