"""Authentication service (MongoDB / Beanie)."""
import base64
import io
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import qrcode

from backend.app.config import get_settings
from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_mfa_secret,
    get_mfa_provisioning_uri,
    hash_password,
    validate_password_policy,
    verify_mfa_token,
    verify_password,
)
from backend.app.models.documents import AuditLog, Invitation, User, UserSession
from backend.app.models.enums import UserRole

settings = get_settings()


class AuthService:
    @staticmethod
    async def register(
        email: str,
        username: str,
        password: str,
        full_name: Optional[str] = None,
        department: Optional[str] = None,
        invitation_token: Optional[str] = None,
    ) -> User:
        valid, msg = validate_password_policy(password)
        if not valid:
            raise ValueError(msg)

        role = UserRole.SECURITY_ANALYST
        if invitation_token:
            invitation = await Invitation.find_one(Invitation.token == invitation_token)
            if (
                not invitation
                or invitation.accepted_at is not None
                or invitation.expires_at < datetime.now(timezone.utc)
            ):
                raise ValueError("Invalid or expired invitation")
            if invitation.email.lower() != email.lower():
                raise ValueError("Email does not match invitation")
            role = invitation.role
            invitation.accepted_at = datetime.now(timezone.utc)
            await invitation.save()

        if await User.find_one(User.email == email) or await User.find_one(User.username == username):
            raise ValueError("User already exists")

        user = User(
            email=email,
            username=username,
            hashed_password=hash_password(password),
            full_name=full_name,
            department=department,
            role=role,
            is_verified=True,
        )
        await user.insert()
        return user

    @staticmethod
    async def login(
        email: str,
        password: str,
        mfa_token: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        user = await User.find_one(User.email == email)
        if not user:
            raise ValueError("Invalid credentials")
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise ValueError("Account is locked. Try again later.")
        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=settings.lockout_duration_minutes
                )
            await user.save()
            raise ValueError("Invalid credentials")
        if user.mfa_enabled:
            if not mfa_token or not verify_mfa_token(user.mfa_secret, mfa_token):
                return {"mfa_required": True}
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        await user.save()

        payload = {"sub": str(user.id), "role": user.role.value}
        access = create_access_token(payload)
        refresh = create_refresh_token(payload)
        decoded = decode_token(access)
        session = UserSession(
            user_id=user.id,
            token_jti=decoded["jti"],
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.fromtimestamp(decoded["exp"], tz=timezone.utc),
        )
        await session.insert()
        await AuditLog(user_id=user.id, action="login", ip_address=ip_address, success=True).insert()
        return {"access_token": access, "refresh_token": refresh, "mfa_required": False}

    @staticmethod
    async def create_invitation(email: str, role: UserRole, invited_by: UUID) -> Invitation:
        invitation = Invitation(
            email=email,
            role=role,
            token=secrets.token_urlsafe(48),
            invited_by=invited_by,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await invitation.insert()
        return invitation

    @staticmethod
    async def setup_mfa(user: User) -> dict:
        secret = generate_mfa_secret()
        user.mfa_secret = secret
        uri = get_mfa_provisioning_uri(secret, user.email)
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        await user.save()
        return {"secret": secret, "provisioning_uri": uri, "qr_code_base64": qr_b64}

    @staticmethod
    async def enable_mfa(user: User, token: str) -> bool:
        if not user.mfa_secret or not verify_mfa_token(user.mfa_secret, token):
            return False
        user.mfa_enabled = True
        await user.save()
        return True

    @staticmethod
    async def create_admin_user(
        email: str,
        username: str,
        password: str,
        role: UserRole = UserRole.SECURITY_ANALYST,
        full_name: Optional[str] = None,
    ) -> User:
        valid, msg = validate_password_policy(password)
        if not valid:
            raise ValueError(msg)
        user = User(
            email=email,
            username=username,
            hashed_password=hash_password(password),
            full_name=full_name,
            role=role,
            is_verified=True,
        )
        await user.insert()
        return user
