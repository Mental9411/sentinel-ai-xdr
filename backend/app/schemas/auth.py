"""Authentication schemas."""
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from backend.app.models.enums import UserRole


class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12)
    full_name: Optional[str] = None
    department: Optional[str] = None
    invitation_token: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    mfa_token: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False


class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    full_name: Optional[str] = None
    department: Optional[str] = None
    role: str
    is_active: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True

    @classmethod
    def from_user(cls, user) -> "UserResponse":
        return cls(
            id=user.id,
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            department=user.department,
            role=user.role.value if hasattr(user.role, "value") else str(user.role),
            is_active=user.is_active,
            mfa_enabled=user.mfa_enabled,
        )


class InvitationCreate(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.SECURITY_ANALYST


class InvitationResponse(BaseModel):
    id: UUID
    email: str
    role: UserRole
    expires_at: str

    class Config:
        from_attributes = True


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_base64: Optional[str] = None


class MFAVerify(BaseModel):
    token: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)


class UserCreateAdmin(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.SECURITY_ANALYST
    department: Optional[str] = None
