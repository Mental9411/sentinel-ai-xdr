"""Authentication API routes."""
from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.app.api.deps import get_current_user
from backend.app.core.rbac import require_permission
from backend.app.models.documents import User
from backend.app.models.enums import UserRole
from backend.app.schemas.auth import (
    InvitationCreate,
    InvitationResponse,
    MFASetupResponse,
    MFAVerify,
    TokenResponse,
    UserCreateAdmin,
    UserLogin,
    UserRegister,
    UserResponse,
)
from backend.app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(data: UserRegister):
    try:
        user = await AuthService.register(
            data.email, data.username, data.password,
            data.full_name, data.department, data.invitation_token,
        )
        return UserResponse.from_user(user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, request: Request):
    try:
        result = await AuthService.login(
            data.email, data.password, data.mfa_token,
            request.client.host if request.client else None,
            request.headers.get("user-agent"),
        )
        if result.get("mfa_required"):
            return TokenResponse(access_token="", refresh_token="", mfa_required=True)
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.from_user(current_user)


@router.post("/invite", response_model=InvitationResponse)
async def invite_user(
    data: InvitationCreate,
    current_user: User = Depends(require_permission("users:invite")),
):
    inv = await AuthService.create_invitation(data.email, data.role, current_user.id)
    return InvitationResponse(
        id=inv.id,
        email=inv.email,
        role=inv.role,
        expires_at=inv.expires_at.isoformat(),
    )


@router.post("/users", response_model=UserResponse, status_code=201)
async def admin_create_user(
    data: UserCreateAdmin,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in (UserRole.SUPER_ADMIN, UserRole.SOC_MANAGER):
        raise HTTPException(status_code=403, detail="Admin only")
    try:
        user = await AuthService.create_admin_user(
            data.email, data.username, data.password, data.role, data.full_name
        )
        return UserResponse.from_user(user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(current_user: User = Depends(get_current_user)):
    return MFASetupResponse(**await AuthService.setup_mfa(current_user))


@router.post("/mfa/enable")
async def mfa_enable(data: MFAVerify, current_user: User = Depends(get_current_user)):
    if not await AuthService.enable_mfa(current_user, data.token):
        raise HTTPException(status_code=400, detail="Invalid MFA token")
    return {"message": "MFA enabled successfully"}
