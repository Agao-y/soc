import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.auth import create_access_token, get_current_user
from app.rate_limiter import get_client_ip, login_limiter, register_limiter
from app.user_store import authenticate_user, create_user, list_users

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class RegisterRequest(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    password: str = Field(min_length=8, max_length=64)


class UserInfo(BaseModel):
    username: str
    role: str


@router.get("/auth/me", response_model=UserInfo)
def me(current_user: dict = Depends(get_current_user)) -> UserInfo:
    """返回当前登录用户的权威角色信息"""
    return UserInfo(username=current_user["username"], role=current_user.get("role", "analyst"))


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request) -> LoginResponse:
    login_limiter.check(f"login:{body.username}")
    login_limiter.check(f"login_ip:{get_client_ip(request)}")

    user = authenticate_user(body.username, body.password)
    if not user:
        time.sleep(0.8)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    token = create_access_token(user["username"])
    return LoginResponse(access_token=token, username=user["username"], role=user.get("role", "analyst"))


@router.post("/auth/register", response_model=UserInfo)
def register(
    body: RegisterRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> UserInfo:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅管理员可创建用户")
    register_limiter.check(f"register:{get_client_ip(request)}")

    result = create_user(body.username, body.password, role="analyst")
    if not result:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="用户名已存在")
    return UserInfo(**result)


@router.get("/auth/users", response_model=list[UserInfo])
def get_users(current_user: dict = Depends(get_current_user)) -> list[UserInfo]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅管理员可查看")
    return [UserInfo(**u) for u in list_users()]
