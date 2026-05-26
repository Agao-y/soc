from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.auth import authenticate_user, create_access_token

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest) -> LoginResponse:
    user = authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token(user["username"])
    return LoginResponse(access_token=token, username=user["username"])
