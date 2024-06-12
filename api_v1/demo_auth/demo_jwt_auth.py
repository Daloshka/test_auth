import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Form,
)
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from auth import utils as auth_utils
from users.schemas import UserSchema

http_bearer = HTTPBearer()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/demo_auth/jwt/login"
)


class TokenInfo(BaseModel):
    access_token: str
    token_type: str


router = APIRouter(prefix="/jwt", tags=["JWT"])

john = UserSchema(
    id=1,
    username="john",
    password=auth_utils.hash_password("password"),
    email="andyivest@gmail.com",
)

sam = UserSchema(
    id=2,
    username="sam",
    active=False,
    password=auth_utils.hash_password("secret"),
)

users_db: dict[str, UserSchema] = {
    john.username: john,
    sam.username: sam,
}


def validate_auth_user(
        username: str = Form(),
        password: str = Form(),
):
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password"
    )
    if not (user := users_db.get(username)):
        raise unauthed_exc

    if not auth_utils.validate_password(
            password=password,
            hashed_password=user.password,
    ):
        raise unauthed_exc

    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return user  # id=1 username='john' password=b'$2b$12$wjz06EattbOi1vfBJne.4eLX8zlf7XUdtzwmISpxi5RLe8d0dkZt6' email='andyivest@gmail.com' active=True


def get_current_token_payload(
        credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
        token: str = Depends(oauth2_scheme),
) -> dict:
    token = credentials.credentials
    try:
        payload = auth_utils.decode_jwt(token)
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return payload


def get_current_auth_user(
        payload: dict = Depends(get_current_token_payload),
) -> UserSchema:
    username: str | None = payload.get("username")
    user = users_db.get(username)
    if user.active is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="User not found",
    )


@router.post("/login")
def auth_user_issue_jwt(
        user: UserSchema = Depends(validate_auth_user),
):
    jwt_payload = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
    }
    token = auth_utils.encode_jwt(jwt_payload)
    return TokenInfo(
        access_token=token,
        token_type="Bearer"
    )


@router.get("/users/me")
def auth_user_self_info(
        user: UserSchema = Depends(get_current_auth_user),
):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
    }
