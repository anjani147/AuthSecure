
import jwt

from datetime import datetime, timedelta, timezone

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Response,
    Request
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash

from database import engine, SessionLocal, Base
from models import User, RefreshToken

from security import (
    create_access_token,
    verify_access_token,
    generate_refresh_token,
    hash_refresh_token,
    REFRESH_TOKEN_EXPIRE_DAYS
)


# Application initialization

app = FastAPI(title="AuthSecure")

Base.metadata.create_all(bind=engine)

password_hasher = PasswordHash.recommended()

DUMMY_HASH = password_hasher.hash("dummy-password")

bearer_scheme = HTTPBearer(auto_error=False)


# Database connection

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# Input validation

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


# Home endpoint

@app.get("/")
def home():
    return {
        "message": "Authentication System is running"
    }


# Health endpoint

@app.get("/health")
def health():
    return {"status": "healthy"}


# User registration

@app.post("/register", status_code=201)
def register(
    user: UserRegister,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.username == user.username
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    new_user = User(
        username=user.username,
        password_hash=password_hasher.hash(user.password)
    )

    db.add(new_user)

    try:
        db.commit()

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "id": new_user.id,
        "username": new_user.username
    }


# User login

@app.post("/login")
def login(
    user: UserLogin,
    response: Response,
    request: Request,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.username == user.username
    ).first()

    # Corrected dummy password verification

    if not existing_user:

        password_hasher.verify(
            user.password,
            DUMMY_HASH
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    valid, updated_hash = password_hasher.verify_and_update(
        user.password,
        existing_user.password_hash
    )

    if not valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if updated_hash:
        existing_user.password_hash = updated_hash

    # Remove previous session associated with this browser

    old_token = request.cookies.get("refresh_token")

    if old_token:
        db.query(RefreshToken).filter(
            RefreshToken.token_hash ==
            hash_refresh_token(old_token)
        ).delete()

    # Generate tokens

    access_token = create_access_token(existing_user.id)

    refresh_token = generate_refresh_token()

    expires_at = datetime.now(timezone.utc).replace(
        tzinfo=None
    ) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # Store refresh token hash

    token_record = RefreshToken(
        user_id=existing_user.id,
        token_hash=hash_refresh_token(refresh_token),
        expires_at=expires_at
    )

    db.add(token_record)
    db.commit()

    # Browser cookie

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/"
    )

    response.headers["Cache-Control"] = "no-store"

    return {
        "message": "Login successful",
        "username": existing_user.username,
        "access_token": access_token,
        "token_type": "bearer"
    }


# Verify authenticated user

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db)
):

    error = HTTPException(
        status_code=401,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"}
    )

    if credentials is None:
        raise error

    try:
        user_id = verify_access_token(
            credentials.credentials
        )

    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise error

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        raise error

    return user


# Protected dashboard

@app.get("/dashboard")
def dashboard(
    response: Response,
    current_user: User = Depends(get_current_user)
):

    response.headers["Cache-Control"] = "no-store"

    return {
        "message": "Welcome to your private dashboard",
        "user_id": current_user.id,
        "username": current_user.username
    }


# Refresh access token

@app.post("/refresh")
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):

    old_token = request.cookies.get("refresh_token")

    if not old_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token missing"
        )

    old_hash = hash_refresh_token(old_token)

    token_record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == old_hash
    ).first()

    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    current_time = datetime.now(timezone.utc).replace(
        tzinfo=None
    )

    if token_record.expires_at <= current_time:
        db.delete(token_record)
        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Refresh token expired"
        )

    user = db.query(User).filter(
        User.id == token_record.user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    # Generate replacement refresh token
    new_refresh_token = generate_refresh_token()

    new_hash = hash_refresh_token(new_refresh_token)

    # Preserve the original session expiration
    expires_at = token_record.expires_at

    # Atomically replace the old token hash
    updated = db.query(RefreshToken).filter(
        RefreshToken.token_hash == old_hash,
        RefreshToken.expires_at > current_time
    ).update(
        {"token_hash": new_hash},
        synchronize_session=False
    )

    if updated != 1:
        db.rollback()

        raise HTTPException(
            status_code=401,
            detail="Refresh token already used"
        )

    access_token = create_access_token(user.id)

    db.commit()

    remaining_seconds = max(
        0,
        int((expires_at - current_time).total_seconds())
    )

    # Replace browser cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=remaining_seconds,
        path="/"
    )

    response.headers["Cache-Control"] = "no-store"

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }



# Server-side logout

@app.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):

    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:

        db.query(RefreshToken).filter(
            RefreshToken.token_hash ==
            hash_refresh_token(refresh_token)
        ).delete()

        db.commit()

    response.delete_cookie(
        key="refresh_token",
        path="/",
        httponly=True,
        secure=False,
        samesite="strict"
    )

    response.headers["Cache-Control"] = "no-store"

    return {
        "message": "Logged out successfully"
    }


# Serve frontend files

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# Website endpoint

@app.get("/website")
def website():
    return FileResponse("static/index.html")

# Administrator authorization

def require_admin(
    current_user: User = Depends(get_current_user)
):

    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required"
        )

    return current_user


# Administrator-only endpoint

@app.get("/admin/users")
def admin_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):

    users = db.query(User).all()

    return {
        "administrator": admin.username,
        "total_users": len(users),
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
            for user in users
        ]
    }
