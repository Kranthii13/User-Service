import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Request, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from application.services import UserService
from dependencies import get_user_service
from infrastructure.auth import (
    create_access_token, 
    generate_split_refresh_token, 
    hash_refresh_token, 
    verify_refresh_token_hash,
    verify_token,
    get_jwks
)
from infrastructure.database import SessionLocal, RefreshTokenTable

logger = logging.getLogger("User-Service-Audit")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def parse_device_name(user_agent: Optional[str]) -> str:
    """Normalizes User-Agent strings into clean user-facing device descriptions"""
    if not user_agent:
        return "Unknown Device"
    ua = user_agent.lower()
    os_name = "Desktop"
    if "windows" in ua: os_name = "Windows"
    elif "mac os" in ua or "macintosh" in ua: os_name = "macOS"
    elif "iphone" in ua or "ipad" in ua: os_name = "iOS"
    elif "android" in ua: os_name = "Android"
    elif "linux" in ua: os_name = "Linux"

    browser = "Browser"
    if "chrome" in ua and "edg" not in ua: browser = "Chrome"
    elif "safari" in ua and "chrome" not in ua: browser = "Safari"
    elif "firefox" in ua: browser = "Firefox"
    elif "edg" in ua: browser = "Edge"

    return f"{os_name} {browser}"

# --- API Schemas ---
class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    bio: Optional[str] = None

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    theme: Optional[str] = None
    accent_color: Optional[str] = None

class ProfileResponse(BaseModel):
    bio: Optional[str] = None
    theme: Optional[str] = "dark"
    accent_color: Optional[str] = "#0ea5e9"
    
    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    first_name: str
    last_name: str
    profile: ProfileResponse
    
    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class SessionResponse(BaseModel):
    session_id: uuid.UUID
    device_name: str
    last_seen: datetime
    is_current: bool

router = APIRouter(tags=["Users"])

# --- JWKS PUBLIC KEY ENDPOINT ---
@router.get("/.well-known/jwks.json", status_code=status.HTTP_200_OK)
def jwks_endpoint():
    return get_jwks()

# --- AUTHENTICATION ---
@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def login_user_endpoint(
    request_data: UserLoginRequest, 
    req: Request,
    response: Response, 
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    try:
        user = service.authenticate_user(email=request_data.email, password=request_data.password)
        
        # Enforce Max 5 Active Sessions via Least Recently Used (LRU) Eviction
        active_sessions = db.query(RefreshTokenTable).filter(
            RefreshTokenTable.user_id == user.id,
            RefreshTokenTable.revoked == False,
            RefreshTokenTable.expires_at > datetime.utcnow()
        ).order_by(asc(RefreshTokenTable.last_used)).all()
        
        if len(active_sessions) >= 5:
            # Evict oldest session
            oldest_session = active_sessions[0]
            oldest_session.revoked = True
            db.commit()

        session_id = uuid.uuid4()
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "sid": str(session_id)})
        token_id_str, secret_token, combined_cookie = generate_split_refresh_token()
        
        family_id = str(uuid.uuid4())
        hashed_argon2 = hash_refresh_token(secret_token)
        expires_at = datetime.utcnow() + timedelta(days=7)
        device_name = parse_device_name(req.headers.get("user-agent"))
        ip_address = req.client.host if req.client else "127.0.0.1"

        db_token = RefreshTokenTable(
            token_id=uuid.UUID(token_id_str),
            session_id=session_id,
            user_id=user.id,
            token_hash=hashed_argon2,
            family=family_id,
            device_name=device_name,
            ip_address=ip_address,
            expires_at=expires_at,
            revoked=False
        )
        db.add(db_token)
        db.commit()

        # Structured Audit Log
        logger.info(f"AUDIT: EVENT=LOGIN_SUCCESS USER_ID={user.id} SESSION_ID={session_id} IP={ip_address} DEVICE='{device_name}'")
        
        response.set_cookie(
            key="refresh_token",
            value=combined_cookie,
            httponly=True,
            samesite="lax",
            max_age=7 * 24 * 60 * 60,
            secure=False
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
    except ValueError as e:
        logger.warning(f"AUDIT: EVENT=LOGIN_FAILURE EMAIL={request_data.email} REASON='{str(e)}'")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

# --- CREATE / REGISTER ---
@router.post("/", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def create_user_endpoint(
    request_data: UserCreateRequest, 
    req: Request,
    response: Response, 
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    try:
        user = service.create_user(
            email=request_data.email, password=request_data.password,
            first_name=request_data.first_name, last_name=request_data.last_name, bio=request_data.bio
        )
        session_id = uuid.uuid4()
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "sid": str(session_id)})
        token_id_str, secret_token, combined_cookie = generate_split_refresh_token()
        
        family_id = str(uuid.uuid4())
        hashed_argon2 = hash_refresh_token(secret_token)
        expires_at = datetime.utcnow() + timedelta(days=7)
        device_name = parse_device_name(req.headers.get("user-agent"))
        ip_address = req.client.host if req.client else "127.0.0.1"

        db_token = RefreshTokenTable(
            token_id=uuid.UUID(token_id_str),
            session_id=session_id,
            user_id=user.id,
            token_hash=hashed_argon2,
            family=family_id,
            device_name=device_name,
            ip_address=ip_address,
            expires_at=expires_at,
            revoked=False
        )
        db.add(db_token)
        db.commit()

        logger.info(f"AUDIT: EVENT=REGISTER_SUCCESS USER_ID={user.id} SESSION_ID={session_id} IP={ip_address}")
        
        response.set_cookie(
            key="refresh_token",
            value=combined_cookie,
            httponly=True,
            samesite="lax",
            max_age=7 * 24 * 60 * 60,
            secure=False
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration error: {str(e)}")

# --- REFRESH TOKEN (Split Token + O(1) DB Lookup + Argon2id + Atomic Locks + Grace Period) ---
class RefreshResponse(BaseModel):
    access_token: str
    token_type: str

@router.post("/refresh", response_model=RefreshResponse, status_code=status.HTTP_200_OK)
def refresh_token_endpoint(
    response: Response,
    refresh_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not refresh_token or "." not in refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing or malformed")

    parts = refresh_token.split(".")
    if len(parts) != 2:
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token format")

    token_id_str, secret_token = parts[0], parts[1]

    try:
        token_id_uuid = uuid.UUID(token_id_str)
    except ValueError:
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token identifier")

    # Fast O(1) Primary Key Lookup with Atomic Row Lock
    stored_token = db.query(RefreshTokenTable).filter(RefreshTokenTable.token_id == token_id_uuid).with_for_update().first()

    if not stored_token:
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session not found")

    # Verify Argon2id secret hash
    if not verify_refresh_token_hash(stored_token.token_hash, secret_token):
        response.delete_cookie("refresh_token")
        logger.warning(f"AUDIT: EVENT=TOKEN_HASH_MISMATCH TOKEN_ID={token_id_uuid} USER_ID={stored_token.user_id}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token secret")

    now = datetime.utcnow()

    # Reuse Detection & Concurrent Tab 10-Second Grace Period
    if stored_token.revoked:
        time_since_used = (now - stored_token.last_used.replace(tzinfo=None)).total_seconds()
        if time_since_used < 10:
            # Legitimate multi-tab concurrent refresh -> Return active access token without family revocation
            logger.info(f"AUDIT: EVENT=TOKEN_REFRESH_CONCURRENT_GRACE USER_ID={stored_token.user_id} SESSION_ID={stored_token.session_id}")
            new_access_token = create_access_token(data={"sub": str(stored_token.user_id), "sid": str(stored_token.session_id)})
            return {"access_token": new_access_token, "token_type": "bearer"}

        # Real token reuse (Compromise Detected!) -> Revoke all tokens in family
        db.query(RefreshTokenTable).filter(RefreshTokenTable.family == stored_token.family).update({"revoked": True})
        db.commit()
        response.delete_cookie("refresh_token")
        logger.critical(f"AUDIT: EVENT=TOKEN_REUSE_SECURITY_ALERT USER_ID={stored_token.user_id} FAMILY={stored_token.family}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Security Alert: Session revoked due to token reuse")

    if stored_token.expires_at.replace(tzinfo=None) < now:
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh session expired")

    # Mark old token revoked & update last_used
    stored_token.revoked = True
    stored_token.last_used = now

    # Issue new access token + new split refresh token
    new_token_id_str, new_secret_token, new_combined = generate_split_refresh_token()
    new_hashed_argon2 = hash_refresh_token(new_secret_token)

    new_db_token = RefreshTokenTable(
        token_id=uuid.UUID(new_token_id_str),
        session_id=stored_token.session_id,
        user_id=stored_token.user_id,
        token_hash=new_hashed_argon2,
        family=stored_token.family,
        device_name=stored_token.device_name,
        ip_address=stored_token.ip_address,
        expires_at=now + timedelta(days=7),
        revoked=False
    )
    db.add(new_db_token)
    db.commit()

    logger.info(f"AUDIT: EVENT=TOKEN_REFRESH_SUCCESS USER_ID={stored_token.user_id} SESSION_ID={stored_token.session_id}")

    new_access_token = create_access_token(data={"sub": str(stored_token.user_id), "sid": str(stored_token.session_id)})
    
    response.set_cookie(
        key="refresh_token",
        value=new_combined,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60,
        secure=False
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

# --- SESSION MANAGEMENT (List Active Devices) ---
@router.get("/sessions", response_model=List[SessionResponse])
def get_user_sessions_endpoint(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    
    payload = verify_token(authorization.split(" ")[1])
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    user_id_str = payload.get("sub")
    current_sid_str = payload.get("sid")
    
    tokens = db.query(RefreshTokenTable).filter(
        RefreshTokenTable.user_id == uuid.UUID(user_id_str),
        RefreshTokenTable.revoked == False,
        RefreshTokenTable.expires_at > datetime.utcnow()
    ).order_by(desc(RefreshTokenTable.last_used)).all()

    seen_sessions = set()
    result = []
    for t in tokens:
        if t.session_id not in seen_sessions:
            seen_sessions.add(t.session_id)
            result.append({
                "session_id": t.session_id,
                "device_name": t.device_name or "Unknown Device",
                "last_seen": t.last_used,
                "is_current": str(t.session_id) == current_sid_str
            })
    return result

# --- REVOKE SINGLE SESSION ---
@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session_endpoint(
    session_id: uuid.UUID,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    
    payload = verify_token(authorization.split(" ")[1])
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    user_id_str = payload.get("sub")

    db.query(RefreshTokenTable).filter(
        RefreshTokenTable.user_id == uuid.UUID(user_id_str),
        RefreshTokenTable.session_id == session_id
    ).update({"revoked": True})
    db.commit()

    logger.info(f"AUDIT: EVENT=REVOKE_SESSION USER_ID={user_id_str} TARGET_SESSION={session_id}")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- LOGOUT ---
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout_endpoint(
    response: Response,
    refresh_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if refresh_token and "." in refresh_token:
        token_id_str = refresh_token.split(".")[0]
        try:
            stored_token = db.query(RefreshTokenTable).filter(RefreshTokenTable.token_id == uuid.UUID(token_id_str)).first()
            if stored_token:
                stored_token.revoked = True
                db.commit()
                logger.info(f"AUDIT: EVENT=LOGOUT_SUCCESS USER_ID={stored_token.user_id} SESSION_ID={stored_token.session_id}")
        except Exception:
            pass

    response.delete_cookie("refresh_token")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- LOGOUT ALL DEVICES ---
@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all_endpoint(
    response: Response,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    if authorization and authorization.startswith("Bearer "):
        payload = verify_token(authorization.split(" ")[1])
        if payload:
            user_id_str = payload.get("sub")
            db.query(RefreshTokenTable).filter(RefreshTokenTable.user_id == uuid.UUID(user_id_str)).update({"revoked": True})
            db.commit()
            logger.info(f"AUDIT: EVENT=LOGOUT_ALL USER_ID={user_id_str}")

    response.delete_cookie("refresh_token")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- READ (ALL) ---
@router.get("/", response_model=List[UserResponse])
def get_all_users_endpoint(service: UserService = Depends(get_user_service)):
    return service.get_all_users()

# --- READ (ONE) ---
@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id_endpoint(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    user = service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# --- UPDATE ---
@router.put("/{user_id}", response_model=UserResponse)
def update_user_endpoint(user_id: uuid.UUID, request_data: UserUpdateRequest, service: UserService = Depends(get_user_service)):
    updated_user = service.update_user(
        user_id=user_id,
        first_name=request_data.first_name,
        last_name=request_data.last_name,
        bio=request_data.bio,
        theme=request_data.theme,
        accent_color=request_data.accent_color
    )
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return updated_user

# --- DELETE ---
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_endpoint(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    success = service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
