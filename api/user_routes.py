import logging
import uuid
import random
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from application.services import UserService
from dependencies import get_user_service
from api.auth_guard import get_current_user_id
from infrastructure.auth import (
    create_access_token, 
    generate_split_refresh_token, 
    hash_refresh_token, 
    verify_refresh_token_hash,
    verify_token,
    get_jwks
)
from infrastructure.database import SessionLocal, RefreshTokenTable, UserTrustedDeviceTable, DeviceOTPTable
from infrastructure.email_service import send_device_otp_email

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
    device_fingerprint: Optional[str] = None

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None
    device_name: Optional[str] = None

class DeviceOTPVerifyRequest(BaseModel):
    email: EmailStr
    device_fingerprint: str
    otp_code: str
    device_name: Optional[str] = None

class DeviceOTPResendRequest(BaseModel):
    email: EmailStr
    device_fingerprint: str
    device_name: Optional[str] = None

class RequestLoginOTPRequest(BaseModel):
    email: EmailStr
    device_fingerprint: Optional[str] = None
    device_name: Optional[str] = None

class VerifyLoginOTPRequest(BaseModel):
    email: EmailStr
    otp_code: str
    device_fingerprint: Optional[str] = None
    device_name: Optional[str] = None


class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    theme: Optional[str] = None
    accent_color: Optional[str] = None
    avatar_url: Optional[str] = None
    navigation_preferences: Optional[dict] = None

class ProfileResponse(BaseModel):
    bio: Optional[str] = None
    theme: Optional[str] = "dark"
    accent_color: Optional[str] = "#0ea5e9"
    avatar_url: Optional[str] = None
    navigation_preferences: Optional[dict] = None
    
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
@router.post("/login", status_code=status.HTTP_200_OK)
def login_user_endpoint(
    request_data: UserLoginRequest, 
    req: Request,
    response: Response, 
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    try:
        user = service.authenticate_user(email=request_data.email, password=request_data.password)
        
        device_fingerprint = request_data.device_fingerprint or req.headers.get("x-device-fingerprint")
        device_name = request_data.device_name or parse_device_name(req.headers.get("user-agent"))

        # First-Time Device Verification Check
        if device_fingerprint:
            trusted_dev = db.query(UserTrustedDeviceTable).filter(
                UserTrustedDeviceTable.user_id == user.id,
                UserTrustedDeviceTable.device_fingerprint == device_fingerprint
            ).first()

            if not trusted_dev:
                # Generate 6-digit OTP
                otp_code = f"{random.randint(100000, 999999)}"
                expires_at = datetime.utcnow() + timedelta(minutes=10)

                existing_otp = db.query(DeviceOTPTable).filter(
                    DeviceOTPTable.user_id == user.id,
                    DeviceOTPTable.device_fingerprint == device_fingerprint
                ).first()

                if existing_otp:
                    existing_otp.otp_code = otp_code
                    existing_otp.expires_at = expires_at
                    existing_otp.attempts = 0
                    existing_otp.verified = False
                else:
                    db_otp = DeviceOTPTable(
                        user_id=user.id,
                        device_fingerprint=device_fingerprint,
                        otp_code=otp_code,
                        expires_at=expires_at,
                        attempts=0,
                        verified=False
                    )
                    db.add(db_otp)

                db.commit()

                send_device_otp_email(user.email, user.first_name, otp_code, device_name)

                # Mask email for privacy (e.g., k***i@gmail.com)
                email_parts = user.email.split("@")
                username = email_parts[0]
                masked_user = username[0] + "***" + username[-1] if len(username) > 2 else username
                masked_email = f"{masked_user}@{email_parts[1]}"

                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "requires_device_verification": True,
                        "email_masked": masked_email,
                        "device_fingerprint": device_fingerprint,
                        "message": "A security verification code has been sent to your email for this new device."
                    }
                )

        # Enforce Max 5 Active Sessions via Least Recently Used (LRU) Eviction
        active_sessions = db.query(RefreshTokenTable).filter(
            RefreshTokenTable.user_id == user.id,
            RefreshTokenTable.revoked == False,
            RefreshTokenTable.expires_at > datetime.utcnow()
        ).order_by(asc(RefreshTokenTable.last_used)).all()
        
        if len(active_sessions) >= 5:
            oldest_session = active_sessions[0]
            oldest_session.revoked = True
            db.commit()

        session_id = uuid.uuid4()
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "sid": str(session_id)})
        token_id_str, secret_token, combined_cookie = generate_split_refresh_token()
        
        family_id = str(uuid.uuid4())
        hashed_argon2 = hash_refresh_token(secret_token)
        expires_at = datetime.utcnow() + timedelta(days=7)
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


@router.post("/login/verify-device-otp", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def verify_device_otp_endpoint(
    request_data: DeviceOTPVerifyRequest,
    req: Request,
    response: Response,
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    user = service.get_user_by_email(request_data.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")

    otp_rec = db.query(DeviceOTPTable).filter(
        DeviceOTPTable.user_id == user.id,
        DeviceOTPTable.device_fingerprint == request_data.device_fingerprint
    ).first()

    if not otp_rec or otp_rec.verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification code.")

    now = datetime.now(timezone.utc)
    exp = otp_rec.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    if now > exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code has expired. Please request a new code.")


    if otp_rec.otp_code.strip() != request_data.otp_code.strip():
        otp_rec.attempts += 1
        db.commit()
        if otp_rec.attempts >= 5:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many invalid attempts. Please request a new code.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect verification code. Please check your email.")

    # Mark OTP as verified & trust device
    otp_rec.verified = True

    device_name = request_data.device_name or parse_device_name(req.headers.get("user-agent"))
    existing_trusted = db.query(UserTrustedDeviceTable).filter(
        UserTrustedDeviceTable.user_id == user.id,
        UserTrustedDeviceTable.device_fingerprint == request_data.device_fingerprint
    ).first()

    if not existing_trusted:
        db_trusted = UserTrustedDeviceTable(
            user_id=user.id,
            device_fingerprint=request_data.device_fingerprint,
            device_name=device_name,
            verified_at=datetime.utcnow()
        )
        db.add(db_trusted)

    db.commit()

    # Issue Session Tokens
    session_id = uuid.uuid4()
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "sid": str(session_id)})
    token_id_str, secret_token, combined_cookie = generate_split_refresh_token()
    family_id = str(uuid.uuid4())
    hashed_argon2 = hash_refresh_token(secret_token)
    expires_at = datetime.utcnow() + timedelta(days=7)
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

    logger.info(f"AUDIT: EVENT=DEVICE_VERIFIED_LOGIN_SUCCESS USER_ID={user.id} SESSION_ID={session_id} DEVICE='{device_name}'")

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


@router.post("/login/resend-device-otp", status_code=status.HTTP_200_OK)
def resend_device_otp_endpoint(
    request_data: DeviceOTPResendRequest,
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    user = service.get_user_by_email(request_data.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")

    otp_code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    existing_otp = db.query(DeviceOTPTable).filter(
        DeviceOTPTable.user_id == user.id,
        DeviceOTPTable.device_fingerprint == request_data.device_fingerprint
    ).first()

    if existing_otp:
        existing_otp.otp_code = otp_code
        existing_otp.expires_at = expires_at
        existing_otp.attempts = 0
        existing_otp.verified = False
    else:
        db_otp = DeviceOTPTable(
            user_id=user.id,
            device_fingerprint=request_data.device_fingerprint,
            otp_code=otp_code,
            expires_at=expires_at,
            attempts=0,
            verified=False
        )
        db.add(db_otp)

    db.commit()

    send_device_otp_email(user.email, user.first_name, otp_code, request_data.device_name or "New Device")

    return {"message": "A new verification code has been sent to your email."}


@router.post("/login/request-login-otp", status_code=status.HTTP_200_OK)
def request_login_otp_endpoint(
    request_data: RequestLoginOTPRequest,
    req: Request,
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    user = service.get_user_by_email(request_data.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No account found with this email. Please register first.")

    device_fingerprint = request_data.device_fingerprint or req.headers.get("x-device-fingerprint") or "web_unknown"
    device_name = request_data.device_name or parse_device_name(req.headers.get("user-agent"))

    otp_code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    existing_otp = db.query(DeviceOTPTable).filter(
        DeviceOTPTable.user_id == user.id,
        DeviceOTPTable.device_fingerprint == device_fingerprint
    ).first()

    if existing_otp:
        existing_otp.otp_code = otp_code
        existing_otp.expires_at = expires_at
        existing_otp.attempts = 0
        existing_otp.verified = False
    else:
        db_otp = DeviceOTPTable(
            user_id=user.id,
            device_fingerprint=device_fingerprint,
            otp_code=otp_code,
            expires_at=expires_at,
            attempts=0,
            verified=False
        )
        db.add(db_otp)

    db.commit()

    send_device_otp_email(user.email, user.first_name, otp_code, f"{device_name} (Login OTP)")

    email_parts = user.email.split("@")
    username = email_parts[0]
    masked_user = username[0] + "***" + username[-1] if len(username) > 2 else username
    masked_email = f"{masked_user}@{email_parts[1]}"

    return {
        "message": "A 6-digit login verification code has been sent to your email.",
        "email_masked": masked_email,
        "device_fingerprint": device_fingerprint
    }


@router.post("/login/verify-login-otp", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def verify_login_otp_endpoint(
    request_data: VerifyLoginOTPRequest,
    req: Request,
    response: Response,
    service: UserService = Depends(get_user_service),
    db: Session = Depends(get_db)
):
    user = service.get_user_by_email(request_data.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")

    device_fingerprint = request_data.device_fingerprint or req.headers.get("x-device-fingerprint") or "web_unknown"

    otp_rec = db.query(DeviceOTPTable).filter(
        DeviceOTPTable.user_id == user.id,
        DeviceOTPTable.device_fingerprint == device_fingerprint
    ).first()

    if not otp_rec or otp_rec.verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired login code.")

    now = datetime.now(timezone.utc)
    exp = otp_rec.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    if now > exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login code has expired. Please request a new code.")


    if otp_rec.otp_code.strip() != request_data.otp_code.strip():
        otp_rec.attempts += 1
        db.commit()
        if otp_rec.attempts >= 5:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many invalid attempts. Please request a new code.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect login code. Please check your email.")

    otp_rec.verified = True

    device_name = request_data.device_name or parse_device_name(req.headers.get("user-agent"))
    existing_trusted = db.query(UserTrustedDeviceTable).filter(
        UserTrustedDeviceTable.user_id == user.id,
        UserTrustedDeviceTable.device_fingerprint == device_fingerprint
    ).first()

    if not existing_trusted:
        db_trusted = UserTrustedDeviceTable(
            user_id=user.id,
            device_fingerprint=device_fingerprint,
            device_name=device_name,
            verified_at=datetime.utcnow()
        )
        db.add(db_trusted)

    db.commit()

    session_id = uuid.uuid4()
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "sid": str(session_id)})
    token_id_str, secret_token, combined_cookie = generate_split_refresh_token()
    family_id = str(uuid.uuid4())
    hashed_argon2 = hash_refresh_token(secret_token)
    expires_at = datetime.utcnow() + timedelta(days=7)
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

    logger.info(f"AUDIT: EVENT=MAGIC_OTP_LOGIN_SUCCESS USER_ID={user.id} SESSION_ID={session_id} DEVICE='{device_name}'")

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
        device_fingerprint = request_data.device_fingerprint or req.headers.get("x-device-fingerprint")
        if device_fingerprint:
            db_trusted = UserTrustedDeviceTable(
                user_id=user.id,
                device_fingerprint=device_fingerprint,
                device_name=parse_device_name(req.headers.get("user-agent")),
                verified_at=datetime.utcnow()
            )
            db.add(db_trusted)
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
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    tokens = db.query(RefreshTokenTable).filter(
        RefreshTokenTable.user_id == current_user_id,
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
                "is_current": False
            })
    return result

# --- REVOKE SINGLE SESSION ---
@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session_endpoint(
    session_id: uuid.UUID,
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    db.query(RefreshTokenTable).filter(
        RefreshTokenTable.user_id == current_user_id,
        RefreshTokenTable.session_id == session_id
    ).update({"revoked": True})
    db.commit()

    logger.info(f"AUDIT: EVENT=REVOKE_SESSION USER_ID={current_user_id} TARGET_SESSION={session_id}")
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
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    db.query(RefreshTokenTable).filter(RefreshTokenTable.user_id == current_user_id).update({"revoked": True})
    db.commit()
    logger.info(f"AUDIT: EVENT=LOGOUT_ALL USER_ID={current_user_id}")

    response.delete_cookie("refresh_token")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- READ (ALL - PROTECTED) ---
@router.get("/", response_model=List[UserResponse])
def get_all_users_endpoint(
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    service: UserService = Depends(get_user_service)
):
    # Only authenticated users can access, returning user records securely
    return service.get_all_users()

# --- READ (ONE - PROTECTED) ---
@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id_endpoint(
    user_id: uuid.UUID,
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    service: UserService = Depends(get_user_service)
):
    if current_user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cannot view another user's profile")
    user = service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# --- UPDATE (PROTECTED & AUTHORIZED) ---
@router.put("/{user_id}", response_model=UserResponse)
def update_user_endpoint(
    user_id: uuid.UUID,
    request_data: UserUpdateRequest,
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    service: UserService = Depends(get_user_service)
):
    if current_user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cannot update another user's profile")
    updated_user = service.update_user(
        user_id=user_id,
        first_name=request_data.first_name,
        last_name=request_data.last_name,
        bio=request_data.bio,
        theme=request_data.theme,
        accent_color=request_data.accent_color,
        avatar_url=request_data.avatar_url,
        navigation_preferences=request_data.navigation_preferences
    )
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return updated_user

# --- DELETE (PROTECTED & AUTHORIZED) ---
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_endpoint(
    user_id: uuid.UUID,
    current_user_id: uuid.UUID = Depends(get_current_user_id),
    service: UserService = Depends(get_user_service)
):
    if current_user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cannot delete another user's account")
    success = service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

