import os
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "c0e8d1763d101d551d574375f2598fd8f0381a3023b37b1ebf61a043a5ec6a29")
KID = os.getenv("JWT_KID", "v1")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
ISSUER = os.getenv("JWT_ISSUER", "lifeflow-auth")
AUDIENCE = os.getenv("JWT_AUDIENCE", "lifeflow-app")

ph = PasswordHasher()

# Key store mapping key IDs (kid) to secrets for key rotation support
KEY_STORE = {
    KID: SECRET_KEY
}

def get_jwks() -> Dict[str, Any]:
    """Exposes JWKS endpoint GET /.well-known/jwks.json"""
    return {
        "keys": [
            {
                "kty": "oct",
                "use": "sig",
                "alg": ALGORITHM,
                "kid": KID
            }
        ]
    }

def hash_refresh_token(secret: str) -> str:
    """Hashes opaque refresh token secret using Argon2id"""
    return ph.hash(secret)

def verify_refresh_token_hash(stored_hash: str, secret: str) -> bool:
    """Verifies opaque refresh token secret against stored Argon2id hash"""
    try:
        return ph.verify(stored_hash, secret)
    except (VerifyMismatchError, InvalidHash, Exception):
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates JWT Access Token with full standard claims:
    - sub: User UUID
    - jti: Token UUID
    - iat: Issued At
    - nbf: Not Before
    - exp: Expiration Time
    - iss: Issuer
    - aud: Audience
    - Header: {"kid": "v1", "alg": "HS256"}
    """
    to_encode = data.copy()
    now_dt = datetime.now(timezone.utc)
    now_ts = int(now_dt.timestamp())
    
    if expires_delta:
        expire_ts = int((now_dt + expires_delta).timestamp())
    else:
        expire_ts = int((now_dt + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp())
        
    jti = str(uuid.uuid4())
    to_encode.update({
        "jti": jti,
        "iat": now_ts,
        "nbf": now_ts,
        "exp": expire_ts,
        "type": "access",
        "iss": ISSUER,
        "aud": AUDIENCE
    })
    
    headers = {"alg": ALGORITHM, "kid": KID}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM, headers=headers)
    return encoded_jwt

def generate_split_refresh_token() -> tuple[str, str, str]:
    """
    Generates Split Refresh Token: (token_id, secret_token, combined_cookie_value)
    token_id: UUID string for O(1) indexed DB primary key lookup
    secret_token: 256-bit opaque random string (secrets.token_urlsafe(32))
    combined_cookie_value: <token_id>.<secret_token>
    """
    token_id = str(uuid.uuid4())
    secret_token = secrets.token_urlsafe(32)
    combined = f"{token_id}.{secret_token}"
    return token_id, secret_token, combined

def verify_token(token: str):
    """Verifies JWT access token using KEY_STORE lookup for kid"""
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid", KID)
        secret = KEY_STORE.get(kid, SECRET_KEY)
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM], issuer=ISSUER, audience=AUDIENCE)
        return payload
    except Exception:
        return None
