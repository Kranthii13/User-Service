"""
Enterprise Security Guard — Validates Normalized Canonical HMAC Gateway Identity signatures.
Canonical format: METHOD \n PATH \n SORTED_QUERY \n BODY_HASH \n USER_ID \n TIMESTAMP \n REQUEST_ID
Prevents unauthenticated direct access, header forgery, and replay attacks.
"""
import os
import time
import hmac
import hashlib
from typing import Optional
from uuid import UUID

from fastapi import Request, HTTPException, status, Header
from jose import jwt
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "c0e8d1763d101d551d574375f2598fd8f0381a3023b37b1ebf61a043a5ec6a29")
INTERNAL_SECRET = os.getenv("INTERNAL_SECRET", SECRET_KEY)
ALGORITHM  = os.getenv("ALGORITHM", "HS256")
ISSUER     = os.getenv("JWT_ISSUER", "lifeflow-auth")
AUDIENCE   = os.getenv("JWT_AUDIENCE", "lifeflow-app")

async def get_current_user_id(
    request: Request,
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID"),
    x_internal_signature: Optional[str] = Header(None, alias="X-Internal-Signature"),
) -> UUID:
    # 1. Gateway HMAC Signature Path (Inter-Service Security)
    if x_user_id and x_timestamp and x_internal_signature:
        try:
            # Replay attack prevention (30s timestamp window)
            if abs(time.time() - float(x_timestamp)) > 30:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Expired internal signature timestamp (> 30s)")
            
            body_bytes = await request.body()
            content_type = request.headers.get("content-type", "").lower()
            if "application/json" in content_type or "text/" in content_type or not content_type:
                body_hash = hashlib.sha256(body_bytes).hexdigest()
            else:
                body_hash = hashlib.sha256(b"").hexdigest()

            method_str = request.method.upper()
            raw_path = request.url.path.rstrip('/')
            for prefix in ["/api/finance", "/api/journal", "/api/tasks", "/api/ledger", "/api/users", "/api/ai"]:
                if raw_path.startswith(prefix):
                    raw_path = raw_path[len(prefix):]
                    break
            path_str = "/" + raw_path.lstrip('/')

            sorted_query = "&".join(sorted([f"{k}={v}" for k, v in request.query_params.items()]))
            req_id_str = x_request_id or ""

            canonical_string = f"{method_str}\n{path_str}\n{sorted_query}\n{body_hash}\n{x_user_id}\n{x_timestamp}\n{req_id_str}"
            expected_sig = hmac.new(INTERNAL_SECRET.encode(), canonical_string.encode(), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected_sig, x_internal_signature):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid internal signature")
            
            return UUID(x_user_id)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Malformed internal identity headers: {str(e)}")

    # Reject direct X-User-ID header forgery attempts bypassing Gateway
    if x_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Direct X-User-ID header forgery rejected")

    # 2. Bearer JWT Token Path (Direct Request Fallback)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], issuer=ISSUER, audience=AUDIENCE)
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise ValueError()
        return UUID(user_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
