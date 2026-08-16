import os
import uuid
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, Tuple
from application.ports.auth_provider import AuthProvider

class SupabaseAuthProvider(AuthProvider):
    """
    Infrastructure Adapter implementing AuthProvider port using Supabase Auth.
    """

    def __init__(self, supabase_url: Optional[str] = None, service_role_key: Optional[str] = None, anon_key: Optional[str] = None):
        self.supabase_url = (supabase_url or os.getenv("SUPABASE_URL", "")).rstrip("/")
        self.service_role_key = service_role_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        self.anon_key = anon_key or os.getenv("SUPABASE_ANON_KEY", "")

    def _headers(self, service_role: bool = False) -> Dict[str, str]:
        key = self.service_role_key if service_role else self.anon_key
        return {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }

    def _request(self, method: str, url: str, headers: Dict[str, str], payload: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, Any]]: # type: ignore
        req = urllib.request.Request(url, method=method.upper())
        for k, v in headers.items():
            req.add_header(k, v)
        data_bytes = json.dumps(payload).encode('utf-8') if payload else None
        try:
            with urllib.request.urlopen(req, data=data_bytes, timeout=10.0) as resp:
                status_code = resp.getcode()
                body = json.loads(resp.read().decode('utf-8')) if resp.length != 0 else {}
                return status_code, body
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode('utf-8'))
            except Exception:
                body = {"error": str(e)}
            return e.code, body
        except Exception as e:
            return 500, {"error": str(e)}

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        if not self.supabase_url or not token:
            return None
        url = f"{self.supabase_url}/auth/v1/user"
        headers = {"apikey": self.anon_key, "Authorization": f"Bearer {token}"}
        code, body = self._request("GET", url, headers)
        return body if code == 200 else None

    def create_user(self, email: str, password: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.supabase_url:
            raise ValueError("SUPABASE_URL is not configured.")
        url = f"{self.supabase_url}/auth/v1/admin/users"
        payload = {"email": email, "password": password, "email_confirm": True, "user_metadata": metadata or {}}
        code, body = self._request("POST", url, self._headers(service_role=True), payload)
        if code in (200, 201):
            return body
        raise ValueError(f"Supabase user creation failed: {body}")

    def sign_in_with_password(self, email: str, password: str) -> Dict[str, Any]:
        if not self.supabase_url:
            raise ValueError("SUPABASE_URL is not configured.")
        url = f"{self.supabase_url}/auth/v1/token?grant_type=password"
        payload = {"email": email, "password": password}
        code, body = self._request("POST", url, self._headers(service_role=False), payload)
        if code == 200:
            return body
        raise ValueError(f"Supabase login failed: {body}")

    def sign_in_with_otp(self, email: str) -> bool:
        if not self.supabase_url:
            return False
        url = f"{self.supabase_url}/auth/v1/otp"
        payload = {"email": email}
        code, _ = self._request("POST", url, self._headers(service_role=False), payload)
        return code == 200

    def refresh_session(self, refresh_token: str) -> Dict[str, Any]:
        if not self.supabase_url:
            raise ValueError("SUPABASE_URL is not configured.")
        url = f"{self.supabase_url}/auth/v1/token?grant_type=refresh_token"
        payload = {"refresh_token": refresh_token}
        code, body = self._request("POST", url, self._headers(service_role=False), payload)
        if code == 200:
            return body
        raise ValueError(f"Token refresh failed: {body}")

    def logout(self, token: str) -> bool:
        if not self.supabase_url or not token:
            return False
        url = f"{self.supabase_url}/auth/v1/logout"
        headers = {"apikey": self.anon_key, "Authorization": f"Bearer {token}"}
        code, _ = self._request("POST", url, headers)
        return code in (200, 204)

    def delete_user(self, user_id: uuid.UUID) -> bool:
        if not self.supabase_url:
            return False
        url = f"{self.supabase_url}/auth/v1/admin/users/{user_id}"
        code, _ = self._request("DELETE", url, self._headers(service_role=True))
        return code in (200, 204)
