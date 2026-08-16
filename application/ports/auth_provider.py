from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import uuid

class AuthProvider(ABC):
    """
    Application Output Port for Authentication & Identity operations.
    Keeps application and domain layers independent of concrete Auth SDKs (e.g. Supabase Auth).
    """

    @abstractmethod
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verifies an access token and returns payload claim dictionary if valid."""
        raise NotImplementedError

    @abstractmethod
    def create_user(
        self, email: str, password: str, metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates a user identity in the authentication provider."""
        raise NotImplementedError

    @abstractmethod
    def sign_in_with_password(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticates user with email & password, returning token session dict."""
        raise NotImplementedError

    @abstractmethod
    def sign_in_with_otp(self, email: str) -> bool:
        """Triggers passwordless OTP / magic link email."""
        raise NotImplementedError

    @abstractmethod
    def refresh_session(self, refresh_token: str) -> Dict[str, Any]:
        """Refreshes identity session using refresh token."""
        raise NotImplementedError

    @abstractmethod
    def logout(self, token: str) -> bool:
        """Revokes token session."""
        raise NotImplementedError

    @abstractmethod
    def delete_user(self, user_id: uuid.UUID) -> bool:
        """Deletes user from authentication provider."""
        raise NotImplementedError
