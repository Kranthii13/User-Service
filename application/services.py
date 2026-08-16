from typing import Optional, List
import bcrypt
import uuid

from domain.user import User, UserProfile
from application.ports.user_repository import UserRepository

def hash_password(password: str) -> str:
    pwd_bytes = password[:72].encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pwd_bytes = plain_password[:72].encode('utf-8')
        hash_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False

from application.ports.auth_provider import AuthProvider

class UserService:
    """
    Application Service containing core business logic for user management & authentication.
    Supports optional AuthProvider (e.g. Supabase Auth) adapter integration.
    """
    def __init__(self, user_repository: UserRepository, auth_provider: Optional[AuthProvider] = None):
        self._repository: UserRepository = user_repository
        self._auth_provider: Optional[AuthProvider] = auth_provider

    # --- CREATE ---
    def create_user(
        self, email: str, password: str, first_name: str, last_name: str, bio: Optional[str] = None
    ) -> User:
        if self._repository.get_by_email(email):
            raise ValueError("User with this email already exists.")
        
        # Register in Supabase Auth Provider if enabled
        if self._auth_provider:
            try:
                self._auth_provider.create_user(
                    email=email,
                    password=password,
                    metadata={"first_name": first_name, "last_name": last_name}
                )
            except Exception as e:
                # Log provider registration warning, proceed with local domain persistence
                pass

        hashed_password = hash_password(password)
        user_profile = UserProfile(bio=bio)
        new_user = User(
            email=email,
            hashed_password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            profile=user_profile
        )
        self._repository.add(new_user)
        return new_user

    # --- AUTHENTICATION ---
    def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """Authenticates a user by email and password via Supabase Auth or local DB."""
        user = self._repository.get_by_email(email)

        # 1. Try Supabase Auth Provider first if configured
        if self._auth_provider:
            try:
                auth_res = self._auth_provider.sign_in_with_password(email, password)
                if auth_res and "user" in auth_res:
                    meta = auth_res["user"].get("user_metadata", {})
                    first_name = meta.get("first_name", email.split("@")[0].capitalize())
                    last_name = meta.get("last_name", "User")
                    
                    if not user:
                        # Auto-sync user into database if present in Supabase Auth
                        user = User(
                            email=email,
                            hashed_password=hash_password(password),
                            first_name=first_name,
                            last_name=last_name,
                            profile=UserProfile()
                        )
                        self._repository.add(user)
                    return user
            except Exception:
                pass

        # 2. Fallback to local database authentication
        if not user:
            raise ValueError("Invalid email or password.")

        if not verify_password(password, user.hashed_password):
            raise ValueError("Invalid email or password.")
            
        return user

    # --- READ ---
    def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Fetches a single user by their ID."""
        return self._repository.get_by_id(user_id)

    def get_all_users(self) -> List[User]:
        """Fetches all users."""
        return self._repository.get_all()

    # --- UPDATE ---
    def update_user(
        self, user_id: uuid.UUID, first_name: Optional[str] = None, last_name: Optional[str] = None, bio: Optional[str] = None, theme: Optional[str] = None, accent_color: Optional[str] = None, avatar_url: Optional[str] = None, navigation_preferences: Optional[dict] = None
    ) -> Optional[User]:
        """Updates a user's profile information."""
        user_to_update = self._repository.get_by_id(user_id)

        if not user_to_update:
            return None # Indicate that the user was not found

        # Update fields only if new values are provided
        if first_name is not None:
            user_to_update.first_name = first_name
        if last_name is not None:
            user_to_update.last_name = last_name
        if bio is not None:
            user_to_update.profile.bio = bio
        if theme is not None:
            user_to_update.profile.theme = theme
        if accent_color is not None:
            user_to_update.profile.accent_color = accent_color
        if avatar_url is not None:
            user_to_update.profile.avatar_url = avatar_url
        if navigation_preferences is not None:
            user_to_update.profile.navigation_preferences = navigation_preferences
        
        self._repository.update(user_to_update)
        return user_to_update

    # --- DELETE ---
    def delete_user(self, user_id: uuid.UUID) -> bool:
        """Deletes a user and returns True if successful, False otherwise."""
        user_to_delete = self._repository.get_by_id(user_id)
        
        if not user_to_delete:
            return False # Indicate user not found
        
        self._repository.delete(user_id)
        return True
