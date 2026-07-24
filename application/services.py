from typing import Optional, List
import bcrypt

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

class UserService:
    """
    This is our updated Application Service, containing the core business logic for all CRUD operations.
    """
    def __init__(self, user_repository: UserRepository):
        self._repository: UserRepository = user_repository

    # --- CREATE ---
    def create_user(
        self, email: str, password: str, first_name: str, last_name: str, bio: Optional[str] = None
    ) -> User:
        if self._repository.get_by_email(email):
            raise ValueError("User with this email already exists.")
        
        # Bcrypt has a 72-character limit for passwords.
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
        """Authenticates a user by email and password."""
        user = self._repository.get_by_email(email)
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
        self, user_id: uuid.UUID, first_name: Optional[str], last_name: Optional[str], bio: Optional[str]
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
