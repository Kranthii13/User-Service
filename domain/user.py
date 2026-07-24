import uuid
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class UserProfile(BaseModel):
    """
    A nested model to hold profile information.
    """
    bio: Optional[str] = None
    theme: Optional[str] = "dark"
    accent_color: Optional[str] = "#0ea5e9"

    class Config:
        from_attributes = True

class User(BaseModel):
    """
    This is our full-fledged core User model.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    email: EmailStr
    hashed_password: str
    first_name: str
    last_name: str
    profile: UserProfile = Field(default_factory=UserProfile)

    class Config:
        # This allows the main User model to be created from database objects.
        from_attributes = True
