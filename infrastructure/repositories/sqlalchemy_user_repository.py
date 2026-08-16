from typing import Optional, List
from sqlalchemy.orm import Session, joinedload
import uuid

from application.ports.user_repository import UserRepository
from domain.user import User as UserDomain
from infrastructure.database import UserTable, ProfileTable

class SQLAlchemyUserRepository(UserRepository):
    """
    The concrete implementation of the UserRepository using SQLAlchemy.
    This adapter translates domain objects to database models and vice versa.
    """
    def __init__(self, db_session: Session):
        self._db: Session = db_session

    def add(self, user_domain: UserDomain) -> None:
        db_profile = ProfileTable(
            bio=user_domain.profile.bio,
            theme=user_domain.profile.theme,
            accent_color=user_domain.profile.accent_color,
            avatar_url=user_domain.profile.avatar_url,
            navigation_preferences=user_domain.profile.navigation_preferences
        )
        db_user = UserTable(
            id=user_domain.id,
            email=user_domain.email,
            hashed_password=user_domain.hashed_password,
            first_name=user_domain.first_name,
            last_name=user_domain.last_name,
            profile=db_profile
        )
        self._db.add(db_user)
        self._db.commit()

    def get_by_id(self, user_id: uuid.UUID) -> Optional[UserDomain]:
        db_user = (
            self._db.query(UserTable)
            .options(joinedload(UserTable.profile))
            .filter(UserTable.id == user_id)
            .first()
        )
        if db_user:
            return UserDomain.model_validate(db_user)
        return None

    def get_by_email(self, email: str) -> Optional[UserDomain]:
        db_user = (
            self._db.query(UserTable)
            .options(joinedload(UserTable.profile))
            .filter(UserTable.email == email)
            .first()
        )
        if db_user:
            return UserDomain.model_validate(db_user)
        return None
    
    def get_all(self) -> List[UserDomain]:
        db_users = self._db.query(UserTable).options(joinedload(UserTable.profile)).all()
        return [UserDomain.model_validate(db_user) for db_user in db_users]

    def update(self, user_domain: UserDomain) -> None:
        # Fetch the existing user from the database
        db_user = self._db.query(UserTable).filter(UserTable.id == user_domain.id).first()
        if db_user:
            # Update the fields
            db_user.first_name = user_domain.first_name
            db_user.last_name = user_domain.last_name
            # Ensure profile exists before updating
            if db_user.profile:
                db_user.profile.bio = user_domain.profile.bio
                db_user.profile.theme = user_domain.profile.theme
                db_user.profile.accent_color = user_domain.profile.accent_color
                db_user.profile.avatar_url = user_domain.profile.avatar_url
                db_user.profile.navigation_preferences = user_domain.profile.navigation_preferences
            
            self._db.commit()

    def delete(self, user_id: uuid.UUID) -> None:
        db_user = self._db.query(UserTable).filter(UserTable.id == user_id).first()
        if db_user:
            self._db.delete(db_user)
            self._db.commit()
