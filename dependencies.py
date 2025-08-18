from fastapi import Depends
from sqlalchemy.orm import Session

# Import all the components needed for the dependencies
from infrastructure.database import SessionLocal
from infrastructure.repositories.sqlalchemy_user_repository import SQLAlchemyUserRepository
from application.ports.user_repository import UserRepository
from application.services import UserService

# 1. Dependency for the database session
def get_db():
    """
    This function creates a database session for a single request,
    and ensures it's properly closed afterwards.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 2. Dependency for the repository
def get_user_repository(db: Session = Depends(get_db)) -> UserRepository:
    """
    This function creates an instance of our concrete repository.
    """
    return SQLAlchemyUserRepository(db)

# 3. Dependency for the service
def get_user_service(
    repository: UserRepository = Depends(get_user_repository),
) -> UserService:
    """
    This function creates an instance of our UserService, injecting the
    repository it gets from the 'get_user_repository' dependency.
    """
    return UserService(repository)